package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/hostinventory"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Host-inventory materialisation, against a real Postgres (asset-inventory
// workstream 2.11b).
//
// Almost nothing here can be proved without a database. The identification
// engine's matching, the singleton guard, RLS, the unique indexes on
// `software_products` and `software_installs`, and the removed-not-deleted
// sweep are all SQL behaviour: a unit test can assert that the code called the
// writer, and not that the writer wrote what the schema would accept or that a
// second collection landed on the first one's asset.
//
// Every payload below is built by running the REAL collector projection
// (hostinventory.ToObservations) over a Report. Hand-assembling the
// observations would test this file against a shape nothing produces — and the
// identifiers, which are the whole question, are exactly what that projection
// decides.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

// seedHostInventoryAgent creates the device_agents row a host_inventory job
// must reference — the widened CHECK requires agent_id for this job type.
func seedHostInventoryAgent(t *testing.T, db *sql.DB, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(
		`INSERT INTO device_agents (id, tenant_id, name, registration_key, platform, version)
		 VALUES ($1, $2, 'host-inventory-test-agent', $3, 'linux', '0.0.0-test')`,
		id, tenantID, "regkey-"+id.String()); err != nil {
		t.Fatalf("seed device_agent: %v", err)
	}
	return id
}

// hostReport is a realistic Linux collection, with every section OK.
//
// `packages` is a real list rather than empty because the absent-install sweep
// and the NULL-not-empty-string identity rule are the two most likely to be wrong,
// and neither is observable on an empty one. The third package deliberately has
// NO purl (a Windows-registry-shaped entry is the real case) so the purl-less
// identity path is exercised on every run.
func hostReport(mode hostinventory.Mode, agentID, serial string, packages []hostinventory.Package) *hostinventory.Report {
	rep := &hostinventory.Report{
		Collected: time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC),
		Mode:      mode,
		Platform:  hostinventory.PlatformLinux,
		AgentID:   agentID,
		Host: hostinventory.Host{
			OS: "Ubuntu", OSVersion: "24.04.1 LTS", Kernel: "6.8.0-45-generic",
			Hostname: "app-01", FQDN: "app-01.example.net",
		},
		Hardware: hostinventory.Hardware{
			Vendor: "Dell Inc.", Model: "PowerEdge R650", Serial: serial,
			UUID: "4c4c4544-0044-5010-8043-b7c04f463432", Firmware: "2.10.2",
		},
		Interfaces: []hostinventory.Interface{
			{Name: "eno1", MAC: "3c:ec:ef:11:22:33", Addresses: []string{"198.51.100.20/24"}, State: "up"},
			// Virtual, so its MAC must NOT become identity: a veth address is
			// generated per container start, and minting identity from one
			// produces a new asset on every restart.
			{Name: "veth9a1b", MAC: "6e:4f:2a:9c:11:02", Addresses: []string{"10.244.1.3/24"}, State: "up", Virtual: true},
			// Locally administered (the U/L bit is set in the first octet), so
			// it rotates and must not become identity either.
			{Name: "wlan0", MAC: "02:11:22:33:44:55", Addresses: []string{"192.0.2.44/24"}, State: "up"},
		},
		Packages: packages,
		Listeners: []hostinventory.Listener{
			{Proto: "tcp", Address: "0.0.0.0", Port: 22, Process: "sshd", PID: 812},
			{Proto: "tcp", Address: "127.0.0.1", Port: 5432, Process: "postgres", PID: 1104},
			{Proto: "udp", Address: "198.51.100.20", Port: 161, Process: "snmpd"},
		},
		CertStores: []hostinventory.CertStore{
			{Path: "/etc/ssl/certs", Count: 141, NonCertificateBlocks: 1},
		},
		Sections: map[string]string{
			hostinventory.SectionHost:       hostinventory.SectionOK,
			hostinventory.SectionHardware:   hostinventory.SectionOK,
			hostinventory.SectionInterfaces: hostinventory.SectionOK,
			hostinventory.SectionPackages:   hostinventory.SectionOK,
			hostinventory.SectionListeners:  hostinventory.SectionOK,
			hostinventory.SectionCertStores: hostinventory.SectionOK,
		},
	}
	return rep
}

func defaultPackages() []hostinventory.Package {
	return []hostinventory.Package{
		{Name: "openssl", Version: "3.0.13", Manager: "dpkg", Arch: "amd64", PURL: "pkg:deb/ubuntu/openssl@3.0.13"},
		{Name: "curl", Version: "8.5.0", Manager: "dpkg", Arch: "amd64", PURL: "pkg:deb/ubuntu/curl@8.5.0"},
		// No purl: the purl-less identity path (name@version), which is where
		// the ''-instead-of-NULL bug collapses every such product onto one row.
		{Name: "vendor-agent", Version: "1.4.2", Manager: "vendor"},
	}
}

func observationsFor(t *testing.T, rep *hostinventory.Report) *di.InterrogateResult {
	t.Helper()
	obs, err := hostinventory.ToObservations(rep)
	if err != nil {
		t.Fatalf("ToObservations: %v", err)
	}
	return obs
}

// newHostInventoryJob creates the device_jobs row a collection is recorded on.
func newHostInventoryJob(t *testing.T, appDB, owner *sql.DB, tenantID, agentID uuid.UUID) uuid.UUID {
	t.Helper()
	job, err := NewJobQueueService(appDB, owner, nil).CreateJob(context.Background(), models.CreateDeviceJobRequest{
		TenantID:   tenantID,
		JobType:    models.JobTypeHostInventory,
		AgentID:    &agentID,
		Parameters: map[string]interface{}{"mode": "remote", "transport": "ssh"},
	})
	if err != nil {
		t.Fatalf("CreateJob(host_inventory): %v", err)
	}
	return job.ID
}

func identifierValues(t *testing.T, db *sql.DB, tenantID uuid.UUID, assetID string, kind string) []string {
	t.Helper()
	rows, err := db.Query(
		`SELECT value FROM asset_identifiers WHERE tenant_id = $1 AND asset_id = $2 AND kind = $3 ORDER BY value`,
		tenantID, assetID, kind)
	if err != nil {
		t.Fatalf("read %s identifiers: %v", kind, err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("scan identifier: %v", err)
		}
		out = append(out, v)
	}
	return out
}

func factValue(t *testing.T, db *sql.DB, tenantID uuid.UUID, assetID, key string) (string, bool) {
	t.Helper()
	var v string
	err := db.QueryRow(
		`SELECT value::text FROM asset_facts WHERE tenant_id = $1 AND asset_id = $2 AND key = $3`,
		tenantID, assetID, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false
	}
	if err != nil {
		t.Fatalf("read fact %s: %v", key, err)
	}
	return v, true
}

func countRows(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// TestIntegration_HostInventory_QueuesConnectionsThroughTheSharedPipeline
// pins the production wiring: the real projection reaches Materialise, the
// host is resolved first, and each valid peer becomes a sensor_discoveries row
// carrying the host's measured source address and asset id. Removing the
// writeConnections call leaves this test with zero rows.
func TestIntegration_HostInventory_QueuesConnectionsThroughTheSharedPipeline(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	jobID := newHostInventoryJob(t, appDB, owner, tenantID, agentID)

	sensorID := uuid.New()
	if _, err := owner.Exec(`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status,tags)
		VALUES($1,$2,'IT system interrogation','linux','test','device_interrogation','active',ARRAY['system'])`, sensorID, tenantID); err != nil {
		t.Fatalf("seed system sensor: %v", err)
	}

	rep := hostReport(hostinventory.ModeLocal, agentID.String(), "CONNECTION-HOST", defaultPackages())
	rep.Sections[hostinventory.SectionConnections] = hostinventory.SectionOK
	rep.Connections = []hostinventory.Connection{
		{Proto: "tcp", LocalAddress: "198.51.100.20", LocalPort: 50111, RemoteAddress: "8.8.8.8", RemotePort: 443, Process: "browser", PID: 77},
		{Proto: "tcp", LocalAddress: "198.51.100.20", LocalPort: 50112, RemoteAddress: "10.40.0.15", RemotePort: 8443, Process: "agent", PID: 78},
		// The producer normally rejects this before projection; the intake also
		// refuses it so older/malformed agents cannot mint a localhost asset.
		{Proto: "tcp", LocalAddress: "127.0.0.1", LocalPort: 50113, RemoteAddress: "127.0.0.1", RemotePort: 9000},
	}
	obs := observationsFor(t, rep)

	counts, err := NewHostInventoryIngest(appDB, owner).MaterialiseAndRecord(t.Context(), tenantID, agentID, jobID, obs)
	if err != nil {
		t.Fatalf("MaterialiseAndRecord: %v", err)
	}
	if counts.ConnectionsQueued != 2 {
		t.Fatalf("connections queued = %d, want 2: %+v", counts.ConnectionsQueued, counts)
	}

	rows, err := owner.Query(`SELECT host(source_ip),host(dest_ip),port,protocol,metadata->>'source_asset_id'
		FROM sensor_discoveries WHERE tenant_id=$1 AND batch_id=$2 ORDER BY host(dest_ip)`, tenantID, "host-inventory-connections:"+jobID.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var got int
	for rows.Next() {
		var source, dest, proto, sourceAsset string
		var port int
		if err := rows.Scan(&source, &dest, &port, &proto, &sourceAsset); err != nil {
			t.Fatal(err)
		}
		if source != "198.51.100.20" {
			t.Errorf("source_ip=%s, want host interface", source)
		}
		if sourceAsset != counts.AssetID {
			t.Errorf("source_asset_id=%s, want %s", sourceAsset, counts.AssetID)
		}
		if dest == "127.0.0.1" {
			t.Error("loopback peer reached the shared routing queue")
		}
		if proto != "tcp" || port == 0 {
			t.Errorf("connection tuple lost: %s:%d/%s", dest, port, proto)
		}
		got++
	}
	if got != 2 {
		t.Fatalf("queued rows=%d, want 2", got)
	}
}

func TestIntegration_HostInventory_FailedConnectionSnapshotIsAProcessingError(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenantID := testdb.NewTenant(t, owner)
	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	jobID := newHostInventoryJob(t, appDB, owner, tenantID, agentID)

	rep := hostReport(hostinventory.ModeLocal, agentID.String(), "CONNECTION-FAILURE-HOST", defaultPackages())
	rep.Sections[hostinventory.SectionConnections] = hostinventory.SectionFailed
	obs := observationsFor(t, rep)
	counts, err := NewHostInventoryIngest(appDB, owner).MaterialiseAndRecord(t.Context(), tenantID, agentID, jobID, obs)
	if err != nil {
		t.Fatalf("MaterialiseAndRecord: %v", err)
	}
	if counts.FullyMaterialized() {
		t.Fatalf("failed connection collection claimed full materialization: %+v", counts)
	}
	if len(counts.Errors) != 1 || !strings.Contains(counts.Errors[0], "connection collection failed") {
		t.Fatalf("processing errors = %#v, want bounded connection failure", counts.Errors)
	}
	var queued int
	if err := owner.QueryRow(`SELECT count(*) FROM sensor_discoveries WHERE tenant_id=$1 AND batch_id=$2`, tenantID, "host-inventory-connections:"+jobID.String()).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 0 {
		t.Fatalf("failed snapshot queued %d connection rows", queued)
	}
}

// ---------------------------------------------------------------------------
// the schema (unchanged from 2.11a — a job type that cannot be stored has
// nothing to materialise)
// ---------------------------------------------------------------------------

// TestIntegration_HostInventoryJob_IsAcceptedByTheSchema pins both halves of the
// schema change at once: the enum value must exist, and the CHECK must permit
// an agent-assigned host_inventory row.
//
// Mutation check: delete the POST-MIGRATIONS `ALTER TYPE ... ADD VALUE` and
// this fails on any database upgraded rather than freshly created — which is
// every customer's.
func TestIntegration_HostInventoryJob_IsAcceptedByTheSchema(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)

	jobQueue := NewJobQueueService(appDB, owner, nil)
	job, err := jobQueue.CreateJob(ctx, models.CreateDeviceJobRequest{
		TenantID: tenantID,
		JobType:  models.JobTypeHostInventory,
		AgentID:  &agentID,
		Parameters: map[string]interface{}{
			"mode":      "remote",
			"transport": "ssh",
		},
	})
	if err != nil {
		t.Fatalf("CreateJob(host_inventory): %v", err)
	}
	if job.JobType != models.JobTypeHostInventory {
		t.Errorf("job_type = %q, want %q", job.JobType, models.JobTypeHostInventory)
	}

	got, err := jobQueue.GetJobByID(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetJobByID: %v", err)
	}
	if got.JobType != models.JobTypeHostInventory {
		t.Errorf("round-tripped job_type = %q", got.JobType)
	}
	if got.AgentID == nil || *got.AgentID != agentID {
		t.Errorf("agent id was lost: %v", got.AgentID)
	}
}

// TestIntegration_HostInventoryJob_RequiresAnAgent pins the other polarity of
// the CHECK. A guard that accepts everything is not a guard.
func TestIntegration_HostInventoryJob_RequiresAnAgent(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	jobQueue := NewJobQueueService(appDB, owner, nil)

	_, err := jobQueue.CreateJob(ctx, models.CreateDeviceJobRequest{
		TenantID: tenantID,
		JobType:  models.JobTypeHostInventory,
		// no AgentID
	})
	if err == nil {
		t.Fatal("an agentless host_inventory job was accepted; valid_job_assignment is not enforcing")
	}
}

// ---------------------------------------------------------------------------
// materialisation
// ---------------------------------------------------------------------------

// TestIntegration_HostInventory_Materialises_LocalMode is the whole feature in
// one run: a local collection becomes an asset with the agent id as its
// strongest identifier, its facts, its endpoints and its software installs.
//
// It runs under the RLS role (crypto_app), not the owner. That is the
// difference between "the SQL is right" and "the SQL is right for the role the
// service actually connects as", which's serviceRls sweep is the standing
// reminder of.
func TestIntegration_HostInventory_Materialises_LocalMode(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	jobID := newHostInventoryJob(t, appDB, owner, tenantID, agentID)

	rep := hostReport(hostinventory.ModeLocal, agentID.String(), "CZ2X5Y3", defaultPackages())
	ingest := NewHostInventoryIngest(appDB, owner)

	counts, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentID, jobID, observationsFor(t, rep))
	if err != nil {
		t.Fatalf("MaterialiseAndRecord: %v", err)
	}
	if counts.AssetID == "" {
		t.Fatalf("no asset was created: %+v", counts)
	}
	if counts.Contested {
		t.Fatalf("a first collection of an unknown host was contested: %s", counts.ContestedReason)
	}
	if !counts.AssetCreated {
		t.Error("asset_created = false for a host nothing had seen before")
	}

	// --- identity ----------------------------------------------------------
	//
	// THE agent id. It is the strongest identifier the product has, it is what
	// makes a second collection land on this asset rather than mint another,
	// and 2.11a emitted it only as a fact — which cannot match anything.
	if got := identifierValues(t, owner, tenantID, counts.AssetID, "agent_id"); len(got) != 1 || got[0] != agentID.String() {
		t.Errorf("agent_id identifiers = %v, want [%s]", got, agentID)
	}
	if got := identifierValues(t, owner, tenantID, counts.AssetID, "serial_number"); len(got) != 1 || got[0] != "CZ2X5Y3" {
		t.Errorf("serial_number identifiers = %v, want [CZ2X5Y3]", got)
	}
	// PHYSICAL MACs only. A veth or a locally-administered address is
	// regenerated per boot or per container start, so identity minted from one
	// produces a new asset on every restart.
	macs := identifierValues(t, owner, tenantID, counts.AssetID, "mac_address")
	if len(macs) != 1 || macs[0] != "3c:ec:ef:11:22:33" {
		t.Errorf("mac_address identifiers = %v, want only the physical NIC [3c:ec:ef:11:22:33]", macs)
	}
	if got := identifierValues(t, owner, tenantID, counts.AssetID, "fqdn"); len(got) != 1 || got[0] != "app-01.example.net" {
		t.Errorf("fqdn identifiers = %v", got)
	}

	// The vendor-qualified PowerEdge rule classifies this measured host while
	// discovery approval remains pending. Linux alone is not server evidence.
	var classKey, classSourceKind, assetStatus string
	if err := owner.QueryRow(
		`SELECT class_key, class_source_kind, asset_status FROM assets WHERE tenant_id = $1 AND id = $2`,
		tenantID, counts.AssetID).Scan(&classKey, &classSourceKind, &assetStatus); err != nil {
		t.Fatalf("read asset: %v", err)
	}
	if classKey != "server" || classSourceKind != "rule" {
		t.Errorf("classification = %q/%q, want server/rule", classKey, classSourceKind)
	}
	if assetStatus != "pending_approval" {
		t.Errorf("asset_status = %q, want pending_approval", assetStatus)
	}

	// --- facts -------------------------------------------------------------
	for key, want := range map[string]string{
		facts.KeyOSName:                    `"Ubuntu"`,
		facts.KeyOSVersion:                 `"24.04.1 LTS"`,
		facts.KeyOSKernel:                  `"6.8.0-45-generic"`,
		facts.KeyHWVendor:                  `"Dell Inc."`,
		facts.KeyHWModel:                   `"PowerEdge R650"`,
		facts.KeyHWSerial:                  `"CZ2X5Y3"`,
		facts.KeyHWUUID:                    `"4c4c4544-0044-5010-8043-b7c04f463432"`,
		facts.KeyAgentMode:                 `"local"`,
		facts.KeyAgentID:                   `"` + agentID.String() + `"`,
		facts.KeyCertsStoreCount:           `141`,
		facts.KeyCertsNonCertificateBlocks: `1`,
	} {
		got, ok := factValue(t, owner, tenantID, counts.AssetID, key)
		if !ok {
			t.Errorf("fact %s is missing", key)
			continue
		}
		if got != want {
			t.Errorf("fact %s = %s, want %s", key, got, want)
		}
	}
	// net.interfaces and svc.listening_sockets are arrays; their presence is
	// what matters here, their shape is pinned in the collector's own tests.
	for _, key := range []string{facts.KeyNetInterfaces, facts.KeySvcListeningSockets} {
		if _, ok := factValue(t, owner, tenantID, counts.AssetID, key); !ok {
			t.Errorf("fact %s is missing", key)
		}
	}
	// The facts are written under the DEVICE-AGENT producer. Routing them
	// through device-interrogation would fail the registry check for os.kernel,
	// hw.uuid, agent.id and svc.listening_sockets, and widening those keys'
	// producer lists to make it pass would be the "one key, two meanings" bug
	// the check exists to prevent.
	if n := countRows(t, owner,
		`SELECT count(*) FROM asset_facts WHERE tenant_id = $1 AND asset_id = $2 AND source_ref = $3`,
		tenantID, counts.AssetID, "agent:"+agentID.String()); n == 0 {
		t.Error("no fact carries the agent's source_ref; provenance was lost")
	}

	// --- endpoints ---------------------------------------------------------
	//
	// One per listening socket, and the loopback one is FLAGGED rather than
	// dropped: a service bound to 127.0.0.1 is the thing a network scan can
	// never see, which is most of why a local collection is worth having.
	type endpointRow struct {
		address     string
		port        int
		transport   string
		serviceName sql.NullString
		boundLocal  sql.NullBool
	}
	rows, err := owner.Query(
		`SELECT host(address), port, transport, service_name, bound_local
		   FROM asset_endpoints WHERE tenant_id = $1 AND asset_id = $2 ORDER BY port`,
		tenantID, counts.AssetID)
	if err != nil {
		t.Fatalf("read endpoints: %v", err)
	}
	defer func() { _ = rows.Close() }()
	got := map[int]endpointRow{}
	for rows.Next() {
		var e endpointRow
		if err := rows.Scan(&e.address, &e.port, &e.transport, &e.serviceName, &e.boundLocal); err != nil {
			t.Fatalf("scan endpoint: %v", err)
		}
		got[e.port] = e
	}
	if len(got) != 3 {
		t.Fatalf("endpoints = %d, want 3 (one per listening socket): %+v", len(got), got)
	}
	// A WILDCARD bind is not an address. 0.0.0.0 in asset_endpoints.address is
	// the placeholder row the passive path had to be stopped from creating, so
	// the endpoint takes the host's own primary address instead.
	if e := got[22]; e.address != "198.51.100.20" || e.transport != "tcp" {
		t.Errorf("the 0.0.0.0-bound sshd endpoint is %+v; a wildcard bind must resolve to the host's own address", e)
	}
	if e := got[22]; !e.serviceName.Valid || e.serviceName.String != "sshd" {
		t.Errorf("the process name was lost: %+v", e)
	}
	if e := got[22]; !e.boundLocal.Valid || e.boundLocal.Bool {
		t.Errorf("bound_local for a 0.0.0.0 socket = %v, want an explicit false", e.boundLocal)
	}
	if e := got[5432]; e.address != "127.0.0.1" || !e.boundLocal.Valid || !e.boundLocal.Bool {
		t.Errorf("the loopback-only postgres socket is %+v, want address 127.0.0.1 and bound_local true", e)
	}
	if e := got[161]; e.transport != "udp" {
		t.Errorf("the UDP socket's transport = %q", e.transport)
	}

	// --- software ----------------------------------------------------------
	if counts.InstallsCreated != 3 {
		t.Errorf("installs_created = %d, want 3", counts.InstallsCreated)
	}
	if counts.PackagesEnumerated == nil || *counts.PackagesEnumerated != 3 {
		t.Errorf("packages_enumerated = %v, want 3", counts.PackagesEnumerated)
	}
	if n := countRows(t, owner, `SELECT count(*) FROM software_products WHERE tenant_id = $1`, tenantID); n != 3 {
		t.Errorf("software_products = %d, want 3", n)
	}
	// The NULL-not-'' rule. software.Product.Identity gives a purl-less product
	// a distinct name@version; storing '' for the missing purl would key every
	// one of them on that single string, and the second would collide with the
	// first. There is one purl-less product here, so this is the polarity that
	// proves the column is NULL rather than ''.
	if n := countRows(t, owner,
		`SELECT count(*) FROM software_products WHERE tenant_id = $1 AND purl IS NULL`, tenantID); n != 1 {
		t.Errorf("purl-less products stored with a NULL purl = %d, want 1", n)
	}
	if n := countRows(t, owner,
		`SELECT count(*) FROM software_products WHERE tenant_id = $1 AND purl = ''`, tenantID); n != 0 {
		t.Errorf("%d product(s) stored an EMPTY purl; coalesce takes '' as a value and they all key on it", n)
	}
	if n := countRows(t, owner,
		`SELECT count(*) FROM software_installs WHERE tenant_id = $1 AND asset_id = $2 AND source_kind = 'measured' AND status = 'active'`,
		tenantID, counts.AssetID); n != 3 {
		t.Errorf("active measured installs = %d, want 3", n)
	}
	// sw.package_count is written from the ROWS, not from the collector's count.
	if v, ok := factValue(t, owner, tenantID, counts.AssetID, facts.KeySWPackageCount); !ok || v != "3" {
		t.Errorf("%s = %q (present=%t), want 3", facts.KeySWPackageCount, v, ok)
	}

	// --- the job row -------------------------------------------------------
	//
	// The counts replace 2.11a's `fatal` line. A run that materialised a host,
	// 18 facts and 3 installs must not still be reporting `materialized: 0`.
	var rawResults []byte
	if err := owner.QueryRow(`SELECT results FROM device_jobs WHERE id = $1`, jobID).Scan(&rawResults); err != nil {
		t.Fatalf("read back results: %v", err)
	}
	var stored struct {
		Processing struct {
			Materialized      int    `json:"materialized"`
			FullyMaterialized bool   `json:"fully_materialized"`
			Fatal             string `json:"fatal"`
			HostInventory     *struct {
				AssetID         string `json:"asset_id"`
				Facts           int    `json:"facts"`
				Endpoints       int    `json:"endpoints"`
				InstallsCreated int    `json:"installs_created"`
			} `json:"host_inventory"`
		} `json:"processing"`
	}
	if err := json.Unmarshal(rawResults, &stored); err != nil {
		t.Fatalf("decode results: %v", err)
	}
	if stored.Processing.Fatal != "" {
		t.Errorf("the job row still carries a fatal line: %q", stored.Processing.Fatal)
	}
	if stored.Processing.Materialized != 1 {
		t.Errorf("materialized = %d, want 1 (one HOST, not a sum of its parts)", stored.Processing.Materialized)
	}
	if !stored.Processing.FullyMaterialized {
		t.Error("fully_materialized = false for a run that landed everything")
	}
	if stored.Processing.HostInventory == nil {
		t.Fatal("the job row carries no host_inventory count block")
	}
	if stored.Processing.HostInventory.AssetID != counts.AssetID ||
		stored.Processing.HostInventory.InstallsCreated != 3 ||
		stored.Processing.HostInventory.Endpoints != 3 {
		t.Errorf("the job row's counts disagree with the run: %+v", *stored.Processing.HostInventory)
	}
}

// TestIntegration_HostInventory_Materialises_SecondReportRefreshesInstalls is
// the property the whole identity apparatus exists for: collect the same host
// twice and get ONE asset, with its software inventory brought up to date
// rather than appended to.
//
// It also pins removed-not-deleted. A package that is gone must keep its
// `first_seen_at`, so "this library was here in March and is gone now" stays
// answerable; a DELETE would make the question unanswerable and would look
// identical from the count.
func TestIntegration_HostInventory_Materialises_SecondReportRefreshesInstalls(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	ingest := NewHostInventoryIngest(appDB, owner)

	first := hostReport(hostinventory.ModeLocal, agentID.String(), "CZ2X5Y3", defaultPackages())
	firstCounts, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentID,
		newHostInventoryJob(t, appDB, owner, tenantID, agentID), observationsFor(t, first))
	if err != nil {
		t.Fatalf("first collection: %v", err)
	}

	// The second run: curl is gone, openssl moved to a new version, and a new
	// package appeared.
	second := hostReport(hostinventory.ModeLocal, agentID.String(), "CZ2X5Y3", []hostinventory.Package{
		{Name: "openssl", Version: "3.0.14", Manager: "dpkg", Arch: "amd64", PURL: "pkg:deb/ubuntu/openssl@3.0.14"},
		{Name: "vendor-agent", Version: "1.4.2", Manager: "vendor"},
		{Name: "nginx", Version: "1.24.0", Manager: "dpkg", Arch: "amd64", PURL: "pkg:deb/ubuntu/nginx@1.24.0"},
	})
	secondCounts, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentID,
		newHostInventoryJob(t, appDB, owner, tenantID, agentID), observationsFor(t, second))
	if err != nil {
		t.Fatalf("second collection: %v", err)
	}

	if secondCounts.AssetID != firstCounts.AssetID {
		t.Fatalf("the second collection landed on asset %s, the first on %s — one host became two",
			secondCounts.AssetID, firstCounts.AssetID)
	}
	if secondCounts.AssetCreated {
		t.Error("asset_created = true on the second collection of the same host")
	}
	if n := countRows(t, owner, `SELECT count(*) FROM assets WHERE tenant_id = $1`, tenantID); n != 1 {
		t.Errorf("assets = %d, want 1", n)
	}

	// curl is REMOVED, not deleted. The row has to still be there.
	var status string
	var firstSeen, lastSeen time.Time
	err = owner.QueryRow(`
		SELECT i.status, i.first_seen_at, i.last_seen_at
		  FROM software_installs i JOIN software_products p ON p.id = i.product_id
		 WHERE i.tenant_id = $1 AND i.asset_id = $2 AND p.name = 'curl'`,
		tenantID, secondCounts.AssetID).Scan(&status, &firstSeen, &lastSeen)
	if err == sql.ErrNoRows {
		t.Fatal("the absent package's install row was DELETED; `removed` is what keeps \"it was here in March\" answerable")
	}
	if err != nil {
		t.Fatalf("read curl install: %v", err)
	}
	if status != "removed" {
		t.Errorf("curl's install status = %q, want removed", status)
	}
	// TWO removals, not one: curl is gone, and so is openssl 3.0.13. A version
	// change is a different catalogue row (the purl carries the version), so an
	// UPGRADE reads as the old version's install going `removed` and the new
	// one being created. That is what keeps "this host moved from openssl
	// 3.0.13 to 3.0.14, and here is when" answerable at all — collapsing the
	// two onto one row would make an upgrade indistinguishable from no change.
	if secondCounts.InstallsRemoved != 2 {
		t.Errorf("installs_removed = %d, want 2 (curl, and the superseded openssl 3.0.13)", secondCounts.InstallsRemoved)
	}
	if secondCounts.InstallsCreated != 2 {
		t.Errorf("installs_created = %d, want 2 (openssl 3.0.14 and nginx)", secondCounts.InstallsCreated)
	}

	// vendor-agent is unchanged and must have been refreshed, not re-created.
	if secondCounts.InstallsUpdated < 1 {
		t.Errorf("installs_updated = %d; a package present in both runs must be refreshed, not duplicated", secondCounts.InstallsUpdated)
	}
	// A NEW VERSION of openssl is a different product (the purl carries the
	// version), so the catalogue holds both and only the new one is installed.
	if n := countRows(t, owner,
		`SELECT count(*) FROM software_products WHERE tenant_id = $1 AND name = 'openssl'`, tenantID); n != 2 {
		t.Errorf("openssl catalogue rows = %d, want 2 (3.0.13 and 3.0.14)", n)
	}
	if n := countRows(t, owner,
		`SELECT count(*) FROM software_installs WHERE tenant_id = $1 AND asset_id = $2 AND status = 'active'`,
		tenantID, secondCounts.AssetID); n != 3 {
		t.Errorf("active installs after the second run = %d, want 3", n)
	}
	if v, ok := factValue(t, owner, tenantID, secondCounts.AssetID, facts.KeySWPackageCount); !ok || v != "3" {
		t.Errorf("%s = %q after the second run, want 3", facts.KeySWPackageCount, v)
	}

	// And the endpoints did not double: the same three sockets, upserted.
	if n := countRows(t, owner,
		`SELECT count(*) FROM asset_endpoints WHERE tenant_id = $1 AND asset_id = $2`,
		tenantID, secondCounts.AssetID); n != 3 {
		t.Errorf("endpoints after two collections = %d, want 3", n)
	}
}

// TestIntegration_HostInventory_Materialises_RemoteModeHasNoAgentID pins the
// other half of the agent-id rule.
//
// In remote mode the agent is not the thing being described — it reached the
// host over SSH — and stamping its installation id on that host would give two
// assets one identity, which is the strongest identifier in the product
// pointing at the wrong machine.
//
// Mutation check: drop the `rep.Mode == ModeLocal` condition in hostPeerRef and
// this fails.
func TestIntegration_HostInventory_Materialises_RemoteModeHasNoAgentID(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	jobID := newHostInventoryJob(t, appDB, owner, tenantID, agentID)

	// A remote report: the collector leaves AgentID empty, because the agent is
	// not the subject.
	rep := hostReport(hostinventory.ModeRemote, "", "CZ2X5Y3", defaultPackages())
	counts, err := NewHostInventoryIngest(appDB, owner).
		MaterialiseAndRecord(ctx, tenantID, agentID, jobID, observationsFor(t, rep))
	if err != nil {
		t.Fatalf("MaterialiseAndRecord: %v", err)
	}
	if counts.AssetID == "" {
		t.Fatalf("no asset was created: %+v", counts)
	}
	if got := identifierValues(t, owner, tenantID, counts.AssetID, "agent_id"); len(got) != 0 {
		t.Errorf("a REMOTE collection attached agent_id %v; the agent is not the host it reached", got)
	}
	// It is still identified — by the things a remote session can establish.
	if got := identifierValues(t, owner, tenantID, counts.AssetID, "serial_number"); len(got) != 1 {
		t.Errorf("serial_number identifiers = %v, want one", got)
	}
	if v, ok := factValue(t, owner, tenantID, counts.AssetID, facts.KeyAgentMode); !ok || v != `"remote"` {
		t.Errorf("%s = %q (present=%t), want \"remote\"", facts.KeyAgentMode, v, ok)
	}
	// agent.id is a LOCAL-only fact for the same reason.
	if _, ok := factValue(t, owner, tenantID, counts.AssetID, facts.KeyAgentID); ok {
		t.Error("a remote collection wrote agent.id; the mode bounds what the report may claim")
	}
}

// TestIntegration_HostInventory_Materialises_ContestedSerialOpensAProposal is
// the singleton guard, reached through this path.
//
// The scenario is a real one and it is not rare: an agent id that has been
// carried onto different hardware (a restored image, a cloned VM, a
// replacement chassis with the agent's state directory copied over). agent_id
// matches the asset we know; the SERIAL says this is a different machine. Two
// different serials are two different chassis whatever else they share, so the
// engine opens a merge proposal rather than quietly putting a second serial on
// one asset — which is the auto-merge ADR-0002 D5 forbids, arriving through the
// door marked "matched".
//
// Mutation check: make identity.Kind.Singleton return false for serial_number
// and this fails — the second report matches the first asset and silently gives
// it two serials.
func TestIntegration_HostInventory_Materialises_ContestedSerialOpensAProposal(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	ingest := NewHostInventoryIngest(appDB, owner)

	first := hostReport(hostinventory.ModeLocal, agentID.String(), "CZ2X5Y3", defaultPackages())
	firstCounts, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentID,
		newHostInventoryJob(t, appDB, owner, tenantID, agentID), observationsFor(t, first))
	if err != nil {
		t.Fatalf("first collection: %v", err)
	}

	// Placement is now available, but this contested observation must not project it.
	location := uuid.New()
	if _, err := owner.Exec(`INSERT INTO locations(id,tenant_id,name,location_type) VALUES($1,$2,'Contested Site','site')`, location, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`INSERT INTO network_segments(tenant_id,name,segment_type,value,environment,location_id) VALUES($1,'Contested','cidr','198.51.100.0/24','production',$2)`, tenantID, location); err != nil {
		t.Fatal(err)
	}
	// Same agent id, DIFFERENT serial.
	second := hostReport(hostinventory.ModeLocal, agentID.String(), "DIFFERENT-CHASSIS", defaultPackages())
	secondCounts, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentID,
		newHostInventoryJob(t, appDB, owner, tenantID, agentID), observationsFor(t, second))
	if err != nil {
		t.Fatalf("second collection: %v", err)
	}

	if !secondCounts.Contested {
		t.Fatalf("a disagreeing serial was not contested: %+v", secondCounts)
	}
	if n := countRows(t, owner, `SELECT count(*) FROM assets WHERE tenant_id=$1 AND (location_id IS NOT NULL OR coalesce(site,'')<>'')`, tenantID); n != 0 {
		t.Fatalf("contested placement projected onto %d assets", n)
	}
	if secondCounts.AssetID == firstCounts.AssetID {
		t.Fatal("the second chassis was folded onto the first asset; that is the auto-merge ADR-0002 D5 forbids")
	}
	// The first asset keeps exactly one serial. Two serials on one asset is the
	// state this guard exists to prevent, and it is invisible from a count of
	// assets alone.
	if got := identifierValues(t, owner, tenantID, firstCounts.AssetID, "serial_number"); len(got) != 1 || got[0] != "CZ2X5Y3" {
		t.Errorf("the original asset's serials = %v, want only [CZ2X5Y3]", got)
	}
	// A human has something to settle, and it is in the queue. Merge proposals
	// live in asset_history under the `merge_proposed` action.
	if n := countRows(t, owner,
		`SELECT count(*) FROM asset_history WHERE tenant_id = $1 AND action = 'merge_proposed'`, tenantID); n == 0 {
		t.Error("no merge proposal was opened; a contested identity with no proposal is a silent drop")
	}
	if secondCounts.ContestedReason == "" {
		t.Error("the run does not say WHY it was contested")
	}
}

// TestIntegration_HostInventory_Materialises_FailedPackageStepWritesNoInstalls
// is the sweep guard, and it is the one that would cost a customer real data.
//
// A host whose `dpkg` could not be read reports `packages: failed` and an empty
// list. Treating that as "no packages" runs the absent-install sweep over an
// empty set and marks the host's ENTIRE software inventory removed — from a
// step that failed.
//
// The guard is the collector's own three-valued contract: sw.package_count is
// emitted only for a section that SUCCEEDED, so its presence is what licenses
// the write. Mutation check: key the write on `len(packages) >= 0` instead and
// this fails.
func TestIntegration_HostInventory_Materialises_FailedPackageStepWritesNoInstalls(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	ingest := NewHostInventoryIngest(appDB, owner)

	// A good run first, so there is a software inventory to lose.
	good := hostReport(hostinventory.ModeLocal, agentID.String(), "CZ2X5Y3", defaultPackages())
	goodCounts, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentID,
		newHostInventoryJob(t, appDB, owner, tenantID, agentID), observationsFor(t, good))
	if err != nil {
		t.Fatalf("first collection: %v", err)
	}

	// Then one where the package step failed.
	broken := hostReport(hostinventory.ModeLocal, agentID.String(), "CZ2X5Y3", nil)
	broken.Sections[hostinventory.SectionPackages] = hostinventory.SectionFailed
	brokenCounts, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentID,
		newHostInventoryJob(t, appDB, owner, tenantID, agentID), observationsFor(t, broken))
	if err != nil {
		t.Fatalf("second collection: %v", err)
	}

	if brokenCounts.PackagesEnumerated != nil {
		t.Errorf("packages_enumerated = %v for a FAILED package step; absence is what says the step did not answer", brokenCounts.PackagesEnumerated)
	}
	if brokenCounts.InstallsRemoved != 0 {
		t.Errorf("installs_removed = %d after a failed package step", brokenCounts.InstallsRemoved)
	}
	if n := countRows(t, owner,
		`SELECT count(*) FROM software_installs WHERE tenant_id = $1 AND asset_id = $2 AND status = 'active'`,
		tenantID, goodCounts.AssetID); n != 3 {
		t.Errorf("active installs after a FAILED package step = %d, want the 3 the last good run recorded", n)
	}
	// The rest of the collection still landed: a failed section costs its own
	// facts, not the run.
	if v, ok := factValue(t, owner, tenantID, goodCounts.AssetID, facts.KeyOSKernel); !ok || v == "" {
		t.Error("a failed package step lost the whole collection")
	}
}

// TestIntegration_HostInventory_Materialises_AMissingPackageListSweepsNothing
// is the OTHER way a host loses its whole software inventory, and the failed
// step above does not cover it.
//
// `sw.package_count` being present says the package STEP succeeded. It cannot
// say the resulting LIST reached us: the count travels as a fact and the list
// travels in `device_info.packages`, two different fields of two different
// halves of the submission that are lost independently. A payload carrying the
// count and not the list arrives with a SUCCEEDED section and no products, and
// the sweep — which marks everything this run did not touch `removed` — then
// retires the host's entire measured inventory on the strength of a transport
// gap.
//
// Mutation check: delete the softwareListArrived call in Materialise and this
// fails with three installs gone to `removed`.
func TestIntegration_HostInventory_Materialises_AMissingPackageListSweepsNothing(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	ingest := NewHostInventoryIngest(appDB, owner)

	// A good run first, so there is a software inventory to lose.
	good := hostReport(hostinventory.ModeLocal, agentID.String(), "CZ2X5Y3", defaultPackages())
	goodCounts, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentID,
		newHostInventoryJob(t, appDB, owner, tenantID, agentID), observationsFor(t, good))
	if err != nil {
		t.Fatalf("first collection: %v", err)
	}

	// Then a run whose package list did not arrive. The section still says OK
	// and sw.package_count still says 3 — which is exactly the payload a client
	// that trimmed the wrong copy, or a lossy result envelope, produces.
	truncated := observationsFor(t, hostReport(hostinventory.ModeLocal, agentID.String(), "CZ2X5Y3", defaultPackages()))
	delete(truncated.DeviceInfo, "packages")

	counts, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentID,
		newHostInventoryJob(t, appDB, owner, tenantID, agentID), truncated)
	if err != nil {
		t.Fatalf("truncated collection: %v", err)
	}

	if counts.InstallsRemoved != 0 {
		t.Errorf("installs_removed = %d for a payload whose package list never arrived", counts.InstallsRemoved)
	}
	if counts.InstallsCreated != 0 {
		t.Errorf("installs_created = %d; nothing arrived to create", counts.InstallsCreated)
	}
	if n := countRows(t, owner,
		`SELECT count(*) FROM software_installs WHERE tenant_id = $1 AND asset_id = $2 AND status = 'active'`,
		tenantID, goodCounts.AssetID); n != 3 {
		t.Errorf("active installs = %d, want the 3 the last run that actually carried a list recorded", n)
	}
	// The package-count fact keeps the last real answer too. Rewriting it to 0
	// would state that a query returns nothing, which is not what happened.
	if v, ok := factValue(t, owner, tenantID, goodCounts.AssetID, facts.KeySWPackageCount); !ok || v != "3" {
		t.Errorf("%s = %q (present=%t) after a truncated payload, want the last measured 3", facts.KeySWPackageCount, v, ok)
	}
	// And it is SAID. A refusal nobody can see is the silent drop with extra
	// steps; this is the line an operator reads on the job row.
	if len(counts.Errors) == 0 {
		t.Fatal("the run reports no error for a payload whose package list did not arrive")
	}
	if !strings.Contains(strings.Join(counts.Errors, " "), "did not arrive") {
		t.Errorf("the reported errors do not say the list was missing: %v", counts.Errors)
	}
	// The rest of the collection still landed: a missing list costs the
	// software half, not the run.
	if counts.AssetID != goodCounts.AssetID {
		t.Errorf("the truncated collection landed on %s, not the host's asset %s", counts.AssetID, goodCounts.AssetID)
	}
	if v, ok := factValue(t, owner, tenantID, goodCounts.AssetID, facts.KeyOSKernel); !ok || v == "" {
		t.Error("a missing package list lost the whole collection")
	}
}

// endpointRows reads an asset's endpoints as port → status.
func endpointRows(t *testing.T, db *sql.DB, tenantID uuid.UUID, assetID string) map[int]string {
	t.Helper()
	rows, err := db.Query(
		`SELECT coalesce(port, -1), status FROM asset_endpoints WHERE tenant_id = $1 AND asset_id = $2`,
		tenantID, assetID)
	if err != nil {
		t.Fatalf("read endpoints: %v", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[int]string{}
	for rows.Next() {
		var port int
		var status string
		if err := rows.Scan(&port, &status); err != nil {
			t.Fatalf("scan endpoint: %v", err)
		}
		out[port] = status
	}
	return out
}

// TestIntegration_HostInventory_Materialises_AbsentListenerIsClosed is the
// endpoint half of removed-not-deleted.
//
// A host inventory reads the machine's OWN socket table, so it is the only
// source that can say "nothing is listening on 5432 any more" — a scan can only
// ever report what answered. A socket absent from a good report has stopped
// listening, and leaving it `active` forever is the silence this workstream
// exists to end.
//
// `closed`, never DELETE: crypto_implementations, external_connections and
// ssh_keys all reference endpoint rows, and the history is the point besides.
//
// Mutation check: delete the closeAbsentEndpoints call and the retired socket
// stays `active`; make the endpoint source ref stable per-agent instead of
// per-run and NOTHING is ever closed, which is the vacuously-false-test trap
// the install sweep documents.
func TestIntegration_HostInventory_Materialises_AbsentListenerIsClosed(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	ingest := NewHostInventoryIngest(appDB, owner)

	first := hostReport(hostinventory.ModeLocal, agentID.String(), "CZ2X5Y3", defaultPackages())
	firstCounts, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentID,
		newHostInventoryJob(t, appDB, owner, tenantID, agentID), observationsFor(t, first))
	if err != nil {
		t.Fatalf("first collection: %v", err)
	}
	if firstCounts.EndpointsClosed != 0 {
		t.Errorf("endpoints_closed = %d on a first collection", firstCounts.EndpointsClosed)
	}

	// An endpoint some OTHER source recorded. A host inventory is authoritative
	// about the host's own sockets and NOT about what anything else observed,
	// so this must survive the sweep untouched.
	if _, err := owner.Exec(`
		INSERT INTO asset_endpoints (tenant_id, asset_id, address, port, transport, source_kind, source_ref, status)
		VALUES ($1, $2, '198.51.100.20'::inet, 8443, 'tcp', 'measured', 'scan:active-scan-run-1', 'active')`,
		tenantID, firstCounts.AssetID); err != nil {
		t.Fatalf("seed a scan-sourced endpoint: %v", err)
	}

	// Second collection: postgres has stopped listening, sshd and snmpd have
	// not, and a new socket appeared.
	second := hostReport(hostinventory.ModeLocal, agentID.String(), "CZ2X5Y3", defaultPackages())
	second.Listeners = []hostinventory.Listener{
		{Proto: "tcp", Address: "0.0.0.0", Port: 22, Process: "sshd", PID: 812},
		{Proto: "udp", Address: "198.51.100.20", Port: 161, Process: "snmpd"},
		{Proto: "tcp", Address: "198.51.100.20", Port: 8080, Process: "nginx"},
	}
	secondCounts, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentID,
		newHostInventoryJob(t, appDB, owner, tenantID, agentID), observationsFor(t, second))
	if err != nil {
		t.Fatalf("second collection: %v", err)
	}
	if secondCounts.AssetID != firstCounts.AssetID {
		t.Fatalf("the second collection landed on a different asset")
	}
	if secondCounts.EndpointsClosed != 1 {
		t.Errorf("endpoints_closed = %d, want 1 (the retired postgres socket)", secondCounts.EndpointsClosed)
	}

	got := endpointRows(t, owner, tenantID, secondCounts.AssetID)
	if got[5432] != "closed" {
		t.Errorf("the retired postgres socket is %q, want closed", got[5432])
	}
	if _, stillThere := got[5432]; !stillThere {
		t.Error("the retired socket row was DELETED; crypto configurations and external connections point at these rows")
	}
	for _, port := range []int{22, 161, 8080} {
		if got[port] != "active" {
			t.Errorf("port %d is %q, want active", port, got[port])
		}
	}
	// The scan's endpoint is NOT this source's to retire.
	if got[8443] != "active" {
		t.Errorf("a scan-sourced endpoint was %q; a host inventory must not close what another source observed", got[8443])
	}

	// And a socket that comes back goes active again, with its history intact.
	third := hostReport(hostinventory.ModeLocal, agentID.String(), "CZ2X5Y3", defaultPackages())
	thirdCounts, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentID,
		newHostInventoryJob(t, appDB, owner, tenantID, agentID), observationsFor(t, third))
	if err != nil {
		t.Fatalf("third collection: %v", err)
	}
	got = endpointRows(t, owner, tenantID, thirdCounts.AssetID)
	if got[5432] != "active" {
		t.Errorf("a socket that came back is %q, want active", got[5432])
	}
	// 8080 is gone again in the third report, so it closes.
	if got[8080] != "closed" {
		t.Errorf("port 8080 is %q after disappearing, want closed", got[8080])
	}
}

// TestIntegration_HostInventory_Materialises_FailedListenerStepClosesNothing is
// the other polarity, and it is the one that would cost a customer a working
// inventory.
//
// A host whose `ss` could not be run reports `listeners: failed` and an empty
// list. Closing on that reports every service on the machine as stopped because
// one command was unavailable — the same shape as sweeping installs after a
// failed `dpkg`.
//
// Mutation check: drop the section gate in listenerListArrived and this fails
// with three live sockets marked closed.
func TestIntegration_HostInventory_Materialises_FailedListenerStepClosesNothing(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	ingest := NewHostInventoryIngest(appDB, owner)

	good := hostReport(hostinventory.ModeLocal, agentID.String(), "CZ2X5Y3", defaultPackages())
	goodCounts, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentID,
		newHostInventoryJob(t, appDB, owner, tenantID, agentID), observationsFor(t, good))
	if err != nil {
		t.Fatalf("first collection: %v", err)
	}

	broken := hostReport(hostinventory.ModeLocal, agentID.String(), "CZ2X5Y3", defaultPackages())
	broken.Listeners = nil
	broken.Sections[hostinventory.SectionListeners] = hostinventory.SectionFailed
	brokenCounts, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentID,
		newHostInventoryJob(t, appDB, owner, tenantID, agentID), observationsFor(t, broken))
	if err != nil {
		t.Fatalf("second collection: %v", err)
	}

	if brokenCounts.EndpointsClosed != 0 {
		t.Errorf("endpoints_closed = %d after a FAILED listeners step", brokenCounts.EndpointsClosed)
	}
	got := endpointRows(t, owner, tenantID, goodCounts.AssetID)
	for _, port := range []int{22, 161, 5432} {
		if got[port] != "active" {
			t.Errorf("port %d is %q after a failed listeners step, want active", port, got[port])
		}
	}
	// A failed section is a NORMAL outcome, not an error on the job row.
	for _, e := range brokenCounts.Errors {
		if strings.Contains(e, "endpoint") {
			t.Errorf("a failed listeners section was reported as an error: %q", e)
		}
	}

	// A payload whose sockets were LOST in transit is a different matter: the
	// fact says there were sockets and none arrived, so the run says so and
	// still closes nothing.
	truncated := observationsFor(t, hostReport(hostinventory.ModeLocal, agentID.String(), "CZ2X5Y3", defaultPackages()))
	truncated.Assets = nil
	lostCounts, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentID,
		newHostInventoryJob(t, appDB, owner, tenantID, agentID), truncated)
	if err != nil {
		t.Fatalf("truncated collection: %v", err)
	}
	if lostCounts.EndpointsClosed != 0 {
		t.Errorf("endpoints_closed = %d for a payload whose sockets never arrived", lostCounts.EndpointsClosed)
	}
	if !strings.Contains(strings.Join(lostCounts.Errors, " "), "did not arrive") {
		t.Errorf("the lost socket list was not reported: %v", lostCounts.Errors)
	}
	got = endpointRows(t, owner, tenantID, goodCounts.AssetID)
	for _, port := range []int{22, 161, 5432} {
		if got[port] != "active" {
			t.Errorf("port %d is %q after a lost socket list, want active", port, got[port])
		}
	}
}

// TestIntegration_HostInventory_Materialises_TheIdentityFloorClaimsNothing is
// the counts half of ADR-0002 D3's floor erratum.
//
// When EVERY identifier the report carries is already owned by other assets and
// none of them may decide, the engine opens a merge proposal and creates
// nothing — inventing an asset would produce the identifier-less row the floor
// exists to prevent. There is then nothing to hang facts, endpoints or installs
// on, and the counts must say so.
//
// `identifiers` is the one that used to lie: it was set from what the
// observation OFFERED, before resolution, so a run that wrote nothing still
// reported five. Every number on this block is what the run WROTE — a job row
// claiming identifiers sends somebody looking for rows that are not there, and
// what the report carried is still on the row in full.
//
// Mutation check: delete `counts.Identifiers = 0` and this fails with 5.
func TestIntegration_HostInventory_Materialises_TheIdentityFloorClaimsNothing(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	ingest := NewHostInventoryIngest(appDB, owner)

	// Asset A: one host, one agent.
	agentA := seedHostInventoryAgent(t, owner, tenantID)
	repA := hostReport(hostinventory.ModeLocal, agentA.String(), "SERIAL-A", defaultPackages())
	countsA, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentA,
		newHostInventoryJob(t, appDB, owner, tenantID, agentA), observationsFor(t, repA))
	if err != nil {
		t.Fatalf("asset A: %v", err)
	}

	// Asset B: a completely separate host — different agent, serial, MAC and
	// names, so nothing it carries is shared with A.
	agentB := seedHostInventoryAgent(t, owner, tenantID)
	repB := hostReport(hostinventory.ModeLocal, agentB.String(), "SERIAL-B", defaultPackages())
	repB.Interfaces[0].MAC = "3c:ec:ef:44:55:66"
	repB.Host.Hostname, repB.Host.FQDN = "app-02", "app-02.example.net"
	countsB, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentB,
		newHostInventoryJob(t, appDB, owner, tenantID, agentB), observationsFor(t, repB))
	if err != nil {
		t.Fatalf("asset B: %v", err)
	}
	if countsB.AssetID == countsA.AssetID {
		t.Fatalf("the two fixtures collapsed onto one asset; the floor cannot be reached")
	}

	// Now a report every identifier of which is spoken for, by TWO different
	// assets: A's agent id and names, B's serial. Two singletons pointing at two
	// assets, and nothing left over for the engine to create from.
	floor := hostReport(hostinventory.ModeLocal, agentA.String(), "SERIAL-B", defaultPackages())
	floorCounts, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentA,
		newHostInventoryJob(t, appDB, owner, tenantID, agentA), observationsFor(t, floor))
	if err != nil {
		t.Fatalf("floor collection: %v", err)
	}

	if floorCounts.AssetID != "" {
		t.Skipf("the engine created asset %s rather than hitting the floor; "+
			"this fixture no longer reaches outcome-three-with-nothing-unowned", floorCounts.AssetID)
	}
	if !floorCounts.Contested {
		t.Error("a run that created nothing is not reported as contested")
	}
	if floorCounts.Identifiers != 0 {
		t.Errorf("identifiers = %d for a run that wrote none; the counts are what the run WROTE, "+
			"not what the report offered", floorCounts.Identifiers)
	}
	if floorCounts.Endpoints != 0 {
		t.Errorf("endpoints = %d for a run that created no asset", floorCounts.Endpoints)
	}
	if floorCounts.Materialized() != 0 || floorCounts.FullyMaterialized() {
		t.Errorf("materialized = %d, fully = %t", floorCounts.Materialized(), floorCounts.FullyMaterialized())
	}
	// And nothing was written anywhere under a third asset.
	if n := countRows(t, owner, `SELECT count(*) FROM assets WHERE tenant_id = $1`, tenantID); n != 2 {
		t.Errorf("assets = %d, want the original 2", n)
	}
}

// TestIntegration_HostInventory_ShowsOnTheAgentFleet pins the reachability
// half: the collection has to be VISIBLE to the person who deployed the agent.
//
// A host-inventory collection is not work an operator queued — it is the agent
// describing its own host on its own timer — so "47 jobs, 2h ago" says nothing
// about whether it is happening. An agent that is busy interrogating firewalls
// and has never reported its own host is a normal, invisible misconfiguration
// (HOST_INVENTORY_ENABLED unset), and these three fields are what make it
// visible on Discovery → Sensors & Agents.
//
// Mutation check: delete the `hi` LATERAL in ListAgents and this fails.
func TestIntegration_HostInventory_ShowsOnTheAgentFleet(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	agents := NewAgentService(appDB, owner, nil)

	// Before any collection: the agent exists and has reported nothing. The
	// three fields are nil TOGETHER, and a zero package count would be a lie —
	// nobody has enumerated this host.
	before, err := agents.ListAgents(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(before) != 1 {
		t.Fatalf("agents = %d, want 1", len(before))
	}
	if before[0].LastHostInventoryAt != nil || before[0].HostInventoryPackages != nil {
		t.Errorf("an agent that has never reported shows %v / %v; nil is the only honest answer",
			before[0].LastHostInventoryAt, before[0].HostInventoryPackages)
	}

	rep := hostReport(hostinventory.ModeLocal, agentID.String(), "CZ2X5Y3", defaultPackages())
	if _, err := NewHostInventoryIngest(appDB, owner).MaterialiseAndRecord(
		ctx, tenantID, agentID, newHostInventoryJob(t, appDB, owner, tenantID, agentID),
		observationsFor(t, rep)); err != nil {
		t.Fatalf("MaterialiseAndRecord: %v", err)
	}

	after, err := agents.ListAgents(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListAgents after: %v", err)
	}
	a := after[0]
	if a.LastHostInventoryAt == nil {
		t.Fatal("the fleet row does not show the collection at all")
	}
	if a.HostInventoryPackages == nil || *a.HostInventoryPackages != 3 {
		t.Errorf("host_inventory_packages = %v, want 3", a.HostInventoryPackages)
	}
	if a.HostInventoryListeners == nil || *a.HostInventoryListeners != 3 {
		t.Errorf("host_inventory_listeners = %v, want 3", a.HostInventoryListeners)
	}
}

// TestIntegration_ProcessJobResults_MaterialisesRemoteHostInventory drives the
// REMOTE path end to end, through the result processor.
//
// This is the wiring test, not the logic test.'s lesson is that a fix can
// compile, pass its unit tests and never run in production because the thing
// that calls it was not wired: deleting the `deviceJob.JobType ==
// JobTypeHostInventory` branch makes this fail, while every unit test of the
// materialiser stays green.
//
// It also pins the OTHER polarity of the 2.11a hold, which the branch replaced:
// a host inventory must not produce discovery findings or sensor_discoveries
// rows, because a socket is not a crypto finding and a 127.0.0.1 endpoint is
// not a connection between two endpoints.
func TestIntegration_ProcessJobResults_MaterialisesRemoteHostInventory(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	jobID := newHostInventoryJob(t, appDB, owner, tenantID, agentID)

	rep := hostReport(hostinventory.ModeRemote, "", "CZ2X5Y3", defaultPackages())
	obs := observationsFor(t, rep)

	// The shape a remote collection actually arrives in: the agent's job-result
	// envelope, not the intake's InterrogateResult.
	result := &models.JobResult{
		JobID:    jobID,
		Success:  true,
		Facts:    obs.Facts,
		Metadata: obs.DeviceInfo,
		Assets:   make([]models.DiscoveredAsset, 0, len(obs.Assets)),
	}
	for _, a := range obs.Assets {
		asset := models.DiscoveredAsset{
			Hostname: a.Hostname, IPAddress: a.IPAddress, Port: a.Port,
			Protocol: a.Protocol, Metadata: a.Metadata,
		}
		if a.ServiceHints != nil {
			asset.ServiceHints = &models.ServiceHints{
				ServiceName:          a.ServiceHints.ServiceName,
				Confidence:           a.ServiceHints.Confidence,
				IdentificationMethod: a.ServiceHints.IdentificationMethod,
			}
		}
		result.Assets = append(result.Assets, asset)
	}

	if err := NewResultProcessor(appDB, owner).ProcessJobResults(ctx, jobID, result); err != nil {
		t.Fatalf("ProcessJobResults: %v", err)
	}

	if n := countRows(t, owner, `SELECT count(*) FROM assets WHERE tenant_id = $1`, tenantID); n != 1 {
		t.Fatalf("assets = %d, want 1 — the remote path did not materialise", n)
	}
	var assetID string
	if err := owner.QueryRow(`SELECT id FROM assets WHERE tenant_id = $1`, tenantID).Scan(&assetID); err != nil {
		t.Fatalf("read asset id: %v", err)
	}
	if n := countRows(t, owner,
		`SELECT count(*) FROM asset_endpoints WHERE tenant_id = $1 AND asset_id = $2`, tenantID, assetID); n != 3 {
		t.Errorf("endpoints = %d, want 3", n)
	}
	if n := countRows(t, owner,
		`SELECT count(*) FROM software_installs WHERE tenant_id = $1 AND asset_id = $2`, tenantID, assetID); n != 3 {
		t.Errorf("installs = %d, want 3", n)
	}
	// The facts reached the asset. Without the `Facts:` line the agent's remote
	// submission used to omit, this is what would be zero — the collection
	// would arrive as a list of ports and nothing else.
	if v, ok := factValue(t, owner, tenantID, assetID, facts.KeyOSName); !ok || v != `"Ubuntu"` {
		t.Errorf("os.name = %q (present=%t); a remote collection must carry its facts", v, ok)
	}

	// And NONE of the crypto pipeline ran.
	for _, table := range []string{"discovery_jobs", "discovery_findings", "sensor_discoveries"} {
		if n := countRows(t, owner,
			`SELECT count(*) FROM `+table+` WHERE tenant_id = $1`, tenantID); n != 0 {
			t.Errorf("%s: %d row(s) — a host inventory is not a crypto finding", table, n)
		}
	}
}

// TestIntegration_ProcessJobResults_StillMaterialisesDeviceInterrogation is the
// other polarity: the host-inventory branch must not have been placed somewhere
// that catches every job type.
//
// Mutation check: drop the job-type condition and this fails.
func TestIntegration_ProcessJobResults_StillMaterialisesDeviceInterrogation(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)

	jobQueue := NewJobQueueService(appDB, owner, nil)
	job, err := jobQueue.CreateJob(ctx, models.CreateDeviceJobRequest{
		TenantID: tenantID,
		JobType:  models.JobTypeDeviceInterrogation,
		AgentID:  &agentID,
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	processor := NewResultProcessor(appDB, owner)
	err = processor.ProcessJobResults(ctx, job.ID, &models.JobResult{
		JobID:   job.ID,
		Success: true,
		Assets: []models.DiscoveredAsset{{
			Hostname:        "lb.example.net",
			IPAddress:       "198.51.100.20",
			Port:            443,
			Protocol:        "TLS",
			ProtocolVersion: "TLS 1.2",
			CipherSuite:     "ECDHE-RSA-AES128-GCM-SHA256",
		}},
	})
	if err != nil {
		t.Fatalf("ProcessJobResults: %v", err)
	}

	var jobs int
	if err := owner.QueryRow(`SELECT count(*) FROM discovery_jobs WHERE tenant_id = $1`, tenantID).Scan(&jobs); err != nil {
		t.Fatalf("count discovery_jobs: %v", err)
	}
	if jobs == 0 {
		t.Fatal("a device interrogation took the host-inventory branch; the branch is catching every job type")
	}
}

// The intake repository's INSERT is covered where it LIVES, in
// internal/handlers, by TestIntegration_HostInventoryIntake_WritesACompletedJobRow.
//
// It used to be here, and could not reach the unexported hostInventoryRepository
// from this package — so it re-typed the INSERT instead. That copy would have
// stayed green through a column added to, renamed in or dropped from the real
// statement, which is the wiring gap CLAUDE.md's "test the WIRING, not just the
// helper" rule exists to catch.
