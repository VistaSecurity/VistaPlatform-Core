package services

// Interrogation findings are owned by the interrogated device ( W2.1 and
// W2.2), driven through the REAL ingest against a real Postgres with the real
// schema and algorithm catalogue.
//
// Each finding below is the shape discovery-processor hands inventory for what
// a collector reported:
//
//	Fortinet tunnel   public remote-gw → no address of the device's own
//	F5 virtual server public VIP
//	PAN-OS rule       a label, `postgres`, no address
//	Cisco SSH         management address + an SSH-1.99 banner
//	F5 virtual server private VIP in a registered segment (control)
//
// Before, the first four had nowhere to go: public or address-less classified
// third_party, and with no source IP there was no connection to write. Now the
// first four land on the device; the control keeps its ordinary routing.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type ownedIngestFixture struct {
	raw    *sql.DB
	svc    *AssetService
	tenant uuid.UUID
	device uuid.UUID
	sensor string
	// job is the completed device_interrogation job that interrogated device:
	// the run every finding below claims to come from.
	job uuid.UUID
}

func newOwnedIngestFixture(t *testing.T) ownedIngestFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	device := uuid.New()
	if _, err := raw.Exec(`
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1, $2, 'fw-edge-01', 'network_device', 'hardware.network_device', 'monitoring', NOW(), NOW(), NOW(), NOW())`,
		device, tenant); err != nil {
		t.Fatalf("seed the interrogated device: %v", err)
	}
	var sensor string
	if err := raw.QueryRow(`SELECT id::text FROM sensors WHERE tenant_id=$1 AND profile='device_interrogation' AND platform_managed AND deleted_at IS NULL`,
		tenant).Scan(&sensor); err != nil {
		t.Fatalf("the tenant has no platform interrogation sensor: %v", err)
	}
	// A registered segment, so the private-VIP control classifies internal.
	if _, err := raw.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment)
		VALUES($1,$2,'DMZ','cidr','192.0.2.0/24','production')`, uuid.New(), tenant); err != nil {
		t.Fatal(err)
	}
	job := uuid.New()
	if _, err := raw.Exec(`INSERT INTO device_jobs (id, tenant_id, job_type, asset_id, status)
		VALUES ($1, $2, 'device_interrogation', $3, 'completed')`, job, tenant, device); err != nil {
		t.Fatalf("seed the device job: %v", err)
	}
	return ownedIngestFixture{raw: raw, svc: newCloudRoutingAssetService(db), tenant: tenant, device: device, sensor: sensor, job: job}
}

// interrogationFinding is what discovery-processor's converter produces from a
// sensor_discoveries row device-interrogation-service wrote.
func (f ownedIngestFixture) interrogationFinding(ip, hostname string, port int, protocol, version, suite string, raw map[string]interface{}) IngestFinding {
	sensor := f.sensor
	out := IngestFinding{
		IPAddress:      &ip,
		Port:           &port,
		AssetType:      "server",
		Protocol:       protocol,
		SourceSensorID: &sensor,
		RawData: map[string]interface{}{
			"discovery_method": "device_interrogation",
			"source":           "sensor_discovery",
			"sensor_id":        sensor,
			"device_id":        f.device.String(),
			"source_device_id": f.device.String(),
			"source_asset_id":  f.device.String(),
			"device_job_id":    f.job.String(),
		},
	}
	if hostname != "" {
		out.Hostname = &hostname
	}
	if version != "" {
		out.ProtocolVersion = &version
	}
	if suite != "" {
		out.CipherSuite = &suite
	}
	for k, v := range raw {
		out.RawData[k] = v
	}
	return out
}

func (f ownedIngestFixture) deviceConfigs(t *testing.T) map[string]sql.NullString {
	t.Helper()
	rows, err := f.raw.Query(`
		SELECT ci.raw_data->>'config_name', COALESCE(host(ae.address) || ':' || ae.port, ae.fqdn)
		  FROM crypto_implementations ci
		  LEFT JOIN asset_endpoints ae ON ae.id = ci.endpoint_id
		 WHERE ci.tenant_id = $1 AND ci.asset_id = $2 AND ci.deleted_at IS NULL`, f.tenant, f.device)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]sql.NullString{}
	for rows.Next() {
		var label sql.NullString
		var endpoint sql.NullString
		if err := rows.Scan(&label, &endpoint); err != nil {
			t.Fatal(err)
		}
		out[label.String] = endpoint
	}
	return out
}

func TestIntegration_InterrogationFindings_LandOnTheInterrogatedDevice(t *testing.T) {
	f := newOwnedIngestFixture(t)

	// Nothing in this ingest may resolve a name: a PAN-OS rule called
	// `postgres` resolved through the cluster's search domain is the
	// platform's own database.
	var resolved []string
	original := lookupHost
	lookupHost = func(_ context.Context, host string) ([]string, error) {
		resolved = append(resolved, host)
		return []string{"127.0.0.1"}, nil
	}
	t.Cleanup(func() { lookupHost = original })

	findings := []IngestFinding{
		f.interrogationFinding("0.0.0.0", "site-a.vpn.example.net", 500, "IPSec", "IKEv2", "aes256-sha256", map[string]interface{}{
			"config_name": "Site-A", "vpn_peer_address": "203.0.113.20", "ike_version": "IKEv2",
		}),
		f.interrogationFinding("203.0.113.30", "", 443, "TLS", "TLS 1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", map[string]interface{}{
			"config_name": "/Common/shop_vs", "profile_name": "/Common/clientssl",
		}),
		f.interrogationFinding("0.0.0.0", "postgres", 443, "TLS", "", "", map[string]interface{}{
			"config_name": "postgres",
		}),
		f.interrogationFinding("198.51.100.1", "198.51.100.1", 22, "SSH", "SSH-1.99", "", map[string]interface{}{
			"config_name": "ssh-management", "ssh_banner": "SSH-1.99-Cisco-1.25", "ssh_host_key_type": "ssh-rsa",
		}),
		// Control: private address in a registered segment.
		f.interrogationFinding("192.0.2.40", "", 443, "TLS", "TLS 1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", map[string]interface{}{
			"config_name": "/Common/internal_vs",
		}),
	}
	report, err := f.svc.IngestFindingsReport(f.tenant, findings, "pending_approval")
	if err != nil {
		t.Fatalf("IngestFindingsReport: %v", err)
	}

	if len(resolved) != 0 {
		t.Errorf("the ingest resolved %v — collector labels must never reach a resolver", resolved)
	}
	if n := countExternalConnections(t, f.raw, f.tenant); n != 0 {
		t.Errorf("%d external_connections row(s): a device's own configuration is not a connection", n)
	}

	configs := f.deviceConfigs(t)
	want := map[string]string{
		// The address was the tunnel's far end, so there is no endpoint of
		// the device's own — and the DNS-valid tunnel name must not become
		// an FQDN endpoint either.
		"Site-A":          "",
		"/Common/shop_vs": "203.0.113.30:443",
		"postgres":        "",
		"ssh-management":  "198.51.100.1:22",
	}
	for label, endpoint := range want {
		got, ok := configs[label]
		if !ok {
			t.Errorf("%q did not land on the interrogated device (device configs: %v)", label, configs)
			continue
		}
		if got.String != endpoint {
			t.Errorf("%q endpoint = %q, want %q", label, got.String, endpoint)
		}
	}
	if _, ok := configs["/Common/internal_vs"]; ok {
		t.Error("a private-address finding was attached to the device; private routing must be unchanged")
	}

	// Nothing was minted from a label or a tunnel's far end, and the private
	// VIP still became an asset of its own.
	var minted int
	if err := f.raw.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id=$1 AND id <> $2 AND deleted_at IS NULL`, f.tenant, f.device).Scan(&minted); err != nil {
		t.Fatal(err)
	}
	if minted != 1 {
		t.Errorf("assets other than the device = %d, want exactly 1 (the private VIP)", minted)
	}

	// The SSH-1.99 banner reached its catalogue row on the device.
	var linked int
	if err := f.raw.QueryRow(`
		SELECT count(*) FROM crypto_implementations ci
		  JOIN crypto_implementation_algorithms cia ON cia.crypto_implementation_id = ci.id
		  JOIN algorithms a ON a.id = cia.algorithm_id
		 WHERE ci.tenant_id=$1 AND ci.asset_id=$2 AND a.code='SSH-1.99'`, f.tenant, f.device).Scan(&linked); err != nil {
		t.Fatal(err)
	}
	if linked == 0 {
		t.Error("the Cisco SSH configuration is not linked to the SSH-1.99 catalogue row")
	}

	// The transport answer discovery-processor settles its rows from.
	for i := 0; i < 4; i++ {
		if report.Results[i].AssetID != f.device.String() || report.EffectiveStatus[i] != "monitoring" {
			t.Errorf("finding %d: result %+v / status %q, want the device and monitoring", i, report.Results[i], report.EffectiveStatus[i])
		}
	}
}

// The claim is honoured only for a row written by the tenant's platform
// interrogation sensor. Anything else claiming a device is REJECTED — not
// attached, and not routed by its address either.
func TestIntegration_InterrogationFindings_UnverifiedClaimIsRejected(t *testing.T) {
	f := newOwnedIngestFixture(t)

	// A tenant-deployed sensor — registered, so the ordinary path would accept
	// it as a collector — claiming the firewall.
	tenantSensor := uuid.New()
	if _, err := f.raw.Exec(`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status) VALUES($1,$2,'Branch sensor','linux','test','datacenter_host','active')`,
		tenantSensor, f.tenant); err != nil {
		t.Fatal(err)
	}
	forged := f.interrogationFinding("203.0.113.31", "", 443, "TLS", "TLS 1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", map[string]interface{}{
		"config_name": "forged",
	})
	other := tenantSensor.String()
	forged.SourceSensorID = &other

	// The platform sensor's own row, naming a device that no longer exists.
	// Public, so the only other door is external_connections.
	deletedOwner := f.interrogationFinding("203.0.113.32", "", 443, "TLS", "TLS 1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", map[string]interface{}{"config_name": "orphan"})
	gone := uuid.NewString()
	deletedOwner.RawData["source_asset_id"] = gone

	report, err := f.svc.IngestFindingsReport(f.tenant, []IngestFinding{forged, deletedOwner}, "monitoring")
	if err != nil {
		t.Fatalf("IngestFindingsReport: %v", err)
	}
	for i, r := range report.Results {
		if r.Outcome != "rejected" || r.AssetID != "" {
			t.Errorf("finding %d: %+v, want rejected with no asset", i, r)
		}
	}
	if configs := f.deviceConfigs(t); len(configs) != 0 {
		t.Errorf("an unverified claim attached configurations to the device: %v", configs)
	}
	if n := countExternalConnections(t, f.raw, f.tenant); n != 0 {
		t.Errorf("an unverified claim was routed to external_connections (%d rows)", n)
	}
}

// A finding at the interrogated device's OWN private address — the Cisco SSH
// management service at the address the device was interrogated on — is the
// device's own management plane. With no registered segment covering the
// address, an unscoped ip_address does not vote in the identification engine,
// so this finding used to mint a second asset for the device.
//
// Each way the device can know its own address is driven separately, and a
// private address that is NOT the device's is the other polarity: it keeps the
// ordinary path and becomes an asset of its own.
func TestIntegration_InterrogationFindings_DeviceOwnAddressIsTheDevice(t *testing.T) {
	const own = "10.20.30.1" // RFC 1918, deliberately in no registered segment
	sshFinding := func(f ownedIngestFixture, ip string) IngestFinding {
		return f.interrogationFinding(ip, ip, 22, "SSH", "SSH-1.99", "", map[string]interface{}{
			"ssh_banner": "SSH-1.99-Cisco-1.25", "ssh_host_key_type": "ssh-rsa",
		})
	}
	assetCount := func(t *testing.T, f ownedIngestFixture) int {
		t.Helper()
		var n int
		if err := f.raw.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL`, f.tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	for _, how := range []struct {
		name string
		seed string
	}{
		{"primary address", `UPDATE assets SET primary_address = $3::inet WHERE tenant_id=$1 AND id=$2`},
		{"measured ip identifier", `INSERT INTO asset_identifiers(tenant_id,asset_id,kind,value,scope,source_kind,source_ref) VALUES($1,$2,'ip_address',$3,'','measured','test')`},
	} {
		t.Run(how.name, func(t *testing.T) {
			f := newOwnedIngestFixture(t)
			if _, err := f.raw.Exec(how.seed, f.tenant, f.device, own); err != nil {
				t.Fatalf("seed the device's own address: %v", err)
			}
			report, err := f.svc.IngestFindingsReport(f.tenant, []IngestFinding{sshFinding(f, own)}, "pending_approval")
			if err != nil {
				t.Fatalf("IngestFindingsReport: %v", err)
			}
			if n := assetCount(t, f); n != 1 {
				t.Errorf("assets = %d, want 1 — the device's own SSH service became a second asset", n)
			}
			if report.Results[0].AssetID != f.device.String() {
				t.Errorf("result = %+v, want the device", report.Results[0])
			}
			if configs := f.deviceConfigs(t); len(configs) != 1 {
				t.Errorf("device configurations = %v, want the SSH configuration", configs)
			}
		})
	}

	// DECLARED addresses are not the device's own for this purpose: a
	// management URL or a declared identifier is what an operator typed, and
	// ADR-0002 D4 keeps declared and measured apart. The finding does not take
	// the owned path; what the ordinary path then does with it is its business.
	for _, how := range []struct {
		name string
		seed string
	}{
		{"declared ip identifier", `INSERT INTO asset_identifiers(tenant_id,asset_id,kind,value,scope,source_kind,source_ref) VALUES($1,$2,'ip_address',$3,'','declared','test')`},
		{"management url", `INSERT INTO asset_management(tenant_id,asset_id,management_url) VALUES($1,$2,'https://' || $3::text || ':8443')`},
	} {
		t.Run(how.name+" does not make an address the device's own", func(t *testing.T) {
			f := newOwnedIngestFixture(t)
			if _, err := f.raw.Exec(how.seed, f.tenant, f.device, own); err != nil {
				t.Fatalf("seed the declared address: %v", err)
			}
			if _, err := f.svc.IngestFindingsReport(f.tenant, []IngestFinding{sshFinding(f, own)}, "pending_approval"); err != nil {
				t.Fatalf("IngestFindingsReport: %v", err)
			}
			if configs := f.deviceConfigs(t); len(configs) != 0 {
				t.Errorf("a declared address pulled the finding onto the device: %v", configs)
			}
		})
	}

	t.Run("a private address that is not the device's", func(t *testing.T) {
		f := newOwnedIngestFixture(t)
		if _, err := f.raw.Exec(`UPDATE assets SET primary_address = $3::inet WHERE tenant_id=$1 AND id=$2`, f.tenant, f.device, own); err != nil {
			t.Fatal(err)
		}
		if _, err := f.svc.IngestFindingsReport(f.tenant, []IngestFinding{sshFinding(f, "10.20.30.99")}, "pending_approval"); err != nil {
			t.Fatalf("IngestFindingsReport: %v", err)
		}
		if configs := f.deviceConfigs(t); len(configs) != 0 {
			t.Errorf("another private address was attached to the device: %v", configs)
		}
		if n := assetCount(t, f); n != 2 {
			t.Errorf("assets = %d, want 2 — a different private address keeps the ordinary path", n)
		}
	})
}
