package services

// Hop 1 of the chained per-vendor pipeline test ( W0.2).
//
// For each vendor a fake appliance serves fixture output, and the REAL
// in-cluster path runs against it: a device record created as Discovery →
// Devices creates it, a device job, the platform worker's
// executeDeviceInterrogation (the collector through the Registry, then
// materializeInterrogatedAsset → writeSensorDiscovery and persistObservations),
// then the same UpdateJobStatus + ProcessJobResults sequence processNextJob
// runs. Nothing here builds an observation or a sensor_discoveries row by hand.
//
// What it produces is compared against two goldens per vendor under
// shared/deviceinterrogation/testdata/pipeline/<vendor>/:
//
//   - hop1_handoff.golden.json      the sensor_discoveries rows and learned
//     segments. This is hop 2's INPUT (discovery-processor-service).
//   - hop1_observations.golden.json the facts, edges, segments, identity
//     outcomes and collection warnings, with identity admission off and
//     enforced.
//
// and against the per-vendor claims in vendorPipelineHop1Claims, which pin the
// CORRECT behaviour and mark what today's code still gets wrong as knownGap.
//
// Regenerate with -update-golden, then regenerate hops 2 and 3 (see
// testdata/pipeline/README.md).
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/pipelinetest"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// vendorPipelineDir is the goldens' home, relative to this package.
const vendorPipelineDir = "../../../../shared/deviceinterrogation/testdata/pipeline"

// vendorPipelinePoison is planted in the fixtures wherever a vendor returns
// material we must never store. No golden may contain it.
const vendorPipelinePoison = "MUST-NOT-BE-COLLECTED"

// hop1Run is one interrogation of one vendor's fake appliance.
type hop1Run struct {
	tenant   uuid.UUID
	device   uuid.UUID
	job      uuid.UUID
	batch    string
	app      pipelinetest.Appliance
	scenario pipelinetest.Scenario
	// segmentIDs maps every segment id of the tenant to its CIDR, read once
	// the run is over.
	segmentIDs map[string]string
}

// runVendorHop1 drives one scenario through the in-cluster executor.
func runVendorHop1(t *testing.T, owner *sql.DB, s pipelinetest.Scenario, enforce bool) hop1Run {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dir := pipelinetest.Dir(t, vendorPipelineDir)

	tenant := testdb.NewTenant(t, owner)
	for _, seg := range s.TenantSegments {
		if _, err := owner.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment,is_active)
			VALUES($1,$2,$3,'cidr',$4,'production',true)`, uuid.New(), tenant, seg.Name, seg.CIDR); err != nil {
			t.Fatalf("seed tenant segment %s: %v", seg.CIDR, err)
		}
	}
	app := pipelinetest.StartAppliance(t, dir, s)

	// The device record, as Discovery → Devices creates it. A self-signed
	// management certificate is the norm on appliances, so the operator has
	// opted out of verification for this device.
	user, pass, insecure := "readonly", "readonly-password", true
	hostname := s.Hostname
	req := models.CreateDeviceRequest{
		DeviceType:            s.DeviceType,
		Hostname:              &hostname,
		Username:              &user,
		Password:              &pass,
		TLSInsecureSkipVerify: &insecure,
	}
	switch s.Transport {
	case "rest":
		mgmt := app.ManagementURL
		req.ManagementURL = &mgmt
	default:
		// SSH and SNMP dial the record's address. The port rides in
		// metadata.ssh_port, the only port key the service reads today
		// (finding C-01, W3.1).
		ip := app.Host
		req.IPAddress = &ip
		req.Metadata = map[string]interface{}{"ssh_port": app.Port}
	}
	deviceSvc := NewDeviceServiceWithKey(owner, testMasterKey)
	dev, err := deviceSvc.CreateDevice(ctx, tenant, req)
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	if enforce {
		// Enforced AFTER the device exists, as on the live tenant the NUL-key
		// bug hit: under enforce, CreateDevice itself retains a record
		// whose only identity is a hostname. The configuration:
		// identity admission enforced, and an asset allowance so admission
		// is deciding on evidence rather than on a full quota.
		if _, err := owner.Exec(`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason)
			SELECT $1,id,'{"quantity":500}'::jsonb,'vendor pipeline test' FROM billable_items WHERE key='max_assets'`, tenant); err != nil {
			t.Fatalf("asset allowance: %v", err)
		}
		if _, err := owner.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"}}')
			ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
			t.Fatalf("enforce admission: %v", err)
		}
	}

	appDB := testdb.ConnectAsAppRole(t, owner)
	jobQueue := NewJobQueueService(appDB, owner, nil)
	created, err := jobQueue.CreateJob(ctx, models.CreateDeviceJobRequest{
		TenantID: tenant,
		JobType:  models.JobTypeDeviceInterrogation,
		AssetID:  &dev.ID,
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	job, err := jobQueue.GetJobByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetJobByID: %v", err)
	}
	worker := &PlatformAgentWorker{
		db:                  appDB,
		bypassDB:            owner,
		jobQueue:            jobQueue,
		deviceService:       NewDeviceServiceWithKey(appDB, testMasterKey),
		deviceInterrogation: NewDeviceInterrogationService(appDB, owner, testMasterKey),
		resultProcessor:     NewResultProcessor(appDB, owner),
	}
	result, err := worker.executeDeviceInterrogation(ctx, job)
	if err != nil {
		t.Fatalf("%s: executeDeviceInterrogation: %v", s.Vendor, err)
	}
	// What processNextJob does with a successful result.
	if err := jobQueue.UpdateJobStatus(ctx, job.ID, models.JobStatusCompleted, result, nil); err != nil {
		t.Fatalf("UpdateJobStatus: %v", err)
	}
	if !shouldProcessResults(result) {
		t.Fatal("the worker would not process this result; the processing block would never be written")
	}
	if err := worker.resultProcessor.ProcessJobResults(ctx, job.ID, result); err != nil {
		t.Fatalf("ProcessJobResults: %v", err)
	}

	var discoveryJob uuid.UUID
	if err := owner.QueryRow(`SELECT (parameters->>'discovery_job_id')::uuid FROM device_jobs WHERE id=$1`, job.ID).Scan(&discoveryJob); err != nil {
		t.Fatalf("the device job recorded no discovery job: %v", err)
	}
	segmentIDs := map[string]string{}
	segRows, err := owner.Query(`SELECT id::text, value FROM network_segments WHERE tenant_id = $1`, tenant)
	if err != nil {
		t.Fatalf("segment ids: %v", err)
	}
	for segRows.Next() {
		var id, value string
		if err := segRows.Scan(&id, &value); err != nil {
			t.Fatalf("scan segment id: %v", err)
		}
		segmentIDs[id] = value
	}
	_ = segRows.Close()
	return hop1Run{tenant: tenant, device: dev.ID, job: job.ID, batch: discoveryJob.String(), app: app, scenario: s, segmentIDs: segmentIDs}
}

// normalize replaces everything that differs per run with a placeholder.
func (r hop1Run) normalize(t *testing.T, v any) any {
	t.Helper()
	host, port := r.app.Host, strconv.Itoa(r.app.Port)
	pairs := []string{
		r.device.String(), pipelinetest.PlaceholderDeviceAssetID,
		r.job.String(), pipelinetest.PlaceholderDeviceJobID,
		r.batch, pipelinetest.PlaceholderBatchID,
		host + ":" + port, pipelinetest.PlaceholderApplianceIP + ":" + pipelinetest.PlaceholderAppliancePort,
	}
	// A network scope is a segment id; name it by the segment's CIDR.
	for id, cidr := range r.segmentIDs {
		pairs = append(pairs, id, "segment:"+cidr)
	}
	replace := pipelinetest.Replacer(pairs...)
	return pipelinetest.Walk(pipelinetest.Canonical(t, v), func(key string, val any) any {
		switch x := val.(type) {
		case string:
			if x == host {
				return pipelinetest.PlaceholderApplianceIP
			}
			if x == port && strings.Contains(key, "port") {
				return pipelinetest.PlaceholderAppliancePort
			}
		case json.Number:
			if string(x) == port && strings.Contains(key, "port") {
				return pipelinetest.PlaceholderAppliancePort
			}
		}
		return replace(key, val)
	})
}

// handoff reads what hop 1 hands to hop 2.
func (r hop1Run) handoff(t *testing.T, owner *sql.DB) pipelinetest.Hop1Handoff {
	t.Helper()
	rows, err := owner.Query(`
		SELECT protocol::text, host(dest_ip), port, confidence::text, metadata, hostname, host(source_ip)
		FROM sensor_discoveries WHERE tenant_id = $1 AND batch_id = $2`, r.tenant, r.batch)
	if err != nil {
		t.Fatalf("read sensor_discoveries: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out pipelinetest.Hop1Handoff
	out.Vendor = r.scenario.Vendor
	for rows.Next() {
		var row pipelinetest.SensorDiscoveryRow
		var port int
		var conf string
		var meta []byte
		var hostname, source sql.NullString
		if err := rows.Scan(&row.Protocol, &row.DestIP, &port, &conf, &meta, &hostname, &source); err != nil {
			t.Fatalf("scan: %v", err)
		}
		row.Port = port
		row.Confidence = json.Number(conf)
		if hostname.Valid {
			row.Hostname = &hostname.String
		}
		if source.Valid {
			row.SourceIP = &source.String
		}
		if err := json.Unmarshal(meta, &row.Metadata); err != nil {
			t.Fatalf("metadata: %v", err)
		}
		out.SensorDiscoveries = append(out.SensorDiscoveries, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	out.LearnedSegments = r.learnedSegments(t, owner)
	out.Assets = r.assetRecords(t, owner)

	var normalized pipelinetest.Hop1Handoff
	raw, _ := json.Marshal(r.normalize(t, out))
	if err := json.Unmarshal(raw, &normalized); err != nil {
		t.Fatalf("normalized handoff: %v", err)
	}
	sort.Slice(normalized.SensorDiscoveries, func(i, j int) bool {
		a, _ := json.Marshal(normalized.SensorDiscoveries[i])
		b, _ := json.Marshal(normalized.SensorDiscoveries[j])
		return string(a) < string(b)
	})
	return normalized
}

// assetRecords is every asset of the tenant after the run — the device and the
// peers the observation sink created — with its identifiers, device first.
func (r hop1Run) assetRecords(t *testing.T, owner *sql.DB) []pipelinetest.AssetRecord {
	t.Helper()
	labels := r.assetLabels(t, owner)
	rows, err := owner.Query(`SELECT id::text, coalesce(hostname, ''), host(primary_address), class_key
		FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, r.tenant)
	if err != nil {
		t.Fatalf("assets: %v", err)
	}
	type raw struct {
		id  string
		rec pipelinetest.AssetRecord
	}
	var all []raw
	for rows.Next() {
		var a raw
		var address sql.NullString
		if err := rows.Scan(&a.id, &a.rec.Hostname, &address, &a.rec.ClassKey); err != nil {
			t.Fatalf("scan asset: %v", err)
		}
		if address.Valid {
			a.rec.PrimaryAddress = &address.String
		}
		a.rec.Label = labels[a.id]
		all = append(all, a)
	}
	_ = rows.Close()

	out := make([]pipelinetest.AssetRecord, 0, len(all))
	for _, a := range all {
		ids, err := owner.Query(`SELECT kind, value, scope, source_kind FROM asset_identifiers
			WHERE tenant_id = $1 AND asset_id = $2 ORDER BY kind, value`, r.tenant, a.id)
		if err != nil {
			t.Fatalf("identifiers: %v", err)
		}
		a.rec.Identifiers = []pipelinetest.AssetIdentifier{}
		for ids.Next() {
			var id pipelinetest.AssetIdentifier
			var scope sql.NullString
			if err := ids.Scan(&id.Kind, &id.Value, &scope, &id.SourceKind); err != nil {
				t.Fatalf("scan identifier: %v", err)
			}
			if scope.Valid {
				id.Scope = &scope.String
			}
			a.rec.Identifiers = append(a.rec.Identifiers, id)
		}
		_ = ids.Close()
		out = append(out, a.rec)
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i].Label == "device") != (out[j].Label == "device") {
			return out[i].Label == "device"
		}
		return out[i].Label < out[j].Label
	})
	return out
}

func (r hop1Run) learnedSegments(t *testing.T, owner *sql.DB) []pipelinetest.LearnedSegment {
	t.Helper()
	registered := map[string]bool{}
	for _, s := range r.scenario.TenantSegments {
		registered[s.CIDR] = true
	}
	rows, err := owner.Query(`SELECT value, segment_type, network_type, metadata FROM network_segments
		WHERE tenant_id = $1 ORDER BY value`, r.tenant)
	if err != nil {
		t.Fatalf("read segments: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []pipelinetest.LearnedSegment
	for rows.Next() {
		var s pipelinetest.LearnedSegment
		var meta []byte
		if err := rows.Scan(&s.Value, &s.SegmentType, &s.NetworkType, &meta); err != nil {
			t.Fatalf("scan segment: %v", err)
		}
		if registered[s.Value] {
			continue
		}
		if err := json.Unmarshal(meta, &s.Metadata); err != nil {
			t.Fatalf("segment metadata: %v", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if out == nil {
		out = []pipelinetest.LearnedSegment{}
	}
	return out
}

// hop1Observed is the non-handoff half: what the interrogation told the
// identity engine and the job detail.
type hop1Observed struct {
	Facts         []map[string]any `json:"facts"`
	Edges         []map[string]any `json:"edges"`
	Assets        []map[string]any `json:"assets"`
	Retained      []map[string]any `json:"retained_observations"`
	Warnings      []map[string]any `json:"collection_warnings"`
	ProcessErrors []any            `json:"processing_errors"`
}

// observed reads the facts, edges, assets, retained identity observations and
// collection warnings, with every asset named by its identifiers rather than
// its random id.
func (r hop1Run) observed(t *testing.T, owner *sql.DB) hop1Observed {
	t.Helper()
	labels := r.assetLabels(t, owner)
	label := func(id sql.NullString) string {
		if !id.Valid {
			return ""
		}
		if l, ok := labels[id.String]; ok {
			return l
		}
		return "unlabelled-asset"
	}
	var out hop1Observed

	facts, err := owner.Query(`SELECT asset_id::text, key, value, source_kind FROM asset_facts WHERE tenant_id = $1`, r.tenant)
	if err != nil {
		t.Fatalf("facts: %v", err)
	}
	for facts.Next() {
		var asset sql.NullString
		var key, kind string
		var value []byte
		if err := facts.Scan(&asset, &key, &value, &kind); err != nil {
			t.Fatalf("scan fact: %v", err)
		}
		var v any
		_ = json.Unmarshal(value, &v)
		out.Facts = append(out.Facts, map[string]any{"asset": label(asset), "key": key, "value": v, "source_kind": kind})
	}
	_ = facts.Close()

	edges, err := owner.Query(`SELECT from_asset_id::text, to_asset_id::text, type, source_kind, status FROM asset_relationships WHERE tenant_id = $1`, r.tenant)
	if err != nil {
		t.Fatalf("edges: %v", err)
	}
	for edges.Next() {
		var from, to sql.NullString
		var typ, kind, status string
		if err := edges.Scan(&from, &to, &typ, &kind, &status); err != nil {
			t.Fatalf("scan edge: %v", err)
		}
		out.Edges = append(out.Edges, map[string]any{"from": label(from), "to": label(to), "type": typ, "source_kind": kind, "status": status})
	}
	_ = edges.Close()

	assets, err := owner.Query(`SELECT id::text, coalesce(class_key,''), asset_status::text FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, r.tenant)
	if err != nil {
		t.Fatalf("assets: %v", err)
	}
	for assets.Next() {
		var id sql.NullString
		var class, status string
		if err := assets.Scan(&id, &class, &status); err != nil {
			t.Fatalf("scan asset: %v", err)
		}
		out.Assets = append(out.Assets, map[string]any{"asset": label(id), "class_key": class, "status": status})
	}
	_ = assets.Close()

	retained, err := owner.Query(`SELECT evidence->'identifiers', admission_reasons, state, source_kind FROM identity_observations WHERE tenant_id = $1`, r.tenant)
	if err != nil {
		t.Fatalf("identity observations: %v", err)
	}
	for retained.Next() {
		var ids []byte
		var reasons []byte
		var state, kind string
		if err := retained.Scan(&ids, pqStringArray(&reasons), &state, &kind); err != nil {
			t.Fatalf("scan identity observation: %v", err)
		}
		var idv any
		_ = json.Unmarshal(ids, &idv)
		out.Retained = append(out.Retained, map[string]any{"identifiers": idv, "admission_reasons": string(reasons), "state": state, "source_kind": kind})
	}
	_ = retained.Close()

	var body []byte
	if err := owner.QueryRow(`SELECT results FROM device_jobs WHERE id = $1`, r.job).Scan(&body); err != nil {
		t.Fatalf("job results: %v", err)
	}
	var stored struct {
		Processing *struct {
			CollectionWarnings []map[string]any `json:"collection_warnings"`
			Errors             []any            `json:"errors"`
		} `json:"processing"`
	}
	if err := json.Unmarshal(body, &stored); err != nil {
		t.Fatalf("job results: %v", err)
	}
	if stored.Processing == nil {
		t.Fatalf("job has no processing block: %s", body)
	}
	out.Warnings = stored.Processing.CollectionWarnings
	out.ProcessErrors = stored.Processing.Errors

	for _, list := range []*[]map[string]any{&out.Facts, &out.Edges, &out.Assets, &out.Retained, &out.Warnings} {
		if *list == nil {
			*list = []map[string]any{}
		}
	}
	if out.ProcessErrors == nil {
		out.ProcessErrors = []any{}
	}
	var normalized hop1Observed
	raw, _ := json.Marshal(r.normalize(t, out))
	if err := json.Unmarshal(raw, &normalized); err != nil {
		t.Fatalf("normalized observations: %v", err)
	}
	for _, list := range [][]map[string]any{normalized.Facts, normalized.Edges, normalized.Assets, normalized.Retained, normalized.Warnings} {
		sortByJSON(list)
	}
	return normalized
}

// assetLabels names every asset of the tenant by its identifiers, sorted, so
// a golden can say which asset a fact landed on without its random id. The
// interrogated device is "device".
func (r hop1Run) assetLabels(t *testing.T, owner *sql.DB) map[string]string {
	t.Helper()
	rows, err := owner.Query(`
		SELECT a.id::text, coalesce(string_agg(i.kind || '=' || i.value, ',' ORDER BY i.kind, i.value), '')
		FROM assets a LEFT JOIN asset_identifiers i ON i.tenant_id = a.tenant_id AND i.asset_id = a.id
		WHERE a.tenant_id = $1 GROUP BY a.id`, r.tenant)
	if err != nil {
		t.Fatalf("asset labels: %v", err)
	}
	defer func() { _ = rows.Close() }()
	labels := map[string]string{}
	for rows.Next() {
		var id, ids string
		if err := rows.Scan(&id, &ids); err != nil {
			t.Fatalf("scan label: %v", err)
		}
		if id == r.device.String() {
			labels[id] = "device"
			continue
		}
		labels[id] = "asset[" + ids + "]"
	}
	return labels
}

func sortByJSON(list []map[string]any) {
	sort.Slice(list, func(i, j int) bool {
		a, _ := json.Marshal(list[i])
		b, _ := json.Marshal(list[j])
		return string(a) < string(b)
	})
}

// pqStringArray scans a Postgres text[] as its literal text ({a,b}).
func pqStringArray(dst *[]byte) any { return &textScanner{dst: dst} }

type textScanner struct{ dst *[]byte }

func (s *textScanner) Scan(src any) error {
	switch v := src.(type) {
	case []byte:
		*s.dst = append([]byte(nil), v...)
	case string:
		*s.dst = []byte(v)
	case nil:
		*s.dst = nil
	default:
		return fmt.Errorf("unexpected %T", src)
	}
	return nil
}

// TestIntegration_VendorPipeline_Hop1_DeviceOutputToSensorDiscoveries is hop 1
// for every vendor.
func TestIntegration_VendorPipeline_Hop1_DeviceOutputToSensorDiscoveries(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	t.Setenv("ENCRYPTION_MASTER_KEY", testMasterKey)
	// No known_hosts from the machine running the suite. The SSH legs verify
	// host keys for real: a Cisco device is never stored with the TLS skip flag
	//so a developer's ~/.ssh/known_hosts would otherwise decide
	// whether the fake appliance's key is accepted.
	t.Setenv("HOME", t.TempDir())
	dir := pipelinetest.Dir(t, vendorPipelineDir)
	// The UniFi management-plane rows record the TLS handshake. The fake's
	// side is pinned; this refuses an environment whose TLS client differs,
	// rather than letting it read as a golden diff.
	pipelinetest.RequireDeterministicTLS(t)

	for _, vendor := range pipelinetest.Vendors {
		t.Run(vendor, func(t *testing.T) {
			s := pipelinetest.LoadScenario(t, dir, vendor)

			off := runVendorHop1(t, owner, s, false)
			handoff := off.handoff(t, owner)
			observedOff := off.observed(t, owner)

			enforced := runVendorHop1(t, owner, s, true)
			enforcedHandoff := enforced.handoff(t, owner)
			observedEnforced := enforced.observed(t, owner)

			// The rows that reach inventory must not depend on identity
			// admission: admission decides which PEERS become assets, never
			// what the device's own crypto is.
			if !pipelinetest.Equal(t, handoff.SensorDiscoveries, enforcedHandoff.SensorDiscoveries) ||
				!pipelinetest.Equal(t, handoff.LearnedSegments, enforcedHandoff.LearnedSegments) {
				t.Errorf("sensor_discoveries or learned segments differ between admission off and enforced:\n off: %s\n enf: %s",
					pipelinetest.Marshal(t, handoff.SensorDiscoveries), pipelinetest.Marshal(t, enforcedHandoff.SensorDiscoveries))
			}

			observed := map[string]hop1Observed{"admission_off": observedOff, "admission_enforce": observedEnforced}
			for _, golden := range []struct {
				file string
				v    any
			}{{pipelinetest.Hop1HandoffFile, handoff}, {pipelinetest.Hop1ObservedFile, observed}} {
				rendered := string(pipelinetest.Marshal(t, golden.v))
				if strings.Contains(rendered, vendorPipelinePoison) {
					t.Errorf("%s carries material the device volunteered and nothing reads", golden.file)
				}
				pipelinetest.CompareGolden(t, filepath.Join(dir, vendor, golden.file), golden.v)
			}

			claims := vendorPipelineHop1Claims(t, vendor, handoff, observedOff, observedEnforced)
			if len(claims) == 0 {
				t.Fatalf("no hop-1 claims for %s: a vendor with no claims asserts nothing but its golden", vendor)
			}
			pipelinetest.Expect(t, claims...)
			if gaps := pipelinetest.GapIDs(claims); len(gaps) > 0 {
				t.Logf("%s hop 1 holds %d known gap(s) open: %s", vendor, len(gaps), strings.Join(gaps, "; "))
			}
		})
	}
}
