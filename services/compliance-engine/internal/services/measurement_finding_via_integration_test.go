package services

// The `finding` shape's `via`, EXECUTED.
//
// `via` selects which findings a counting control counts: the default counts
// only findings whose subject IS the asset, "relationship" reaches edges the
// asset takes part in, and "asset_or_endpoint" (workstream 3.5) counts both
// asset- and endpoint-subject findings — because the `configuration` producer
// raises `plaintext_management` at either granularity, and a control that read
// only one of them would report a switch with a live Telnet listener as
// compliant because the finding was recorded against the socket.
//
// Everything else about that via was checked without ever running it: the
// generator validates the NAME, the Go whitelist validates the VALUE, and the
// SQL golden pins the TEXT. None of those executes the statement, so a wrong
// correlation in the endpoint subquery — `e.asset_id = a.id` written as
// `e.id = a.id`, the tenant predicate forgotten — would pin perfectly and count
// the wrong rows on a customer's estate.
//
// This runs the real extractor over a real Postgres and asserts the counts,
// three-valued: an asset with no coverage entry yields NO ROW at all.
//
// Skips without TEST_DATABASE_URL (shared/testdb); `make test-integration-db`.

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type findingViaFixture struct {
	db     *sqlx.DB
	tenant uuid.UUID

	// managed carries one plaintext_management finding on ITSELF and one on
	// each of two endpoints: three in total, and only one of them is visible
	// to the default via.
	managed uuid.UUID
	// clean is assessed and has nothing: an honest zero, which is a different
	// answer from the asset below.
	clean uuid.UUID
	// unassessed has an endpoint finding and an EMPTY coverage array. It must
	// yield no row at all — "nobody has evaluated this" is not "zero".
	unassessed uuid.UUID
}

func newFindingViaFixture(t *testing.T) *findingViaFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	f := &findingViaFixture{db: db, tenant: tenant}

	// Coverage goes in `producer_assessments` — the record of who has LOOKED,
	// which the finding shape gates on. NOT `assets.risk_assessed_by`, which is
	// its risk-feeding subset and means something narrower.
	asset := func(host string, assessed bool) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := db.QueryRow(`
			INSERT INTO assets (tenant_id, class_key, class_path, hostname, asset_status)
			VALUES ($1, 'switch', 'hardware.network_device.switch', $2, 'monitoring')
			RETURNING id`, tenant, host).Scan(&id); err != nil {
			t.Fatalf("seed asset %s: %v", host, err)
		}
		if assessed {
			if _, err := db.Exec(`INSERT INTO producer_assessments (tenant_id, asset_id, producer)
			                      VALUES ($1, $2, 'configuration')`, tenant, id); err != nil {
				t.Fatalf("seed coverage for %s: %v", host, err)
			}
		}
		return id
	}
	f.managed = asset("via-managed.example.test", true)
	f.clean = asset("via-clean.example.test", true)
	f.unassessed = asset("via-unassessed.example.test", false)

	endpoint := func(owner uuid.UUID, port int) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := db.QueryRow(`
			INSERT INTO asset_endpoints (tenant_id, asset_id, fqdn, port, transport, status)
			VALUES ($1, $2, $3, $4, 'tcp', 'active')
			RETURNING id`, tenant, owner, "via-ep.example.test", port).Scan(&id); err != nil {
			t.Fatalf("seed endpoint: %v", err)
		}
		return id
	}
	managedEP1 := endpoint(f.managed, 23)
	managedEP2 := endpoint(f.managed, 21)
	// An endpoint on the CLEAN asset, carrying a finding of a different kind.
	// If the predicate leaked, this would show up as a plaintext count.
	cleanEP := endpoint(f.clean, 6379)
	unassessedEP := endpoint(f.unassessed, 23)

	finding := func(kind, subjectType string, subject uuid.UUID, state, workflow string) {
		t.Helper()
		if _, err := db.Exec(`
			INSERT INTO findings (tenant_id, producer, kind, subject_type, subject_id,
			                      severity, score, summary, detection_state, workflow_status)
			VALUES ($1, 'configuration', $2, $3, $4, 'high', 70, 'seeded', $5, $6)`,
			tenant, kind, subjectType, subject, state, workflow); err != nil {
			t.Fatalf("seed finding %s/%s: %v", kind, subjectType, err)
		}
	}

	finding("plaintext_management", "asset", f.managed, "ACTIVE", "NEW")
	finding("plaintext_management", "endpoint", managedEP1, "ACTIVE", "NEW")
	finding("plaintext_management", "endpoint", managedEP2, "ACTIVE", "NEW")
	// Neither of these counts: one is resolved, one is a different kind.
	finding("plaintext_management", "endpoint", cleanEP, "INACTIVE", "NEW")
	finding("insecure_service_exposed", "endpoint", cleanEP, "ACTIVE", "NEW")
	// And this asset is not assessed at all, so its finding is not counted
	// because it produces no row to count into.
	finding("plaintext_management", "endpoint", unassessedEP, "ACTIVE", "NEW")

	return f
}

// TestIntegration_MeasurementFindingVia_CountsAssetAndEndpointSubjects drives
// the real extractor, so the statement it executes is the one a deployment
// executes.
//
// Mutation-proven: change `mgmt_plaintext`'s via to the default in
// standards/measurement-types.yaml (regenerating), or break the endpoint
// correlation in findingCountSQL, and the managed asset's count drops to 1.
func TestIntegration_MeasurementFindingVia_CountsAssetAndEndpointSubjects(t *testing.T) {
	f := newFindingViaFixture(t)

	values, err := NewMeasurementExtractor(f.db).ExtractMeasurements(f.tenant, "mgmt_plaintext")
	if err != nil {
		t.Fatalf("extract mgmt_plaintext: %v", err)
	}

	got := map[uuid.UUID]int{}
	for _, v := range values {
		n, ok := v.Value.(int)
		if !ok {
			t.Fatalf("measurement value %#v (%T) is not an integer", v.Value, v.Value)
		}
		got[v.SubjectID] = n
	}

	if n := len(got); n != 2 {
		t.Fatalf("got %d measurements, want 2 — an asset with no producer in risk_assessed_by must yield "+
			"NO ROW, so the control reads not assessed rather than compliant (got %v)", n, got)
	}
	if _, present := got[f.unassessed]; present {
		t.Errorf("the unassessed asset produced a measurement; it has an open endpoint finding and no " +
			"coverage entry, and reporting a number for it would claim an evaluation nobody made")
	}
	if n := got[f.managed]; n != 3 {
		t.Errorf("the managed switch counts %d plaintext findings, want 3 — one on the asset and one on "+
			"each of its two endpoints. A count of 1 means `via: asset_or_endpoint` is not reaching the "+
			"endpoint subjects, and a device whose only Telnet listener was recorded against the socket "+
			"would read as compliant", n)
	}
	if n := got[f.clean]; n != 0 {
		t.Errorf("the clean asset counts %d, want 0 — its endpoint carries a RESOLVED plaintext finding "+
			"and an ACTIVE finding of a different kind, and neither is this measurement", n)
	}
}
