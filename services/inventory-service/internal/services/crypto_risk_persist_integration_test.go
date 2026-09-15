package services

// A configuration's risk score has to be able to go DOWN.
//
// `crypto_implementations.risk_score` is a LAST-WRITE column, not an
// accumulator, and the ingest path used to write it only when the computed
// score was above zero:
//
//	if cryptoRiskScore > 0 { UPDATE ... SET risk_score = ... }
//
// The reasoning behind the guard was right — a persisted 0 must not read as
// "assessed clean" when nobody looked — and the place it acted on that was
// wrong. A configuration first observed with a component the catalogue rates 90
// kept the 90 through every later observation that resolved to a clean set,
// because the clean answer was 0 and a 0 never reached the row. The product
// reported remediation as unfinished at exactly the moment it was finished, and
// the stale number went on feeding the `crypto` producer's finding, the asset
// roll-up and the risk band.
//
// These tests drive the REAL entry point, AssetService.IngestFindings, not
// catalogue_risk.go's helper — the helper was always correct, and
// catalogue_risk_integration_test.go already pins it. What was broken was the
// WIRING between it and the column, which is only visible end to end.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/cryptoassess"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type riskPersistFixture struct {
	raw    *sqlx.DB
	db     *database.DB
	svc    *AssetService
	tenant uuid.UUID
}

func newRiskPersistFixture(t *testing.T) riskPersistFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	return riskPersistFixture{
		raw:    db.DB,
		db:     db,
		svc:    NewAssetService(db),
		tenant: testdb.NewTenant(t, raw),
	}
}

// run executes the test body under the SHARED schema advisory lock.
//
// Ingest writes a lot of ordinary rows across the partitioned asset and
// configuration tables, and a neighbouring package binary can be applying
// scripts/database/schema.sql at the same time under `go test ./...` — which
// takes ACCESS EXCLUSIVE across those tables and deadlocks against these writes.
// It did, on the first parallel run of this very test. Shared mode, so these
// tests do not serialize against each other; only against an applier.
//
// After newRiskPersistFixture, never around it: the fixture applies the schema
// and takes the same key EXCLUSIVELY to do it.
func (f riskPersistFixture) run(t *testing.T, body func()) {
	t.Helper()
	testdb.WithSchemaShareLock(t, f.raw.DB, body)
}

// observe runs one observation of the same endpoint through the production
// entry point and returns the configuration it materialized.
//
// The natural key is identical every time, so the second and later calls
// RE-OBSERVE the row the first created rather than adding another — which is
// the whole point: the question is what a re-observation does to the score.
//
// `"monitoring"` skips the pending-approval queue. That queue is a separate
// concern with its own tests; withholding the asset here would only mean
// nothing materialises and the test would assert on an empty table.
func (f riskPersistFixture) observe(t *testing.T, host, ip string, port int, version string) uuid.UUID {
	t.Helper()
	p := port
	finding := IngestFinding{
		Hostname:        &host,
		IPAddress:       &ip,
		Port:            &p,
		AssetType:       "server",
		Protocol:        "TLS",
		ProtocolVersion: &version,
		RawData: map[string]interface{}{
			"source":           "sensor",
			"discovery_method": "active",
		},
	}
	if _, err := f.svc.IngestFindings(f.tenant, []IngestFinding{finding}, "monitoring"); err != nil {
		t.Fatalf("IngestFindings(%s): %v", version, err)
	}

	var ids []uuid.UUID
	if err := f.raw.Select(&ids, `
		SELECT ci.id FROM crypto_implementations ci
		  JOIN assets a ON a.id = ci.asset_id AND a.tenant_id = ci.tenant_id
		 WHERE ci.tenant_id = $1 AND a.hostname = $2 AND ci.deleted_at IS NULL`,
		f.tenant, host); err != nil {
		t.Fatalf("look up configuration for %s: %v", host, err)
	}
	if len(ids) != 1 {
		t.Fatalf("%s has %d crypto configurations, want exactly 1 — the dedup key is not "+
			"matching itself, so this test is measuring a different row each observation", host, len(ids))
	}
	return ids[0]
}

// score reads the persisted number.
func (f riskPersistFixture) score(t *testing.T, implID uuid.UUID) int {
	t.Helper()
	var got int
	if err := f.raw.Get(&got, `SELECT COALESCE(risk_score, 0) FROM crypto_implementations WHERE id = $1`, implID); err != nil {
		t.Fatalf("read risk_score: %v", err)
	}
	return got
}

// assessed is the three-valued marker for a CONFIGURATION: at least one
// catalogue component linked in a risk-contributing role.
//
// It is a derived fact rather than a column, and deliberately so — it is
// exactly the predicate the `crypto` finding producer already computes (its
// `cat.linked` count) when deciding whether an asset's crypto was judged at
// all, and a second, stored answer to one question is how two producers come to
// disagree about the same row. Spelled out here so the test asserts the same
// rule the product reads.
func (f riskPersistFixture) assessed(t *testing.T, implID uuid.UUID) bool {
	t.Helper()
	var n int
	if err := f.raw.Get(&n, `
		SELECT COUNT(*) FROM crypto_implementation_algorithms
		 WHERE crypto_implementation_id = $1 AND algorithm_type = ANY($2)`,
		implID, pqArray(cryptoassess.CatalogueRiskRoles)); err != nil {
		t.Fatalf("read linked catalogue components: %v", err)
	}
	return n > 0
}

// rescoreLinked re-assesses every catalogue row this configuration links, to
// `to`, and restores the originals afterwards.
//
// `algorithms` is GLOBAL reference data: testdb.NewTenant's CASCADE cleanup does
// not undo an edit to it, so an un-restored row would silently re-assess that
// algorithm for every later test in this package (the same trap
// catalogue_risk_integration_test.go records).
//
// Editing the catalogue — rather than sending different components — is also the
// only way to move the score of the SAME row: every negotiated component is part
// of the dedup natural key, so an observation carrying different components is a
// different configuration. Which makes this the realistic shape of the bug as
// well: "edit the catalogue row, not Go code" (CLAUDE.md) is the documented way
// to correct an assessment, and a correction downwards has to reach the rows
// already scored under the old one.
func (f riskPersistFixture) rescoreLinked(t *testing.T, implID uuid.UUID, to int) {
	t.Helper()
	type row struct {
		ID        uuid.UUID `db:"id"`
		RiskScore *int      `db:"risk_score"`
	}
	var rows []row
	if err := f.raw.Select(&rows, `
		SELECT a.id, a.risk_score
		  FROM crypto_implementation_algorithms cia
		  JOIN algorithms a ON a.id = cia.algorithm_id
		 WHERE cia.crypto_implementation_id = $1 AND cia.algorithm_type = ANY($2)`,
		implID, pqArray(cryptoassess.CatalogueRiskRoles)); err != nil {
		t.Fatalf("read linked catalogue rows: %v", err)
	}
	if len(rows) == 0 {
		t.Fatalf("configuration %s links no catalogue component — there is nothing to re-assess, "+
			"so this test would prove nothing", implID)
	}
	for _, r := range rows {
		original := r.RiskScore
		id := r.ID
		t.Cleanup(func() {
			if _, err := f.raw.Exec(`UPDATE algorithms SET risk_score = $1 WHERE id = $2`, original, id); err != nil {
				t.Errorf("restore catalogue row %s: %v", id, err)
			}
		})
		if _, err := f.raw.Exec(`UPDATE algorithms SET risk_score = $1 WHERE id = $2`, to, id); err != nil {
			t.Fatalf("re-assess catalogue row %s: %v", id, err)
		}
	}
}

// The ladder, on ONE configuration: up, down, and all the way down to an
// assessed zero.
//
// Each rung is asserted separately rather than only the endpoint, because they
// fail for different reasons and a single end-to-end assertion cannot say which
// rung broke. The rung that the old `score > 0` guard fails is the last one —
// the first three passed before this change, which is precisely why the bug
// survived: every test that moved a score moved it between two non-zero values.
func TestIntegration_CryptoRiskScore_FollowsTheCatalogueDownAsWellAsUp(t *testing.T) {
	f := newRiskPersistFixture(t)
	const host, ip, port = "riskladder.example.test", "192.0.2.31", 443

	f.run(t, func() {
		riskLadder(t, f, host, ip, port)
	})
}

func riskLadder(t *testing.T, f riskPersistFixture, host, ip string, port int) {
	t.Helper()

	implID := f.observe(t, host, ip, port, "TLS 1.2")
	if !f.assessed(t, implID) {
		t.Fatal("the first observation linked no catalogue component, so nothing below is testing " +
			"the catalogue path — check the seeded algorithms table")
	}
	first := f.score(t, implID)
	if first <= 0 {
		t.Fatalf("first observation scored %d, want a positive catalogue score to fall from", first)
	}

	for _, step := range []struct {
		name string
		to   int
	}{
		// Up: the catalogue is re-assessed as dangerous.
		{"raised", 90},
		// Down, but still risky: the number must follow, which it always did.
		{"lowered", 10},
		// Down to clean. THIS is the regression: the computed score is 0, and
		// the old guard refused to write it, so the row kept the 10 above.
		{"lowered to an assessed zero", 0},
	} {
		t.Run(step.name, func(t *testing.T) {
			f.rescoreLinked(t, implID, step.to)

			same := f.observe(t, host, ip, port, "TLS 1.2")
			if same != implID {
				t.Fatalf("re-observation materialized a different configuration (%s, was %s)", same, implID)
			}
			if got := f.score(t, implID); got != step.to {
				t.Errorf("risk_score = %d after the catalogue was re-assessed to %d — "+
					"the persisted score does not follow the catalogue in this direction", got, step.to)
			}
			// And the zero, when it comes, is an ASSESSED zero: the components
			// are still linked, so it reads as "clean", never as "nobody
			// looked".
			if !f.assessed(t, implID) {
				t.Error("the configuration lost its catalogue components, so its score is no longer " +
					"distinguishable from NOT ASSESSED")
			}
		})
	}
}

// A pass that could resolve NOTHING writes nothing, and says so.
//
// This is the other half of the change, and the half that keeps the
// three-valued honesty: an observation whose components resolve to no catalogue
// row has not judged the configuration clean, it has not judged it at all. It
// must leave whatever verdict an earlier, better-informed pass reached exactly
// as it found it — overwriting a real score with a 0 it cannot justify would be
// a worse lie than the stale score this change removes.
func TestIntegration_CryptoRiskScore_AnUnresolvablePassLeavesTheScoreAlone(t *testing.T) {
	f := newRiskPersistFixture(t)
	const host, ip, port = "unresolvable.example.test", "192.0.2.32", 8443

	f.run(t, func() {
		unresolvablePass(t, f, host, ip, port)
	})
}

func unresolvablePass(t *testing.T, f riskPersistFixture, host, ip string, port int) {
	t.Helper()

	// A protocol version the catalogue has never heard of. The protocol itself
	// is TLS, so the row materialises; nothing about it resolves.
	implID := f.observe(t, host, ip, port, "TLS 9.9-vendor-preview")
	if f.assessed(t, implID) {
		t.Fatal("expected no catalogue component to resolve for an invented protocol version")
	}
	if got := f.score(t, implID); got != 0 {
		t.Fatalf("an unassessed configuration scored %d, want 0 (NOT ASSESSED)", got)
	}

	// Somebody — a past pass, an operator, another producer — put a real verdict
	// on the row. A later pass that resolves nothing must not erase it.
	if _, err := f.raw.Exec(`UPDATE crypto_implementations SET risk_score = 55 WHERE id = $1`, implID); err != nil {
		t.Fatalf("seed a prior verdict: %v", err)
	}

	if same := f.observe(t, host, ip, port, "TLS 9.9-vendor-preview"); same != implID {
		t.Fatalf("re-observation materialized a different configuration (%s, was %s)", same, implID)
	}

	if got := f.score(t, implID); got != 55 {
		t.Errorf("risk_score = %d after a pass that resolved nothing, want 55 unchanged — "+
			"a pass with no opinion has overwritten one that had", got)
	}
	if f.assessed(t, implID) {
		t.Error("the unresolvable pass claimed a catalogue assessment it did not make")
	}
}

// pqArray binds a Go string slice as a Postgres text[]. Spelled out rather than
// importing lib/pq into the test for one call, so the helper reads the same as
// the production queries it mirrors.
func pqArray(vals []string) interface{} {
	out := "{"
	for i, v := range vals {
		if i > 0 {
			out += ","
		}
		out += fmt.Sprintf("%q", v)
	}
	return out + "}"
}
