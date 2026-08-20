package services

// Guards for B-40 and the B-18 remnant, which share one statement.
//
// B-40: the three materialized views are declared `CREATE MATERIALIZED VIEW IF
// NOT EXISTS`, and nothing anywhere dropped them (repo-wide DROP MATERIALIZED
// VIEW count was 0) after the POST-MIGRATIONS collapse removed the old
// drop+recreate block. `CREATE MATERIALIZED VIEW` has no OR REPLACE and IF NOT
// EXISTS matches by NAME, so any edit to a matview body was a silent no-op on
// every existing install: schema-migration exits 0 while the cluster keeps the
// stale definition. Worse, the file still runs `DROP TABLE IF EXISTS
// public.network_assets_legacy CASCADE`, which on a pre-partition-conversion
// cluster took mv_location_finding_summary with it — and the later
// `CREATE OR REPLACE VIEW mv_..._tenant AS SELECT * FROM mv_...` then failed
// under ON_ERROR_STOP=1, wedging the upgrade entirely.
//
// B-18 remnant: mv_location_finding_summary counted findings with
// `FILTER (WHERE a.risk_level = 'Critical')` and v_ci_inventory's asset branch
// selected the stored risk_level column. Nothing writes that column — ingest
// updates risk_score and never its sibling — so it sits at its schema DEFAULT
// 'Informational' forever, making those four counters structurally zero and
// pushing `risk_level: "Informational"` next to `risk_score: 90` into any CMDB
// sync profile that maps it. Both now band risk_score through the canonical
// ladder in models/risk_bands.go.
//
// The two are tested together because the banded body only reaches an existing
// database THROUGH the B-40 drop+recreate. A double-apply against an empty
// database proves neither: the matview is empty either way and the counters are
// zero either way. This test inserts assets spanning every band BETWEEN the two
// applies, so the assertions can only pass if the re-apply rebuilt the matview
// AND the rebuilt body bands risk_score.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db). Addresses are RFC 5737 documentation ranges.

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_Schema_MatviewsRebuildAndBandRiskScore(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)

	locationID := uuid.New()
	mustExec(t, db, `
		INSERT INTO locations (id, tenant_id, name, location_type, full_path)
		VALUES ($1,$2,'B-40 HQ','site','/b40-hq')`, locationID, tenant)

	// One asset per band, including 0 = NOT ASSESSED, which must land in none of
	// the four counters.
	type banded struct {
		host  string
		ip    string
		score int
		level string
	}
	assets := []banded{
		{"b40-crit.example.test", "192.0.2.90", 95, "Critical"},
		{"b40-high.example.test", "192.0.2.75", 75, "High"},
		{"b40-med.example.test", "192.0.2.55", 55, "Medium"},
		{"b40-low.example.test", "192.0.2.10", 10, "Low"},
		{"b40-none.example.test", "192.0.2.1", 0, "Informational"},
	}
	ids := make(map[string]uuid.UUID, len(assets))
	for _, a := range assets {
		id := uuid.New()
		ids[a.host] = id
		mustExec(t, db, `
			INSERT INTO network_assets (id, tenant_id, location_id, hostname, ip_address, environment,
			                            asset_type, asset_status, risk_score, last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,'production','server','monitoring',$6,NOW(),NOW(),NOW(),NOW())`,
			id, tenant, locationID, a.host, a.ip, a.score)
	}

	// Re-apply the schema exactly as the migration Job does. Advisory lock 889 is
	// testdb's own applier lock — see the note in the aws_cost_data guard.
	body, err := os.ReadFile(filepath.Join(testdb.RepoRoot(t), "scripts", "database", "schema.sql"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("acquire connection: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(889)`); err != nil {
		t.Fatalf("pg_advisory_lock: %v", err)
	}
	defer func() { _, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock(889)`) }()

	if _, err := conn.ExecContext(ctx, string(body)); err != nil {
		t.Fatalf("schema.sql is not re-appliable over an existing, populated database: %v", err)
	}

	// B-40: the matview must have been REBUILT, so it sees rows inserted after it
	// was last built. Under `CREATE ... IF NOT EXISTS` this query returns no rows
	// at all — the location simply is not in the stale snapshot.
	var assetCount, critical, high, medium, low int
	err = db.QueryRow(`
		SELECT asset_count, critical_findings, high_findings, medium_findings, low_findings
		  FROM mv_location_finding_summary WHERE location_id = $1`, locationID,
	).Scan(&assetCount, &critical, &high, &medium, &low)
	if err != nil {
		t.Fatalf("mv_location_finding_summary has no row for a location created before the re-apply — "+
			"the matview kept its stale definition and data (B-40): %v", err)
	}
	if assetCount != len(assets) {
		t.Errorf("asset_count = %d, want %d", assetCount, len(assets))
	}

	// B-18: one asset per band, from risk_score. Before the fix all four were 0,
	// because every asset's stored risk_level was the DEFAULT 'Informational'.
	for _, tc := range []struct {
		name string
		got  int
	}{{"critical_findings", critical}, {"high_findings", high}, {"medium_findings", medium}, {"low_findings", low}} {
		if tc.got != 1 {
			t.Errorf("%s = %d, want 1 — the counters must band risk_score, not read the never-written risk_level column",
				tc.name, tc.got)
		}
	}

	// B-18: v_ci_inventory's asset branch must band too, matching the
	// crypto_configuration branch of the same view.
	for _, a := range assets {
		var score int
		var level string
		if err := db.QueryRow(
			`SELECT risk_score, risk_level FROM v_ci_inventory WHERE id = $1 AND ci_category = 'infrastructure_asset'`,
			ids[a.host],
		).Scan(&score, &level); err != nil {
			t.Fatalf("read v_ci_inventory for %s: %v", a.host, err)
		}
		if score != a.score || level != a.level {
			t.Errorf("v_ci_inventory %s: risk_score=%d risk_level=%q, want %d/%q",
				a.host, score, level, a.score, a.level)
		}
	}

	// The view's risk_level column must stay `character varying`. CREATE OR
	// REPLACE VIEW cannot change a column's type, so emitting ::text from the
	// first UNION branch (which is what decides the resolved type) aborts the
	// migration on every EXISTING install while passing on a fresh one. The
	// re-apply above is the real proof; this pins the reason.
	var dataType string
	if err := db.QueryRow(`
		SELECT data_type FROM information_schema.columns
		 WHERE table_name = 'v_ci_inventory' AND column_name = 'risk_level'`).Scan(&dataType); err != nil {
		t.Fatalf("read v_ci_inventory column type: %v", err)
	}
	if dataType != "character varying" {
		t.Errorf("v_ci_inventory.risk_level type = %q, want \"character varying\" — "+
			"changing it breaks CREATE OR REPLACE VIEW on every existing install", dataType)
	}
}
