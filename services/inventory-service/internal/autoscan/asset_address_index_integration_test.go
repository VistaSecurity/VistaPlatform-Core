package autoscan

// The assets address index against a real Postgres.
//
// Every address lookup in the services compares host(primary_address) with a
// text value -- a scan target's input, a source IP -- so the index that serves
// it has to be on that expression. Two ways to lose it silently, and neither
// shows up in a unit test or in a schema double-apply:
//
//   - an index on the bare inet column, which looks right and cannot serve a
//     host(primary_address) predicate (the function is on the column side);
//   - a PARTIAL index, which serves the lookup but hides the expression's
//     n_distinct from the planner. It then prices every join probe at the
//     1-in-200 default and keeps a hash join over the tenant's whole asset
//     set even though the index is there and two orders of magnitude faster.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"strings"
	"testing"
)

const addressIndexName = "idx_assets_tenant_primary_host"

// The definition is pinned, not just the name: the two regressions above both
// keep the name.
func TestIntegration_AssetAddressIndex_IsOnHostExpressionAndNotPartial(t *testing.T) {
	_, db, _ := newStampFixture(t)

	var def string
	if err := db.QueryRow(
		`SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' AND tablename = 'assets' AND indexname = $1`,
		addressIndexName).Scan(&def); err != nil {
		t.Fatalf("the %s index is missing from public.assets: %v", addressIndexName, err)
	}
	if !strings.Contains(def, "host(primary_address)") {
		t.Errorf("index is not on host(primary_address), so it cannot serve the address lookups: %s", def)
	}
	if !strings.Contains(def, "(tenant_id, host(primary_address))") {
		t.Errorf("index must lead with tenant_id, as every lookup is tenant-scoped: %s", def)
	}
	if strings.Contains(strings.ToUpper(def), " WHERE ") {
		t.Errorf("index must not be partial -- the planner ignores a partial index's expression "+
			"statistics and keeps the hash join over the tenant's assets: %s", def)
	}
}

// The index is usable for the predicate shape the lookups write. Seq scans are
// switched off so a tiny table's cost model cannot pick the scan for us: what
// is asserted is that the planner HAS an index path for the predicate, which a
// btree on the bare inet column does not provide.
func TestIntegration_AssetAddressIndex_ServesTheHostTextLookup(t *testing.T) {
	_, db, tenant := newStampFixture(t)

	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, primary_address, metadata,
		                    last_seen_at, first_discovered_at, created_at, updated_at)
		SELECT gen_random_uuid(), $1, 'addr' || g, 'server', 'hardware.computer.server', 'monitoring',
		       ('10.' || (g / 65536) || '.' || ((g / 256) % 256) || '.' || (g % 256))::inet, '{}'::jsonb,
		       NOW(), NOW(), NOW(), NOW()
		FROM generate_series(1, 2000) g`, tenant); err != nil {
		t.Fatalf("seed assets: %v", err)
	}
	// A partition that has never been analysed is costed as ten pages, at which
	// size several indexes tie and the planner may take the tenant_id-only one.
	// Give this tenant's partition real statistics; they roll back with the
	// transaction, so the shared database is left as it was found.
	var partition string
	if err := tx.QueryRowContext(ctx,
		`SELECT tableoid::regclass::text FROM assets WHERE tenant_id = $1 LIMIT 1`, tenant).Scan(&partition); err != nil {
		t.Fatalf("find the tenant's partition: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `ANALYZE `+partition); err != nil {
		t.Fatalf("ANALYZE %s: %v", partition, err)
	}
	if _, err := tx.ExecContext(ctx, `SET LOCAL enable_seqscan = off`); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}

	rows, err := tx.QueryContext(ctx, `EXPLAIN (COSTS OFF)
		SELECT a.id FROM assets a
		WHERE a.tenant_id = $1 AND host(a.primary_address) = $2 AND a.deleted_at IS NULL`,
		tenant, "10.0.1.5")
	if err != nil {
		t.Fatalf("EXPLAIN: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var plan []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatalf("scan plan: %v", err)
		}
		plan = append(plan, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("plan rows: %v", err)
	}
	// The expression must appear in an Index Cond. It also appears in a Filter
	// when the planner scans another index and filters by it, which is the
	// failure this is here to catch.
	for _, line := range plan {
		if strings.Contains(line, "Index Cond") && strings.Contains(line, "host(primary_address) = ") {
			return
		}
	}
	t.Fatalf("the lookup does not use an index condition on host(primary_address):\n%s", strings.Join(plan, "\n"))
}
