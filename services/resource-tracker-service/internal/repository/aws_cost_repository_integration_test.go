package repository

// Guard for B-57: StoreCostData's ON CONFLICT arbiter used to be
// `(tenant_id, cost_date, service_name, COALESCE(usage_type, ''))` with no
// WHERE clause, against a table whose only matching unique index is PARTIAL
// (`WHERE deleted_at IS NULL`). Postgres will not infer a partial index as an
// arbiter without the predicate in the ON CONFLICT clause, so every call
// failed with 42P10 ("no unique or exclusion constraint matching the ON
// CONFLICT specification"). StoreCostData's per-row `continue` on error
// swallowed that, so the sync silently stored nothing — see the batch brief.
//
// Fixing only the WHERE clause is not enough on its own: aws_cost_data.tenant_id
// is nullable (the platform-wide sync writes tenant_id = NULL), and Postgres
// unique indexes treat NULL as distinct from every other value, including
// another NULL, so a bare `tenant_id` column in the arbiter can never make a
// second NULL-tenant row conflict with the first. Both the index (schema.sql)
// and this arbiter COALESCE tenant_id to the same sentinel UUID so a
// platform-wide row collapses onto one key like every other row.
//
// A unit test over a fake DB cannot exercise real ON CONFLICT / partial-index
// arbiter matching, so this is a DB-integration test (shared/testdb harness).
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/aws"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func newTestAWSCostRepository(t *testing.T) *AWSCostRepository {
	t.Helper()
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	log := logrus.New()
	log.SetLevel(logrus.PanicLevel) // keep test output quiet; StoreCostData logs per-row errors at Error level
	return NewAWSCostRepository(db, db, log)
}

// countCostRows returns how many aws_cost_data rows exist for the given
// (tenant_id, cost_date, service_name) key. tenant_id is compared with `IS NOT
// DISTINCT FROM` so a nil tenantID correctly matches a NULL column instead of
// matching nothing (the exact NULL-semantics trap this bug lived in).
func countCostRows(t *testing.T, repo *AWSCostRepository, tenantID interface{}, costDate, service string) int {
	t.Helper()
	var n int
	err := repo.bypassDB.QueryRow(
		`SELECT COUNT(*) FROM aws_cost_data WHERE tenant_id IS NOT DISTINCT FROM $1 AND cost_date = $2 AND service_name = $3`,
		tenantID, costDate, service,
	).Scan(&n)
	if err != nil {
		t.Fatalf("countCostRows: %v", err)
	}
	return n
}

// TestIntegration_StoreCostData_PlatformWideUpsertsNotDuplicates proves the
// platform-wide sync path (tenant_id NULL) — the one the audit found could
// never conflict with itself — actually upserts on a second sync of the same
// day/service instead of erroring or silently duplicating.
func TestIntegration_StoreCostData_PlatformWideUpsertsNotDuplicates(t *testing.T) {
	repo := newTestAWSCostRepository(t)
	ctx := context.Background()

	const costDate = "2026-08-01"
	const service = "b57-platform-ec2" // distinctive name so cleanup can't clip real data

	t.Cleanup(func() {
		_, _ = repo.bypassDB.Exec(`DELETE FROM aws_cost_data WHERE service_name = $1`, service)
	})

	first := []aws.AWSCostData{{
		TenantID: nil,
		Service:  service,
		Amount:   10.00,
		Currency: "USD",
		Date:     mustParseDate(t, costDate),
	}}
	if err := repo.StoreCostData(ctx, first); err != nil {
		t.Fatalf("first StoreCostData: %v", err)
	}
	if n := countCostRows(t, repo, nil, costDate, service); n != 1 {
		t.Fatalf("after first sync: got %d rows, want 1", n)
	}

	second := []aws.AWSCostData{{
		TenantID: nil,
		Service:  service,
		Amount:   25.00,
		Currency: "USD",
		Date:     mustParseDate(t, costDate),
	}}
	if err := repo.StoreCostData(ctx, second); err != nil {
		t.Fatalf("second StoreCostData: %v", err)
	}

	// The bug's failure mode was silence: StoreCostData swallowed the 42P10 per
	// row and still returned nil. Assert the row count AND the stored value,
	// not just "no error" — a test that only checked err==nil would have
	// passed while storing nothing (0 rows) just as easily as while storing 2.
	if n := countCostRows(t, repo, nil, costDate, service); n != 1 {
		t.Fatalf("after second sync: got %d rows, want 1 (must be an UPDATE, not a duplicate insert)", n)
	}

	var amount float64
	if err := repo.bypassDB.QueryRow(
		`SELECT amount FROM aws_cost_data WHERE tenant_id IS NULL AND cost_date = $1 AND service_name = $2`,
		costDate, service,
	).Scan(&amount); err != nil {
		t.Fatalf("read back amount: %v", err)
	}
	if amount != 25.00 {
		t.Fatalf("amount = %v, want 25.00 (second sync's value should have overwritten the first)", amount)
	}
}

// TestIntegration_StoreCostData_TenantScopedUpsertsNotDuplicates proves the
// ordinary per-tenant sync path (tenant_id set) still upserts correctly with
// the same fix in place.
func TestIntegration_StoreCostData_TenantScopedUpsertsNotDuplicates(t *testing.T) {
	repo := newTestAWSCostRepository(t)
	ctx := context.Background()
	tenantID := testdb.NewTenant(t, repo.bypassDB)

	const costDate = "2026-08-02"
	const service = "b57-tenant-s3"

	t.Cleanup(func() {
		_, _ = repo.bypassDB.Exec(`DELETE FROM aws_cost_data WHERE service_name = $1`, service)
	})

	first := []aws.AWSCostData{{
		TenantID: &tenantID,
		Service:  service,
		Amount:   5.00,
		Currency: "USD",
		Date:     mustParseDate(t, costDate),
	}}
	if err := repo.StoreCostData(ctx, first); err != nil {
		t.Fatalf("first StoreCostData: %v", err)
	}
	second := []aws.AWSCostData{{
		TenantID: &tenantID,
		Service:  service,
		Amount:   9.00,
		Currency: "USD",
		Date:     mustParseDate(t, costDate),
	}}
	if err := repo.StoreCostData(ctx, second); err != nil {
		t.Fatalf("second StoreCostData: %v", err)
	}

	if n := countCostRows(t, repo, tenantID, costDate, service); n != 1 {
		t.Fatalf("got %d rows for tenant-scoped sync, want 1 (must be an UPDATE, not a duplicate insert)", n)
	}

	var amount float64
	if err := repo.bypassDB.QueryRow(
		`SELECT amount FROM aws_cost_data WHERE tenant_id = $1 AND cost_date = $2 AND service_name = $3`,
		tenantID, costDate, service,
	).Scan(&amount); err != nil {
		t.Fatalf("read back amount: %v", err)
	}
	if amount != 9.00 {
		t.Fatalf("amount = %v, want 9.00", amount)
	}
}

func mustParseDate(t *testing.T, s string) time.Time {
	t.Helper()
	parsed, err := time.Parse("2006-01-02", s)
	if err != nil {
		t.Fatalf("parse date %q: %v", s, err)
	}
	return parsed
}

// TestIntegration_Schema_ReappliesOverDuplicateCostRows is the schema-side half
// of B-57, and the reason the first attempt at this fix was rejected.
//
// idx_aws_cost_data_unique_v2 collapses a NULL tenant_id onto a sentinel UUID.
// That is the correct arbiter — but it makes rows that were DISTINCT under the
// old index collide, and duplicate NULL-tenant rows are precisely what the
// broken sync produced. Creating the index on such a database raises
// "could not create unique index ... Key (...) is duplicated", and the chart's
// schema-migration Job runs the file under `psql -v ON_ERROR_STOP=1`, so that
// aborts the ENTIRE migration — every helm upgrade fails, not just the cost
// feature.
//
// schema.sql therefore de-duplicates immediately BEFORE the CREATE UNIQUE
// INDEX, in the pg_dump body rather than in POST-MIGRATIONS: the index lives
// thousands of lines above POST-MIGRATIONS, so a repair appended at the bottom
// would only run after the statement it exists to unblock had already failed.
//
// A double-apply against an EMPTY database proves nothing here — the CREATE
// succeeds trivially on an empty table. This test populates the duplicates
// first, exactly the way the bug did.
func TestIntegration_Schema_ReappliesOverDuplicateCostRows(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	const service = "b57-reapply-ec2"
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM aws_cost_data WHERE service_name = $1`, service)
		// Restore the index the body creates, in case a failed run left it off.
		_, _ = db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_aws_cost_data_unique_v2 ON public.aws_cost_data USING btree (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), cost_date, service_name, COALESCE(usage_type, ''::character varying)) WHERE (deleted_at IS NULL)`)
	})

	// Rewind to the pre-migration state: the v2 index does not exist yet, so the
	// duplicates the buggy sync produced can be inserted.
	if _, err := db.Exec(`DROP INDEX IF EXISTS public.idx_aws_cost_data_unique_v2`); err != nil {
		t.Fatalf("drop v2 index: %v", err)
	}
	for _, amount := range []float64{10, 11, 12} {
		if _, err := db.Exec(`
			INSERT INTO aws_cost_data (tenant_id, cost_date, service_name, amount, currency, usage_type, synced_at)
			VALUES (NULL, '2026-08-01', $1, $2, 'USD', 'BoxUsage', NOW() - ($3 || ' hours')::interval)`,
			service, amount, int(amount)); err != nil {
			t.Fatalf("insert duplicate cost row: %v", err)
		}
	}
	// A soft-deleted duplicate: outside the partial index, and the dedup must
	// leave it alone.
	if _, err := db.Exec(`
		INSERT INTO aws_cost_data (tenant_id, cost_date, service_name, amount, currency, usage_type, synced_at, deleted_at)
		VALUES (NULL, '2026-08-01', $1, 99, 'USD', 'BoxUsage', NOW(), NOW())`, service); err != nil {
		t.Fatalf("insert soft-deleted row: %v", err)
	}

	// Re-apply the schema exactly as the migration Job does.
	body, err := os.ReadFile(filepath.Join(testdb.RepoRoot(t), "scripts", "database", "schema.sql"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	// Take the same advisory lock testdb's own applier uses (key 889). `go test
	// ./...` runs package binaries in parallel, and two concurrent appliers fail
	// with "tuple concurrently updated" on the GRANT / ALTER DEFAULT PRIVILEGES
	// statements — a race, not a schema bug, but one that would make this guard
	// flaky and therefore ignorable.
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("acquire connection: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(context.Background(), `SELECT pg_advisory_lock(889)`); err != nil {
		t.Fatalf("pg_advisory_lock: %v", err)
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(889)`) }()

	if _, err := conn.ExecContext(context.Background(), string(body)); err != nil {
		t.Fatalf("schema.sql is not re-appliable once aws_cost_data holds the duplicates the buggy "+
			"sync produced — the migration Job would abort on the next helm upgrade: %v", err)
	}

	var live, soft int
	if err := db.QueryRow(
		`SELECT COUNT(*) FILTER (WHERE deleted_at IS NULL), COUNT(*) FILTER (WHERE deleted_at IS NOT NULL)
		   FROM aws_cost_data WHERE service_name = $1`, service,
	).Scan(&live, &soft); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if live != 1 {
		t.Errorf("live rows after re-apply = %d, want 1 (the dedup must keep exactly one per key)", live)
	}
	if soft != 1 {
		t.Errorf("soft-deleted rows after re-apply = %d, want 1 (rows outside the partial index must survive)", soft)
	}

	// The survivor must be the most recently synced one, not an arbitrary row.
	var amount float64
	if err := db.QueryRow(
		`SELECT amount FROM aws_cost_data WHERE service_name = $1 AND deleted_at IS NULL`, service,
	).Scan(&amount); err != nil {
		t.Fatalf("read survivor: %v", err)
	}
	if amount != 10 {
		t.Errorf("surviving amount = %v, want 10 (the row with the newest synced_at)", amount)
	}
}
