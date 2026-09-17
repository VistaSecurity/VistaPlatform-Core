package processor

// Integration proof, against a real Postgres with the real schema, that the
// retention sweep purges only what it is supposed to: PROCESSED rows past the
// retention window, and nothing else.
//
// Mutation that proves this test: in deleteBatch's DELETE, drop
// `processed_at IS NOT NULL` — "unprocessed survives" goes red (the
// still-being-worked row is deleted). Drop the age predicate
// (`processed_at < $1`) — "recent survives" goes red (a row processed
// seconds ago is deleted alongside the week-old one).
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// seedDiscoveryRow writes one sensor_discoveries row with an explicit
// processed_at (nil for unprocessed), backdated by insertAge from now.
func seedDiscoveryRow(t *testing.T, db *sqlx.DB, tenant uuid.UUID, ip string, processedAt *time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.Exec(`
		INSERT INTO sensor_discoveries
			(id, sensor_id, tenant_id, batch_id, protocol, dest_ip, port, confidence, metadata, approval_status, processed_at)
		VALUES ($1, $2, $3, $4, 'TLS', $5::inet, 443, 0.9, '{}'::jsonb, 'auto_approved', $6)`,
		id, uuid.New(), tenant, uuid.New().String(), ip, processedAt)
	if err != nil {
		t.Fatalf("seed discovery row: %v", err)
	}
	return id
}

func rowExists(t *testing.T, db *sqlx.DB, id uuid.UUID) bool {
	t.Helper()
	var n int
	if err := db.Get(&n, `SELECT count(*) FROM sensor_discoveries WHERE id = $1`, id); err != nil {
		t.Fatalf("check row existence: %v", err)
	}
	return n > 0
}

func TestIntegration_RetentionSweep_DeletesOnlyOldProcessedRows(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	now := time.Now().UTC()
	old := now.Add(-30 * 24 * time.Hour) // 30 days ago — well past a 7-day window
	recent := now.Add(-1 * time.Hour)    // processed an hour ago — well inside it

	processedOld := seedDiscoveryRow(t, db, tenant, "198.51.100.101", &old)
	processedRecent := seedDiscoveryRow(t, db, tenant, "198.51.100.102", &recent)
	unprocessedOld := seedDiscoveryRow(t, db, tenant, "198.51.100.103", nil)
	// An unprocessed row's own `created_at`/`timestamp` can still be old — the
	// sweep must judge by processed_at, not by how long the row has existed.
	if _, err := db.Exec(`UPDATE sensor_discoveries SET timestamp = $1, created_at = $1 WHERE id = $2`, old, unprocessedOld); err != nil {
		t.Fatalf("backdate unprocessed row: %v", err)
	}

	j := NewRetentionSweepJob(db)
	j.window = 7 * 24 * time.Hour
	j.batchSize = 2
	j.now = func() time.Time { return now }

	j.Sweep(context.Background())

	if rowExists(t, db, processedOld) {
		t.Error("the old processed row survived the sweep")
	}
	if !rowExists(t, db, processedRecent) {
		t.Error("a recently processed row was deleted — it is well inside the retention window")
	}
	if !rowExists(t, db, unprocessedOld) {
		t.Error("an UNPROCESSED row was deleted — the sweep must never touch processed_at IS NULL, however old")
	}
}

// The sweep works through a backlog larger than one batch, purging it all in
// one Sweep() call rather than leaving the tail for the next tick.
func TestIntegration_RetentionSweep_WorksThroughABacklogLargerThanOneBatch(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	now := time.Now().UTC()
	old := now.Add(-30 * 24 * time.Hour)

	const total = 7
	ids := make([]uuid.UUID, total)
	for i := range ids {
		ids[i] = seedDiscoveryRow(t, db, tenant, "198.51.100.2"+string(rune('0'+i)), &old)
	}

	j := NewRetentionSweepJob(db)
	j.window = 7 * 24 * time.Hour
	j.batchSize = 2 // Forces 4 delete calls (2+2+2+1) for 7 rows.
	j.now = func() time.Time { return now }

	j.Sweep(context.Background())

	for _, id := range ids {
		if rowExists(t, db, id) {
			t.Errorf("row %s survived a sweep that should have worked through the whole backlog", id)
		}
	}
}

// A sweep that finds nothing to do is a no-op, not an error — the healthy
// steady state once the backlog is drained.
func TestIntegration_RetentionSweep_NothingToDoIsFine(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	now := time.Now().UTC()
	recent := now.Add(-1 * time.Minute)
	row := seedDiscoveryRow(t, db, tenant, "198.51.100.201", &recent)

	j := NewRetentionSweepJob(db)
	j.window = 7 * 24 * time.Hour
	j.now = func() time.Time { return now }

	j.Sweep(context.Background()) // Must not panic or error out.

	if !rowExists(t, db, row) {
		t.Error("a row well inside the retention window was deleted by a sweep with nothing due")
	}
}
