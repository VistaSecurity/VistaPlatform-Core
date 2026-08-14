package services

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// TestIntegration_StampRestoreSQL exercises the exact statements
// stampScanFailed issues, against a real Postgres, on a table shaped like the
// columns it touches. It is the only way to prove the pq array encoding and the
// unnest($2::uuid[], $3::timestamptz[]) cast actually round-trip — a unit test
// over planStampRestore pins the decision, not the SQL that carries it out.
//
// Skips unless SCAN_RESTORE_TEST_DSN is set (same convention as the repo's other
// DB-integration tests: the PR gate stays green without a database).
func TestIntegration_StampRestoreSQL(t *testing.T) {
	const probeTable = "scan_restore_probe"

	dsn := os.Getenv("SCAN_RESTORE_TEST_DSN")
	if dsn == "" {
		t.Skip("SCAN_RESTORE_TEST_DSN not set; skipping live SQL check")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.Exec(`
		DROP TABLE IF EXISTS scan_restore_probe;
		CREATE TABLE scan_restore_probe (
			id               uuid PRIMARY KEY,
			tenant_id        uuid NOT NULL,
			last_scanned_at  timestamptz,
			last_scan_status text,
			updated_at       timestamptz DEFAULT now()
		);`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	tenantID := uuid.New()
	neverScanned := uuid.New()
	scannedBefore := uuid.New()
	when := time.Date(2026, 8, 6, 14, 30, 45, 123456000, time.UTC)

	// Seed: one asset never scanned, one scanned a week ago.
	if _, err := db.Exec(`INSERT INTO scan_restore_probe (id, tenant_id, last_scanned_at) VALUES ($1,$2,NULL),($3,$2,$4)`,
		neverScanned, tenantID, scannedBefore, when); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Capture prior state, then apply the optimistic stamp (what stampScanning does).
	prior := []scanStamp{
		{assetID: neverScanned, lastScannedAt: sql.NullTime{Valid: false}},
		{assetID: scannedBefore, lastScannedAt: sql.NullTime{Time: when, Valid: true}},
	}
	if _, err := db.Exec(`UPDATE scan_restore_probe SET last_scanned_at = now(), last_scan_status = 'scanning' WHERE tenant_id = $1`, tenantID); err != nil {
		t.Fatalf("stamp: %v", err)
	}

	// Now the restore — the SAME statements stampScanFailed issues, from the
	// same builders, pointed at the probe table.
	nullIDs, tsIDs, tsValues := planStampRestore(prior)
	if len(nullIDs) > 0 {
		if _, err := db.Exec(restoreNullStampSQL(probeTable), tenantID, pq.Array(nullIDs)); err != nil {
			t.Fatalf("restore NULL group: %v", err)
		}
	}
	if len(tsIDs) > 0 {
		if _, err := db.Exec(restoreTimestampStampSQL(probeTable), tenantID, pq.Array(tsIDs), pq.Array(tsValues)); err != nil {
			t.Fatalf("restore timestamp group: %v", err)
		}
	}

	// Direction 1: never-scanned asset is back to NULL (returns to the Active Scan list).
	var got sql.NullTime
	var status string
	if err := db.QueryRow(`SELECT last_scanned_at, last_scan_status FROM scan_restore_probe WHERE id = $1`, neverScanned).Scan(&got, &status); err != nil {
		t.Fatalf("read never-scanned: %v", err)
	}
	if got.Valid {
		t.Errorf("never-scanned asset should be NULL after restore, got %v", got.Time)
	}
	if status != "failed" {
		t.Errorf("last_scan_status = %q, want \"failed\"", status)
	}

	// Direction 2: previously-scanned asset keeps its REAL timestamp — history intact.
	if err := db.QueryRow(`SELECT last_scanned_at, last_scan_status FROM scan_restore_probe WHERE id = $1`, scannedBefore).Scan(&got, &status); err != nil {
		t.Fatalf("read previously-scanned: %v", err)
	}
	if !got.Valid {
		t.Fatal("previously-scanned asset was blanked — real scan history erased")
	}
	if !got.Time.UTC().Equal(when) {
		t.Errorf("last_scanned_at = %v, want the exact prior instant %v", got.Time.UTC(), when)
	}
	if status != "failed" {
		t.Errorf("last_scan_status = %q, want \"failed\"", status)
	}

	_, _ = db.Exec(`DROP TABLE IF EXISTS scan_restore_probe`)
}
