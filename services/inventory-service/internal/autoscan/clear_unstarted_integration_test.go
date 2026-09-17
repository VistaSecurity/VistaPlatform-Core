package autoscan

// ClearUnstartedScanStamps against a real Postgres: which assets get their
// "last automatically scanned" stamp handed back, in both polarities.
//
// RecordScanned stamps at ENQUEUE, deliberately — an unanswered probe is still
// a probe, and re-stamping only on success would re-queue a permanently-silent
// host on every tick. The exception this covers is a job that never ran at
// all: a sensor that refuses the command, or never collects it before the
// command expires, touches nothing, and the enqueue stamp then claims a scan
// that did not happen.
//
// The discriminator is the structured column `started_at`, not the wording of
// error_message. Each test seeds one asset whose stamp names one job and
// varies exactly one thing about that job.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
)

// unstartedSeed is one auto-scan dispatch as the stamp-clearing path sees it.
type unstartedSeed struct {
	jobStatus string // 'failed' | 'completed' | 'queued'
	started   bool   // did anything ever begin? (started_at NOT NULL)
	automatic bool   // false = a manual Active Scan, which this path must ignore
	// stampNamesJob false points the asset's last_auto_scan_job_id at some
	// OTHER job, so a later sweep's stamp is never undone by an older failure.
	stampNamesJob bool
}

// seedUnstartedScan writes the asset and the job its stamp names. Returns the
// asset id.
func seedUnstartedScan(t *testing.T, db *sql.DB, tenant uuid.UUID, seed unstartedSeed) uuid.UUID {
	t.Helper()
	assetID, jobID := uuid.New(), uuid.New()
	const addr = "10.20.30.41"

	namedJob := jobID
	if !seed.stampNamesJob {
		namedJob = uuid.New()
	}

	execOrFail(t, db, `
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, primary_address, metadata,
		                    last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1, $2, 'unstarted.example.test', 'server', 'hardware.computer.server', 'monitoring', $3::inet,
		        jsonb_build_object('last_auto_scan_job_id', $4::text,
		                           'last_auto_scan_at', '2026-09-17T06:00:00Z',
		                           'keep_me', 'yes'),
		        NOW(), NOW(), NOW(), NOW())`,
		assetID, tenant, addr, namedJob.String())

	metadata := `{"options":{"active_scan":true}}`
	if seed.automatic {
		metadata = `{"options":{"active_scan":true,"origin":"` + Origin + `"}}`
	}
	var startedAt any
	if seed.started {
		startedAt = "2026-09-17T06:00:30Z"
	}
	execOrFail(t, db, `
		INSERT INTO discovery_jobs (id, tenant_id, execution_mode, status, started_at, completed_at, error_message, metadata, created_at, updated_at)
		VALUES ($1, $2, 'sensors', $3, $4, NOW(), 'sensor probe-1 refused the job: Unknown command type: discovery_job; nothing was scanned',
		        $5::jsonb, NOW() - interval '1 hour', NOW())`,
		jobID, tenant, seed.jobStatus, startedAt, metadata)

	return assetID
}

// readScanStamp returns the asset's stamp fields and one unrelated metadata key,
// so a test can prove the clear surgically removed two keys rather than
// blanking the document.
func readScanStamp(t *testing.T, db *sql.DB, tenant, assetID uuid.UUID) (sql.NullString, sql.NullString, sql.NullString) {
	t.Helper()
	var at, job, keep sql.NullString
	if err := db.QueryRow(`
		SELECT metadata ->> 'last_auto_scan_at',
		       metadata ->> 'last_auto_scan_job_id',
		       metadata ->> 'keep_me'
		FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, assetID).Scan(&at, &job, &keep); err != nil {
		t.Fatalf("read the asset: %v", err)
	}
	return at, job, keep
}

func TestIntegration_ClearUnstartedScanStamps_ClearsAFailedJobThatNeverStarted(t *testing.T) {
	store, db, tenant := newStampFixture(t)
	assetID := seedUnstartedScan(t, db, tenant, unstartedSeed{
		jobStatus: "failed", started: false, automatic: true, stampNamesJob: true,
	})

	cleared, err := store.ClearUnstartedScanStamps(context.Background(), tenant)
	if err != nil {
		t.Fatalf("ClearUnstartedScanStamps: %v", err)
	}
	if cleared != 1 {
		t.Fatalf("cleared %d assets, want 1 — a sensor that refused the command scanned nothing, so the asset must go back on the list", cleared)
	}

	at, job, keep := readScanStamp(t, db, tenant, assetID)
	if at.Valid || job.Valid {
		t.Fatalf("stamp survived: last_auto_scan_at=%v last_auto_scan_job_id=%v — the asset stays skipped for a full rescan interval on the strength of a scan that never happened", at, job)
	}
	if !keep.Valid || keep.String != "yes" {
		t.Fatalf("keep_me = %v, want \"yes\" — the clear must remove two keys, not blank the metadata document", keep)
	}
}

func TestIntegration_ClearUnstartedScanStamps_KeepsAJobThatStarted(t *testing.T) {
	// The documented design: a job that ran and got nothing back still probed
	// the address. Clearing here would re-queue a permanently-silent host on
	// every single tick, which is what the enqueue stamp exists to prevent.
	store, db, tenant := newStampFixture(t)
	assetID := seedUnstartedScan(t, db, tenant, unstartedSeed{
		jobStatus: "failed", started: true, automatic: true, stampNamesJob: true,
	})

	cleared, err := store.ClearUnstartedScanStamps(context.Background(), tenant)
	if err != nil {
		t.Fatalf("ClearUnstartedScanStamps: %v", err)
	}
	if cleared != 0 {
		t.Fatalf("cleared %d assets, want 0 — the job started, so the address was probed", cleared)
	}
	if at, _, _ := readScanStamp(t, db, tenant, assetID); !at.Valid {
		t.Fatal("the stamp was removed from an asset whose job actually ran")
	}
}

func TestIntegration_ClearUnstartedScanStamps_KeepsACompletedJob(t *testing.T) {
	store, db, tenant := newStampFixture(t)
	assetID := seedUnstartedScan(t, db, tenant, unstartedSeed{
		jobStatus: "completed", started: false, automatic: true, stampNamesJob: true,
	})

	cleared, err := store.ClearUnstartedScanStamps(context.Background(), tenant)
	if err != nil {
		t.Fatalf("ClearUnstartedScanStamps: %v", err)
	}
	if cleared != 0 {
		t.Fatalf("cleared %d assets, want 0 — only a FAILED job is evidence nothing ran", cleared)
	}
	if at, _, _ := readScanStamp(t, db, tenant, assetID); !at.Valid {
		t.Fatal("the stamp was removed from an asset whose job completed")
	}
}

func TestIntegration_ClearUnstartedScanStamps_IgnoresAManualScan(t *testing.T) {
	// The manual Active Scan stamps at dispatch on purpose (a person asked for
	// it, and the optimistic stamp is what takes the asset off the coverage
	// list they are looking at). This path owns the automatic sweep only.
	store, db, tenant := newStampFixture(t)
	assetID := seedUnstartedScan(t, db, tenant, unstartedSeed{
		jobStatus: "failed", started: false, automatic: false, stampNamesJob: true,
	})

	cleared, err := store.ClearUnstartedScanStamps(context.Background(), tenant)
	if err != nil {
		t.Fatalf("ClearUnstartedScanStamps: %v", err)
	}
	if cleared != 0 {
		t.Fatalf("cleared %d assets, want 0 — a manual Active Scan is not this path's business", cleared)
	}
	if at, _, _ := readScanStamp(t, db, tenant, assetID); !at.Valid {
		t.Fatal("the stamp was removed on account of a manual job")
	}
}

func TestIntegration_ClearUnstartedScanStamps_OnlyConsultsTheJobTheStampNames(t *testing.T) {
	// A newer sweep's stamp must not be undone by an older failure sitting in
	// the same tenant.
	store, db, tenant := newStampFixture(t)
	assetID := seedUnstartedScan(t, db, tenant, unstartedSeed{
		jobStatus: "failed", started: false, automatic: true, stampNamesJob: false,
	})

	cleared, err := store.ClearUnstartedScanStamps(context.Background(), tenant)
	if err != nil {
		t.Fatalf("ClearUnstartedScanStamps: %v", err)
	}
	if cleared != 0 {
		t.Fatalf("cleared %d assets, want 0 — the asset's stamp names a different job", cleared)
	}
	if at, _, _ := readScanStamp(t, db, tenant, assetID); !at.Valid {
		t.Fatal("an unrelated failed job cleared this asset's stamp")
	}
}

func TestIntegration_ClearUnstartedScanStamps_IsIdempotent(t *testing.T) {
	store, db, tenant := newStampFixture(t)
	seedUnstartedScan(t, db, tenant, unstartedSeed{
		jobStatus: "failed", started: false, automatic: true, stampNamesJob: true,
	})

	if _, err := store.ClearUnstartedScanStamps(context.Background(), tenant); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	cleared, err := store.ClearUnstartedScanStamps(context.Background(), tenant)
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if cleared != 0 {
		t.Fatalf("second pass cleared %d assets, want 0 — the sweep calls this every pass", cleared)
	}
}
