package jobs

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// recordJobCompletion used to SET updated_at on platform_log_retention_jobs, a
// column that table does not have (it carries created_at / started_at /
// completed_at only). Postgres answered 42703 on every run, so the row
// recordJobStart had just inserted was never closed out and each sweep left
// behind an orphan at execution_status='running' with all counters 0. Nothing
// surfaced it: runRetentionPolicy only logs the error, and the archive/delete
// work on platform_log_metadata commits independently.
//
// A column that does not exist is not something a compile or a mock can catch,
// so this is pinned against a real database.

func newRetentionJobForTest(t *testing.T) (*LogRetentionJob, *sql.DB) {
	t.Helper()
	db := testdb.Connect(t)
	// Same-package construction: NewLogRetentionJob wants an S3 client and a
	// bucket, neither of which the job-history bookkeeping touches.
	return &LogRetentionJob{
		db:          db,
		bypassDB:    db,
		hotDays:     90,
		archiveDays: 365,
		logger:      log.New(log.Writer(), "[LogRetentionJobTest] ", log.LstdFlags),
	}, db
}

func newJobRow(t *testing.T, j *LogRetentionJob, db *sql.DB) uuid.UUID {
	t.Helper()
	jobID := uuid.New()
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM platform_log_retention_jobs WHERE id = $1`, jobID)
	})
	if err := j.recordJobStart(context.Background(), jobID, "full_retention", time.Now()); err != nil {
		t.Fatalf("recordJobStart: %v", err)
	}
	return jobID
}

type jobRow struct {
	status       string
	completedAt  sql.NullTime
	processed    int
	archived     int
	deleted      int
	scrubbed     int
	durationMs   sql.NullInt64
	errorMessage sql.NullString
}

func readJobRow(t *testing.T, db *sql.DB, jobID uuid.UUID) jobRow {
	t.Helper()
	var r jobRow
	if err := db.QueryRow(`
		SELECT execution_status, completed_at, logs_processed, logs_archived,
		       logs_deleted, logs_scrubbed, duration_ms, error_message
		FROM platform_log_retention_jobs WHERE id = $1`, jobID).
		Scan(&r.status, &r.completedAt, &r.processed, &r.archived,
			&r.deleted, &r.scrubbed, &r.durationMs, &r.errorMessage); err != nil {
		t.Fatalf("read job row: %v", err)
	}
	return r
}

// TestIntegration_LogRetentionJobRowIsClosedOut is the direct regression: the
// completion UPDATE must be accepted by Postgres and must actually move the row
// out of 'running'.
func TestIntegration_LogRetentionJobRowIsClosedOut(t *testing.T) {
	j, db := newRetentionJobForTest(t)
	jobID := newJobRow(t, j, db)

	if before := readJobRow(t, db, jobID); before.status != "running" {
		t.Fatalf("row starts at status %q, want running", before.status)
	}

	if err := j.recordJobCompletion(context.Background(), jobID, 7, 3, 0, 1500*time.Millisecond, nil); err != nil {
		t.Fatalf("recordJobCompletion: %v", err)
	}

	got := readJobRow(t, db, jobID)
	if got.status != "completed" {
		t.Fatalf("execution_status = %q, want completed — the job row was left orphaned at 'running'", got.status)
	}
	if !got.completedAt.Valid {
		t.Fatal("completed_at is NULL after completion")
	}
	if got.archived != 7 || got.deleted != 3 || got.scrubbed != 0 || got.processed != 10 {
		t.Fatalf("counters = processed %d / archived %d / deleted %d / scrubbed %d, want 10/7/3/0",
			got.processed, got.archived, got.deleted, got.scrubbed)
	}
	if !got.durationMs.Valid || got.durationMs.Int64 != 1500 {
		t.Fatalf("duration_ms = %v, want 1500", got.durationMs)
	}
}

// TestIntegration_LogRetentionJobRecordsArchiveFailure pins the second half of
// the finding. runRetentionPolicy reused a single `err`, so deleteOldLogs'
// (usually nil) result overwrote an archive failure and the run was recorded as
// 'completed'. The errors are now joined; this asserts an archive-only failure
// still reaches the row, and that both messages survive.
func TestIntegration_LogRetentionJobRecordsArchiveFailure(t *testing.T) {
	j, db := newRetentionJobForTest(t)

	archiveErr := errors.New("failed to archive logs: connection reset")
	var deleteErr error // the delete step succeeded

	jobID := newJobRow(t, j, db)
	if err := j.recordJobCompletion(context.Background(), jobID, 0, 4, 0, time.Second,
		errors.Join(archiveErr, deleteErr)); err != nil {
		t.Fatalf("recordJobCompletion: %v", err)
	}

	got := readJobRow(t, db, jobID)
	if got.status != "failed" {
		t.Fatalf("execution_status = %q, want failed — an archive failure was swallowed "+
			"by the delete step's nil error", got.status)
	}
	if !got.errorMessage.Valid || got.errorMessage.String != archiveErr.Error() {
		t.Fatalf("error_message = %q, want %q", got.errorMessage.String, archiveErr.Error())
	}

	// And both failures are reported when both steps fail.
	bothID := newJobRow(t, j, db)
	deleteErr = errors.New("failed to delete logs: deadlock detected")
	if err := j.recordJobCompletion(context.Background(), bothID, 0, 0, 0, time.Second,
		errors.Join(archiveErr, deleteErr)); err != nil {
		t.Fatalf("recordJobCompletion (both): %v", err)
	}
	both := readJobRow(t, db, bothID)
	if !both.errorMessage.Valid ||
		!strings.Contains(both.errorMessage.String, archiveErr.Error()) ||
		!strings.Contains(both.errorMessage.String, deleteErr.Error()) {
		t.Fatalf("error_message = %q, want both step errors", both.errorMessage.String)
	}
}

// TestIntegration_LogRetentionRunRecordsArchiveError drives the whole
// runRetentionPolicy cycle rather than recordJobCompletion in isolation, which
// is where the error actually got lost: the archive and delete steps shared one
// `err` variable, so whatever deleteOldLogs returned overwrote the archive
// failure before it was ever recorded.
//
// A bypassDB pointing nowhere makes both sweeps fail; the assertion that
// distinguishes the fix is that the ARCHIVE error survives into the row.
func TestIntegration_LogRetentionRunRecordsArchiveError(t *testing.T) {
	j, db := newRetentionJobForTest(t)

	// RFC 5737 TEST-NET-1: guaranteed non-routable, so this handle can only
	// ever fail, and never reaches anything real.
	deadDB, err := sql.Open("postgres", "postgres://nobody:nobody@192.0.2.1:5432/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("open dead handle: %v", err)
	}
	t.Cleanup(func() { _ = deadDB.Close() })
	j.bypassDB = deadDB

	before := time.Now().Add(-time.Second)
	j.runRetentionPolicy(context.Background())

	var jobID uuid.UUID
	if err := db.QueryRow(`
		SELECT id FROM platform_log_retention_jobs
		WHERE job_type = 'full_retention' AND created_at >= $1
		ORDER BY created_at DESC LIMIT 1`, before).Scan(&jobID); err != nil {
		t.Fatalf("locate job row written by runRetentionPolicy: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM platform_log_retention_jobs WHERE id = $1`, jobID)
	})

	got := readJobRow(t, db, jobID)
	if got.status != "failed" {
		t.Fatalf("execution_status = %q, want failed", got.status)
	}
	if !got.completedAt.Valid {
		t.Fatal("completed_at is NULL — the job row was never closed out")
	}
	if !got.errorMessage.Valid || !strings.Contains(got.errorMessage.String, "failed to archive logs") {
		t.Fatalf("error_message = %q, want it to carry the archive failure — the delete "+
			"step's error overwrote it", got.errorMessage.String)
	}
}
