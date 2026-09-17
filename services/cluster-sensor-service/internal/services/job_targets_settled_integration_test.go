package services

// A job that ends has no unfinished targets left.
//
// Only two paths ever settled `discovery_targets`: the in-cluster executor
// (job_processor.go, 'running' then 'completed' per target) and the sensor's
// own completion report (sensor-manager's discovery_job_service.go). A job that
// dies before either runs — a sensor that refuses the command, a dispatch that
// fails, a stale command the sweep reaps — left its targets at 'pending' for
// ever, and the Jobs page showed targets still queued underneath a job that
// finished minutes ago.
//
// Observed live on a dev cluster: two auto-scan jobs failed with "sensor
// <name> refused the job: Unknown command type: discovery_job; nothing was
// scanned" and left three target rows pending indefinitely.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// seedJobWithTargets writes one job and one target per status in
// targetStatuses, and returns the job id.
func seedJobWithTargets(t *testing.T, db *sql.DB, tenant uuid.UUID, targetStatuses ...string) string {
	t.Helper()
	jobID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO discovery_jobs (id, tenant_id, execution_mode, status, metadata, created_at, updated_at)
		VALUES ($1, $2, 'sensors', 'awaiting_sensor', '{"options":{"active_scan":true}}'::jsonb, NOW(), NOW())`,
		jobID, tenant); err != nil {
		t.Fatalf("insert job: %v", err)
	}
	for i, status := range targetStatuses {
		if _, err := db.Exec(`
			INSERT INTO discovery_targets (id, job_id, tenant_id, input, protocols, ports, status)
			VALUES ($1, $2, $3, $4, ARRAY['TLS'], ARRAY[443], $5)`,
			uuid.New(), jobID, tenant, "10.20.30."+string(rune('1'+i)), status); err != nil {
			t.Fatalf("insert target %s: %v", status, err)
		}
	}
	return jobID.String()
}

// targetStates returns status → count for a job's targets.
func targetStates(t *testing.T, db *sql.DB, jobID string) map[string]int {
	t.Helper()
	rows, err := db.Query(`SELECT status, count(*) FROM discovery_targets WHERE job_id = $1 GROUP BY status`, jobID)
	if err != nil {
		t.Fatalf("read targets: %v", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[status] = n
	}
	return out
}

func TestIntegration_UpdateJobStatus_FailedJobSettlesItsPendingTargets(t *testing.T) {
	svc, raw, tenant := materializationFixture(t)
	jobID := seedJobWithTargets(t, raw, tenant, "pending", "pending", "running")

	reason := "sensor probe-1 refused the job: Unknown command type: discovery_job; nothing was scanned"
	if err := svc.UpdateJobStatus(jobID, "failed", &reason); err != nil {
		t.Fatalf("UpdateJobStatus: %v", err)
	}

	got := targetStates(t, raw, jobID)
	if got["pending"] != 0 || got["running"] != 0 {
		t.Fatalf("targets left unfinished: %v — the Jobs page shows targets queued under a job that already failed", got)
	}
	if got["failed"] != 3 {
		t.Fatalf("failed targets = %d, want 3 (got %v)", got["failed"], got)
	}

	// The reason must travel with them: 'failed' alone cannot tell an operator
	// whether the address refused the connection or the scan never started.
	var msg sql.NullString
	if err := raw.QueryRow(`SELECT error_message FROM discovery_targets WHERE job_id = $1 LIMIT 1`, jobID).Scan(&msg); err != nil {
		t.Fatalf("read the target's error_message: %v", err)
	}
	if !msg.Valid || msg.String != reason {
		t.Fatalf("target error_message = %q, want the job's reason — a bare 'failed' does not say what happened", msg.String)
	}
}

func TestIntegration_UpdateJobStatus_KeepsTerminalTargetOutcomes(t *testing.T) {
	// A job that scanned half its targets and then failed keeps the outcomes it
	// earned. This is the other polarity: settling must not overwrite a target
	// that already reached a terminal state.
	svc, raw, tenant := materializationFixture(t)
	jobID := seedJobWithTargets(t, raw, tenant, "completed", "failed", "pending")

	reason := "sensor collected the job but never reported completion"
	if err := svc.UpdateJobStatus(jobID, "failed", &reason); err != nil {
		t.Fatalf("UpdateJobStatus: %v", err)
	}

	got := targetStates(t, raw, jobID)
	if got["completed"] != 1 {
		t.Fatalf("completed targets = %d, want 1 — a target that answered was overwritten (%v)", got["completed"], got)
	}
	if got["failed"] != 2 {
		t.Fatalf("failed targets = %d, want 2 (the pre-existing one plus the settled pending one): %v", got["failed"], got)
	}
}

func TestIntegration_UpdateJobStatus_RunningJobLeavesTargetsAlone(t *testing.T) {
	// Only a terminal job settles targets. A job going 'running' must leave
	// them queued — settling here would mark every target finished before the
	// executor had touched one.
	svc, raw, tenant := materializationFixture(t)
	jobID := seedJobWithTargets(t, raw, tenant, "pending", "pending")

	if err := svc.UpdateJobStatus(jobID, "running", nil); err != nil {
		t.Fatalf("UpdateJobStatus: %v", err)
	}

	if got := targetStates(t, raw, jobID); got["pending"] != 2 {
		t.Fatalf("pending targets = %d, want 2 — a job that just started has not finished its targets: %v", got["pending"], got)
	}
}
