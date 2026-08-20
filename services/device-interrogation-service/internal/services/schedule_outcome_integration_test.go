package services

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// B-50: interrogation schedules never recorded an outcome. TriggerSchedule wrote
// last_run_status='pending' and nothing ever moved it, success_count and
// failure_count were inserted as 0 and never incremented, and schedule_history
// had a reader (GET /schedules/:id/history) with no producer at all — so
// Discovery → Scheduled Scans permanently read "last run 3 minutes ago ·
// pending · 0 failures" for every schedule, and a nightly interrogation that had
// failed for a month looked identical to one succeeding.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

// newScheduledDeviceJob creates a device + an enabled schedule targeting it, then
// fires the schedule, returning the schedule and the dispatched job.
func newScheduledDeviceJob(t *testing.T, appDB, owner *sql.DB, tenantID uuid.UUID) (*InterrogationSchedule, *models.DeviceJob) {
	t.Helper()
	ctx := context.Background()

	hostname := "fw-" + uuid.New().String()[:8] + ".example.test"
	dev, err := NewDeviceService(appDB).CreateDevice(ctx, tenantID, models.CreateDeviceRequest{
		DeviceType: "fortinet",
		Hostname:   &hostname,
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	sched := NewSchedulerService(appDB, owner, NewJobQueueService(appDB, owner, nil))
	schedule, err := sched.CreateSchedule(ctx, tenantID, CreateScheduleRequest{
		Name:           "nightly",
		CronExpression: "0 2 * * *",
		TargetType:     "device",
		TargetID:       dev.ID,
	})
	if err != nil {
		t.Fatalf("CreateSchedule: %v", err)
	}

	job, err := sched.TriggerSchedule(ctx, tenantID, schedule.ID)
	if err != nil {
		t.Fatalf("TriggerSchedule: %v", err)
	}
	return schedule, job
}

// readSchedule re-reads the three columns the Scheduled Scans page renders.
func readSchedule(t *testing.T, owner *sql.DB, scheduleID uuid.UUID) (status string, success, failure int) {
	t.Helper()
	var s sql.NullString
	if err := owner.QueryRow(
		`SELECT last_run_status, success_count, failure_count
		   FROM interrogation_schedules WHERE id = $1`, scheduleID,
	).Scan(&s, &success, &failure); err != nil {
		t.Fatalf("read schedule: %v", err)
	}
	return s.String, success, failure
}

// TestIntegration_ScheduleOutcome_RecordedOnJobCompletion is the direct guard.
//
// The outcome is attached at JobQueueService.UpdateJobStatus because that is the
// one choke point every executor passes through — in-cluster worker, agent
// result submission, the async cloud goroutine and the dispatch-failure paths.
//
// Mutation check: delete the recordScheduleOutcome call in UpdateJobStatus and
// every assertion below reverts to the shipped behaviour — 'pending', 0, 0, and
// an unfinished history row.
func TestIntegration_ScheduleOutcome_RecordedOnJobCompletion(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	schedule, job := newScheduledDeviceJob(t, appDB, owner, tenantID)

	// Immediately after dispatch the run is genuinely pending, and the history
	// row already exists so an abandoned run is visible rather than absent.
	if status, success, failure := readSchedule(t, owner, schedule.ID); status != scheduleRunPending || success != 0 || failure != 0 {
		t.Fatalf("after trigger: status=%q success=%d failure=%d, want pending/0/0", status, success, failure)
	}
	var pendingRows int
	if err := owner.QueryRow(
		`SELECT count(*) FROM schedule_history WHERE schedule_id = $1 AND status = 'pending' AND completed_at IS NULL`,
		schedule.ID).Scan(&pendingRows); err != nil {
		t.Fatalf("count pending history: %v", err)
	}
	if pendingRows != 1 {
		t.Fatalf("pending schedule_history rows = %d, want 1", pendingRows)
	}

	jobQueue := NewJobQueueService(appDB, owner, nil)
	if err := jobQueue.UpdateJobStatus(ctx, job.ID, models.JobStatusCompleted, &models.JobResult{
		JobID:    job.ID,
		Success:  true,
		Metadata: map[string]interface{}{"assets_count": 7},
	}, nil); err != nil {
		t.Fatalf("UpdateJobStatus(completed): %v", err)
	}

	status, success, failure := readSchedule(t, owner, schedule.ID)
	if status != scheduleRunSuccess {
		t.Errorf("last_run_status = %q, want %q", status, scheduleRunSuccess)
	}
	if success != 1 || failure != 0 {
		t.Errorf("success_count/failure_count = %d/%d, want 1/0", success, failure)
	}

	var histRows, assetsFound int
	var histStatus string
	if err := owner.QueryRow(
		`SELECT count(*) OVER (), status, assets_found FROM schedule_history
		  WHERE schedule_id = $1 AND job_id = $2`, schedule.ID, job.ID,
	).Scan(&histRows, &histStatus, &assetsFound); err != nil {
		t.Fatalf("schedule_history has no row for the run — the history endpoint stays empty: %v", err)
	}
	if histRows != 1 {
		t.Errorf("schedule_history rows for the run = %d, want 1", histRows)
	}
	if histStatus != scheduleRunSuccess {
		t.Errorf("schedule_history.status = %q, want %q", histStatus, scheduleRunSuccess)
	}
	// The in-cluster interrogation executor forwards an EMPTY asset list by
	// design and carries the real figure in Metadata["assets_count"]; reading
	// only the slice would record 0 for every scheduled interrogation.
	if assetsFound != 7 {
		t.Errorf("schedule_history.assets_found = %d, want 7", assetsFound)
	}
}

// TestIntegration_ScheduleOutcome_IsIdempotent pins the property that makes this
// safe to hang off UpdateJobStatus: one job can legitimately reach a terminal
// status twice (the platform worker marks a job completed, then
// ProcessJobResults marks it failed on a broken platform-sensor invariant).
//
// The history row is keyed by job id and the counters are recomputed from it, so
// the second call corrects the record rather than appending a second run and
// double-counting.
//
// Mutation check: change the counter update to `success_count = success_count + 1`
// and this fails with 1/1 instead of 0/1.
func TestIntegration_ScheduleOutcome_IsIdempotent(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	schedule, job := newScheduledDeviceJob(t, appDB, owner, tenantID)
	jobQueue := NewJobQueueService(appDB, owner, nil)

	if err := jobQueue.UpdateJobStatus(ctx, job.ID, models.JobStatusCompleted, nil, nil); err != nil {
		t.Fatalf("UpdateJobStatus(completed): %v", err)
	}
	// Same run, re-reported terminal — this time as a failure.
	reason := "platform device-interrogation sensor is missing for this tenant"
	if err := jobQueue.UpdateJobStatus(ctx, job.ID, models.JobStatusFailed, nil, &reason); err != nil {
		t.Fatalf("UpdateJobStatus(failed): %v", err)
	}

	status, success, failure := readSchedule(t, owner, schedule.ID)
	if status != scheduleRunFailed {
		t.Errorf("last_run_status = %q, want %q", status, scheduleRunFailed)
	}
	if success != 0 || failure != 1 {
		t.Errorf("success_count/failure_count = %d/%d, want 0/1 — one run counted once", success, failure)
	}

	var rows int
	if err := owner.QueryRow(
		`SELECT count(*) FROM schedule_history WHERE schedule_id = $1`, schedule.ID).Scan(&rows); err != nil {
		t.Fatalf("count schedule_history: %v", err)
	}
	if rows != 1 {
		t.Errorf("schedule_history rows = %d, want 1 — one run must not appear twice", rows)
	}

	var histErr sql.NullString
	if err := owner.QueryRow(
		`SELECT error_message FROM schedule_history WHERE job_id = $1`, job.ID).Scan(&histErr); err != nil {
		t.Fatalf("read history error_message: %v", err)
	}
	if histErr.String != reason {
		t.Errorf("schedule_history.error_message = %q, want the job's failure reason", histErr.String)
	}
}

// TestIntegration_ScheduleOutcome_StaleCompletionStillUpdatesHistory covers the
// overlapping-run case: run A can finish after run B has already become the
// schedule's current last_run_job_id. Run A must still update its own history row
// and counters, while leaving last_run_status attached to run B.
func TestIntegration_ScheduleOutcome_StaleCompletionStillUpdatesHistory(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	schedule, firstJob := newScheduledDeviceJob(t, appDB, owner, tenantID)
	sched := NewSchedulerService(appDB, owner, NewJobQueueService(appDB, owner, nil))
	secondJob, err := sched.TriggerSchedule(ctx, tenantID, schedule.ID)
	if err != nil {
		t.Fatalf("TriggerSchedule(second run): %v", err)
	}
	if firstJob.ID == secondJob.ID {
		t.Fatal("second trigger reused the first job id")
	}

	jobQueue := NewJobQueueService(appDB, owner, nil)
	if err := jobQueue.UpdateJobStatus(ctx, firstJob.ID, models.JobStatusCompleted, &models.JobResult{
		JobID:    firstJob.ID,
		Success:  true,
		Metadata: map[string]interface{}{"assets_count": 3},
	}, nil); err != nil {
		t.Fatalf("UpdateJobStatus(first completed after second trigger): %v", err)
	}

	status, success, failure := readSchedule(t, owner, schedule.ID)
	if status != scheduleRunPending {
		t.Errorf("last_run_status = %q, want pending for the still-current second run", status)
	}
	if success != 1 || failure != 0 {
		t.Errorf("success_count/failure_count = %d/%d, want 1/0 from the stale completed run", success, failure)
	}

	var firstStatus string
	var firstCompleted sql.NullTime
	var firstAssets int
	if err := owner.QueryRow(
		`SELECT status, completed_at, assets_found FROM schedule_history WHERE job_id = $1`, firstJob.ID,
	).Scan(&firstStatus, &firstCompleted, &firstAssets); err != nil {
		t.Fatalf("read first history row: %v", err)
	}
	if firstStatus != scheduleRunSuccess || !firstCompleted.Valid || firstAssets != 3 {
		t.Errorf("first history = status %q completed %v assets %d, want success/completed/3",
			firstStatus, firstCompleted.Valid, firstAssets)
	}

	var secondStatus string
	var secondCompleted sql.NullTime
	if err := owner.QueryRow(
		`SELECT status, completed_at FROM schedule_history WHERE job_id = $1`, secondJob.ID,
	).Scan(&secondStatus, &secondCompleted); err != nil {
		t.Fatalf("read second history row: %v", err)
	}
	if secondStatus != scheduleRunPending || secondCompleted.Valid {
		t.Errorf("second history = status %q completed %v, want pending/not completed",
			secondStatus, secondCompleted.Valid)
	}
}

// TestIntegration_ScheduleOutcome_IgnoresAdHocJobs guards the other polarity: an
// ad-hoc interrogation (the Devices page "Interrogate" button) belongs to no
// schedule, and finishing one must not touch any schedule's counters. Without
// this a too-loose predicate would pass the tests above while silently
// attributing every manual run to whichever schedule happened to match.
func TestIntegration_ScheduleOutcome_IgnoresAdHocJobs(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	schedule, _ := newScheduledDeviceJob(t, appDB, owner, tenantID)

	hostname := "fw-" + uuid.New().String()[:8] + ".example.test"
	dev, err := NewDeviceService(appDB).CreateDevice(ctx, tenantID, models.CreateDeviceRequest{
		DeviceType: "cisco",
		Hostname:   &hostname,
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	jobQueue := NewJobQueueService(appDB, owner, nil)
	adHoc, err := jobQueue.CreateJob(ctx, models.CreateDeviceJobRequest{
		TenantID: tenantID,
		JobType:  models.JobTypeDeviceInterrogation,
		DeviceID: &dev.ID,
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if err := jobQueue.UpdateJobStatus(ctx, adHoc.ID, models.JobStatusCompleted, nil, nil); err != nil {
		t.Fatalf("UpdateJobStatus: %v", err)
	}

	status, success, failure := readSchedule(t, owner, schedule.ID)
	if status != scheduleRunPending || success != 0 || failure != 0 {
		t.Errorf("an ad-hoc job moved the schedule: status=%q success=%d failure=%d, want pending/0/0",
			status, success, failure)
	}
}
