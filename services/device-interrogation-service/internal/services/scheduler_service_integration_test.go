package services

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// seedDueSchedule inserts an enabled schedule whose next_run_at is already in
// the past, targeting a real device so TriggerSchedule's job insert satisfies
// the device_jobs CHECK constraint.
func seedDueSchedule(t *testing.T, db *sql.DB, tenantID uuid.UUID, cronExpr string) (scheduleID uuid.UUID) {
	t.Helper()
	ctx := context.Background()

	hostname := "sched-target-" + uuid.New().String()[:8] + ".example.test"
	dev, err := NewDeviceService(db).CreateDevice(ctx, tenantID, models.CreateDeviceRequest{
		DeviceType: "cisco_ios",
		Hostname:   &hostname,
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	scheduleID = uuid.New()
	_, err = db.Exec(`
		INSERT INTO interrogation_schedules
			(id, tenant_id, name, cron_expression, target_type, target_id, is_enabled, next_run_at)
		VALUES ($1, $2, $3, $4, 'device', $5, true, NOW() - INTERVAL '5 minutes')`,
		scheduleID, tenantID, "due-"+scheduleID.String()[:8], cronExpr, dev.ID,
	)
	if err != nil {
		t.Fatalf("seed interrogation_schedule: %v", err)
	}
	return scheduleID
}

func nextRunAt(t *testing.T, db *sql.DB, scheduleID uuid.UUID) sql.NullTime {
	t.Helper()
	var next sql.NullTime
	if err := db.QueryRow(
		`SELECT next_run_at FROM interrogation_schedules WHERE id = $1`, scheduleID,
	).Scan(&next); err != nil {
		t.Fatalf("read next_run_at: %v", err)
	}
	return next
}

func jobCountForTenant(t *testing.T, db *sql.DB, tenantID uuid.UUID) int {
	t.Helper()
	var n int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM device_jobs WHERE tenant_id = $1 AND deleted_at IS NULL`, tenantID,
	).Scan(&n); err != nil {
		t.Fatalf("count device_jobs: %v", err)
	}
	return n
}

// TestIntegration_ProcessDueSchedules_TriggersAndAdvances is the real-database
// half of the scheduler fix. A due schedule must produce exactly one job
// and have its next_run_at advanced into the future — the second half is what
// stops the sweep from re-firing the same schedule every single tick once the
// driver loop exists.
func TestIntegration_ProcessDueSchedules_TriggersAndAdvances(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	// "0 * * * *" — hourly, so the recomputed next_run_at is unambiguously in
	// the future and cannot be mistaken for the seeded past value.
	scheduleID := seedDueSchedule(t, db, tenant, "0 * * * *")

	before := jobCountForTenant(t, db, tenant)

	svc := NewSchedulerService(db, db, NewJobQueueService(db, db, nil))
	triggered, err := svc.ProcessDueSchedules(ctx)
	if err != nil {
		t.Fatalf("ProcessDueSchedules = %v, want nil", err)
	}
	if triggered != 1 {
		t.Fatalf("ProcessDueSchedules triggered %d, want 1", triggered)
	}
	if got := jobCountForTenant(t, db, tenant); got != before+1 {
		t.Fatalf("device_jobs for tenant = %d, want %d", got, before+1)
	}

	next := nextRunAt(t, db, scheduleID)
	if !next.Valid || !next.Time.After(time.Now()) {
		t.Fatalf("next_run_at = %v, want a future timestamp", next)
	}

	// A second immediate sweep must find nothing — the schedule is no longer due.
	triggered, err = svc.ProcessDueSchedules(ctx)
	if err != nil {
		t.Fatalf("second ProcessDueSchedules = %v, want nil", err)
	}
	if triggered != 0 {
		t.Fatalf("second ProcessDueSchedules triggered %d, want 0 (schedule re-fired)", triggered)
	}
	if got := jobCountForTenant(t, db, tenant); got != before+1 {
		t.Fatalf("device_jobs after second sweep = %d, want %d (duplicate job created)", got, before+1)
	}
}

// TestIntegration_ProcessDueSchedules_ClaimIsExclusive proves the claim actually
// locks. The original implementation issued SELECT ... FOR UPDATE SKIP LOCKED
// through QueryContext — its own implicit transaction, committed the moment the
// statement finished — so the row locks were gone before any caller acted on
// them and two replicas would both trigger the same schedule. Here a concurrent
// transaction holds the row; the sweep must skip it rather than double-fire.
func TestIntegration_ProcessDueSchedules_ClaimIsExclusive(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	scheduleID := seedDueSchedule(t, db, tenant, "0 * * * *")
	before := jobCountForTenant(t, db, tenant)

	// Stand in for the other replica: hold the row lock for the whole sweep.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if _, err := tx.ExecContext(ctx,
		`SELECT id FROM interrogation_schedules WHERE id = $1 FOR UPDATE`, scheduleID,
	); err != nil {
		_ = tx.Rollback()
		t.Fatalf("lock schedule row: %v", err)
	}

	svc := NewSchedulerService(db, db, NewJobQueueService(db, db, nil))
	triggered, err := svc.ProcessDueSchedules(ctx)
	_ = tx.Rollback()
	if err != nil {
		t.Fatalf("ProcessDueSchedules = %v, want nil", err)
	}
	if triggered != 0 {
		t.Fatalf("ProcessDueSchedules triggered %d while the row was locked, want 0", triggered)
	}
	if got := jobCountForTenant(t, db, tenant); got != before {
		t.Fatalf("device_jobs = %d, want %d — a locked schedule was double-fired", got, before)
	}
}

// TestIntegration_ProcessDueSchedules_UnparseableCronDoesNotHotLoop — a schedule
// whose cron expression cannot be parsed must have next_run_at cleared, not left
// in the past, or every sweep for the rest of the deployment's life re-claims it.
func TestIntegration_ProcessDueSchedules_UnparseableCronDoesNotHotLoop(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	scheduleID := seedDueSchedule(t, db, tenant, "not a cron expression")

	svc := NewSchedulerService(db, db, NewJobQueueService(db, db, nil))
	if _, err := svc.ProcessDueSchedules(ctx); err != nil {
		t.Fatalf("ProcessDueSchedules = %v, want nil", err)
	}

	if next := nextRunAt(t, db, scheduleID); next.Valid {
		t.Fatalf("next_run_at = %v for an unparseable cron, want NULL", next.Time)
	}

	// And it must not be picked up again.
	triggered, err := svc.ProcessDueSchedules(ctx)
	if err != nil {
		t.Fatalf("second ProcessDueSchedules = %v, want nil", err)
	}
	if triggered != 0 {
		t.Fatalf("second ProcessDueSchedules triggered %d, want 0", triggered)
	}
}

// TestIntegration_ProcessDueSchedules_FailedTriggerStillAdvances is what
// separates the claim-then-trigger rewrite from the original.
//
// The original advanced next_run_at only inside TriggerSchedule, i.e. only on
// success. A schedule whose trigger fails — target device deleted, quota
// rejected, anything — therefore stayed due forever, and once the sweep loop
// exists (which is the actual fix) it would retry that failure on every
// single tick, for the life of the deployment. Claiming the row by advancing
// next_run_at BEFORE triggering makes a failure cost one attempt per scheduled
// occurrence instead of one per tick. The same claim, held inside one
// transaction, is what stops two replicas double-firing the same schedule.
func TestIntegration_ProcessDueSchedules_FailedTriggerStillAdvances(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	// Point the schedule at a device id that does not exist, so TriggerSchedule's
	// job insert fails on the device_jobs foreign key.
	scheduleID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO interrogation_schedules
			(id, tenant_id, name, cron_expression, target_type, target_id, is_enabled, next_run_at)
		VALUES ($1, $2, $3, '0 * * * *', 'device', $4, true, NOW() - INTERVAL '5 minutes')`,
		scheduleID, tenant, "doomed-"+scheduleID.String()[:8], uuid.New(),
	); err != nil {
		t.Fatalf("seed interrogation_schedule: %v", err)
	}

	svc := NewSchedulerService(db, db, NewJobQueueService(db, db, nil))
	triggered, err := svc.ProcessDueSchedules(ctx)
	if err != nil {
		t.Fatalf("ProcessDueSchedules = %v, want nil (a failing trigger must not fail the sweep)", err)
	}
	if triggered != 0 {
		t.Fatalf("ProcessDueSchedules triggered %d, want 0 — the trigger was supposed to fail", triggered)
	}

	next := nextRunAt(t, db, scheduleID)
	if !next.Valid || !next.Time.After(time.Now()) {
		t.Fatalf("next_run_at = %v after a failed trigger, want it advanced into the future; "+
			"leaving it in the past makes every subsequent sweep retry the same failure", next)
	}

	// Confirm the consequence directly: a second sweep must not re-attempt it.
	if triggered, err = svc.ProcessDueSchedules(ctx); err != nil {
		t.Fatalf("second ProcessDueSchedules = %v, want nil", err)
	}
	if triggered != 0 {
		t.Fatalf("second sweep triggered %d, want 0", triggered)
	}
	if next2 := nextRunAt(t, db, scheduleID); !next2.Valid || !next2.Time.Equal(next.Time) {
		t.Fatalf("next_run_at moved from %v to %v — the schedule was re-claimed on the very next tick", next, next2)
	}
}

// TestIntegration_PlatformAgentHeartbeat_RefreshesLastHeartbeat covers the other
// half of's false-offline story: the in-cluster platform agent's
// last_heartbeat was stamped once at registration and never again, so the
// compliance-engine discovery_agent_offline detector (15-minute dwell, no
// platform exclusion) opened a permanent false alert against a healthy service.
func TestIntegration_PlatformAgentHeartbeat_RefreshesLastHeartbeat(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	agentID := uuid.New()
	stale := time.Now().Add(-2 * time.Hour)
	if _, err := db.Exec(`
		INSERT INTO device_agents (id, tenant_id, registration_key, platform, version, status, last_heartbeat)
		VALUES ($1, $2, '', 'platform', 'system', 'active', $3)`,
		agentID, tenant, stale,
	); err != nil {
		t.Fatalf("insert platform agent: %v", err)
	}

	// A tenant-owned agent must be left alone — only platform rows are the
	// service's own liveness to assert.
	tenantAgent := insertDeviceAgent(t, db, tenant)
	if _, err := db.Exec(
		`UPDATE device_agents SET last_heartbeat = $1 WHERE id = $2`, stale, tenantAgent,
	); err != nil {
		t.Fatalf("stale tenant agent heartbeat: %v", err)
	}

	if err := TouchPlatformAgentHeartbeat(ctx, db); err != nil {
		t.Fatalf("TouchPlatformAgentHeartbeat = %v, want nil", err)
	}

	var platformHB, tenantHB time.Time
	if err := db.QueryRow(`SELECT last_heartbeat FROM device_agents WHERE id = $1`, agentID).Scan(&platformHB); err != nil {
		t.Fatalf("read platform heartbeat: %v", err)
	}
	if err := db.QueryRow(`SELECT last_heartbeat FROM device_agents WHERE id = $1`, tenantAgent).Scan(&tenantHB); err != nil {
		t.Fatalf("read tenant heartbeat: %v", err)
	}

	// 15 minutes is the detector's dwell window.
	if time.Since(platformHB) > 15*time.Minute {
		t.Fatalf("platform agent last_heartbeat = %v, want refreshed to ~now", platformHB)
	}
	if time.Since(tenantHB) < time.Hour {
		t.Fatalf("tenant agent last_heartbeat = %v, want left stale", tenantHB)
	}
}
