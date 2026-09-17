package services

// CompleteSensorJob against a real Postgres: only the sensor a job was
// dispatched to can close it, the close carries the sensor's counts and the
// pickup time, and a verdict the platform already gave (failed: sensor
// offline) is not rewritten by a late report.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type completionFixture struct {
	db     *sql.DB
	svc    *DiscoveryJobService
	tenant uuid.UUID
	sensor uuid.UUID
}

func newCompletionFixture(t *testing.T) *completionFixture {
	t.Helper()
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	sensor := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status, last_heartbeat)
		VALUES ($1, $2, 'xps16-sensor', 'linux', '1.0.0', 'datacenter_host', 'active', NOW())`, sensor, tenant); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}
	return &completionFixture{db: db, svc: NewDiscoveryJobService(db), tenant: tenant, sensor: sensor}
}

// dispatchedJob writes a job in the state the cluster-sensor dispatcher leaves
// it: awaiting_sensor, assigned, with a delivered command behind it.
func (f *completionFixture) dispatchedJob(t *testing.T, status string) uuid.UUID {
	t.Helper()
	jobID := uuid.New()
	if _, err := f.db.Exec(`
		INSERT INTO discovery_jobs (id, tenant_id, execution_mode, status, requested_sensor_ids, assigned_sensor_id, dispatched_at)
		VALUES ($1, $2, 'sensors', $3, ARRAY[$4::text], $4::uuid, NOW() - interval '2 minutes')`,
		jobID, f.tenant, status, f.sensor.String()); err != nil {
		t.Fatalf("insert job: %v", err)
	}
	if _, err := f.db.Exec(`
		INSERT INTO discovery_targets (job_id, tenant_id, input, protocols, ports)
		VALUES ($1, $2, '192.0.2.10', ARRAY['TLS'], ARRAY[443])`, jobID, f.tenant); err != nil {
		t.Fatalf("insert target: %v", err)
	}
	if _, err := f.db.Exec(`
		INSERT INTO sensor_commands (sensor_id, command_type, payload, status, created_at, delivered_at, expires_at)
		VALUES ($1, $2, jsonb_build_object('job_id', $3::text), 'delivered', NOW() - interval '2 minutes', NOW() - interval '1 minute', NOW() + interval '3 minutes')`,
		f.sensor, sensordispatch.CommandType, jobID.String()); err != nil {
		t.Fatalf("insert command: %v", err)
	}
	return jobID
}

func TestIntegration_CompleteSensorJob_ClosesTheJobWithTheSensorsCounts(t *testing.T) {
	f := newCompletionFixture(t)
	jobID := f.dispatchedJob(t, sensordispatch.StatusAwaitingSensor)

	err := f.svc.CompleteSensorJob(context.Background(), f.tenant, f.sensor, jobID, sensordispatch.Completion{
		Status: "completed", TotalTargets: 1, SuccessfulTargets: 1, DiscoveriesSubmitted: 2,
	})
	if err != nil {
		t.Fatalf("CompleteSensorJob: %v", err)
	}

	var status string
	var started, completed sql.NullTime
	var submitted int
	var targetStatus string
	if err := f.db.QueryRow(`
		SELECT status, started_at, completed_at, (metadata -> 'sensor_result' ->> 'discoveries_submitted')::int
		FROM discovery_jobs WHERE id = $1`, jobID).Scan(&status, &started, &completed, &submitted); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "completed" || !completed.Valid || submitted != 2 {
		t.Errorf("job = %s completed=%v submitted=%d", status, completed.Valid, submitted)
	}
	// started_at is when the sensor COLLECTED the command, so the timeline
	// reads queued → dispatched → picked up → completed.
	if !started.Valid || time.Since(started.Time) < 30*time.Second {
		t.Errorf("started_at = %v, want the command's delivered_at (~1 minute ago)", started)
	}
	if err := f.db.QueryRow(`SELECT status FROM discovery_targets WHERE job_id = $1`, jobID).Scan(&targetStatus); err != nil {
		t.Fatalf("read target: %v", err)
	}
	if targetStatus != "completed" {
		t.Errorf("target status = %q, want completed", targetStatus)
	}
}

func TestIntegration_CompleteSensorJob_FailedReportCarriesTheReason(t *testing.T) {
	f := newCompletionFixture(t)
	jobID := f.dispatchedJob(t, sensordispatch.StatusAwaitingSensor)
	err := f.svc.CompleteSensorJob(context.Background(), f.tenant, f.sensor, jobID, sensordispatch.Completion{
		Status: "failed", ErrorMessage: "malformed discovery_job payload: targets is empty", TotalTargets: 0,
	})
	if err != nil {
		t.Fatalf("CompleteSensorJob: %v", err)
	}
	var status string
	var errMsg sql.NullString
	_ = f.db.QueryRow(`SELECT status, error_message FROM discovery_jobs WHERE id = $1`, jobID).Scan(&status, &errMsg)
	if status != "failed" || !errMsg.Valid || errMsg.String != "malformed discovery_job payload: targets is empty" {
		t.Errorf("job = %s / %v", status, errMsg)
	}
}

// Only the assigned sensor may close the job. An unknown job, another
// tenant's, another sensor's and a platform-run one all answer the same.
func TestIntegration_CompleteSensorJob_OnlyTheAssignedSensorMayClose(t *testing.T) {
	f := newCompletionFixture(t)
	jobID := f.dispatchedJob(t, sensordispatch.StatusAwaitingSensor)
	otherSensor := uuid.New()
	otherTenant := testdb.NewTenant(t, f.db)
	platformJob := uuid.New()
	if _, err := f.db.Exec(`INSERT INTO discovery_jobs (id, tenant_id, execution_mode, status) VALUES ($1, $2, 'async', 'running')`, platformJob, f.tenant); err != nil {
		t.Fatalf("insert platform job: %v", err)
	}
	done := sensordispatch.Completion{Status: "completed"}

	cases := []struct {
		name   string
		tenant uuid.UUID
		sensor uuid.UUID
		job    uuid.UUID
	}{
		{"unknown job", f.tenant, f.sensor, uuid.New()},
		{"another tenant", otherTenant, f.sensor, jobID},
		{"another sensor", f.tenant, otherSensor, jobID},
		{"platform-run job", f.tenant, f.sensor, platformJob},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := f.svc.CompleteSensorJob(context.Background(), tc.tenant, tc.sensor, tc.job, done)
			if !errors.Is(err, ErrJobNotAssignedToSensor) {
				t.Fatalf("err = %v, want ErrJobNotAssignedToSensor", err)
			}
		})
	}
	var status string
	_ = f.db.QueryRow(`SELECT status FROM discovery_jobs WHERE id = $1`, jobID).Scan(&status)
	if status != sensordispatch.StatusAwaitingSensor {
		t.Errorf("a refused close changed the job to %q", status)
	}
}

// The sweep failed the job as "sensor offline" and the tenant has seen that.
// The sensor's late report is kept, but the verdict stands.
func TestIntegration_CompleteSensorJob_LateReportDoesNotRewriteTheVerdict(t *testing.T) {
	f := newCompletionFixture(t)
	jobID := f.dispatchedJob(t, "failed")
	if _, err := f.db.Exec(`UPDATE discovery_jobs SET error_message = 'sensor xps16-sensor offline; nothing was scanned' WHERE id = $1`, jobID); err != nil {
		t.Fatalf("set verdict: %v", err)
	}
	err := f.svc.CompleteSensorJob(context.Background(), f.tenant, f.sensor, jobID, sensordispatch.Completion{Status: "completed", DiscoveriesSubmitted: 4})
	if !errors.Is(err, ErrJobNotAwaitingSensor) {
		t.Fatalf("err = %v, want ErrJobNotAwaitingSensor", err)
	}
	var status string
	var errMsg sql.NullString
	var late sql.NullString
	_ = f.db.QueryRow(`SELECT status, error_message, metadata -> 'sensor_result_late' ->> 'discoveries_submitted' FROM discovery_jobs WHERE id = $1`, jobID).Scan(&status, &errMsg, &late)
	if status != "failed" || !errMsg.Valid || errMsg.String == "" {
		t.Errorf("verdict rewritten: status=%s error=%v", status, errMsg)
	}
	if !late.Valid || late.String != "4" {
		t.Errorf("late report not kept as evidence: %v", late)
	}
}

func TestIntegration_CompleteSensorJob_RefusesAnInvalidCompletion(t *testing.T) {
	f := newCompletionFixture(t)
	jobID := f.dispatchedJob(t, sensordispatch.StatusAwaitingSensor)
	if err := f.svc.CompleteSensorJob(context.Background(), f.tenant, f.sensor, jobID, sensordispatch.Completion{Status: "partial"}); err == nil {
		t.Fatal("an unknown status was recorded")
	}
	var status string
	_ = f.db.QueryRow(`SELECT status FROM discovery_jobs WHERE id = $1`, jobID).Scan(&status)
	if status != sensordispatch.StatusAwaitingSensor {
		t.Errorf("job changed to %q", status)
	}
}
