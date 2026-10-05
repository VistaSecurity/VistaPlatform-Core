package services

// A planned job's started_at ( WP3, spec V13), through sensor-manager's
// real RecordSensorUnits / CompleteSensorJob against Postgres: it is when the
// sensor first reported (a host or an empty ping), not when it collected the
// command; the job stays awaiting_sensor while it runs; and a job that
// reported nothing still gets the delivered_at back-fill at completion.
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

func (f *completionFixture) jobStart(t *testing.T, jobID uuid.UUID) (string, sql.NullTime, time.Time) {
	t.Helper()
	var status string
	var started sql.NullTime
	var delivered time.Time
	if err := f.db.QueryRow(`
		SELECT j.status, j.started_at, c.delivered_at
		FROM discovery_jobs j JOIN sensor_commands c ON c.payload ->> 'job_id' = j.id::text
		WHERE j.id = $1`, jobID).Scan(&status, &started, &delivered); err != nil {
		t.Fatal(err)
	}
	return status, started, delivered
}

func TestIntegration_PlannedSensorJob_StartedAtIsTheFirstReport(t *testing.T) {
	f := newCompletionFixture(t)
	ctx := context.Background()
	jobID, targetID := f.plannedJob(t, "10.183.9.1", "10.183.9.2")

	if _, started, _ := f.jobStart(t, jobID); started.Valid {
		t.Fatalf("started_at = %v before the sensor reported anything", started.Time)
	}

	// The sensor's first contact is an empty ping.
	if resp, err := f.svc.RecordSensorUnits(ctx, f.tenant, f.sensor, jobID, sensordispatch.UnitBatch{}); err != nil || resp.Code != "" {
		t.Fatalf("ping = %+v %v", resp, err)
	}
	status, started, delivered := f.jobStart(t, jobID)
	if !started.Valid {
		t.Fatal("started_at still NULL after the sensor's first report")
	}
	// delivered_at is a minute ago (dispatchedJob); the first report is now.
	if !started.Time.After(delivered.Add(30 * time.Second)) {
		t.Fatalf("started_at = %v, want the first report's time, not the command's delivered_at %v", started.Time, delivered)
	}
	// The status a planned sensor job runs under, and that the stale-dispatch
	// sweep keys on, is unchanged.
	if status != sensordispatch.StatusAwaitingSensor {
		t.Fatalf("status = %s, want %s", status, sensordispatch.StatusAwaitingSensor)
	}
	first := started.Time

	// Later reports and the completion keep the first time.
	if _, err := f.svc.RecordSensorUnits(ctx, f.tenant, f.sensor, jobID, sensordispatch.UnitBatch{Units: []sensordispatch.UnitResult{sshHost(targetID, "10.183.9.1")}}); err != nil {
		t.Fatal(err)
	}
	if _, started, _ := f.jobStart(t, jobID); !started.Time.Equal(first) {
		t.Fatalf("a later report moved started_at from %v to %v", first, started.Time)
	}
	if err := f.svc.CompleteSensorJob(ctx, f.tenant, f.sensor, jobID, sensordispatch.Completion{Status: "completed", TotalTargets: 2, SuccessfulTargets: 1, FailedTargets: 1}); err != nil {
		t.Fatalf("CompleteSensorJob: %v", err)
	}
	if status, started, _ := f.jobStart(t, jobID); status != "completed" || !started.Time.Equal(first) {
		t.Fatalf("after completion: %s, started_at %v (want %v)", status, started.Time, first)
	}
}

// The fallback: a planned job whose sensor reported nothing before finishing
// is still given a start, from the command's delivered_at.
func TestIntegration_PlannedSensorJob_NoReportsFallsBackToDelivery(t *testing.T) {
	f := newCompletionFixture(t)
	jobID, _ := f.plannedJob(t, "10.183.9.1")
	if err := f.svc.CompleteSensorJob(context.Background(), f.tenant, f.sensor, jobID, sensordispatch.Completion{Status: "completed", TotalTargets: 1, FailedTargets: 1}); err != nil {
		t.Fatalf("CompleteSensorJob: %v", err)
	}
	_, started, delivered := f.jobStart(t, jobID)
	if !started.Valid || !started.Time.Equal(delivered) {
		t.Fatalf("started_at = %v, want the command's delivered_at %v", started, delivered)
	}
}
