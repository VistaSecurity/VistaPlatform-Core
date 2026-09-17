package autoscan

// The Active Scanning settings run list is where automatic scans are visible
//: each run must say WHICH executor ran it and, for a job handed to a
// tenant sensor that never collected it, that it failed as "sensor offline"
// beside the sensor's last heartbeat. Read against a real Postgres because the
// executor facts come from three tables the query joins.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_RecentJobs_CarryTheExecutorAndTheDispatchFacts(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	store := NewStore(db)

	sensorID := uuid.New()
	if _, err := raw.Exec(`
		INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status, last_heartbeat)
		VALUES ($1, $2, 'xps16-sensor', 'linux', '1.0.0', 'datacenter_host', 'active', NOW() - interval '40 minutes')`, sensorID, tenant); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}
	// One automatic job the platform ran, one handed to the sensor that failed
	// as offline, one still awaiting the sensor with its command collected.
	platformJob, offlineJob, runningJob := uuid.New(), uuid.New(), uuid.New()
	for _, row := range []struct {
		id       uuid.UUID
		mode     string
		status   string
		assigned interface{}
		errMsg   interface{}
	}{
		{platformJob, "async", "completed", nil, nil},
		{offlineJob, "sensors", "failed", sensorID, "sensor xps16-sensor offline; nothing was scanned (last heartbeat 2026-09-17T11:00:00Z)"},
		{runningJob, "sensors", "awaiting_sensor", sensorID, nil},
	} {
		if _, err := raw.Exec(`
			INSERT INTO discovery_jobs (id, tenant_id, execution_mode, status, assigned_sensor_id, dispatched_at, error_message, metadata, created_at)
			VALUES ($1, $2, $3, $4, $5, CASE WHEN $5::uuid IS NULL THEN NULL ELSE NOW() - interval '5 minutes' END, $6, $7::jsonb, NOW())`,
			row.id, tenant, row.mode, row.status, row.assigned, row.errMsg, `{"options":{"origin":"`+Origin+`"}}`); err != nil {
			t.Fatalf("insert job %s: %v", row.id, err)
		}
	}
	if _, err := raw.Exec(`
		INSERT INTO sensor_commands (sensor_id, command_type, payload, status, created_at, delivered_at)
		VALUES ($1, 'discovery_job', jsonb_build_object('job_id', $2::text), 'delivered', NOW() - interval '5 minutes', NOW() - interval '4 minutes')`,
		sensorID, runningJob.String()); err != nil {
		t.Fatalf("insert command: %v", err)
	}

	jobs, err := store.RecentJobs(context.Background(), tenant, 10)
	if err != nil {
		t.Fatalf("RecentJobs: %v", err)
	}
	byID := map[string]RecentJob{}
	for _, j := range jobs {
		byID[j.ID] = j
	}

	p := byID[platformJob.String()]
	if p.Executor != "platform" || p.ExecutorName != nil || p.ErrorMessage != nil {
		t.Errorf("platform job = %+v, want executor platform with no sensor and no error", p)
	}
	o := byID[offlineJob.String()]
	if o.Executor != "sensor" || o.ExecutorName == nil || *o.ExecutorName != "xps16-sensor" {
		t.Errorf("offline job executor = %s / %v, want sensor xps16-sensor", o.Executor, o.ExecutorName)
	}
	if o.ErrorMessage == nil || !strings.Contains(*o.ErrorMessage, "offline") || o.ExecutorLastHeartbeat == nil || o.DispatchedAt == nil {
		t.Errorf("offline job lacks the failure facts: error=%v heartbeat=%v dispatched=%v", o.ErrorMessage, o.ExecutorLastHeartbeat, o.DispatchedAt)
	}
	r := byID[runningJob.String()]
	if r.Status != "awaiting_sensor" || r.PickedUpAt == nil || r.DispatchedAt == nil {
		t.Errorf("running job = status %s picked_up=%v dispatched=%v, want awaiting_sensor with both stamps", r.Status, r.PickedUpAt, r.DispatchedAt)
	}
}
