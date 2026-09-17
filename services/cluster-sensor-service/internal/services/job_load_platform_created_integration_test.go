package services

// A discovery job the platform created on its own initiative — the automatic
// active-scan sweep, any HMAC service-auth caller — has created_by NULL
// (createdByOrNull). GetJob is the FIRST thing the job processor does with a
// job, and it scanned that NULL into a plain string, so every such job failed
// to load and sat in `queued` forever; the stuck-job sweep republished it every
// 30 seconds to the same failure. GetJobs selected error_message into a struct
// that had no such field (sqlx is strict), and GetJob wrapped a pq.StringArray
// in pq.Array, which cannot scan into strings once the array is non-empty.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_GetJob_LoadsAJobThePlatformCreated(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	svc := NewDiscoveryService(db, db)
	tenant := testdb.NewTenant(t, raw)

	sensorID := uuid.New().String()
	jobID := uuid.New()
	if _, err := raw.Exec(`
		INSERT INTO discovery_jobs (id, tenant_id, created_by, execution_mode, status, requested_sensor_ids, error_message)
		VALUES ($1, $2, NULL, 'async', 'queued', ARRAY[$3::text], 'earlier attempt')`, jobID, tenant, sensorID); err != nil {
		t.Fatalf("insert platform-created job: %v", err)
	}
	if _, err := raw.Exec(`
		INSERT INTO discovery_targets (job_id, tenant_id, input, protocols, ports)
		VALUES ($1, $2, '192.0.2.10', ARRAY['TLS'], ARRAY[443])`, jobID, tenant); err != nil {
		t.Fatalf("insert target: %v", err)
	}

	job, err := svc.GetJob(jobID.String())
	if err != nil {
		t.Fatalf("GetJob on a created_by NULL job with a named sensor: %v — the job processor would never run it", err)
	}
	if job.CreatedBy != "" {
		t.Errorf("CreatedBy = %q, want empty for a platform-created job", job.CreatedBy)
	}
	if len(job.RequestedSensorIDs) != 1 || job.RequestedSensorIDs[0] != sensorID {
		t.Errorf("RequestedSensorIDs = %v, want [%s]", job.RequestedSensorIDs, sensorID)
	}
	if job.ErrorMessage == nil || *job.ErrorMessage != "earlier attempt" {
		t.Errorf("ErrorMessage = %v, want the stored message", job.ErrorMessage)
	}
	if strings.Join(job.Targets, ",") != "192.0.2.10" {
		t.Errorf("Targets = %v", job.Targets)
	}

	jobs, total, err := svc.GetJobs(tenant.String(), 1, 10, "", "", "", "")
	if err != nil {
		t.Fatalf("GetJobs: %v", err)
	}
	if total != 1 || len(jobs) != 1 || jobs[0].ID != jobID.String() || jobs[0].CreatedBy != "" {
		t.Fatalf("GetJobs = %d/%+v, want the one platform-created job with empty CreatedBy", total, jobs)
	}
	if len(jobs[0].RequestedSensorIDs) != 1 || jobs[0].ErrorMessage == nil {
		t.Errorf("GetJobs row lost requested_sensor_ids/error_message: %+v", jobs[0])
	}
}

// The other polarity: a job a person created still reads with its author.
func TestIntegration_GetJob_KeepsAUserCreatedJobsAuthor(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	svc := NewDiscoveryService(db, db)
	tenant := testdb.NewTenant(t, raw)

	var userID uuid.UUID
	if err := raw.QueryRow(`SELECT id FROM users WHERE tenant_id = $1 LIMIT 1`, tenant).Scan(&userID); err != nil {
		t.Skipf("no user on the test tenant to attribute a job to: %v", err)
	}
	jobID := uuid.New()
	if _, err := raw.Exec(`
		INSERT INTO discovery_jobs (id, tenant_id, created_by, execution_mode, status)
		VALUES ($1, $2, $3, 'async', 'queued')`, jobID, tenant, userID); err != nil {
		t.Fatalf("insert user-created job: %v", err)
	}
	job, err := svc.GetJob(jobID.String())
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if job.CreatedBy != userID.String() {
		t.Errorf("CreatedBy = %q, want %s", job.CreatedBy, userID)
	}
}
