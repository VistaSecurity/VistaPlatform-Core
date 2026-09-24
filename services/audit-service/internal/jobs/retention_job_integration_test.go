package jobs

// The retention job's archive step, after cold_storage_days was removed
// (admin-ui review decision 14, security-staff-16).
//
// The step used to run only for a policy carrying a cold_storage_days value —
// a number nothing else read. With S3 archival configured, only archived rows
// are deleted, so a policy without the field was never archived and its logs
// were never deleted either, whatever total_retention_days said. Whether to
// archive is now decided by the deployment (S3 configured or not), which these
// tests pin through processPolicy against a real Postgres:
//
//   - S3 configured: logs past the hot period are uploaded, stamped archived,
//     and — past the total — deleted, for a policy with no cold-tier field;
//   - S3 not configured: nothing is uploaded or stamped, logs past the total
//     are deleted, and logs_archived reports 0 (it used to report a count of
//     rows it had skipped).
//
// The S3 endpoint is an in-process fake that accepts PutObject, so the real
// S3ArchivalService (aws-sdk client, gzip, key layout) runs unmodified.
// Skipped unless TEST_DATABASE_URL is set (make test-integration-db).

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	auditConfig "github.com/vistasecurity/vistaplatform/audit-service/internal/config"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// fakeS3 accepts every PutObject and counts them.
type fakeS3 struct {
	mu   sync.Mutex
	puts int
	srv  *httptest.Server
}

func newFakeS3(t *testing.T) *fakeS3 {
	t.Helper()
	f := &fakeS3{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.Method == http.MethodPut {
			f.mu.Lock()
			f.puts++
			f.mu.Unlock()
		}
		w.Header().Set("ETag", `"fake"`)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeS3) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.puts
}

type retentionJobFixture struct {
	db     *sql.DB
	ids    []uuid.UUID
	policy services.RetentionPolicy
}

// newRetentionJobFixture seeds n logs 60 days old under a unique event type,
// and a policy (hot 30, total 45) scoped to that event type, so every
// statement the job runs touches only these rows.
func newRetentionJobFixture(t *testing.T, n int) *retentionJobFixture {
	t.Helper()
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)

	occurredAt := time.Now().AddDate(0, 0, -60)
	if _, err := db.Exec(`SELECT audit.create_activity_logs_partition($1, $2)`,
		occurredAt.Year(), int(occurredAt.Month())); err != nil {
		t.Fatalf("ensure partition: %v", err)
	}
	eventType := "retention.job.itest." + uuid.NewString()[:8]
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM audit.activity_logs WHERE event_type = $1`, eventType)
		_, _ = db.Exec(`DELETE FROM audit.job_execution_logs WHERE job_name = $1`, "Retention: "+eventType)
	})
	f := &retentionJobFixture{db: db}
	for i := 0; i < n; i++ {
		id := uuid.New()
		if _, err := db.Exec(`
			INSERT INTO audit.activity_logs
			    (id, tenant_id, user_type, event_type, event_category, action, occurred_at)
			VALUES ($1, $2, 'tenant', $3, 'system', 'retention.fixture', $4)`,
			id, tenantID, eventType, occurredAt); err != nil {
			t.Fatalf("seed activity log: %v", err)
		}
		f.ids = append(f.ids, id)
	}
	f.policy = services.RetentionPolicy{
		ID:                 uuid.New(),
		PolicyName:         eventType,
		EventType:          &eventType,
		HotStorageDays:     30,
		TotalRetentionDays: 45,
		IsActive:           true,
	}
	return f
}

func (f *retentionJobFixture) remaining(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(`SELECT count(*) FROM audit.activity_logs WHERE id = ANY($1::uuid[])`, pq.Array(f.ids)).Scan(&n); err != nil {
		t.Fatalf("count remaining: %v", err)
	}
	return n
}

// completion returns the finished job row's status and the counts the job
// recorded at completion (LogJobCompletion stores them in error_details).
func (f *retentionJobFixture) completion(t *testing.T) (string, map[string]interface{}) {
	t.Helper()
	var status string
	var raw []byte
	if err := f.db.QueryRow(`
		SELECT status, COALESCE(error_details, '{}'::jsonb)
		FROM audit.job_execution_logs
		WHERE job_type = 'retention' AND job_name = $1
		ORDER BY started_at DESC LIMIT 1`, "Retention: "+f.policy.PolicyName).Scan(&status, &raw); err != nil {
		t.Fatalf("read job row: %v", err)
	}
	meta := map[string]interface{}{}
	_ = json.Unmarshal(raw, &meta)
	return status, meta
}

func (f *retentionJobFixture) job(s3 *services.S3ArchivalService) *RetentionJob {
	retention := services.NewRetentionService(f.db, f.db)
	jobs := services.NewJobExecutionService(f.db, f.db)
	j := NewRetentionJob(retention, jobs)
	if s3 != nil {
		j = NewRetentionJobWithS3(retention, jobs, s3, services.NewActivityLogService(f.db, f.db))
	}
	j.logger = log.New(io.Discard, "", 0)
	return j
}

func TestIntegration_RetentionJob_ArchivesWithoutAColdTier_WhenS3Configured(t *testing.T) {
	f := newRetentionJobFixture(t, 3)
	fake := newFakeS3(t)
	s3, err := services.NewS3ArchivalService(&auditConfig.S3Config{
		Enabled: true, Bucket: "retention-it", Region: "us-east-1", Endpoint: fake.srv.URL,
		AccessKeyID: "it-access", SecretAccessKey: "it-access-pair", PathPrefix: "it",
	})
	if err != nil {
		t.Fatalf("s3 archival service: %v", err)
	}

	f.job(s3).processPolicy(context.Background(), f.policy)

	if fake.count() != 1 {
		t.Fatalf("S3 PutObject calls = %d, want 1 (the policy's past-hot logs, one batch)", fake.count())
	}
	if n := f.remaining(t); n != 0 {
		t.Fatalf("%d of 3 logs past total_retention_days survived: archived-then-deleted did not happen", n)
	}
	status, meta := f.completion(t)
	if status != "completed" {
		t.Fatalf("job status = %q, want completed (metadata %v)", status, meta)
	}
	if meta["logs_archived"] != float64(3) || meta["logs_deleted"] != float64(3) {
		t.Fatalf("job metadata = %v, want logs_archived=3 and logs_deleted=3", meta)
	}
}

func TestIntegration_RetentionJob_NoS3_DeletesAndReportsNothingArchived(t *testing.T) {
	f := newRetentionJobFixture(t, 2)

	f.job(nil).processPolicy(context.Background(), f.policy)

	if n := f.remaining(t); n != 0 {
		t.Fatalf("%d of 2 logs past total_retention_days survived", n)
	}
	var stamped int
	if err := f.db.QueryRow(`SELECT count(*) FROM audit.activity_logs WHERE id = ANY($1::uuid[]) AND metadata->>'archived' = 'true'`,
		pq.Array(f.ids)).Scan(&stamped); err != nil {
		t.Fatal(err)
	}
	if stamped != 0 {
		t.Fatalf("%d logs stamped archived with no archive configured", stamped)
	}
	status, meta := f.completion(t)
	if status != "completed" {
		t.Fatalf("job status = %q, want completed (metadata %v)", status, meta)
	}
	if meta["logs_archived"] != float64(0) || meta["logs_deleted"] != float64(2) {
		t.Fatalf("job metadata = %v, want logs_archived=0 and logs_deleted=2", meta)
	}
}

// A deployment that wires the S3 service but leaves archival switched off is
// "not configured": no upload is attempted, and logs are deleted at the total.
func TestIntegration_RetentionJob_S3Disabled_IsNotConfigured(t *testing.T) {
	f := newRetentionJobFixture(t, 2)
	s3, err := services.NewS3ArchivalService(&auditConfig.S3Config{Enabled: false})
	if err != nil {
		t.Fatalf("s3 archival service: %v", err)
	}

	f.job(s3).processPolicy(context.Background(), f.policy)

	if n := f.remaining(t); n != 0 {
		t.Fatalf("%d of 2 logs past total_retention_days survived", n)
	}
	status, meta := f.completion(t)
	if status != "completed" || meta["logs_archived"] != float64(0) {
		t.Fatalf("job status = %q, metadata = %v; want completed with logs_archived=0", status, meta)
	}
}
