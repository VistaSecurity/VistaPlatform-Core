package services

// F7: a job's finding count and its inventory outcome answer different
// questions. Progress counts discovery_findings; inventory materializes from
// sensor_discoveries. A job could therefore report N findings honestly and add
// zero assets, with nothing reconciling the two numbers.
//
// getJobMaterialization is the reconciliation: it reports the queue outcome
// alongside the find count, under distinct names, and reports "not dispositioned
// yet" explicitly rather than as a zero.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func materializationFixture(t *testing.T) (*DiscoveryService, *sql.DB, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	return NewDiscoveryService(db, db), raw, testdb.NewTenant(t, raw)
}

// queueRow writes one mirrored finding into the ingestion queue.
// processedAt nil means the pipeline has not dispositioned it yet.
func queueRow(t *testing.T, db *sql.DB, tenant uuid.UUID, jobID, ip, approvalStatus string, processed bool) {
	t.Helper()
	var processedAt interface{}
	if processed {
		processedAt = "now()"
	}
	_, err := db.Exec(`
		INSERT INTO sensor_discoveries
			(sensor_id, tenant_id, batch_id, protocol, dest_ip, port, confidence, metadata, approval_status, processed_at)
		VALUES ($1, $2, $3, 'TLS', $4::inet, 443, 0.9, '{}'::jsonb, $5,
		        CASE WHEN $6::text IS NULL THEN NULL ELSE now() END)`,
		uuid.New(), tenant, jobID, ip, approvalStatus, processedAt)
	if err != nil {
		t.Fatalf("insert queue row: %v", err)
	}
}

func TestIntegration_JobMaterialization_ReportsBothNumbersSeparately(t *testing.T) {
	svc, raw, tenant := materializationFixture(t)
	jobID := uuid.New().String()

	// A job that found 3 things: one auto-approved, one queued for approval, one
	// still being processed.
	queueRow(t, raw, tenant, jobID, "192.0.2.11", "auto_approved", true)
	queueRow(t, raw, tenant, jobID, "192.0.2.12", "pending", true)
	queueRow(t, raw, tenant, jobID, "192.0.2.13", "pending", false)

	m := svc.getJobMaterialization(jobID, 3)
	if m == nil {
		t.Fatal("materialization unavailable — the reconciliation between find count and inventory outcome is missing")
	}
	if m.Findings != 3 || m.Queued != 3 {
		t.Fatalf("findings=%d queued=%d, want 3/3", m.Findings, m.Queued)
	}
	if m.AutoApproved != 1 || m.PendingApproval != 1 || m.AwaitingProcessing != 1 {
		t.Fatalf("split was auto=%d pending=%d awaiting=%d, want 1/1/1",
			m.AutoApproved, m.PendingApproval, m.AwaitingProcessing)
	}
}

// The case F7 is actually about: a job that found things, none of which became
// inventory (every finding was a third-party endpoint, or had no IP to anchor
// on). The find count must stay non-zero and the materialized count must be an
// explicit zero — one number presented as if it answered both questions is what
// must not survive.
func TestIntegration_JobMaterialization_NonZeroFindingsWithExplicitZeroMaterialized(t *testing.T) {
	svc, _, _ := materializationFixture(t)

	m := svc.getJobMaterialization(uuid.New().String(), 7)
	if m == nil {
		t.Fatal("materialization unavailable for a job with nothing queued — absent means 'unknown', which would misreport a real zero")
	}
	if m.Findings != 7 {
		t.Fatalf("findings=%d, want 7 — the job's own record must not be erased by a zero inventory outcome", m.Findings)
	}
	if m.Queued != 0 || m.AutoApproved != 0 || m.PendingApproval != 0 || m.AwaitingProcessing != 0 {
		t.Fatalf("queue counts should all be zero, got queued=%d auto=%d pending=%d awaiting=%d",
			m.Queued, m.AutoApproved, m.PendingApproval, m.AwaitingProcessing)
	}
}

// One job's counts must not include another's.
func TestIntegration_JobMaterialization_ScopedToTheJob(t *testing.T) {
	svc, raw, tenant := materializationFixture(t)
	mine, theirs := uuid.New().String(), uuid.New().String()

	queueRow(t, raw, tenant, mine, "192.0.2.21", "auto_approved", true)
	queueRow(t, raw, tenant, theirs, "192.0.2.22", "auto_approved", true)
	queueRow(t, raw, tenant, theirs, "192.0.2.23", "pending", true)

	m := svc.getJobMaterialization(mine, 1)
	if m == nil || m.Queued != 1 || m.AutoApproved != 1 {
		t.Fatalf("counts leaked across jobs: %+v", m)
	}
}
