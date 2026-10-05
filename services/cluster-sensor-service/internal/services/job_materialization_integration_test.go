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

// `observed` (host observations) and `suppressed` (archived/denied assets)
// must not be counted as pending_approval — that was the bug: the old filter
// was `approval_status <> 'auto_approved'`, so both landed in the same bucket
// as a row genuinely awaiting a human in Discovery → Approvals, permanently
// overstating it. `suppressed` gets its own count; `observed` gets none — it
// simply must not inflate pending_approval.
//
// Mutation that proves it: restore `approval_status <> 'auto_approved'` for
// pending_approval — this test's pending_approval assertion goes red (4
// instead of 1: it re-absorbs the one `observed` row and both `suppressed`
// rows), and TestIntegration_JobMaterialization_ReportsBothNumbersSeparately
// stays green (it never exercises `observed` or `suppressed`), which is why
// that older test alone could not have caught the regression. (Verified by
// running the mutation: it does NOT also move the `suppressed` count, which
// is a separate FILTER clause the old predicate never touched.)
func TestIntegration_JobMaterialization_ObservedAndSuppressedAreNotPendingApproval(t *testing.T) {
	svc, raw, tenant := materializationFixture(t)
	jobID := uuid.New().String()

	queueRow(t, raw, tenant, jobID, "192.0.2.31", "pending", true)    // genuinely awaiting a human
	queueRow(t, raw, tenant, jobID, "192.0.2.32", "observed", true)   // host observation — never awaits approval
	queueRow(t, raw, tenant, jobID, "192.0.2.33", "suppressed", true) // archived asset — nothing to approve
	queueRow(t, raw, tenant, jobID, "192.0.2.34", "suppressed", true) // denied asset — nothing to approve
	queueRow(t, raw, tenant, jobID, "192.0.2.35", "auto_approved", true)

	m := svc.getJobMaterialization(jobID, 5)
	if m == nil {
		t.Fatal("materialization unavailable")
	}
	if m.PendingApproval != 1 {
		t.Errorf("pending_approval = %d, want 1 — the observed and suppressed rows must not be counted as "+
			"awaiting a human", m.PendingApproval)
	}
	if m.Suppressed != 2 {
		t.Errorf("suppressed = %d, want 2", m.Suppressed)
	}
	if m.AutoApproved != 1 {
		t.Errorf("auto_approved = %d, want 1", m.AutoApproved)
	}
	if m.Queued != 5 {
		t.Errorf("queued = %d, want 5 — every row still reached the queue, whatever its disposition", m.Queued)
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

//: the rows kept as observations are counted — how many and on how many
// hosts — so the job can say where they went (Discovery → Observations)
// instead of a silent "0 pending approval"; and the job's findings report the
// hosts they are on, so a finding count is not read as a count of assets.
// Only processed `observed` rows count: one the pipeline has not reached yet
// is still awaiting processing, not an observation.
func TestIntegration_JobMaterialization_CountsObservedRowsAndHosts(t *testing.T) {
	svc, raw, tenant := materializationFixture(t)
	jobID := uuid.New().String()

	queueRow(t, raw, tenant, jobID, "192.0.2.41", "observed", true)
	queueRow(t, raw, tenant, jobID, "192.0.2.41", "observed", true) // a second port on the same host
	queueRow(t, raw, tenant, jobID, "192.0.2.42", "observed", true)
	queueRow(t, raw, tenant, jobID, "192.0.2.43", "observed", false) // not dispositioned yet
	queueRow(t, raw, tenant, jobID, "192.0.2.44", "pending", true)

	m := svc.getJobMaterialization(jobID, 5)
	if m == nil {
		t.Fatal("materialization unavailable")
	}
	if m.Observed != 3 || m.ObservedHosts != 2 {
		t.Errorf("observed = %d on %d host(s), want 3 on 2", m.Observed, m.ObservedHosts)
	}
	if m.PendingApproval != 1 || m.AwaitingProcessing != 1 {
		t.Errorf("pending = %d, awaiting = %d; want 1 and 1 (observed must not move them)", m.PendingApproval, m.AwaitingProcessing)
	}

	// A job with nothing observed reports an explicit zero, not an absence.
	other := svc.getJobMaterialization(uuid.New().String(), 0)
	if other == nil || other.Observed != 0 || other.ObservedHosts != 0 {
		t.Fatalf("a job with no observed rows = %+v, want explicit zeros", other)
	}
}

// finding_hosts is the distinct hosts of the job's own findings: three
// findings on two addresses are "3 open ports on 2 hosts", not 3 of anything.
func TestIntegration_JobMaterialization_FindingHosts(t *testing.T) {
	f, _ := newUnitFixture(t)
	jobID := f.createPlanJob(t, "22", "10.183.4.0/24")
	var targetID string
	if err := f.raw.QueryRow(`SELECT id FROM discovery_targets WHERE job_id = $1 LIMIT 1`, jobID).Scan(&targetID); err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct {
		ip   string
		port int
	}{{"10.183.4.1", 22}, {"10.183.4.1", 443}, {"10.183.4.2", 22}} {
		if _, err := f.raw.Exec(`INSERT INTO discovery_findings (job_id, target_id, tenant_id, executed_via, protocol, port, resolved_ip)
			VALUES ($1, $2, $3, 'scan-engine', 'SSH', $4, $5)`, jobID, targetID, f.tenant, r.port, r.ip); err != nil {
			t.Fatal(err)
		}
	}
	m := f.svc.getJobMaterialization(jobID, 3)
	if m == nil || m.Findings != 3 || m.FindingHosts != 2 {
		t.Fatalf("materialization = %+v, want 3 findings on 2 hosts", m)
	}
}
