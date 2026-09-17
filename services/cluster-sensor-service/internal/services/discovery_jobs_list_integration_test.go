package services

// GetJobs against a real Postgres — the query the unified Discovery → Discovery
// Jobs page's list endpoint (GET /discovery/jobs, proxied by inventory-service's
// ListJobs) reads through. Three properties a mock cannot prove because they
// live in the WHERE clause and the tenant-scoped transaction, not in Go:
//
//   - tenant scoping — a caller in tenant A must never see tenant B's jobs,
//     even by paging past their own;
//   - the kind filter — "automatic" / "manual" reads the same
//     metadata.options.origin marker inventory-service's autoscan package
//     writes (mirrored here as a literal, not imported — see the comment on
//     the switch in GetJobs);
//   - pagination — page/page_size actually slice the tenant's rows, and
//     `total` counts the whole filtered set, not just the page returned.
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

func listJobsFixture(t *testing.T) (*DiscoveryService, *sql.DB, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	return NewDiscoveryService(db, db), raw, testdb.NewTenant(t, raw)
}

// insertListJob writes a bare discovery_jobs row for list-query fixtures.
// automatic=true stamps the same metadata.options.origin marker
// inventory-service's autoscan.JobOptions() writes for a sweep-created job.
func insertListJob(t *testing.T, raw *sql.DB, tenant uuid.UUID, status string, automatic bool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	metadata := `{}`
	if automatic {
		metadata = `{"options":{"origin":"auto_scan","active_scan":true}}`
	}
	if _, err := raw.Exec(`
		INSERT INTO discovery_jobs (id, tenant_id, created_by, execution_mode, status, metadata)
		VALUES ($1, $2, NULL, 'async', $3, $4::jsonb)`, id, tenant, status, metadata); err != nil {
		t.Fatalf("insert job (automatic=%v): %v", automatic, err)
	}
	return id
}

func TestIntegration_GetJobs_TenantScoping(t *testing.T) {
	svc, raw, tenantA := listJobsFixture(t)
	tenantB := testdb.NewTenant(t, raw)

	insertListJob(t, raw, tenantA, "queued", false)
	insertListJob(t, raw, tenantA, "queued", false)
	insertListJob(t, raw, tenantB, "queued", false)

	jobsA, totalA, err := svc.GetJobs(tenantA.String(), 1, 50, "", "", "", "")
	if err != nil {
		t.Fatalf("GetJobs(tenantA): %v", err)
	}
	if totalA != 2 || len(jobsA) != 2 {
		t.Fatalf("tenant A: total=%d len=%d, want 2/2 — must not see tenant B's job", totalA, len(jobsA))
	}
	for _, j := range jobsA {
		if j.TenantID != tenantA.String() {
			t.Fatalf("GetJobs(tenantA) returned a row for tenant %s — cross-tenant leak", j.TenantID)
		}
	}

	jobsB, totalB, err := svc.GetJobs(tenantB.String(), 1, 50, "", "", "", "")
	if err != nil {
		t.Fatalf("GetJobs(tenantB): %v", err)
	}
	if totalB != 1 || len(jobsB) != 1 {
		t.Fatalf("tenant B: total=%d len=%d, want 1/1", totalB, len(jobsB))
	}
}

func TestIntegration_GetJobs_StatusFilter(t *testing.T) {
	svc, raw, tenant := listJobsFixture(t)
	insertListJob(t, raw, tenant, "queued", false)
	insertListJob(t, raw, tenant, "completed", false)
	insertListJob(t, raw, tenant, "completed", false)

	jobs, total, err := svc.GetJobs(tenant.String(), 1, 50, "completed", "", "", "")
	if err != nil {
		t.Fatalf("GetJobs status=completed: %v", err)
	}
	if total != 2 || len(jobs) != 2 {
		t.Fatalf("total=%d len=%d, want 2/2 completed jobs", total, len(jobs))
	}
	for _, j := range jobs {
		if j.Status != "completed" {
			t.Errorf("status filter leaked a %q row", j.Status)
		}
	}
}

// The kind filter is what lets the unified Jobs page's "Automatic scan" chip
// mean something: it must isolate exactly the sweep-created rows, in both
// directions — asking for "manual" must not also return automatic rows, and
// vice versa. Losing either direction reintroduces the flattened-to-one-kind
// bug this filter exists to prevent.
func TestIntegration_GetJobs_KindFilter(t *testing.T) {
	svc, raw, tenant := listJobsFixture(t)
	autoID := insertListJob(t, raw, tenant, "completed", true)
	manualID := insertListJob(t, raw, tenant, "completed", false)

	autoJobs, autoTotal, err := svc.GetJobs(tenant.String(), 1, 50, "", "automatic", "", "")
	if err != nil {
		t.Fatalf("GetJobs kind=automatic: %v", err)
	}
	if autoTotal != 1 || len(autoJobs) != 1 || autoJobs[0].ID != autoID.String() {
		t.Fatalf("kind=automatic returned %d rows (want the 1 sweep-created job): %+v", autoTotal, autoJobs)
	}
	if autoJobs[0].Origin != "auto_scan" {
		t.Errorf("Origin = %q, want auto_scan on the row the filter matched", autoJobs[0].Origin)
	}

	manualJobs, manualTotal, err := svc.GetJobs(tenant.String(), 1, 50, "", "manual", "", "")
	if err != nil {
		t.Fatalf("GetJobs kind=manual: %v", err)
	}
	if manualTotal != 1 || len(manualJobs) != 1 || manualJobs[0].ID != manualID.String() {
		t.Fatalf("kind=manual returned %d rows (want the 1 operator-started job): %+v", manualTotal, manualJobs)
	}
	if manualJobs[0].Origin != "" {
		t.Errorf("Origin = %q, want empty on a manually started job", manualJobs[0].Origin)
	}

	// No kind filter: both rows, unfiltered.
	all, allTotal, err := svc.GetJobs(tenant.String(), 1, 50, "", "", "", "")
	if err != nil {
		t.Fatalf("GetJobs kind=<empty>: %v", err)
	}
	if allTotal != 2 || len(all) != 2 {
		t.Fatalf("no kind filter: total=%d len=%d, want both rows", allTotal, len(all))
	}
}

func TestIntegration_GetJobs_Pagination(t *testing.T) {
	svc, raw, tenant := listJobsFixture(t)
	for i := 0; i < 5; i++ {
		insertListJob(t, raw, tenant, "queued", false)
	}

	page1, total, err := svc.GetJobs(tenant.String(), 1, 2, "", "", "", "")
	if err != nil {
		t.Fatalf("GetJobs page 1: %v", err)
	}
	if total != 5 {
		t.Fatalf("total=%d, want 5 — total must count the whole filtered set, not the page", total)
	}
	if len(page1) != 2 {
		t.Fatalf("page 1 len=%d, want 2", len(page1))
	}

	page3, _, err := svc.GetJobs(tenant.String(), 3, 2, "", "", "", "")
	if err != nil {
		t.Fatalf("GetJobs page 3: %v", err)
	}
	if len(page3) != 1 {
		t.Fatalf("page 3 (5 rows, page_size 2) len=%d, want 1 — the remainder", len(page3))
	}

	seen := map[string]bool{}
	for _, j := range page1 {
		seen[j.ID] = true
	}
	for _, j := range page3 {
		if seen[j.ID] {
			t.Errorf("job %s appeared on both page 1 and page 3", j.ID)
		}
	}
}

// GetJob (singular, by id) must surface the same Origin marker GetJobs does —
// the detail panel and the list row must never disagree about a job's kind.
func TestIntegration_GetJob_SurfacesOrigin(t *testing.T) {
	svc, raw, tenant := listJobsFixture(t)
	autoID := insertListJob(t, raw, tenant, "completed", true)

	job, err := svc.GetJob(autoID.String())
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if job.Origin != "auto_scan" {
		t.Errorf("GetJob Origin = %q, want auto_scan", job.Origin)
	}
}
