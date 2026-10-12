package services

// Database-integration tests for the single score fold (overrides included),
// deterministic override precedence, duplicate rejection and the read-only
// Frameworks status GET. They skip unless TEST_DATABASE_URL is set.

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
)

func (f *evalFixture) rollupScore(t *testing.T) *int {
	t.Helper()
	findings := &FindingsService{db: f.db}
	if err := findings.recomputeFrameworkScore(context.Background(), f.tenant, f.frameworkID, f.controls); err != nil {
		t.Fatalf("recomputeFrameworkScore: %v", err)
	}
	var score *int
	if err := f.db.QueryRow(`SELECT score FROM tenant_framework_scores
		WHERE tenant_id = $1 AND platform_framework_id = $2`, f.tenant, f.frameworkID).Scan(&score); err != nil {
		t.Fatalf("read rollup: %v", err)
	}
	return score
}

func (f *evalFixture) statusScore(t *testing.T) *int {
	t.Helper()
	st, err := NewEvaluationService(f.db).GetFrameworkStatus(f.tenant)
	if err != nil {
		t.Fatalf("GetFrameworkStatus: %v", err)
	}
	for _, fw := range st.Frameworks {
		if fw.ID == f.frameworkID.String() {
			return fw.CompliancePercent
		}
	}
	t.Fatalf("fixture framework missing from status: %+v", st.Frameworks)
	return nil
}

func (f *evalFixture) liveScore(t *testing.T) *int {
	t.Helper()
	sum, err := NewEvaluationService(f.db).EvaluateFramework(f.tenant, f.frameworkID, "1.0", models.ScenarioFilters{}, nil)
	if err != nil {
		t.Fatalf("EvaluateFramework: %v", err)
	}
	return sum.KPIs.Score
}

// user mints a tenant user: compliance_overrides.created_by FKs to users.
func (f *evalFixture) user(t *testing.T) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := f.db.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`,
		id, f.tenant, "ov-"+id.String()[:8]+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

func intStr(p *int) string {
	if p == nil {
		return "nil"
	}
	return strconv.Itoa(*p)
}

func sameScore(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func TestIntegration_FrameworkScore_StatusRollupAndEvaluateAgreeWithOverride(t *testing.T) {
	f := newEvalFixture(t)
	f.failCritical(t)

	// No override: Critical failing (4), Low passing (1) -> 20 on every path.
	for name, got := range map[string]*int{"status": f.statusScore(t), "rollup": f.rollupScore(t), "live": f.liveScore(t)} {
		if got == nil || *got != 20 {
			t.Fatalf("%s score without override = %s, want 20", name, intStr(got))
		}
	}

	// Disregard the failing Critical control: it now counts as a pass everywhere.
	ov := NewOverrideService(f.db)
	if _, err := ov.CreateOverride(f.tenant, f.user(t), nil, f.critical, models.OverrideTypeDisregard, nil, nil, "accepted", "platform"); err != nil {
		t.Fatalf("CreateOverride: %v", err)
	}
	status, rollup, live := f.statusScore(t), f.rollupScore(t), f.liveScore(t)
	if live == nil || *live != 100 {
		t.Fatalf("live score with disregard = %s, want 100", intStr(live))
	}
	if !sameScore(status, live) || !sameScore(rollup, live) {
		t.Fatalf("scores diverge with an override present: status=%s rollup=%s live=%s",
			intStr(status), intStr(rollup), intStr(live))
	}
}

// failingFindingsDB returns a pool whose search_path resolves the unqualified
// `findings` to a view that errors when read, so every per-control findings read
// fails while the rest of the schema is untouched. This is how a per-control
// error is injected without altering any shared table.
func (f *evalFixture) failingFindingsDB(t *testing.T) *sqlx.DB {
	t.Helper()
	schema := "errfind_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	for _, q := range []string{
		`CREATE SCHEMA ` + schema,
		`CREATE VIEW ` + schema + `.findings AS SELECT * FROM public.findings WHERE (1/(SELECT 0)) = 1`,
	} {
		if _, err := f.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	t.Cleanup(func() { _, _ = f.db.Exec(`DROP SCHEMA ` + schema + ` CASCADE`) })
	u, err := url.Parse(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatalf("parse TEST_DATABASE_URL: %v", err)
	}
	q := u.Query()
	q.Set("options", "-c search_path="+schema+",public")
	u.RawQuery = q.Encode()
	db, err := sqlx.Open("postgres", u.String())
	if err != nil {
		t.Fatalf("open failing pool: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestIntegration_FrameworkStatus_ControlErrorSurfaces(t *testing.T) {
	f := newEvalFixture(t)
	bad := f.failingFindingsDB(t)
	// Sanity: the injection really breaks a findings read.
	if _, err := bad.Exec(`SELECT 1 FROM findings LIMIT 1`); err == nil {
		t.Fatal("fault injection did not take effect")
	}
	// A per-control read error used to be `continue`d past (the control vanished
	// from the score, inflating it) or logged and shown as "no score". It must
	// reach the caller.
	if _, err := NewEvaluationService(bad).calculatePlatformFrameworkScore(f.tenant, f.frameworkID); err == nil {
		t.Fatal("calculatePlatformFrameworkScore swallowed a findings read error")
	}
	if _, err := NewEvaluationService(bad).GetFrameworkStatus(f.tenant); err == nil {
		t.Fatal("GetFrameworkStatus swallowed a findings read error")
	}
}

func TestIntegration_Override_DuplicateRejected(t *testing.T) {
	f := newEvalFixture(t)
	ov := NewOverrideService(f.db)
	mk := func(scenario *uuid.UUID) error {
		_, err := ov.CreateOverride(f.tenant, f.user(t), scenario, f.critical, models.OverrideTypeDisregard, nil, nil, "r", "platform")
		return err
	}
	if err := mk(nil); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if err := mk(nil); !errors.Is(err, ErrDuplicateOverride) {
		t.Fatalf("duplicate global override: err = %v, want ErrDuplicateOverride", err)
	}
	// A different control is not a duplicate.
	if _, err := ov.CreateOverride(f.tenant, f.user(t), nil, f.low, models.OverrideTypeDisregard, nil, nil, "r", "platform"); err != nil {
		t.Fatalf("other control: %v", err)
	}
}

func TestIntegration_Override_LegacyDuplicatesResolveDeterministically(t *testing.T) {
	f := newEvalFixture(t)
	// Legacy rows: two global overrides for one control (no unique index exists).
	// The earliest must win everywhere, however the planner orders the scan.
	ins := func(typ string, sevTo *string, age string) {
		if _, err := f.db.Exec(`
			INSERT INTO compliance_overrides (id, tenant_id, control_id, override_type, severity_from, severity_to, rationale, created_by, created_at, framework_type)
			VALUES ($1, $2, $3, $4, $5, $6, 'legacy', $7, now() - $8::interval, 'platform')`,
			uuid.New(), f.tenant, f.critical, typ, sevTo, sevTo, f.user(t), age); err != nil {
			t.Fatalf("seed legacy override: %v", err)
		}
	}
	low := "low"
	ins("severity", &low, "2 days") // older: severity re-rate, status untouched
	ins("disregard", nil, "1 day")  // newer: would flip the control to PASS
	f.failCritical(t)

	svc := NewEvaluationService(f.db)
	for i := 0; i < 5; i++ {
		m, err := svc.getOverrides(f.tenant, nil)
		if err != nil {
			t.Fatalf("getOverrides: %v", err)
		}
		if got := m[f.critical].OverrideType; got != models.OverrideTypeSeverity {
			t.Fatalf("getOverrides winner = %s, want the earliest (severity)", got)
		}
	}
	active, err := NewOverrideService(f.db).GetActiveOverrideForControl(f.tenant, f.critical, nil)
	if err != nil || active == nil || active.OverrideType != models.OverrideTypeSeverity {
		t.Fatalf("GetActiveOverrideForControl = %+v, %v; want the earliest (severity)", active, err)
	}
	// The earliest (severity) leaves the failing control failing: score stays 20.
	if got := f.statusScore(t); got == nil || *got != 20 {
		t.Fatalf("status score = %s, want 20", intStr(got))
	}
}

func TestIntegration_FrameworkStatus_GETIsReadOnly(t *testing.T) {
	f := newEvalFixture(t)
	// A signature of every licence row (content, not just count): an INSERT or
	// an UPDATE issued by the GET both change it.
	count := func() string {
		var sig string
		if err := f.db.QueryRow(`SELECT COALESCE(md5(string_agg(row_to_json(l)::text, '|' ORDER BY platform_framework_id)), '')
			FROM tenant_framework_licenses l WHERE tenant_id = $1`, f.tenant).Scan(&sig); err != nil {
			t.Fatalf("licence signature: %v", err)
		}
		return sig
	}
	// Make sure the tenant has no ACTIVE default licence (the repair trigger path).
	if _, err := f.db.Exec(`UPDATE tenant_framework_licenses SET is_default = false WHERE tenant_id = $1`, f.tenant); err != nil {
		t.Fatalf("clear defaults: %v", err)
	}
	before := count()
	st, err := NewEvaluationService(f.db).GetFrameworkStatus(f.tenant)
	if err != nil {
		t.Fatalf("GetFrameworkStatus: %v", err)
	}
	if after := count(); after != before {
		t.Fatalf("GET status changed tenant_framework_licenses rows: %s -> %s", before, after)
	}
	if len(st.Frameworks) == 0 || st.SelectedFramework == nil {
		t.Fatalf("status should still select a framework without a default: %+v", st)
	}
}

func TestIntegration_EvaluateMultipleFrameworks_ErrorEntryAndOrder(t *testing.T) {
	f := newEvalFixture(t)
	missing := uuid.New()
	ids := []uuid.UUID{missing, f.frameworkID, uuid.New()}
	res, err := NewEvaluationService(f.db).EvaluateMultipleFrameworks(f.tenant, ids, nil, models.ScenarioFilters{}, "")
	if err != nil {
		t.Fatalf("EvaluateMultipleFrameworks: %v", err)
	}
	if len(res) != len(ids) {
		t.Fatalf("got %d results for %d frameworks; a failed framework must keep an entry", len(res), len(ids))
	}
	for i, id := range ids {
		if res[i].FrameworkID != id.String() {
			t.Fatalf("result %d is %s, want input order (%s)", i, res[i].FrameworkID, id)
		}
	}
	if res[0].Error == "" || res[2].Error == "" || res[1].Error != "" || res[1].Summary == nil {
		t.Fatalf("error entries wrong: %+v", res)
	}
}

func TestIntegration_Override_CreateAndDeleteEnqueueScopedReconcile(t *testing.T) {
	f := newEvalFixture(t)
	var jobs []ReconcileJob
	ov := NewOverrideService(f.db)
	ov.SetReconcileEnqueuer(&ReconcileEnqueuer{sink: func(j ReconcileJob) { jobs = append(jobs, j) }})

	created, err := ov.CreateOverride(f.tenant, f.user(t), nil, f.critical, models.OverrideTypeDisregard, nil, nil, "r", "platform")
	if err != nil {
		t.Fatalf("CreateOverride: %v", err)
	}
	if len(jobs) != 1 || jobs[0].TenantID != f.tenant.String() || jobs[0].FrameworkID != f.frameworkID.String() {
		t.Fatalf("create should enqueue one reconcile scoped to the control's framework, got %+v", jobs)
	}
	if err := ov.DeleteOverride(f.tenant, created.ID); err != nil {
		t.Fatalf("DeleteOverride: %v", err)
	}
	if len(jobs) != 2 || jobs[1].FrameworkID != f.frameworkID.String() {
		t.Fatalf("delete should enqueue a scoped reconcile too, got %+v", jobs)
	}
}
