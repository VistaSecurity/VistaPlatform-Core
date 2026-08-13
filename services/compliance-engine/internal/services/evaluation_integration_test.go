package services

// Database-integration tests for framework-level evaluation arithmetic.
//
// Both defects pinned here are invisible without a real framework fixture:
//
//  1. EvaluateMultipleFrameworks counted controls by comparing
//     ControlSummary.StatusEffective (always UPPERCASE, from
//     calculateControlStatus/applyOverrides) against lowercase literals, so the
//     aggregate passing/failing counters were structurally always 0/0.
//  2. The materialized rollup (tenant_framework_scores) scored a framework by
//     flat control count while the live path scored it severity-weighted, so the
//     same tenant+framework showed two different numbers depending on which
//     path served the page.
//
// The fixture is deliberately asymmetric — one Critical control failing, one Low
// control passing — because that is the only shape where flat and weighted
// scoring differ. Under flat counting it scores 50; weighted (Critical=4x,
// Low=1x, per CLAUDE.md) it scores 20.
//
// They skip unless TEST_DATABASE_URL is set (see shared/testdb): CI runs them in
// the nightly backend job; locally use `make test-integration-db`.

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// evalFixture is a published platform framework with two controls of different
// baseline severity, licensed to a throwaway tenant.
type evalFixture struct {
	db          *sqlx.DB
	tenant      uuid.UUID
	frameworkID uuid.UUID
	critical    uuid.UUID // baseline_severity = Critical
	low         uuid.UUID // baseline_severity = Low
	controls    []models.Control
}

func newEvalFixture(t *testing.T) *evalFixture {
	t.Helper()
	raw := testdb.Connect(t) // skips if TEST_DATABASE_URL unset
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	// platform_frameworks.created_by FKs to platform_users, which FKs to
	// platform_roles. The integration database is schema-only (no seed), so mint
	// the whole chain rather than assuming a seeded admin exists.
	roleID, userID := uuid.New(), uuid.New()
	suffix := roleID.String()[:8]
	if _, err := db.Exec(`INSERT INTO platform_roles (id, name, display_name) VALUES ($1, $2, $3)`,
		roleID, "it-role-"+suffix, "IT Role"); err != nil {
		t.Fatalf("seed platform role: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_roles WHERE id = $1`, roleID) })
	if _, err := db.Exec(`
		INSERT INTO platform_users (id, email, password_hash, first_name, last_name, role_id)
		VALUES ($1, $2, 'x', 'IT', 'User', $3)`,
		userID, "it-"+suffix+"@example.test", roleID); err != nil {
		t.Fatalf("seed platform user: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_users WHERE id = $1`, userID) })

	frameworkID := uuid.New()
	// organization is set (not left NULL) because models.PlatformFramework.Organization
	// is a plain string, not sql.NullString — scanning a NULL organization column fails
	// with "converting NULL to string is unsupported" wherever it's selected (e.g.
	// GetAvailableFrameworks), and the fixture should exercise the same shape real rows
	// have rather than a shape that happens to dodge that.
	if _, err := db.Exec(`
		INSERT INTO platform_frameworks (id, code, name, version, description, organization, status, created_by)
		VALUES ($1, $2, 'IT Framework', '1.0', 'integration fixture', 'IT Org', 'published', $3)`,
		frameworkID, "it-fw-"+suffix, userID); err != nil {
		t.Fatalf("seed framework: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_frameworks WHERE id = $1`, frameworkID) })

	critical, low := uuid.New(), uuid.New()
	for _, c := range []struct {
		id       uuid.UUID
		code     string
		severity string
	}{
		{critical, "IT-1", "Critical"},
		{low, "IT-2", "Low"},
	} {
		if _, err := db.Exec(`
			INSERT INTO platform_framework_controls (id, framework_id, control_id, title, description, baseline_severity, crypto_relevant)
			VALUES ($1, $2, $3, $4, 'integration fixture control', $5, true)`,
			c.id, frameworkID, c.code, "Control "+c.code, c.severity); err != nil {
			t.Fatalf("seed control %s: %v", c.code, err)
		}
	}

	if _, err := db.Exec(`
		INSERT INTO tenant_framework_licenses (tenant_id, platform_framework_id, subscription_status)
		VALUES ($1, $2, 'active')`, tenant, frameworkID); err != nil {
		t.Fatalf("seed license: %v", err)
	}

	f := &evalFixture{db: db, tenant: tenant, frameworkID: frameworkID, critical: critical, low: low}
	svc := NewEvaluationService(db)
	controls, err := svc.getControlsForFramework(frameworkID, models.ScenarioFilters{}, "platform")
	if err != nil {
		t.Fatalf("load fixture controls: %v", err)
	}
	if len(controls) != 2 {
		t.Fatalf("fixture: expected 2 controls, got %d", len(controls))
	}
	f.controls = controls
	return f
}

// failCritical puts one ACTIVE Critical finding on the Critical-baseline control,
// leaving the Low-baseline control clean.
func (f *evalFixture) failCritical(t *testing.T) {
	t.Helper()
	_, err := f.db.Exec(`
		INSERT INTO compliance_findings
			(id, tenant_id, control_id, asset_id, asset_type, severity, summary, detection_state, workflow_status)
		VALUES ($1, $2, $3, $4, 'certificate', 'Critical', 'RSA-2048 in a PQC-required scope', 'ACTIVE', 'NEW')`,
		uuid.New(), f.tenant, f.critical, uuid.New())
	if err != nil {
		t.Fatalf("seed finding: %v", err)
	}
}

// TestIntegration_EvaluateMultipleFrameworks_CountsControls pins defect (2): the
// aggregate control counters returned to the multi-framework endpoint.
func TestIntegration_EvaluateMultipleFrameworks_CountsControls(t *testing.T) {
	f := newEvalFixture(t)
	f.failCritical(t)

	svc := NewEvaluationService(f.db)
	results, err := svc.EvaluateMultipleFrameworks(
		f.tenant, []uuid.UUID{f.frameworkID}, nil, models.ScenarioFilters{}, "")
	if err != nil {
		t.Fatalf("EvaluateMultipleFrameworks: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 framework result, got %d", len(results))
	}
	got := results[0].Controls
	if got.Total != 2 {
		t.Fatalf("Controls.Total = %d, want 2", got.Total)
	}
	if got.Passing != 1 || got.Failing != 1 {
		t.Fatalf("Controls = {passing:%d failing:%d}, want {passing:1 failing:1}; "+
			"0/0 means the status comparison used the wrong case (statuses are UPPERCASE)",
			got.Passing, got.Failing)
	}
}

// TestIntegration_FrameworkScore_MaterializedMatchesLive pins defect (3): the
// materialized rollup and the live evaluation must report the SAME score for the
// same tenant+framework. Weighted is the documented model (CLAUDE.md), so the
// expected value is the weighted one.
func TestIntegration_FrameworkScore_MaterializedMatchesLive(t *testing.T) {
	f := newEvalFixture(t)
	f.failCritical(t)

	evalSvc := NewEvaluationService(f.db)
	summary, err := evalSvc.EvaluateFramework(f.tenant, f.frameworkID, "1.0", models.ScenarioFilters{}, nil)
	if err != nil {
		t.Fatalf("EvaluateFramework: %v", err)
	}
	live := summary.KPIs.Score

	findings := &FindingsService{db: f.db}
	if err := findings.recomputeFrameworkScore(context.Background(), f.tenant, f.frameworkID, f.controls); err != nil {
		t.Fatalf("recomputeFrameworkScore: %v", err)
	}
	var materialized, total, passing, failing int
	if err := f.db.QueryRow(`
		SELECT score, controls_total, controls_passing, controls_failing
		FROM tenant_framework_scores WHERE tenant_id = $1 AND platform_framework_id = $2`,
		f.tenant, f.frameworkID).Scan(&materialized, &total, &passing, &failing); err != nil {
		t.Fatalf("read rollup: %v", err)
	}

	// Critical control failing (weight 4), Low control passing (weight 1):
	// weighted = 1*100/5 = 20. Flat control count would say 1*100/2 = 50.
	const wantWeighted = 20
	if live != wantWeighted {
		t.Fatalf("live score = %d, want %d (severity-weighted)", live, wantWeighted)
	}
	if materialized != live {
		t.Fatalf("materialized rollup score = %d but live evaluation score = %d — "+
			"the same tenant+framework shows two different numbers depending on which path served the page",
			materialized, live)
	}
	if total != 2 || passing != 1 || failing != 1 {
		t.Fatalf("rollup counts = {total:%d passing:%d failing:%d}, want {2 1 1}", total, passing, failing)
	}
}

// TestIntegration_EvaluateAsset_RollupForFullyPassingFramework pins the baseline
// preview-score gap: a framework the tenant fully passes produces no findings, so
// the old affected-only rollup refresh never wrote its tenant_framework_scores row
// and its card showed "—" instead of a preview score. EvaluateAsset must upsert a
// rollup for EVERY published framework, including one with zero findings.
func TestIntegration_EvaluateAsset_RollupForFullyPassingFramework(t *testing.T) {
	f := newEvalFixture(t)

	extractor := NewMeasurementExtractor(f.db)
	evaluator := NewRuleEvaluator(f.db, extractor)
	findings := NewFindingsService(f.db, f.db, evaluator, nil, NewEvaluationService(f.db, evaluator), nil)

	// An asset with no crypto measurements: nothing violates, no finding is written,
	// so under affected-only refresh this framework's rollup would never appear.
	if _, err := findings.EvaluateAsset(context.Background(), f.tenant, uuid.New()); err != nil {
		t.Fatalf("EvaluateAsset: %v", err)
	}

	var score, failing int
	err := f.db.QueryRow(`
		SELECT score, controls_failing
		FROM tenant_framework_scores WHERE tenant_id = $1 AND platform_framework_id = $2`,
		f.tenant, f.frameworkID).Scan(&score, &failing)
	if err != nil {
		t.Fatalf("read rollup: %v — a fully-passing framework must still get a rollup row", err)
	}
	if score != 100 || failing != 0 {
		t.Fatalf("rollup = {score:%d failing:%d}, want {100 0} for a framework with no findings", score, failing)
	}
}

// TestIntegration_FrameworkScore_SuppressedFindingsIgnored pins the other half of
// the divergence: the live path filters SUPPRESSED findings out of a control's
// evidence, so the rollup must too, or a suppressed violation still drags the
// materialized score down.
func TestIntegration_FrameworkScore_SuppressedFindingsIgnored(t *testing.T) {
	f := newEvalFixture(t)
	if _, err := f.db.Exec(`
		INSERT INTO compliance_findings
			(id, tenant_id, control_id, asset_id, asset_type, severity, summary, detection_state, workflow_status)
		VALUES ($1, $2, $3, $4, 'certificate', 'Critical', 'accepted risk', 'ACTIVE', 'SUPPRESSED')`,
		uuid.New(), f.tenant, f.critical, uuid.New()); err != nil {
		t.Fatalf("seed suppressed finding: %v", err)
	}

	evalSvc := NewEvaluationService(f.db)
	summary, err := evalSvc.EvaluateFramework(f.tenant, f.frameworkID, "1.0", models.ScenarioFilters{}, nil)
	if err != nil {
		t.Fatalf("EvaluateFramework: %v", err)
	}
	findings := &FindingsService{db: f.db}
	if err := findings.recomputeFrameworkScore(context.Background(), f.tenant, f.frameworkID, f.controls); err != nil {
		t.Fatalf("recomputeFrameworkScore: %v", err)
	}
	var materialized int
	if err := f.db.QueryRow(`
		SELECT score FROM tenant_framework_scores WHERE tenant_id = $1 AND platform_framework_id = $2`,
		f.tenant, f.frameworkID).Scan(&materialized); err != nil {
		t.Fatalf("read rollup: %v", err)
	}
	if summary.KPIs.Score != 100 {
		t.Fatalf("live score = %d, want 100 (the only finding is SUPPRESSED)", summary.KPIs.Score)
	}
	if materialized != 100 {
		t.Fatalf("materialized score = %d, want 100 — a SUPPRESSED finding must not count against the rollup", materialized)
	}
}
