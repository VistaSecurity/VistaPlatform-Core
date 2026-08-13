package services

// Database-integration tests for QA-reported framework-metadata defects
// (v0.5.7 live UI QA):
//
//  - H-3: GetAvailableFrameworks returned controls_count: 0 for every framework
//    because its query never joined platform_framework_controls, unlike the
//    sibling ListPublishedFrameworksWithLicense/ViewFramework queries.
//  - H-4 / M-15: an unactivated framework's preview score (tenant_framework_scores)
//    can legitimately read controls_failing: 0 while /findings/by-control shows
//    real open findings, because the severity-weighted scoring model
//    (statusForWorstSeverity) counts a control whose worst finding is Low
//    severity as passing. GetAvailableFrameworks now also reports
//    open_findings_controls — the raw "has any open finding" count — so the UI
//    is never handed a number that contradicts /findings/by-control.
//  - M-6: /frameworks/context's controls_failing undercounts against
//    /findings/by-control for the same severity-collapse reason. It now also
//    reports open_findings_controls per framework.
//
// They skip unless TEST_DATABASE_URL is set (see shared/testdb): CI runs them in
// the nightly backend job; locally use `make test-integration-db`.

import (
	"testing"

	"github.com/google/uuid"
)

// seedLowFinding puts one ACTIVE Low-severity finding on the fixture's Low-baseline
// control — the shape that scores as "passing" under statusForWorstSeverity even
// though a real finding exists.
func (f *evalFixture) seedLowFinding(t *testing.T) {
	t.Helper()
	if _, err := f.db.Exec(`
		INSERT INTO compliance_findings
			(id, tenant_id, control_id, asset_id, asset_type, severity, summary, detection_state, workflow_status)
		VALUES ($1, $2, $3, $4, 'certificate', 'Low', 'cert expires within 90 days', 'ACTIVE', 'NEW')`,
		uuid.New(), f.tenant, f.low, uuid.New()); err != nil {
		t.Fatalf("seed low-severity finding: %v", err)
	}
}

// TestIntegration_GetAvailableFrameworks_ControlsCount pins H-3: the available-
// frameworks list must report the framework's real control count, matching what
// ViewFramework/ListPublishedFrameworksWithLicense already return.
func TestIntegration_GetAvailableFrameworks_ControlsCount(t *testing.T) {
	f := newEvalFixture(t)

	svc := NewFrameworkLicenseService(f.db)
	available, err := svc.GetAvailableFrameworks(f.tenant)
	if err != nil {
		t.Fatalf("GetAvailableFrameworks: %v", err)
	}

	var found bool
	for _, entry := range available {
		if entry.PlatformFramework == nil || entry.PlatformFramework.ID != f.frameworkID {
			continue
		}
		found = true
		if entry.PlatformFramework.ControlsCount != 2 {
			t.Fatalf("controls_count = %d, want 2 (the fixture's Critical + Low controls) — "+
				"0 means the query is missing the platform_framework_controls join",
				entry.PlatformFramework.ControlsCount)
		}
	}
	if !found {
		t.Fatalf("fixture framework %s not present in GetAvailableFrameworks result", f.frameworkID)
	}
}

// TestIntegration_GetAvailableFrameworks_OpenFindingsControls pins H-4/M-15: a
// framework whose only open finding is Low severity scores controls_failing: 0
// (statusForWorstSeverity treats Low as passing), but open_findings_controls must
// still report 1 so the preview card never contradicts /findings/by-control.
func TestIntegration_GetAvailableFrameworks_OpenFindingsControls(t *testing.T) {
	f := newEvalFixture(t)
	f.seedLowFinding(t)

	// Materialize the rollup the same way the reconcile engine would.
	findings := &FindingsService{db: f.db}
	if err := findings.recomputeFrameworkScore(t.Context(), f.tenant, f.frameworkID, f.controls); err != nil {
		t.Fatalf("recomputeFrameworkScore: %v", err)
	}

	svc := NewFrameworkLicenseService(f.db)
	available, err := svc.GetAvailableFrameworks(f.tenant)
	if err != nil {
		t.Fatalf("GetAvailableFrameworks: %v", err)
	}

	var entry *struct {
		ControlsFailing      *int
		OpenFindingsControls *int
	}
	for _, e := range available {
		if e.PlatformFramework == nil || e.PlatformFramework.ID != f.frameworkID {
			continue
		}
		entry = &struct {
			ControlsFailing      *int
			OpenFindingsControls *int
		}{e.ControlsFailing, e.OpenFindingsControls}
	}
	if entry == nil {
		t.Fatalf("fixture framework %s not present in GetAvailableFrameworks result", f.frameworkID)
	}
	if entry.ControlsFailing == nil || *entry.ControlsFailing != 0 {
		t.Fatalf("controls_failing = %v, want 0 (Low-severity-only findings score as passing)", entry.ControlsFailing)
	}
	if entry.OpenFindingsControls == nil || *entry.OpenFindingsControls != 1 {
		t.Fatalf("open_findings_controls = %v, want 1 — the Low-severity finding is a real open "+
			"exposure even though it doesn't move controls_failing", entry.OpenFindingsControls)
	}
}

// TestIntegration_FrameworkContext_OpenFindingsControls pins M-6: the posture
// scorecard (/frameworks/context) must expose the same raw "has an open finding"
// count as /findings/by-control, alongside the severity-weighted controls_failing
// that can read lower.
func TestIntegration_FrameworkContext_OpenFindingsControls(t *testing.T) {
	f := newEvalFixture(t)
	f.seedLowFinding(t)

	licenseSvc := NewFrameworkLicenseService(f.db)
	evalSvc := NewEvaluationService(f.db)
	ctxSvc := NewFrameworkContextService(f.db, licenseSvc, evalSvc)

	resp, err := ctxSvc.GetFrameworkContext(f.tenant, uuid.Nil)
	if err != nil {
		t.Fatalf("GetFrameworkContext: %v", err)
	}
	if resp.Status == nil {
		t.Fatalf("response.Status is nil")
	}

	var item *FrameworkStatusItem
	for i := range resp.Status.Frameworks {
		if resp.Status.Frameworks[i].ID == f.frameworkID.String() {
			item = &resp.Status.Frameworks[i]
		}
	}
	if item == nil {
		t.Fatalf("fixture framework %s not present in /frameworks/context result", f.frameworkID)
	}
	if item.ControlsFailing != 0 {
		t.Fatalf("controls_failing = %d, want 0 (Low-severity-only findings score as passing)", item.ControlsFailing)
	}
	if item.OpenFindingsControls != 1 {
		t.Fatalf("open_findings_controls = %d, want 1 — the Low-severity finding is a real open "+
			"exposure that /findings/by-control would also list", item.OpenFindingsControls)
	}
}
