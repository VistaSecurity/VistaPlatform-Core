package services

// Database-integration tests for B-43: GetControlDetails reported score 100 and
// zero failing findings for a control that was failing.
//
// The endpoint was missed by the honesty pass and kept its own arithmetic:
//
//   - failingFindingsCount counted only Critical/High/Med, even though every row
//     it iterates is already an ACTIVE, non-SUPPRESSED violation. A control whose
//     violations are all Low counted zero of them.
//   - score was derived as (total - failing) / total, so with failing == 0 it
//     came out 100 — printed next to `status: FAIL` and a full findings array.
//   - status came from calculateControlStatus alone, with no loadControlAssessments
//     call, so a control with no measurements reported PASS/100 here while every
//     other endpoint reported NOT_ASSESSED/nil.
//
// Its live consumers are the MCP tool vistaplatform_get_control_findings — so an
// AI agent reading a tenant's posture was told "clean" — and direct API clients.
//
// Skips unless TEST_DATABASE_URL is set (shared/testdb); `make test-integration-db`.

import (
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
)

// TestIntegration_GetControlDetails_LowSeverityViolationsAreFailing is the
// headline case from the report: the seeded cert-expiry-90-day control on a
// tenant with expiring certificates. Its findings are Low, so the old count
// excluded every one of them.
func TestIntegration_GetControlDetails_LowSeverityViolationsAreFailing(t *testing.T) {
	f := newAuthoringFixture(t, "published")
	seedTenantInventory(t, f.db, f.tenant)

	controlID := f.newControl(t, "CD-1", "Low")
	f.seedMeasurementRow(t, controlID)
	evaluatedAtRollup(t, f.db, f.tenant, f.frameworkID, time.Now())

	const violations = 12
	for i := 0; i < violations; i++ {
		if _, err := f.db.Exec(`
			INSERT INTO compliance_findings
				(id, tenant_id, control_id, asset_id, asset_type, severity, summary, detection_state, workflow_status)
			VALUES ($1, $2, $3, $4, 'certificate', 'Low', 'certificate expires inside 90 days', 'ACTIVE', 'NEW')`,
			uuid.New(), f.tenant, controlID, uuid.New()); err != nil {
			t.Fatalf("seed finding %d: %v", i, err)
		}
	}

	details, err := NewEvaluationService(f.db).GetControlDetails(
		f.tenant, controlID, nil, models.ScenarioFilters{}, 1, 50)
	if err != nil {
		t.Fatalf("GetControlDetails: %v", err)
	}

	if details.Control.Status != statusFail {
		t.Fatalf("status = %q, want FAIL", details.Control.Status)
	}
	if details.EvidenceSummary.FailingFindingsCount != violations {
		t.Fatalf("failing_findings_count = %d, want %d — every visible finding IS a failing "+
			"finding; excluding Low is the severity-decides-the-result mistake #1369 removed",
			details.EvidenceSummary.FailingFindingsCount, violations)
	}
	if details.Control.Score == nil || *details.Control.Score != 0 {
		t.Fatalf("score = %s, want 0 — a control with open violations cannot report a perfect "+
			"score beside status FAIL and a %d-item findings array", scoreStr(details.Control.Score), violations)
	}
	if len(details.Findings) != violations {
		t.Fatalf("findings array has %d entries, want %d", len(details.Findings), violations)
	}
	if details.EvidenceSummary.AffectedAssetsCount != violations {
		t.Fatalf("affected_assets_count = %d, want %d",
			details.EvidenceSummary.AffectedAssetsCount, violations)
	}
}

// TestIntegration_GetControlDetails_CleanControlScores100 is the other polarity:
// an evaluated control with nothing against it is a genuine pass, and must not be
// dragged to 0 by an over-eager fix.
func TestIntegration_GetControlDetails_CleanControlScores100(t *testing.T) {
	f := newAuthoringFixture(t, "published")
	seedTenantInventory(t, f.db, f.tenant)

	controlID := f.newControl(t, "CD-2", "High")
	f.seedMeasurementRow(t, controlID)
	evaluatedAtRollup(t, f.db, f.tenant, f.frameworkID, time.Now())

	details, err := NewEvaluationService(f.db).GetControlDetails(
		f.tenant, controlID, nil, models.ScenarioFilters{}, 1, 50)
	if err != nil {
		t.Fatalf("GetControlDetails: %v", err)
	}
	if details.Control.Status != statusPass {
		t.Fatalf("status = %q, want PASS", details.Control.Status)
	}
	if details.Control.Score == nil || *details.Control.Score != 100 {
		t.Fatalf("score = %s, want 100", scoreStr(details.Control.Score))
	}
	if details.EvidenceSummary.FailingFindingsCount != 0 {
		t.Fatalf("failing_findings_count = %d, want 0", details.EvidenceSummary.FailingFindingsCount)
	}
	if details.Control.NotAssessedReason != "" {
		t.Fatalf("not_assessed_reason = %q, want empty on a PASS", details.Control.NotAssessedReason)
	}
}

// TestIntegration_GetControlDetails_NoMeasurementsIsNotAssessed pins the
// agreement with every other endpoint. A control nobody wrote a rule for reported
// PASS/100 here — the loudest possible way of saying "we did not look" — while
// /summary, the posture grid and the rollup all said NOT_ASSESSED.
func TestIntegration_GetControlDetails_NoMeasurementsIsNotAssessed(t *testing.T) {
	f := newAuthoringFixture(t, "published")
	seedTenantInventory(t, f.db, f.tenant)

	// Deliberately no measurement row.
	controlID := f.newControl(t, "CD-3", "Critical")
	evaluatedAtRollup(t, f.db, f.tenant, f.frameworkID, time.Now())

	details, err := NewEvaluationService(f.db).GetControlDetails(
		f.tenant, controlID, nil, models.ScenarioFilters{}, 1, 50)
	if err != nil {
		t.Fatalf("GetControlDetails: %v", err)
	}
	if details.Control.Status != statusNotAssessed {
		t.Fatalf("status = %q, want NOT_ASSESSED for a control with no measurement rule",
			details.Control.Status)
	}
	if details.Control.Score != nil {
		t.Fatalf("score = %v, want nil (renders \"—\") — a sentinel integer here is read as a "+
			"posture claim about a check that never ran", *details.Control.Score)
	}
	if details.Control.NotAssessedReason != reasonNoMeasurements {
		t.Fatalf("not_assessed_reason = %q, want %q",
			details.Control.NotAssessedReason, reasonNoMeasurements)
	}

	// And it must agree with the endpoint the UI uses for the same control.
	summary, err := NewEvaluationService(f.db).EvaluateFramework(
		f.tenant, f.frameworkID, "1.0", models.ScenarioFilters{}, nil)
	if err != nil {
		t.Fatalf("EvaluateFramework: %v", err)
	}
	for _, c := range summary.Controls {
		if c.ID != controlID.String() {
			continue
		}
		if c.StatusEffective != details.Control.Status {
			t.Fatalf("EvaluateFramework says %q but GetControlDetails says %q for the same control — "+
				"two endpoints disagreeing about one control is the whole defect",
				c.StatusEffective, details.Control.Status)
		}
	}
}

// scoreStr renders a *int score the way the UI does, so a failure message says
// "100" or "—" rather than a pointer address.
func scoreStr(score *int) string {
	if score == nil {
		return "—"
	}
	return strconv.Itoa(*score)
}
