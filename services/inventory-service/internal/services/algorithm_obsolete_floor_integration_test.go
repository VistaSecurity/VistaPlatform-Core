package services

// Decision 12 end to end on the grading side: deprecating an algorithm moves
// the catalogue risk of every crypto configuration that uses it into the
// Critical band — which is what "will grade as Critical" means to a tenant —
// and re-activating it moves them back. Skips without TEST_DATABASE_URL.

import (
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/riskbands"
)

func TestIntegration_ObsoleteFloor_MovesConfigurationGradeAndBack(t *testing.T) {
	f := newCatRiskFixture(t)
	svc := NewAlgorithmService(f.db)
	code := "RC38-GRADE-" + uuid.NewString()
	t.Cleanup(func() { _, _ = f.db.Exec(`DELETE FROM algorithms WHERE code = $1`, code) })
	if _, err := svc.CreateAlgorithm(AlgorithmCreate{
		Code: code, Name: "RC-38 grading fixture", Category: "hash", RiskScore: algorithmServiceIntPtr(45),
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	impl := f.implWith(t, map[string]string{"hash": code})

	if got, _, _ := f.score(t, impl); riskbands.GetRiskLevel(got) != "Medium" {
		t.Fatalf("baseline grade = %s (%d), want Medium", riskbands.GetRiskLevel(got), got)
	}

	updated, outcome, err := svc.UpdateAlgorithmAssessment(code, AlgorithmAssessmentUpdate{DeprecationStatus: obsoletePtr("obsolete")})
	if err != nil || updated == nil {
		t.Fatalf("deprecate: %v", err)
	}
	if outcome.ObsoleteTransition != ObsoleteTransitionEntered || outcome.RememberedRiskScore == nil || *outcome.RememberedRiskScore != 45 {
		t.Fatalf("outcome = %+v, want entered with 45 remembered", outcome)
	}
	if got, _, _ := f.score(t, impl); riskbands.GetRiskLevel(got) != "Critical" {
		t.Fatalf("a configuration using an obsolete algorithm grades %s (%d), want Critical", riskbands.GetRiskLevel(got), got)
	}

	if _, _, err := svc.UpdateAlgorithmAssessment(code, AlgorithmAssessmentUpdate{DeprecationStatus: obsoletePtr("current")}); err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if got, _, _ := f.score(t, impl); got != 45 {
		t.Fatalf("after reactivate the configuration scores %d, want the restored 45", got)
	}

	// Creating straight into obsolete follows the same rule.
	code2 := "RC38-CREATE-" + uuid.NewString()
	t.Cleanup(func() { _, _ = f.db.Exec(`DELETE FROM algorithms WHERE code = $1`, code2) })
	created, err := svc.CreateAlgorithm(AlgorithmCreate{
		Code: code2, Name: "RC-38 create fixture", Category: "hash",
		RiskScore: algorithmServiceIntPtr(10), DeprecationStatus: obsoletePtr("obsolete"),
	})
	if err != nil {
		t.Fatalf("create obsolete: %v", err)
	}
	if created.RiskScore == nil || *created.RiskScore != ObsoleteRiskFloor() {
		t.Fatalf("created-obsolete risk = %v, want the floor %d", created.RiskScore, ObsoleteRiskFloor())
	}
	if _, _, err := svc.UpdateAlgorithmAssessment(code2, AlgorithmAssessmentUpdate{DeprecationStatus: obsoletePtr("deprecated")}); err != nil {
		t.Fatalf("reactivate created: %v", err)
	}
	after, err := svc.GetAlgorithmByCode(code2)
	if err != nil || after == nil || after.RiskScore == nil || *after.RiskScore != 10 {
		t.Fatalf("reactivated created-obsolete risk = %+v, want 10", after)
	}
}
