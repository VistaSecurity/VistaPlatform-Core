package services

// A published framework the tenant has not activated must come back from
// EvaluateFramework as the TYPED ErrFrameworkNotLicensed, not as an anonymous
// fmt.Errorf. The /summary handler maps the typed error to a clear 403; an
// anonymous one fell through to a 500 "Failed to evaluate framework" — which is
// what the MCP compliance-summary tool reported for a framework listed as
// available but never activated.
//
// Skips unless TEST_DATABASE_URL is set (see shared/testdb).

import (
	"errors"
	"testing"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_EvaluateFramework_NotActivatedIsTyped(t *testing.T) {
	f := newEvalFixture(t) // its tenant IS licensed; use it for the positive polarity
	svc := NewEvaluationService(f.db)

	if _, err := svc.EvaluateFramework(f.tenant, f.frameworkID, "1.0", models.ScenarioFilters{}, nil); err != nil {
		t.Fatalf("licensed tenant must evaluate: %v", err)
	}

	// A second tenant that never activated the same published framework.
	other := testdb.NewTenant(t, f.db.DB)
	_, err := svc.EvaluateFramework(other, f.frameworkID, "1.0", models.ScenarioFilters{}, nil)
	if err == nil {
		t.Fatal("an unlicensed tenant evaluated a platform framework it never activated")
	}
	if !errors.Is(err, ErrFrameworkNotLicensed) {
		t.Fatalf("err = %v; want errors.Is ErrFrameworkNotLicensed (an untyped error reaches the client as a 500)", err)
	}
	if errors.Is(err, ErrFrameworkNotFound) {
		t.Fatal("a real but unactivated framework must not read as 'not found'")
	}
}
