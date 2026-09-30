package server

// Two tools whose platform endpoints answer a well-formed request the tenant's
// edition or state cannot satisfy:
//
//   - vistaplatform_compare_cbom_artifacts — 402 on a Core build. It used to be
//     a bare 404 (the routes were never mounted), which an agent read as "those
//     artifacts do not exist".
//   - vistaplatform_get_compliance_summary — 403 `framework_not_activated` for a
//     published framework the tenant never activated. It used to be a 500.
//
// Both must come back as a structured `available: false` RESULT naming the
// reason, and neither may swallow the platform's OTHER refusals.

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	compareCoreBase         = "0c0c0c0c-0000-4000-8000-000000000001"
	compareMissingBase      = "0c0c0c0c-0000-4000-8000-000000000404"
	compareHead             = "0c0c0c0c-0000-4000-8000-0000000000aa"
	frameworkNotActivated   = "fa0fa0fa-0000-4000-8000-000000000001"
	frameworkForbiddenOther = "fa0fa0fa-0000-4000-8000-000000000002"
	frameworkActive         = "fa0fa0fa-0000-4000-8000-000000000003"
)

type unavailableShape struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
	Message   string `json:"message"`
	Instead   string `json:"instead"`
}

func decodeUnavailable(t *testing.T, text string) unavailableShape {
	t.Helper()
	var got unavailableShape
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("result was not the unavailable shape: %v (%s)", err, text)
	}
	return got
}

func TestCompareToolReportsNotIncludedInYourSubscription(t *testing.T) {
	f := newFixture(t)
	result := callTool(t, f, f.validPAT, "vistaplatform_compare_cbom_artifacts",
		map[string]any{"base_id": compareCoreBase, "head_id": compareHead})

	if result["isError"] == true {
		t.Fatalf("a 402 came back as a tool error; an agent will retry something that cannot succeed: %v", result)
	}
	got := decodeUnavailable(t, toolText(t, result))
	if got.Available {
		t.Error("available is true on a refusal")
	}
	if got.Reason != "edition" {
		t.Errorf("reason = %q, want edition", got.Reason)
	}
	if !strings.Contains(got.Message, "not included in your subscription") {
		t.Errorf("message does not say the capability is not included in the subscription: %q", got.Message)
	}
	if !strings.Contains(got.Message, "not a missing-artifact error") {
		t.Errorf("message does not rule out the missing-artifact reading: %q", got.Message)
	}
	if !strings.Contains(got.Instead, "vistaplatform_get_cbom_artifact") {
		t.Errorf("no working alternative named: %q", got.Instead)
	}
}

// The other polarity: a real 404 (an artifact that does not exist) stays a real
// error, and a successful diff passes through untouched. Otherwise the 402 arm
// would be a catch-all that dresses every failure as an edition question.
func TestCompareToolLeavesOtherOutcomesAlone(t *testing.T) {
	f := newFixture(t)

	missing := callTool(t, f, f.validPAT, "vistaplatform_compare_cbom_artifacts",
		map[string]any{"base_id": compareMissingBase, "head_id": compareHead})
	if missing["isError"] != true {
		t.Fatalf("a genuine 404 must stay a tool error: %v", missing)
	}
	if strings.Contains(toolText(t, missing), "not included in your subscription") {
		t.Errorf("a missing artifact was reported as an edition refusal: %s", toolText(t, missing))
	}

	ok := callTool(t, f, f.validPAT, "vistaplatform_compare_cbom_artifacts",
		map[string]any{"base_id": "0c0c0c0c-0000-4000-8000-000000000002", "head_id": compareHead})
	if ok["isError"] == true {
		t.Fatalf("a successful diff errored: %v", ok)
	}
	if !strings.Contains(toolText(t, ok), "regressions") {
		t.Errorf("the diff did not reach the agent: %s", toolText(t, ok))
	}
}

func TestComplianceSummaryReportsFrameworkNotActivated(t *testing.T) {
	f := newFixture(t)
	result := callTool(t, f, f.validPAT, "vistaplatform_get_compliance_summary",
		map[string]any{"framework_id": frameworkNotActivated})

	if result["isError"] == true {
		t.Fatalf("a not-activated framework came back as a tool error: %v", result)
	}
	got := decodeUnavailable(t, toolText(t, result))
	if got.Available {
		t.Error("available is true on a refusal")
	}
	if got.Reason != "framework_not_activated" {
		t.Errorf("reason = %q, want framework_not_activated", got.Reason)
	}
	if !strings.Contains(got.Message, "framework not activated") {
		t.Errorf("message does not say the framework is not activated: %q", got.Message)
	}
	if !strings.Contains(got.Instead, "vistaplatform_list_compliance_frameworks") {
		t.Errorf("no working alternative named: %q", got.Instead)
	}
}

// A 403 WITHOUT the activation reason is a different refusal (scope-narrowed
// token, missing permission) and must stay a real error — the same polarity
// rule `vistaplatform_ask` follows for its 403.
func TestComplianceSummaryOtherForbiddenStaysAnError(t *testing.T) {
	f := newFixture(t)
	result := callTool(t, f, f.validPAT, "vistaplatform_get_compliance_summary",
		map[string]any{"framework_id": frameworkForbiddenOther})
	if result["isError"] != true {
		t.Fatalf("an unrelated 403 was dressed as an activation answer: %v", result)
	}
	if strings.Contains(toolText(t, result), "not activated") {
		t.Errorf("unrelated 403 text mentions activation: %s", toolText(t, result))
	}

	ok := callTool(t, f, f.validPAT, "vistaplatform_get_compliance_summary",
		map[string]any{"framework_id": frameworkActive})
	if ok["isError"] == true || !strings.Contains(toolText(t, ok), "Best Practices") {
		t.Fatalf("an active framework's summary did not pass through: %v", ok)
	}
}
