package services

// Pure-logic tests for the single framework-scoring model. These run in the PR
// gate (no database), so the arithmetic that the DB-integration tests exercise
// end-to-end is also pinned where every contributor sees it.

import (
	"database/sql"
	"testing"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
)

func TestFrameworkScore_IsSeverityWeightedNotFlat(t *testing.T) {
	// One Critical control failing, one Low control passing. Flat control
	// counting scores this 50; the documented severity-weighted model scores it
	// 20 (Low weight 1 of a total weight of 5). This asymmetry is the whole
	// reason the two former implementations disagreed.
	outcomes := []controlOutcome{
		{BaselineSeverity: "Critical", Status: statusFail},
		{BaselineSeverity: "Low", Status: statusPass},
	}
	score, total, passing, failing := frameworkScore(outcomes)
	if score != 20 {
		t.Fatalf("score = %d, want 20 (severity-weighted); 50 means flat control counting", score)
	}
	if total != 2 || passing != 1 || failing != 1 {
		t.Fatalf("counts = {total:%d passing:%d failing:%d}, want {2 1 1}", total, passing, failing)
	}
}

func TestFrameworkScore_WarnEarnsNoCredit(t *testing.T) {
	// WARN is not a breach (it never reaches KPISummary.FailingControls) but it
	// earns no score weight either — matching the live path's long-standing
	// behaviour, where only PASS accumulated passWeight.
	score, _, passing, failing := frameworkScore([]controlOutcome{
		{BaselineSeverity: "High", Status: statusWarn},
		{BaselineSeverity: "High", Status: statusPass},
	})
	if score != 50 {
		t.Fatalf("score = %d, want 50 (one of two equal-weight controls passing)", score)
	}
	if passing != 1 || failing != 1 {
		t.Fatalf("counts = {passing:%d failing:%d}, want {1 1} — failing is the complement of passing", passing, failing)
	}
}

func TestFrameworkScore_EmptyFrameworkScoresPerfect(t *testing.T) {
	score, total, passing, failing := frameworkScore(nil)
	if score != 100 || total != 0 || passing != 0 || failing != 0 {
		t.Fatalf("got {score:%d total:%d passing:%d failing:%d}, want {100 0 0 0}", score, total, passing, failing)
	}
}

func TestFrameworkScore_AllPassingAndAllFailing(t *testing.T) {
	all := []controlOutcome{
		{BaselineSeverity: "Critical", Status: statusPass},
		{BaselineSeverity: "Med", Status: statusPass},
	}
	if score, _, _, _ := frameworkScore(all); score != 100 {
		t.Fatalf("all passing: score = %d, want 100", score)
	}
	for i := range all {
		all[i].Status = statusFail
	}
	if score, _, _, _ := frameworkScore(all); score != 0 {
		t.Fatalf("all failing: score = %d, want 0", score)
	}
}

func TestStatusForWorstSeverity(t *testing.T) {
	cases := map[string]string{
		"Critical": statusFail,
		"High":     statusFail,
		"Med":      statusWarn,
		"Low":      statusPass,
		"":         statusPass, // no findings
	}
	for severity, want := range cases {
		if got := statusForWorstSeverity(severity); got != want {
			t.Errorf("statusForWorstSeverity(%q) = %q, want %q", severity, got, want)
		}
	}
}

// TestStatusConstantsAreUppercase guards the casing the multi-framework endpoint
// got wrong. ControlSummary.StatusEffective is compared against these values by
// callers outside this package's tests, so the wire form is part of the contract.
func TestStatusConstantsAreUppercase(t *testing.T) {
	for _, s := range []string{statusPass, statusWarn, statusFail} {
		if s != "PASS" && s != "WARN" && s != "FAIL" {
			t.Fatalf("unexpected status constant %q — statuses travel UPPERCASE", s)
		}
	}
}

func TestApplyThresholdOverride(t *testing.T) {
	base := func() models.ControlMeasurement {
		return models.ControlMeasurement{
			Predicate:        map[string]interface{}{"operator": ">=", "value": float64(30)},
			SeverityOverride: "High",
		}
	}

	t.Run("no override leaves the platform measurement alone", func(t *testing.T) {
		m := base()
		applyThresholdOverride(&m, nil, sql.NullString{})
		if m.Predicate["value"] != float64(30) || m.SeverityOverride != "High" {
			t.Fatalf("measurement mutated without an override: %+v", m)
		}
	})

	t.Run("predicate override replaces the platform predicate", func(t *testing.T) {
		m := base()
		applyThresholdOverride(&m, []byte(`{"operator": ">=", "value": 90}`), sql.NullString{})
		if m.Predicate["value"] != float64(90) {
			t.Fatalf("predicate = %+v, want value 90", m.Predicate)
		}
		if m.SeverityOverride != "High" {
			t.Fatalf("severity = %q, want High (a NULL severity must not clear the platform rating)", m.SeverityOverride)
		}
	})

	t.Run("severity override re-rates the violation", func(t *testing.T) {
		m := base()
		applyThresholdOverride(&m, nil, sql.NullString{String: "Low", Valid: true})
		if m.SeverityOverride != "Low" {
			t.Fatalf("severity = %q, want Low", m.SeverityOverride)
		}
	})

	t.Run("empty or malformed predicate is ignored", func(t *testing.T) {
		for name, raw := range map[string][]byte{
			"empty object":  []byte(`{}`),
			"json null":     []byte(`null`),
			"not an object": []byte(`"nonsense"`),
			"invalid json":  []byte(`{`),
		} {
			m := base()
			applyThresholdOverride(&m, raw, sql.NullString{})
			if m.Predicate["value"] != float64(30) {
				t.Errorf("%s: predicate became %+v — an unusable override must leave the "+
					"platform predicate in place, not silently disable the control", name, m.Predicate)
			}
		}
	})
}
