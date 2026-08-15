package services

// Pure-logic tests for the single framework-scoring model. These run in the PR
// gate (no database), so the arithmetic that the DB-integration tests exercise
// end-to-end is also pinned where every contributor sees it.

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"
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
	b := frameworkScore(outcomes)
	if b.Score == nil {
		t.Fatal("score = nil, want 20 — both controls were assessed")
	}
	if *b.Score != 20 {
		t.Fatalf("score = %d, want 20 (severity-weighted); 50 means flat control counting", *b.Score)
	}
	if b.Total != 2 || b.Passing != 1 || b.Failing != 1 || b.NotAssessed != 0 {
		t.Fatalf("counts = %+v, want {total:2 passing:1 failing:1 notAssessed:0}", b)
	}
}

// TestFrameworkScore_LowSeverityViolationDragsTheScore is the headline
// regression. Before the fix a violated Low-baseline control mapped to
// PASS, so cert-expiry-90-day reported "score 100, 1/1 controls passing" while
// carrying two ACTIVE findings.
func TestFrameworkScore_LowSeverityViolationDragsTheScore(t *testing.T) {
	b := frameworkScore([]controlOutcome{
		{BaselineSeverity: "Critical", Status: statusPass},
		{BaselineSeverity: "Low", Status: statusFail},
	})
	// Critical passing (weight 4) of a total weight of 5 → 80.
	if b.Score == nil {
		t.Fatal("score = nil, want 80 — both controls were assessed")
	}
	if *b.Score != 80 {
		t.Fatalf("score = %d, want 80; 100 means a Low violation is still invisible to scoring", *b.Score)
	}
	if b.Failing != 1 {
		t.Fatalf("failing = %d, want 1 — a Low-severity violation is still a violation", b.Failing)
	}
}

// TestFrameworkScore_NotAssessedIsExcludedFromBothSides pins D3: not-assessed
// controls leave the fraction entirely rather than being counted as passes
// (which inflates) or failures (which punishes an empty inventory).
func TestFrameworkScore_NotAssessedIsExcludedFromBothSides(t *testing.T) {
	b := frameworkScore([]controlOutcome{
		{BaselineSeverity: "Critical", Status: statusPass},
		{BaselineSeverity: "Critical", Status: statusFail},
		{BaselineSeverity: "Critical", Status: statusNotAssessed},
	})
	// One of two ASSESSED equal-weight controls passing → 50. Counting the
	// not-assessed control as a pass gives 67; as a failure, 33.
	if b.Score == nil {
		t.Fatal("score = nil, want 50 — two of the three controls were assessed")
	}
	if *b.Score != 50 {
		t.Fatalf("score = %d, want 50 (assessed subset only); 67 counts not-assessed as passing, 33 as failing", *b.Score)
	}
	if b.Total != 3 || b.Passing != 1 || b.Failing != 1 || b.NotAssessed != 1 {
		t.Fatalf("counts = %+v, want {total:3 passing:1 failing:1 notAssessed:1}", b)
	}
	if b.Passing+b.Failing+b.NotAssessed != b.Total {
		t.Fatalf("counts must partition the framework: %+v", b)
	}
}

// TestFrameworkScore_ZeroAssessedHasNoScore pins the loudest half of: a
// framework where nothing could be evaluated reports NO score. Returning 100
// said "perfectly compliant" when it meant "we did not look"; returning 0 would
// say "totally non-compliant", which is equally invented.
func TestFrameworkScore_ZeroAssessedHasNoScore(t *testing.T) {
	for name, outcomes := range map[string][]controlOutcome{
		"no controls at all": nil,
		"every control not assessed": {
			{BaselineSeverity: "Critical", Status: statusNotAssessed},
			{BaselineSeverity: "Low", Status: statusNotAssessed},
		},
	} {
		b := frameworkScore(outcomes)
		if b.Score != nil {
			t.Errorf("%s: score = %d, want no score (nil) — the UI renders '—'", name, *b.Score)
		}
		if b.NotAssessed != len(outcomes) || b.Total != len(outcomes) {
			t.Errorf("%s: counts = %+v, want all %d controls not assessed", name, b, len(outcomes))
		}
	}
}

// TestFrameworkScore_CoverageWorkedExample pins the exact figure the customer
// docs publish: 11 controls, 8 assessed (2 Critical + 3 High + 2 Med + 1 Low =
// weight 22), one High failing → 19/22 = 86%, shown with "8 of 11 controls
// assessed". If this test moves, the published docs are wrong too.
func TestFrameworkScore_CoverageWorkedExample(t *testing.T) {
	var outcomes []controlOutcome
	add := func(n int, severity, status string) {
		for i := 0; i < n; i++ {
			outcomes = append(outcomes, controlOutcome{BaselineSeverity: severity, Status: status})
		}
	}
	add(2, "Critical", statusPass) // weight 4 each
	add(1, "High", statusFail)     // weight 3 — the one failure
	add(2, "High", statusPass)     // weight 3 each
	add(2, "Med", statusPass)      // weight 2 each
	add(1, "Low", statusPass)      // weight 1
	add(3, "High", statusNotAssessed)

	b := frameworkScore(outcomes)
	if b.Score == nil {
		t.Fatal("score = nil, want 86 — eight controls were assessed")
	}
	if *b.Score != 86 {
		t.Fatalf("score = %d, want 86 (19 of 22 assessed weight)", *b.Score)
	}
	if b.Total != 11 || b.Passing+b.Failing != 8 || b.NotAssessed != 3 {
		t.Fatalf("counts = %+v, want 11 total, 8 assessed, 3 not assessed", b)
	}
}

func TestFrameworkScore_AllPassingAndAllFailing(t *testing.T) {
	all := []controlOutcome{
		{BaselineSeverity: "Critical", Status: statusPass},
		{BaselineSeverity: "Med", Status: statusPass},
	}
	if b := frameworkScore(all); b.Score == nil || *b.Score != 100 {
		t.Fatalf("all passing: score = %v, want 100", b.Score)
	}
	for i := range all {
		all[i].Status = statusFail
	}
	if b := frameworkScore(all); b.Score == nil || *b.Score != 0 {
		t.Fatalf("all failing: score = %v, want 0", b.Score)
	}
}

func TestStatusForFindings(t *testing.T) {
	if got := statusForFindings(true); got != statusFail {
		t.Errorf("statusForFindings(true) = %q, want %q", got, statusFail)
	}
	if got := statusForFindings(false); got != statusPass {
		t.Errorf("statusForFindings(false) = %q, want %q", got, statusPass)
	}
}

// TestStatusConstantsAreUppercase guards the casing the multi-framework endpoint
// got wrong. ControlSummary.StatusEffective is compared against these values by
// callers outside this package's tests, so the wire form is part of the contract.
func TestStatusConstantsAreUppercase(t *testing.T) {
	for _, s := range []string{statusPass, statusFail, statusNotAssessed} {
		if s != "PASS" && s != "FAIL" && s != "NOT_ASSESSED" {
			t.Fatalf("unexpected status constant %q — statuses travel UPPERCASE", s)
		}
	}
}

// TestNotAssessedReasonsAreDistinct guards the machine-readable reason values
// the UI switches on to pick its hover sentence.
func TestNotAssessedReasonsAreDistinct(t *testing.T) {
	want := map[string]bool{"no_measurements": true, "nothing_in_scope": true, "check_error": true}
	got := map[string]bool{reasonNoMeasurements: true, reasonNothingInScope: true, reasonCheckError: true}
	if len(got) != 3 {
		t.Fatalf("reasons collide: %v", got)
	}
	for r := range got {
		if !want[r] {
			t.Errorf("unexpected reason value %q — the frontend switches on these strings", r)
		}
	}
}

// TestOutcomesFromAssessments_UnknownControlIsNotAPass pins the other half of the
// old default: loadControlStatuses seeded every control statusPass, so a control
// missing from the assessment map silently earned score weight.
func TestOutcomesFromAssessments_UnknownControlIsNotAPass(t *testing.T) {
	type ctrl struct {
		id       uuid.UUID
		severity string
	}
	// A deliberately empty assessment map — nothing is known about the control.
	outcomes := outcomesFromAssessments([]ctrl{{uuid.New(), "Critical"}},
		func(c ctrl) uuid.UUID { return c.id },
		func(c ctrl) string { return c.severity },
		nil)
	if len(outcomes) != 1 || outcomes[0].Status != statusNotAssessed {
		t.Fatalf("unknown control produced %+v, want NOT_ASSESSED — defaulting to PASS is the bug", outcomes)
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
