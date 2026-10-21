package services

// Structural guards for the population probes behind fact 3 of
// loadControlAssessments.
//
// The stored score can only be as honest as these probes, and both failure
// directions are real and silent:
//
//   - a probe LOOSER than the extraction reports PASS over a population the
//     live evaluator finds empty. That is the bug these replace: one probe per
//     SHAPE asked "did the hygiene producer assess any asset" for IH-008 and
//     IH-013 alike, so a rack-position control passed on an estate with no
//     racks and Inventory Hygiene scored 73 where the live evaluator's answer
//     was 25.
//   - a probe TIGHTER than the extraction reports NOT ASSESSED over values the
//     live evaluator judges perfectly well.
//
// The cure for both is that there is one population, measurementPopulation,
// and the probe and the extraction are each built from it. These tests pin
// that, without a database; the integration test
// score_population_consistency_integration_test.go runs both paths.

import (
	"strings"
	"testing"
)

// Every registry row compiles to a probe built from the very population its
// extraction statement reads. Rebuild the probe from anything else — the shape
// alone, the shape plus `where` but not `subject_where` — and this fails.
func TestPopulationProbe_IsTheExtractionsPopulation(t *testing.T) {
	plans, errs := compileMeasurementRegistry(measurementTypeRegistry)
	for code, err := range errs {
		t.Errorf("measurement %q does not compile: %v", code, err)
	}
	for code, plan := range plans {
		if plan.populationSQL == "" {
			t.Errorf("measurement %q has no population probe", code)
			continue
		}
		// The extraction is SELECT <columns> <population> ORDER BY …; cut the
		// population back out of it.
		from := strings.Index(plan.sql, "\n\t\tFROM ")
		order := strings.LastIndex(plan.sql, "\n\t\tORDER BY ")
		if from < 0 || order < from {
			t.Fatalf("measurement %q: extraction statement has no FROM…ORDER BY to compare against:\n%s", code, plan.sql)
		}
		population := plan.sql[from:order]
		if !strings.HasPrefix(plan.populationSQL, "SELECT EXISTS (SELECT 1"+population+"\n") {
			t.Errorf("measurement %q: the population probe does not read the extraction's population.\n"+
				"extraction population:%s\nprobe:\n%s", code, population, plan.populationSQL)
		}
	}
}

// A row whose `subject_where` narrows its population must yield a probe that is
// narrower than its shape's bare FROM + base — the specific regression: the
// DCIM hygiene rows (IH-007..IH-015) were probed as "any assessed asset".
func TestPopulationProbe_CarriesSubjectWhere(t *testing.T) {
	plans, _ := compileMeasurementRegistry(measurementTypeRegistry)
	for _, code := range []string{"rack_position_missing_count", "warranty_expired_count", "unracked_count"} {
		plan, ok := plans[code]
		if !ok {
			t.Fatalf("registry lost %q", code)
		}
		bare := measurementPopulation(plan.shape, compiled{clause: "TRUE"}, compiled{clause: "TRUE"})
		if strings.Contains(plan.populationSQL, bare) {
			t.Errorf("%q: population probe is the shape's bare population (subject_where %q dropped):\n%s",
				code, plan.def.Source.SubjectWhere, plan.populationSQL)
		}
	}
}

// Every measurement type in the shipped registry resolves to a real probe. A
// registry row that fell through to alwaysInScope would fail OPEN.
func TestScopeProbeForEveryRegistryMeasurement(t *testing.T) {
	for _, def := range measurementTypeRegistry {
		key := scopeProbeFor(def.Code)
		if key == alwaysInScope {
			t.Errorf("measurement %q (shape %q) has no population probe and fails open", def.Code, def.Source.Shape)
			continue
		}
		if key.Code != def.Code {
			t.Errorf("measurement %q probes %q", def.Code, key.Code)
		}
	}
}

// An unknown measurement type fails OPEN, and the direction is deliberate: a
// gap in this file's knowledge is not evidence about the tenant.
func TestScopeProbeForUnknownMeasurementFailsOpen(t *testing.T) {
	if got := scopeProbeFor("no-such-measurement-type"); got != alwaysInScope {
		t.Errorf("an unknown measurement type probes %v, want the fail-open key — asserting NOT ASSESSED "+
			"over a measurement we cannot place would be a claim about the tenant we have not earned", got)
	}
	satisfied := map[scopeProbeKey]bool{alwaysInScope: true}
	if !anySatisfied([]scopeProbeKey{alwaysInScope}, satisfied) {
		t.Error("the fail-open key does not satisfy anySatisfied")
	}
}

// anySatisfied is an OR over the control's measurements: one readable
// measurement means the control was assessed.
func TestAnySatisfiedIsAnOr(t *testing.T) {
	readable := scopeProbeKey{Code: "asset_has_owner"}
	absent := scopeProbeKey{Code: "os_eol_days"}
	satisfied := map[scopeProbeKey]bool{readable: true, absent: false}

	if !anySatisfied([]scopeProbeKey{absent, readable}, satisfied) {
		t.Error("a control with one readable measurement reported nothing in scope")
	}
	if anySatisfied([]scopeProbeKey{absent}, satisfied) {
		t.Error("a control whose only measurement has nothing to read reported in scope")
	}
	if anySatisfied(nil, satisfied) {
		t.Error("a control with no probes at all reported in scope")
	}
}

// rebaseParams renumbers in one pass: $1 → $11 must not then become $21, and a
// two-digit parameter is one parameter.
func TestRebaseParams(t *testing.T) {
	got := rebaseParams("a = $1 AND b = $2 AND c = $10 AND d = $1", 10)
	want := "a = $11 AND b = $12 AND c = $20 AND d = $11"
	if got != want {
		t.Errorf("rebaseParams = %q, want %q", got, want)
	}
	if got := rebaseParams("x = $3", 0); got != "x = $3" {
		t.Errorf("a zero offset rewrote the statement: %q", got)
	}
}
