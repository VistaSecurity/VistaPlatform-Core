package services

// Structural guards for the per-shape scope probes.
//
// `loadControlAssessments` can only be as honest as these probes are, and the
// two failure directions are both real and both silent:
//
//   - a MISSING probe falls through to `alwaysInScope`, which means a control
//     over that shape reports PASS on a tenant with nothing for it to read.
//     That is the bug the Gate 3 end-to-end proof found: every Lifecycle control
//     measures the `fact` shape, no probe distinguished it from "this tenant has
//     some crypto somewhere", and the framework scored 100 over an estate the
//     end-of-life catalogue had never resolved a date for.
//   - a probe that stops MIRRORING its shape reports NOT ASSESSED over data the
//     extractor reads perfectly well, which is the same dishonesty pointed the
//     other way.
//
// Neither is visible from any test of the scoring arithmetic, which is why
// these are structural. They run without a database.

import (
	"strings"
	"testing"
)

// Every shape a measurement can name must have a probe. Delete an entry from
// `scopeProbes` and this fails; that is the point.
func TestScopeProbeCoversEveryShape(t *testing.T) {
	for name := range measurementShapes {
		if _, ok := scopeProbes[name]; !ok {
			t.Errorf("measurement shape %q has no scope probe, so every control measuring it falls through "+
				"to alwaysInScope and reports PASS on a tenant with nothing for it to read", name)
		}
	}
	// And the other direction: a probe for a shape that no longer exists is
	// dead weight that reads as coverage.
	for name := range scopeProbes {
		if _, ok := measurementShapes[name]; !ok {
			t.Errorf("scope probe %q names a shape that is not in measurementShapes", name)
		}
	}
}

// Each probe reads the tables its shape reads, carries its shape's tenant and
// soft-delete predicates, and takes the shape's extra parameter exactly when
// the shape declares one.
func TestScopeProbe_MirrorsItsShape(t *testing.T) {
	for name, shape := range measurementShapes {
		probe, ok := scopeProbes[name]
		if !ok {
			continue // reported by the test above
		}

		// Tables. The shape's From is a FROM plus its JOINs; every table named
		// in it has to appear in the probe, or the probe is asking a different
		// question from the extractor.
		for _, table := range tablesIn(shape.From) {
			if !strings.Contains(probe, table) {
				t.Errorf("the %q probe does not read %s, which its shape's FROM joins — a probe that reads "+
					"fewer tables than its shape is looser than the extractor and reports PASS over rows "+
					"the extractor cannot see", name, table)
			}
		}

		// Soft deletes. Every shape that excludes deleted rows must have a probe
		// that does too; is exactly this predicate going missing.
		for _, base := range shape.Base {
			if strings.Contains(base, "deleted_at IS NULL") && !strings.Contains(probe, "deleted_at IS NULL") {
				t.Errorf("the %q probe does not exclude soft-deleted rows, which its shape does", name)
			}
		}

		// The shape's own parameter.
		parameterised := shape.NeedsFactKey || shape.NeedsAssessedBy
		if parameterised && !strings.Contains(probe, "$2") {
			t.Errorf("the %q shape takes a fact key or a producer, but its probe binds no second parameter — "+
				"so it asks 'has this tenant ANY fact' where the control asks about ONE", name)
		}
		if !parameterised && strings.Contains(probe, "$2") {
			t.Errorf("the %q probe binds a second parameter its shape does not declare", name)
		}
	}
}

// Every measurement type in the registry resolves to a real probe, with an
// argument exactly when its shape is parameterised.
//
// A registry row whose shape has no probe would be indistinguishable from an
// unplaceable hand-seeded measurement type, which fails OPEN — and the whole
// value of the probe is in the rows the registry DOES describe.
func TestScopeProbeForEveryRegistryMeasurement(t *testing.T) {
	for _, def := range measurementTypeRegistry {
		key := scopeProbeFor(def.Code)
		if key == alwaysInScope {
			t.Errorf("measurement %q (shape %q) has no scope probe and fails open", def.Code, def.Source.Shape)
			continue
		}
		if key.Shape != def.Source.Shape {
			t.Errorf("measurement %q probes shape %q, want %q", def.Code, key.Shape, def.Source.Shape)
		}
		shape := measurementShapes[def.Source.Shape]
		switch {
		case shape.NeedsFactKey && key.Arg != def.Source.FactKey:
			t.Errorf("measurement %q probes fact key %q, want %q", def.Code, key.Arg, def.Source.FactKey)
		case shape.NeedsAssessedBy && key.Arg != def.Source.AssessedBy:
			t.Errorf("measurement %q probes producer %q, want %q", def.Code, key.Arg, def.Source.AssessedBy)
		case !shape.NeedsFactKey && !shape.NeedsAssessedBy && key.Arg != "":
			t.Errorf("measurement %q carries probe argument %q for a shape that takes none", def.Code, key.Arg)
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
	readable := scopeProbeKey{Shape: "asset"}
	absent := scopeProbeKey{Shape: "fact", Arg: "eol.os.date"}
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

// tablesIn pulls the NARROWING table names out of a shape's FROM clause: the
// first word of the FROM, plus the first word after each INNER JOIN.
//
// Outer joins are skipped on purpose. A LEFT JOIN cannot remove a row, so a
// shape's outer-joined table says nothing about whether the shape can yield
// anything and a probe is not looser for omitting it — the crypto_configuration
// shape's `LEFT JOIN asset_endpoints` is the live example.
func tablesIn(from string) []string {
	var out []string
	parts := strings.Split(from, "JOIN")
	for i, part := range parts {
		trimmed := strings.TrimSpace(part)
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		if i == 0 {
			out = append(out, fields[0])
			continue
		}
		// The join TYPE is the tail of the preceding fragment.
		prev := strings.ToUpper(strings.TrimSpace(parts[i-1]))
		if strings.HasSuffix(prev, "LEFT") || strings.HasSuffix(prev, "RIGHT") ||
			strings.HasSuffix(prev, "FULL") || strings.HasSuffix(prev, "OUTER") {
			continue
		}
		out = append(out, fields[0])
	}
	return out
}
