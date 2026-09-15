package services

// The runtime belt around a registry row that does not compile.
//
// `TestMeasurementRegistryCompiles` is the build-time guarantee that the
// SHIPPED registry has no such row, and it is the one that matters: a broken
// row cannot reach a release. This file covers what happens if one ever does —
// because the failure mode without a belt is the quiet one. The extractor would
// store the error and say nothing until something evaluated that code, while
// the catalogue went on offering it, so an admin could author a control against
// a measurement type that errors on every call: a control that can neither pass
// nor fail, arrived at from the authoring end instead of the SQL end.
//
// Two halves, and each is asserted in BOTH polarities, because a log line that
// always prints and a filter that always withholds would each pass a
// one-directional test:
//
//   - NewMeasurementExtractor LOGS the row by name and reason, and is silent
//     for the shipped registry;
//   - MeasurementCatalogue and MeasurementCatalogueEntry — the two functions the
//     two routes call — WITHHOLD it, and offer all 28 for the shipped registry.

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// brokenMeasurementCode is broken by pointing its value at a selectable no
// shape offers — the shape of a real accident (a shape renamed a column and the
// registry was not updated), rather than the hostile input the generator's own
// name check already refuses.
const brokenMeasurementCode = "last_seen_days"

// withRegistry swaps the package-level registry for the duration of one test.
// Nothing in this package runs t.Parallel(), so the swap cannot be observed by
// another test; the cleanup restores it even on failure.
func withRegistry(t *testing.T, defs []MeasurementTypeDef) {
	t.Helper()
	original := measurementTypeRegistry
	measurementTypeRegistry = defs
	t.Cleanup(func() { measurementTypeRegistry = original })
}

// registryWithBrokenRow copies the shipped registry and breaks exactly one row.
// The copy is by value, and Source is a struct, so the shipped rows are
// untouched.
func registryWithBrokenRow(t *testing.T, code string) []MeasurementTypeDef {
	t.Helper()
	out := make([]MeasurementTypeDef, len(measurementTypeRegistry))
	copy(out, measurementTypeRegistry)
	for i := range out {
		if out[i].Code == code {
			out[i].Source.Value = "no_such_selectable"
			return out
		}
	}
	t.Fatalf("%q is not in the registry; pick a code that is, or the test proves nothing", code)
	return nil
}

// captureLog redirects the standard logger for one test and returns a reader
// for what was written.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	flags, writer := log.Flags(), log.Writer()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(writer)
		log.SetFlags(flags)
	})
	return &buf
}

func TestMeasurementCompileFailure_IsLoggedByName(t *testing.T) {
	t.Run("a row that does not compile is named, with its reason", func(t *testing.T) {
		withRegistry(t, registryWithBrokenRow(t, brokenMeasurementCode))
		out := captureLog(t)

		e := NewMeasurementExtractor(nil)

		logged := out.String()
		if !strings.Contains(logged, brokenMeasurementCode) {
			t.Errorf("the log does not name the broken measurement type.\ngot: %q", logged)
		}
		if !strings.Contains(logged, "no_such_selectable") {
			t.Errorf("the log does not say WHY the row failed, so an operator cannot act on it.\ngot: %q", logged)
		}
		if _, bad := e.errs[brokenMeasurementCode]; !bad {
			t.Errorf("the extractor did not record %q as broken", brokenMeasurementCode)
		}
		if _, ok := e.plans[brokenMeasurementCode]; ok {
			t.Errorf("the extractor built a plan for a row that does not compile")
		}
		// And it is refused at the point of use, loudly, rather than returning
		// an empty result that reads as "nothing to assess".
		if _, err := e.ExtractMeasurements(uuid.New(), brokenMeasurementCode); err == nil {
			t.Error("extracting a broken measurement type returned no error — an unusable type must fail " +
				"at the point of use, where the rule evaluator counts it as a failed check")
		}
		// The other 27 are unaffected: the belt withholds one row, not the file.
		if len(e.plans) != len(measurementTypeRegistry)-1 {
			t.Errorf("compiled %d plans, want %d — one broken row must not take the rest with it",
				len(e.plans), len(measurementTypeRegistry)-1)
		}
	})

	// The polarity that makes the assertion above mean something. An
	// unconditional log line would satisfy the first subtest perfectly.
	t.Run("the shipped registry logs nothing", func(t *testing.T) {
		out := captureLog(t)

		e := NewMeasurementExtractor(nil)

		if logged := out.String(); logged != "" {
			t.Errorf("NewMeasurementExtractor logged against the shipped registry, so the line above "+
				"proves nothing:\n%s", logged)
		}
		if len(e.errs) != 0 {
			t.Errorf("the shipped registry has %d row(s) that do not compile: %v", len(e.errs), e.errs)
		}
	})
}

// TestIntegration_MeasurementCatalogue_WithholdsARowThatDoesNotCompile covers
// the half that reaches the authoring UIs. It exercises MeasurementCatalogue
// and MeasurementCatalogueEntry rather than the HTTP routes because the swap
// above is package-local; the routes are held to these two functions by
// handlers/measurement_catalog_contract_test.go, which drives them for real.
//
// Skips without TEST_DATABASE_URL (shared/testdb); `make test-integration-db`.
func TestIntegration_MeasurementCatalogue_WithholdsARowThatDoesNotCompile(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")

	// Polarity first: with the shipped registry every declared type is offered
	// and nothing is withheld. If this ever fails, the subtest below is
	// measuring the wrong thing.
	t.Run("the shipped registry is offered whole", func(t *testing.T) {
		types, missing, unservable, err := MeasurementCatalogue(db)
		if err != nil {
			t.Fatalf("catalogue: %v", err)
		}
		if len(unservable) != 0 {
			t.Errorf("withheld %v from a registry that compiles cleanly", unservable)
		}
		if len(missing) != 0 {
			t.Errorf("seeded database is missing %v — re-run the seed", missing)
		}
		if len(types) != len(measurementTypeRegistry) {
			t.Errorf("offered %d types, want all %d", len(types), len(measurementTypeRegistry))
		}
		if _, ok, err := MeasurementCatalogueEntry(db, brokenMeasurementCode); err != nil || !ok {
			t.Errorf("%s is not individually resolvable (ok=%v, err=%v) — the subtest below would pass "+
				"for the wrong reason", brokenMeasurementCode, ok, err)
		}
	})

	t.Run("a row that does not compile is not offered", func(t *testing.T) {
		withRegistry(t, registryWithBrokenRow(t, brokenMeasurementCode))

		types, missing, unservable, err := MeasurementCatalogue(db)
		if err != nil {
			t.Fatalf("catalogue: %v", err)
		}
		for _, mt := range types {
			if mt.Code == brokenMeasurementCode {
				t.Fatalf("%s is still offered to the rule builder. A control authored against it would "+
					"error on every evaluation — it could neither pass nor fail", brokenMeasurementCode)
			}
		}
		if len(unservable) != 1 || unservable[0] != brokenMeasurementCode {
			t.Errorf("unservable = %v, want [%s] — withholding it silently is the failure this reports",
				unservable, brokenMeasurementCode)
		}
		// It is withheld as UNSERVABLE, not reported as unseeded: the two say
		// different things to an operator, and only one of them is fixed by a
		// re-seed.
		for _, code := range missing {
			if code == brokenMeasurementCode {
				t.Errorf("%s was reported as missing from the seed; it is seeded, it does not compile",
					brokenMeasurementCode)
			}
		}
		if len(types) != len(measurementTypeRegistry)-1 {
			t.Errorf("offered %d types, want %d — one broken row must not withhold the rest",
				len(types), len(measurementTypeRegistry)-1)
		}
		// The by-code route must agree with the list, or a withheld type stays
		// reachable at its own URL.
		if _, ok, err := MeasurementCatalogueEntry(db, brokenMeasurementCode); err != nil {
			t.Fatalf("entry: %v", err)
		} else if ok {
			t.Errorf("GET /measurement-types/%s still resolves a type the list withheld",
				brokenMeasurementCode)
		}
	})
}
