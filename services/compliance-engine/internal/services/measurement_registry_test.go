package services

// Unit tests for the measurement registry and the statements it compiles to.
// Nothing here needs a database: the point is that every registry row resolves
// against a shape, a selectable, a transform and the query catalogue BEFORE any
// deployment runs it, and that the SQL it produces is reviewable.

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/query"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/ladder"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/registrycatalog"
)

var updateGolden = flag.Bool("update-measurement-golden", false,
	"rewrite testdata/measurement_sql_golden.sql from the current registry")

func testPlans(t *testing.T) map[string]*measurementPlan {
	t.Helper()
	cat := registrycatalog.New(registrycatalog.Options{})
	opts := query.DefaultOptionsFor(cat)
	plans := make(map[string]*measurementPlan, len(measurementTypeRegistry))
	for _, def := range measurementTypeRegistry {
		plan, err := buildMeasurementPlan(def, cat, opts)
		if err != nil {
			t.Fatalf("measurement %q does not compile: %v", def.Code, err)
		}
		plans[def.Code] = plan
	}
	return plans
}

// TestMeasurementRegistryCompiles is the check the YAML generator cannot make:
// every row names a shape that exists, a selectable that shape offers, a
// transform and row filter that are implemented, and a query-language predicate
// that resolves against the production catalogue.
//
// It is also what makes NewMeasurementExtractor's eager compilation safe to
// rely on — a row that does not compile is an error returned on every
// extraction of that code, and this test says the shipped registry has none.
func TestMeasurementRegistryCompiles(t *testing.T) {
	if len(measurementTypeRegistry) == 0 {
		t.Fatal("the registry is empty; the generator did not run")
	}
	plans := testPlans(t)

	e := NewMeasurementExtractor(nil)
	if len(e.errs) != 0 {
		t.Fatalf("extractor reports compile errors: %v", e.errs)
	}
	for _, def := range measurementTypeRegistry {
		if _, ok := e.plans[def.Code]; !ok {
			t.Errorf("measurement %q has no plan", def.Code)
		}
		plan := plans[def.Code]
		if plan.shape.Subject != def.Subject {
			t.Errorf("measurement %q: subject %q but shape measures %q", def.Code, def.Subject, plan.shape.Subject)
		}
	}
}

// TestMeasurementShapesGuardDeletedRows pins the soft-delete predicates. A
// whole-tenant reconcile that re-extracts a deleted asset flips its INACTIVE
// findings straight back to ACTIVE, resetting the tenant's triage state and
// dropping their score for an asset that no longer exists. Delete either
// predicate from a shape and this fails.
func TestMeasurementShapesGuardDeletedRows(t *testing.T) {
	want := map[string][]string{
		"crypto_configuration": {"na.deleted_at IS NULL", "ci.deleted_at IS NULL"},
		"asset":                {"a.deleted_at IS NULL"},
		"fact":                 {"a.deleted_at IS NULL"},
		"finding":              {"a.deleted_at IS NULL"},
	}
	for name, predicates := range want {
		shape, ok := measurementShapes[name]
		if !ok {
			t.Fatalf("shape %q is gone", name)
		}
		base := strings.Join(shape.Base, " ")
		for _, p := range predicates {
			if !strings.Contains(base, p) {
				t.Errorf("shape %q no longer carries %q", name, p)
			}
		}
	}
	// The certificates table has no deleted_at column, so its shape must not
	// pretend to have one — and it must still scope to leaf certificates.
	certBase := strings.Join(measurementShapes["certificate"].Base, " ")
	if strings.Contains(certBase, "deleted_at") {
		t.Error("the certificate shape references deleted_at, which that table does not have")
	}
	if !strings.Contains(certBase, "is_ca_certificate = false") {
		t.Error("the certificate shape no longer scopes to leaf certificates")
	}
}

// TestMeasurementShapesScopeToTenant pins that every shape carries the explicit
// tenant predicate. RLS is defence in depth; the WHERE clause is the boundary.
func TestMeasurementShapesScopeToTenant(t *testing.T) {
	for name, shape := range measurementShapes {
		if !strings.Contains(strings.Join(shape.Base, " "), "tenant_id = $1") {
			t.Errorf("shape %q does not scope to the tenant", name)
		}
		if !strings.Contains(strings.Join(shape.Base, " "), "$2::uuid IS NULL OR") {
			t.Errorf("shape %q has no per-asset filter, so a per-asset reconcile would scan the tenant", name)
		}
	}
}

// TestMeasurementRegistryIgnoresTheBandLadder proves the claim
// NewMeasurementExtractor makes: no registry predicate compares a risk band, so
// the ladder the catalogue is wired with cannot change an extraction. Compiling
// the whole registry against two DIFFERENT ladders must produce identical SQL.
func TestMeasurementRegistryIgnoresTheBandLadder(t *testing.T) {
	compileAll := func(l catalog.BandLadder) map[string]string {
		cat := registrycatalog.New(registrycatalog.Options{Ladder: l})
		opts := query.DefaultOptions(l)
		out := map[string]string{}
		for _, def := range measurementTypeRegistry {
			plan, err := buildMeasurementPlan(def, cat, opts)
			if err != nil {
				t.Fatalf("measurement %q: %v", def.Code, err)
			}
			out[def.Code] = plan.sql
		}
		return out
	}
	a := compileAll(ladder.FromRungs(90, 70, 40, 1))
	b := compileAll(ladder.FromRungs(80, 60, 30, 2))
	for code, sqlA := range a {
		if sqlA != b[code] {
			t.Errorf("measurement %q compiles differently under two band ladders:\n%s\n---\n%s", code, sqlA, b[code])
		}
	}
}

// TestMeasurementSQLGolden pins the statement every registry row compiles to.
//
// It is the review surface for a registry change: a new measurement type, a
// changed predicate or an edited shape shows up here as the SQL it will
// actually run, which is otherwise assembled out of three files. Regenerate
// with `go test ./internal/services -run TestMeasurementSQLGolden -update-measurement-golden`.
func TestMeasurementSQLGolden(t *testing.T) {
	plans := testPlans(t)
	codes := make([]string, 0, len(plans))
	for code := range plans {
		codes = append(codes, code)
	}
	sort.Strings(codes)

	var b strings.Builder
	b.WriteString("-- The statement each measurement type compiles to, from\n")
	b.WriteString("-- standards/measurement-types.yaml + measurement_shapes.go. GENERATED by\n")
	b.WriteString("-- TestMeasurementSQLGolden; regenerate with -update-measurement-golden.\n")
	b.WriteString("-- $1 is the tenant, $2 the optional single-subject filter; a shape's own\n")
	b.WriteString("-- parameter (fact key, producer) is $3 and the compiled predicates follow.\n")
	for _, code := range codes {
		p := plans[code]
		b.WriteString("\n-- ============================================================\n")
		b.WriteString("-- " + code + "  [shape: " + p.shape.Name + ", subject: " + p.shape.Subject + "]\n")
		if len(p.extraArgs) > 0 {
			b.WriteString("-- $3 = " + fmt.Sprintf("%v", p.extraArgs) + "\n")
		}
		if len(p.predArgs) > 0 {
			b.WriteString("-- predicate args: " + fmt.Sprintf("%v", p.predArgs) + "\n")
		}
		b.WriteString(p.sql + "\n")
	}

	path := filepath.Join("testdata", "measurement_sql_golden.sql")
	got := b.String()
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("golden rewritten")
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v (run with -update-measurement-golden to create it)", err)
	}
	if string(want) != got {
		t.Errorf("compiled measurement SQL differs from testdata/measurement_sql_golden.sql.\n"+
			"If the change is intended, rerun with -update-measurement-golden and review the diff.\ngot:\n%s", got)
	}
}

// ------------------------------------------------------------- transforms --

func TestMeasurementTransformsAreWhitelisted(t *testing.T) {
	for _, def := range measurementTypeRegistry {
		name := transformName(def)
		if _, ok := measurementTransforms[name]; !ok {
			t.Errorf("measurement %q names transform %q, which does not exist", def.Code, name)
		}
		if def.Source.RowFilter != "" {
			if _, ok := measurementRowFilters[def.Source.RowFilter]; !ok {
				t.Errorf("measurement %q names row filter %q, which does not exist", def.Code, def.Source.RowFilter)
			}
		}
	}
}

func TestTransformPQCClass(t *testing.T) {
	cases := map[string]string{
		"RSA":               "quantum_vulnerable",
		"ecdsa-with-SHA256": "quantum_vulnerable",
		"":                  "quantum_vulnerable", // absent is not safe
		"ML-DSA-65":         "quantum_safe",
		"X25519MLKEM768":    "quantum_safe", // hybrid counts
	}
	for in, want := range cases {
		got, err := measurementTransforms["pqc_class"](textValue(in))
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got != want {
			t.Errorf("pqc_class(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestTransformSymmetricMargin(t *testing.T) {
	cases := map[string]string{
		"AES-256-GCM":       "quantum_safe",
		"ChaCha20-Poly1305": "quantum_safe",
		"AES-128-GCM":       "quantum_marginal",
		"":                  "quantum_marginal",
	}
	for in, want := range cases {
		got, _ := measurementTransforms["symmetric_margin"](textValue(in))
		if got != want {
			t.Errorf("symmetric_margin(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestTransformPFS(t *testing.T) {
	cases := map[string]bool{"ECDHE": true, "DHE": true, "ecdhe": true, "RSA": false, "": false}
	for in, want := range cases {
		got, _ := measurementTransforms["pfs"](textValue(in))
		if got != want {
			t.Errorf("pfs(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestTransformChainValid(t *testing.T) {
	selfSigned := scannedValue{kind: scanBool}
	selfSigned.bl.Valid, selfSigned.bl.Bool = true, true
	if got, _ := measurementTransforms["chain_valid"](selfSigned); got != false {
		t.Errorf("chain_valid(self-signed) = %v, want false", got)
	}
	notSelfSigned := scannedValue{kind: scanBool}
	notSelfSigned.bl.Valid, notSelfSigned.bl.Bool = true, false
	if got, _ := measurementTransforms["chain_valid"](notSelfSigned); got != true {
		t.Errorf("chain_valid(ca-signed) = %v, want true", got)
	}
	if got, _ := measurementTransforms["chain_valid"](scannedValue{kind: scanBool}); got != true {
		t.Errorf("chain_valid(NULL) = %v, want true", got)
	}
}

// TestTransformDaysFloorVersusTrunc pins the difference the two day transforms
// exist for: an expired certificate counts DOWN past zero, so -0.5 days is -1
// and not "expires today", while a validity PERIOD is never negative and
// truncates.
func TestTransformDaysFloorVersusTrunc(t *testing.T) {
	if got, _ := measurementTransforms["days_floor"](floatValue(-0.5)); got != -1 {
		t.Errorf("days_floor(-0.5) = %v, want -1", got)
	}
	if got, _ := measurementTransforms["days_floor"](floatValue(45.9)); got != 45 {
		t.Errorf("days_floor(45.9) = %v, want 45", got)
	}
	if got, _ := measurementTransforms["days_trunc"](floatValue(397.8)); got != 397 {
		t.Errorf("days_trunc(397.8) = %v, want 397", got)
	}
	if _, err := measurementTransforms["days_floor"](scannedValue{kind: scanFloat}); err == nil {
		t.Error("days_floor(NULL) produced a measurement; a NULL is not zero days")
	}
}

// TestTransformDaysUntilDate covers the lifecycle transform, including the part
// that matters most: a value that is not a date yields NO measurement, so a
// malformed fact is reported as not assessed rather than as "ends today".
func TestTransformDaysUntilDate(t *testing.T) {
	future := time.Now().UTC().AddDate(0, 0, 40).Format("2006-01-02")
	got, err := measurementTransforms["days_until_date"](textValue(future))
	if err != nil {
		t.Fatalf("future date: %v", err)
	}
	if days, ok := got.(int); !ok || days < 38 || days > 40 {
		t.Errorf("days_until_date(+40d) = %v, want about 39-40", got)
	}

	past := time.Now().UTC().AddDate(0, 0, -400).Format("2006-01-02")
	got, err = measurementTransforms["days_until_date"](textValue(past))
	if err != nil {
		t.Fatalf("past date: %v", err)
	}
	if days, ok := got.(int); !ok || days > -399 || days < -401 {
		t.Errorf("days_until_date(-400d) = %v, want about -400", got)
	}

	for _, bad := range []string{"", "not-a-date", "31/12/2030"} {
		if _, err := measurementTransforms["days_until_date"](textValue(bad)); err == nil {
			t.Errorf("days_until_date(%q) produced a measurement", bad)
		}
	}
}

func TestRowFilterKeyFamilies(t *testing.T) {
	row := func(alg string) map[string]scannedValue {
		return map[string]scannedValue{"public_key_algorithm": textValue(alg)}
	}
	ff := measurementRowFilters["key_family_finite_field"]
	ec := measurementRowFilters["key_family_elliptic_curve"]

	if !ff(row("RSA")) || ec(row("RSA")) {
		t.Error("RSA must be finite-field only")
	}
	// The substring trap: ECDSA contains DSA.
	if !ec(row("ecdsa-with-SHA384")) || ff(row("ecdsa-with-SHA384")) {
		t.Error("ECDSA must be elliptic-curve only")
	}
	// A post-quantum key has no classical floor, so NEITHER family claims it.
	if ff(row("ML-DSA-65")) || ec(row("ML-DSA-65")) {
		t.Error("a PQC key must be judged by neither key-size measurement")
	}
	// Unclassifiable is not assessed, not assessed against a guess.
	if ff(row("wat")) || ec(row("wat")) {
		t.Error("an unrecognised algorithm must be judged by neither key-size measurement")
	}
}

func textValue(s string) scannedValue {
	v := scannedValue{kind: scanText}
	v.str.Valid, v.str.String = true, s
	return v
}

func floatValue(f float64) scannedValue {
	v := scannedValue{kind: scanFloat}
	v.flt.Valid, v.flt.Float64 = true, f
	return v
}
