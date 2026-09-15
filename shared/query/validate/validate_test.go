package validate_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"

	"github.com/vistasecurity/vistaplatform/shared/query/catalog/testcatalog"
	"github.com/vistasecurity/vistaplatform/shared/query/parser"
	"github.com/vistasecurity/vistaplatform/shared/query/queryerr"
	"github.com/vistasecurity/vistaplatform/shared/query/validate"
)

// Every rule in §6 is checked in BOTH polarities: it must reject the thing it
// names and accept the nearest legal query. An over-strict guard is the same
// bug pointed the other way, and this package has one job.

func opts() validate.Options {
	return validate.DefaultOptions().WithLadder(testcatalog.Ladder)
}

// check runs a query and returns its error codes.
func check(t *testing.T, src, target string, o validate.Options) []queryerr.Code {
	t.Helper()
	res, err := parser.Parse(src)
	if err != nil {
		t.Fatalf("Parse(%q): %v", src, err)
	}
	if target == "" {
		target = "asset"
	}
	_, err = validate.Validate(res, target, testcatalog.New(), o)
	if err == nil {
		return nil
	}
	list, ok := err.(queryerr.List)
	if !ok {
		t.Fatalf("Validate(%q) returned %T, want a queryerr.List", src, err)
	}
	return list.Codes()
}

func mustReject(t *testing.T, src string, want queryerr.Code) {
	t.Helper()
	codes := check(t, src, "", opts())
	for _, c := range codes {
		if c == want {
			return
		}
	}
	t.Errorf("Validate(%q) = %v, want %s", src, codes, want)
}

func mustAccept(t *testing.T, src string) {
	t.Helper()
	if codes := check(t, src, "", opts()); codes != nil {
		t.Errorf("Validate(%q) = %v, want no errors", src, codes)
	}
}

func TestUnknownField(t *testing.T) {
	for _, q := range []string{
		"hostnaem:web-1",
		"attr.not_registered:1",
		"fact.not.registered:1",
		"id.not_a_kind:1",
		"attr:1",
		"tag:x and bogus:1",
	} {
		mustReject(t, q, queryerr.CodeUnknownField)
	}
	for _, q := range []string{
		"hostname:web-1",
		"attr.cpu_count:1",
		"fact.os.name:linux",
		"id.serial_number:1",
		"tag.anything:1",
		"tag:x",
	} {
		mustAccept(t, q)
	}
}

// TestUnknownFieldSuggests pins §6's "naming the closest match (edit distance
// ≤ 2)" and §10's worked example.
func TestUnknownFieldSuggests(t *testing.T) {
	res, _ := parser.Parse("environment:production and hostnaem:web-1")
	_, err := validate.Validate(res, "asset", testcatalog.New(), opts())
	list := err.(queryerr.List)
	if len(list) != 1 {
		t.Fatalf("got %d errors, want 1: %v", len(list), list)
	}
	e := list[0]
	if !strings.Contains(e.Suggestion, "hostname") {
		t.Errorf("suggestion %q should name hostname", e.Suggestion)
	}
	// The span must underline the field, not the whole query (§10).
	if got := "environment:production and hostnaem:web-1"[e.Span.Start:e.Span.End]; got != "hostnaem" {
		t.Errorf("span covers %q, want %q", got, "hostnaem")
	}
	// A misspelled relationship is an unknown field, and the suggestion has to
	// come from the relationship vocabulary.
	res, _ = parser.Parse("depands_on:(class:server)")
	_, err = validate.Validate(res, "asset", testcatalog.New(), opts())
	if !strings.Contains(err.(queryerr.List)[0].Suggestion, "depends_on") {
		t.Errorf("suggestion %q should name the depends_on relationship", err.(queryerr.List)[0].Suggestion)
	}
}

func TestOperatorNotAllowed(t *testing.T) {
	for _, q := range []string{
		"environment < production",       // keyword has no ordering
		"class != server",                // class takes '=' only
		`risk_score ~ "7"`,               // no regex on numbers
		"last_seen in (now, now-1d)",     // no in-list on timestamps
		"attr.controller_managed > true", // no ordering on booleans
		"risk_score:web-*",               // no wildcard on numbers
		"class:hard*",                    // no wildcard on a class key
	} {
		mustReject(t, q, queryerr.CodeOperatorNotAllowed)
	}
	for _, q := range []string{
		"environment:production",
		"not class=server",
		"risk_score >= 70",
		"last_seen < now-1d",
		"hostname:web-*",
		"risk_score:[40 to 69]",
	} {
		mustAccept(t, q)
	}
	if codes := check(t, "self_signed:true", "certificate", opts()); codes != nil {
		t.Errorf("a boolean equality is fine, got %v", codes)
	}
}

func TestTypeMismatch(t *testing.T) {
	for _, q := range []string{
		"risk >= 70",         // §10's example: risk is a band
		"risk_score >= high", // and the other way round
		"last_seen < soon",
		"last_seen < now-1mo-15d",
		"segment_id=not-a-uuid",
		"primary_address:999.1.1.1",
		"attr.controller_managed:yes",
		"attr.cpu_count:abc",
	} {
		mustReject(t, q, queryerr.CodeTypeMismatch)
	}
	for _, q := range []string{
		"risk_score >= 70",
		"risk >= high",
		"last_seen < now-45d",
		"segment_id=550e8400-e29b-41d4-a716-446655440000",
		"primary_address:198.51.100.0/24",
		"attr.controller_managed:true",
		"attr.cpu_count:3",
	} {
		mustAccept(t, q)
	}
}

func TestUnknownValue(t *testing.T) {
	for _, q := range []string{
		"status:monitorng",
		"status:pending",
		"class:serverr",
		"ownership:internel",
		"rel(depands_on, out):(class:server)",
		"rel(used_by, out):(class:server)",
	} {
		mustReject(t, q, queryerr.CodeUnknownValue)
	}
	for _, q := range []string{
		"status:monitoring",
		"status:pending_approval",
		"class:server",
		"ownership:internal",
		"rel(depends_on, out):(class:server)",
		"used_by:(class:server)",
	} {
		mustAccept(t, q)
	}
}

// TestNotAssessedNeedsCoverage pins §5.2: not_assessed is only meaningful for a
// band field that records who assessed it.
func TestNotAssessedNeedsCoverage(t *testing.T) {
	mustAccept(t, "risk:not_assessed")
	if codes := check(t, "severity:not_assessed", "finding", opts()); len(codes) == 0 {
		t.Error("severity records no coverage, so not_assessed should be rejected")
	}
	mustAccept(t, "risk:informational")
}

func TestTraversalBudget(t *testing.T) {
	// The default budget is 3 (§11 Q3).
	mustAccept(t, "depends_on(3):(class:server)")
	mustReject(t, "depends_on(4):(class:server)", queryerr.CodeDepthExceeded)

	// The budget is the SUM along the deepest nested path (§5.6).
	mustAccept(t, "depends_on(2):(hosted_on:(class:hypervisor))")
	mustReject(t, "depends_on(2):(hosted_on(2):(class:hypervisor))", queryerr.CodeDepthExceeded)

	// Two traversals side by side each cost their own depth, not the sum.
	mustAccept(t, "depends_on(3):(class:server) and hosted_on(3):(class:hypervisor)")

	// A larger configured budget is honoured up to the hard maximum of 6…
	wide := opts()
	wide.TraversalBudget = 6
	if codes := check(t, "depends_on(6):(class:server)", "", wide); codes != nil {
		t.Errorf("a configured budget of 6 should allow six hops, got %v", codes)
	}
	// …and no configuration may exceed it.
	tooWide := opts()
	tooWide.TraversalBudget = 10
	codes := check(t, "depends_on(7):(class:server)", "", tooWide)
	if len(codes) == 0 || codes[0] != queryerr.CodeDepthExceeded {
		t.Errorf("the hard maximum of 6 must win over configuration, got %v", codes)
	}
	if codes := check(t, "depends_on(6):(class:server)", "", tooWide); codes != nil {
		t.Errorf("six hops is exactly the hard maximum and must pass, got %v", codes)
	}

	// A tightened budget is honoured too.
	tight := opts()
	tight.TraversalBudget = 1
	if codes := check(t, "depends_on(2):(class:server)", "", tight); len(codes) == 0 {
		t.Error("a configured budget of 1 should reject two hops")
	}
	if codes := check(t, "depends_on:(class:server)", "", tight); codes != nil {
		t.Errorf("one hop is within a budget of 1, got %v", codes)
	}
}

func TestRegexRules(t *testing.T) {
	// Compiles as RE2.
	mustAccept(t, `hostname ~ "^web[0-9]+$"`)
	mustAccept(t, `hostname ~ "(?i)^web"`)
	mustReject(t, `hostname ~ "^web[0-9"`, queryerr.CodeRegexInvalid)
	// RE2 has no backreferences by construction, so this is a compile failure
	// rather than a rule of ours.
	mustReject(t, `hostname ~ "(a)\\1"`, queryerr.CodeRegexInvalid)

	// A single repetition count: 255 passes, 256 does not. The bound is
	// Postgres's own (DUPMAX) — §6 said 1000, and every count from 256 up
	// validated and was then refused by the database (§13 A9).
	mustAccept(t, `hostname ~ "a{255}"`)
	mustReject(t, `hostname ~ "a{256}"`, queryerr.CodeRegexInvalid)
	mustAccept(t, `hostname ~ "a{1,255}"`)
	mustReject(t, `hostname ~ "a{1,256}"`, queryerr.CodeRegexInvalid)

	// The PRODUCT across nesting is capped separately, at 1000: two bounds
	// that are each legal can multiply into one that is not, which Postgres
	// reports as "regular expression is too complex" — a 500, where this is a
	// diagnostic with a span.
	mustAccept(t, `hostname ~ "(a{10}){100}"`)
	mustReject(t, `hostname ~ "(a{11}){100}"`, queryerr.CodeRegexInvalid)

	// Length: 256 passes, 257 does not.
	mustAccept(t, `hostname ~ "`+strings.Repeat("a", 256)+`"`)
	mustReject(t, `hostname ~ "`+strings.Repeat("a", 257)+`"`, queryerr.CodeRegexInvalid)
}

// TestRegexLengthIsInRunes is T5. §6 says the regex cap is 256 CHARACTERS and
// the query cap is 4096 BYTES — two different units, in two adjacent rows of
// one table, which is exactly the kind of thing an ASCII-only test cannot tell
// apart. The regex cap was counting bytes, so a pattern of accented characters
// was refused at 128 of them.
//
// Every string here is non-ASCII, so the two units give different answers.
func TestRegexLengthIsInRunes(t *testing.T) {
	const multi = "é" // two bytes, one rune

	at := strings.Repeat(multi, 256)
	if len(at) == utf8.RuneCountInString(at) {
		t.Fatal("test setup: the pattern must be non-ASCII for this to measure anything")
	}
	mustAccept(t, `hostname ~ "`+at+`"`)

	over := strings.Repeat(multi, 257)
	mustReject(t, `hostname ~ "`+over+`"`, queryerr.CodeRegexInvalid)

	// And the message counts the same way it caps.
	codes := check(t, `hostname ~ "`+over+`"`, "asset", opts())
	if len(codes) != 1 || codes[0] != queryerr.CodeRegexInvalid {
		t.Fatalf("got %v, want one regex_invalid", codes)
	}
}

// TestQueryLengthIsInBytes is T5's other half: the query cap stays BYTES, so a
// multibyte query reaches it sooner than its character count suggests. That is
// §6 as written, and the right unit for a size cap on stored text.
func TestQueryLengthIsInBytes(t *testing.T) {
	// "é" is two bytes, so 2048 of them plus the field name is over 4096.
	body := strings.Repeat("é", 2048)
	q := `hostname:"` + body + `"`
	if utf8.RuneCountInString(q) > 4096 {
		t.Fatalf("test setup: %d runes — it must be under the cap in runes and over it in bytes",
			utf8.RuneCountInString(q))
	}
	if len(q) <= 4096 {
		t.Fatalf("test setup: %d bytes, want over 4096", len(q))
	}
	mustReject(t, q, queryerr.CodeQueryTooLong)
}

func TestQueryTooLong(t *testing.T) {
	// The cap is on the source text, at 4096 bytes.
	term := "hostname:aaaaaaaa"
	long := strings.Repeat(term+" or ", 4096/(len(term)+4)+1)
	long = strings.TrimSuffix(long, " or ")
	if len(long) <= 4096 {
		t.Fatalf("test setup: query is only %d bytes", len(long))
	}
	mustReject(t, long, queryerr.CodeQueryTooLong)

	fits := "hostname:" + strings.Repeat("a", 4096-len("hostname:"))
	if len(fits) != 4096 {
		t.Fatalf("test setup: query is %d bytes, want exactly 4096", len(fits))
	}
	mustAccept(t, fits)

	// The failing side, exactly one byte over: a cap tested only with a query
	// far past it cannot tell 4096 from 40960.
	overByOne := fits + "a"
	if len(overByOne) != 4097 {
		t.Fatalf("test setup: query is %d bytes, want exactly 4097", len(overByOne))
	}
	mustReject(t, overByOne, queryerr.CodeQueryTooLong)
}

func TestSizeCaps(t *testing.T) {
	// 64 leaves pass, 65 do not.
	mustAccept(t, strings.TrimSuffix(strings.Repeat("hostname:a and ", 64), " and "))
	mustReject(t, strings.TrimSuffix(strings.Repeat("hostname:a and ", 65), " and "),
		queryerr.CodeTooManyClauses)

	// 16 sub-predicates pass, 17 do not.
	mustAccept(t, strings.TrimSuffix(strings.Repeat("endpoint:(port:1) and ", 16), " and "))
	mustReject(t, strings.TrimSuffix(strings.Repeat("endpoint:(port:1) and ", 17), " and "),
		queryerr.CodeTooManyClauses)

	// 16 levels of parentheses pass, 17 do not.
	mustAccept(t, strings.Repeat("(", 16)+"hostname:a"+strings.Repeat(")", 16))
	mustReject(t, strings.Repeat("(", 17)+"hostname:a"+strings.Repeat(")", 17),
		queryerr.CodeTooManyClauses)

	// 256 values in one list pass, 257 do not. The field is business_unit
	// rather than environment because the cap is what is under test: the values
	// are filler, and a closed enum would fail them for a second reason.
	mustAccept(t, "business_unit in ("+strings.TrimSuffix(strings.Repeat("a, ", 256), ", ")+")")
	mustReject(t, "business_unit in ("+strings.TrimSuffix(strings.Repeat("a, ", 257), ", ")+")",
		queryerr.CodeTooManyClauses)
}

func TestUntranslatable(t *testing.T) {
	// A collection with no shape from this target.
	if codes := check(t, "finding:(kind:stale)", "endpoint", opts()); len(codes) == 0 ||
		codes[0] != queryerr.CodeUntranslatable {
		t.Errorf("finding from an endpoint should be untranslatable, got %v", codes)
	}
	if codes := check(t, "asset:(class:server)", "endpoint", opts()); codes != nil {
		t.Errorf("asset from an endpoint is reachable, got %v", codes)
	}
	// Free text where §5.4's column set does not exist.
	if codes := check(t, "payroll", "certificate", opts()); len(codes) == 0 {
		t.Error("free text on a certificate should be untranslatable")
	}
	if codes := check(t, "subject_dn:payroll", "certificate", opts()); codes != nil {
		t.Errorf("a named field on a certificate is fine, got %v", codes)
	}
	// Traversal from a target that is not an asset.
	if codes := check(t, "depends_on:(class:server)", "certificate", opts()); len(codes) == 0 {
		t.Error("traversal from a certificate should be untranslatable")
	}
}

// TestBandWithoutLadder is the fail-closed case: without a ladder there is no
// way to compare a band, and guessing a threshold is exactly what §5.5 forbids.
func TestBandWithoutLadder(t *testing.T) {
	res, _ := parser.Parse("risk >= high")
	_, err := validate.Validate(res, "asset", testcatalog.New(), validate.DefaultOptions())
	if err == nil {
		t.Fatal("a band comparison without a ladder must be refused")
	}
	if !err.(queryerr.List).Has(queryerr.CodeUntranslatable) {
		t.Errorf("got %v, want untranslatable", err)
	}
}

func TestUnknownTarget(t *testing.T) {
	res, _ := parser.Parse("hostname:web-1")
	_, err := validate.Validate(res, "nonesuch", testcatalog.New(), opts())
	if err == nil {
		t.Fatal("an unknown target must be refused")
	}
}

func TestEmptyQueryIsValid(t *testing.T) {
	mustAccept(t, "")
}

// TestResolutionFillsTheFieldRef proves the validator is what makes a query
// translatable: before it runs, no field has a type or an accessor.
func TestResolutionFillsTheFieldRef(t *testing.T) {
	res, _ := parser.Parse("hostname:web-1")
	root, err := validate.Validate(res, "asset", testcatalog.New(), opts())
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	ast.Fields(root, func(f *ast.FieldRef) {
		seen++
		if !f.Resolved {
			t.Errorf("field %q was not resolved", f.Text)
		}
		if f.Type != ast.TypeText || f.Accessor.Column != "hostname" {
			t.Errorf("field %q resolved to %s/%q", f.Text, f.Type, f.Accessor.Column)
		}
	})
	if seen != 1 {
		t.Errorf("visited %d fields, want 1", seen)
	}
}
