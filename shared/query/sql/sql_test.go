package sql_test

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/query/ast"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/testcatalog"
	"github.com/vistasecurity/vistaplatform/shared/query/parser"
	"github.com/vistasecurity/vistaplatform/shared/query/queryerr"
	"github.com/vistasecurity/vistaplatform/shared/query/sql"
	"github.com/vistasecurity/vistaplatform/shared/query/validate"
)

var now = time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

func translate(t *testing.T, src, target string) (string, []any, error) {
	t.Helper()
	if target == "" {
		target = "asset"
	}
	cat := testcatalog.New()
	res, err := parser.Parse(src)
	if err != nil {
		t.Fatalf("Parse(%q): %v", src, err)
	}
	root, err := validate.Validate(res, target, cat, validate.DefaultOptions().WithLadder(testcatalog.Ladder))
	if err != nil {
		t.Fatalf("Validate(%q): %v", src, err)
	}
	return sql.Translate(root, target, cat, sql.Options{Ladder: testcatalog.Ladder, Now: now})
}

func mustTranslate(t *testing.T, src, target string) (string, []any) {
	t.Helper()
	where, args, err := translate(t, src, target)
	if err != nil {
		t.Fatalf("Translate(%q): %v", src, err)
	}
	return where, args
}

// TestNoTenantPredicate is the §7.2 rule the whole isolation story rests on:
// every statement runs inside a transaction that has already set
// app.tenant_id, so RLS scopes it. A tenant predicate emitted here would make
// a bug in this package look like an isolation control.
func TestNoTenantPredicate(t *testing.T) {
	queries := []struct{ src, target string }{
		{"hostname:web-1", "asset"},
		{"endpoint:(port:443)", "asset"},
		{"cert:(not_after < now+30d)", "asset"},
		{"finding:(severity >= high)", "asset"},
		{"software:(name:openssl)", "asset"},
		{"identifier:(kind:mac_address)", "asset"},
		{"relationship:(status:active)", "asset"},
		{"depends_on(3):(class:server)", "asset"},
		{"any_rel:(class:server)", "asset"},
		{"payroll", "asset"},
		{"fact.os.name:linux", "asset"},
		{"tag:prod", "asset"},
		{"id.mac:aa:bb:*", "asset"},
		{"attr.provider:aws", "asset"},
		{"risk:not_assessed", "asset"},
		{"port:443 and asset:(class:server)", "endpoint"},
		{"not_after < now+30d", "certificate"},
		{"producer:crypto", "finding"},
		{"name:openssl", "software_install"},
		{"type:depends_on", "relationship"},
		{"strength:weak", "crypto_configuration"},
		{"", "asset"},
	}
	for _, q := range queries {
		where, _ := mustTranslate(t, q.src, q.target)
		if strings.Contains(where, "tenant") {
			t.Errorf("%q emits a tenant predicate: %s", q.src, where)
		}
	}
}

// TestEveryLiteralIsBound proves parameterisation structurally: there is no
// quoted literal anywhere in the output, so nothing from the query text can
// have been interpolated into SQL.
func TestEveryLiteralIsBound(t *testing.T) {
	queries := []string{
		`hostname="Web01'; DROP TABLE assets; --"`,
		`display_name:"100%"`,
		"hostname:web-*",
		`hostname ~ "^web'"`,
		// business_unit rather than environment: this needs an OPEN keyword
		// field, because the values are arbitrary text chosen to be bound, and
		// environment is the closed environment_type enum (§12 A1).
		"business_unit in (a, b, c)",
		"tag.\"quote\\\"key\":value",
		"class:hardware",
		"risk:[low to high]",
		"endpoint:(service_name:telnet)",
	}
	for _, q := range queries {
		where, args := mustTranslate(t, q, "asset")
		if strings.Contains(where, "'") {
			t.Errorf("%q emits a quoted literal: %s", q, where)
		}
		if len(args) == 0 {
			t.Errorf("%q bound no arguments: %s", q, where)
		}
	}
}

// TestInjectionAttemptsStayValues is the same property from the attacker's
// side: the payload arrives as an argument, never as SQL.
func TestInjectionAttemptsStayValues(t *testing.T) {
	payload := `x'; DROP TABLE assets; --`
	where, args := mustTranslate(t, `hostname=`+ast.Quote(payload), "asset")
	if strings.Contains(where, "DROP") {
		t.Fatalf("payload reached the SQL: %s", where)
	}
	if len(args) != 1 || args[0] != payload {
		t.Fatalf("payload should be argument 1 verbatim, got %v", args)
	}
}

func TestParamNumbering(t *testing.T) {
	where, args := mustTranslate(t, "environment:production and class:server", "asset")
	if !strings.Contains(where, "$1") || !strings.Contains(where, "$3") {
		t.Errorf("placeholders should run from $1: %s", where)
	}
	if len(args) != 3 {
		t.Errorf("got %d args, want 3", len(args))
	}

	// A caller that has already bound parameters of its own can start higher.
	cat := testcatalog.New()
	res, _ := parser.Parse("environment:production")
	root, _ := validate.Validate(res, "asset", cat, validate.DefaultOptions().WithLadder(testcatalog.Ladder))
	where, args, err := sql.Translate(root, "asset", cat, sql.Options{
		Ladder: testcatalog.Ladder, Now: now, ParamStart: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(where, "$5") || strings.Contains(where, "$1") {
		t.Errorf("ParamStart should shift the placeholders: %s", where)
	}
	if len(args) != 1 {
		t.Errorf("got %d args, want 1", len(args))
	}
}

// TestBandSQLComesFromTheLadder is §5.5's rule: change the ladder and the SQL
// changes with it. A hand-written threshold would not move.
func TestBandSQLComesFromTheLadder(t *testing.T) {
	_, args := mustTranslate(t, "risk >= high", "asset")
	if len(args) != 1 || args[0] != 70 {
		t.Fatalf("risk >= high should bind the ladder's High minimum (70), got %v", args)
	}

	cat := testcatalog.New()
	res, _ := parser.Parse("risk >= high")
	shifted := shiftedLadder{}
	root, err := validate.Validate(res, "asset", cat, validate.DefaultOptions().WithLadder(shifted))
	if err != nil {
		t.Fatal(err)
	}
	_, args, err = sql.Translate(root, "asset", cat, sql.Options{Ladder: shifted, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 1 || args[0] != 61 {
		t.Fatalf("the threshold must come from the supplied ladder, got %v", args)
	}
}

// shiftedLadder is the same ladder with High moved, so a hard-coded 70 fails.
type shiftedLadder struct{}

func (shiftedLadder) Bands() []catalog.Band {
	return []catalog.Band{
		{Label: "Critical", Min: 91},
		{Label: "High", Min: 61},
		{Label: "Medium", Min: 41},
		{Label: "Low", Min: 1},
		{Label: "Informational", Min: 0},
	}
}

func TestRiskBandEquality(t *testing.T) {
	// A band with no stored label becomes the half-open score interval.
	where, args := mustTranslate(t, "risk:medium", "asset")
	if !strings.Contains(where, ">=") || !strings.Contains(where, "<") {
		t.Errorf("a band equality should be an interval: %s", where)
	}
	if len(args) != 2 || args[0] != 40 || args[1] != 70 {
		t.Errorf("medium should be [40, 70), got %v", args)
	}
	// The top band is unbounded above.
	where, args = mustTranslate(t, "risk:critical", "asset")
	if strings.Contains(where, "<") {
		t.Errorf("the top band has no upper bound: %s", where)
	}
	if len(args) != 1 || args[0] != 90 {
		t.Errorf("critical should be >= 90, got %v", args)
	}
	// A row that carries a stored label uses it (findings do).
	where, _ = mustTranslate(t, "severity:critical", "finding")
	if !strings.Contains(where, "severity") {
		t.Errorf("a stored label should be compared directly: %s", where)
	}
}

// TestBandEdgesStayThreeValued covers the two band comparisons that have no
// rung to compare against — above the top band, and at-or-below it. Both match
// or miss every SCORED row, but neither may answer FALSE for an unscored one:
// a row with a NULL score must match neither the predicate nor its negation
// (§5.2). A bare FALSE or an IS NOT NULL test would break exactly that, and is
// what these two branches used to emit.
func TestBandEdgesStayThreeValued(t *testing.T) {
	for _, q := range []string{"risk > critical", "risk <= critical"} {
		where, _ := mustTranslate(t, q, "asset")
		if strings.Contains(where, "FALSE") || strings.Contains(where, "IS NOT NULL") {
			t.Errorf("%q collapses an unscored row to a definite answer: %s", q, where)
		}
		if !strings.Contains(where, "risk_score") {
			t.Errorf("%q should be written in terms of the column: %s", q, where)
		}
	}
}

// TestNotAssessedIsNotInformational pins the distinction §5.2 insists on: one
// is "the coverage array is empty", the other is "the coverage array is NOT
// empty and the score is in the bottom band". They are complementary on the
// coverage test, which is what makes them different sets.
func TestNotAssessedIsNotInformational(t *testing.T) {
	notAssessed, _ := mustTranslate(t, "risk:not_assessed", "asset")
	informational, _ := mustTranslate(t, "risk:informational", "asset")
	if notAssessed == informational {
		t.Fatal("not_assessed and informational must translate differently")
	}
	if !strings.Contains(notAssessed, "array_length(a.risk_assessed_by, 1), 0) = 0") {
		t.Errorf("not_assessed should test for an EMPTY coverage array: %s", notAssessed)
	}
	if !strings.Contains(informational, "array_length(a.risk_assessed_by, 1), 0) > 0") {
		t.Errorf("informational should require coverage: %s", informational)
	}
	if !strings.Contains(informational, "risk_score") {
		t.Errorf("informational should also test the score: %s", informational)
	}
}

func TestVersionComparesOnTheSortKey(t *testing.T) {
	where, args := mustTranslate(t, "software:(version < 3.0)", "asset")
	if !strings.Contains(where, "version_sort") {
		t.Errorf("a version comparison must use the normalised key: %s", where)
	}
	if !strings.Contains(where, `COLLATE "C"`) {
		t.Errorf("the key must be compared byte-wise, not by locale: %s", where)
	}
	key, _ := ast.VersionSortKey("3.0")
	if len(args) != 1 || args[0] != key {
		t.Errorf("the bound value should be the normalised key %q, got %v", key, args)
	}
}

// TestUnresolvedFieldIsRefused is the fail-closed rule: the translator never
// sees an unvalidated tree, and if it does it refuses rather than guessing.
func TestUnresolvedFieldIsRefused(t *testing.T) {
	res, err := parser.Parse("hostname:web-1")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = sql.Translate(res.Root, "asset", testcatalog.New(), sql.Options{
		Ladder: testcatalog.Ladder, Now: now,
	})
	if err == nil {
		t.Fatal("translating an unvalidated tree must fail")
	}
	if !err.(queryerr.List).Has(queryerr.CodeUntranslatable) {
		t.Errorf("got %v, want untranslatable", err)
	}
}

// TestInMemoryTargetIsRefused: an observation has no table, and inventing one
// would be worse than refusing.
func TestInMemoryTargetIsRefused(t *testing.T) {
	for _, target := range []string{"observation", "measurement"} {
		cat := testcatalog.New()
		res, _ := parser.Parse("confidence >= 0.5")
		root, err := validate.Validate(res, target, cat, validate.DefaultOptions().WithLadder(testcatalog.Ladder))
		if target == "measurement" {
			// `confidence` is not a measurement field; use the reserved scalar.
			res, _ = parser.Parse("value >= 0.5")
			root, err = validate.Validate(res, target, cat, validate.DefaultOptions().WithLadder(testcatalog.Ladder))
		}
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if _, _, err := sql.Translate(root, target, cat, sql.Options{Ladder: testcatalog.Ladder, Now: now}); err == nil {
			t.Errorf("%s has no table and must not translate", target)
		}
	}
}

func TestEmptyQueryMatchesEverything(t *testing.T) {
	where, args := mustTranslate(t, "", "asset")
	if where != "TRUE" || len(args) != 0 {
		t.Errorf("an empty query should be TRUE with no args, got %q %v", where, args)
	}
}

func TestNotSubIsNotExists(t *testing.T) {
	where, _ := mustTranslate(t, "not endpoint:(port:443)", "asset")
	if !strings.HasPrefix(where, "NOT EXISTS") {
		t.Errorf("a negated sub-predicate should be NOT EXISTS: %s", where)
	}
}

func TestTraversalIsCycleSafeAndDepthBounded(t *testing.T) {
	where, args := mustTranslate(t, "depends_on(3):(class:server)", "asset")
	// Cycle-safety is the depth bound plus deduplication on (id, depth), not a
	// visited-path array — see TestTraversalDeduplicates and §13 A7. A cycle
	// re-enters at a greater depth and is cut off by the bound, and the set of
	// reachable assets is the same either way.
	for _, want := range []string{"WITH RECURSIVE", "(id, depth)", "depth < $", " UNION "} {
		if !strings.Contains(where, want) {
			t.Errorf("traversal SQL is missing %q: %s", want, where)
		}
	}
	// The declared depth and the active-edge filter are both bound values.
	found := false
	for _, a := range args {
		if a == 3 {
			found = true
		}
	}
	if !found {
		t.Errorf("the hop count should be a bound parameter, got %v", args)
	}
	if args[0] != "active" {
		t.Errorf("traversal should follow active edges only, got %v", args[0])
	}
}

func TestClassSubtreeUsesThePath(t *testing.T) {
	where, args := mustTranslate(t, "class:hardware", "asset")
	if !strings.Contains(where, "class_path") {
		t.Errorf("a subtree match should use the materialised path: %s", where)
	}
	if len(args) != 2 || args[0] != "hardware" || args[1] != "hardware.%" {
		t.Errorf("subtree args = %v, want the path and its prefix", args)
	}
	where, args = mustTranslate(t, "class=server", "asset")
	if strings.Contains(where, "class_path") {
		t.Errorf("an exact match should use the key column: %s", where)
	}
	if len(args) != 1 || args[0] != "server" {
		t.Errorf("exact args = %v", args)
	}
}

func TestTextColonIsSubstringAndKeywordColonIsEquality(t *testing.T) {
	where, args := mustTranslate(t, "hostname:web", "asset")
	if !strings.Contains(where, "ILIKE") || args[0] != "%web%" {
		t.Errorf("text ':' should be a case-insensitive substring: %s %v", where, args)
	}
	where, args = mustTranslate(t, "business_unit:finance", "asset")
	if !strings.Contains(where, "lower(") || args[0] != "finance" {
		t.Errorf("keyword ':' should be case-insensitive equality: %s %v", where, args)
	}
	where, args = mustTranslate(t, `hostname="Web01"`, "asset")
	if strings.Contains(where, "ILIKE") || args[0] != "Web01" {
		t.Errorf("'=' should be exact and case-sensitive: %s %v", where, args)
	}
}

func TestLikeMetacharactersAreEscaped(t *testing.T) {
	_, args := mustTranslate(t, `display_name:"50%_off"`, "asset")
	if args[0] != `%50\%\_off%` {
		t.Errorf("LIKE metacharacters in a value must be escaped, got %q", args[0])
	}
	_, args = mustTranslate(t, "hostname:web-*", "asset")
	if args[0] != "web-%" {
		t.Errorf("only the user's asterisk should become a wildcard, got %q", args[0])
	}
}

func TestRelativeDatesResolveOnce(t *testing.T) {
	_, args := mustTranslate(t, "last_seen < now-30d and first_seen > now-30d", "asset")
	if len(args) != 2 {
		t.Fatalf("got %d args, want 2", len(args))
	}
	if args[0] != args[1] {
		t.Errorf("two now-30d terms must resolve to the same instant: %v vs %v", args[0], args[1])
	}
	want := now.AddDate(0, 0, -30)
	if got, ok := args[0].(time.Time); !ok || !got.Equal(want) {
		t.Errorf("now-30d resolved to %v, want %v", args[0], want)
	}
}

func TestJSONBCastsAreGuarded(t *testing.T) {
	// §5.2: a value of the wrong shape is UNKNOWN, not a runtime cast error.
	where, _ := mustTranslate(t, "attr.cpu_count < 3", "asset")
	if !strings.Contains(where, "CASE WHEN") {
		t.Errorf("a numeric jsonb comparison must be guarded: %s", where)
	}
	if !strings.Contains(where, "::numeric") {
		t.Errorf("the guarded branch should cast: %s", where)
	}
}

// TestEveryBandFormIsCoverageGuarded is S1, the ADR-0005 D4 rule made
// structural.
//
// `assets.risk_score` DEFAULTs to 0 and is NOT NULL, so a band predicate
// written over it alone can never be UNKNOWN: `risk < high` was TRUE for every
// asset nobody had ever scored, and `risk:informational` was a strict superset
// of `risk:not_assessed`. §5.2 says those are different sets and neither
// implies the other.
//
// Every ordering operator, both ladder ends, equality, inequality, `in` and a
// range must therefore carry the coverage guard — and it must be a CASE with no
// ELSE, so NULL propagates through NOT.
func TestEveryBandFormIsCoverageGuarded(t *testing.T) {
	const guard = "CASE WHEN coalesce(array_length(a.risk_assessed_by, 1), 0) > 0 THEN"
	forms := []string{
		"risk:high", "risk = high", "risk != high",
		"risk < high", "risk <= high", "risk > high", "risk >= high",
		"risk:informational", "risk:critical",
		"risk < informational", "risk > critical", "risk <= critical", "risk >= informational",
		"risk in (high, critical)",
		"risk:[low to high]",
		"not (risk < high)",
	}
	for _, q := range forms {
		where, _ := mustTranslate(t, q, "asset")
		if !strings.Contains(where, guard) {
			t.Errorf("%q is not coverage-guarded: %s", q, where)
		}
		// An `AND` guard would answer FALSE for an unassessed row, whose
		// negation is TRUE — the same bug pointed the other way. A CASE with
		// an ELSE would do the same. Neither may appear.
		if strings.Contains(where, "END ELSE") || strings.Contains(where, "ELSE ") {
			t.Errorf("%q has an ELSE, which would make an unassessed row definite: %s", q, where)
		}
	}

	// The other polarity, twice over.
	//
	// not_assessed IS the coverage test, so it must NOT be wrapped in it, and
	// a band field with no coverage column — a finding's severity, a crypto
	// configuration's risk — is assessed by construction and is not guarded.
	notAssessed, _ := mustTranslate(t, "risk:not_assessed", "asset")
	if strings.Contains(notAssessed, guard) {
		t.Errorf("not_assessed is the coverage test and must not be guarded by it: %s", notAssessed)
	}
	for _, c := range []struct{ query, target string }{
		{"severity >= high", "finding"},
		{"severity:low", "finding"},
		{"risk >= high", "crypto_configuration"},
	} {
		where, _ := mustTranslate(t, c.query, c.target)
		if strings.Contains(where, "array_length") {
			t.Errorf("%q on %s records no coverage and must not be guarded: %s", c.query, c.target, where)
		}
	}
}

// TestBandRangeReadsTheSameColumnAsEquality is S9's other half: bandRange
// ignored LabelColumn, so on findings `severity:low` compared the stored label
// while `severity:[low to low]` compared the numeric score. Two columns, one
// question, and no reason for them to agree.
func TestBandRangeReadsTheSameColumnAsEquality(t *testing.T) {
	eq, _ := mustTranslate(t, "severity:low", "finding")
	rng, _ := mustTranslate(t, "severity:[low to low]", "finding")
	if !strings.Contains(eq, "f.severity") {
		t.Fatalf("severity:low should read the stored label: %s", eq)
	}
	if !strings.Contains(rng, "f.severity") {
		t.Errorf("severity:[low to low] should read the SAME column: %s", rng)
	}
	if strings.Contains(rng, "f.score") {
		t.Errorf("severity:[low to low] should not fall back to the score: %s", rng)
	}

	// A wider range names every label in the run, highest-first ladder order.
	wide, args := mustTranslate(t, "severity:[low to high]", "finding")
	if !strings.Contains(wide, "IN (") {
		t.Errorf("a multi-band range over a label column should be an IN: %s", wide)
	}
	want := []any{"high", "medium", "low"}
	if len(args) != len(want) {
		t.Fatalf("got args %v, want %v", args, want)
	}
	for i, w := range want {
		if args[i] != w {
			t.Errorf("arg %d = %v, want %v", i, args[i], w)
		}
	}

	// Where there is no label column the range is still the score interval,
	// and the bounds are the ladder's, in order.
	score, args := mustTranslate(t, "risk:[low to medium]", "asset")
	if !strings.Contains(score, "a.risk_score >= $1 AND a.risk_score < $2") {
		t.Errorf("risk:[low to medium] = %s", score)
	}
	if len(args) != 2 || args[0] != 1 || args[1] != 70 {
		t.Errorf("bounds = %v, want [1 70] (low.Min, high.Min)", args)
	}
}

// TestPresenceReadsTheRawValue is S4: a presence test must ask whether there is
// a value, not whether the value parses as its declared type.
//
// `attr.cpu_count` is declared numeric in the catalogue, so the comparison
// path wraps it in a guarded cast — a regex test that yields NULL for anything
// that is not a number, which is right for `attr.cpu_count < 3`. Running that
// cast under `IS NOT NULL` turned "we have a value and cannot parse it" into
// "we have no value": a stored "10.0.19045" made `attr.cpu_count:*` FALSE and
// `not exists(attr.cpu_count)` TRUE.
func TestPresenceReadsTheRawValue(t *testing.T) {
	for _, q := range []string{"exists(attr.cpu_count)", "attr.cpu_count:*"} {
		where, args := mustTranslate(t, q, "asset")
		if strings.Contains(where, "::numeric") || strings.Contains(where, "CASE WHEN") {
			t.Errorf("%q casts before testing presence: %s", q, where)
		}
		if !strings.Contains(where, "a.attributes ->> $1") {
			t.Errorf("%q should read the raw jsonb text: %s", q, where)
		}
		if !strings.Contains(where, "IS NOT NULL") {
			t.Errorf("%q should be a presence test: %s", q, where)
		}
		if len(args) != 1 || args[0] != "cpu_count" {
			t.Errorf("%q bound %v, want just the key", q, args)
		}
	}

	// A fact field is the same rule through the other shape: the EXISTS stays,
	// and the cast inside it goes.
	where, _ := mustTranslate(t, "exists(fact.sw.package_count)", "asset")
	if strings.Contains(where, "::numeric") {
		t.Errorf("a fact presence test casts before testing: %s", where)
	}
	if !strings.Contains(where, "FROM asset_facts") || !strings.Contains(where, "IS NOT NULL") {
		t.Errorf("a fact presence test should be an EXISTS over the raw value: %s", where)
	}

	// The other polarity: a COMPARISON on the same field must still be cast,
	// or a non-numeric value would raise a runtime cast error instead of
	// reading as UNKNOWN (§5.2).
	cmp, _ := mustTranslate(t, "attr.cpu_count < 3", "asset")
	if !strings.Contains(cmp, "::numeric") {
		t.Errorf("a comparison must keep its guarded cast: %s", cmp)
	}
}

// TestFactComparesTheReconciledValue is S2 / §13 A4.
//
// `asset_facts` is unique on (tenant, asset, key, source_ref), so several
// producers may each hold a row for one key. Comparing with an EXISTS over all
// of them was wrong twice over: `fact.os.name:linux` matched if ANY producer
// had ever said linux — including one an operator had since overridden — and
// its negation became NOT EXISTS, which is TRUE for an asset nobody has
// recorded the key for at all. §5.2 requires a term over an unmeasured value
// and its negation to BOTH be UNKNOWN.
//
// A scalar subquery over the highest-precedence row answers both: it returns
// the reconciled value, or no row, and comparing against a subquery that
// returns no row yields NULL.
func TestFactComparesTheReconciledValue(t *testing.T) {
	where, args := mustTranslate(t, "fact.os.name:linux", "asset")
	if strings.HasPrefix(where, "EXISTS") {
		t.Fatalf("a fact comparison must be a scalar subquery, not an EXISTS: %s", where)
	}
	for _, want := range []string{
		"(SELECT ", " FROM asset_facts af1 ", "array_position(ARRAY[", "LIMIT 1)",
	} {
		if !strings.Contains(where, want) {
			t.Errorf("fact comparison is missing %q: %s", want, where)
		}
	}
	// The precedence order is ADR-0005 D2's, bound in order and not inlined.
	want := []any{"measured", "declared", "imported", "inferred"}
	found := false
	for i := 0; i+len(want) <= len(args); i++ {
		if reflect.DeepEqual(args[i:i+len(want)], want) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("args %v do not carry the source precedence %v in order", args, want)
	}

	// Negation must NOT become NOT EXISTS. It is a NOT over a comparison with
	// a scalar subquery, so an asset with no such fact is UNKNOWN on both.
	neg, _ := mustTranslate(t, "not fact.os.name:linux", "asset")
	if strings.Contains(neg, "NOT EXISTS") {
		t.Errorf("negating a fact term must not become NOT EXISTS: %s", neg)
	}
	if !strings.Contains(neg, "NOT (") {
		t.Errorf("negating a fact term should be a NOT over the comparison: %s", neg)
	}

	// The other polarity: PRESENCE is a question about the rows, so it stays an
	// EXISTS with no reconciliation.
	present, _ := mustTranslate(t, "exists(fact.os.name)", "asset")
	if !strings.HasPrefix(present, "EXISTS") {
		t.Errorf("exists(fact.x) should stay an EXISTS over the raw rows: %s", present)
	}
	if strings.Contains(present, "array_position") {
		t.Errorf("exists(fact.x) asks whether ANY producer recorded the key, so it does not reconcile: %s", present)
	}
}

// TestNotEqualOnRowShapedAccessorsIsNotExists is S3.
//
// An identifier or tag field reads its value from ROWS of a child table, so its
// predicate is an EXISTS. Pushing `!=` inside that EXISTS inverts the meaning:
// `EXISTS (… value <> $1)` is "this asset has SOME identifier that is not X",
// which every asset with two identifiers satisfies. `id.mac != aa:bb:…` matched
// the very asset it was written to exclude, and `tag != prod` matched any asset
// with a tag whose key OR value differed — that is, almost all of them.
//
// The question is "no row matches", which is NOT EXISTS.
func TestNotEqualOnRowShapedAccessorsIsNotExists(t *testing.T) {
	for _, c := range []struct{ query, table string }{
		{"id.mac != aa:bb:cc:dd:ee:ff", "asset_identifiers"},
		{`id.any != "aa:bb:cc:dd:ee:ff"`, "asset_identifiers"},
		{"tag != prod", "jsonb_each_text"},
	} {
		where, _ := mustTranslate(t, c.query, "asset")
		if !strings.HasPrefix(where, "NOT EXISTS") {
			t.Errorf("%q should be a NOT EXISTS: %s", c.query, where)
		}
		if strings.Contains(where, "<>") {
			t.Errorf("%q still pushes the inequality inside the EXISTS: %s", c.query, where)
		}
		if !strings.Contains(where, c.table) {
			t.Errorf("%q should read %s: %s", c.query, c.table, where)
		}
	}

	// The other polarity, three ways.
	//
	// Positive terms on the same fields stay a plain EXISTS; `!=` on an
	// ordinary COLUMN stays `<>` (the row is the current one, so three-valued
	// logic already handles absence); and `!=` on a fact stays `<>` against
	// the reconciled scalar subquery, which is three-valued where NOT EXISTS
	// would not be.
	pos, _ := mustTranslate(t, "id.mac:aa:bb:cc:dd:ee:ff", "asset")
	if !strings.HasPrefix(pos, "EXISTS") || strings.HasPrefix(pos, "NOT") {
		t.Errorf("a positive identifier term should be a plain EXISTS: %s", pos)
	}
	col, _ := mustTranslate(t, "hostname != web1", "asset")
	if !strings.Contains(col, "a.hostname <> $1") {
		t.Errorf("a column inequality should stay <>: %s", col)
	}
	fact, _ := mustTranslate(t, "fact.os.name != linux", "asset")
	if strings.Contains(fact, "NOT EXISTS") {
		t.Errorf("a fact inequality is scalar and must stay three-valued: %s", fact)
	}
	if !strings.Contains(fact, "<>") {
		t.Errorf("a fact inequality should be <> against the reconciled value: %s", fact)
	}
}

// TestDerivedKeywordFieldsBehaveLikeKeywords is S5.
//
// `proposed_by` and `strength` are keyword-typed in the catalogue, so §4.4 says
// they take `:` (case-insensitive), `=` (case-sensitive), `!=`, `in`, `~` and a
// `*` wildcard, and answer `exists`. They took none of that: the derived
// builders had a switch of their own that compared case-sensitively and
// accepted only ":" and "=", so `proposed_by:match*` searched for the literal
// string "match*" and `proposed_by:*` validated and then failed
// `untranslatable` — §6's code for a parser bug, shown to a user who wrote
// something the cheat sheet documents.
func TestDerivedKeywordFieldsBehaveLikeKeywords(t *testing.T) {
	// ":" is case-insensitive. The kind guard binds two params ahead of the
	// value — `inferred` and `rule`, the two machine-proposed class kinds — so
	// the comparison lands on $3.
	where, args := mustTranslate(t, "proposed_by:Matcher", "asset")
	if !strings.Contains(where, "lower(a.class_source_ref) = $3") {
		t.Errorf(`proposed_by:Matcher should fold case: %s`, where)
	}
	if len(args) != 3 || args[2] != "matcher" {
		t.Errorf("the folded value should be bound: %v", args)
	}
	// "=" is not.
	where, args = mustTranslate(t, "proposed_by=Matcher", "asset")
	if strings.Contains(where, "lower(a.class_source_ref)") {
		t.Errorf(`proposed_by=Matcher is case-SENSITIVE: %s`, where)
	}
	if len(args) != 3 || args[2] != "Matcher" {
		t.Errorf("the verbatim value should be bound: %v", args)
	}
	// A wildcard is a LIKE pattern, not a literal asterisk.
	where, args = mustTranslate(t, "proposed_by:match*", "asset")
	if !strings.Contains(where, "ILIKE") {
		t.Errorf("proposed_by:match* should be a LIKE: %s", where)
	}
	if len(args) != 3 || args[2] != "match%" {
		t.Errorf("the wildcard should become a LIKE pattern, got %v", args)
	}
	// Presence works, and does not compare anything.
	for _, q := range []string{"proposed_by:*", "exists(proposed_by)"} {
		where, _ = mustTranslate(t, q, "asset")
		if !strings.Contains(where, "a.class_source_ref IS NOT NULL") {
			t.Errorf("%q should be a presence test: %s", q, where)
		}
	}
	// A regex and a list reach it too.
	if where, _ = mustTranslate(t, `proposed_by ~ "^match"`, "asset"); !strings.Contains(where, " ~ ") {
		t.Errorf("proposed_by ~ should be a regex: %s", where)
	}
	if where, _ = mustTranslate(t, "proposed_by in (matcher, importer)", "asset"); !strings.Contains(where, " OR ") {
		t.Errorf("proposed_by in (…) should be an OR: %s", where)
	}
	// And it reaches BOTH machine-proposed class kinds. §4.3 wrote the sugar as
	// `source=inferred` because `inferred` was the only one there was;
	// workstream 2.10b added `rule`, whose class_source_ref carries the
	// classification_rules row id — the exact thing this field exists to name.
	// While the guard said `= 'inferred'`, the proposed_by FACET listed those
	// `rule:<id>` refs (it reads the column with no kind filter) and clicking
	// one returned nothing: a facet that filters to zero, which is the silent
	// wrong answer rather than an empty result.
	where, args = mustTranslate(t, "proposed_by:*", "asset")
	if !strings.Contains(where, "class_source_kind IN ($1, $2)") {
		t.Errorf("proposed_by must admit both machine-proposed kinds: %s", where)
	}
	if len(args) != 2 || args[0] != "inferred" || args[1] != "rule" {
		t.Errorf("proposed_by kind guard bound %v, want [inferred rule]", args)
	}
	// `measured` and `declared` stay OUT. A sensor id or a user id in
	// class_source_ref says who observed or decided the class, not who proposed
	// it, and admitting them would make `proposed_by:*` mean "has a
	// class_source_ref" — which is every row.
	for _, kind := range []string{"measured", "declared", "imported"} {
		if strings.Contains(fmt.Sprint(args), kind) {
			t.Errorf("proposed_by admitted %q; it names the PROPOSER, not every producer", kind)
		}
	}

	// The same for the crypto strength lens, which is row-shaped — so `!=`
	// negates the whole EXISTS (S3's rule).
	where, _ = mustTranslate(t, "strength:Weak", "crypto_configuration")
	if !strings.Contains(where, "lower(alg2.strength) = $1") {
		t.Errorf("strength:Weak should fold case: %s", where)
	}
	where, _ = mustTranslate(t, "strength != weak", "crypto_configuration")
	if !strings.HasPrefix(where, "NOT EXISTS") {
		t.Errorf(`strength != weak should be "no algorithm is weak": %s`, where)
	}
	where, _ = mustTranslate(t, "exists(strength)", "crypto_configuration")
	if !strings.Contains(where, "alg2.strength IS NOT NULL") {
		t.Errorf("exists(strength) should be a presence test over the rows: %s", where)
	}
}

// TestDerivedBooleanIsAnAggregate covers the one derived field whose value is
// NOT a per-row column: "does this configuration use a deprecated algorithm" is
// an aggregate over the linked algorithms. Comparing per row would make
// `algorithm.deprecated:false` mean "has some algorithm that is not deprecated"
// instead of "has none that is".
func TestDerivedBooleanIsAnAggregate(t *testing.T) {
	yes, args := mustTranslate(t, "algorithm.deprecated:true", "crypto_configuration")
	if !strings.Contains(yes, "(EXISTS (SELECT 1 FROM crypto_implementation_algorithms") {
		t.Errorf("the value should be an EXISTS aggregate: %s", yes)
	}
	if len(args) != 3 || args[2] != true {
		t.Errorf("the boolean should be bound, got %v", args)
	}
	no, args := mustTranslate(t, "algorithm.deprecated:false", "crypto_configuration")
	if len(args) != 3 || args[2] != false {
		t.Errorf("false should be bound as false, got %v", args)
	}
	if strings.Contains(no, "NOT EXISTS") {
		t.Errorf("`:false` compares the aggregate to false; it is not a separate shape: %s", no)
	}
	// Presence asks whether the data to compute it is there at all.
	where, _ := mustTranslate(t, "exists(algorithm.deprecated)", "crypto_configuration")
	if !strings.Contains(where, "deprecation_status IS NOT NULL") {
		t.Errorf("exists() on the derived flag should test for the source data: %s", where)
	}
}

// TestTraversalDeduplicates is S12 / §13 A7.
//
// The recursive term was UNION ALL over a CTE carrying the visited path, so a
// node reachable by several routes produced one row per ROUTE. In a dense graph
// — two hops through a busy switch — the number of simple paths is exponential
// in the depth, and the CTE materialises all of them to answer a question that
// only needs the set of reachable nodes.
//
// Measured over a four-layer mesh of sixteen nodes on PG 17: 340 rows before,
// 16 after.
//
// Keeping the path column and only switching to UNION changes NOTHING — every
// route to a node carries a different path, so the rows are distinct and UNION
// removes none of them (measured: 340 either way). The path had to go with it.
func TestTraversalDeduplicates(t *testing.T) {
	// The inner predicate is deliberately not a class term: `class_path` would
	// put the word "path" in the clause for a reason that has nothing to do
	// with the CTE.
	where, _ := mustTranslate(t, "depends_on(3):(hostname:web)", "asset")

	if strings.Contains(where, "UNION ALL") {
		t.Errorf("the recursive term must deduplicate: %s", where)
	}
	if !strings.Contains(where, " UNION ") {
		t.Errorf("the recursive term should be a UNION: %s", where)
	}
	if strings.Contains(where, "path") {
		t.Errorf("carrying a path column defeats the deduplication entirely: %s", where)
	}
	if !strings.Contains(where, "(id, depth)") {
		t.Errorf("the CTE should carry (id, depth) and nothing else: %s", where)
	}
	// Termination still comes from the depth bound, which §5.6 caps at 6.
	if !strings.Contains(where, ".depth < $") {
		t.Errorf("the recursive term must stay depth-bounded: %s", where)
	}
	// The starting asset is excluded from its own result, in BOTH terms: "what
	// does this depend on" must not answer "itself" because of a cycle three
	// hops out. That is the one thing the path array did besides pruning.
	if n := strings.Count(where, "<> a.id"); n != 2 {
		t.Errorf("the source asset should be excluded in both terms, found %d: %s", n, where)
	}
}

// TestOuterAliasAndPrefix covers the two knobs S12 asks for. The clause NAMES
// the target's alias, so a caller whose FROM spells it differently needs to say
// so; and a caller splicing two translations into one statement needs their
// generated aliases not to collide.
func TestOuterAliasAndPrefix(t *testing.T) {
	cat := testcatalog.New()
	res, err := parser.Parse("hostname:web-1 and endpoint:(port:443)")
	if err != nil {
		t.Fatal(err)
	}
	root, err := validate.Validate(res, "asset", cat, validate.DefaultOptions().WithLadder(testcatalog.Ladder))
	if err != nil {
		t.Fatal(err)
	}

	// The default is the catalogue's alias.
	base, _, err := sql.Translate(root, "asset", cat, sql.Options{Ladder: testcatalog.Ladder, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(base, "a.hostname") {
		t.Errorf("default should use the catalogue alias: %s", base)
	}

	named, _, err := sql.Translate(root, "asset", cat, sql.Options{
		Ladder: testcatalog.Ladder, Now: now, OuterAlias: "asset",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(named, "asset.hostname") {
		t.Errorf("OuterAlias should rename the target: %s", named)
	}
	if !strings.Contains(named, ".asset_id = asset.id") {
		t.Errorf("child shapes should correlate to the outer alias: %s", named)
	}

	prefixed, _, err := sql.Translate(root, "asset", cat, sql.Options{
		Ladder: testcatalog.Ladder, Now: now, AliasPrefix: "q2_",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prefixed, "asset_endpoints q2_e1") {
		t.Errorf("AliasPrefix should prefix generated aliases: %s", prefixed)
	}
	if strings.Contains(prefixed, " e1") {
		t.Errorf("no unprefixed generated alias should remain: %s", prefixed)
	}
	// The prefix must not touch the outer alias, which the caller owns.
	if !strings.Contains(prefixed, "a.hostname") {
		t.Errorf("AliasPrefix should leave the outer alias alone: %s", prefixed)
	}
}

// TestAssetChildShapes_AgreeWithFindingsSubjectPaths pins the `asset/crypto`
// and `asset/cert` shapes to shared/findings.AssetSubjects, fragment for
// fragment.
//
// They are two spellings of ONE question — "which crypto configurations and
// certificates belong to this asset" — asked by different readers of the same
// rows: `crypto:(…)`/`cert:(…)` compile through the shapes here, while
// `finding:(…)`, the `has_findings` facet, the per-asset findings read and the
// risk rollup all resolve through AssetSubjects. When the two disagreed, a
// facet counted one set and the click it produced queried another, which is why
// that facet was withdrawn in Gate 1.
//
// They disagreed again for a while: AssetSubjects learned in that
// `crypto_implementations.endpoint_id` is nullable and these shapes did not, so
// an at-rest configuration's FINDINGS were reachable from its asset while the
// configuration itself was not. Nothing failed. This is what fails now.
func TestAssetChildShapes_AgreeWithFindingsSubjectPaths(t *testing.T) {
	// AssetSubjects mints its aliases through a caller-supplied generator; give
	// it the bare prefix so both sides normalise to the same text.
	bare := func(prefix string) string { return prefix }
	subjects := map[string]string{}
	for _, s := range findings.AssetSubjects("a", bare) {
		subjects[s.Type] = s.IDs
	}

	for _, tc := range []struct {
		collection string
		subject    string
	}{
		{"crypto", findings.SubjectCryptoConfiguration},
		{"cert", findings.SubjectCertificate},
	} {
		t.Run(tc.collection, func(t *testing.T) {
			where, _, err := translate(t, "exists("+tc.collection+")", "asset")
			if err != nil {
				t.Fatalf("translate: %v", err)
			}
			// `exists(<collection>)` is the shape with no inner predicate, so
			// what is left between FROM and the closing paren is exactly the
			// join chain and the correlation.
			shape := strings.TrimSuffix(strings.TrimPrefix(where, "EXISTS (SELECT 1 FROM "), ")")
			want, ok := subjects[tc.subject]
			if !ok {
				t.Fatalf("findings.AssetSubjects has no %q path", tc.subject)
			}
			_, want, _ = strings.Cut(want, " FROM ")

			if got := stripAliasDigits(shape); got != want {
				t.Errorf("the %q shape and findings.AssetSubjects(%s) walk different paths:\n"+
					"  query language: %s\n"+
					"  findings:       %s\n"+
					"one of them is wrong, and whichever it is, a facet count and the list it "+
					"leads to now describe different sets", tc.collection, tc.subject, got, want)
			}
		})
	}
}

// aliasDigits matches the counter the builder appends to a generated alias.
// Anchored to the aliases these two shapes actually mint, so it cannot mangle
// an identifier that happens to end in a digit (fingerprint_sha256).
var aliasDigits = regexp.MustCompile(`\b(a|c|ci|cic|e|si)\d+\b`)

func stripAliasDigits(s string) string { return aliasDigits.ReplaceAllString(s, "$1") }
