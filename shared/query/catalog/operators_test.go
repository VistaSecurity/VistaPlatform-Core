package catalog

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
)

// The §4.4 type → operator matrix had no test of any kind: it was consulted by
// the validator and pinned only where a conformance fixture happened to
// exercise a pair. These tables restate §4.4 by hand, in BOTH polarities, so a
// cell cannot be changed without saying so — a matrix is exactly the shape of
// thing where a typo looks like intent.

// allowed lists the operators §4.4 marks ✅ for each type. Everything not
// listed must be refused.
var allowed = map[ast.FieldType]struct {
	ops                      []ast.Op
	in, match, rng, wildcard bool
}{
	ast.TypeKeyword:      {ops: []ast.Op{ast.OpColon, ast.OpEq, ast.OpNe}, in: true, match: true, wildcard: true},
	ast.TypeText:         {ops: []ast.Op{ast.OpColon, ast.OpEq, ast.OpNe}, in: true, match: true, wildcard: true},
	ast.TypeNumber:       {ops: []ast.Op{ast.OpColon, ast.OpEq, ast.OpNe, ast.OpLt, ast.OpLte, ast.OpGt, ast.OpGte}, in: true, rng: true},
	ast.TypeTimestamp:    {ops: []ast.Op{ast.OpColon, ast.OpEq, ast.OpNe, ast.OpLt, ast.OpLte, ast.OpGt, ast.OpGte}, rng: true},
	ast.TypeBoolean:      {ops: []ast.Op{ast.OpColon, ast.OpEq, ast.OpNe}},
	ast.TypeInet:         {ops: []ast.Op{ast.OpColon, ast.OpEq, ast.OpNe}, in: true, wildcard: true},
	ast.TypeClass:        {ops: []ast.Op{ast.OpColon, ast.OpEq}, in: true},
	ast.TypeBand:         {ops: []ast.Op{ast.OpColon, ast.OpEq, ast.OpNe, ast.OpLt, ast.OpLte, ast.OpGt, ast.OpGte}, in: true, rng: true},
	ast.TypeVersion:      {ops: []ast.Op{ast.OpColon, ast.OpEq, ast.OpNe, ast.OpLt, ast.OpLte, ast.OpGt, ast.OpGte}, in: true, wildcard: true},
	ast.TypeUUID:         {ops: []ast.Op{ast.OpColon, ast.OpEq, ast.OpNe}, in: true},
	ast.TypeKeywordArray: {ops: []ast.Op{ast.OpColon, ast.OpEq}, in: true},
	// json takes NOTHING but exists. Written out as an empty row rather than
	// left out of the table, so it is covered by every loop below: a type
	// absent from `allowed` is untested, and an untested all-false row is
	// indistinguishable from a type nobody remembered to add.
	ast.TypeJSON: {},
}

var everyOp = []ast.Op{
	ast.OpColon, ast.OpEq, ast.OpNe, ast.OpLt, ast.OpLte, ast.OpGt, ast.OpGte,
}

func TestOperatorAllowedMatchesTheSpecTable(t *testing.T) {
	for typ, want := range allowed {
		yes := map[ast.Op]bool{}
		for _, op := range want.ops {
			yes[op] = true
		}
		for _, op := range everyOp {
			got := OperatorAllowed(typ, op)
			if got != yes[op] {
				t.Errorf("OperatorAllowed(%s, %q) = %v, want %v", typ, op, got, yes[op])
			}
		}
		if got := InAllowed(typ); got != want.in {
			t.Errorf("InAllowed(%s) = %v, want %v", typ, got, want.in)
		}
		if got := MatchAllowed(typ); got != want.match {
			t.Errorf("MatchAllowed(%s) = %v, want %v", typ, got, want.match)
		}
		if got := RangeAllowed(typ); got != want.rng {
			t.Errorf("RangeAllowed(%s) = %v, want %v", typ, got, want.rng)
		}
		if got := WildcardAllowed(typ); got != want.wildcard {
			t.Errorf("WildcardAllowed(%s) = %v, want %v", typ, got, want.wildcard)
		}
	}
}

// TestTwoNarrowRowsStayNarrow pins the two rows of §4.4 that read as broader
// than they are, and that a future edit would most plausibly "fix":
//
//   - class takes `=` but NOT `!=` ("= exact only"),
//   - keyword[] takes `=` as contains, but not `!=`.
//
// Both are deliberate: "this asset's class is not exactly X" and "this array
// does not contain X" are better written with `not`, where the three-valued
// rule (§5.2) is visible in the text rather than hidden in an operator.
func TestTwoNarrowRowsStayNarrow(t *testing.T) {
	for _, typ := range []ast.FieldType{ast.TypeClass, ast.TypeKeywordArray} {
		if !OperatorAllowed(typ, ast.OpEq) {
			t.Errorf("%s should accept %q", typ, ast.OpEq)
		}
		if OperatorAllowed(typ, ast.OpNe) {
			t.Errorf("%s must NOT accept %q — write it with `not` (§4.4)", typ, ast.OpNe)
		}
	}
}

// TestUnknownTypeIsRefused is the fail-closed half: a field the catalogue left
// untyped must not quietly acquire every operator.
func TestUnknownTypeIsRefused(t *testing.T) {
	for _, typ := range []ast.FieldType{ast.TypeUnresolved, ast.FieldType("invented")} {
		if KnownType(typ) {
			t.Errorf("KnownType(%q) should be false", typ)
		}
		for _, op := range everyOp {
			if OperatorAllowed(typ, op) {
				t.Errorf("OperatorAllowed(%q, %q) should be false", typ, op)
			}
		}
		if InAllowed(typ) || MatchAllowed(typ) || RangeAllowed(typ) || WildcardAllowed(typ) {
			t.Errorf("%q should allow no list, match, range or wildcard", typ)
		}
	}
	for typ := range allowed {
		if !KnownType(typ) {
			t.Errorf("KnownType(%s) should be true", typ)
		}
	}
}

// TestOperatorsForListsWhatIsAllowed keeps the error-message helper honest: it
// is what a user is told to write instead, so it must not name an operator the
// matrix refuses, nor omit one it accepts.
func TestOperatorsForListsWhatIsAllowed(t *testing.T) {
	for typ := range allowed {
		listed := strings.Join(OperatorsFor(typ), " ")
		for _, op := range everyOp {
			// Compared entry by entry, not by substring: ":" and "=" occur
			// inside ">=" and "<=", so a Contains check would pass vacuously.
			if has(OperatorsFor(typ), string(op)) != OperatorAllowed(typ, op) {
				t.Errorf("OperatorsFor(%s) = %q, but OperatorAllowed(%s, %q) = %v",
					typ, listed, typ, op, OperatorAllowed(typ, op))
			}
		}
		if has(OperatorsFor(typ), "in") != InAllowed(typ) {
			t.Errorf("OperatorsFor(%s) = %q disagrees with InAllowed", typ, listed)
		}
		if has(OperatorsFor(typ), "~") != MatchAllowed(typ) {
			t.Errorf("OperatorsFor(%s) = %q disagrees with MatchAllowed", typ, listed)
		}
		if has(OperatorsFor(typ), "[a to b]") != RangeAllowed(typ) {
			t.Errorf("OperatorsFor(%s) = %q disagrees with RangeAllowed", typ, listed)
		}
		// Every type answers exists(), so every list ends with it.
		if !has(OperatorsFor(typ), "exists") {
			t.Errorf("OperatorsFor(%s) = %q should offer exists", typ, listed)
		}
	}
}

// TestJSONIsPresenceOnly pins the json row's two halves, which pull in
// opposite directions and are both load-bearing.
//
// KnownType must be TRUE: the validator refuses an unknown type outright, and
// that would take `exists(fact.net.interfaces)` — a question the database
// answers perfectly — down with the comparisons. OperatorsFor must offer
// exactly "exists": it is what the user is told to write instead, so naming
// anything else would send them to an operator that is about to be refused.
func TestJSONIsPresenceOnly(t *testing.T) {
	if !KnownType(ast.TypeJSON) {
		t.Error("KnownType(json) must be true, or exists() on a json field is refused too")
	}
	if got := strings.Join(OperatorsFor(ast.TypeJSON), " "); got != "exists" {
		t.Errorf("OperatorsFor(json) = %q, want exactly %q", got, "exists")
	}
}

func has(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// TestBandLadderHelpers covers the ladder arithmetic every band predicate is
// generated from (§5.5). A rung's interval is half-open and the top one is
// unbounded; getting either wrong moves every badge and facet at once.
func TestBandLadderHelpers(t *testing.T) {
	l := fixedLadder{}

	if got := BandLabels(l, false); strings.Join(got, ",") != "critical,high,medium,low,informational" {
		t.Errorf("BandLabels = %v", got)
	}
	if got := BandLabels(l, true); got[len(got)-1] != NotAssessed {
		t.Errorf("BandLabels with not_assessed = %v", got)
	}

	for label, wantIdx := range map[string]int{"Critical": 0, "high": 1, "MEDIUM": 2, "low": 3, "informational": 4} {
		if got, ok := BandIndex(l, label); !ok || got != wantIdx {
			t.Errorf("BandIndex(%q) = %d,%v want %d,true", label, got, ok, wantIdx)
		}
	}
	if _, ok := BandIndex(l, "nonesuch"); ok {
		t.Error("BandIndex should refuse an unknown label")
	}

	// Half-open interval, and unbounded at the top.
	min, max, hasMax, ok := BandBounds(l, "medium")
	if !ok || min != 40 || max != 70 || !hasMax {
		t.Errorf("BandBounds(medium) = %d,%d,%v,%v want 40,70,true,true", min, max, hasMax, ok)
	}
	min, _, hasMax, ok = BandBounds(l, "critical")
	if !ok || min != 90 || hasMax {
		t.Errorf("BandBounds(critical) = %d,_,%v,%v want 90,_,false,true", min, hasMax, ok)
	}
	if _, _, _, ok = BandBounds(l, "nonesuch"); ok {
		t.Error("BandBounds should refuse an unknown label")
	}

	if got, ok := BandAtLeast(l, "high"); !ok || got != 70 {
		t.Errorf("BandAtLeast(high) = %d,%v want 70,true", got, ok)
	}
	if _, ok := BandAtLeast(l, "nonesuch"); ok {
		t.Error("BandAtLeast should refuse an unknown label")
	}
}

type fixedLadder struct{}

func (fixedLadder) Bands() []Band {
	return []Band{
		{Label: "Critical", Min: 90},
		{Label: "High", Min: 70},
		{Label: "Medium", Min: 40},
		{Label: "Low", Min: 1},
		{Label: "Informational", Min: 0},
	}
}
