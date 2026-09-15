// Package eval evaluates a validated query against a value in memory, for the
// targets that have no table.
//
// QUERY_LANGUAGE.md §4.1 defines two of those: `observation`, the in-flight
// discovery an auto-approval rule sees, and `measurement`, the scalar a
// compliance rule extracted. Neither names rows, so the SQL translator refuses
// them (`untranslatable`, by design) and the predicate has to be decided where
// the value lives — in the identification engine, against a struct.
//
// This is that decision, and it is deliberately the SAME AST the translator
// reads. A second parser, or a hand-written condition interpreter beside the
// language, is how a rule comes to mean one thing in the editor's autocomplete
// and another at the moment it fires.
//
// # Three-valued, like the SQL side
//
// §5.2: a comparison against an absent value is UNKNOWN, not false, and its
// negation is UNKNOWN too. The two together do not partition the input; the
// residue is exactly the things nobody measured. On the SQL side Postgres gives
// that for free. Here it has to be written out, which is why [Result] has three
// values and why [Match] is `result == True` rather than `!False`.
package eval

import (
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
)

// Result is the three-valued outcome of a predicate (§5.2).
type Result int

const (
	// False is a definite no.
	False Result = iota
	// True is a definite yes.
	True
	// Unknown is "nobody measured this". It matches neither the predicate nor
	// its negation.
	Unknown
)

func (r Result) String() string {
	switch r {
	case True:
		return "true"
	case False:
		return "false"
	default:
		return "unknown"
	}
}

// Source supplies the values a predicate reads.
//
// Implementations are tiny — a switch over the field's accessor column onto a
// struct field. Returning ok=false is how absence is stated, and it is NOT the
// same as returning a zero value: `confidence >= 0.8` against an unmeasured
// confidence is Unknown, while against a measured 0.0 it is False.
type Source interface {
	// Field returns the value of a resolved field.
	//
	// The concrete types the evaluator understands are string, bool, the
	// numeric types, time.Time, netip.Addr, netip.Prefix and []string. A type
	// it does not understand is a programming error and surfaces as an error,
	// never as a silent no-match.
	//
	// For a TypeClass field, return the class PATH (`hardware.computer.server`).
	// `class:X` is a subtree test on it and `class=X` compares its last
	// segment, so one value answers both (§5.3).
	Field(ref ast.FieldRef) (any, bool)

	// FreeText returns the strings a bare term searches (§5.4): the thing's
	// display name, its hostname, its identifier values, and its tag keys and
	// values. Nothing else — a free-text query must not be able to widen.
	FreeText() []string
}

// Options configure an evaluation.
type Options struct {
	// Now is the instant relative dates resolve against, evaluated once per
	// query so two terms in one query always agree (§5.5).
	Now time.Time
	// Ladder is the band ladder `risk >= high` compares through. A band field
	// with no ladder is refused rather than guessed — the same choice the
	// translator makes.
	Ladder catalog.BandLadder
}

// Match reports whether src satisfies the predicate.
//
// It is `Eval(...) == True`, spelled out because the difference matters: an
// Unknown does NOT match, and writing `!= False` would auto-approve every
// observation a rule could not measure.
func Match(n ast.Node, src Source, opts Options) (bool, error) {
	r, err := Eval(n, src, opts)
	if err != nil {
		return false, err
	}
	return r == True, nil
}

// Eval walks the AST and returns the three-valued result.
//
// A nil node is True: an empty query matches everything, which is what an empty
// scope means and what a rule with no conditions means.
func Eval(n ast.Node, src Source, opts Options) (Result, error) {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	e := &evaluator{src: src, opts: opts}
	r := e.node(n)
	if e.err != nil {
		return False, e.err
	}
	return r, nil
}

type evaluator struct {
	src  Source
	opts Options
	err  error
}

func (e *evaluator) fail(format string, args ...any) Result {
	if e.err == nil {
		e.err = fmt.Errorf(format, args...)
	}
	return False
}

func (e *evaluator) node(n ast.Node) Result {
	switch t := n.(type) {
	case nil:
		return True
	case *ast.And:
		// False wins over Unknown: one definite no settles a conjunction
		// whatever else is unmeasured.
		out := True
		for _, c := range t.Children {
			switch e.node(c) {
			case False:
				return False
			case Unknown:
				out = Unknown
			}
		}
		return out
	case *ast.Or:
		// True wins over Unknown, symmetrically.
		out := False
		for _, c := range t.Children {
			switch e.node(c) {
			case True:
				return True
			case Unknown:
				out = Unknown
			}
		}
		return out
	case *ast.Not:
		switch e.node(t.Child) {
		case True:
			return False
		case False:
			return True
		default:
			// §5.2: the negation of an unmeasured comparison is also
			// unmeasured. This line is the whole rule.
			return Unknown
		}
	case *ast.Compare:
		return e.compare(t)
	case *ast.InSet:
		return e.inSet(t)
	case *ast.Range:
		return e.rangeTerm(t)
	case *ast.Match:
		return e.match(t)
	case *ast.Exists:
		_, ok := e.src.Field(t.Field)
		return boolResult(ok)
	case *ast.FreeText:
		return e.freeText(t)
	case *ast.Sub:
		return e.fail("%s: a sub-predicate over %q has no in-memory shape; this target carries no child collections",
			spanText(t.Sp), t.Collection)
	case *ast.Traverse:
		return e.fail("%s: relationship traversal has no in-memory shape; an observation is not yet an asset and has no edges",
			spanText(t.Sp))
	default:
		return e.fail("unsupported node %T", n)
	}
}

// ------------------------------------------------------------ comparisons --

func (e *evaluator) compare(t *ast.Compare) Result {
	// `field:*` is the exists spelling (§3 cheat sheet).
	if t.Op == ast.OpColon && t.Value.IsBareStar() {
		_, ok := e.src.Field(t.Field)
		return boolResult(ok)
	}
	raw, ok := e.src.Field(t.Field)
	if !ok {
		return Unknown
	}
	r := e.compareValue(t.Field, t.Op, t.Value, raw)
	if t.Op == ast.OpNe && r != Unknown {
		// `!=` is the negation of `=`, and stays three-valued: an absent value
		// already returned Unknown above.
		return negate(r)
	}
	return r
}

// compareValue applies one operator to one value, dispatching on the field's
// DECLARED type rather than on the Go type of the value. The declared type is
// what the validator checked the literal against, so the two cannot disagree
// about what `0.8` or `now-30d` meant.
func (e *evaluator) compareValue(f ast.FieldRef, op ast.Op, lit ast.Literal, raw any) Result {
	switch f.Type {
	case ast.TypeNumber:
		return e.numberCompare(f, op, lit, raw)
	case ast.TypeBoolean:
		return e.boolCompare(op, lit, raw)
	case ast.TypeTimestamp:
		return e.timeCompare(f, op, lit, raw)
	case ast.TypeInet:
		return e.inetCompare(op, lit, raw)
	case ast.TypeClass:
		return e.classCompare(op, lit, raw)
	case ast.TypeBand:
		return e.bandCompare(f, op, lit, raw)
	case ast.TypeKeywordArray:
		return e.arrayCompare(op, lit, raw)
	case ast.TypeJSON:
		// §4.4's json row: exists and nothing else. Refused, not guessed.
		return e.fail("%s: %q is a JSON value; only exists(%s) is available on it", spanText(lit.Sp), f.Text, f.Text)
	default:
		return e.stringCompare(f, op, lit, raw)
	}
}

func (e *evaluator) stringCompare(f ast.FieldRef, op ast.Op, lit ast.Literal, raw any) Result {
	got, ok := toString(raw)
	if !ok {
		return e.fail("%s: %q is a %s but the source gave %T", spanText(lit.Sp), f.Text, f.Type, raw)
	}
	want := lit.Value
	switch op {
	case ast.OpEq, ast.OpNe:
		// `=` is case-SENSITIVE (§2). A wildcard is still a wildcard.
		if lit.IsWildcard() {
			return boolResult(globMatch(want, got, false))
		}
		return boolResult(got == want)
	case ast.OpColon:
		if lit.IsWildcard() {
			return boolResult(globMatch(want, got, true))
		}
		if f.Type == ast.TypeText {
			// `:` on text is SUBSTRING, which is what a search box means.
			return boolResult(strings.Contains(strings.ToLower(got), strings.ToLower(want)))
		}
		return boolResult(strings.EqualFold(got, want))
	default:
		return e.fail("%s: operator %q is not available on %q", spanText(lit.Sp), op, f.Text)
	}
}

func (e *evaluator) numberCompare(f ast.FieldRef, op ast.Op, lit ast.Literal, raw any) Result {
	got, ok := toFloat(raw)
	if !ok {
		return e.fail("%s: %q is a number but the source gave %T", spanText(lit.Sp), f.Text, raw)
	}
	want, ok := ast.ParseNumber(lit.Value)
	if !ok {
		return e.fail("%s: %q is not a number", spanText(lit.Sp), lit.Value)
	}
	return compareOrdered(op, cmpFloat(got, want))
}

func (e *evaluator) boolCompare(op ast.Op, lit ast.Literal, raw any) Result {
	got, ok := raw.(bool)
	if !ok {
		return e.fail("%s: expected a boolean, got %T", spanText(lit.Sp), raw)
	}
	want, ok := ast.ParseBool(lit.Value)
	if !ok {
		return e.fail("%s: %q is not true or false", spanText(lit.Sp), lit.Value)
	}
	switch op {
	case ast.OpColon, ast.OpEq, ast.OpNe:
		return boolResult(got == want)
	default:
		return e.fail("%s: operator %q is not available on a boolean", spanText(lit.Sp), op)
	}
}

func (e *evaluator) timeCompare(f ast.FieldRef, op ast.Op, lit ast.Literal, raw any) Result {
	got, ok := raw.(time.Time)
	if !ok {
		return e.fail("%s: %q is a timestamp but the source gave %T", spanText(lit.Sp), f.Text, raw)
	}
	date, ok := ast.ParseDate(lit.Value)
	if !ok {
		return e.fail("%s: %q is not a date", spanText(lit.Sp), lit.Value)
	}
	want := date.Resolve(e.opts.Now)
	return compareOrdered(op, cmpTime(got, want))
}

func (e *evaluator) inetCompare(op ast.Op, lit ast.Literal, raw any) Result {
	var addr netip.Addr
	switch v := raw.(type) {
	case netip.Addr:
		addr = v
	case string:
		a, err := netip.ParseAddr(strings.TrimSpace(v))
		if err != nil {
			// A source that holds an unparseable address has measured
			// something, but not an address. Unknown rather than false.
			return Unknown
		}
		addr = a
	default:
		return e.fail("%s: expected an address, got %T", spanText(lit.Sp), raw)
	}
	if op != ast.OpColon && op != ast.OpEq && op != ast.OpNe {
		return e.fail("%s: operator %q is not available on an address", spanText(lit.Sp), op)
	}
	if lit.IsWildcard() {
		return boolResult(globMatch(lit.Value, addr.String(), true))
	}
	if prefix, err := netip.ParsePrefix(strings.TrimSpace(lit.Value)); err == nil {
		// §4.4: `:` on inet is CIDR containment. `=` against a CIDR is the same
		// question — there is no other sensible reading of "equals a network".
		return boolResult(prefix.Contains(addr))
	}
	want, err := netip.ParseAddr(strings.TrimSpace(lit.Value))
	if err != nil {
		return e.fail("%s: %q is not an address or a CIDR", spanText(lit.Sp), lit.Value)
	}
	return boolResult(addr == want)
}

// classCompare implements §5.3 over the class PATH.
//
// `class:hardware` matches the class and every descendant, by prefix on the
// path; `class=server` matches that class only, by its last segment. The path
// is what the source returns, so one value answers both — and a tenant leaf
// subclass, whose path is a runtime row, is matched by its parent's subtree
// term exactly as it is in SQL.
func (e *evaluator) classCompare(op ast.Op, lit ast.Literal, raw any) Result {
	path, ok := toString(raw)
	if !ok {
		return e.fail("%s: expected a class path, got %T", spanText(lit.Sp), raw)
	}
	want := strings.ToLower(strings.TrimSpace(lit.Value))
	path = strings.ToLower(path)
	switch op {
	case ast.OpColon:
		return boolResult(path == want || strings.HasPrefix(path, want+"."))
	case ast.OpEq, ast.OpNe:
		key := path
		if i := strings.LastIndex(path, "."); i >= 0 {
			key = path[i+1:]
		}
		return boolResult(key == want)
	default:
		return e.fail("%s: operator %q is not available on a class", spanText(lit.Sp), op)
	}
}

// bandCompare turns a label into the ladder's numeric floor and compares the
// score against it — never against a threshold written here (§5.5). Without a
// ladder the comparison is refused, exactly as the translator refuses it.
func (e *evaluator) bandCompare(f ast.FieldRef, op ast.Op, lit ast.Literal, raw any) Result {
	if e.opts.Ladder == nil {
		return e.fail("%s: %q is a band and no ladder was supplied; a band comparison is never guessed", spanText(lit.Sp), f.Text)
	}
	score, ok := toFloat(raw)
	if !ok {
		return e.fail("%s: %q is a band and the source must give its numeric score, got %T", spanText(lit.Sp), f.Text, raw)
	}
	bands := e.opts.Ladder.Bands()
	want := strings.ToLower(strings.TrimSpace(lit.Value))
	idx := -1
	for i, b := range bands {
		if strings.EqualFold(b.Label, want) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return e.fail("%s: %q is not a band label", spanText(lit.Sp), lit.Value)
	}
	min := float64(bands[idx].Min)
	// Bands are supplied highest-first, so the band ABOVE this one is its
	// exclusive upper bound. The top band has none.
	max := math.Inf(1)
	if idx > 0 {
		max = float64(bands[idx-1].Min)
	}
	switch op {
	case ast.OpColon, ast.OpEq, ast.OpNe:
		return boolResult(score >= min && score < max)
	case ast.OpGte:
		return boolResult(score >= min)
	case ast.OpGt:
		return boolResult(score >= max)
	case ast.OpLt:
		return boolResult(score < min)
	case ast.OpLte:
		return boolResult(score < max)
	default:
		return e.fail("%s: operator %q is not available on a band", spanText(lit.Sp), op)
	}
}

func (e *evaluator) arrayCompare(op ast.Op, lit ast.Literal, raw any) Result {
	list, ok := raw.([]string)
	if !ok {
		return e.fail("%s: expected a string list, got %T", spanText(lit.Sp), raw)
	}
	if op != ast.OpColon && op != ast.OpEq && op != ast.OpNe {
		return e.fail("%s: operator %q is not available on a list", spanText(lit.Sp), op)
	}
	for _, v := range list {
		if lit.IsWildcard() {
			if globMatch(lit.Value, v, op == ast.OpColon) {
				return True
			}
			continue
		}
		if op == ast.OpColon && strings.EqualFold(v, lit.Value) {
			return True
		}
		if op != ast.OpColon && v == lit.Value {
			return True
		}
	}
	return False
}

func (e *evaluator) inSet(t *ast.InSet) Result {
	raw, ok := e.src.Field(t.Field)
	if !ok {
		return Unknown
	}
	out := False
	for _, v := range t.Values {
		switch e.compareValue(t.Field, ast.OpColon, v, raw) {
		case True:
			out = True
		case Unknown:
			if out == False {
				out = Unknown
			}
		}
		if out == True {
			break
		}
	}
	if t.Negated && out != Unknown {
		return negate(out)
	}
	return out
}

func (e *evaluator) rangeTerm(t *ast.Range) Result {
	raw, ok := e.src.Field(t.Field)
	if !ok {
		return Unknown
	}
	lo := e.compareValue(t.Field, ast.OpGte, t.Lo, raw)
	if lo != True {
		return lo
	}
	return e.compareValue(t.Field, ast.OpLte, t.Hi, raw)
}

func (e *evaluator) match(t *ast.Match) Result {
	raw, ok := e.src.Field(t.Field)
	if !ok {
		return Unknown
	}
	got, ok := toString(raw)
	if !ok {
		return e.fail("%s: a regex needs a string, got %T", spanText(t.Sp), raw)
	}
	// RE2 by construction: Go's regexp is RE2, which is why the language's
	// regex type is what it is. The validator already compiled this pattern;
	// compiling again here is cheap and keeps the evaluator self-contained.
	re, err := regexp.Compile(t.Regex)
	if err != nil {
		return e.fail("%s: %v", spanText(t.Sp), err)
	}
	return boolResult(re.MatchString(got))
}

func (e *evaluator) freeText(t *ast.FreeText) Result {
	needle := strings.ToLower(t.Value.Value)
	for _, hay := range e.src.FreeText() {
		if t.Value.IsWildcard() {
			if globMatch(t.Value.Value, hay, true) {
				return True
			}
			continue
		}
		if strings.Contains(strings.ToLower(hay), needle) {
			return True
		}
	}
	return False
}

// ---------------------------------------------------------------- helpers --

func boolResult(b bool) Result {
	if b {
		return True
	}
	return False
}

func negate(r Result) Result {
	switch r {
	case True:
		return False
	case False:
		return True
	default:
		return Unknown
	}
}

func compareOrdered(op ast.Op, cmp int) Result {
	switch op {
	case ast.OpColon, ast.OpEq:
		return boolResult(cmp == 0)
	case ast.OpNe:
		return boolResult(cmp != 0)
	case ast.OpLt:
		return boolResult(cmp < 0)
	case ast.OpLte:
		return boolResult(cmp <= 0)
	case ast.OpGt:
		return boolResult(cmp > 0)
	case ast.OpGte:
		return boolResult(cmp >= 0)
	}
	return Unknown
}

func cmpFloat(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func cmpTime(a, b time.Time) int {
	switch {
	case a.Before(b):
		return -1
	case a.After(b):
		return 1
	default:
		return 0
	}
}

func toString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case fmt.Stringer:
		return t.String(), true
	}
	return "", false
}

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case int:
		return float64(t), true
	case int32:
		return float64(t), true
	case int64:
		return float64(t), true
	}
	return 0, false
}

// globMatch implements `*` — any run of characters (§3) — without building a
// regex out of user text. `*` is the ONLY metacharacter; everything else is
// literal, which is what keeps `id.mac:aa:bb:*` from having to escape a colon.
func globMatch(pattern, value string, fold bool) bool {
	if fold {
		pattern = strings.ToLower(pattern)
		value = strings.ToLower(value)
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == value
	}
	if !strings.HasPrefix(value, parts[0]) {
		return false
	}
	value = value[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, part := range parts[1 : len(parts)-1] {
		i := strings.Index(value, part)
		if i < 0 {
			return false
		}
		value = value[i+len(part):]
	}
	return strings.HasSuffix(value, last) && len(value) >= len(last)
}

func spanText(s ast.Span) string {
	return fmt.Sprintf("at %d:%d", s.Start, s.End)
}
