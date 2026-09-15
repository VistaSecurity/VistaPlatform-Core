// Package validate checks a parsed query against the field catalogue and the
// safety rules, and resolves every field in place.
//
// It implements QUERY_LANGUAGE.md §6 — one rule, one error code — and is the
// only thing that decides a query is safe to translate. It fails closed: a node
// it cannot account for is untranslatable rather than passed through.
//
// Every rule here is mutation-tested in both polarities (validate_test.go): a
// rule must reject the thing it names AND accept the nearest legal query,
// because an over-strict guard is the same bug pointed the other way.
package validate

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode/utf8"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
	"github.com/vistasecurity/vistaplatform/shared/query/parser"
	"github.com/vistasecurity/vistaplatform/shared/query/queryerr"
)

// Options carry the caps from §6. Every one is a field rather than a constant
// so a deployment can tighten them, and so a test can prove a cap is load
// bearing by moving it.
type Options struct {
	// MaxBytes caps the query text (§6 query_too_long).
	MaxBytes int
	// TraversalBudget is the configured traversal budget (§5.6, default 3).
	TraversalBudget int
	// HardMaxTraversal is the ceiling no configuration may exceed (§5.6: 6).
	HardMaxTraversal int
	// MaxLeaves caps leaf terms.
	MaxLeaves int
	// MaxSubs caps sub-predicates and traversals together.
	MaxSubs int
	// MaxParenDepth caps parenthesis nesting in the source.
	MaxParenDepth int
	// MaxInValues caps the values in one `in (…)` list.
	MaxInValues int
	// MaxRegexLen caps a regex pattern's length.
	MaxRegexLen int
	// MaxRepetition caps a regex repetition count.
	MaxRepetition int
	// Ladder is the band ladder (§5.5). Without one, band fields are
	// untranslatable rather than guessed at.
	Ladder catalog.BandLadder
}

// DefaultOptions returns §6's caps and §5.6's default budget.
func DefaultOptions() Options {
	return Options{
		MaxBytes:         4096,
		TraversalBudget:  3,
		HardMaxTraversal: 6,
		MaxLeaves:        64,
		MaxSubs:          16,
		MaxParenDepth:    16,
		MaxInValues:      256,
		MaxRegexLen:      256,
		MaxRepetition:    1000,
	}
}

// WithLadder returns a copy of o carrying the given band ladder.
func (o Options) WithLadder(l catalog.BandLadder) Options {
	o.Ladder = l
	return o
}

// Validate checks a parsed query against the catalogue for target and resolves
// every field reference in place. The returned node is res.Root; it is only
// safe to translate when the error is nil.
func Validate(res *parser.Result, target string, cat catalog.Catalog, opts Options) (ast.Node, error) {
	v := &validator{cat: cat, opts: opts, src: res.Source}

	if n := len(res.Source); n > opts.MaxBytes {
		v.errs = v.errs.Add(queryerr.New(queryerr.CodeQueryTooLong,
			ast.Span{Start: 0, End: n},
			"query is %d bytes; the limit is %d", n, opts.MaxBytes))
		return res.Root, v.errs.OrNil()
	}
	if res.MaxParenDepth > opts.MaxParenDepth {
		v.errs = v.errs.Add(queryerr.New(queryerr.CodeTooManyClauses,
			ast.Span{Start: 0, End: len(res.Source)},
			"query nests %d levels of parentheses; the limit is %d", res.MaxParenDepth, opts.MaxParenDepth))
	}

	tgt, ok := catalog.FindTarget(cat, target)
	if !ok {
		v.errs = v.errs.Add(queryerr.New(queryerr.CodeUnknownField,
			ast.Span{Start: 0, End: len(res.Source)},
			"unknown target %q", target).
			WithSuggestion("targets: %s", strings.Join(catalog.TargetNames(cat), ", ")))
		return res.Root, v.errs.OrNil()
	}

	if res.Root != nil {
		v.node(res.Root, tgt)
		v.checkCounts(res.Root, res.Source)
		v.checkBudget(res.Root)
	}
	return res.Root, v.errs.Sorted().OrNil()
}

type validator struct {
	cat  catalog.Catalog
	opts Options
	src  string
	errs queryerr.List
}

func (v *validator) add(e *queryerr.Error) { v.errs = v.errs.Add(e) }

// node walks the tree, carrying the target the current scope resolves against.
func (v *validator) node(n ast.Node, tgt catalog.Target) {
	switch t := n.(type) {
	case *ast.And:
		for _, c := range t.Children {
			v.node(c, tgt)
		}
	case *ast.Or:
		for _, c := range t.Children {
			v.node(c, tgt)
		}
	case *ast.Not:
		v.node(t.Child, tgt)
	case *ast.Compare:
		v.compare(t, tgt)
	case *ast.InSet:
		v.inSet(t, tgt)
	case *ast.Range:
		v.rangeTerm(t, tgt)
	case *ast.Match:
		v.match(t, tgt)
	case *ast.Exists:
		if v.resolve(&t.Field, tgt) {
			v.translatableField(t.Field)
		}
	case *ast.FreeText:
		v.freeText(t, tgt)
	case *ast.Sub:
		v.sub(t, tgt)
	case *ast.Traverse:
		v.traverse(t, tgt)
	default:
		v.add(queryerr.New(queryerr.CodeUntranslatable, n.Span(),
			"the parser produced a node the validator does not know (%T)", n))
	}
}

// resolve fills in a field reference from the catalogue, or reports
// unknown_field with the closest match (§6).
func (v *validator) resolve(f *ast.FieldRef, tgt catalog.Target) bool {
	if f.Resolved {
		return true
	}
	resolved, err := v.cat.Resolve(tgt.Name, f.Segments)
	if err == nil {
		text, sp, segs, quoted := f.Text, f.Sp, f.Segments, f.Quoted
		*f = resolved
		f.Text, f.Sp, f.Segments, f.Quoted = text, sp, segs, quoted
		return true
	}
	var re *catalog.ResolveError
	if !asResolveError(err, &re) {
		v.add(queryerr.New(queryerr.CodeUnknownField, f.Sp, "%s", err.Error()))
		return false
	}
	v.add(v.unknownField(f, tgt, re))
	return false
}

// unknownField writes §10's worked error: name the span, name the closest
// match, and say where the other namespaces live.
func (v *validator) unknownField(f *ast.FieldRef, tgt catalog.Target, re *catalog.ResolveError) *queryerr.Error {
	base := queryerr.New(queryerr.CodeUnknownField, f.Sp,
		"no field %q on %s", f.Text, plural(tgt.Name))
	switch re.Reason {
	case catalog.ReasonEmptyKey:
		return queryerr.New(queryerr.CodeUnknownField, f.Sp,
			"%q is a namespace, not a field", f.Text).
			WithSuggestion("write the key after it, for example %s.<key>", re.Namespace)
	case catalog.ReasonUnknownKey:
		msg := queryerr.New(queryerr.CodeUnknownField, f.Sp,
			"no %s key %q is registered", re.Namespace, strings.Join(f.Segments[1:], "."))
		if near, ok := queryerr.Nearest(f.Text, catalog.FieldNames(v.cat, tgt.Name), 2); ok {
			return msg.WithSuggestion("did you mean %q?", near)
		}
		return msg
	}
	if near, ok := queryerr.Nearest(f.Text, catalog.FieldNames(v.cat, tgt.Name), 2); ok {
		return base.WithSuggestion("did you mean %q?", near)
	}
	// A misspelled relationship or collection reaches here rather than the
	// parser: `depands_on:(class:server)` is syntactically a value group over a
	// field called depands_on, because ':' is legal inside a bare value. The
	// name is the mistake, so the suggestion has to come from this side.
	if len(f.Segments) == 1 {
		if near, ok := queryerr.Nearest(f.Text, relationshipNames(v.cat), 2); ok {
			return base.WithSuggestion("did you mean the relationship %q? write %s:(…)", near, near)
		}
		if near, ok := queryerr.Nearest(f.Text, ast.Collections, 2); ok {
			return base.WithSuggestion("did you mean the collection %q? write %s:(…)", near, near)
		}
		return base.WithSuggestion(
			"class attributes are written \"attr.<name>\"; facts \"fact.<key>\"; identifiers \"id.<kind>\"; tags \"tag.<key>\"")
	}
	return base
}

// compare checks one field/operator/literal term.
func (v *validator) compare(t *ast.Compare, tgt catalog.Target) {
	if !v.resolve(&t.Field, tgt) {
		return
	}
	if !v.translatableField(t.Field) {
		return
	}
	if !catalog.OperatorAllowed(t.Field.Type, t.Op) {
		v.add(v.operatorError(t.Field, string(t.Op), t.Sp))
		return
	}
	v.literal(tgt, t.Field, t.Value, t.Op)
}

func (v *validator) inSet(t *ast.InSet, tgt catalog.Target) {
	if !v.resolve(&t.Field, tgt) {
		return
	}
	if !v.translatableField(t.Field) {
		return
	}
	if !catalog.InAllowed(t.Field.Type) {
		v.add(v.operatorError(t.Field, "in", t.Sp))
		return
	}
	if len(t.Values) > v.opts.MaxInValues {
		v.add(queryerr.New(queryerr.CodeTooManyClauses, t.Sp,
			"%d values in one list; the limit is %d", len(t.Values), v.opts.MaxInValues))
		return
	}
	for _, lit := range t.Values {
		v.literal(tgt, t.Field, lit, ast.OpColon)
	}
}

func (v *validator) rangeTerm(t *ast.Range, tgt catalog.Target) {
	if !v.resolve(&t.Field, tgt) {
		return
	}
	if !v.translatableField(t.Field) {
		return
	}
	if !catalog.RangeAllowed(t.Field.Type) {
		v.add(v.operatorError(t.Field, "[a to b]", t.Sp))
		return
	}
	v.literal(tgt, t.Field, t.Lo, ast.OpGte)
	v.literal(tgt, t.Field, t.Hi, ast.OpLte)
}

func (v *validator) match(t *ast.Match, tgt catalog.Target) {
	if !v.resolve(&t.Field, tgt) {
		return
	}
	if !v.translatableField(t.Field) {
		return
	}
	if !catalog.MatchAllowed(t.Field.Type) {
		v.add(v.operatorError(t.Field, "~", t.Sp))
		return
	}
	v.regex(t.Regex, t.Sp)
}

// regex enforces §6's three regex rules, plus §13 A6's dialect rule.
//
// The order matters. The subset scanner runs FIRST, because it is the check
// that knows about the database: the pattern is not run by Go, it is handed to
// Postgres `~`, which is ARE and not RE2 (see regex.go). Go's regexp compile
// stays as the second check — it is the "no backtracking by construction"
// guarantee, and it catches malformed patterns the subset scanner does not
// look for.
//
// The length cap is in RUNES, as §6's "256 chars" says. It used to be bytes,
// so a pattern of accented characters was refused at 128 of them.
func (v *validator) regex(pattern string, sp ast.Span) {
	if n := utf8.RuneCountInString(pattern); n > v.opts.MaxRegexLen {
		v.add(queryerr.New(queryerr.CodeRegexInvalid, sp,
			"pattern is %d characters; the limit is %d", n, v.opts.MaxRegexLen))
		return
	}
	reps, problem := checkRegexSubset(pattern)
	if problem != "" {
		v.add(queryerr.New(queryerr.CodeRegexInvalid, sp, "%s", problem).
			WithSuggestion("%s", regexSubsetHelp))
		return
	}
	if reps > v.opts.MaxRepetition {
		v.add(queryerr.New(queryerr.CodeRegexInvalid, sp,
			"pattern repeats %d times; the limit is %d", reps, v.opts.MaxRepetition))
		return
	}
	if _, err := regexp.Compile(pattern); err != nil {
		msg := err.Error()
		if se, ok := err.(*syntax.Error); ok {
			msg = string(se.Code)
		}
		v.add(queryerr.New(queryerr.CodeRegexInvalid, sp, "pattern is not a valid RE2 expression: %s", msg).
			WithSuggestion("%s", regexSubsetHelp))
	}
}

// regexSubsetHelp is the one description of the dialect, so every regex error
// points at the same rules. It replaces a suggestion that told users to write
// "(?i)" for a case-insensitive match without saying where — and mid-pattern
// Postgres raises "invalid regular expression" at query time.
const regexSubsetHelp = "the regex dialect is the common subset of RE2 and Postgres: " +
	`literals, ".", [...] classes, \d \D \w \W \s \S, escaped metacharacters, ` +
	`"^" and "$", (...) and (?:...) groups, * + ? {n} {n,} {n,m}, "|", ` +
	`and "(?i)" at the START of the pattern`

func (v *validator) freeText(t *ast.FreeText, tgt catalog.Target) {
	// §5.4 defines free text over an asset's display name, hostname,
	// identifier values and tags. No other target has that column set, so a
	// free-text term there is untranslatable rather than silently narrowed.
	if !tgt.FreeTextable {
		v.add(queryerr.New(queryerr.CodeUntranslatable, t.Sp,
			"a free-text term has no meaning on %s; name a field", plural(tgt.Name)).
			WithSuggestion("free text searches an asset's name, hostname, identifiers and tags"))
	}
}

func (v *validator) sub(t *ast.Sub, tgt catalog.Target) {
	inner, ok := catalog.CollectionTarget[t.Collection]
	if !ok {
		v.add(queryerr.New(queryerr.CodeUntranslatable, t.Sp,
			"unknown collection %q", t.Collection))
		return
	}
	if !contains(tgt.Subs, t.Collection) {
		v.add(queryerr.New(queryerr.CodeUntranslatable, t.Sp,
			"%q is not reachable from %s", t.Collection, plural(tgt.Name)).
			WithSuggestion("from %s you can reach: %s", plural(tgt.Name), strings.Join(tgt.Subs, ", ")))
		return
	}
	innerTgt, ok := catalog.FindTarget(v.cat, inner)
	if !ok {
		v.add(queryerr.New(queryerr.CodeUntranslatable, t.Sp,
			"the catalogue has no target for collection %q", t.Collection))
		return
	}
	if t.Predicate != nil {
		v.node(t.Predicate, innerTgt)
	}
}

func (v *validator) traverse(t *ast.Traverse, tgt catalog.Target) {
	if !tgt.Traversable {
		v.add(queryerr.New(queryerr.CodeUntranslatable, t.Sp,
			"relationships join assets; traversal is not available on %s", plural(tgt.Name)).
			WithSuggestion("wrap it: asset:(%s:(…))", t.Name))
		return
	}
	if t.Form != ast.FormAny {
		if !v.knownRelationship(t.Name) {
			names := relationshipNames(v.cat)
			e := queryerr.New(queryerr.CodeUnknownValue, t.Sp, "unknown relationship %q", t.Name)
			if near, ok := queryerr.Nearest(t.Name, names, 2); ok {
				v.add(e.WithSuggestion("did you mean %q?", near))
			} else {
				v.add(e.WithSuggestion("relationships: %s", strings.Join(names, ", ")))
			}
			return
		}
		if t.Form == ast.FormExplicit && !ast.IsRelationshipType(t.Name) {
			rel, _ := ast.LookupRelationship(t.Name)
			v.add(queryerr.New(queryerr.CodeUnknownValue, t.Sp,
				"%q is a reverse label; the rel(…) form takes a canonical relationship type", t.Name).
				WithSuggestion("write rel(%s, in, …) or use the label on its own: %s:(…)", rel.Type, t.Name))
			return
		}
	}
	// There is deliberately no `t.Depth < 1` check here. The hop count is
	// grammar, not vocabulary: the parser refuses anything but a positive whole
	// number (parser.intArg) and defaults to 1 when the argument is absent, so
	// a Traverse node cannot reach the validator with a depth below one. A
	// second copy of the rule here could only ever disagree with the first, and
	// an unreachable branch reads as a check that is doing something.
	// TestHopCountMustBePositive pins it where it lives.
	v.node(t.Predicate, tgt)
}

func (v *validator) knownRelationship(name string) bool {
	for _, r := range v.cat.RelationshipNames() {
		if strings.EqualFold(r.Name, name) {
			return true
		}
	}
	return false
}

func relationshipNames(c catalog.Catalog) []string {
	rels := c.RelationshipNames()
	out := make([]string, 0, len(rels))
	for _, r := range rels {
		out = append(out, r.Name)
	}
	return out
}

// translatableField rejects a resolved field the translator could not build SQL
// for, before it gets there (§6 untranslatable).
func (v *validator) translatableField(f ast.FieldRef) bool {
	if !catalog.KnownType(f.Type) {
		v.add(queryerr.New(queryerr.CodeUntranslatable, f.Sp,
			"field %q has no usable type in the catalogue", f.Text))
		return false
	}
	if f.Type == ast.TypeVersion && f.Accessor.SortColumn == "" {
		v.add(queryerr.New(queryerr.CodeUntranslatable, f.Sp,
			"field %q is a version with no normalised sort key, and a lexical comparison is forbidden", f.Text))
		return false
	}
	if f.Type == ast.TypeBand && v.opts.Ladder == nil {
		v.add(queryerr.New(queryerr.CodeUntranslatable, f.Sp,
			"field %q is a band and no band ladder was supplied", f.Text))
		return false
	}
	return true
}

func (v *validator) operatorError(f ast.FieldRef, op string, sp ast.Span) *queryerr.Error {
	e := queryerr.New(queryerr.CodeOperatorNotAllowed, sp,
		"%q is a %s field and does not accept %q", f.Text, f.Type, op)
	return e.WithSuggestion("%s accepts: %s", f.Type, strings.Join(catalog.OperatorsFor(f.Type), " "))
}

// literal checks a value against the field's type (§6 type_mismatch) and
// against any closed value set (§6 unknown_value).
func (v *validator) literal(tgt catalog.Target, f ast.FieldRef, lit ast.Literal, op ast.Op) {
	if lit.IsBareStar() {
		// `field:*` is the "present at all" spelling and is legal on every
		// type; there is nothing to type-check.
		if op != ast.OpColon {
			v.add(queryerr.New(queryerr.CodeTypeMismatch, lit.Sp,
				"a bare %q means \"present at all\" and only works with %q", "*", ":").
				WithSuggestion("write exists(%s)", f.Text))
		}
		return
	}
	if lit.IsWildcard() {
		if !catalog.WildcardAllowed(f.Type) {
			v.add(queryerr.New(queryerr.CodeOperatorNotAllowed, lit.Sp,
				"%q is a %s field and does not accept a %q wildcard", f.Text, f.Type, "*").
				WithSuggestion("%s accepts: %s", f.Type, strings.Join(catalog.OperatorsFor(f.Type), " ")))
			return
		}
		if op.Ordering() {
			v.add(queryerr.New(queryerr.CodeTypeMismatch, lit.Sp,
				"a wildcard cannot be ordered against with %q", op))
		}
		return
	}

	switch f.Type {
	case ast.TypeNumber:
		if _, ok := ast.ParseNumber(lit.Value); !ok {
			v.add(v.typeMismatch(f, lit, "a number"))
		}
	case ast.TypeTimestamp:
		if _, ok := ast.ParseDate(lit.Value); !ok {
			v.add(v.typeMismatch(f, lit, "a date").
				WithSuggestion("write 2026-09-11, 2026-09-11T14:30:00Z, now, or now-30d"))
		}
	case ast.TypeBoolean:
		if _, ok := ast.ParseBool(lit.Value); !ok {
			v.add(v.typeMismatch(f, lit, "true or false"))
		}
	case ast.TypeUUID:
		if !ast.ParseUUID(lit.Value) {
			e := v.typeMismatch(f, lit, "a uuid")
			// `id:"aa:bb:cc:dd:ee:ff"` was the cheat sheet's spelling for "an
			// identifier of any kind" before a bare `id` became the row's own
			// uuid (§13 A1). Anyone carrying the old form lands here, so say
			// where it went — asked of the catalogue, not hard-coded, so a
			// catalogue without the any-kind form says nothing.
			if alt, ok := v.anyIdentifierField(tgt, f); ok {
				e = e.WithSuggestion("for an identifier of any kind write %s:%s", alt, ast.QuoteValue(lit.Value))
			}
			v.add(e)
		}
	case ast.TypeInet:
		if _, ok := ast.ParseInet(lit.Value); !ok {
			v.add(v.typeMismatch(f, lit, "an address or a CIDR block"))
		}
	case ast.TypeVersion:
		if !ast.LooksLikeVersion(lit.Value) {
			v.add(v.typeMismatch(f, lit, "a version"))
		}
	case ast.TypeClass:
		if _, ok := v.cat.ClassExists(lit.Value); !ok {
			e := queryerr.New(queryerr.CodeUnknownValue, lit.Sp, "no class %q", lit.Value)
			if near, ok := queryerr.NearestValue(lit.Value, v.classNames()); ok {
				e = e.WithSuggestion("did you mean %q?", near)
			}
			v.add(e)
		}
		return
	case ast.TypeBand:
		v.band(tgt, f, lit, op)
		return
	}
	// Every other type may additionally carry a closed value set.
	v.enum(f, lit)
}

// band checks a band label against the ladder, and not_assessed against the
// field's coverage column (§5.2) and the operator it was written with.
func (v *validator) band(tgt catalog.Target, f ast.FieldRef, lit ast.Literal, op ast.Op) {
	if strings.EqualFold(lit.Value, catalog.NotAssessed) {
		if f.Accessor.AssessedBy == "" {
			v.add(queryerr.New(queryerr.CodeUnknownValue, lit.Sp,
				"%q does not record who assessed it, so %q has no meaning for it", f.Text, catalog.NotAssessed).
				WithSuggestion("bands: %s", strings.Join(catalog.BandLabels(v.opts.Ladder, false), ", ")))
			return
		}
		// not_assessed is NOT a rung of the ladder — it is the absence of a
		// score — so it cannot be ordered against or used as a range bound.
		// `risk < not_assessed` used to validate and then return every
		// unassessed asset, because the translator ignored the operator; and
		// `risk:[not_assessed to high]` validated and then failed
		// `untranslatable`, a code §6 reserves for a parser bug. Refuse both
		// here, where the error can say what to write instead.
		if op != ast.OpColon && op != ast.OpEq && op != ast.OpNe {
			v.add(queryerr.New(queryerr.CodeOperatorNotAllowed, lit.Sp,
				"%q is not a rung of the ladder, so it cannot be used with %q", catalog.NotAssessed, op).
				WithSuggestion("write %s:%s, or order against a band: %s",
					f.Text, catalog.NotAssessed,
					strings.Join(catalog.BandLabels(v.opts.Ladder, false), ", ")))
		}
		return
	}
	if _, ok := catalog.BandIndex(v.opts.Ladder, lit.Value); ok {
		return
	}
	e := queryerr.New(queryerr.CodeTypeMismatch, lit.Sp,
		"%q is a band (%s)", f.Text,
		strings.Join(catalog.BandLabels(v.opts.Ladder, f.Accessor.AssessedBy != ""), ", "))
	if _, isNum := ast.ParseNumber(lit.Value); isNum {
		if numeric, ok := v.numericTwin(tgt, f); ok {
			e = e.WithSuggestion("for the numeric score use %q", numeric+" "+string(ast.OpGte)+" "+lit.Value)
		}
	} else if near, ok := queryerr.NearestValue(lit.Value, catalog.BandLabels(v.opts.Ladder, true)); ok {
		e = e.WithSuggestion("did you mean %q?", near)
	}
	v.add(e)
}

// anyIdentifierField reports the catalogue's spelling for "an identifier of any
// kind", when the field being complained about is the bare row id that spelling
// used to collide with (§13 A1).
func (v *validator) anyIdentifierField(tgt catalog.Target, f ast.FieldRef) (string, bool) {
	if !strings.EqualFold(f.Text, "id") {
		return "", false
	}
	for _, cand := range v.cat.Fields(tgt.Name) {
		if cand.Accessor.Kind == ast.AccessorIdentifierAny {
			return cand.Name, true
		}
	}
	return "", false
}

// numericTwin finds the number-typed field that shares a band field's column,
// so "risk >= 70" can suggest "risk_score >= 70" without hard-coding the pair.
func (v *validator) numericTwin(tgt catalog.Target, f ast.FieldRef) (string, bool) {
	for _, cand := range v.cat.Fields(tgt.Name) {
		if cand.Type == ast.TypeNumber && cand.Accessor.Column == f.Accessor.Column {
			return cand.Name, true
		}
	}
	return "", false
}

// enum checks a closed value set.
func (v *validator) enum(f ast.FieldRef, lit ast.Literal) {
	values, ok := v.cat.EnumValues(f)
	if !ok {
		return
	}
	for _, val := range values {
		if strings.EqualFold(val, lit.Value) {
			return
		}
	}
	e := queryerr.New(queryerr.CodeUnknownValue, lit.Sp,
		"%q is not a value of %q", lit.Value, f.Text)
	if near, ok := queryerr.NearestValue(lit.Value, values); ok {
		e = e.WithSuggestion("did you mean %q?", near)
	} else {
		e = e.WithSuggestion("values: %s", strings.Join(values, ", "))
	}
	v.add(e)
}

func (v *validator) typeMismatch(f ast.FieldRef, lit ast.Literal, want string) *queryerr.Error {
	return queryerr.New(queryerr.CodeTypeMismatch, lit.Sp,
		"%q is a %s field; %q is not %s", f.Text, f.Type, lit.Value, want)
}

// classNames returns the class keys a catalogue publishes, if it publishes
// them. Catalog only exposes class existence, so a "did you mean" for a class
// needs the optional extension below; without it the unknown class is still
// reported, just without a suggestion.
func (v *validator) classNames() []string {
	if l, ok := v.cat.(ClassLister); ok {
		return l.ClassKeys()
	}
	return nil
}

// ClassLister is an optional extension a catalogue may implement so the
// validator can suggest a near-miss class key. Without it, an unknown class is
// still reported, just without a "did you mean".
type ClassLister interface {
	ClassKeys() []string
}

// checkCounts enforces the leaf, sub-predicate and traversal caps (§6).
func (v *validator) checkCounts(root ast.Node, src string) {
	leaves, subs := 0, 0
	ast.Walk(root, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.Compare, *ast.InSet, *ast.Range, *ast.Match, *ast.Exists, *ast.FreeText:
			leaves++
		case *ast.Sub, *ast.Traverse:
			subs++
		}
		return true
	})
	whole := ast.Span{Start: 0, End: len(src)}
	if leaves > v.opts.MaxLeaves {
		v.add(queryerr.New(queryerr.CodeTooManyClauses, whole,
			"query has %d terms; the limit is %d", leaves, v.opts.MaxLeaves))
	}
	if subs > v.opts.MaxSubs {
		v.add(queryerr.New(queryerr.CodeTooManyClauses, whole,
			"query has %d sub-predicates and traversals; the limit is %d", subs, v.opts.MaxSubs))
	}
}

// checkBudget enforces the traversal budget: the sum of declared depths along
// the deepest nested path (§5.6).
func (v *validator) checkBudget(root ast.Node) {
	budget := v.opts.TraversalBudget
	if budget > v.opts.HardMaxTraversal {
		budget = v.opts.HardMaxTraversal
	}
	cost, deepest := traversalCost(root)
	if cost <= budget {
		return
	}
	sp := root.Span()
	if deepest != nil {
		sp = deepest.Span()
	}
	e := queryerr.New(queryerr.CodeDepthExceeded, sp,
		"traversal is %d hops deep; the budget is %d", cost, budget)
	if v.opts.TraversalBudget > v.opts.HardMaxTraversal {
		e = e.WithSuggestion("the configured budget of %d is above the hard maximum of %d",
			v.opts.TraversalBudget, v.opts.HardMaxTraversal)
	} else {
		e = e.WithSuggestion("the budget is the sum of declared depths along the deepest nested path")
	}
	v.add(e)
}

// traversalCost returns the budget a tree consumes and the traversal that tops
// it, for the error span.
func traversalCost(n ast.Node) (int, ast.Node) {
	switch t := n.(type) {
	case nil:
		return 0, nil
	case *ast.And:
		return maxCost(t.Children)
	case *ast.Or:
		return maxCost(t.Children)
	case *ast.Not:
		return traversalCost(t.Child)
	case *ast.Sub:
		return traversalCost(t.Predicate)
	case *ast.Traverse:
		inner, _ := traversalCost(t.Predicate)
		return t.Depth + inner, t
	}
	return 0, nil
}

func maxCost(children []ast.Node) (int, ast.Node) {
	best, node := 0, ast.Node(nil)
	for _, c := range children {
		if cost, deepest := traversalCost(c); cost > best {
			best, node = cost, deepest
		}
	}
	return best, node
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func plural(target string) string {
	switch target {
	case "asset":
		return "assets"
	case "certificate":
		return "certificates"
	case "finding":
		return "findings"
	case "endpoint":
		return "endpoints"
	case "identifier":
		return "identifiers"
	case "relationship":
		return "relationships"
	case "observation":
		return "observations"
	}
	return target + "s"
}

func asResolveError(err error, out **catalog.ResolveError) bool {
	re, ok := err.(*catalog.ResolveError)
	if ok {
		*out = re
	}
	return ok
}
