// Package sql translates a validated query into a parameterised Postgres WHERE
// clause.
//
// It emits only the five shapes of QUERY_LANGUAGE.md §7.2 — column compare,
// jsonb compare, EXISTS over a child, depth-bounded recursive CTE, free text —
// over the DATA_MODEL.md tables. Anything else is untranslatable and refused.
//
// Two invariants hold for every query, and both are tested:
//
//  1. Every value that came from the query text is a bind parameter. The
//     generated SQL contains no quoted literal at all; identifiers come from
//     the catalogue, never from user text.
//  2. No tenant_id predicate is emitted, ever. Every statement runs in a
//     transaction that has already executed SET LOCAL app.tenant_id, so RLS
//     scopes it. A predicate here would make a bug in this package look like
//     an isolation control (§7.2).
//
// The caller composes the outer SELECT; this package returns the WHERE clause
// and its arguments.
package sql

import (
	"strconv"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
	"github.com/vistasecurity/vistaplatform/shared/query/queryerr"
)

// Options configure a translation.
type Options struct {
	// Ladder is the band ladder every band comparison is generated from
	// (§5.5). In production this is models.RiskBands.
	Ladder catalog.BandLadder
	// Now is the statement timestamp. Relative dates resolve against it once
	// per query (§5.5), so two terms in one query always agree.
	Now time.Time
	// ParamStart is the number of the first bind parameter, for a caller that
	// has already bound some of its own. Zero means 1.
	ParamStart int
	// OuterAlias is the alias the caller gives the target table in its FROM.
	// Empty means the catalogue's Target.Alias, which is what a caller writing
	// the SELECT from Translate's documentation will have used.
	//
	// It exists because the returned clause NAMES that alias — `a.hostname`,
	// `e1.asset_id = a.id` — so a caller whose FROM says `FROM assets asset`
	// needs a way to say so, rather than discovering the mismatch as a SQL
	// error at run time.
	OuterAlias string
	// AliasPrefix is prepended to every alias this package generates (a1, e2,
	// af3 …). A caller composing two translations into one statement, or
	// splicing one into a query with aliases of its own, gives each a distinct
	// prefix so they cannot collide. Empty is the default and is right for a
	// caller that writes a plain SELECT.
	AliasPrefix string
}

// Translate renders a validated node as a WHERE clause over target.
//
// The returned clause is safe to interpolate into a SELECT; args are the bind
// parameters, in order. An empty query yields TRUE, which under RLS is "every
// row this tenant may see".
//
// # The alias contract
//
// The clause REFERS TO the target table by an alias, and the caller's FROM must
// use the same one or the statement will not compile:
//
//	tgt, _ := catalog.FindTarget(cat, "asset")     // tgt.Alias is "a"
//	where, args, _ := sql.Translate(root, "asset", cat, opts)
//	db.Query("SELECT * FROM assets "+tgt.Alias+" WHERE "+where, args...)
//
// Options.OuterAlias chooses a different one. Every OTHER alias in the clause
// is generated here and numbered, so it cannot collide with the outer one;
// Options.AliasPrefix separates two translations spliced into one statement.
//
// The statement must already have run `SET LOCAL app.tenant_id`: this package
// emits no tenant predicate, by design (§7.2).
func Translate(root ast.Node, target string, cat catalog.Catalog, opts Options) (string, []any, error) {
	if opts.ParamStart <= 0 {
		opts.ParamStart = 1
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	b := &builder{cat: cat, opts: opts}

	tgt, ok := catalog.FindTarget(cat, target)
	if !ok {
		return "", nil, queryerr.List{queryerr.New(queryerr.CodeUntranslatable,
			ast.Span{}, "unknown target %q", target)}
	}
	if tgt.InMemory {
		return "", nil, queryerr.List{queryerr.New(queryerr.CodeUntranslatable, ast.Span{},
			"the %q target has no table: it is evaluated against an in-flight discovery, not in SQL", tgt.Name).
			WithSuggestion("approval rules run this query in the identification engine")}
	}
	if root == nil {
		return "TRUE", nil, nil
	}

	clause := b.node(root, b.rootScope(tgt))
	if len(b.errs) > 0 {
		return "", nil, b.errs.Sorted()
	}
	return clause, b.args, nil
}

type builder struct {
	cat    catalog.Catalog
	opts   Options
	args   []any
	nextID int
	errs   queryerr.List
}

// scope is the SQL context a node is translated in: which table aliases its
// fields resolve to.
type scope struct {
	target catalog.Target
	// self is the alias of the target's own table.
	self string
	// rels holds extra relation aliases keyed by ast.Accessor.Rel, for shapes
	// that join more than one table (software installs and their products).
	rels map[string]string
	// assetAlias is the alias of the asset a shape is correlated to. It is
	// empty when the current row has no single owning asset in scope, and the
	// fact, identifier, tag and free-text shapes need it.
	assetAlias string
}

func (b *builder) rootScope(t catalog.Target) scope {
	self := t.Alias
	if b.opts.OuterAlias != "" {
		self = b.opts.OuterAlias
	}
	sc := scope{target: t, self: self, rels: map[string]string{}}
	if t.Name == "asset" {
		sc.assetAlias = self
	}
	return sc
}

// alias returns a fresh, code-supplied table alias. Every alias in the output
// comes from here or from Options.OuterAlias — never from user text, which is
// what keeps a user-supplied identifier out of SQL (§7.1).
func (b *builder) alias(prefix string) string {
	b.nextID++
	return b.opts.AliasPrefix + prefix + strconv.Itoa(b.nextID)
}

// param binds a value and returns its placeholder.
func (b *builder) param(v any) string {
	b.args = append(b.args, v)
	return "$" + strconv.Itoa(b.opts.ParamStart+len(b.args)-1)
}

func (b *builder) fail(sp ast.Span, format string, args ...any) string {
	b.errs = b.errs.Add(queryerr.New(queryerr.CodeUntranslatable, sp, format, args...))
	return "FALSE"
}

// node dispatches on node type. Every branch returns a self-contained boolean
// SQL expression, parenthesised where precedence needs it.
func (b *builder) node(n ast.Node, sc scope) string {
	switch t := n.(type) {
	case *ast.And:
		return b.join(t.Children, " AND ", sc)
	case *ast.Or:
		return b.join(t.Children, " OR ", sc)
	case *ast.Not:
		// Not{Sub} is NOT EXISTS, which is the shape §7.2 names and which
		// reads as the set operation §5.1 describes.
		if sub, ok := t.Child.(*ast.Sub); ok {
			return "NOT " + b.sub(sub, sc)
		}
		return "NOT (" + b.node(t.Child, sc) + ")"
	case *ast.Compare:
		return b.compare(t, sc)
	case *ast.InSet:
		return b.inSet(t, sc)
	case *ast.Range:
		return b.rangeTerm(t, sc)
	case *ast.Match:
		return b.match(t, sc)
	case *ast.Exists:
		return b.exists(t.Field, t.Sp, sc)
	case *ast.FreeText:
		return b.freeText(t, sc)
	case *ast.Sub:
		return b.sub(t, sc)
	case *ast.Traverse:
		return b.traverse(t, sc)
	}
	return b.fail(n.Span(), "no SQL shape for node %T", n)
}

func (b *builder) join(children []ast.Node, sep string, sc scope) string {
	parts := make([]string, 0, len(children))
	for _, c := range children {
		parts = append(parts, b.node(c, sc))
	}
	return "(" + strings.Join(parts, sep) + ")"
}

// ------------------------------------------------------------ leaf terms --

func (b *builder) compare(t *ast.Compare, sc scope) string {
	if !t.Field.Resolved {
		return b.unresolved(t.Field, t.Sp)
	}
	return b.fieldPredicate(sc, t.Field, t.Op, t.Value, t.Sp)
}

// inSet is the list form of ":" — §3's cheat sheet equates `field in (a, b)`
// with `field:(a or b)`, so both produce the same SQL.
func (b *builder) inSet(t *ast.InSet, sc scope) string {
	if !t.Field.Resolved {
		return b.unresolved(t.Field, t.Sp)
	}
	parts := make([]string, 0, len(t.Values))
	for _, v := range t.Values {
		parts = append(parts, b.fieldPredicate(sc, t.Field, ast.OpColon, v, t.Sp))
	}
	clause := "(" + strings.Join(parts, " OR ") + ")"
	if t.Negated {
		return "NOT " + clause
	}
	return clause
}

func (b *builder) rangeTerm(t *ast.Range, sc scope) string {
	if !t.Field.Resolved {
		return b.unresolved(t.Field, t.Sp)
	}
	if t.Field.Type == ast.TypeBand {
		return b.bandRange(sc, t)
	}
	lo := b.fieldPredicate(sc, t.Field, ast.OpGte, t.Lo, t.Sp)
	hi := b.fieldPredicate(sc, t.Field, ast.OpLte, t.Hi, t.Sp)
	return "(" + lo + " AND " + hi + ")"
}

func (b *builder) match(t *ast.Match, sc scope) string {
	if !t.Field.Resolved {
		return b.unresolved(t.Field, t.Sp)
	}
	pattern := t.Regex
	return b.overValue(sc, t.Field, t.Sp, func(e expr) string {
		// "~" is case-sensitive RE2; (?i) inside the pattern is how a user
		// asks for otherwise (§2). Postgres "~" accepts the same constructs
		// the validator has already checked as RE2.
		return "(" + e.sql + " ~ " + b.param(pattern) + ")"
	})
}

// exists is `exists(field)`: present at all. For a column that is IS NOT NULL;
// for the row-shaped accessors it is the child EXISTS with no inner predicate.
//
// It reads the RAW text of a jsonb or fact value, before any type cast. The
// cast is guarded (guardedCast), so a value that does not match its declared
// type reads as NULL — which is right for a comparison and wrong for a presence
// test: `attr.cpu_count:*` answered FALSE for a stored "10.0.19045" that the
// catalogue declares numeric, and `not exists(attr.cpu_count)` answered TRUE.
// "We have a value and cannot parse it" is not "we have no value".
func (b *builder) exists(f ast.FieldRef, sp ast.Span, sc scope) string {
	if !f.Resolved {
		return b.unresolved(f, sp)
	}
	return b.overValueRaw(sc, f, sp, func(e expr) string {
		if f.Type == ast.TypeKeywordArray {
			return "(coalesce(array_length(" + e.sql + ", 1), 0) > 0)"
		}
		return "(" + e.sql + " IS NOT NULL)"
	})
}

// freeText is §7.2 shape 5: ILIKE over the §5.4 column set, unioned with an
// EXISTS over asset_identifiers and the tag map. Nothing else — notably not
// description and not finding summaries, so free text cannot silently widen.
func (b *builder) freeText(t *ast.FreeText, sc scope) string {
	if sc.assetAlias == "" || !sc.target.FreeTextable {
		return b.fail(t.Sp, "a free-text term has no column set on %q", sc.target.Name)
	}
	a := sc.assetAlias
	pattern := b.param("%" + escapeLike(t.Value.Value) + "%")
	ident := b.alias("ai")
	tag := b.alias("tg")
	return "(" + a + ".display_name ILIKE " + pattern +
		" OR " + a + ".hostname ILIKE " + pattern +
		" OR EXISTS (SELECT 1 FROM asset_identifiers " + ident +
		" WHERE " + ident + ".asset_id = " + a + ".id AND " + ident + ".value ILIKE " + pattern + ")" +
		" OR EXISTS (SELECT 1 FROM jsonb_each_text(" + a + ".tags) AS " + tag + "(key, value)" +
		" WHERE " + tag + ".key ILIKE " + pattern + " OR " + tag + ".value ILIKE " + pattern + "))"
}

func (b *builder) unresolved(f ast.FieldRef, sp ast.Span) string {
	return b.fail(sp, "field %q was never resolved; validate before translating", f.Text)
}

// ---------------------------------------------------------- field shapes --

// expr is a value expression plus the alias it was read from, so a sibling
// column (a class path, a band label, a version sort key) can be addressed
// without re-parsing the SQL string.
type expr struct {
	alias string
	sql   string
}

// sibling renders another column of the same row.
func (e expr) sibling(column string) string { return e.alias + "." + column }

// fieldPredicate is the entry point for every field term: it picks the shape
// from the accessor, then the comparison from the type.
func (b *builder) fieldPredicate(sc scope, f ast.FieldRef, op ast.Op, lit ast.Literal, sp ast.Span) string {
	// `field:*` is "present at all" whatever the shape (§3 cheat sheet).
	if lit.IsBareStar() && op == ast.OpColon {
		return b.exists(f, sp, sc)
	}
	// `!=` on a row-shaped accessor has to negate the whole EXISTS, not the
	// comparison inside it. `EXISTS (… value <> $1)` is "this asset has SOME
	// identifier that is not X", which every asset with two identifiers
	// satisfies — so `id.mac != aa:bb…` matched the very asset it was meant to
	// exclude. The question is "no row matches", which is NOT EXISTS.
	//
	// Inside it the comparison is `=`, not `:`: §2 makes `!=` case-sensitive,
	// so its negation must be too.
	if op == ast.OpNe && rowShaped(f.Accessor) {
		return "NOT " + b.overValue(sc, f, sp, func(e expr) string {
			return b.comparison(e, f, ast.OpEq, lit, sp)
		})
	}
	return b.overValue(sc, f, sp, func(e expr) string {
		return b.comparison(e, f, op, lit, sp)
	})
}

// rowShaped reports whether an accessor reads a value from ROWS of a child
// table rather than from the current row. For those, a predicate is an EXISTS
// and its negation is NOT EXISTS.
//
// AccessorFact is not here: since §13 A4 it is a scalar subquery over the
// single reconciled row, so `<>` against it is already correct — and stays
// three-valued, which NOT EXISTS is not.
func rowShaped(a ast.Accessor) bool {
	switch a.Kind {
	case ast.AccessorIdentifier, ast.AccessorIdentifierAny, ast.AccessorTagAny:
		return true
	case ast.AccessorDerived:
		return derivedRowShaped(a.Derived)
	}
	return false
}

// overValue builds the SQL context a field's value lives in and applies inner
// to it. A column or jsonb field is an expression in the current row; a fact,
// identifier or tag field is a row in a child table, so the predicate is
// wrapped in an EXISTS — shape 3 of §7.2 — around the same inner comparison.
func (b *builder) overValue(sc scope, f ast.FieldRef, sp ast.Span, inner func(expr) string) string {
	return b.overValueMode(sc, f, sp, false, inner)
}

// overValueRaw is overValue with the declared-type cast skipped, for a presence
// test — see exists.
func (b *builder) overValueRaw(sc scope, f ast.FieldRef, sp ast.Span, inner func(expr) string) string {
	return b.overValueMode(sc, f, sp, true, inner)
}

func (b *builder) overValueMode(sc scope, f ast.FieldRef, sp ast.Span, raw bool, inner func(expr) string) string {
	// A field that lives on a relation the current shape does not join — the
	// product behind a software install, when software_install is the target
	// rather than a sub-predicate — is reached by its own EXISTS, so the
	// clause stays self-contained whatever FROM the caller writes.
	if f.Accessor.Rel != "" {
		if _, joined := sc.rels[f.Accessor.Rel]; !joined {
			return b.overRelation(sc, f, sp, raw, inner)
		}
	}
	switch f.Accessor.Kind {
	case ast.AccessorColumn, ast.AccessorJSONB:
		e, ok := b.scalarExpr(sc, f, sp, raw)
		if !ok {
			return "FALSE"
		}
		return inner(e)

	case ast.AccessorFact:
		a, ok := b.assetAlias(sc, f, sp)
		if !ok {
			return "FALSE"
		}
		if raw {
			// Presence is a question about the ROWS: `exists(fact.x)` asks
			// whether anybody recorded the key at all, so it stays an EXISTS
			// over the raw rows with no reconciliation and no cast (§13 A4).
			al := b.alias("af")
			return "EXISTS (SELECT 1 FROM asset_facts " + al +
				" WHERE " + al + ".asset_id = " + a + ".id" +
				" AND " + al + ".key = " + b.param(f.Accessor.Key) +
				" AND " + inner(b.factValue(al)) + ")"
		}
		return b.factComparison(a, f, sp, inner)

	case ast.AccessorIdentifier, ast.AccessorIdentifierAny:
		a, ok := b.assetAlias(sc, f, sp)
		if !ok {
			return "FALSE"
		}
		al := b.alias("ai")
		clause := "EXISTS (SELECT 1 FROM asset_identifiers " + al +
			" WHERE " + al + ".asset_id = " + a + ".id"
		if f.Accessor.Kind == ast.AccessorIdentifier {
			clause += " AND " + al + ".kind = " + b.param(f.Accessor.Key)
		}
		return clause + " AND " + inner(expr{alias: al, sql: al + "." + f.Accessor.Column}) + ")"

	case ast.AccessorDerived:
		return b.derivedOver(sc, f, sp, raw, inner)

	case ast.AccessorTagAny:
		a, ok := b.assetAlias(sc, f, sp)
		if !ok {
			return "FALSE"
		}
		al := b.alias("tg")
		// Bare `tag:x` matches a key or a value, which is what §8's
		// tags_any_of migration needs; `tag.<key>:v` is the jsonb shape.
		return "EXISTS (SELECT 1 FROM jsonb_each_text(" + a + "." + f.Accessor.JSONColumn +
			") AS " + al + "(key, value) WHERE " +
			inner(expr{alias: al, sql: al + ".key"}) + " OR " +
			inner(expr{alias: al, sql: al + ".value"}) + ")"
	}
	return b.fail(sp, "field %q has accessor kind %q, which has no SQL shape", f.Text, f.Accessor.Kind)
}

// factValue renders asset_facts.value as text. "#>> $n::text[]" with an empty
// path reads a jsonb scalar as text without an inline literal.
func (b *builder) factValue(alias string) expr {
	return expr{alias: alias, sql: "(" + alias + ".value #>> " + b.param("{}") + "::text[])"}
}

// factSources is the reconciliation order of ADR-0005 D2, best first. It is a
// code constant, bound like every other value so the generated SQL carries no
// quoted literal at all.
var factSources = []string{"measured", "declared", "imported", "inferred"}

// factComparison compares a `fact.` field against the ONE reconciled value
// (§13 A4).
//
// `asset_facts` is unique on (tenant, asset, key, source_ref), so several
// producers may each hold a row for the same key. The old shape was an EXISTS
// over all of them, which meant two different bugs at once:
//
//   - `fact.os.name:linux` matched if ANY producer said linux, even one an
//     operator had overridden. "The OS is linux" is not "somebody once said
//     linux".
//   - `not fact.os.name:linux` became NOT EXISTS, which is TRUE for an asset
//     nobody has recorded the key for. That breaks §5.2: a term over an
//     unmeasured value and its negation must BOTH be UNKNOWN.
//
// A scalar subquery fixes both: it returns the highest-precedence producer's
// value, or no row — and comparing against a subquery that returns no row
// yields NULL, so the term and its negation are both UNKNOWN, for free.
//
// observed_at breaks a tie within one source kind. The precedence list alone
// leaves two rows from the same kind unordered, and an unordered LIMIT 1 is a
// nondeterministic answer to a question the user expects one answer to.
func (b *builder) factComparison(assetAlias string, f ast.FieldRef, sp ast.Span, inner func(expr) string) string {
	al := b.alias("af")
	// The cast goes INSIDE the SELECT list, applied to the winning row's value
	// — so reconciliation picks the row and the declared type is applied to
	// that row, not to whichever row happens to parse. It also keeps the
	// correlated subquery written once.
	val, ok := b.guardedCast(b.factValue(al), f, sp)
	if !ok {
		return "FALSE"
	}
	order := make([]string, 0, len(factSources))
	for _, kind := range factSources {
		order = append(order, b.param(kind))
	}
	// The alias is dropped: a scalar subquery has no row for a sibling column
	// to be read from. Only band, class and version fields ask for siblings,
	// and guardedCast has already refused every type but text, keyword,
	// number, timestamp and boolean — so this fails closed rather than
	// generating an out-of-scope reference.
	return inner(expr{sql: "(SELECT " + val.sql +
		" FROM asset_facts " + al +
		" WHERE " + al + ".asset_id = " + assetAlias + ".id" +
		" AND " + al + ".key = " + b.param(f.Accessor.Key) +
		" ORDER BY array_position(ARRAY[" + strings.Join(order, ", ") + "], " + al + ".source_kind)" +
		", " + al + ".observed_at DESC LIMIT 1)"})
}

// assetAlias returns the asset alias a child-table shape correlates to.
func (b *builder) assetAlias(sc scope, f ast.FieldRef, sp ast.Span) (string, bool) {
	if sc.assetAlias == "" {
		b.errs = b.errs.Add(queryerr.New(queryerr.CodeUntranslatable, sp,
			"field %q belongs to an asset, and %q has no asset in scope", f.Text, sc.target.Name))
		return "", false
	}
	return sc.assetAlias, true
}

// scalarExpr renders the expression a column or jsonb field is read from,
// typed for comparison.
func (b *builder) scalarExpr(sc scope, f ast.FieldRef, sp ast.Span, raw bool) (expr, bool) {
	alias, ok := b.aliasFor(sc, f, sp)
	if !ok {
		return expr{}, false
	}
	switch f.Accessor.Kind {
	case ast.AccessorColumn:
		col := alias + "." + f.Accessor.Column
		if f.Accessor.Cast != "" {
			col = "(" + col + ")::" + f.Accessor.Cast
		}
		return expr{alias: alias, sql: col}, true
	case ast.AccessorJSONB:
		text := expr{alias: alias, sql: "(" + alias + "." + f.Accessor.JSONColumn +
			" ->> " + b.param(f.Accessor.Key) + ")"}
		if raw {
			return text, true
		}
		return b.guardedCast(text, f, sp)
	}
	b.reject(sp, "field %q has accessor kind %q, which is not a scalar", f.Text, f.Accessor.Kind)
	return expr{}, false
}

// guardedCast wraps a text expression in the cast its declared type needs, with
// a regex guard so a value of the wrong shape is NULL — UNKNOWN — instead of a
// runtime cast error (§5.2).
func (b *builder) guardedCast(e expr, f ast.FieldRef, sp ast.Span) (expr, bool) {
	switch f.Type {
	case ast.TypeText, ast.TypeKeyword:
		return e, true
	case ast.TypeNumber:
		e.sql = "(CASE WHEN " + e.sql + " ~ " + b.param(numericPattern) +
			" THEN (" + e.sql + ")::numeric END)"
		return e, true
	case ast.TypeTimestamp:
		e.sql = "(CASE WHEN " + e.sql + " ~ " + b.param(timestampPattern) +
			" THEN (" + e.sql + ")::timestamptz END)"
		return e, true
	case ast.TypeBoolean:
		e.sql = "(CASE WHEN lower(" + e.sql + ") IN (" + b.param("true") + ", " + b.param("false") +
			") THEN (lower(" + e.sql + "))::boolean END)"
		return e, true
	}
	b.reject(sp, "field %q is a %s read out of jsonb, which has no safe cast", f.Text, f.Type)
	return expr{}, false
}

// numericPattern and timestampPattern guard the jsonb casts. They are code
// constants, bound like everything else so the generated SQL carries no quoted
// literal at all — which is the property that proves parameterisation.
const (
	numericPattern   = `^-?[0-9]+(\.[0-9]+)?$`
	timestampPattern = `^[0-9]{4}-[0-9]{2}-[0-9]{2}([T ][0-9]{2}:[0-9]{2}(:[0-9]{2})?)?`
)

// aliasFor resolves the table alias a field's relation maps to in this scope.
func (b *builder) aliasFor(sc scope, f ast.FieldRef, sp ast.Span) (string, bool) {
	if f.Accessor.Rel == "" {
		return sc.self, true
	}
	alias, ok := sc.rels[f.Accessor.Rel]
	if !ok {
		b.reject(sp, "field %q needs relation %q, which %q does not join",
			f.Text, f.Accessor.Rel, sc.target.Name)
		return "", false
	}
	return alias, true
}

func (b *builder) reject(sp ast.Span, format string, args ...any) {
	b.errs = b.errs.Add(queryerr.New(queryerr.CodeUntranslatable, sp, format, args...))
}

// comparison builds `expr <op> value` for a scalar expression, per type.
func (b *builder) comparison(e expr, f ast.FieldRef, op ast.Op, lit ast.Literal, sp ast.Span) string {
	switch f.Type {
	case ast.TypeText, ast.TypeKeyword:
		return b.textComparison(e, f.Type, op, lit)
	case ast.TypeNumber:
		n, ok := numberArg(lit.Value)
		if !ok {
			return b.fail(sp, "%q is not a number", lit.Value)
		}
		return "(" + e.sql + " " + sqlOp(op) + " " + b.param(n) + ")"
	case ast.TypeTimestamp:
		d, ok := ast.ParseDate(lit.Value)
		if !ok {
			return b.fail(sp, "%q is not a date", lit.Value)
		}
		return "(" + e.sql + " " + sqlOp(op) + " " + b.param(d.Resolve(b.opts.Now)) + ")"
	case ast.TypeBoolean:
		v, ok := ast.ParseBool(lit.Value)
		if !ok {
			return b.fail(sp, "%q is not a boolean", lit.Value)
		}
		return "(" + e.sql + " " + sqlOp(op) + " " + b.param(v) + ")"
	case ast.TypeUUID:
		return "(" + e.sql + " " + sqlOp(op) + " " + b.param(lit.Value) + "::uuid)"
	case ast.TypeInet:
		return b.inetComparison(e, op, lit)
	case ast.TypeClass:
		return b.classComparison(e, f, op, lit, sp)
	case ast.TypeBand:
		return b.bandComparison(e, f, op, lit, sp)
	case ast.TypeVersion:
		return b.versionComparison(e, f, op, lit, sp)
	case ast.TypeKeywordArray:
		return b.arrayComparison(e, op, lit, sp)
	}
	return b.fail(sp, "no comparison for type %q", f.Type)
}

// textComparison implements §4.4's two rules at once: ":" is substring on text
// and equality on keyword, and ":" is case-insensitive while "=" is not.
func (b *builder) textComparison(e expr, t ast.FieldType, op ast.Op, lit ast.Literal) string {
	if lit.IsWildcard() {
		pattern := b.param(wildcardPattern(lit.Value))
		switch op {
		case ast.OpColon:
			return "(" + e.sql + " ILIKE " + pattern + ")"
		case ast.OpNe:
			return "(" + e.sql + " NOT LIKE " + pattern + ")"
		}
		return "(" + e.sql + " LIKE " + pattern + ")"
	}
	if op == ast.OpColon {
		if t == ast.TypeText {
			// A search box means substring (§4.4 Q1).
			return "(" + e.sql + " ILIKE " + b.param("%"+escapeLike(lit.Value)+"%") + ")"
		}
		return "(lower(" + e.sql + ") = " + b.param(strings.ToLower(lit.Value)) + ")"
	}
	return "(" + e.sql + " " + sqlOp(op) + " " + b.param(lit.Value) + ")"
}

func (b *builder) inetComparison(e expr, op ast.Op, lit ast.Literal) string {
	if lit.IsWildcard() {
		return "((" + e.sql + ")::text ILIKE " + b.param(wildcardPattern(lit.Value)) + ")"
	}
	isCIDR, _ := ast.ParseInet(lit.Value)
	if op == ast.OpColon && isCIDR {
		// ":" on inet is containment, which is what a CIDR means (§4.4).
		return "(" + e.sql + " <<= " + b.param(lit.Value) + "::inet)"
	}
	return "(" + e.sql + " " + sqlOp(op) + " " + b.param(lit.Value) + "::inet)"
}

// classComparison implements §5.3: ":" matches the class and every descendant
// by prefix on the materialised path, "=" matches the class exactly.
func (b *builder) classComparison(e expr, f ast.FieldRef, op ast.Op, lit ast.Literal, sp ast.Span) string {
	info, ok := b.cat.ClassExists(lit.Value)
	if !ok {
		return b.fail(sp, "no class %q", lit.Value)
	}
	if op == ast.OpEq {
		return "(" + e.sql + " = " + b.param(info.Key) + ")"
	}
	if f.Accessor.PathColumn == "" {
		return b.fail(sp, "field %q has no class path column, so a subtree match is impossible", f.Text)
	}
	path := e.sibling(f.Accessor.PathColumn)
	return "(" + path + " = " + b.param(info.Path) +
		" OR " + path + " LIKE " + b.param(escapeLike(info.Path)+".%") + ")"
}

// bandComparison generates every band predicate from the supplied ladder, and
// never from a threshold written here (§5.5). Every form it produces is wrapped
// in the coverage guard (§5.2 — see assessedGuard).
func (b *builder) bandComparison(e expr, f ast.FieldRef, op ast.Op, lit ast.Literal, sp ast.Span) string {
	if b.opts.Ladder == nil {
		return b.fail(sp, "no band ladder was supplied, so %q cannot be compared", f.Text)
	}
	if strings.EqualFold(lit.Value, catalog.NotAssessed) {
		// not_assessed IS the coverage test, so it is the one form that must
		// not be guarded by it.
		return b.notAssessed(e, f, op, sp)
	}
	if op.Ordering() {
		return b.assessedGuard(e, f, b.bandOrdering(e, op, lit, sp))
	}
	return b.assessedGuard(e, f, b.bandEquality(e, f, op, lit, sp))
}

// bandEquality is `risk:high` / `risk = high` / `risk != high`. A stored label
// is authoritative where the row carries one; otherwise the band is the
// half-open score interval the ladder defines.
func (b *builder) bandEquality(e expr, f ast.FieldRef, op ast.Op, lit ast.Literal, sp ast.Span) string {
	if f.Accessor.LabelColumn != "" {
		label := "lower(" + e.sibling(f.Accessor.LabelColumn) + ")"
		if op == ast.OpNe {
			return "(" + label + " <> " + b.param(strings.ToLower(lit.Value)) + ")"
		}
		return "(" + label + " = " + b.param(strings.ToLower(lit.Value)) + ")"
	}
	min, max, hasMax, ok := catalog.BandBounds(b.opts.Ladder, lit.Value)
	if !ok {
		return b.fail(sp, "no band %q", lit.Value)
	}
	clause := "(" + e.sql + " >= " + b.param(min)
	if hasMax {
		clause += " AND " + e.sql + " < " + b.param(max)
	}
	clause += ")"
	if op == ast.OpNe {
		return "NOT " + clause
	}
	return clause
}

// assessedGuard makes a band predicate UNKNOWN for a row nobody scored (§5.2,
// ADR-0005 D4).
//
// This is not decoration. `assets.risk_score` defaults to 0 and is NOT NULL, so
// without the guard NOTHING is ever unknown: `risk < high` was TRUE for every
// asset that had never been assessed, and `risk:informational` was a strict
// superset of `risk:not_assessed` — the two sets §5.2 says must be different.
//
// It must be a CASE with no ELSE rather than an AND, because the result has to
// propagate NULL through NOT: `not (risk < high)` must exclude an unassessed
// asset as firmly as `risk < high` does. `cov AND (…)` would be FALSE there,
// and its negation TRUE, which is exactly the bug the other way round.
//
// A band field with no coverage column — a crypto configuration's risk, a
// finding's severity — is assessed by construction and is not guarded.
func (b *builder) assessedGuard(e expr, f ast.FieldRef, clause string) string {
	if f.Accessor.AssessedBy == "" {
		return clause
	}
	return "(CASE WHEN coalesce(array_length(" + e.sibling(f.Accessor.AssessedBy) +
		", 1), 0) > 0 THEN " + clause + " END)"
}

// bandOrdering turns "risk >= high" into the ladder's rung, and the other three
// orderings into the bounds of the same rung, so one ladder decides all four.
func (b *builder) bandOrdering(e expr, op ast.Op, lit ast.Literal, sp ast.Span) string {
	min, max, hasMax, ok := catalog.BandBounds(b.opts.Ladder, lit.Value)
	if !ok {
		return b.fail(sp, "no band %q", lit.Value)
	}
	switch op {
	case ast.OpGte:
		return "(" + e.sql + " >= " + b.param(min) + ")"
	case ast.OpLt:
		return "(" + e.sql + " < " + b.param(min) + ")"
	case ast.OpGt:
		if !hasMax {
			// Nothing is above the top band, so this matches no scored row —
			// but it must still be UNKNOWN for an unscored one, or its
			// negation would pick up every asset nobody assessed (§5.2). A
			// bare FALSE would do exactly that, so the contradiction is
			// written in terms of the column instead.
			p := b.param(min)
			return "(" + e.sql + " >= " + p + " AND " + e.sql + " < " + p + ")"
		}
		return "(" + e.sql + " >= " + b.param(max) + ")"
	default: // OpLte
		if !hasMax {
			// Everything scored is at or below the top band, and an unscored
			// row is UNKNOWN — the same reasoning, the other way up. `IS NOT
			// NULL` would answer FALSE where the honest answer is UNKNOWN.
			p := b.param(min)
			return "(" + e.sql + " >= " + p + " OR " + e.sql + " < " + p + ")"
		}
		return "(" + e.sql + " < " + b.param(max) + ")"
	}
}

// bandRange is `risk:[low to high]`: from the bottom of the low band to the top
// of the high one, inclusive at both ends as §3 specifies.
//
// It reads the SAME column bandEquality does — the stored label where the row
// carries one, the score otherwise. It used to always read the score, so on
// findings `severity:low` and `severity:[low to low]` answered from two
// different columns and could disagree.
func (b *builder) bandRange(sc scope, t *ast.Range) string {
	if b.opts.Ladder == nil {
		return b.fail(t.Sp, "no band ladder was supplied, so %q cannot be compared", t.Field.Text)
	}
	e, ok := b.scalarExpr(sc, t.Field, t.Sp, false)
	if !ok {
		return "FALSE"
	}
	lo, okLo := catalog.BandIndex(b.opts.Ladder, t.Lo.Value)
	if !okLo {
		return b.fail(t.Sp, "no band %q", t.Lo.Value)
	}
	hi, okHi := catalog.BandIndex(b.opts.Ladder, t.Hi.Value)
	if !okHi {
		return b.fail(t.Sp, "no band %q", t.Hi.Value)
	}
	return b.assessedGuard(e, t.Field, b.bandRangeClause(e, t.Field, lo, hi))
}

// bandRangeClause renders the inclusive band interval. The ladder is ordered
// highest-first, so `[low to high]` is the index run hi…lo.
func (b *builder) bandRangeClause(e expr, f ast.FieldRef, lo, hi int) string {
	bands := b.opts.Ladder.Bands()
	if hi > lo {
		// An inverted range ([critical to low]) covers nothing. Written in
		// terms of the column so an unassessed row stays UNKNOWN rather than
		// becoming FALSE — the same reasoning as bandOrdering above the top
		// rung.
		p := b.param(bands[len(bands)-1].Min)
		return "(" + e.sql + " >= " + p + " AND " + e.sql + " < " + p + ")"
	}
	if f.Accessor.LabelColumn != "" {
		label := "lower(" + e.sibling(f.Accessor.LabelColumn) + ")"
		parts := make([]string, 0, lo-hi+1)
		for i := hi; i <= lo; i++ {
			parts = append(parts, b.param(strings.ToLower(bands[i].Label)))
		}
		return "(" + label + " IN (" + strings.Join(parts, ", ") + "))"
	}
	clause := "(" + e.sql + " >= " + b.param(bands[lo].Min)
	if hi > 0 {
		clause += " AND " + e.sql + " < " + b.param(bands[hi-1].Min)
	}
	return clause + ")"
}

// notAssessed is the §5.2 rule made explicit: not_assessed means the coverage
// array is empty, which is a different set from "scored zero".
func (b *builder) notAssessed(e expr, f ast.FieldRef, op ast.Op, sp ast.Span) string {
	if f.Accessor.AssessedBy == "" {
		return b.fail(sp, "field %q records no coverage, so not_assessed has no meaning", f.Text)
	}
	clause := "(coalesce(array_length(" + e.sibling(f.Accessor.AssessedBy) + ", 1), 0) = 0)"
	if op == ast.OpNe {
		return "NOT " + clause
	}
	return clause
}

// versionComparison compares on the normalised sort key, in the C collation so
// the ordering is by byte and not by the database's locale (§5.5). A row whose
// version did not parse has a NULL key and is UNKNOWN, never "less than".
func (b *builder) versionComparison(e expr, f ast.FieldRef, op ast.Op, lit ast.Literal, sp ast.Span) string {
	if lit.IsWildcard() {
		return "(" + e.sql + " ILIKE " + b.param(wildcardPattern(lit.Value)) + ")"
	}
	if f.Accessor.SortColumn == "" {
		return b.fail(sp, "field %q has no normalised sort key, and a lexical comparison is forbidden", f.Text)
	}
	key, ok := ast.VersionSortKey(lit.Value)
	if !ok {
		return b.fail(sp, "%q is not a version", lit.Value)
	}
	return "(" + e.sibling(f.Accessor.SortColumn) + ` COLLATE "C" ` + sqlOp(op) + " " + b.param(key) + ")"
}

// arrayComparison implements ":" as array-contains, case-insensitively.
func (b *builder) arrayComparison(e expr, op ast.Op, lit ast.Literal, sp ast.Span) string {
	if op != ast.OpColon && op != ast.OpEq {
		return b.fail(sp, "an array field does not accept %q", op)
	}
	elem := b.alias("v")
	value := b.param(strings.ToLower(lit.Value))
	return "EXISTS (SELECT 1 FROM unnest(" + e.sql + ") AS " + elem +
		" WHERE lower(" + elem + ") = " + value + ")"
}

func sqlOp(op ast.Op) string {
	switch op {
	case ast.OpColon, ast.OpEq:
		return "="
	case ast.OpNe:
		return "<>"
	}
	return string(op)
}

// numberArg binds a whole number as an integer and anything else as a float, so
// a port is not bound as 443.0.
func numberArg(s string) (any, bool) {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, true
	}
	f, ok := ast.ParseNumber(s)
	if !ok {
		return nil, false
	}
	return f, true
}

// escapeLike escapes the LIKE metacharacters in a literal value.
func escapeLike(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\', '%', '_':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// wildcardPattern turns a `*` value into a LIKE pattern, escaping everything
// else so only the user's asterisks are metacharacters.
func wildcardPattern(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '*':
			b.WriteByte('%')
		case '\\', '%', '_':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
