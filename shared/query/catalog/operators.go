package catalog

import (
	"sort"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
)

// The type → operator matrix of QUERY_LANGUAGE.md §4.4, in one table so the
// validator has exactly one opinion about what is legal.
//
// Two rows read as narrower than a glance suggests, and deliberately so:
// class names only `=` in the `= !=` column ("`=` exact only"), and keyword[]
// names only `=` ("`=` contains"). Neither accepts `!=`: "this asset's class is
// not exactly X" and "this array does not contain X" are both better written
// with `not`, where the three-valued rule (§5.2) is visible in the text rather
// than hidden in an operator.

// ops is the per-type permission set.
type ops struct {
	colon    bool
	eq       bool
	ne       bool
	ordering bool
	in       bool
	match    bool
	rng      bool
	wildcard bool
}

var matrix = map[ast.FieldType]ops{
	ast.TypeKeyword:      {colon: true, eq: true, ne: true, in: true, match: true, wildcard: true},
	ast.TypeText:         {colon: true, eq: true, ne: true, in: true, match: true, wildcard: true},
	ast.TypeNumber:       {colon: true, eq: true, ne: true, ordering: true, in: true, rng: true},
	ast.TypeTimestamp:    {colon: true, eq: true, ne: true, ordering: true, rng: true},
	ast.TypeBoolean:      {colon: true, eq: true, ne: true},
	ast.TypeInet:         {colon: true, eq: true, ne: true, in: true, wildcard: true},
	ast.TypeClass:        {colon: true, eq: true, in: true},
	ast.TypeBand:         {colon: true, eq: true, ne: true, ordering: true, in: true, rng: true},
	ast.TypeVersion:      {colon: true, eq: true, ne: true, ordering: true, in: true, wildcard: true},
	ast.TypeUUID:         {colon: true, eq: true, ne: true, in: true},
	ast.TypeKeywordArray: {colon: true, eq: true, in: true},
	// §4.4's json row: a jsonb array or object answers `exists` and nothing
	// else. Every field in the ops struct is false, which is the point — the
	// zero value here is a decision, not an omission. OperatorsFor appends
	// "exists" unconditionally, so the error a comparison gets names the one
	// thing that does work.
	ast.TypeJSON: {},
}

// OperatorAllowed reports whether op may be applied to a field of type t.
func OperatorAllowed(t ast.FieldType, op ast.Op) bool {
	o, ok := matrix[t]
	if !ok {
		return false
	}
	switch op {
	case ast.OpColon:
		return o.colon
	case ast.OpEq:
		return o.eq
	case ast.OpNe:
		return o.ne
	case ast.OpLt, ast.OpLte, ast.OpGt, ast.OpGte:
		return o.ordering
	}
	return false
}

// InAllowed reports whether `in (…)` may be applied to type t.
func InAllowed(t ast.FieldType) bool { return matrix[t].in }

// MatchAllowed reports whether `~ "regex"` may be applied to type t.
func MatchAllowed(t ast.FieldType) bool { return matrix[t].match }

// RangeAllowed reports whether `[lo to hi]` may be applied to type t.
func RangeAllowed(t ast.FieldType) bool { return matrix[t].rng }

// WildcardAllowed reports whether a `*` value may be applied to type t. A bare
// `*` on its own is the "present at all" spelling and is allowed for every
// type, which is why the validator checks this only for a partial wildcard.
func WildcardAllowed(t ast.FieldType) bool { return matrix[t].wildcard }

// KnownType reports whether t is a type the matrix covers. An unresolved field
// has no type and must never reach the translator.
func KnownType(t ast.FieldType) bool {
	_, ok := matrix[t]
	return ok
}

// KnownTypes lists every type the matrix covers, sorted.
//
// It exists so the TypeScript mirror of the matrix can be GENERATED from this
// one rather than typed a second time: §4.4 is a table, and a table written
// twice is a table that disagrees with itself eventually. Callers that want to
// ask about one type want KnownType.
func KnownTypes() []ast.FieldType {
	out := make([]ast.FieldType, 0, len(matrix))
	for t := range matrix {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// OperatorsFor lists the operators legal on type t, for error messages.
func OperatorsFor(t ast.FieldType) []string {
	o := matrix[t]
	var out []string
	if o.colon {
		out = append(out, ":")
	}
	if o.eq {
		out = append(out, "=")
	}
	if o.ne {
		out = append(out, "!=")
	}
	if o.ordering {
		out = append(out, "<", "<=", ">", ">=")
	}
	if o.in {
		out = append(out, "in")
	}
	if o.match {
		out = append(out, "~")
	}
	if o.rng {
		out = append(out, "[a to b]")
	}
	return append(out, "exists")
}
