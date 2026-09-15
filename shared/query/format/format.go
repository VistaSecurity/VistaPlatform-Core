// Package format renders an AST back to canonical query text.
//
// QUERY_LANGUAGE.md §10: Format(q) rewrites any valid query to one text, and
// Format(Format(q)) == Format(q). Formatting is syntactic normalisation, not
// algebraic rewriting — clause order is preserved, `a >= 1 and a <= 10` is not
// folded into a range, and terms are never sorted. The facet rail edits by
// position, and a user's order carries meaning they can read back.
//
// It runs on an unvalidated tree as happily as a validated one: everything here
// is decided by the shape of the node, never by a field's type.
package format

import (
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
)

// Format renders a node as canonical query text. A nil node is the empty
// query, which matches everything under RLS.
func Format(n ast.Node) string {
	if n == nil {
		return ""
	}
	var b strings.Builder
	write(&b, n, ctxTop)
	return b.String()
}

// context says what the node is nested inside, which is all that decides
// whether it needs parentheses.
type context int

const (
	ctxTop context = iota
	ctxOr
	ctxAnd
	ctxNot
)

// needsParens reports whether a node must be parenthesised in the given
// context. The rule is not only precedence: an Or directly inside an Or, or an
// And inside an And, would reparse as one flattened node — a different tree —
// so the parentheses that produced the nesting are kept. §10 licenses removing
// a parenthesis only when "the result reparses to an identical AST".
func needsParens(n ast.Node, ctx context) bool {
	switch n.(type) {
	case *ast.Or:
		// `or` binds loosest, so it needs parentheses anywhere but the top.
		return ctx != ctxTop
	case *ast.And:
		// `and` binds tighter than `or`, so `a or b and c` already reparses to
		// Or{a, And{b, c}} — no parentheses inside an Or. Inside another And
		// they preserve the nesting; inside a Not they preserve the scope.
		return ctx == ctxAnd || ctx == ctxNot
	}
	return false
}

func write(b *strings.Builder, n ast.Node, ctx context) {
	if needsParens(n, ctx) {
		b.WriteByte('(')
		writeBare(b, n)
		b.WriteByte(')')
		return
	}
	writeBare(b, n)
}

func writeBare(b *strings.Builder, n ast.Node) {
	switch t := n.(type) {
	case *ast.And:
		for i, c := range t.Children {
			if i > 0 {
				b.WriteString(" and ")
			}
			write(b, c, ctxAnd)
		}
	case *ast.Or:
		for i, c := range t.Children {
			if i > 0 {
				b.WriteString(" or ")
			}
			write(b, c, ctxOr)
		}
	case *ast.Not:
		// `-term` is written `not term` (§10).
		b.WriteString("not ")
		write(b, t.Child, ctxNot)
	case *ast.Compare:
		b.WriteString(t.Field.Text)
		b.WriteString(opSpelling(t.Op))
		b.WriteString(value(t.Value))
	case *ast.InSet:
		b.WriteString(t.Field.Text)
		if t.Negated {
			b.WriteString(" not in (")
		} else {
			b.WriteString(" in (")
		}
		for i, v := range t.Values {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(value(v))
		}
		b.WriteByte(')')
	case *ast.Range:
		b.WriteString(t.Field.Text)
		b.WriteString(":[")
		b.WriteString(value(t.Lo))
		b.WriteString(" to ")
		b.WriteString(value(t.Hi))
		b.WriteByte(']')
	case *ast.Match:
		b.WriteString(t.Field.Text)
		b.WriteString(" ~ ")
		b.WriteString(ast.Quote(t.Regex))
	case *ast.Exists:
		b.WriteString("exists(")
		b.WriteString(t.Field.Text)
		b.WriteByte(')')
	case *ast.FreeText:
		// A free-text term is quoted more eagerly than a value: see
		// ast.IsSafeFreeText.
		b.WriteString(ast.QuoteFreeText(t.Value))
	case *ast.Sub:
		if t.Predicate == nil {
			b.WriteString("exists(")
			b.WriteString(t.Collection)
			b.WriteByte(')')
			return
		}
		b.WriteString(t.Collection)
		b.WriteString(":(")
		write(b, t.Predicate, ctxTop)
		b.WriteByte(')')
	case *ast.Traverse:
		writeTraverse(b, t)
	}
}

func writeTraverse(b *strings.Builder, t *ast.Traverse) {
	switch t.Form {
	case ast.FormExplicit:
		b.WriteString(ast.RelKeyword)
		b.WriteByte('(')
		b.WriteString(t.Name)
		b.WriteString(", ")
		b.WriteString(string(t.Direction))
		if t.Depth != 1 {
			b.WriteString(", ")
			b.WriteString(strconv.Itoa(t.Depth))
		}
		b.WriteByte(')')
	default:
		b.WriteString(t.Name)
		// One hop is the grammar's default, so `depends_on(1)` canonicalises
		// to `depends_on`; anything else is written.
		if t.Depth != 1 {
			b.WriteByte('(')
			b.WriteString(strconv.Itoa(t.Depth))
			b.WriteByte(')')
		}
	}
	b.WriteString(":(")
	write(b, t.Predicate, ctxTop)
	b.WriteByte(')')
}

// opSpelling renders an operator with §10's spacing: none around ":" and "=",
// one space around every other comparison operator.
func opSpelling(op ast.Op) string {
	switch op {
	case ast.OpColon:
		return ":"
	case ast.OpEq:
		return "="
	}
	return " " + string(op) + " "
}

// value renders a literal: quoted iff it is not a safe bareword, and with a
// relative date written in the largest unit that is exact (§10).
func value(l ast.Literal) string { return ast.QuoteLiteral(l) }
