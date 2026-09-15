// Package parser turns query text into an AST.
//
// Hand-written recursive descent over QUERY_LANGUAGE.md §3, with no generator
// and no dependencies. It knows the grammar's fixed vocabulary (the eight
// collections and the twenty relationship names, both from shared/query/ast)
// but nothing about fields, types or SQL: every field is left unresolved for
// the validator, which is what keeps the parser catalogue-independent.
//
// The parser reports the first error it meets. A query is one line in a rail or
// a column; there is no useful recovery to do, and a cascade of follow-on
// errors from a single typo reads worse than the one that matters.
package parser

import (
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
	"github.com/vistasecurity/vistaplatform/shared/query/lexer"
	"github.com/vistasecurity/vistaplatform/shared/query/queryerr"
)

// Result is a parsed query.
type Result struct {
	// Root is the predicate. It is nil for an empty query, which matches
	// everything under RLS (§8: "Empty predicate → empty string").
	Root ast.Node
	// Source is the text that was parsed.
	Source string
	// MaxParenDepth is the deepest nesting of parentheses in the source. The
	// validator caps it (§6); it is measured here because canonical form drops
	// redundant parentheses, so the AST no longer shows what was written.
	MaxParenDepth int
}

// MaxDepth is the parser's own hard ceiling on how deeply a query may nest:
// parentheses, value groups, sub-predicates, traversals and unary chains all
// count against it.
//
// It exists because recursive descent recurses, and the validator's
// configurable MaxParenDepth (§6, default 16) cannot help — the validator runs
// on a tree the parser has already had to build. Five million open parentheses
// overflowed the goroutine stack, and a stack overflow is a runtime *fatal*
// error: the recover() in Parse never sees it and the whole process dies. A
// query arrives from a URL, a saved view, a stored rule and an AI, so that is a
// denial of service, not a tidiness problem.
//
// It is deliberately well above §6's 16 so the validator's configurable cap
// stays the one users meet, and this one only ever catches an attack.
const MaxDepth = 64

// Parse scans and parses src. On failure the error is a queryerr.List holding
// exactly one *queryerr.Error, with code syntax_error for text the grammar
// rejects and too_many_clauses for text that nests past MaxDepth.
func Parse(src string) (res *Result, err error) {
	p := &parser{lex: lexer.New(src), src: src}
	defer func() {
		if r := recover(); r != nil {
			pe, ok := r.(parseError)
			if !ok {
				panic(r)
			}
			res, err = nil, queryerr.List{pe.err}
		}
	}()
	root := p.parseQuery()
	return &Result{Root: root, Source: src, MaxParenDepth: p.maxParen}, nil
}

type parseError struct{ err *queryerr.Error }

type parser struct {
	lex      *lexer.Lexer
	src      string
	paren    int
	maxParen int
	depth    int
}

func (p *parser) fail(span ast.Span, format string, args ...any) {
	panic(parseError{err: queryerr.New(queryerr.CodeSyntax, span, format, args...)})
}

// enter records one level of grammatical nesting and refuses to go past
// MaxDepth. Every recursive entry point calls it; leave() pairs with it.
func (p *parser) enter(span ast.Span) {
	p.depth++
	if p.depth > MaxDepth {
		e := queryerr.New(queryerr.CodeTooManyClauses, span,
			"query nests more than %d levels deep", MaxDepth).
			WithSuggestion("split it into smaller predicates")
		panic(parseError{err: e})
	}
}

func (p *parser) leave() { p.depth-- }

func (p *parser) failSuggest(span ast.Span, suggestion, format string, args ...any) {
	e := queryerr.New(queryerr.CodeSyntax, span, format, args...).WithSuggestion("%s", suggestion)
	panic(parseError{err: e})
}

func (p *parser) openParen(span ast.Span) {
	p.paren++
	if p.paren > p.maxParen {
		p.maxParen = p.paren
	}
	_ = span
}

func (p *parser) closeParen() { p.paren-- }

// parseQuery parses a whole query and requires that the input is consumed.
func (p *parser) parseQuery() ast.Node {
	if p.lex.PeekRune() == lexer.EOF {
		return nil
	}
	n := p.parseOr()
	tok := p.lex.Next(lexer.ModeDefault)
	if tok.Kind != lexer.KindEOF {
		p.fail(tok.Span, "unexpected %q after the end of the query", p.text(tok))
	}
	return n
}

func (p *parser) parseOr() ast.Node {
	p.enter(ast.Span{Start: p.lex.Pos(), End: p.lex.Pos()})
	defer p.leave()
	first := p.parseAnd()
	var children []ast.Node
	for {
		mark := p.lex.Mark()
		tok := p.lex.Next(lexer.ModeDefault)
		if tok.Kind != lexer.KindIdent || !strings.EqualFold(tok.Text, "or") {
			p.lex.Reset(mark)
			break
		}
		if children == nil {
			children = append(children, first)
		}
		children = append(children, p.parseAnd())
	}
	if children == nil {
		return first
	}
	return &ast.Or{Children: children, Sp: spanOf(children)}
}

func (p *parser) parseAnd() ast.Node {
	first := p.parseUnary()
	var children []ast.Node
	for {
		r := p.lex.PeekRune()
		if r == lexer.EOF || r == ')' || r == ']' || r == ',' {
			break
		}
		mark := p.lex.Mark()
		tok := p.lex.Next(lexer.ModeDefault)
		switch {
		case tok.Kind == lexer.KindIdent && strings.EqualFold(tok.Text, "or"):
			p.lex.Reset(mark)
			if children == nil {
				return first
			}
			return &ast.And{Children: children, Sp: spanOf(children)}
		case tok.Kind == lexer.KindIdent && strings.EqualFold(tok.Text, "and"):
			// explicit and: fall through to parse the right-hand side
		default:
			// juxtaposition is an implicit and (§2)
			p.lex.Reset(mark)
		}
		if children == nil {
			children = append(children, first)
		}
		children = append(children, p.parseUnary())
	}
	if children == nil {
		return first
	}
	return &ast.And{Children: children, Sp: spanOf(children)}
}

func (p *parser) parseUnary() ast.Node {
	mark := p.lex.Mark()
	tok := p.lex.Next(lexer.ModeDefault)
	if tok.Kind == lexer.KindMinus || (tok.Kind == lexer.KindIdent && strings.EqualFold(tok.Text, "not")) {
		// `not not not …` is a recursion path of its own, with no parenthesis
		// to be counted by openParen — count it here.
		p.enter(tok.Span)
		child := p.parseUnary()
		p.leave()
		return &ast.Not{Child: child, Sp: tok.Span.Merge(child.Span())}
	}
	p.lex.Reset(mark)
	return p.parsePrimary()
}

func (p *parser) parsePrimary() ast.Node {
	mark := p.lex.Mark()
	tok := p.lex.Next(lexer.ModeDefault)
	if tok.Kind == lexer.KindLParen {
		p.openParen(tok.Span)
		inner := p.parseOr()
		p.expect(lexer.KindRParen, ")")
		p.closeParen()
		return inner
	}
	p.lex.Reset(mark)
	return p.parseTerm()
}

// parseTerm parses one term: exists, a traversal, a sub-predicate, a field term
// or free text.
func (p *parser) parseTerm() ast.Node {
	mark := p.lex.Mark()
	r := p.lex.PeekRune()
	if r == lexer.EOF {
		pos := p.lex.SkipSpace()
		p.fail(ast.Span{Start: pos, End: pos}, "expected a term")
	}
	if r == '"' || r == '\'' {
		// §3's `segment = identifier | string` holds at the HEAD of a path too,
		// so `"hostname":web1` is a field term. Without this it silently
		// became two free-text terms — no error, just a different query.
		if n, ok := p.tryQuotedHeadTerm(mark); ok {
			return n
		}
		return p.parseFreeText(mark)
	}
	if !isIdentStart(r) {
		return p.parseFreeText(mark)
	}

	head := p.lex.Next(lexer.ModeDefault)
	if head.Kind != lexer.KindIdent {
		p.lex.Reset(mark)
		return p.parseFreeText(mark)
	}
	name := strings.ToLower(head.Text)

	if name == "exists" && p.lex.Peek(lexer.ModeDefault).Kind == lexer.KindLParen {
		return p.parseExists(head)
	}

	field, ok := p.tryFieldPath(head)
	if !ok {
		// The dotted name is not a field path (`web.01` — a digit is not an
		// identifier), so the term was free text all along. Only the path
		// parse is retried: an error after the operator is a real error and
		// must not be swallowed by re-reading the term as text.
		p.lex.Reset(mark)
		return p.parseFreeText(mark)
	}

	// The one-segment forms that are not fields: traversals and sub-predicates.
	if len(field.Segments) == 1 {
		if n, ok := p.tryTraverseOrSub(field, name, mark); ok {
			return n
		}
	}

	if n, ok := p.parseFieldTermTail(field); ok {
		return n
	}

	// No operator followed the name, so it was free text all along.
	p.lex.Reset(mark)
	return p.parseFreeText(mark)
}

// tryQuotedHeadTerm parses a field term whose first path segment is a quoted
// string (`"hostname":web1`, `"cost center".sub:x`). It reports false — having
// rewound — when the string is not followed by a path separator or an operator,
// because then it is an ordinary quoted free-text term.
//
// A quoted head is never a relationship or collection name: quoting a segment
// is how a tenant-supplied key is written, and `"endpoint":(…)` asking for a
// field called "endpoint" is the only reading that makes the quotes mean
// something.
func (p *parser) tryQuotedHeadTerm(mark int) (ast.Node, bool) {
	head := p.lex.Next(lexer.ModeDefault)
	if head.Kind != lexer.KindString {
		p.lex.Reset(mark)
		return nil, false
	}
	switch p.lex.Peek(lexer.ModeDefault).Kind {
	case lexer.KindDot, lexer.KindColon, lexer.KindOp:
	default:
		p.lex.Reset(mark)
		return nil, false
	}
	field, ok := p.tryFieldPath(head)
	if !ok {
		p.lex.Reset(mark)
		return nil, false
	}
	if n, ok := p.parseFieldTermTail(field); ok {
		return n, true
	}
	p.lex.Reset(mark)
	return nil, false
}

// parseFieldTermTail reads the operator and value that follow a field path. It
// reports false — leaving the scanner where the caller can rewind it — when
// nothing that can follow a field does.
func (p *parser) parseFieldTermTail(field ast.FieldRef) (ast.Node, bool) {
	next := p.lex.Peek(lexer.ModeDefault)
	switch {
	case next.Kind == lexer.KindColon:
		p.lex.Next(lexer.ModeDefault)
		return p.parseColonForm(field), true
	case next.Kind == lexer.KindOp:
		p.lex.Next(lexer.ModeDefault)
		return p.parseOpForm(field, next), true
	case next.Kind == lexer.KindIdent && strings.EqualFold(next.Text, "in"):
		save := p.lex.Mark()
		p.lex.Next(lexer.ModeDefault)
		if p.listFollows() {
			return p.parseInList(field, false), true
		}
		p.lex.Reset(save)
	case next.Kind == lexer.KindIdent && strings.EqualFold(next.Text, "not"):
		save := p.lex.Mark()
		p.lex.Next(lexer.ModeDefault)
		after := p.lex.Peek(lexer.ModeDefault)
		if after.Kind == lexer.KindIdent && strings.EqualFold(after.Text, "in") {
			p.lex.Next(lexer.ModeDefault)
			if p.listFollows() {
				return p.parseInList(field, true), true
			}
		}
		p.lex.Reset(save)
	}
	return nil, false
}

// tryFieldPath is parseFieldPath with the failure turned into a bool, so the
// caller can fall back to free text instead of reporting a syntax error.
func (p *parser) tryFieldPath(head lexer.Token) (field ast.FieldRef, ok bool) {
	mark := p.lex.Mark()
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		if _, isParse := r.(parseError); !isParse {
			panic(r)
		}
		p.lex.Reset(mark)
		field, ok = ast.FieldRef{}, false
	}()
	return p.parseFieldPath(head), true
}

// parseFieldPath reads `segment { "." segment }` after the head segment, which
// §3 allows to be an identifier or a quoted string.
func (p *parser) parseFieldPath(head lexer.Token) ast.FieldRef {
	segs := []string{strings.ToLower(head.Text)}
	quoted := []bool{false}
	if head.Kind == lexer.KindString {
		// A quoted segment keeps its case, head or not: it is a
		// tenant-supplied key, not a language identifier.
		segs[0], quoted[0] = head.Value, true
	}
	span := head.Span
	for {
		mark := p.lex.Mark()
		dot := p.lex.Next(lexer.ModeDefault)
		if dot.Kind != lexer.KindDot {
			p.lex.Reset(mark)
			break
		}
		seg := p.lex.Next(lexer.ModeDefault)
		switch seg.Kind {
		case lexer.KindIdent:
			segs = append(segs, strings.ToLower(seg.Text))
			quoted = append(quoted, false)
		case lexer.KindString:
			// A quoted segment keeps its case: it is a tenant-supplied key
			// (a tag or a fact key), not a language identifier.
			segs = append(segs, seg.Value)
			quoted = append(quoted, true)
		default:
			p.fail(seg.Span, "expected a field name after %q", ".")
		}
		span = span.Merge(seg.Span)
	}
	return ast.FieldRef{Segments: segs, Quoted: quoted, Text: fieldText(segs, quoted), Sp: span}
}

// tryTraverseOrSub handles `name(n):(…)`, `name:(…)`, `rel(…):(…)` and
// `any_rel:(…)`. It reports false when the name is an ordinary field.
func (p *parser) tryTraverseOrSub(field ast.FieldRef, name string, termStart int) (ast.Node, bool) {
	next := p.lex.Peek(lexer.ModeDefault)

	if next.Kind == lexer.KindLParen {
		switch name {
		case ast.RelKeyword:
			return p.parseExplicitTraverse(field), true
		case ast.AnyRel:
			depth := p.parseDepthArg()
			return p.parseTraverseTail(field, ast.FormAny, name, "", ast.DirAny, depth, false), true
		}
		if rel, ok := ast.LookupRelationship(name); ok {
			depth := p.parseDepthArg()
			return p.parseTraverseTail(field, ast.FormNamed, name, rel.Type, rel.Direction, depth, false), true
		}
		return nil, false
	}

	if next.Kind != lexer.KindColon {
		return nil, false
	}
	// `x:(` — a sub-predicate, a one-hop traversal, or a value group.
	save := p.lex.Mark()
	p.lex.Next(lexer.ModeDefault)
	if p.lex.Peek(lexer.ModeValue).Kind != lexer.KindLParen {
		p.lex.Reset(save)
		return nil, false
	}
	switch {
	case ast.IsCollection(name):
		open := p.lex.Next(lexer.ModeDefault)
		p.openParen(open.Span)
		inner := p.parseOr()
		closing := p.expect(lexer.KindRParen, ")")
		p.closeParen()
		return &ast.Sub{Collection: name, Predicate: inner, Sp: field.Sp.Merge(closing.Span)}, true
	case name == ast.AnyRel:
		return p.parseTraverseTail(field, ast.FormAny, name, "", ast.DirAny, 1, true), true
	default:
		if rel, ok := ast.LookupRelationship(name); ok {
			return p.parseTraverseTail(field, ast.FormNamed, name, rel.Type, rel.Direction, 1, true), true
		}
	}
	p.lex.Reset(save)
	_ = termStart
	return nil, false
}

// parseDepthArg reads the optional `(n)` after a traversal name.
func (p *parser) parseDepthArg() int {
	open := p.lex.Next(lexer.ModeDefault)
	p.openParen(open.Span)
	tok := p.lex.Next(lexer.ModeValue)
	n := p.intArg(tok)
	p.expect(lexer.KindRParen, ")")
	p.closeParen()
	return n
}

func (p *parser) intArg(tok lexer.Token) int {
	if tok.Kind != lexer.KindBare {
		p.fail(tok.Span, "expected a hop count, found %q", p.text(tok))
	}
	n, err := strconv.Atoi(tok.Text)
	if err != nil || n < 1 {
		p.fail(tok.Span, "hop count must be a positive whole number, found %q", tok.Text)
	}
	return n
}

// parseTraverseTail reads the `:(predicate)` that every traversal form ends in.
// colonEaten says whether the caller has already consumed the ":" — the
// `name:(…)` form has, because the colon is what told it this was a traversal
// and not a field.
func (p *parser) parseTraverseTail(field ast.FieldRef, form ast.TraverseForm, name, typ string, dir ast.Direction, depth int, colonEaten bool) ast.Node {
	if !colonEaten {
		if p.lex.Peek(lexer.ModeDefault).Kind != lexer.KindColon {
			tok := p.lex.Peek(lexer.ModeDefault)
			p.fail(tok.Span, "expected %q before the traversal predicate", ":")
		}
		p.lex.Next(lexer.ModeDefault)
	}
	open := p.expect(lexer.KindLParen, "(")
	p.openParen(open.Span)
	inner := p.parseOr()
	closing := p.expect(lexer.KindRParen, ")")
	p.closeParen()
	return &ast.Traverse{
		Form:      form,
		Name:      name,
		Type:      typ,
		Direction: dir,
		Depth:     depth,
		Predicate: inner,
		Sp:        field.Sp.Merge(closing.Span),
	}
}

// parseExplicitTraverse reads `rel(type, direction[, depth]):(…)`.
func (p *parser) parseExplicitTraverse(field ast.FieldRef) ast.Node {
	open := p.expect(lexer.KindLParen, "(")
	p.openParen(open.Span)

	typTok := p.lex.Next(lexer.ModeDefault)
	if typTok.Kind != lexer.KindIdent {
		p.fail(typTok.Span, "expected a relationship type, found %q", p.text(typTok))
	}
	// An unknown or reverse-label type is NOT a parse error: the explicit form
	// is unambiguous whatever the name is, so the name is vocabulary and
	// belongs to the validator, which reports it as unknown_value (§6).
	typ := strings.ToLower(typTok.Text)

	p.expect(lexer.KindComma, ",")
	dirTok := p.lex.Next(lexer.ModeDefault)
	if dirTok.Kind != lexer.KindIdent {
		p.fail(dirTok.Span, "expected a direction, found %q", p.text(dirTok))
	}
	dir, ok := ast.ParseDirection(dirTok.Text)
	if !ok {
		p.failSuggest(dirTok.Span, "direction is out, in or any", "unknown direction %q", dirTok.Text)
	}

	depth := 1
	if p.lex.Peek(lexer.ModeDefault).Kind == lexer.KindComma {
		p.lex.Next(lexer.ModeDefault)
		depth = p.intArg(p.lex.Next(lexer.ModeValue))
	}
	p.expect(lexer.KindRParen, ")")
	p.closeParen()
	return p.parseTraverseTail(field, ast.FormExplicit, typ, typ, dir, depth, false)
}

// parseExists reads `exists(field)`. A collection name inside becomes a Sub
// with no predicate, because `exists(endpoint)` is an EXISTS over a child table
// (§8: `has_certificates` → `exists(cert)`).
func (p *parser) parseExists(head lexer.Token) ast.Node {
	open := p.expect(lexer.KindLParen, "(")
	p.openParen(open.Span)
	inner := p.lex.Next(lexer.ModeDefault)
	if inner.Kind != lexer.KindIdent {
		p.fail(inner.Span, "expected a field name inside exists(), found %q", p.text(inner))
	}
	field := p.parseFieldPath(inner)
	closing := p.expect(lexer.KindRParen, ")")
	p.closeParen()
	span := head.Span.Merge(closing.Span)
	if len(field.Segments) == 1 && ast.IsCollection(field.Segments[0]) {
		return &ast.Sub{Collection: field.Segments[0], Sp: span}
	}
	return &ast.Exists{Field: field, Sp: span}
}

// parseColonForm reads everything that may follow a field's ":".
func (p *parser) parseColonForm(field ast.FieldRef) ast.Node {
	next := p.lex.Peek(lexer.ModeValue)
	switch next.Kind {
	case lexer.KindLParen:
		return p.parseValueGroup(field)
	case lexer.KindLBracket:
		return p.parseRange(field)
	case lexer.KindBare:
		if strings.EqualFold(next.Text, "in") {
			save := p.lex.Mark()
			p.lex.Next(lexer.ModeValue)
			if p.listFollows() {
				return p.parseInList(field, false)
			}
			// `status:in` and `status:in production` are not lists at all —
			// they are someone using the keyword as a value. Rewinding hands
			// the token to parseValue, which gives it the same "quote it"
			// diagnostic every other keyword gets, instead of an `expected
			// "("` that names a parenthesis the user never meant to write.
			p.lex.Reset(save)
		}
	}
	lit := p.parseValue()
	return &ast.Compare{Field: field, Op: ast.OpColon, Value: lit, Sp: field.Sp.Merge(lit.Sp)}
}

// parseOpForm reads `op value`, `~ "regex"` and `= value`.
func (p *parser) parseOpForm(field ast.FieldRef, op lexer.Token) ast.Node {
	if op.Text == "~" {
		tok := p.lex.Next(lexer.ModeValue)
		if tok.Kind != lexer.KindString {
			p.failSuggest(tok.Span, `write the pattern in double quotes: ~ "^web[0-9]+"`,
				"the regex operator takes a quoted pattern, found %q", p.text(tok))
		}
		return &ast.Match{Field: field, Regex: tok.Value, Sp: field.Sp.Merge(tok.Span)}
	}
	// ":=" is an accepted alias for "=" and is normalised here (§10).
	text := op.Text
	if text == ":=" {
		text = "="
	}
	lit := p.parseValue()
	return &ast.Compare{Field: field, Op: ast.Op(text), Value: lit, Sp: field.Sp.Merge(lit.Sp)}
}

// listFollows reports whether the just-consumed `in` is followed by the "("
// that opens a list. When it is not, the caller rewinds and lets the token be
// read as a value, so `status:in` reports the keyword, not a missing bracket.
func (p *parser) listFollows() bool {
	return p.lex.Peek(lexer.ModeDefault).Kind == lexer.KindLParen
}

// parseInList reads `in (a, b, c)`.
func (p *parser) parseInList(field ast.FieldRef, negated bool) ast.Node {
	open := p.expect(lexer.KindLParen, "(")
	p.openParen(open.Span)
	var values []ast.Literal
	for {
		values = append(values, p.parseValue())
		tok := p.lex.Next(lexer.ModeDefault)
		if tok.Kind == lexer.KindComma {
			continue
		}
		if tok.Kind == lexer.KindRParen {
			p.closeParen()
			return &ast.InSet{Field: field, Values: values, Negated: negated, Sp: field.Sp.Merge(tok.Span)}
		}
		p.fail(tok.Span, "expected %q or %q in a list, found %q", ",", ")", p.text(tok))
	}
}

// parseRange reads `[lo to hi]`, inclusive.
func (p *parser) parseRange(field ast.FieldRef) ast.Node {
	p.expect(lexer.KindLBracket, "[")
	lo := p.parseValue()
	kw := p.lex.Next(lexer.ModeValue)
	if kw.Kind != lexer.KindBare || !strings.EqualFold(kw.Text, "to") {
		p.failSuggest(kw.Span, "a range is written [low to high]",
			"expected %q in a range, found %q", "to", p.text(kw))
	}
	hi := p.parseValue()
	closing := p.expect(lexer.KindRBracket, "]")
	return &ast.Range{Field: field, Lo: lo, Hi: hi, Sp: field.Sp.Merge(closing.Span)}
}

// parseValueGroup reads `field:(a or b and not c)` and desugars it against the
// same field. §7.1's node set has no group node: the group is sugar for the
// boolean combination it names, and the formatter writes the desugared form.
func (p *parser) parseValueGroup(field ast.FieldRef) (node ast.Node) {
	// A misspelled relationship name reaches here, because `depand_on:(…)` is
	// syntactically a value group over a field called depand_on. The group
	// parse then fails on the first thing only a predicate may contain, and
	// the bare failure ("expected \")\"") hides the real mistake.
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		pe, ok := r.(parseError)
		if !ok {
			panic(r)
		}
		if len(field.Segments) == 1 && pe.err.Suggestion == "" {
			if near, found := queryerr.Nearest(field.Segments[0], vocabularyNames(), 2); found {
				pe.err = pe.err.WithSuggestion("%q is not a relationship or a collection; did you mean %q?",
					field.Segments[0], near)
			}
		}
		panic(parseError{err: pe.err})
	}()
	open := p.expect(lexer.KindLParen, "(")
	p.openParen(open.Span)
	node = p.parseValueOr(field)
	p.expect(lexer.KindRParen, ")")
	p.closeParen()
	return node
}

func (p *parser) parseValueOr(field ast.FieldRef) ast.Node {
	first := p.parseValueAnd(field)
	var children []ast.Node
	for p.peekValueKeyword("or") {
		p.lex.Next(lexer.ModeValue)
		if children == nil {
			children = append(children, first)
		}
		children = append(children, p.parseValueAnd(field))
	}
	if children == nil {
		return first
	}
	return &ast.Or{Children: children, Sp: spanOf(children)}
}

func (p *parser) parseValueAnd(field ast.FieldRef) ast.Node {
	first := p.parseValueNot(field)
	var children []ast.Node
	for p.peekValueKeyword("and") {
		p.lex.Next(lexer.ModeValue)
		if children == nil {
			children = append(children, first)
		}
		children = append(children, p.parseValueNot(field))
	}
	if children == nil {
		return first
	}
	return &ast.And{Children: children, Sp: spanOf(children)}
}

// parseValueNot reads `[ "not" ] value`. The "not" binds to ONE value, exactly
// as the outer grammar's `unary` binds to one term, so
// `environment:(not production and not staging)` is And{Not, Not} and reads
// the way it looks. The original grammar allowed a single "not" per value_and
// clause, which made that query a syntax error with a suggestion to quote the
// word — see §13 amendment 3.
func (p *parser) parseValueNot(field ast.FieldRef) ast.Node {
	if p.peekValueKeyword("not") {
		tok := p.lex.Next(lexer.ModeValue)
		child := p.parseValueLeaf(field)
		return &ast.Not{Child: child, Sp: tok.Span.Merge(child.Span())}
	}
	return p.parseValueLeaf(field)
}

func (p *parser) parseValueLeaf(field ast.FieldRef) ast.Node {
	lit := p.parseValue()
	return &ast.Compare{Field: field, Op: ast.OpColon, Value: lit, Sp: field.Sp.Merge(lit.Sp)}
}

// peekValueKeyword reports whether the next value-mode token is the given bare
// keyword. A quoted "or" is a value, not a keyword, which is how a value
// spelled like a keyword is written.
func (p *parser) peekValueKeyword(kw string) bool {
	tok := p.lex.Peek(lexer.ModeValue)
	return tok.Kind == lexer.KindBare && strings.EqualFold(tok.Text, kw)
}

// parseValue reads one value literal.
func (p *parser) parseValue() ast.Literal {
	tok := p.lex.Next(lexer.ModeValue)
	switch tok.Kind {
	case lexer.KindString:
		return ast.Literal{Form: ast.LitString, Value: tok.Value, Sp: tok.Span}
	case lexer.KindBare:
		if ast.IsKeyword(tok.Text) {
			p.failSuggest(tok.Span, "quote it to use it as a value: \""+tok.Text+"\"",
				"%q is a keyword, not a value", strings.ToLower(tok.Text))
		}
		return ast.Literal{Form: ast.LitBare, Value: tok.Text, Sp: tok.Span}
	case lexer.KindIllegal:
		p.fail(tok.Span, "%s", tok.Text)
	}
	p.fail(tok.Span, "expected a value, found %q", p.text(tok))
	return ast.Literal{}
}

// parseFreeText re-scans the term as a value, which is what a term with no
// field is (§5.4).
func (p *parser) parseFreeText(mark int) ast.Node {
	p.lex.Reset(mark)
	lit := p.parseValue()
	return &ast.FreeText{Value: lit, Sp: lit.Sp}
}

func (p *parser) expect(kind lexer.Kind, what string) lexer.Token {
	tok := p.lex.Next(lexer.ModeDefault)
	if tok.Kind != kind {
		p.fail(tok.Span, "expected %q, found %q", what, p.text(tok))
	}
	return tok
}

// text renders a token for an error message.
func (p *parser) text(tok lexer.Token) string {
	switch tok.Kind {
	case lexer.KindEOF:
		return "end of query"
	case lexer.KindIllegal:
		return tok.Text
	}
	return tok.Text
}

func spanOf(nodes []ast.Node) ast.Span {
	if len(nodes) == 0 {
		return ast.Span{}
	}
	sp := nodes[0].Span()
	for _, n := range nodes[1:] {
		sp = sp.Merge(n.Span())
	}
	return sp
}

// fieldText renders a field path in canonical form: unquoted segments as
// written (already lowercased), quoted segments re-quoted.
func fieldText(segs []string, quoted []bool) string {
	var b strings.Builder
	for i, s := range segs {
		if i > 0 {
			b.WriteByte('.')
		}
		// A quoted segment loses its quotes only when it would re-lex to
		// exactly itself: an identifier that is already lowercase. Anything
		// else — a space, a dot, a capital letter the lexer would fold — stays
		// quoted, or the canonical form would name a different key.
		//
		// A keyword in HEAD position is the third case: `"not":foo` unquoted
		// is `not:foo`, which reparses as a negation of the free text ":foo".
		// Later segments are safe, because parseFieldPath takes any identifier
		// after a ".".
		reLexesToItself := ast.IsIdentifier(s) && s == strings.ToLower(s) &&
			(i != 0 || !ast.IsKeyword(s))
		if i < len(quoted) && quoted[i] && !reLexesToItself {
			b.WriteString(ast.Quote(s))
			continue
		}
		b.WriteString(s)
	}
	return b.String()
}

// vocabularyNames is every name that may head a `name:(…)` predicate.
func vocabularyNames() []string {
	out := make([]string, 0, len(ast.Collections)+len(ast.Relationships)+2)
	out = append(out, ast.Collections...)
	for _, r := range ast.Relationships {
		out = append(out, r.Name)
	}
	return append(out, ast.AnyRel, ast.RelKeyword)
}

func isIdentStart(r rune) bool {
	return r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}
