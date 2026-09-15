package parser_test

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
	"github.com/vistasecurity/vistaplatform/shared/query/format"
	"github.com/vistasecurity/vistaplatform/shared/query/parser"
	"github.com/vistasecurity/vistaplatform/shared/query/queryerr"
)

func mustParse(t *testing.T, src string) *parser.Result {
	t.Helper()
	res, err := parser.Parse(src)
	if err != nil {
		t.Fatalf("Parse(%q): %v", src, err)
	}
	return res
}

// TestBareValuesTakeTheirOwnCharacters pins §2's rule that makes the language
// usable: after a field separator, a value may contain ":" and "/" and "*",
// because the field has already been consumed.
func TestBareValuesTakeTheirOwnCharacters(t *testing.T) {
	cases := map[string]string{
		"id.mac:aa:bb:*":                  "aa:bb:*",
		"primary_address:198.51.100.0/24": "198.51.100.0/24",
		"hostname:web-01":                 "web-01",
		"purl:pkg:deb/debian/openssl@3.0": "pkg:deb/debian/openssl@3.0",
		"owner_email:a.b@example.com":     "a.b@example.com",
		"hostname:100%":                   "100%",
		"tag.env:#prod":                   "#prod",
		"last_seen:now+7d":                "now+7d",
	}
	for src, want := range cases {
		res := mustParse(t, src)
		cmp, ok := res.Root.(*ast.Compare)
		if !ok {
			t.Errorf("%q parsed as %T, want a comparison", src, res.Root)
			continue
		}
		if cmp.Value.Value != want {
			t.Errorf("%q value = %q, want %q", src, cmp.Value.Value, want)
		}
	}
}

// TestFreeTextTakesTheWholeToken is the other side of the same rule: a term
// with no field is re-scanned as a value, so it is one term and not several.
func TestFreeTextTakesTheWholeToken(t *testing.T) {
	cases := map[string]string{
		"payroll":      "payroll",
		"web-01":       "web-01",
		"198.51.100.7": "198.51.100.7",
		`"two words"`:  "two words",
		// A free-text term that contains ":" has to be quoted, because an
		// unquoted one is a field and a value — which is why §9's examples
		// write id:"aa:bb:cc:00:11:22" rather than the bare address.
		`"aa:bb:cc:dd"`:  "aa:bb:cc:dd",
		"pay* roll":      "pay*",
		"3.0":            "3.0",
		"payroll-server": "payroll-server",
	}
	for src, want := range cases {
		res := mustParse(t, src)
		node := res.Root
		if and, ok := node.(*ast.And); ok {
			node = and.Children[0]
		}
		ft, ok := node.(*ast.FreeText)
		if !ok {
			t.Errorf("%q parsed as %T, want free text", src, node)
			continue
		}
		if ft.Value.Value != want {
			t.Errorf("%q free text = %q, want %q", src, ft.Value.Value, want)
		}
	}
}

func TestImplicitAndAndNegation(t *testing.T) {
	res := mustParse(t, "environment:production class:server -status:denied not exists(owner_email)")
	and, ok := res.Root.(*ast.And)
	if !ok {
		t.Fatalf("root is %T, want an And", res.Root)
	}
	if len(and.Children) != 4 {
		t.Fatalf("got %d children, want 4", len(and.Children))
	}
	if _, ok := and.Children[2].(*ast.Not); !ok {
		t.Errorf("'-' should parse as a Not, got %T", and.Children[2])
	}
	if _, ok := and.Children[3].(*ast.Not); !ok {
		t.Errorf("'not' should parse as a Not, got %T", and.Children[3])
	}
}

func TestPrecedence(t *testing.T) {
	// and binds tighter than or.
	res := mustParse(t, "a:1 or b:2 and c:3")
	or, ok := res.Root.(*ast.Or)
	if !ok {
		t.Fatalf("root is %T, want an Or", res.Root)
	}
	if len(or.Children) != 2 {
		t.Fatalf("got %d children, want 2", len(or.Children))
	}
	if _, ok := or.Children[1].(*ast.And); !ok {
		t.Errorf("the right arm should be an And, got %T", or.Children[1])
	}
}

func TestTraversalForms(t *testing.T) {
	cases := []struct {
		src   string
		form  ast.TraverseForm
		name  string
		typ   string
		dir   ast.Direction
		depth int
	}{
		{"depends_on:(a:1)", ast.FormNamed, "depends_on", "depends_on", ast.DirOut, 1},
		{"depends_on(3):(a:1)", ast.FormNamed, "depends_on", "depends_on", ast.DirOut, 3},
		{"used_by:(a:1)", ast.FormNamed, "used_by", "depends_on", ast.DirIn, 1},
		{"any_rel:(a:1)", ast.FormAny, "any_rel", "", ast.DirAny, 1},
		{"any_rel(2):(a:1)", ast.FormAny, "any_rel", "", ast.DirAny, 2},
		{"rel(connects_to, in, 2):(a:1)", ast.FormExplicit, "connects_to", "connects_to", ast.DirIn, 2},
		{"rel(connects_to, any):(a:1)", ast.FormExplicit, "connects_to", "connects_to", ast.DirAny, 1},
	}
	for _, c := range cases {
		res := mustParse(t, c.src)
		tr, ok := res.Root.(*ast.Traverse)
		if !ok {
			t.Errorf("%q parsed as %T, want a traversal", c.src, res.Root)
			continue
		}
		if tr.Form != c.form || tr.Name != c.name || tr.Type != c.typ || tr.Direction != c.dir || tr.Depth != c.depth {
			t.Errorf("%q = {%s %s %s %s %d}, want {%s %s %s %s %d}",
				c.src, tr.Form, tr.Name, tr.Type, tr.Direction, tr.Depth,
				c.form, c.name, c.typ, c.dir, c.depth)
		}
	}
}

// TestExistsOverCollection pins the §8 shape `exists(cert)`: a collection name
// inside exists() is an EXISTS over a child table, not a field.
func TestExistsOverCollection(t *testing.T) {
	res := mustParse(t, "exists(cert)")
	sub, ok := res.Root.(*ast.Sub)
	if !ok {
		t.Fatalf("exists(cert) parsed as %T, want a Sub", res.Root)
	}
	if sub.Collection != "cert" || sub.Predicate != nil {
		t.Errorf("got %+v, want the cert collection with no predicate", sub)
	}
	res = mustParse(t, "exists(owner_email)")
	if _, ok := res.Root.(*ast.Exists); !ok {
		t.Errorf("exists(owner_email) parsed as %T, want an Exists", res.Root)
	}
}

func TestEmptyQuery(t *testing.T) {
	for _, src := range []string{"", "   ", "\t"} {
		res := mustParse(t, src)
		if res.Root != nil {
			t.Errorf("Parse(%q) root = %v, want nil", src, res.Root)
		}
	}
}

func TestParenDepthIsMeasured(t *testing.T) {
	cases := map[string]int{
		"class:server":                   0,
		"(class:server)":                 1,
		"((class:server))":               2,
		"(((class:server)))":             3,
		"endpoint:(port:443)":            1,
		"endpoint:(asset:(class:a))":     2,
		"depends_on(2):(endpoint:(p:1))": 2,
		"environment in (a, b)":          1,
	}
	for src, want := range cases {
		if got := mustParse(t, src).MaxParenDepth; got != want {
			t.Errorf("%q paren depth = %d, want %d", src, got, want)
		}
	}
}

func TestSyntaxErrorsCarryASpan(t *testing.T) {
	cases := []string{
		"environment:",
		`display_name:"web`,
		"risk_score:[40 69]",
		"environment:and",
		"class:server and",
		"(class:server",
		"class:server)",
		"~ foo",
		"depends_on:(",
		"rel(depends_on):(a:1)",
		"in (a, b)",
	}
	for _, src := range cases {
		res, err := parser.Parse(src)
		if err == nil {
			t.Errorf("Parse(%q) should have failed, got %v", src, res.Root)
			continue
		}
		list, ok := err.(queryerr.List)
		if !ok || len(list) != 1 {
			t.Errorf("Parse(%q) error is %T (%v), want one queryerr", src, err, err)
			continue
		}
		e := list[0]
		if e.Code != queryerr.CodeSyntax {
			t.Errorf("Parse(%q) code = %s, want %s", src, e.Code, queryerr.CodeSyntax)
		}
		if e.Span.End < e.Span.Start || e.Span.Start > len(src) {
			t.Errorf("Parse(%q) span %v is not inside the source", src, e.Span)
		}
		if strings.ToLower(e.Message) != e.Message {
			t.Errorf("Parse(%q) message %q should be lowercase (§10)", src, e.Message)
		}
	}
}

// TestMisspelledRelationshipSuggests covers the shape the parser can still
// catch: a group whose contents are not values at all.
func TestMisspelledRelationshipSuggests(t *testing.T) {
	_, err := parser.Parse("depands_on:(class=server)")
	if err == nil {
		t.Fatal("expected a syntax error")
	}
	list := err.(queryerr.List)
	if !strings.Contains(list[0].Suggestion, "depends_on") {
		t.Errorf("suggestion %q should name depends_on", list[0].Suggestion)
	}
}

// TestRoundTrip is §10's property at the parser level: canonical text reparses
// to the same tree.
func TestRoundTrip(t *testing.T) {
	queries := []string{
		"environment:production",
		"environment:production class:server",
		"not class:hardware",
		"-class:hardware",
		"(a:1 or b:2) and c:3",
		"a:1 or (b:2 or c:3)",
		"a:1 or b:2 and c:3",
		"not (a:1 and b:2)",
		"not not a:1",
		"environment in (production, staging)",
		"environment not in (production, staging)",
		"risk_score:[40 to 69]",
		`hostname ~ "^web[0-9]{2}\\."`,
		"exists(owner_email)",
		"exists(endpoint)",
		"endpoint:(port:443 and protocol:tls)",
		"depends_on(3):(display_name:\"Payroll\")",
		"rel(connects_to, any, 2):(a:1)",
		"any_rel:(id:\"aa:bb\")",
		"tag.\"cost center\":finance",
		"payroll",
		`display_name:"has space"`,
		"last_seen < now-24h",
		"a:1 and b:2 and c:3",
	}
	for _, q := range queries {
		first := mustParse(t, q)
		canon := format.Format(first.Root)
		second, err := parser.Parse(canon)
		if err != nil {
			t.Errorf("canonical form %q of %q does not reparse: %v", canon, q, err)
			continue
		}
		if !ast.EqualJSON(first.Root, second.Root) {
			a, _ := ast.MarshalJSON(first.Root)
			b, _ := ast.MarshalJSON(second.Root)
			t.Errorf("%q round-trips to a different tree via %q\n  %s\n  %s", q, canon, a, b)
		}
		if twice := format.Format(second.Root); twice != canon {
			t.Errorf("%q: format is not idempotent: %q then %q", q, canon, twice)
		}
	}
}

func TestQuotedFieldSegmentKeepsCase(t *testing.T) {
	res := mustParse(t, `tag."Cost Center":finance`)
	cmp := res.Root.(*ast.Compare)
	if got := cmp.Field.Segments[1]; got != "Cost Center" {
		t.Errorf("quoted segment = %q, want %q", got, "Cost Center")
	}
	// An unquoted segment is lowercased: field names are case-insensitive.
	res = mustParse(t, "ENVIRONMENT:production")
	if got := res.Root.(*ast.Compare).Field.Text; got != "environment" {
		t.Errorf("field = %q, want %q", got, "environment")
	}
}

func TestStringEscapes(t *testing.T) {
	res := mustParse(t, `display_name:"a\"b\\c\nd\teA"`)
	got := res.Root.(*ast.Compare).Value.Value
	want := "a\"b\\c\nd\teA"
	if got != want {
		t.Errorf("escapes decoded to %q, want %q", got, want)
	}
	// Single quotes are accepted on input; the canonical quote is ".
	res = mustParse(t, `display_name:'single'`)
	if got := res.Root.(*ast.Compare).Value.Value; got != "single" {
		t.Errorf("single-quoted value = %q", got)
	}
}

// TestParseIsDepthBounded is the regression for the crash that could not be
// recovered from: recursive descent recurses, so deeply nested text ran the
// goroutine stack out. A stack overflow is a runtime FATAL error — the
// recover() in Parse does not catch it, and the process dies — and this input
// arrives from a URL, a saved view, a stored rule or an AI.
//
// Ten megabytes of parentheses, and ten megabytes of "not", must each come back
// as an ordinary diagnostic.
func TestParseIsDepthBounded(t *testing.T) {
	cases := map[string]string{
		"parentheses": strings.Repeat("(", 5_000_000) + "a:1" + strings.Repeat(")", 5_000_000),
		"unary not":   strings.Repeat("not ", 2_500_000) + "a:1",
		"unary dash":  strings.Repeat("-", 10_000_000) + "a:1",
		"unclosed":    strings.Repeat("(", 5_000_000),
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			res, err := parser.Parse(src)
			if err == nil {
				t.Fatalf("Parse accepted %d bytes of nesting, want a diagnostic (root %T)", len(src), res.Root)
			}
			list, ok := err.(queryerr.List)
			if !ok {
				t.Fatalf("Parse returned %T, want a queryerr.List", err)
			}
			if len(list) != 1 || list[0].Code != queryerr.CodeTooManyClauses {
				t.Fatalf("Parse reported %v, want one %s", list.Codes(), queryerr.CodeTooManyClauses)
			}
		})
	}
}

// TestParseAcceptsNestingUpToTheLimit is the other polarity: the depth guard
// must reject only absurd nesting, never ordinary nesting. MaxDepth sits well
// above §6's configurable paren cap of 16 precisely so the validator's cap is
// the one a user ever meets.
func TestParseAcceptsNestingUpToTheLimit(t *testing.T) {
	// parseOr counts one level per parenthesis plus one for the outermost
	// call, so MaxDepth-1 parentheses is the deepest input that parses.
	n := parser.MaxDepth - 1
	src := strings.Repeat("(", n) + "a:1" + strings.Repeat(")", n)
	if _, err := parser.Parse(src); err != nil {
		t.Fatalf("Parse rejected %d levels of nesting, which is inside the limit: %v", n, err)
	}
	deeper := strings.Repeat("(", n+1) + "a:1" + strings.Repeat(")", n+1)
	if _, err := parser.Parse(deeper); err == nil {
		t.Fatalf("Parse accepted %d levels of nesting, which is past MaxDepth=%d", n+1, parser.MaxDepth)
	}
}

// TestKeywordAsValueReportsTheKeyword is P2: `status:in` is not a list, it is
// someone using a keyword as a value, and it used to report `expected "("` —
// naming a bracket the user never meant to write. Every other keyword in that
// position gets "quote it"; `in` now does too.
func TestKeywordAsValueReportsTheKeyword(t *testing.T) {
	for _, src := range []string{
		"status:in",
		"status:in production",
		"status in production",
		"status not in production",
	} {
		_, err := parser.Parse(src)
		if err == nil {
			t.Errorf("Parse(%q) succeeded, want a diagnostic", src)
			continue
		}
		list, ok := err.(queryerr.List)
		if !ok || len(list) != 1 {
			t.Errorf("Parse(%q) returned %v", src, err)
			continue
		}
		if !strings.Contains(list[0].Message, "keyword") {
			t.Errorf("Parse(%q) said %q, want it to name the keyword", src, list[0].Message)
		}
		if !strings.Contains(list[0].Suggestion, `"in"`) {
			t.Errorf("Parse(%q) suggested %q, want the quoted spelling", src, list[0].Suggestion)
		}
	}
	// The other polarity: a real list still parses, negated or not.
	for _, src := range []string{
		"status in (monitoring, denied)",
		"status not in (monitoring, denied)",
		"status:in (monitoring, denied)",
	} {
		if _, err := parser.Parse(src); err != nil {
			t.Errorf("Parse(%q): %v", src, err)
		}
	}
}

// TestValueGroupNegatesEachValue is P3 (§13 amendment 3): a value group's
// "not" binds to ONE value, exactly as the outer grammar's unary does, so
// `environment:(not production and not staging)` is And{Not, Not}.
//
// It used to be a syntax error whose suggestion told the user to quote "not"
// — advice that would have silently searched for the literal string.
func TestValueGroupNegatesEachValue(t *testing.T) {
	res := mustParse(t, "environment:(not production and not staging)")
	and, ok := res.Root.(*ast.And)
	if !ok {
		t.Fatalf("root is %T, want an And", res.Root)
	}
	if len(and.Children) != 2 {
		t.Fatalf("got %d children, want 2", len(and.Children))
	}
	for i, child := range and.Children {
		not, ok := child.(*ast.Not)
		if !ok {
			t.Fatalf("child %d is %T, want a Not", i, child)
		}
		if _, ok := not.Child.(*ast.Compare); !ok {
			t.Errorf("child %d negates a %T, want a Compare: \"not\" binds to one value", i, not.Child)
		}
	}
	// Canonical form is the desugared one, and it reparses to the same tree.
	if got := format.Format(res.Root); got != "not environment:production and not environment:staging" {
		t.Errorf("canonical = %q", got)
	}

	// Mixed with "or", and negating a single value, still work.
	for _, src := range []string{
		"environment:(not production or staging)",
		"environment:(not production)",
		"tag:(dev or test)",
		"environment:(production and staging)",
	} {
		if _, err := parser.Parse(src); err != nil {
			t.Errorf("Parse(%q): %v", src, err)
		}
	}
}

// TestQuotedHeadSegmentIsAField is P4: §3's `segment = identifier | string`
// holds at the HEAD of a path, not only after a dot. `"hostname":web1` used to
// become two free-text terms — silently, with no error — because parseTerm
// only reached for a field path when the term started with an identifier
// character.
func TestQuotedHeadSegmentIsAField(t *testing.T) {
	cases := map[string]struct{ field, value string }{
		`"hostname":web1`:       {"hostname", "web1"},
		`"not":foo`:             {`"not"`, "foo"},
		`"cost center":x`:       {`"cost center"`, "x"},
		`"tag"."cost center":x`: {`tag."cost center"`, "x"},
		`"hostname"="Web01"`:    {"hostname", "Web01"},
	}
	for src, want := range cases {
		res := mustParse(t, src)
		cmp, ok := res.Root.(*ast.Compare)
		if !ok {
			t.Errorf("%q parsed as %T, want a comparison", src, res.Root)
			continue
		}
		if cmp.Field.Text != want.field || cmp.Value.Value != want.value {
			t.Errorf("%q = %s / %q, want %s / %q", src, cmp.Field.Text, cmp.Value.Value, want.field, want.value)
		}
		// The canonical form has to reparse to the same tree — a keyword head
		// that lost its quotes would not.
		canon := format.Format(res.Root)
		again := mustParse(t, canon)
		if !ast.EqualJSON(res.Root, again.Root) {
			t.Errorf("%q canonicalised to %q, which parses differently", src, canon)
		}
	}

	// The other polarity: a quoted term with no operator after it is still
	// free text, and is not turned into a field.
	for _, src := range []string{`"payroll"`, `"two words"`, `"aa:bb:cc:dd"`} {
		res := mustParse(t, src)
		if _, ok := res.Root.(*ast.FreeText); !ok {
			t.Errorf("%q parsed as %T, want free text", src, res.Root)
		}
	}
}

// TestHopCountMustBePositive is T7: the hop count is grammar, not vocabulary,
// so it is refused HERE and nowhere else.
//
// The validator carried a second `Depth < 1` check that no input could reach,
// because the parser had already rejected every way of writing one. An
// unreachable branch reads as a check that is doing something, and a second
// copy of a rule can only ever disagree with the first.
func TestHopCountMustBePositive(t *testing.T) {
	for _, src := range []string{
		"depends_on(0):(a:1)",
		"depends_on(-1):(a:1)",
		"depends_on(x):(a:1)",
		"depends_on(1.5):(a:1)",
		"depends_on():(a:1)",
		"any_rel(0):(a:1)",
		"rel(connects_to, out, 0):(a:1)",
	} {
		if res, err := parser.Parse(src); err == nil {
			t.Errorf("Parse(%q) accepted it: %v", src, res.Root)
		}
	}

	// The other polarity: one hop is the default and every positive count
	// parses, carrying the depth it was given.
	for src, want := range map[string]int{
		"depends_on:(a:1)":               1,
		"depends_on(1):(a:1)":            1,
		"depends_on(3):(a:1)":            3,
		"any_rel(6):(a:1)":               6,
		"rel(connects_to, out, 2):(a:1)": 2,
	} {
		res := mustParse(t, src)
		tr, ok := res.Root.(*ast.Traverse)
		if !ok {
			t.Errorf("%q parsed as %T, want a traversal", src, res.Root)
			continue
		}
		if tr.Depth != want {
			t.Errorf("%q depth = %d, want %d", src, tr.Depth, want)
		}
	}
}
