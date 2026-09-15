package queryerr

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
)

var fields = []string{"hostname", "display_name", "environment", "owner_email", "class", "risk_score"}

// TestNearestRespectsTheDistanceCap is T4. §6 fixes the unknown_field
// suggestion at edit distance 2, and nothing checked either end of that: a
// suggestion offered for a name nothing like the one written is worse than no
// suggestion, because it sends the user off to try it.
func TestNearestRespectsTheDistanceCap(t *testing.T) {
	within := map[string]string{
		"hostnaem":     "hostname", // transposition: 2
		"hostnam":      "hostname", // deletion: 1
		"hostnames":    "hostname", // insertion: 1
		"HOSTNAME":     "hostname", // case only: 0
		"clas":         "class",
		"risk_scor":    "risk_score",
		"display_nam":  "display_name",
		"environmentt": "environment",
	}
	for word, want := range within {
		got, ok := Nearest(word, fields, 2)
		if !ok {
			t.Errorf("Nearest(%q) found nothing; %q is within two edits", word, want)
			continue
		}
		if got != want {
			t.Errorf("Nearest(%q) = %q, want %q", word, got, want)
		}
	}

	// Three or more edits away: no suggestion at all.
	beyond := []string{
		"xyz",  // nothing like anything
		"host", // 4 from hostname
		"",     // nothing written
		"completely_made_up_field",
		"riskscoreish", // 3 from risk_score
	}
	for _, word := range beyond {
		if got, ok := Nearest(word, fields, 2); ok {
			t.Errorf("Nearest(%q) offered %q; it is more than two edits from every candidate", word, got)
		}
	}

	// The cap is the parameter, not a constant baked into the helper.
	if _, ok := Nearest("host", fields, 2); ok {
		t.Error(`"host" should be outside a cap of 2`)
	}
	if got, ok := Nearest("host", fields, 4); !ok || got != "class" && got != "hostname" {
		t.Errorf("Nearest(host, 4) = %q,%v — a wider cap should find something", got, ok)
	}

	// Ties break deterministically, so the same typo always gets the same
	// advice.
	tied := []string{"beta", "alfa", "alpa"}
	first, _ := Nearest("alpha", tied, 2)
	for i := 0; i < 20; i++ {
		if again, _ := Nearest("alpha", tied, 2); again != first {
			t.Fatalf("Nearest is not deterministic: %q then %q", first, again)
		}
	}
}

// TestNearestValueAlsoTakesPrefixes covers the extra rule for closed value
// sets: a value is often the short form of a longer one, and "pending" for
// "pending_approval" is six edits away. Field suggestions deliberately do NOT
// get this — §6 fixes those at distance 2.
func TestNearestValueAlsoTakesPrefixes(t *testing.T) {
	values := []string{"pending_approval", "monitoring", "denied", "archived"}

	if got, ok := NearestValue("pending", values); !ok || got != "pending_approval" {
		t.Errorf("NearestValue(pending) = %q,%v want pending_approval", got, ok)
	}
	// The plain helper does not, at the same distance.
	if got, ok := Nearest("pending", values, 2); ok {
		t.Errorf("Nearest(pending) offered %q; §6 caps a FIELD suggestion at two edits", got)
	}
	// A typo still works through the distance rule.
	if got, ok := NearestValue("monitorng", values); !ok || got != "monitoring" {
		t.Errorf("NearestValue(monitorng) = %q,%v want monitoring", got, ok)
	}
	// And a word related to nothing still gets nothing.
	if got, ok := NearestValue("zzzzzz", values); ok {
		t.Errorf("NearestValue(zzzzzz) offered %q", got)
	}
	// An empty word must not match every candidate by prefix.
	if got, ok := NearestValue("", values); ok {
		t.Errorf("NearestValue(\"\") offered %q", got)
	}
}

func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"a", "", 1},
		{"", "abc", 3},
		{"abc", "abc", 0},
		{"hostnaem", "hostname", 2},
		{"kitten", "sitting", 3},
		// Runes, not bytes: "é" is two bytes and one edit.
		{"café", "cafe", 1},
		{"héllo", "hello", 1},
	}
	for _, c := range cases {
		if got := Levenshtein(c.a, c.b); got != c.want {
			t.Errorf("Levenshtein(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := Levenshtein(c.b, c.a); got != c.want {
			t.Errorf("Levenshtein is not symmetric for %q/%q", c.a, c.b)
		}
	}
}

// TestListOrdering pins the two properties callers depend on: Sorted is stable
// and by span, so output does not depend on the validator's walk order, and
// OrNil lets a caller write `if err != nil`.
func TestListOrdering(t *testing.T) {
	var l List
	l = l.Add(New(CodeUnknownField, ast.Span{Start: 20, End: 25}, "third"))
	l = l.Add(New(CodeTypeMismatch, ast.Span{Start: 0, End: 5}, "first"))
	l = l.Add(New(CodeUnknownValue, ast.Span{Start: 10, End: 12}, "second"))
	// Same span, different codes: ordered by code so the output is stable.
	l = l.Add(New(CodeDepthExceeded, ast.Span{Start: 10, End: 12}, "second-a"))

	got := l.Sorted()
	want := []string{"first", "second-a", "second", "third"}
	for i, w := range want {
		if got[i].Message != w {
			t.Errorf("sorted[%d] = %q, want %q", i, got[i].Message, w)
		}
	}
	// Sorted does not mutate the receiver.
	if l[0].Message != "third" {
		t.Error("Sorted mutated the list it was called on")
	}

	if l.Has(CodeRegexInvalid) {
		t.Error("Has should be false for a code that is not present")
	}
	if !l.Has(CodeUnknownField) {
		t.Error("Has should be true for a code that is")
	}
	if (List{}).OrNil() != nil {
		t.Error("an empty list should be nil as an error")
	}
	if l.OrNil() == nil {
		t.Error("a non-empty list should not be nil as an error")
	}
	if l.Add(nil).Error() == "" {
		t.Error("Add(nil) should be a no-op, not a panic")
	}
}

// TestCaretRendersTheSpan covers §10's display, including the ends: a span at
// the very start, a zero-width one, and one that runs past the text (a
// truncated query reaching an error renderer should not panic).
func TestCaretRendersTheSpan(t *testing.T) {
	const src = "environment:production and hostnaem:web-1"
	e := New(CodeUnknownField, ast.Span{Start: 27, End: 35}, "no field %q", "hostnaem").
		WithSuggestion("did you mean %q?", "hostname")

	out := Caret(src, e)
	lines := strings.Split(out, "\n")
	if len(lines) != 4 {
		t.Fatalf("Caret rendered %d lines, want 4:\n%s", len(lines), out)
	}
	if lines[0] != src {
		t.Errorf("line 1 should be the query, got %q", lines[0])
	}
	if lines[1] != strings.Repeat(" ", 27)+strings.Repeat("^", 8) {
		t.Errorf("carets are not under the span:\n%s", out)
	}
	if !strings.HasPrefix(lines[2], string(CodeUnknownField)+": ") {
		t.Errorf("line 3 should open with the code, got %q", lines[2])
	}
	if lines[3] != `did you mean "hostname"?` {
		t.Errorf("line 4 should be the suggestion, got %q", lines[3])
	}

	// Degenerate spans must render, not panic.
	for _, sp := range []ast.Span{
		{Start: 0, End: 0},
		{Start: -5, End: 3},
		{Start: 0, End: len(src) + 100},
		{Start: len(src), End: len(src)},
	} {
		if got := Caret(src, New(CodeSyntax, sp, "x")); got == "" {
			t.Errorf("Caret(%v) rendered nothing", sp)
		}
	}
}

func TestErrorStrings(t *testing.T) {
	e := New(CodeSyntax, ast.Span{}, "bad %s", "thing")
	if got := e.Error(); got != "syntax_error: bad thing" {
		t.Errorf("Error() = %q", got)
	}
	withSug := e.WithSuggestion("try %q", "x")
	if got := withSug.Error(); got != `syntax_error: bad thing (try "x")` {
		t.Errorf("Error() with a suggestion = %q", got)
	}
	// WithSuggestion returns a copy; the original is untouched.
	if e.Suggestion != "" {
		t.Error("WithSuggestion mutated the receiver")
	}
	if (List{}).Error() != "no errors" {
		t.Errorf("an empty list should say so")
	}
	l := List{e, withSug}
	if got := l.Codes(); len(got) != 2 || got[0] != CodeSyntax {
		t.Errorf("Codes() = %v", got)
	}
}
