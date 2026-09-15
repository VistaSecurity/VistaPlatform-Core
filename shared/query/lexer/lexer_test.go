package lexer_test

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/query/lexer"
)

// scanString scans src as a value and returns the token.
func scanValue(src string) lexer.Token {
	return lexer.New(src).Next(lexer.ModeValue)
}

// TestUnicodeEscapes covers §2's `\uXXXX`, including the case that used to be
// accepted and silently changed: a lone surrogate.
//
// utf8.EncodeRune (behind strings.Builder.WriteRune) substitutes U+FFFD for
// any value in D800–DFFF, so `"\ud800"` and `"\udfff"` decoded to the SAME
// string — two different queries collapsing into one stored predicate, with no
// diagnostic anywhere. A half of a UTF-16 pair is not a character; the lexer
// refuses it.
func TestUnicodeEscapes(t *testing.T) {
	ok := map[string]string{
		`"A"`: "A",
		`"é"`: "é",
		`"€"`: "€",
		`"퟿"`: "퟿", // just below the surrogate block
		`""`: "", // just above it
		`"	"`: "\t",
	}
	for src, want := range ok {
		tok := scanValue(src)
		if tok.Kind != lexer.KindString {
			t.Errorf("%s scanned as %s (%q), want a string", src, tok.Kind, tok.Text)
			continue
		}
		if tok.Value != want {
			t.Errorf("%s decoded to %q, want %q", src, tok.Value, want)
		}
	}

	bad := []string{`"\ud800"`, `"\udc00"`, `"\udfff"`, `"\udbff"`}
	for _, src := range bad {
		tok := scanValue(src)
		if tok.Kind != lexer.KindIllegal {
			t.Errorf("%s scanned as %s (%q), want an error", src, tok.Kind, tok.Value)
			continue
		}
		if !strings.Contains(tok.Text, "surrogate") {
			t.Errorf("%s reported %q, want it to name the surrogate", src, tok.Text)
		}
	}

	// A malformed escape is still a malformed escape.
	for _, src := range []string{`"\u12"`, `"\uZZZZ"`, `"\q"`} {
		if tok := scanValue(src); tok.Kind != lexer.KindIllegal {
			t.Errorf("%s scanned as %s, want an error", src, tok.Kind)
		}
	}
}
