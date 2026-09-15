// Package lexer scans query text into tokens.
//
// The scanner is mode-driven, because the language is: after a field separator
// or an operator, a bare value may contain `:` `/` `*` and friends (§2), so
// `id.mac:aa:bb:*` is a field, a separator and one value — not five tokens. The
// parser therefore asks for the next token in the mode it expects, which is the
// smallest mechanism that makes §2's rule true without a second grammar.
package lexer

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
)

// Kind is the lexical class of a token.
type Kind string

const (
	// KindEOF is the end of input.
	KindEOF Kind = "eof"
	// KindIdent is an identifier: [A-Za-z_][A-Za-z0-9_]*.
	KindIdent Kind = "ident"
	// KindString is a quoted string; Value holds the decoded text.
	KindString Kind = "string"
	// KindBare is a run of bare-value characters, scanned in value mode.
	KindBare Kind = "bare"
	// KindLParen is "(".
	KindLParen Kind = "("
	// KindRParen is ")".
	KindRParen Kind = ")"
	// KindLBracket is "[".
	KindLBracket Kind = "["
	// KindRBracket is "]".
	KindRBracket Kind = "]"
	// KindComma is ",".
	KindComma Kind = ","
	// KindColon is ":" used as a field separator.
	KindColon Kind = ":"
	// KindDot is "." between field segments.
	KindDot Kind = "."
	// KindOp is a comparison operator: = := != < <= > >= ~.
	KindOp Kind = "op"
	// KindMinus is a leading "-" negation.
	KindMinus Kind = "-"
	// KindIllegal is a character that starts no token in the current mode, or
	// a malformed string. Text carries a human-readable reason.
	KindIllegal Kind = "illegal"
)

// Mode selects the scanning rules for one token.
type Mode int

const (
	// ModeDefault scans structure: identifiers, punctuation and operators.
	ModeDefault Mode = iota
	// ModeValue scans a value position: a quoted string, a bare run, or the
	// punctuation that opens a group, a list or a range.
	ModeValue
)

// Token is one lexeme.
type Token struct {
	Kind Kind
	// Text is the raw source text of the token.
	Text string
	// Value is the decoded value; it differs from Text only for strings.
	Value string
	Span  ast.Span
}

// Lexer scans a query string. It holds no state beyond a position, so the
// parser can save and restore it to re-scan a term in another mode.
type Lexer struct {
	src string
	pos int
}

// New returns a lexer over src.
func New(src string) *Lexer { return &Lexer{src: src} }

// Src returns the source text.
func (l *Lexer) Src() string { return l.src }

// Mark returns the current position, for Reset.
func (l *Lexer) Mark() int { return l.pos }

// Reset moves the scanner back to a position returned by Mark.
func (l *Lexer) Reset(pos int) { l.pos = pos }

// Pos returns the current byte offset.
func (l *Lexer) Pos() int { return l.pos }

// SkipSpace advances past whitespace and returns the new position.
func (l *Lexer) SkipSpace() int {
	for l.pos < len(l.src) {
		switch l.src[l.pos] {
		case ' ', '\t', '\n', '\r':
			l.pos++
		default:
			return l.pos
		}
	}
	return l.pos
}

// EOF is what PeekRune returns at end of input. It is not zero, because a NUL
// byte in the middle of a query is a character like any other and must not be
// mistaken for the end of the text.
const EOF = rune(-1)

// PeekRune returns the next rune after any whitespace, without consuming it,
// or EOF at end of input.
func (l *Lexer) PeekRune() rune {
	p := l.pos
	l.SkipSpace()
	r := EOF
	if l.pos < len(l.src) {
		r, _ = utf8.DecodeRuneInString(l.src[l.pos:])
	}
	l.pos = p
	return r
}

// Peek scans the next token in the given mode without consuming it.
func (l *Lexer) Peek(mode Mode) Token {
	p := l.pos
	tok := l.Next(mode)
	l.pos = p
	return tok
}

// Next scans and consumes the next token in the given mode.
func (l *Lexer) Next(mode Mode) Token {
	l.SkipSpace()
	start := l.pos
	if l.pos >= len(l.src) {
		return Token{Kind: KindEOF, Span: ast.Span{Start: start, End: start}}
	}
	c := l.src[l.pos]

	// Punctuation that means the same thing in both modes.
	switch c {
	case '(':
		l.pos++
		return l.tok(KindLParen, start)
	case ')':
		l.pos++
		return l.tok(KindRParen, start)
	case '[':
		l.pos++
		return l.tok(KindLBracket, start)
	case ']':
		l.pos++
		return l.tok(KindRBracket, start)
	case ',':
		l.pos++
		return l.tok(KindComma, start)
	case '"', '\'':
		return l.scanString()
	}

	if mode == ModeValue {
		return l.scanBare(start)
	}

	switch {
	case isIdentStart(c):
		l.pos++
		for l.pos < len(l.src) && isIdentPart(l.src[l.pos]) {
			l.pos++
		}
		return l.tok(KindIdent, start)
	case c == '.':
		l.pos++
		return l.tok(KindDot, start)
	case c == ':':
		// ":=" is the accepted alias for "=" (§3 cheat sheet).
		if l.pos+1 < len(l.src) && l.src[l.pos+1] == '=' {
			l.pos += 2
			return l.tok(KindOp, start)
		}
		l.pos++
		return l.tok(KindColon, start)
	case c == '-':
		l.pos++
		return l.tok(KindMinus, start)
	case c == '=' || c == '~':
		l.pos++
		return l.tok(KindOp, start)
	case c == '!':
		if l.pos+1 < len(l.src) && l.src[l.pos+1] == '=' {
			l.pos += 2
			return l.tok(KindOp, start)
		}
		l.pos++
		return Token{Kind: KindIllegal, Text: "expected \"!=\"", Span: ast.Span{Start: start, End: l.pos}}
	case c == '<' || c == '>':
		l.pos++
		if l.pos < len(l.src) && l.src[l.pos] == '=' {
			l.pos++
		}
		return l.tok(KindOp, start)
	}

	l.pos += runeLen(l.src[l.pos:])
	return Token{
		Kind: KindIllegal,
		Text: "unexpected character " + strconv.QuoteRune(firstRune(l.src[start:l.pos])),
		Span: ast.Span{Start: start, End: l.pos},
	}
}

// scanBare scans a run of bare-value characters (§2).
func (l *Lexer) scanBare(start int) Token {
	for l.pos < len(l.src) {
		r, size := utf8.DecodeRuneInString(l.src[l.pos:])
		if !ast.IsBareValueChar(r) {
			break
		}
		l.pos += size
	}
	if l.pos == start {
		l.pos += runeLen(l.src[l.pos:])
		return Token{
			Kind: KindIllegal,
			Text: "expected a value, found " + strconv.QuoteRune(firstRune(l.src[start:l.pos])),
			Span: ast.Span{Start: start, End: l.pos},
		}
	}
	return l.tok(KindBare, start)
}

// scanString scans a quoted string and decodes §2's escapes.
func (l *Lexer) scanString() Token {
	start := l.pos
	quote := l.src[l.pos]
	l.pos++
	var b strings.Builder
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch c {
		case quote:
			l.pos++
			return Token{
				Kind:  KindString,
				Text:  l.src[start:l.pos],
				Value: b.String(),
				Span:  ast.Span{Start: start, End: l.pos},
			}
		case '\\':
			l.pos++
			if l.pos >= len(l.src) {
				return l.unterminated(start)
			}
			switch e := l.src[l.pos]; e {
			case '\\', '"', '\'':
				b.WriteByte(e)
				l.pos++
			case 'n':
				b.WriteByte('\n')
				l.pos++
			case 't':
				b.WriteByte('\t')
				l.pos++
			case 'r':
				b.WriteByte('\r')
				l.pos++
			case 'u':
				if l.pos+4 >= len(l.src) {
					return l.badEscape(start, "\\u needs four hex digits")
				}
				hex := l.src[l.pos+1 : l.pos+5]
				n, err := strconv.ParseUint(hex, 16, 32)
				if err != nil {
					return l.badEscape(start, "\\u needs four hex digits")
				}
				if n >= 0xD800 && n <= 0xDFFF {
					// A surrogate is half of a UTF-16 pair and is not a
					// character. WriteRune would silently substitute U+FFFD,
					// so \ud800 and \udfff would decode to the SAME value —
					// two different queries, one stored predicate. Refuse it
					// rather than quietly changing what was written.
					return l.badEscape(start, "\\u"+hex+" is an unpaired surrogate, not a character")
				}
				b.WriteRune(rune(n))
				l.pos += 5
			default:
				return l.badEscape(start, "unknown escape \\"+string(e))
			}
		default:
			r, size := utf8.DecodeRuneInString(l.src[l.pos:])
			b.WriteRune(r)
			l.pos += size
		}
	}
	return l.unterminated(start)
}

func (l *Lexer) unterminated(start int) Token {
	l.pos = len(l.src)
	return Token{
		Kind: KindIllegal,
		Text: "unterminated string",
		Span: ast.Span{Start: start, End: l.pos},
	}
}

func (l *Lexer) badEscape(start int, reason string) Token {
	l.pos = len(l.src)
	return Token{Kind: KindIllegal, Text: reason, Span: ast.Span{Start: start, End: l.pos}}
}

func (l *Lexer) tok(kind Kind, start int) Token {
	text := l.src[start:l.pos]
	return Token{Kind: kind, Text: text, Value: text, Span: ast.Span{Start: start, End: l.pos}}
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

func runeLen(s string) int {
	if s == "" {
		return 1
	}
	_, size := utf8.DecodeRuneInString(s)
	return size
}

func firstRune(s string) rune {
	r, _ := utf8.DecodeRuneInString(s)
	return r
}
