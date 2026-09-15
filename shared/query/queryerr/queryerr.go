// Package queryerr holds the structured error the query language reports.
//
// QUERY_LANGUAGE.md §10: errors are `{code, message, span, suggestion?}`.
// Messages are lowercase, name the offending span, and offer the fix — never
// "invalid query". §6 fixes the code vocabulary for validation; `syntax_error`
// is the one addition, for text that does not parse at all.
package queryerr

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
)

// Code is the stable, machine-readable error code. Callers switch on it; the
// UI maps it to help text.
type Code string

const (
	// CodeSyntax is text that does not parse. Not in §6's table, which covers
	// validation only; a parse failure has to report something.
	CodeSyntax Code = "syntax_error"
	// CodeUnknownField is a field that resolves in no namespace for the target.
	CodeUnknownField Code = "unknown_field"
	// CodeOperatorNotAllowed is an operator the field's type does not accept.
	CodeOperatorNotAllowed Code = "operator_not_allowed"
	// CodeTypeMismatch is a literal that does not parse as the field's type.
	CodeTypeMismatch Code = "type_mismatch"
	// CodeUnknownValue is a value outside a closed set: an enum member, a
	// class key, a relationship name.
	CodeUnknownValue Code = "unknown_value"
	// CodeDepthExceeded is a traversal budget over the configured or hard cap.
	CodeDepthExceeded Code = "depth_exceeded"
	// CodeRegexInvalid is a pattern that is not RE2, is too long, or repeats
	// more than a thousand times.
	CodeRegexInvalid Code = "regex_invalid"
	// CodeQueryTooLong is query text over 4096 bytes.
	CodeQueryTooLong Code = "query_too_long"
	// CodeTooManyClauses is any of the four size caps in §6.
	CodeTooManyClauses Code = "too_many_clauses"
	// CodeUntranslatable is a node that maps to none of the five SQL shapes.
	// Fail-closed: the translator refuses rather than guessing.
	CodeUntranslatable Code = "untranslatable"
)

// Error is one structured diagnostic.
type Error struct {
	Code       Code     `json:"code"`
	Message    string   `json:"message"`
	Span       ast.Span `json:"span"`
	Suggestion string   `json:"suggestion,omitempty"`
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Suggestion != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Suggestion)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// New builds an error without a suggestion.
func New(code Code, span ast.Span, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...), Span: span}
}

// WithSuggestion returns a copy of e carrying the given suggestion.
func (e *Error) WithSuggestion(format string, args ...any) *Error {
	out := *e
	out.Suggestion = fmt.Sprintf(format, args...)
	return &out
}

// List is a set of diagnostics, reported together so a user sees every problem
// at once rather than one per round trip.
type List []*Error

// Error implements the error interface.
func (l List) Error() string {
	if len(l) == 0 {
		return "no errors"
	}
	parts := make([]string, 0, len(l))
	for _, e := range l {
		parts = append(parts, e.Error())
	}
	return strings.Join(parts, "; ")
}

// Add appends an error and returns the list, for `errs = errs.Add(…)`.
func (l List) Add(e *Error) List {
	if e == nil {
		return l
	}
	return append(l, e)
}

// Sorted returns the list ordered by span start, then by code, so output is
// deterministic regardless of walk order.
func (l List) Sorted() List {
	out := make(List, len(l))
	copy(out, l)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Span.Start != out[j].Span.Start {
			return out[i].Span.Start < out[j].Span.Start
		}
		return out[i].Code < out[j].Code
	})
	return out
}

// Codes returns just the codes, in list order. Tests and fixtures compare
// codes, not messages, so message wording can improve without churn.
func (l List) Codes() []Code {
	out := make([]Code, 0, len(l))
	for _, e := range l {
		out = append(out, e.Code)
	}
	return out
}

// Has reports whether the list contains an error with the given code.
func (l List) Has(code Code) bool {
	for _, e := range l {
		if e.Code == code {
			return true
		}
	}
	return false
}

// OrNil returns nil when the list is empty, so callers can `if err != nil`.
func (l List) OrNil() error {
	if len(l) == 0 {
		return nil
	}
	return l
}

// Nearest returns the candidate closest to word by Levenshtein distance, when
// that distance is at most maxDist. §6 fixes maxDist at 2 for the unknown_field
// suggestion; the same helper builds every other "did you mean" in the package
// so one notion of "close" is used everywhere.
func Nearest(word string, candidates []string, maxDist int) (string, bool) {
	word = strings.ToLower(word)
	best, bestDist := "", maxDist+1
	for _, c := range candidates {
		d := Levenshtein(word, strings.ToLower(c))
		if d < bestDist || (d == bestDist && best != "" && c < best) {
			best, bestDist = c, d
		}
	}
	if bestDist > maxDist {
		return "", false
	}
	return best, true
}

// NearestValue is Nearest with one extra fallback, for closed value sets: a
// candidate that starts with the word (or that the word starts with) is offered
// even when the edit distance is larger, because a value is often the short
// form of a longer one — "pending" for "pending_approval". Field suggestions
// deliberately do NOT use this: §6 fixes those at edit distance 2.
func NearestValue(word string, candidates []string) (string, bool) {
	if near, ok := Nearest(word, candidates, 2); ok {
		return near, true
	}
	lower := strings.ToLower(word)
	best := ""
	for _, c := range candidates {
		lc := strings.ToLower(c)
		if lower == "" || lc == "" {
			continue
		}
		if !strings.HasPrefix(lc, lower) && !strings.HasPrefix(lower, lc) {
			continue
		}
		if best == "" || len(c) < len(best) {
			best = c
		}
	}
	return best, best != ""
}

// Levenshtein returns the edit distance between a and b.
func Levenshtein(a, b string) int {
	ar, br := []rune(a), []rune(b)
	prev := make([]int, len(br)+1)
	cur := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		cur[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			cur[j] = min3(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(br)]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

// Caret renders the §10 error display: the query, a caret run under the span,
// and the message. Used by the CLI and by test failure output.
func Caret(src string, e *Error) string {
	start, end := e.Span.Start, e.Span.End
	if start < 0 {
		start = 0
	}
	if end > len(src) {
		end = len(src)
	}
	if end <= start {
		end = start + 1
	}
	var b strings.Builder
	b.WriteString(src)
	b.WriteByte('\n')
	b.WriteString(strings.Repeat(" ", start))
	b.WriteString(strings.Repeat("^", end-start))
	b.WriteByte('\n')
	b.WriteString(string(e.Code))
	b.WriteString(": ")
	b.WriteString(e.Message)
	if e.Suggestion != "" {
		b.WriteByte('\n')
		b.WriteString(e.Suggestion)
	}
	return b.String()
}
