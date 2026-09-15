package validate

import (
	"strconv"
	"strings"
)

// The regex dialect: the common subset of RE2 and Postgres ARE (§13 A6).
//
// §2 says `~` is "case-sensitive RE2", and §6 says the validator checks the
// pattern compiles as RE2. Both are true and neither is enough, because the
// pattern is not run by Go — it is handed to Postgres `~`, which is ARE
// (Spencer). The two dialects agree on most of what anyone writes and diverge
// on a handful of constructs, in the two worst ways:
//
//   - SILENTLY. In ARE `\b` is a BACKSPACE character, not a word boundary. So
//     `hostname ~ "\bweb\b"` compiles as RE2, validates, reaches Postgres, and
//     returns the wrong rows — no error anywhere. (Verified against PG 17:
//     `'word' ~ '\bword\b'` is FALSE.)
//   - LOUDLY, at query time. `(?i)` mid-pattern, `\z`, `\p{L}`, `(?i:…)` and
//     named groups all raise "invalid regular expression" from the database,
//     which surfaces as a 500 rather than as a validation error with a span.
//
// So the language's regex is the intersection, checked by the scanner below
// BEFORE the RE2 compile (which stays, as the second check — the subset
// scanner does not verify that a bracket range is well formed, that a group is
// balanced in every way RE2 cares about, or that the pattern is otherwise
// sane).
//
// Allowed, and nothing else:
//
//	literals; "."
//	bracket classes [...] with ranges and a leading "^"
//	the escapes \d \D \w \W \s \S
//	the escaped metacharacters \. \\ \( \) \[ \] \{ \} \* \+ \? \| \^ \$ \-
//	anchors ^ $
//	groups (...) and (?:...)
//	quantifiers * + ? {n} {n,} {n,m}
//	alternation |
//	the flag group (?i), as a PREFIX only
//
// The PG probe in regex_dialect_integration_test.go runs every accepted
// construct against a live Postgres, so this list cannot drift from what the
// database actually does.

// classEscapes are the shorthand classes both dialects spell the same way.
const classEscapes = "dDwWsS"

// literalEscapes are the metacharacters an escape may make literal.
const literalEscapes = `.\()[]{}*+?|^$-`

// MaxRepetitionBound is the largest count a SINGLE repetition may carry.
//
// It is Postgres's own limit (DUPMAX, 255), not a number chosen here: `a{256}`
// raises "invalid regular expression: invalid repetition count(s)" from the
// database. §6 capped repetition at 1000, so every count from 256 to 1000
// validated and then failed at query time — the same shape as every other
// divergence in §13 A6, and found by the execution test on its first run.
//
// The cap on the PRODUCT across nesting (Options.MaxRepetition) is separate and
// still earns its place: two nested bounds of 100 are each legal and their
// product is not. Postgres rejects that as "regular expression is too complex",
// which reaches a user as a 500; the product cap makes it a validation error
// with a span.
const MaxRepetitionBound = 255

// maxRegexNesting caps the subset scanner's own recursion. A pattern is at most
// MaxRegexLen runes, so nesting cannot exceed that — but the scanner recurses
// per group, and a cap is cheaper than trusting the caller's cap to be small.
const maxRegexNesting = 64

// repetitionCeiling clamps the running repetition product so a deeply nested
// pattern cannot overflow int before the cap is compared.
const repetitionCeiling = 1 << 30

// checkRegexSubset validates pattern against the common subset and returns the
// largest effective repetition count in it — the PRODUCT along the nesting, so
// `(a{100}){100}` counts as 10,000 rather than 100.
//
// problem is empty when the pattern is inside the subset; otherwise it names
// the construct, for a message a user can act on.
func checkRegexSubset(pattern string) (maxRepetition int, problem string) {
	s := &reScanner{src: []rune(pattern)}
	// (?i) is the one flag group, and only as a prefix: ARE rejects it
	// anywhere else, so accepting it mid-pattern would be storing a query the
	// database refuses to run.
	if strings.HasPrefix(pattern, "(?i)") {
		s.pos = 4
	}
	max := s.alt(0)
	if s.problem != "" {
		return 0, s.problem
	}
	if s.pos < len(s.src) {
		return 0, "unbalanced " + strconv.Quote(string(s.src[s.pos]))
	}
	return max, ""
}

type reScanner struct {
	src     []rune
	pos     int
	problem string
}

func (s *reScanner) fail(format string) {
	if s.problem == "" {
		s.problem = format
	}
}

func (s *reScanner) peek() rune {
	if s.pos >= len(s.src) {
		return 0
	}
	return s.src[s.pos]
}

// alt reads `seq { "|" seq }` and returns the largest repetition product in it.
func (s *reScanner) alt(depth int) int {
	if depth > maxRegexNesting {
		s.fail("pattern nests more than " + strconv.Itoa(maxRegexNesting) + " groups deep")
		return 1
	}
	max := s.seq(depth)
	for s.problem == "" && s.peek() == '|' {
		s.pos++
		if n := s.seq(depth); n > max {
			max = n
		}
	}
	return max
}

// seq reads a run of quantified atoms.
func (s *reScanner) seq(depth int) int {
	max := 1
	for s.problem == "" && s.pos < len(s.src) {
		switch s.peek() {
		case '|', ')':
			return max
		}
		inside := s.atom(depth)
		if s.problem != "" {
			return max
		}
		bound := s.quantifier()
		if s.problem != "" {
			return max
		}
		if n := clampProduct(inside, bound); n > max {
			max = n
		}
	}
	return max
}

// atom reads one atom and returns the largest repetition product inside it (1
// for anything but a group).
func (s *reScanner) atom(depth int) int {
	c := s.src[s.pos]
	switch c {
	case '(':
		return s.group(depth)
	case '[':
		s.class()
		return 1
	case '.', '^', '$', '}':
		// "}" with no "{" to close is an ordinary character in both dialects.
		s.pos++
		return 1
	case '\\':
		s.escape()
		return 1
	case '*', '+', '?':
		s.fail("quantifier " + strconv.Quote(string(c)) + " with nothing to repeat")
		return 1
	case '{':
		// A "{" that does not open a valid repetition is a literal brace in
		// both dialects today, but only by accident of two different parsers
		// agreeing. Say what to write instead.
		s.fail(`"{" must open a repetition like {2} or {2,5}; write \{ for a literal brace`)
		return 1
	}
	s.pos++
	return 1
}

// group reads "(...)" or "(?:...)", and rejects every other "(?" form.
func (s *reScanner) group(depth int) int {
	s.pos++ // "("
	if s.peek() == '?' {
		rest := string(s.src[s.pos:])
		switch {
		case strings.HasPrefix(rest, "?:"):
			s.pos += 2
		case strings.HasPrefix(rest, "?i)"):
			s.fail(`the "(?i)" flag is only allowed at the start of the pattern`)
			return 1
		default:
			s.fail(`only "(...)" and "(?:...)" groups are allowed`)
			return 1
		}
	}
	inside := s.alt(depth + 1)
	if s.problem != "" {
		return inside
	}
	if s.peek() != ')' {
		s.fail("unterminated group")
		return inside
	}
	s.pos++
	return inside
}

// class reads a bracket expression. Escapes and nested "[" are refused inside
// one: ARE reads `[[:alpha:]]` as a POSIX class and `[]]` as a class containing
// "]", and RE2 does not agree about either.
func (s *reScanner) class() {
	s.pos++ // "["
	if s.peek() == '^' {
		s.pos++
	}
	for s.pos < len(s.src) {
		switch s.src[s.pos] {
		case ']':
			s.pos++
			return
		case '\\':
			s.fail(`a "\" is not allowed inside a character class; the characters in one are already literal`)
			return
		case '[':
			s.fail(`a "[" is not allowed inside a character class`)
			return
		}
		s.pos++
	}
	s.fail("unterminated character class")
}

// escape reads a backslash escape and rejects everything outside the subset.
func (s *reScanner) escape() {
	s.pos++ // "\"
	if s.pos >= len(s.src) {
		s.fail(`pattern ends in a "\"`)
		return
	}
	c := s.src[s.pos]
	if strings.ContainsRune(classEscapes, c) || strings.ContainsRune(literalEscapes, c) {
		s.pos++
		return
	}
	s.fail(`the escape "\` + string(c) + `" is not in the common subset of RE2 and Postgres` +
		escapeHint(c))
}

// escapeHint adds the specific reason for the escapes people actually reach
// for, because "not in the subset" alone does not tell them what to do.
func escapeHint(c rune) string {
	switch c {
	case 'b', 'B':
		return `: Postgres reads "\b" as a backspace character, not a word boundary`
	case 'A', 'z', 'Z':
		return `: use "^" and "$"`
	case 'p', 'P':
		return `: write the characters out in a [...] class`
	case '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return ": RE2 has no backreferences"
	case 'n', 't', 'r':
		return `: put the character itself in the pattern, or write it as \uXXXX in the query string`
	}
	return ""
}

// quantifier reads an optional quantifier and returns its upper bound (1 when
// there is none). A lazy quantifier is refused: both dialects accept `a+?` and
// they do not agree on what it means.
func (s *reScanner) quantifier() int {
	bound := 1
	switch s.peek() {
	case '*', '+', '?':
		s.pos++
	case '{':
		bound = s.repetition()
		if s.problem != "" {
			return bound
		}
	default:
		return bound
	}
	if s.peek() == '?' {
		s.fail("a non-greedy quantifier means different things in RE2 and in Postgres")
	}
	return bound
}

// repetition reads `{n}`, `{n,}` or `{n,m}` and returns the largest count.
func (s *reScanner) repetition() int {
	start := s.pos
	s.pos++ // "{"
	lo, ok := s.number()
	if !ok {
		s.pos = start
		s.fail(`a repetition is written {n}, {n,} or {n,m}; write \{ for a literal brace`)
		return 1
	}
	max := lo
	if s.peek() == ',' {
		s.pos++
		if hi, ok := s.number(); ok {
			max = hi
		}
	}
	if s.peek() != '}' {
		s.pos = start
		s.fail(`a repetition is written {n}, {n,} or {n,m}; write \{ for a literal brace`)
		return 1
	}
	s.pos++
	if max > MaxRepetitionBound {
		s.fail("a single repetition count may not exceed " + strconv.Itoa(MaxRepetitionBound) +
			"; Postgres refuses a larger one outright")
		return 1
	}
	return max
}

// number reads a run of digits. It reports false for an absent number and for
// one too large to be a repetition count — `a{99999999999999999999}` is not a
// malformed brace, it is a count nobody meant.
func (s *reScanner) number() (int, bool) {
	start := s.pos
	for s.pos < len(s.src) && s.src[s.pos] >= '0' && s.src[s.pos] <= '9' {
		s.pos++
	}
	if s.pos == start {
		return 0, false
	}
	n, err := strconv.Atoi(string(s.src[start:s.pos]))
	if err != nil {
		// Out of int range. Report it as an enormous count rather than as a
		// syntax problem, so the repetition cap is what rejects it.
		return repetitionCeiling, true
	}
	return n, true
}

// clampProduct multiplies without overflowing, so a deeply nested pattern is
// compared against the cap rather than wrapping past it.
func clampProduct(a, b int) int {
	if a <= 0 || b <= 0 {
		return 0
	}
	if a > repetitionCeiling/b {
		return repetitionCeiling
	}
	return a * b
}
