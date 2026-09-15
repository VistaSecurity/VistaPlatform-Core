package validate

import (
	"regexp"
	"strings"
	"testing"
	"unicode"
)

// acceptedPatterns is every construct §13 A6 admits. The integration test in
// regex_dialect_integration_test.go runs this exact table against a live
// Postgres, so the list cannot drift from what the database does.
var acceptedPatterns = []string{
	`^web[0-9]{2}\.`,
	`web`,
	`.`,
	`^web`,
	`web$`,
	`^$`,
	`[0-9]`,
	`[^a-z]`,
	`[a-zA-Z0-9_.-]`,
	`[-x]`,
	`[x-]`,
	`\d`, `\D`, `\w`, `\W`, `\s`, `\S`,
	`\d+`,
	`\.`, `\\`, `\(`, `\)`, `\[`, `\]`, `\{`, `\}`,
	`\*`, `\+`, `\?`, `\|`, `\^`, `\$`, `\-`,
	`a|b`,
	`(ab)`,
	`(ab)+`,
	`(?:ab)`,
	`(?:ab)*`,
	`a?`,
	`a*`,
	`a+`,
	`a{2}`,
	`a{2,}`,
	`a{2,5}`,
	`(?i)web`,
	`(?i)^web[0-9]{2}$`,
	`^(web|db)[0-9]{1,3}\.example\.com$`,
	`(a(b(c)))`,
	`a}b`,
	`(a{10}){10}`,
}

// rejectedPatterns are the constructs RE2 and Postgres ARE do not agree on, or
// that only one of them has. Each entry names why, so the table doubles as the
// documentation for §13 A6.
var rejectedPatterns = map[string]string{
	// Postgres reads \b as BACKSPACE. This one is the reason the whole subset
	// exists: it compiles as RE2, validates, reaches the database, and returns
	// the wrong rows with no error anywhere.
	`\bword\b`: "word boundary",
	`\Bword`:   "non-boundary",
	// Postgres raises "invalid regular expression" at query time.
	`web(?i)01`:   "(?i) mid-pattern",
	`(?i:web)`:    "flag group",
	`(?m)^web`:    "multiline flag",
	`(?P<n>web)`:  "named group (Go spelling)",
	`(?<n>web)`:   "named group (PCRE spelling)",
	`(?=web)`:     "lookahead",
	`(?!web)`:     "negative lookahead",
	`web\z`:       `\z`,
	`\Aweb`:       `\A`,
	`\p{L}`:       "unicode class",
	`\P{L}`:       "negated unicode class",
	`(a)\1`:       "backreference",
	`a+?`:         "lazy quantifier",
	`a*?`:         "lazy star",
	`a{2,3}?`:     "lazy repetition",
	`a{,3}`:       "open-lower repetition",
	`[[:alpha:]]`: "POSIX class",
	`[a\]]`:       "escape inside a class",
	`a\nb`:        "newline escape",
	`a\tb`:        "tab escape",
	`a\x41`:       "hex escape",
	// Structural problems the scanner should name rather than pass on.
	`(ab`:  "unterminated group",
	`ab)`:  "unbalanced close",
	`[a-z`: "unterminated class",
	`*a`:   "quantifier with nothing to repeat",
	`a{b}`: "brace that is not a repetition",
	`a\`:   "trailing backslash",
}

func TestRegexSubsetAcceptsTheDialect(t *testing.T) {
	for _, pat := range acceptedPatterns {
		if _, problem := checkRegexSubset(pat); problem != "" {
			t.Errorf("checkRegexSubset(%q) refused it: %s", pat, problem)
		}
		// Everything in the subset must also compile as RE2, or the second
		// check would reject what the first one admitted.
		if _, err := regexp.Compile(pat); err != nil {
			t.Errorf("%q is in the subset but is not valid RE2: %v", pat, err)
		}
	}
}

func TestRegexSubsetRejectsWhatTheDialectsDisagreeOn(t *testing.T) {
	for pat, why := range rejectedPatterns {
		_, problem := checkRegexSubset(pat)
		if problem == "" {
			t.Errorf("checkRegexSubset(%q) accepted it; it is a %s", pat, why)
			continue
		}
		// §10: messages are lowercase. Proper nouns inside one (RE2, Postgres)
		// are not the thing that rule is about, so only the opening matters.
		if r := []rune(problem)[0]; unicode.IsUpper(r) {
			t.Errorf("%q: message %q should not start with a capital (§10)", pat, problem)
		}
	}
}

// TestRegexSubsetNamesTheConstruct holds the messages to §10: never "invalid
// query", always the thing that is wrong and what to write instead.
func TestRegexSubsetNamesTheConstruct(t *testing.T) {
	cases := map[string]string{
		`\bword\b`:  "backspace",
		`web(?i)01`: "start of the pattern",
		`web\z`:     `"^" and "$"`,
		`\p{L}`:     "[...] class",
		`(a)\1`:     "backreferences",
		`a+?`:       "non-greedy",
		`a{b}`:      `\{`,
	}
	for pat, want := range cases {
		_, problem := checkRegexSubset(pat)
		if !strings.Contains(problem, want) {
			t.Errorf("checkRegexSubset(%q) said %q, want it to mention %q", pat, problem, want)
		}
	}
}

// TestRegexRepetitionIsAProduct is T6: a nested counted repetition multiplies.
// `(a{100}){100}` is ten thousand repetitions however the braces are written,
// and counting the largest single bound saw only a hundred.
func TestRegexRepetitionIsAProduct(t *testing.T) {
	cases := map[string]int{
		`a`:                1,
		`a{5}`:             5,
		`a{2,7}`:           7,
		`a{2,}`:            2,
		`(a{100}){100}`:    10000,
		`(a{10}){10}`:      100,
		`((a{10}){10}){9}`: 900,
		`(a{10})(b{20})`:   20,
		`(a{10}|b{30})`:    30,
		`(a{255}){2}`:      510,
		// An escaped brace is a literal, not a repetition.
		`a\{100\}`: 1,
		// A brace inside a character class is a literal too.
		`[{}]`: 1,
	}
	for pat, want := range cases {
		got, problem := checkRegexSubset(pat)
		if problem != "" {
			t.Errorf("checkRegexSubset(%q): %s", pat, problem)
			continue
		}
		if got != want {
			t.Errorf("checkRegexSubset(%q) counted %d repetitions, want %d", pat, got, want)
		}
	}
}

// TestRegexRepetitionCountTooLarge covers the branch that used to report
// "malformed repetition count": a bound too large for an int. It is reachable —
// it just had no test — and the complaint must be about the SIZE, not the
// syntax, or the user is sent to fix a brace that is not the problem.
func TestRegexRepetitionCountTooLarge(t *testing.T) {
	for _, pat := range []string{`a{99999999999999999999}`, `a{100000}`, `a{256}`} {
		_, problem := checkRegexSubset(pat)
		if problem == "" {
			t.Errorf("checkRegexSubset(%q) accepted a count past %d", pat, MaxRepetitionBound)
			continue
		}
		if !strings.Contains(problem, "repetition count") {
			t.Errorf("checkRegexSubset(%q) said %q, want it to name the count", pat, problem)
		}
		if strings.Contains(problem, "literal brace") {
			t.Errorf("checkRegexSubset(%q) blamed the braces: %q", pat, problem)
		}
	}
}

// TestRegexSingleBoundCapIsPostgresLimit pins the bound to the database's, in
// both polarities. It is 255 because Postgres says so (DUPMAX), not because
// anyone here picked a round number.
func TestRegexSingleBoundCapIsPostgresLimit(t *testing.T) {
	if MaxRepetitionBound != 255 {
		t.Fatalf("MaxRepetitionBound = %d; Postgres DUPMAX is 255", MaxRepetitionBound)
	}
	for _, pat := range []string{`a{255}`, `a{1,255}`, `a{255,}`} {
		if _, problem := checkRegexSubset(pat); problem != "" {
			t.Errorf("checkRegexSubset(%q) refused a count Postgres accepts: %s", pat, problem)
		}
	}
	for _, pat := range []string{`a{256}`, `a{1,256}`, `a{256,}`} {
		if _, problem := checkRegexSubset(pat); problem == "" {
			t.Errorf("checkRegexSubset(%q) accepted a count Postgres refuses", pat)
		}
	}
}
