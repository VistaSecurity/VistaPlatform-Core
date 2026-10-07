package database

import (
	"regexp"
	"strings"
	"testing"
)

// likeMatch is an independent reference implementation of Postgres LIKE with
// backslash as the escape character, used to prove EscapeLike's output matches
// the input literally and nothing else.
func likeMatch(pattern, s string) bool {
	var re strings.Builder
	re.WriteString("^(?s)")
	pr := []rune(pattern)
	for i := 0; i < len(pr); i++ {
		switch pr[i] {
		case '\\':
			if i+1 < len(pr) {
				i++
				re.WriteString(regexp.QuoteMeta(string(pr[i])))
			}
		case '%':
			re.WriteString(".*")
		case '_':
			re.WriteString(".")
		default:
			re.WriteString(regexp.QuoteMeta(string(pr[i])))
		}
	}
	re.WriteString("$")
	return regexp.MustCompile(re.String()).MatchString(s)
}

func TestEscapeLike(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"plain", "plain"},
		{"100%", `100\%`},
		{"a_b", `a\_b`},
		{`a\b`, `a\\b`},
		{`%_\`, `\%\_\\`},
		{"ünï_çödé", `ünï\_çödé`},
	}
	for _, c := range cases {
		if got := EscapeLike(c.in); got != c.want {
			t.Errorf("EscapeLike(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The behaviour that matters: with the escaped pattern, `%` and `_` match only
// themselves, where the unescaped pattern matches far more.
func TestContainsPatternMatchesLiterally(t *testing.T) {
	rows := []string{
		"build_agent_01",
		"buildXagentX01",
		"100% coverage",
		"1000 coverage",
		`back\slash`,
		"backslash",
		"anything",
	}
	cases := []struct {
		search string
		want   []string
	}{
		{"_", []string{"build_agent_01"}},
		{"%", []string{"100% coverage"}},
		{"d_a", []string{"build_agent_01"}},
		{"0%", []string{"100% coverage"}},
		{`k\s`, []string{`back\slash`}},
		{"agent", []string{"build_agent_01", "buildXagentX01"}},
	}
	for _, c := range cases {
		var got []string
		for _, r := range rows {
			if likeMatch(ContainsPattern(c.search), r) {
				got = append(got, r)
			}
		}
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("search %q matched %v, want %v", c.search, got, c.want)
		}
	}

	// Sanity: the reference matcher does treat the unescaped forms as wildcards,
	// so the assertions above are not vacuous.
	if !likeMatch("%_%", "anything") || !likeMatch("%%%", "anything") {
		t.Fatal("reference matcher does not model % and _ as wildcards")
	}
}

func TestLikeEscapeClause(t *testing.T) {
	if LikeEscapeClause != ` ESCAPE '\'` {
		t.Fatalf("LikeEscapeClause = %q", LikeEscapeClause)
	}
}
