package validate

import (
	"database/sql"
	"os"
	"strings"
	"testing"

	_ "github.com/lib/pq" // registers the "postgres" driver
)

// TestIntegration_RegexSubsetRunsInPostgres is the half of §13 A6 that cannot
// be asserted in Go: the patterns the validator admits are handed to Postgres
// `~`, which is ARE (Spencer) and not RE2. A Go-only test can prove the subset
// is valid RE2 — TestRegexSubsetAcceptsTheDialect does — and can say nothing
// about whether the database agrees.
//
// Every accepted construct must therefore execute against a live Postgres
// without raising "invalid regular expression". Without that, the accepted list
// is a claim about a database nobody asked.
//
// Skips when TEST_DATABASE_URL is unset, the same rule the shared/testdb
// harness uses, so `go test ./...` and the PR gate stay green.
func TestIntegration_RegexSubsetRunsInPostgres(t *testing.T) {
	db := connectOrSkip(t)

	for _, pat := range acceptedPatterns {
		// A pattern that is inside the subset must run. The result is not
		// asserted — what a pattern matches is RE2's business, and this test is
		// only about the database accepting the construct at all.
		var matched bool
		if err := db.QueryRow(`SELECT 'web01.example.com' ~ $1`, pat).Scan(&matched); err != nil {
			t.Errorf("Postgres refused %q, which the subset accepts: %v", pat, err)
		}
	}
}

// TestIntegration_RejectedRegexesReallyDiverge proves the rejections that
// matter are not paranoia. Each case below either raises an error in Postgres,
// or runs and gives a DIFFERENT answer from the one RE2 gives for the same
// subject.
//
// The second kind is the dangerous one and the reason the subset exists at all:
// `'word' ~ '\bword\b'` is FALSE in Postgres, where \b is a backspace, and TRUE
// in Go. No error, no warning, wrong rows.
//
// Not every rejection is a divergence. The subset also NARROWS — POSIX classes,
// `\n`, lazy quantifiers and `\A` are refused although both engines happen to
// accept them today — because a small dialect somebody can hold in their head
// is worth more than every construct two engines currently agree on. Those are
// pinned by the Go-only table; this test covers the ones that would have bitten.
func TestIntegration_RejectedRegexesReallyDiverge(t *testing.T) {
	db := connectOrSkip(t)

	const subject = "word"
	cases := []struct {
		pattern string
		// goAnswer is what Go's RE2 returns for subject.
		goAnswer bool
		// pgErrors says Postgres refuses the pattern outright.
		pgErrors bool
	}{
		{`\bword\b`, true, false}, // silent: Postgres reads \b as a backspace
		{`word\z`, true, true},
		{`wo(?i)RD`, true, true},
		{`(?i:WORD)`, true, true},
		{`(?P<w>word)`, true, true},
		{`(?<w>word)`, true, true},
		{`\p{L}+`, true, true},
	}
	for _, c := range cases {
		if _, problem := checkRegexSubset(c.pattern); problem == "" {
			t.Errorf("%q should be outside the subset", c.pattern)
			continue
		}
		var pgAnswer bool
		err := db.QueryRow(`SELECT $1::text ~ $2`, subject, c.pattern).Scan(&pgAnswer)
		if c.pgErrors {
			if err == nil {
				t.Errorf("%q was expected to fail in Postgres, but ran and answered %v",
					c.pattern, pgAnswer)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q was expected to RUN in Postgres (that is what makes it dangerous): %v",
				c.pattern, err)
			continue
		}
		if pgAnswer == c.goAnswer {
			t.Errorf("%q was expected to answer differently from RE2, but both said %v",
				c.pattern, pgAnswer)
		}
	}

	// The control: a pattern INSIDE the subset runs and agrees.
	var pgAnswer bool
	if err := db.QueryRow(`SELECT $1::text ~ $2`, subject, `(?i)WORD`).Scan(&pgAnswer); err != nil {
		t.Fatalf("(?i)WORD is in the subset but Postgres refused it: %v", err)
	}
	if !pgAnswer {
		t.Errorf("(?i)WORD should match %q in Postgres, as it does in RE2", subject)
	}
}

// connectOrSkip opens TEST_DATABASE_URL, or skips.
func connectOrSkip(t *testing.T) *sql.DB {
	t.Helper()
	url := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping the Postgres regex-dialect probe")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
