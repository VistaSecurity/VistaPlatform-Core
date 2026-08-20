package handlers

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The seeded Terms of Service and Privacy Policy ship as TEMPLATES. These tests
// pin the detector that stops one being published unedited.
//
// The case that matters is the first one: it reads the REAL seed file rather
// than a hand-written sample, because a detector tuned against a synthetic
// string can pass while missing the only document it exists to catch.

func TestFindPlaceholders_DetectsTheRealSeededTemplates(t *testing.T) {
	seed := readSeed(t)

	for _, marker := range []string{"$tos$", "$priv$"} {
		body := extractDollarQuoted(t, seed, marker)
		got := findPlaceholders(body)
		if len(got) == 0 {
			t.Fatalf("%s: seeded template reported CLEAN — the guard would let an "+
				"unedited template be published, which is the whole point of it", marker)
		}
		t.Logf("%s: %d placeholder(s), first: %v", marker, len(got), got[:min(3, len(got))])
	}
}

func TestFindPlaceholders(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "bracketed upper-case markers are placeholders",
			body: "These Terms govern the deployment operated by **[YOUR LEGAL ENTITY]**, at [YOUR SERVICE URL].",
			want: []string{"[YOUR LEGAL ENTITY]", "[YOUR SERVICE URL]"},
		},
		{
			name: "multi-word instructions with punctuation",
			body: "[LIST YOUR SUB-PROCESSORS, OR STATE THAT THERE ARE NONE.]",
			want: []string{"[LIST YOUR SUB-PROCESSORS, OR STATE THAT THERE ARE NONE.]"},
		},
		{
			name: "duplicates collapse, order of first appearance preserved",
			body: "[YOUR LEGAL ENTITY] ... [PERIOD] ... [YOUR LEGAL ENTITY]",
			want: []string{"[YOUR LEGAL ENTITY]", "[PERIOD]"},
		},
		{
			name: "a finished document is clean",
			body: "These Terms govern the deployment operated by **Acme Corporation**, at https://vista.acme.example.",
			want: []string{},
		},
		{
			name: "markdown link labels are not placeholders",
			body: "See [our security page](https://example.com/security) and [Settings](/settings).",
			want: []string{},
		},
		{
			name: "task-list checkboxes are not placeholders",
			body: "- [x] reviewed\n- [ ] signed",
			want: []string{},
		},
		{
			name: "a short acronym reference is not a placeholder",
			body: "as defined by the [EU] and [UK] regimes",
			want: []string{},
		},
		{
			name: "empty body",
			body: "",
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findPlaceholders(tt.body)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("index %d: got %q, want %q (full: %v)", i, got[i], tt.want[i], got)
				}
			}
		})
	}
}

func TestFindPlaceholders_CapsWhatItReports(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxReportedPlaceholders*3; i++ {
		b.WriteString("[PLACEHOLDER NUMBER ")
		b.WriteString(strings.Repeat("X", i+1))
		b.WriteString("]\n")
	}
	if got := len(findPlaceholders(b.String())); got != maxReportedPlaceholders {
		t.Fatalf("reported %d placeholders, want the cap of %d — the API must not "+
			"echo a second copy of the document back at the caller", got, maxReportedPlaceholders)
	}
}

// TestPlaceholderPattern_MutationCheck is the house rule made executable: a
// guard that cannot fail is worse than no guard. It asserts that a detector
// which had been loosened in the two most plausible ways would be caught by the
// table above — i.e. that those cases are load-bearing, not decoration.
func TestPlaceholderPattern_MutationCheck(t *testing.T) {
	linkBody := "See [our security page](https://example.com/security)."
	checkboxBody := "- [x] reviewed"

	// Mutation 1: drop the upper-case anchor. Markdown link labels start
	// matching, so the "not a placeholder" cases would fail.
	loose := regexp.MustCompile(`\[[A-Za-z0-9 ._/&'-]{2,}\]`)
	if !loose.MatchString(linkBody) {
		t.Fatal("expected the case-insensitive mutation to match a Markdown link label; " +
			"if it no longer does, the link case in the table is no longer proving anything")
	}

	// Mutation 2: drop the minimum length. `[x]` starts matching.
	short := regexp.MustCompile(`\[[A-Za-z0-9 ._/&'-]+\]`)
	if !short.MatchString(checkboxBody) {
		t.Fatal("expected the no-minimum-length mutation to match a checkbox; " +
			"the checkbox case in the table is no longer proving anything")
	}

	// And the real pattern rejects both.
	if findPlaceholders(linkBody) != nil && len(findPlaceholders(linkBody)) != 0 {
		t.Fatalf("real detector matched a Markdown link: %v", findPlaceholders(linkBody))
	}
	if len(findPlaceholders(checkboxBody)) != 0 {
		t.Fatalf("real detector matched a checkbox: %v", findPlaceholders(checkboxBody))
	}
}

// readSeed locates scripts/database/seed.sql from the service's test working
// directory. Kept explicit rather than embedded: the point is to read the file
// the deployment actually applies.
func readSeed(t *testing.T) string {
	t.Helper()
	const rel = "../../../../scripts/database/seed.sql"
	b, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("cannot read %s: %v", rel, err)
	}
	return string(b)
}

// extractDollarQuoted pulls the body out of a $tag$ ... $tag$ literal.
func extractDollarQuoted(t *testing.T, s, tag string) string {
	t.Helper()
	start := strings.Index(s, tag)
	if start < 0 {
		t.Fatalf("seed.sql no longer contains a %s literal — has the legal seed moved?", tag)
	}
	rest := s[start+len(tag):]
	end := strings.Index(rest, tag)
	if end < 0 {
		t.Fatalf("unterminated %s literal in seed.sql", tag)
	}
	return rest[:end]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
