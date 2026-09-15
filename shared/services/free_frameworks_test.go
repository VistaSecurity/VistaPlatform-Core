package services

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The free/regulated framework partition is enforced in three places, and this
// list is only trustworthy while all three agree:
//
//   - scripts/audit-edition-boundary.mjs (FREE_FRAMEWORKS / REGULATED_FRAMEWORKS),
//     run by `make audit` — it fails if a free framework leaves seed.sql or a
//     regulated one enters it;
//   - scripts/database/seed.sql's final summary block, which counts them;
//   - FreeFrameworkCodes here, which decides what consumes cap.
//
// Adding a seventh free framework to the audit script without adding it here
// would leave it published, advertised, and unreachable to any tenant whose
// compliance_frameworks_max is 0 — which is exactly the bug (CMP-6) this list
// was introduced to fix. So the drift is a test failure, not a review item.
func TestFreeFrameworkCodesMatchTheEditionBoundaryAudit(t *testing.T) {
	root := testdb.RepoRoot(t)

	auditPath := filepath.Join(root, "scripts", "audit-edition-boundary.mjs")
	body, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read %s: %v", auditPath, err)
	}
	src := string(body)

	fromAudit := quotedCodesInArrayLiteral(t, src, "FREE_FRAMEWORKS")

	got := append([]string(nil), FreeFrameworkCodes...)
	sort.Strings(got)
	sort.Strings(fromAudit)

	if strings.Join(got, ",") != strings.Join(fromAudit, ",") {
		t.Errorf("FreeFrameworkCodes and the edition-boundary audit disagree:\n  Go:    %v\n  audit: %v", got, fromAudit)
	}

	// And the regulated catalog must stay OUT of the exemption: those are what
	// the cap is for.
	fromRegulated := quotedCodesInArrayLiteral(t, src, "REGULATED_FRAMEWORKS")
	for _, code := range fromRegulated {
		for _, free := range FreeFrameworkCodes {
			if free == code {
				t.Errorf("regulated framework %q is exempted from the compliance-framework cap", code)
			}
		}
	}
}

// quotedCodesInArrayLiteral extracts the single-quoted string elements of a
// `const <varName> = [ ... ]` array literal declared in a JS source file.
//
// It is comment- and string-aware rather than a bare `\[(.*?)\]` /
// `'([^']+)'` regex pair, because that pairing broke the first time a comment
// inside the array contained an apostrophe ("the inventory's own two",
// workstream 3.6): the apostrophe reads as a string delimiter to a
// quote-matching regex, pairs with the next real quote, and manufactures a
// bogus multi-line "code" out of the prose in between — silently producing a
// `fromAudit` list that can never equal FreeFrameworkCodes, no matter what
// FreeFrameworkCodes contains. Scanning character-by-character with real
// string/comment state means an apostrophe in prose, or a stray `[`/`]`
// inside a comment, can never be mistaken for array syntax.
func quotedCodesInArrayLiteral(t *testing.T, src, varName string) []string {
	t.Helper()

	loc := regexp.MustCompile(regexp.QuoteMeta(varName) + `\s*=\s*\[`).FindStringIndex(src)
	if loc == nil {
		t.Fatalf("could not find %q array literal in scripts/audit-edition-boundary.mjs — if it was renamed, update this test rather than deleting it", varName)
	}

	runes := []rune(src[loc[1]:])
	var body strings.Builder
	depth := 1
	inString := false
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if inString {
			body.WriteRune(c)
			if c == '\\' && i+1 < len(runes) {
				i++
				body.WriteRune(runes[i])
				continue
			}
			if c == '\'' {
				inString = false
			}
			continue
		}
		switch {
		case c == '\'':
			inString = true
			body.WriteRune(c)
		case c == '/' && i+1 < len(runes) && runes[i+1] == '/':
			for i < len(runes) && runes[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(runes) && runes[i+1] == '*':
			i += 2
			for i+1 < len(runes) && (runes[i] != '*' || runes[i+1] != '/') {
				i++
			}
			i++
		case c == '[':
			depth++
			body.WriteRune(c)
		case c == ']':
			depth--
			if depth == 0 {
				var codes []string
				for _, m := range regexp.MustCompile(`'([^']*)'`).FindAllStringSubmatch(body.String(), -1) {
					codes = append(codes, m[1])
				}
				return codes
			}
			body.WriteRune(c)
		default:
			body.WriteRune(c)
		}
	}
	t.Fatalf("unterminated %q array literal in scripts/audit-edition-boundary.mjs", varName)
	return nil
}
