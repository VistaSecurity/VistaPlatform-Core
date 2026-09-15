package ai

// The provider boundary's COMPOSITION, as a structural rule over the
// repository.
//
// # What the two decorators guarantee, and only in one order
//
// [Boundary] is `WithRedaction(WithAudit(p, sink))` — redaction outermost. The
// order is not a style preference:
//
//   - `WithAudit(WithRedaction(p), sink)` hashes the request IT was handed,
//     which is the UNREDACTED one, so the recorded digest is of text that was
//     never sent and two prompts differing only in a rotated password hash
//     differently. That one at least fails loudly now: [WithAudit] refuses a
//     request that has not been through [Redact] ([ErrNotSanitized]).
//   - `WithRedaction(p)` ALONE is the one that does not fail. The prompt is
//     scrubbed, the provider accepts it, the call succeeds — and ADR-0008 D4.7's
//     audit record is simply never written. No error, no log line, nothing in
//     `activity_logs`, and the only way to notice is to go looking for a row
//     that was never there. It is this repository's oldest shape: the check that
//     did not run, rendered as the check that passed.
//   - `WithAudit(p, sink)` alone refuses everything, which is at least loud.
//
// Five seams wire this today — the narrator (cbom-service/ee/diff), the author
// (compliance-engine/ee/author), the enricher (admin-service/ee/enrich), and
// the query and remediator seams (shared/ai/edition) — and each does it in its
// own package, from its own constructor, with no compiler relationship between
// them. Nothing made them agree; they agree because five people read the same
// doc comment. A sixth seam is one `WithRedaction(provider)` away from an
// unaudited generative capability.
//
// # The rule
//
// Outside this package, [Boundary] is the only supported way to compose the two.
// A call to `ai.WithRedaction(` or `ai.WithAudit(` in a non-test file anywhere
// else is the failure above, whichever order it is in.
//
// Structural rather than behavioural, for the reason the sibling guard in
// shared/ai/seams gives: a behavioural test only gets written once somebody has
// thought about the seam, and the composition is exactly what somebody thinking
// about their seam assumes is already handled.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBoundaryIsTheOnlySupportedComposition(t *testing.T) {
	root := aiRepoRoot(t)

	// The package that DEFINES the decorators may of course call them; that is
	// what Boundary is. Everything below shared/ai is this package's own tree —
	// the providers, the edition wiring, the two ee seams — and the edition
	// wiring is where Boundary itself is applied for the seams it constructs.
	const owner = "shared/ai"

	type violation struct{ rel, line string }
	var violations []violation
	var boundaryCalls []string
	scanned := 0

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".git", "dist", "vendor", "build":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		body, readErr := os.ReadFile(filepath.Clean(path))
		if readErr != nil {
			return readErr
		}
		scanned++

		for _, line := range strings.Split(string(body), "\n") {
			code := strings.TrimSpace(line)
			// Comments explain the rule in several of these files — including
			// the ones being pointed AT — so a doc comment must not read as a
			// call site.
			if strings.HasPrefix(code, "//") {
				continue
			}
			if strings.Contains(code, "ai.Boundary(") {
				boundaryCalls = append(boundaryCalls, rel)
			}
			if strings.HasPrefix(rel, owner+"/") || rel == owner {
				continue
			}
			for _, banned := range []string{"ai.WithRedaction(", "ai.WithAudit("} {
				if strings.Contains(code, banned) {
					violations = append(violations, violation{rel: rel, line: code})
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}

	// The negative control. A walk that read nothing would make the assertion
	// below vacuously true, which is the failure mode this file is written
	// against.
	if scanned == 0 {
		t.Fatalf("walked %s and found no Go files at all; that is a broken path, not a clean repository", root)
	}
	if len(boundaryCalls) == 0 {
		t.Fatalf("not one ai.Boundary( call anywhere under %s — either the walk is wrong or every "+
			"generative seam has stopped wrapping its provider, and this guard cannot tell which", root)
	}
	t.Logf("scanned %d Go files; ai.Boundary is wired in %v", scanned, boundaryCalls)

	for _, v := range violations {
		t.Errorf("%s composes the provider boundary by hand:\n    %s\n"+
			"Use ai.Boundary(provider, sink). WithRedaction alone scrubs the prompt and writes NO "+
			"audit record — ADR-0008 D4.7 silently unmet, with nothing failing anywhere — and the "+
			"other order hashes text that was never sent.", v.rel, v.line)
	}
}

// aiRepoRoot walks up from this package until it finds the workspace file, and
// FAILS rather than skipping when it cannot: a pin that silently does not run is
// indistinguishable in CI output from one that passed.
func aiRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, statErr := os.Stat(filepath.Join(dir, "go.work")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("no go.work above %s: this guard cannot locate the repository and must fail rather "+
		"than pass over nothing", dir)
	return ""
}
