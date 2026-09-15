package seams

// The invoker key's OWNERSHIP, as a structural rule over the repository.
//
// # The bug this exists for, which has now shipped three times
//
// `ai.WithAudit` refuses a request naming no invoker (ADR-0008 D4.7,
// `ai.ErrUnattributed`). None of the seam interfaces takes an invoker argument,
// so it travels on the context — which means SOMETHING has to declare the
// context key, and where that something lives decides who can stamp it. A
// context key declared in an `ee/` package can only be written by code that can
// import that package, and a Core file may not.
//
//   - the ENRICHER (AI_SEAMS §12) exported `WithInvoker` from its Enterprise
//     package. The console-triggered runs it was written for could not call it,
//     so it had no caller at all and every audit record carried the nightly
//     rule's name instead of the person's. The symptom was only in the audit
//     trail, which is where nobody looks.
// - the REMEDIATOR was caught in review before it shipped one.
// - the QUERY seam shipped a private key in 4.4a. Its caller is a
//     Core handler by construction — the endpoint is mounted in every edition
//     so Core can answer 402 — so EVERY question would have been refused
//     `ErrUnattributed`: a healthy provider reported as unavailable, with the
//     cause in a log line.
//
// Three times is a pattern, and a pattern needs a check rather than a third
// reviewer noticing. Hence this file.
//
// # The rule
//
// An `ee/` package may declare its own unexported invoker context key ONLY if
// something inside the same `ee/` tree calls its `WithInvoker`. That is the one
// arrangement where the key's owner and the key's writer can both exist: the
// narrator and the author are each called by a handler that ships in their own
// `ee/` package, so a private key is reachable and correct there. As soon as the
// caller is a Core file — which is what "mounted in every edition" always means
// — the key has to live in Core, and the Enterprise spelling becomes a
// re-export of [WithInvoker].
//
// The rule is structural rather than behavioural on purpose: a behavioural test
// can only be written once somebody has thought about the seam, and every
// instance of this bug got past somebody who had.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// invokerKeyDecl is how an owned key reads. Matching the type declaration
// rather than the word "invoker" keeps a doc comment mentioning the concept
// from counting as ownership.
const invokerKeyDecl = "type invokerKey struct{}"

func TestEnterpriseInvokerKeysHaveAnEnterpriseCaller(t *testing.T) {
	root := repoRoot(t)

	// One entry per PACKAGE DIRECTORY under an ee/ tree. Per directory and not
	// per ee root, because `shared/ai/ee` holds both the query seam and the
	// remediator: grouping them would let the remediator's re-export count as
	// the query package's caller, which is the exact bug, one import away.
	type eePkg struct {
		dir      string
		eeRoot   string
		declares bool // declares its own unexported invoker key
		exports  bool // and its own WithInvoker
		callers  []string
	}
	pkgs := map[string]*eePkg{}
	// Every non-declaration mention of `WithInvoker(` anywhere in the repo,
	// with the file it was in — so a caller in a SIBLING ee package counts too.
	type mention struct{ rel, line string }
	mentions := []mention{}
	scanned, eeFiles := 0, 0

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
		src := string(body)
		scanned++

		for _, line := range strings.Split(src, "\n") {
			if !strings.Contains(line, "WithInvoker(") || strings.Contains(line, "func WithInvoker(") {
				continue
			}
			mentions = append(mentions, mention{rel: rel, line: strings.TrimSpace(line)})
		}

		eeRoot, inEE := enterpriseRootOf(rel)
		if !inEE {
			return nil
		}
		eeFiles++
		dir := path2dir(rel)
		pkg := pkgs[dir]
		if pkg == nil {
			pkg = &eePkg{dir: dir, eeRoot: eeRoot}
			pkgs[dir] = pkg
		}
		if strings.Contains(src, invokerKeyDecl) {
			pkg.declares = true
		}
		if strings.Contains(src, "func WithInvoker(") {
			pkg.exports = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}

	// The negative control. If the walk read nothing, every assertion below
	// would be vacuous — and a guard that passes over nothing is the failure
	// mode this whole file is written against.
	if scanned == 0 {
		t.Fatalf("walked %s and found no Go files at all; that is a broken path, not a tree with "+
			"nothing to check", root)
	}

	// …and the one tree where an empty result is the CORRECT answer.
	//
	// This file used to Fatal on `eeFiles == 0` too, with a comment asserting
	// that the Core export "does not ship this test". It does: the export
	// removes ee/ trees and every file carrying `//go:build ee`, and this file is
	// neither, so it lands in VistaSecurity/VistaPlatform-Core and fails there —
	// on a guard about a directory that cannot exist in that copy. Anyone
	// cloning a source-available product and running `go test ./...` met a red
	// suite; `prepare-public-tree.sh` only BUILDS the exported tree, so nothing
	// caught it.
	//
	// Skipping needs a POSITIVE identification, not the absence of one thing:
	// "no ee directories" also describes a private checkout somebody has broken.
	// The export removes the trees AND the ee-tagged wiring files together, so a
	// tree with neither is the export, and a tree with tagged files but no trees
	// is broken and still fails.
	if eeFiles == 0 {
		if tagged := eeTaggedFiles(t, root); tagged > 0 {
			t.Fatalf("walked %s: %d Go files, no ee/ directory, but %d file(s) still carry "+
				"//go:build ee. That is a checkout missing its Enterprise trees, not the Core "+
				"export — this guard cannot run and must not pass.", root, scanned, tagged)
		}
		t.Skipf("no ee/ tree and no ee-tagged file under %s (%d Go files): this is the Core "+
			"export, where the rule has nothing to check by construction.", root, scanned)
	}
	if len(mentions) == 0 {
		t.Fatalf("not one WithInvoker( call anywhere under %s — the match below cannot be doing "+
			"any work", root)
	}
	t.Logf("scanned %d Go files (%d under ee/), %d ee package(s), %d WithInvoker call site(s)",
		scanned, eeFiles, len(pkgs), len(mentions))

	for _, pkg := range pkgs {
		if !pkg.declares || !pkg.exports {
			continue
		}
		// A caller is either inside this very package (an unqualified call) or
		// anywhere else under the SAME ee root naming this package (`query.` /
		// `eequery.` — the qualified form contains the bare one).
		qualified := path2base(pkg.dir) + ".WithInvoker("
		for _, m := range mentions {
			switch {
			case path2dir(m.rel) == pkg.dir:
				pkg.callers = append(pkg.callers, m.rel)
			case strings.HasPrefix(m.rel, pkg.eeRoot+"/") && strings.Contains(m.line, qualified):
				pkg.callers = append(pkg.callers, m.rel)
			}
		}

		if len(pkg.callers) == 0 {
			t.Errorf("%s declares its own %q and NOTHING inside an ee/ tree calls its WithInvoker.\n"+
				"Its caller is therefore Core — which is what every endpoint mounted in all editions "+
				"has, since Core has to be able to answer 402 — and a Core file may not import an "+
				"ee/ package. Every call from it reaches ai.WithAudit unattributed and is refused "+
				"with ai.ErrUnattributed: a healthy provider reported as unavailable, with the cause "+
				"in a log line.\n"+
				"Fix it the way shared/ai/ee/query and shared/ai/ee/remediator did: delete the "+
				"private key and make this package's WithInvoker a re-export of seams.WithInvoker.",
				pkg.dir, invokerKeyDecl)
			continue
		}
		t.Logf("%s owns its invoker key and is called from %v — allowed: the caller ships inside "+
			"an Enterprise tree", pkg.dir, pkg.callers)
	}
}

// enterpriseRootOf returns the `…/ee` prefix of a repo-relative slash path, and
// whether the path is under one at all.
func enterpriseRootOf(rel string) (string, bool) {
	parts := strings.Split(rel, "/")
	for i, p := range parts {
		if p == "ee" {
			return strings.Join(parts[:i+1], "/"), true
		}
	}
	return "", false
}

func path2dir(rel string) string {
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		return rel[:i]
	}
	return "."
}

func path2base(dir string) string {
	if i := strings.LastIndex(dir, "/"); i >= 0 {
		return dir[i+1:]
	}
	return dir
}

// repoRoot walks up from this package until it finds the workspace file.
//
// It FAILS rather than skipping when it cannot: a pin that silently does not
// run is indistinguishable in CI output from one that passed.
func repoRoot(t *testing.T) string {
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

// eeTaggedFiles counts Go files carrying the `//go:build ee` prologue.
//
// It is the corroborating fact that tells the Core export apart from a broken
// checkout: the export removes the ee/ trees and these files in the same pass,
// so neither being present is the export, while one without the other is a tree
// somebody has damaged.
func eeTaggedFiles(t *testing.T, root string) int {
	t.Helper()
	count := 0
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
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		body, readErr := os.ReadFile(filepath.Clean(path))
		if readErr != nil {
			return readErr
		}
		// The prologue only counts at the top of the file, where it is a build
		// constraint; further down it is prose in a doc comment, and several of
		// these files explain the rule in exactly those words.
		head := string(body)
		if len(head) > 512 {
			head = head[:512]
		}
		for _, line := range strings.Split(head, "\n") {
			if strings.TrimSpace(line) == "//go:build ee" {
				count++
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s for ee-tagged files: %v", root, err)
	}
	return count
}
