package testdb_test

// The integration runner must reach every package that has a DB-integration
// test.
//
// `scripts/run-integration-db-tests.sh` named its targets one by one, and every
// comment in that list is about something the list silently missed:
// shared/services, then's entitlement tests, then sensor-manager's RLS
// tests during the v0.5.0 regression. Gate 1 found nine more — one of which,
// shared/query, was RED the whole time while the documented local command
// reported success.
//
// The fix was a discovery sweep. This is the guard ON the sweep: it does the
// same discovery in Go and fails if a package would be reached by neither the
// named legs nor the sweep. Two ways that can happen, and both are real —
// somebody adds the package to ALREADY_RUN without adding a leg, or the sweep's
// grep stops matching.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("go.work not found above the working directory; not a full checkout")
	return ""
}

// alreadyRunEntry matches a line of the sweep's ALREADY_RUN array.
var alreadyRunEntry = regexp.MustCompile(`^\s*"([^":]+):([^"]+)"\s*$`)

// namedLeg matches a leg in run-integration-db-tests.sh:
//
//	( cd services/foo && go test … ./internal/bar/ )
var namedLeg = regexp.MustCompile(`\(\s*cd\s+(\S+)\s+&&\s+go test[^)]*?(\./\S*)\s*\)`)

func TestIntegrationRunnerCoversEveryPackage(t *testing.T) {
	root := repoRoot(t)

	// 1. Every package holding a TestIntegration_ — the same convention the
	//    sweep greps for, re-derived here rather than read from the script.
	packages := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".git", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if !strings.Contains(string(body), "func TestIntegration_") {
			return nil
		}
		dir := filepath.Dir(path)
		module := dir
		for module != root {
			if _, statErr := os.Stat(filepath.Join(module, "go.mod")); statErr == nil {
				break
			}
			module = filepath.Dir(module)
		}
		if module == root {
			return nil // not inside a module of the workspace
		}
		rel, _ := filepath.Rel(root, module)
		pkg, _ := filepath.Rel(module, dir)
		packages[rel+" ./"+filepath.ToSlash(pkg)] = true
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(packages) < 20 {
		t.Fatalf("found only %d packages with a TestIntegration_; the walk has stopped walking, "+
			"which is the one way this guard passes over nothing", len(packages))
	}

	// 2. What the NAMED legs run, and what the sweep claims is already covered.
	runner := mustRead(t, filepath.Join(root, "scripts", "run-integration-db-tests.sh"))
	sweep := mustRead(t, filepath.Join(root, "scripts", "integration-coverage.sh"))

	if !strings.Contains(runner, "integration-coverage.sh --run") {
		t.Fatal("run-integration-db-tests.sh no longer invokes the discovery sweep; every package " +
			"below is back to being reached only if somebody remembered to name it")
	}

	named := map[string]bool{}
	for _, m := range namedLeg.FindAllStringSubmatch(runner, -1) {
		named[strings.TrimSuffix(m[1], "/")+" "+strings.TrimSuffix(m[2], "/")] = true
	}

	claimed := map[string]bool{}
	inArray := false
	for _, line := range strings.Split(sweep, "\n") {
		if strings.HasPrefix(line, "ALREADY_RUN=(") {
			inArray = true
			continue
		}
		if inArray && strings.HasPrefix(line, ")") {
			break
		}
		if !inArray {
			continue
		}
		if m := alreadyRunEntry.FindStringSubmatch(line); m != nil {
			claimed[strings.TrimSuffix(m[1], "/")+" "+strings.TrimSuffix(m[2], "/")] = true
		}
	}
	if len(claimed) == 0 {
		t.Fatal("parsed no ALREADY_RUN entries out of integration-coverage.sh; the parse has stopped " +
			"parsing and this guard would pass over nothing")
	}

	// 3. A package the sweep believes is already covered must ACTUALLY be run
	//    by a named leg — otherwise it is run by nothing at all, which is the
	//    exact shape of every miss in the runner's own comment history.
	for pkg := range packages {
		if !claimed[pkg] {
			continue // the sweep will run it
		}
		if coveredByNamedLeg(named, pkg) {
			continue
		}
		t.Errorf("%s is listed in integration-coverage.sh's ALREADY_RUN, but no named leg in "+
			"run-integration-db-tests.sh runs it — so the sweep skips it and nothing runs it.\n"+
			"Either add the leg or remove the ALREADY_RUN entry (a duplicate run is slow; a "+
			"skipped one is how shared/query stayed red).", pkg)
	}
}

// coveredByNamedLeg reports whether a named leg runs this package, honouring
// Go's `...` wildcard: `./identity/...` covers `./identity/postgres`, and
// `./...` covers the whole module.
func coveredByNamedLeg(named map[string]bool, pkg string) bool {
	if named[pkg] {
		return true
	}
	fields := strings.Fields(pkg)
	module, path := fields[0], fields[1]
	for leg := range named {
		legFields := strings.Fields(leg)
		if len(legFields) != 2 || legFields[0] != module {
			continue
		}
		legPath := legFields[1]
		if !strings.HasSuffix(legPath, "...") {
			continue
		}
		prefix := strings.TrimSuffix(legPath, "...")
		if prefix == "./" || strings.HasPrefix(path+"/", prefix) {
			return true
		}
	}
	return false
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// liveLines drops the lines a shell or YAML reader would not execute — blank
// ones, comments, and `:`-prefixed no-ops — so a "still mentioned" line cannot
// satisfy a "still runs" assertion.
func liveLines(s string) string {
	var kept []string
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ": ") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// The local runner must prime its database the same way nightly does.
//
// `make test-integration-db` applied schema.sql only while the nightly
// `test-backend` job applied schema.sql AND seed.sql, so a test that reaches
// the database through testdb.Connect alone (never calling ApplySchemaAndSeed
// itself) saw an unseeded database locally and a seeded one in CI. A test that
// assumes an empty table, or whose insert collides with a seeded global row,
// then passes locally and fails nightly — a real divergence, not a flake
//
//
// The parity is currently INERT: the whole suite is green with the seed applied
// and green with it removed. Which is exactly why it needs a guard — there is
// no failing test to notice if the line is dropped again, and the divergence
// would only resurface the next time somebody writes a test that touches a
// seeded table.
func TestIntegrationRunnerAppliesSchemaAndSeedLikeNightly(t *testing.T) {
	root := repoRoot(t)
	// Commented-out and `:`-disabled lines are stripped before matching:
	// both files are named repeatedly in the runner's prose comments, and a
	// line that has been commented out is the most likely way the apply goes
	// away — either would satisfy a naive substring search.
	runner := liveLines(mustRead(t, filepath.Join(root, "scripts", "run-integration-db-tests.sh")))
	nightly := liveLines(mustRead(t, filepath.Join(root, ".github", "workflows", "nightly.yml")))

	for _, file := range []string{"scripts/database/schema.sql", "scripts/database/seed.sql"} {
		// An APPLYING line, not a mention: require a psql invocation that
		// consumes the file on the same line.
		applies := regexp.MustCompile(`psql[^\n]*` + regexp.QuoteMeta(file))
		if !applies.MatchString(runner) {
			t.Errorf("scripts/run-integration-db-tests.sh never applies %s with psql.\n"+
				"The nightly test-backend job applies both files before running any test binary, so "+
				"dropping one here reintroduces the passes-locally/fails-nightly divergence of #1672.", file)
		}
		if !applies.MatchString(nightly) {
			t.Errorf(".github/workflows/nightly.yml no longer applies %s with psql — this guard is "+
				"comparing the local runner against a job that has moved. Re-derive the parity.", file)
		}
	}
}
