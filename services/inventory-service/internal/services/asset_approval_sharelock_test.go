package services

// A structural guard: every test taking its database from getTestDBAndTenant
// writes under the schema share lock.
//
// The two tests this exists for — TestIntegration_AssetIngestionPendingApproval
// and TestIntegration_ApproveAssets — failed intermittently under the parallel
// integration runner with `pq: deadlock detected`, and the Postgres server log
// says exactly why:
//
//	DETAIL: Process A waits for AccessShareLock on <partition>; blocked by B.
//	        Process B waits for AccessExclusiveLock on <partition>; blocked by A.
//	        Process B: -- Vista Platform - Consolidated Database Schema ...
//
// B is another package binary applying scripts/database/schema.sql. Nothing
// about the approval logic is involved; the test is simply the session Postgres
// picked to kill. getTestDBAndTenant applies the schema itself, so every test
// using it is guaranteed to run in a window where appliers are active.
//
// The exposure is not the approval tests'. It belongs to the FIXTURE, so it is
// shared by every file that uses it — network_space_test.go as well, whose six
// DB-backed tests showed the same deadlock class in the same baseline run. Both
// files are listed below, and a third that starts calling the fixture fails the
// coverage guard until it is added.
//
// The cure is the shared advisory lock around the writes — in either of its two
// shapes, testdb.WithSchemaShareLock (a block) or testdb.HoldSchemaShareLock
// (the whole test) — shared mode, so the tests
// still run concurrently with each other, and exclusive appliers cannot
// overlap them. The cure is also invisible: a test that loses the wrapper goes
// back to passing almost always, and starts failing again only on a busy
// machine, weeks later, blamed on something else. So it is pinned here rather
// than left to the next person to remember.
//
// Deliberately a SOURCE check. The alternative — asserting at runtime that the
// lock is held — would have to be written into each test, which is the thing
// being forgotten in the first place. This reads the file the way a reviewer
// would, and it costs no database.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// sharedFixtureTestFiles are the files under guard: every file in this package
// whose tests take their database from getTestDBAndTenant. Named rather than
// globbed, because the claim is about THAT fixture and a glob would silently
// start policing files with their own, correct, different arrangements.
//
// Both files must be listed, and the list is checked against the package: a
// third file that starts calling the fixture and is not added here would be
// unguarded, so TestIntegration_SharedFixtureGuard_CoversEveryFile fails until
// it is.
var sharedFixtureTestFiles = []string{
	"asset_approval_test.go",
	"network_space_test.go",
	// These two do not use getTestDBAndTenant; they apply the schema inline
	// (testdb.ApplySchemaAndSeed), which is the SAME exposure by a different
	// spelling — the deadlock comes from applying the schema, not from the
	// fixture that happens to wrap it. Listed here so the lock they now take
	// cannot be removed silently.
	"asset_identity_integration_test.go",
	"asset_query_integration_test.go",
}

// fixtureHelper is the fixture whose callers must hold the lock, and the one the
// COVERAGE guard below hunts for across the package.
const fixtureHelper = "getTestDBAndTenant"

// schemaApplyHelpers are the OTHER way a test in this package puts itself in the
// deadlock window: calling testdb.ApplySchemaAndSeed itself instead of going
// through getTestDBAndTenant. A function in a listed file that calls either
// spelling must take the lock.
//
// Only the LISTED files are held to this. Fifty-odd test files in this package
// call testdb.ApplySchemaAndSeed without the lock, and sweeping all of them is a
// separate piece of work with its own risk — asserting it here would make this
// guard fail on arrival and teach the next person to delete it. The coverage
// guard below therefore still keys on getTestDBAndTenant alone, and this list is
// the set of files somebody has actually fixed.
var schemaApplyHelpers = map[string]bool{
	"ApplySchemaAndSeed": true,
}

// lockHelpers are the two shapes of the SAME shared advisory lock. The callback
// form wraps a block; the hold form takes it for the whole test from t.Cleanup.
// Either satisfies the guard — what matters is that the lock is held while the
// test writes, not which spelling took it.
var lockHelpers = map[string]bool{
	"WithSchemaShareLock": true,
	"HoldSchemaShareLock": true,
}

func TestIntegration_ApprovalTests_HoldTheSchemaShareLock(t *testing.T) {
	for _, name := range sharedFixtureTestFiles {
		t.Run(name, func(t *testing.T) { checkFileHoldsTheLock(t, name) })
	}
}

// TestIntegration_SharedFixtureGuard_CoversEveryFile keeps the list above
// honest. A guard that names its inputs can be defeated by adding a file, and
// the whole point of this pair is that the next person does not have to
// remember.
func TestIntegration_SharedFixtureGuard_CoversEveryFile(t *testing.T) {
	listed := map[string]bool{}
	for _, f := range sharedFixtureTestFiles {
		listed[f] = true
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	var scanned int
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, "_test.go") || listed[name] {
			continue
		}
		scanned++
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if strings.Contains(string(src), fixtureHelper+"(t)") {
			t.Errorf("%s calls %s but is not in sharedFixtureTestFiles, so its tests are "+
				"unguarded — add it to the list (and give its tests the lock)", name, fixtureHelper)
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no other test file in this package — this guard is inert")
	}
}

func checkFileHoldsTheLock(t *testing.T, path string) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	// EVERY function, not only Test*: a file may put the schema apply and the
	// lock in its own fixture helper (newIdentityFixture does), and the claim is
	// that the two travel together wherever they live. A test that merely CALLS
	// such a fixture reaches neither branch and is skipped, which is correct —
	// the lock is already held by the time it runs.
	var checked int
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		// The definition of getTestDBAndTenant itself is exempt: it applies the
		// schema and deliberately leaves the lock to its CALLERS, each of which
		// is checked below by the ident branch. Holding it inside the fixture
		// would be a second, redundant acquisition of the same advisory lock.
		if fn.Name.Name == fixtureHelper {
			continue
		}

		var usesHelper, takesLock bool
		var entry string
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch f := call.Fun.(type) {
			case *ast.Ident:
				if f.Name == fixtureHelper {
					usesHelper = true
					entry = fixtureHelper
				}
			case *ast.SelectorExpr:
				pkg, ok := f.X.(*ast.Ident)
				if !ok || pkg.Name != "testdb" {
					return true
				}
				if lockHelpers[f.Sel.Name] {
					takesLock = true
				}
				if schemaApplyHelpers[f.Sel.Name] {
					usesHelper = true
					if entry == "" {
						entry = "testdb." + f.Sel.Name
					}
				}
			}
			return true
		})

		if !usesHelper {
			continue
		}
		checked++
		if !takesLock {
			t.Errorf("%s calls %s but never testdb.WithSchemaShareLock or "+
				"testdb.HoldSchemaShareLock — its writes can deadlock against another package "+
				"binary's schema apply, and it will report as a failure of the logic under test",
				fn.Name.Name, entry)
		}
	}

	// A guard that inspects nothing passes for free. If a file grows or shrinks
	// that is fine, but ZERO means the AST walk stopped matching and this test
	// has quietly become a no-op.
	if checked == 0 {
		t.Fatalf("found no function in %s calling %s or testdb.ApplySchemaAndSeed — "+
			"this guard is inert", path, fixtureHelper)
	}
}
