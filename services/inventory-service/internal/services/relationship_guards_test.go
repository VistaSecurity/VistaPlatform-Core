package services

// Two guards over things that are load-bearing, cheap to break, and invisible
// to every other test in the suite. Neither needs a database, so both run in the
// ordinary unit suite rather than waiting for a nightly.
//
//  1. The `asset_history.action` CHECK accepts every action Go can write, in
//     BOTH schema copies.
//  2. The relationship recursive CTEs deduplicate and bound their depth.
//
// Both were found by mutation: an unwidened constraint, and swapping `UNION`
// for `UNION ALL`, each left the whole suite green.

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func relGuardsRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../../.."))
}

func relGuardsRead(t *testing.T, root, rel string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(body)
}

// TestSchemaAssetHistoryActionsCoverTheGoVocabulary is the STATIC half of the
// `asset_history.action` guard: schema file against Go source, both schema
// copies, no database.
//
// replaced the old two-block shape (a `NOT EXISTS`-guarded ADD plus a
// separate widening) with ONE coverage-gated DO block holding ONE `actions`
// array, which removes the drift hazard this guard was originally written for —
// there is no longer a second copy to fall out of step with the first. What
// remains, and what this pins, is the OTHER half of the same trap: a value added
// to the Go vocabulary and not to that array. Because the history writer LOGS a
// rejected insert rather than returning it, such a row is simply never written
// and nobody finds out until they read a timeline months later.
//
// `TestIntegration_SBOM_HistoryActionCheckCoversEveryGoAction` checks the
// DEPLOYED constraint against the same Go vocabulary and is the better check
// where it runs; it needs a database, so it is nightly-and-local only. This one
// is free and runs in the ordinary unit suite, and it checks BOTH schema copies
// rather than whichever one the harness happened to apply.
//
// The vocabulary is read out of shared/identity rather than restated, so the
// guard cannot drift from the thing it guards.
//
// Mutation check: add a HistoryAction without adding it to either schema copy's
// `actions` array, or delete a value from one copy, and this fails.
func TestSchemaAssetHistoryActionsCoverTheGoVocabulary(t *testing.T) {
	root := relGuardsRepoRoot(t)
	actions := goHistoryActions(t, root)

	for _, rel := range []string{
		"scripts/database/schema.sql",
		"charts/vistaplatform/files/schema/schema.sql",
	} {
		t.Run(rel, func(t *testing.T) {
			sql := relGuardsRead(t, root, rel)

			// ONE block, one list. Two would be the drift hazard removed.
			if n := strings.Count(sql, "actions text[] := ARRAY["); n != 1 {
				t.Fatalf("%s declares the action vocabulary %d times, want exactly 1 — "+
					"a second copy drifts, and it drifts in the direction that fails silently", rel, n)
			}
			idx := strings.Index(sql, "actions text[] := ARRAY[")
			block := sql[idx:min(len(sql), idx+900)]

			// The convergence must be gated on COVERAGE, not on a value name: a
			// gate naming the newest value is the second copy under another name.
			if !strings.Contains(block, "asset_history_action_check") &&
				!strings.Contains(sql[idx:min(len(sql), idx+2000)], "asset_history_action_check") {
				t.Errorf("%s: the actions array is not the one feeding asset_history_action_check", rel)
			}
			if strings.Contains(sql[idx:min(len(sql), idx+2000)], "NOT LIKE '%") {
				t.Errorf("%s: the convergence is gated on a value NAME rather than on coverage", rel)
			}

			for _, action := range actions {
				if !strings.Contains(block, "'"+action+"'") {
					t.Errorf("%s: shared/identity writes action %q but the CHECK's actions array does "+
						"not list it — every write of it is rejected, and the writer LOGS that rather "+
						"than returning it, so the row is simply absent", rel, action)
				}
			}
		})
	}
}

var goHistoryAction = regexp.MustCompile(`Action\w+\s+HistoryAction = "([a-z_]+)"`)

// goHistoryActions reads the action vocabulary out of shared/identity rather
// than restating it, so the guard cannot drift from the thing it guards.
func goHistoryActions(t *testing.T, root string) []string {
	t.Helper()
	src := relGuardsRead(t, root, "shared/identity/repository.go")
	matches := goHistoryAction.FindAllStringSubmatch(src, -1)
	if len(matches) < 10 {
		t.Fatalf("found only %d HistoryAction constants in shared/identity/repository.go; "+
			"the regexp has stopped matching and this guard is inert", len(matches))
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m[1])
	}
	return out
}

// TestRelationshipWalksDeduplicateAndBoundDepth pins the two properties that
// keep the recursive CTEs from running forever.
//
// The cycle integration test cannot see either of them. It asserts the RESULT —
// two nodes for a three-ring — and the result is deduplicated a second time by
// the `reached` CTE's `GROUP BY asset_id`, so swapping the recursion's `UNION`
// for `UNION ALL` leaves it passing while the working table goes exponential on
// any graph with more than one route between two nodes. Measured: the mutation
// survives `TestIntegration_Impact_CycleSafe` unchanged.
//
// Termination is the depth bound, not the deduplication: `(asset_id, depth)`
// pairs are distinct at every level, so an unbounded walk over a cycle never
// repeats a row and never stops. Both are therefore load-bearing, and neither
// is observable from the outside until it is too late.
//
// Mutation check: change either `UNION` to `UNION ALL`, or drop a
// `WHERE w.depth < $3`, and this fails.
func TestRelationshipWalksDeduplicateAndBoundDepth(t *testing.T) {
	src := relGuardsRead(t, relGuardsRepoRoot(t), "services/inventory-service/internal/services/relationship_service.go")

	// Both walks, named by their exact signature. The impact walk carries a
	// third column (`crossed`) for the terminal-edge rule; the neighbourhood
	// walk does not, and a guard that matched either loosely would stop
	// noticing if one turned into the other.
	for _, signature := range []string{
		"WITH RECURSIVE walk(asset_id, depth) AS (",
		"WITH RECURSIVE walk(asset_id, depth, crossed) AS (",
	} {
		if n := strings.Count(src, signature); n != 1 {
			t.Fatalf("found %d walks spelled %q, want exactly 1; "+
				"a new or renamed walk needs adding to this guard", n, signature)
		}
	}
	if strings.Contains(src, "UNION ALL") {
		t.Errorf("a relationship walk uses UNION ALL. The recursion must deduplicate on " +
			"(asset_id, depth): with ALL, every route through a node produces its own row and a " +
			"graph with several routes between two nodes goes exponential. The integration test " +
			"cannot catch this — `reached` groups by asset_id, so the RESULT is identical.")
	}
	if n := strings.Count(src, "UNION\n"); n < 2 {
		t.Errorf("expected both recursive walks to be spelled with a bare UNION, found %d", n)
	}
	if n := strings.Count(src, "WHERE w.depth < $3"); n != 2 {
		t.Errorf("found %d depth bounds across the two walks, want 2. The bound is what TERMINATES "+
			"the recursion — deduplicating on (asset_id, depth) does not, because the depth column "+
			"makes every lap around a cycle a new row", n)
	}
}
