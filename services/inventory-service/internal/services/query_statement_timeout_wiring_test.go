package services

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A read that splices a tenant-supplied predicate into its WHERE clause must
// open its transaction with the statement ceiling (security review X.5, X5-10).
//
// This is a scan of the source, and it is the right shape for the question.
// `SET LOCAL statement_timeout` is not observable from outside its own
// transaction, so the only ways to assert the wiring at runtime are timing (a
// flaky guard, which is the kind this review exists to remove) or changing a
// database-wide default (which the integration harness shares with every other
// package running at the same time). What CAN be checked exactly is that the
// functions which compile a caller's query open the BOUNDED helper.
//
// The behaviour of that helper — that the ceiling fires, carries the value
// asked for, and reverts with the transaction — is pinned against a real
// Postgres in query_statement_timeout_integration_test.go.
//
// To mutation-test: change any of the named functions back to
// database.WithTenantTx. This fails and names it.
func TestQueryReadsUseTheBoundedTenantTx(t *testing.T) {
	// Functions that compile a caller's `?query=` (directly or through
	// buildAssetWhere) and then run it. Each must reach WithTenantTxTimeout.
	want := map[string]string{
		"GetAssets":            "asset_queries.go",
		"GetRecentAssetsCount": "asset_queries.go",
		"GetStaleAssets":       "asset_lifecycle_service.go",
		"riskFacets":           "asset_facets_queries.go",
		"booleanFacet":         "asset_facets_queries.go",
		"facetRows":            "asset_facets_queries.go",
	}

	bodies := map[string]string{}
	for fn, file := range want {
		raw, err := os.ReadFile(filepath.Join(".", file))
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		body, ok := functionBody(string(raw), fn)
		if !ok {
			t.Fatalf("%s has no func %s — if it was renamed, this guard needs renaming with it, not deleting",
				file, fn)
		}
		bodies[fn] = body
	}

	for fn, body := range bodies {
		if !strings.Contains(body, "WithTenantTxTimeout(") {
			t.Errorf("%s runs a tenant-supplied query-language predicate but opens its transaction with the "+
				"UNBOUNDED helper — a predicate a tenant controls would run with no statement ceiling", fn)
		}
		// The bounded helper delegates to the plain one, so a body that calls
		// both is a body where one read is bounded and another is not.
		plain := regexp.MustCompile(`database\.WithTenantTx\(`)
		if plain.MatchString(body) {
			t.Errorf("%s also opens a plain database.WithTenantTx; every read in it that carries the "+
				"compiled predicate needs the ceiling", fn)
		}
	}
}

// functionBody returns the text of `func … name(` up to the next top-level
// `\n}` — enough to see which helper it opens, without pulling in go/ast for
// one scan.
func functionBody(src, name string) (string, bool) {
	re := regexp.MustCompile(`(?m)^func (?:\([^)]*\) )?` + regexp.QuoteMeta(name) + `\(`)
	loc := re.FindStringIndex(src)
	if loc == nil {
		return "", false
	}
	rest := src[loc[0]:]
	if end := strings.Index(rest, "\n}\n"); end > 0 {
		return rest[:end], true
	}
	return rest, true
}
