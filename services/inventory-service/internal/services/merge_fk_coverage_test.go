package services

// The merge's foreign-key coverage, derived from the schema rather than
// asserted from a list somebody kept up to date.
//
// A merge that leaves rows pointing at the archived source is SILENT: every one
// of these FKs is ON DELETE SET NULL or points at a row that is archived rather
// than deleted, so nothing errors and nothing logs. The survivor simply shows
// no SSH keys, no external connections, no interrogation jobs and no
// disk-encryption state for hardware it just absorbed — and the merge looks
// finished.
//
// It is a UNIT test, not an integration one: it reads schema.sql, which is in
// the repository, so it runs on every `go test ./...` rather than only when a
// Postgres is up. A guard that runs nightly is a guard that catches the new
// table a week late.

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// assetChildTables are the asset's OWN children: each is moved by name in
// moveAssetChildren with a collision rule of its own, so they are covered but
// not through assetReferrers.
var assetChildTables = map[string]bool{
	"asset_endpoints":     true,
	"asset_identifiers":   true,
	"asset_management":    true,
	"asset_credentials":   true,
	"asset_relationships": true,
	"asset_facts":         true,
	"asset_history":       true,
	"software_installs":   true,
	// Producer coverage: unique per (tenant, asset, producer), so it needs the
	// same insert-on-conflict rule the endpoints and identifiers need and is
	// moved by name alongside them.
	"producer_assessments": true,
}

var fkPattern = regexp.MustCompile(
	`ADD CONSTRAINT\s+(\w+)\s+FOREIGN KEY\s*\(\s*tenant_id\s*,\s*(\w+)\s*\)\s*\n?\s*REFERENCES\s+public\.(assets|asset_endpoints)\b`)

// constraintTable pulls the table name out of an `ALTER TABLE [ONLY] public.x`
// line above a constraint. The pg_dump body wraps them in DO blocks, so the
// ALTER is a few lines up.
var alterPattern = regexp.MustCompile(`ALTER TABLE(?:\s+ONLY)?\s+public\.(\w+)`)

// writableRelation maps a base table onto the relation writers actually name.
// `crypto_implementations` is an updatable VIEW over the partitioned base
// table, and every writer in the service (the merge included) goes through the
// view — so a foreign key declared on the base table is covered by a mover that
// names the view.
func writableRelation(table string) string {
	if table == "crypto_implementations_partitioned" {
		return "crypto_implementations"
	}
	return table
}

func schemaSQL(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	// services -> internal -> inventory-service -> services -> repo root
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..",
		"scripts", "database", "schema.sql")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("schema.sql not readable from here (%v); not a full checkout", err)
	}
	return string(body)
}

// TestMergeMovesEveryForeignKeyToAssets: every column in the schema that names
// an asset or an endpoint is either one of the asset's own children (moved by
// name, with its own collision rule) or in the mover's referrer lists.
func TestMergeMovesEveryForeignKeyToAssets(t *testing.T) {
	body := schemaSQL(t)

	covered := map[string]bool{}
	for _, r := range assetReferrers {
		covered["assets|"+r.table+"."+r.column] = true
	}
	for _, r := range endpointReferrers {
		covered["asset_endpoints|"+r.table+"."+r.column] = true
	}

	matches := fkPattern.FindAllStringSubmatchIndex(body, -1)
	if len(matches) == 0 {
		t.Fatal("found no (tenant_id, *) foreign keys to assets/asset_endpoints in schema.sql; " +
			"the pattern has stopped matching, which is the one way this guard passes over nothing")
	}

	seen := 0
	for _, m := range matches {
		column := body[m[4]:m[5]]
		target := body[m[6]:m[7]]

		// The owning table: the nearest ALTER TABLE above this constraint.
		prefix := body[:m[0]]
		alters := alterPattern.FindAllStringSubmatch(prefix, -1)
		if len(alters) == 0 {
			t.Errorf("constraint on %s.%s has no ALTER TABLE above it", target, column)
			continue
		}
		table := writableRelation(alters[len(alters)-1][1])
		if table == "assets" && column == "tenant_id" {
			continue
		}
		seen++

		if assetChildTables[table] {
			continue // moved by name, with its own collision rule
		}
		key := target + "|" + table + "." + column
		if !covered[key] {
			t.Errorf("%s.%s references %s and the merge never moves it.\n"+
				"A merge that leaves it behind is SILENT — the FK is ON DELETE SET NULL or the source is "+
				"archived rather than deleted — and the survivor shows none of that evidence.\n"+
				"Add it to assetReferrers/endpointReferrers in merge_proposal_service.go.",
				table, column, target)
		}
		delete(covered, key)
	}
	if seen < 10 {
		t.Errorf("only %d asset/endpoint foreign keys found; the schema has more than that and the "+
			"scanner is missing them", seen)
	}
	for key := range covered {
		t.Errorf("the merge moves %s but the schema has no such foreign key; the list has drifted "+
			"the other way", strings.ReplaceAll(key, "|", " → "))
	}
}
