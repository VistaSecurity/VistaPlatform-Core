package query_test

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// No query in this package had ever been run against a database.
//
// Every other test here asserts on generated TEXT, which cannot tell a clause
// that is merely well-formed from one Postgres will accept: a correlated
// subquery referring to an alias that is out of scope, a column the catalogue
// renamed but the shape did not, a cast that does not exist for a type. The
// traversal CTE is the shape that most needs it — `EXISTS (WITH RECURSIVE …)`
// correlated to the outer row — and no amount of string comparison can check
// it.
//
// So: EXPLAIN every fixture's clause, with its real bind parameters, against a
// live Postgres. EXPLAIN parses, resolves every name and plans the statement
// without running it, which is exactly the check wanted.
//
// Skips without TEST_DATABASE_URL, per the shared/testdb rule, so `go test
// ./...` and the PR gate stay green.

// requiredTables are the DATA_MODEL tables the translator's shapes name. They
// arrive with the asset-inventory schema (workstream 0.2, PR).
var requiredTables = []string{
	"assets", "asset_endpoints", "asset_identifiers", "asset_relationships",
	"asset_facts", "software_products", "software_installs", "findings",
}

// pendingColumns are columns a shape names that the shipped schema does not
// have yet, with the workstream that owes them. A fixture failing on one of
// these is skipped with a note; a fixture failing on anything else is a bug in
// this package.
//
// The list is asserted to be USED: when the column lands, the entry becomes
// stale and this test says so, rather than quietly carrying an exemption
// forever.
// EMPTY, and that is the point: every column the shapes name now exists.
//
// It carried `crypto_implementations.endpoint_id` until phase 1 added it, and
// the entry then went stale — which is exactly what the assertion at the bottom
// of TestIntegration_QuerySQLExecutes is for. An exemption list that nobody
// prunes turns into a list of things nobody checks, so the test fails on an
// entry no fixture needed rather than carrying it forever.
var pendingColumns = map[string]string{}

func TestIntegration_QuerySQLExecutes(t *testing.T) {
	db := testdb.Connect(t)
	requireInventorySchema(t, db)
	// Held for the whole test: `go test ./...` runs package binaries in PARALLEL
	// against one Postgres, and a neighbour applying scripts/database/schema.sql
	// takes ACCESS EXCLUSIVE across the tables these statements name. Postgres
	// breaks the resulting cycle by killing a session, and the loser is reported
	// as "Postgres refused the generated clause: pq: deadlock detected" — a
	// translator bug that is not one. Observed on this test with the shared/query
	// sweep leg running beside shared/testdb and shared/findings/producer.
	//
	// Shared mode, so this does not serialize against other tests; only against
	// an applier. AFTER Connect, and this package never applies the schema
	// itself (requireInventorySchema only probes), so there is nothing to wait on.
	testdb.HoldSchemaShareLock(t, db)

	cases := loadCases(t)
	tables := targetTables(t)
	ran, skipped := 0, map[string]int{}

	for _, c := range cases {
		if c.SQL == nil {
			continue
		}
		target := c.Target
		if target == "" {
			target = "asset"
		}
		from, ok := tables[target]
		if !ok {
			t.Errorf("%s: no table for target %q", c.Name, target)
			continue
		}
		t.Run(c.Name, func(t *testing.T) {
			stmt := "EXPLAIN SELECT 1 FROM " + from[0] + " " + from[1] + " WHERE " + c.SQL.Where
			args := decodeArgs(t, c)
			rows, err := db.Query(stmt, args...)
			if err == nil {
				_ = rows.Close()
				ran++
				return
			}
			if reason, pending := pendingReason(err); pending {
				skipped[reason]++
				t.Skipf("needs %s: %v", pendingColumns[reason], err)
			}
			t.Fatalf("Postgres refused the generated clause:\n  %s\n  args: %v\n  %v", stmt, args, err)
		})
	}

	if ran == 0 {
		t.Fatal("no fixture reached the database; the test proved nothing")
	}
	t.Logf("%d clauses planned against Postgres", ran)

	// The exemption list must be earning its place.
	for col := range pendingColumns {
		if skipped[col] == 0 {
			t.Errorf("pendingColumns names %q, but no fixture needed it — the column has landed, "+
				"so remove the entry", col)
		}
	}
}

// TestIntegration_QuerySemanticsOverRealRows covers the three answers that only
// a database can give, and that every text assertion in this package is blind
// to. Each is a bug this review found, restated as behaviour.
func TestIntegration_QuerySemanticsOverRealRows(t *testing.T) {
	db := testdb.Connect(t)
	requireInventorySchema(t, db)
	testdb.HoldSchemaShareLock(t, db) // see TestIntegration_QuerySQLExecutes
	tenant := testdb.NewTenant(t, db)

	// One asset nobody has scored (risk_assessed_by empty, risk_score 0 by
	// DEFAULT — which is why an unguarded band predicate matched it), and one
	// that has been assessed and scored zero.
	unscored := insertAsset(t, db, tenant, "unscored", 0, nil)
	assessed := insertAsset(t, db, tenant, "assessed-clean", 0, []string{"crypto"})
	scoredHigh := insertAsset(t, db, tenant, "scored-high", 80, []string{"crypto"})

	t.Run("S1 a band term and its negation both exclude an unassessed asset", func(t *testing.T) {
		below := matchIDs(t, db, tenant, "risk < high")
		notBelow := matchIDs(t, db, tenant, "not (risk < high)")

		if below[unscored] {
			t.Error("`risk < high` matched an asset nobody scored: risk_score defaults to 0 (§5.2)")
		}
		if notBelow[unscored] {
			t.Error("`not (risk < high)` matched it too; UNKNOWN must not pass either way (§5.2)")
		}
		if !below[assessed] {
			t.Error("`risk < high` should match an asset that WAS assessed and scored zero")
		}
		if !notBelow[scoredHigh] {
			t.Error("`not (risk < high)` should match an asset scored 80")
		}
	})

	t.Run("S1 informational and not_assessed are different sets", func(t *testing.T) {
		informational := matchIDs(t, db, tenant, "risk:informational")
		notAssessed := matchIDs(t, db, tenant, "risk:not_assessed")

		if !informational[assessed] || informational[unscored] {
			t.Error("`risk:informational` is `assessed and scored zero` (§5.2)")
		}
		if !notAssessed[unscored] || notAssessed[assessed] {
			t.Error("`risk:not_assessed` is `nobody scored it` (§5.2)")
		}
	})

	t.Run("S2 a fact resolves to the highest-precedence producer", func(t *testing.T) {
		// Two producers disagree about the same key on the same asset. The
		// declared value was written later, so "most recent wins" would pick
		// it; the measured one must win anyway (ADR-0005 D2).
		insertFact(t, db, tenant, scoredHigh, "os.name", `"linux"`, "measured", "sensor:1")
		insertFact(t, db, tenant, scoredHigh, "os.name", `"windows"`, "declared", "cmdb:1")

		if ids := matchIDs(t, db, tenant, "fact.os.name:linux"); !ids[scoredHigh] {
			t.Error("the measured value should win over the declared one")
		}
		if ids := matchIDs(t, db, tenant, "fact.os.name:windows"); ids[scoredHigh] {
			t.Error("the overridden value still matched; a fact term compares the RECONCILED value (§13 A4)")
		}
	})

	t.Run("S2 a fact term and its negation both exclude an asset with no such fact", func(t *testing.T) {
		term := matchIDs(t, db, tenant, "fact.os.name:linux")
		negated := matchIDs(t, db, tenant, "not fact.os.name:linux")
		if term[unscored] {
			t.Error("`fact.os.name:linux` matched an asset with no such fact")
		}
		if negated[unscored] {
			t.Error("`not fact.os.name:linux` matched it; the old NOT EXISTS was TRUE there (§5.2)")
		}
	})

	t.Run("S4 an unparseable value is present, not absent", func(t *testing.T) {
		// attr.cpu_count is NUMBER in the catalogue, and this is not one.
		// An attribute can hold whatever an importer or a collector put there;
		// the catalogue's type is what the QUERY means by it, not a constraint
		// on the jsonb.
		setAttributes(t, db, tenant, unscored, `{"cpu_count": "many"}`)

		if ids := matchIDs(t, db, tenant, "exists(attr.cpu_count)"); !ids[unscored] {
			t.Error("a present-but-unparseable value must read as PRESENT (S4)")
		}
		if ids := matchIDs(t, db, tenant, "not exists(attr.cpu_count)"); ids[unscored] {
			t.Error("`not exists` matched an asset that has the attribute")
		}
		// And the comparison over it is still UNKNOWN, not an error and not a
		// match — which is what the guarded cast is for.
		if ids := matchIDs(t, db, tenant, "attr.cpu_count < 3"); ids[unscored] {
			t.Error("an unparseable value must not compare as less than 3")
		}
		if ids := matchIDs(t, db, tenant, "not (attr.cpu_count < 3)"); ids[unscored] {
			t.Error("nor as not-less-than-3: the comparison is UNKNOWN (§5.2)")
		}
	})

	t.Run("S3 `!=` on an identifier excludes the asset that has it", func(t *testing.T) {
		insertIdentifier(t, db, tenant, scoredHigh, "mac_address", "aa:bb:cc:dd:ee:ff")
		insertIdentifier(t, db, tenant, scoredHigh, "serial_number", "J7K2QX1")

		ids := matchIDs(t, db, tenant, "id.mac != aa:bb:cc:dd:ee:ff")
		if ids[scoredHigh] {
			t.Error("the asset holding that MAC matched `id.mac != <it>` — the old shape asked " +
				"whether SOME identifier differed, which two identifiers always satisfy (S3)")
		}
		if ids := matchIDs(t, db, tenant, "id.mac:aa:bb:cc:dd:ee:ff"); !ids[scoredHigh] {
			t.Error("the positive term should match it")
		}
	})
}

// ---------------------------------------------------------------- helpers --

// requireInventorySchema skips when the asset-inventory tables are not in the
// database, and FAILS when the repository's schema.sql has them and the
// database does not — a stale database rather than an unmerged workstream.
func requireInventorySchema(t *testing.T, db *sql.DB) {
	t.Helper()
	var missing []string
	for _, table := range requiredTables {
		var reg sql.NullString
		if err := db.QueryRow(`SELECT to_regclass($1)::text`, "public."+table).Scan(&reg); err != nil {
			t.Fatalf("probe %s: %v", table, err)
		}
		if !reg.Valid {
			missing = append(missing, table)
		}
	}
	if len(missing) == 0 {
		return
	}
	schema, err := os.ReadFile(filepath.Join(testdb.RepoRoot(t), "scripts", "database", "schema.sql"))
	if err != nil {
		t.Fatalf("read schema.sql: %v", err)
	}
	for _, table := range missing {
		if strings.Contains(string(schema), "CREATE TABLE IF NOT EXISTS public."+table+" (") {
			t.Fatalf("schema.sql creates %q but the database does not have it — "+
				"the test database is stale; re-apply the schema", table)
		}
	}
	t.Skipf("the asset-inventory tables are not in scripts/database/schema.sql yet "+
		"(missing: %s) — this test runs once workstream 0.2 (PR #1618) lands",
		strings.Join(missing, ", "))
}

// targetTables maps a target name to its table and the alias the generated
// clause expects (Translate's alias contract).
func targetTables(t *testing.T) map[string][2]string {
	t.Helper()
	out := map[string][2]string{}
	for _, tgt := range testcatalogTargets() {
		if tgt.Table == "" {
			continue
		}
		out[tgt.Name] = [2]string{tgt.Table, tgt.Alias}
	}
	if len(out) == 0 {
		t.Fatal("the catalogue published no table-backed target")
	}
	return out
}

// decodeArgs turns a fixture's recorded args back into driver values.
func decodeArgs(t *testing.T, c Case) []any {
	t.Helper()
	if len(c.SQL.Args) == 0 {
		return nil
	}
	var raw []any
	if err := jsonUnmarshal(c.SQL.Args, &raw); err != nil {
		t.Fatalf("%s: decode args: %v", c.Name, err)
	}
	// Every JSON number arrives as float64. Postgres infers the parameter type
	// from context, and a float64 is accepted wherever an integer is for the
	// comparisons this package emits.
	return raw
}

// pendingReason reports whether a Postgres error is one of the known missing
// columns, and which.
func pendingReason(err error) (string, bool) {
	pgErr, ok := err.(*pq.Error)
	if !ok {
		return "", false
	}
	// 42703 undefined_column, 42P01 undefined_table.
	if pgErr.Code != "42703" && pgErr.Code != "42P01" {
		return "", false
	}
	for col := range pendingColumns {
		_, name, _ := strings.Cut(col, ".")
		if strings.Contains(pgErr.Message, name) {
			return col, true
		}
	}
	return "", false
}
