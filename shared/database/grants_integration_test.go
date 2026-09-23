package database_test

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestIntegration_Schema_SingleApplyGrantsEveryRelation is the semantic guard
// behind scripts/audit-schema-grant-order.mjs.
//
// `GRANT ... ON ALL TABLES IN SCHEMA public` is expanded ONCE, over the tables
// that exist at that instant — it is not a standing rule. While the blanket
// grant sat mid-file in schema.sql, nine tables created below it (alerts,
// alert_events, legal_documents, legal_acceptances, …) ended up with zero
// privileges for crypto_app. serviceRls defaults to ON, so services connect as
// that NOBYPASSRLS role, and the chart's schema-migration Job applies the file
// exactly ONCE on install — so a brand-new install answered "permission denied
// for table alerts" across Remediation → Alerts, the notification digest queue,
// the platform operator inbox, and the ToS/Privacy write on the signup path.
//
// Two things make this test's shape non-negotiable:
//
//  1. It applies the schema into a FRESH, THROWAWAY DATABASE it creates itself,
//     rather than reusing TEST_DATABASE_URL's. The shared integration database
//     has the schema applied by the harness and is further grant-patched by
//     other packages (auth-service's connectAsBypassRole issues a bare blanket
//     GRANT), any of which would retroactively hide the bug.
//
//  2. It checks after exactly ONE apply first. A second apply is what masked
//     this for so long: by then every table exists when the GRANT runs. It then
//     applies the file a second time (what every `helm upgrade` does) and checks
//     again, because the deliberate narrowings have the OPPOSITE exposure: on a
//     re-apply the blanket GRANT re-adds write privileges, and only a REVOKE
//     that still runs after it takes them away again.
func TestIntegration_Schema_SingleApplyGrantsEveryRelation(t *testing.T) {
	admin := testdb.Connect(t) // skips unless TEST_DATABASE_URL is set

	dbName := "grantorder_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	if _, err := admin.Exec(fmt.Sprintf("CREATE DATABASE %q", dbName)); err != nil {
		t.Fatalf("create throwaway database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %q WITH (FORCE)", dbName))
	})

	fresh := openNamed(t, dbName)

	// The role-split section GRANTs to crypto_user's default privileges; real
	// deployments connect as it. The ephemeral harness runs as postgres, so
	// create it exactly as scripts/run-integration-db-tests.sh does.
	if _, err := fresh.Exec("CREATE ROLE crypto_user"); err != nil && !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("create crypto_user: %v", err)
	}

	schema, err := os.ReadFile(filepath.Join(testdb.RepoRoot(t), "scripts/database/schema.sql"))
	if err != nil {
		t.Fatalf("read schema.sql: %v", err)
	}
	if _, err := fresh.Exec(string(schema)); err != nil {
		t.Fatalf("single apply of schema.sql failed: %v", err)
	}
	assertSchemaGrants(t, fresh, "a fresh SINGLE apply")

	if _, err := fresh.Exec(string(schema)); err != nil {
		t.Fatalf("second apply of schema.sql failed: %v", err)
	}
	assertSchemaGrants(t, fresh, "a SECOND apply (helm upgrade)")
}

// readOnlyForApp lists the tables crypto_app may READ but must never WRITE.
// They are the deliberate exceptions to "every table gets full DML", so the
// full-DML check skips them and assertSchemaGrants holds them to the narrower
// rule instead: SELECT present, INSERT/UPDATE/DELETE/TRUNCATE absent.
//
// Adding a table here is a security decision, not a way to quiet the full-DML
// check: it needs a matching REVOKE ALL + GRANT SELECT in the ROLE GRANTS block
// at the end of scripts/database/schema.sql, AFTER the blanket grants.
var readOnlyForApp = []string{
	// The install's licence. Every service's entitlement resolver reads it on
	// the app pool; a crypto_app INSERT of an 'enterprise' row would switch on
	// every paid capability for every tenant.
	"platform_license",
	// The install's identity, which an MSP licence is bound to. Rewriting it
	// would let a licence bound to another install verify here.
	"platform_install",
	// The MSP soft cap's grace clocks, one per licence. Deleting a licence's
	// row from the app pool would hand it a second grace period.
	"license_cap_grace",
	// The MSP usage-metering ledger (edition-licensing spec PR 4). Only
	// admin-service's usage collector writes it, on the bypass pool; a
	// crypto_app write could drop a customer from a month's report or forge
	// its lifecycle.
	"license_usage_events",
	"license_usage_snapshot_runs",
	"license_usage_daily",
	"license_usage_reports",
}

// noAccessForApp lists the tables crypto_app may not even READ. Same rule as
// readOnlyForApp for adding one: a REVOKE ALL in the ROLE GRANTS block, after
// the blanket grants — and no GRANT back.
var noAccessForApp = []string{
	// The install signing key's private half on an install with none mounted
	// (compose/dev). Anyone who can read it can sign a usage report as this
	// install.
	"license_signing_dev_key",
}

// assertSchemaGrants checks crypto_app's and crypto_bypass's privileges after
// the schema has been applied; after names which apply, for the failure text.
func assertSchemaGrants(t *testing.T, fresh *sql.DB, after string) {
	t.Helper()
	readOnly := "'" + strings.Join(append(append([]string{}, readOnlyForApp...), noAccessForApp...), "','") + "'"

	// Every ordinary and partitioned table in both schemas must be fully
	// reachable by crypto_app. Anything listed here is a table that was created
	// after the blanket grant.
	assertNone(t, fresh, after, "tables without full crypto_app DML", `
		SELECT n.nspname || '.' || c.relname
		  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname IN ('public','audit') AND c.relkind IN ('r','p')
		   AND NOT (n.nspname = 'public' AND c.relname IN (`+readOnly+`))
		   AND NOT (has_table_privilege('crypto_app', c.oid, 'SELECT')
		        AND has_table_privilege('crypto_app', c.oid, 'INSERT')
		        AND has_table_privilege('crypto_app', c.oid, 'UPDATE')
		        AND has_table_privilege('crypto_app', c.oid, 'DELETE'))
		 ORDER BY 1`)

	// The read-only tables: each must EXIST (a renamed or dropped table would
	// otherwise pass both checks below vacuously), be readable by crypto_app,
	// and not be writable by it in any way. crypto_bypass — the reconciler's
	// pool — keeps full DML.
	for _, table := range readOnlyForApp {
		var exists, sel, ins, upd, del, trunc, bypassWrite bool
		if err := fresh.QueryRow(`
			SELECT to_regclass($1) IS NOT NULL,
			       COALESCE(has_table_privilege('crypto_app', to_regclass($1), 'SELECT'), false),
			       COALESCE(has_table_privilege('crypto_app', to_regclass($1), 'INSERT'), false),
			       COALESCE(has_table_privilege('crypto_app', to_regclass($1), 'UPDATE'), false),
			       COALESCE(has_table_privilege('crypto_app', to_regclass($1), 'DELETE'), false),
			       COALESCE(has_table_privilege('crypto_app', to_regclass($1), 'TRUNCATE'), false),
			       COALESCE(has_table_privilege('crypto_bypass', to_regclass($1), 'INSERT')
			            AND has_table_privilege('crypto_bypass', to_regclass($1), 'UPDATE')
			            AND has_table_privilege('crypto_bypass', to_regclass($1), 'DELETE'), false)`,
			"public."+table).Scan(&exists, &sel, &ins, &upd, &del, &trunc, &bypassWrite); err != nil {
			t.Fatalf("after %s: read privileges on %s: %v", after, table, err)
		}
		switch {
		case !exists:
			t.Errorf("after %s: public.%s is listed in readOnlyForApp but does not exist — "+
				"a renamed table would leave its replacement unguarded", after, table)
		case !sel:
			t.Errorf("after %s: crypto_app cannot SELECT public.%s — every service's resolver reads it on the app pool; "+
				"the GRANT SELECT after the REVOKE in schema.sql's ROLE GRANTS block is missing", after, table)
		case ins || upd || del || trunc:
			t.Errorf("after %s: crypto_app can write public.%s (INSERT=%v UPDATE=%v DELETE=%v TRUNCATE=%v) — "+
				"the REVOKE ALL in schema.sql's ROLE GRANTS block is missing or runs before the blanket GRANT",
				after, table, ins, upd, del, trunc)
		case !bypassWrite:
			t.Errorf("after %s: crypto_bypass cannot write public.%s — admin-service's licence reconciler writes it on that pool", after, table)
		}
	}

	// The no-access tables: they must exist, crypto_app must hold NO privilege
	// on them (not even SELECT), and crypto_bypass — admin-service's pool —
	// keeps full DML.
	for _, table := range noAccessForApp {
		var exists, anyApp, bypassAll bool
		if err := fresh.QueryRow(`
			SELECT to_regclass($1) IS NOT NULL,
			       COALESCE(has_table_privilege('crypto_app', to_regclass($1), 'SELECT')
			             OR has_table_privilege('crypto_app', to_regclass($1), 'INSERT')
			             OR has_table_privilege('crypto_app', to_regclass($1), 'UPDATE')
			             OR has_table_privilege('crypto_app', to_regclass($1), 'DELETE')
			             OR has_table_privilege('crypto_app', to_regclass($1), 'TRUNCATE'), false),
			       COALESCE(has_table_privilege('crypto_bypass', to_regclass($1), 'SELECT')
			            AND has_table_privilege('crypto_bypass', to_regclass($1), 'INSERT')
			            AND has_table_privilege('crypto_bypass', to_regclass($1), 'UPDATE')
			            AND has_table_privilege('crypto_bypass', to_regclass($1), 'DELETE'), false)`,
			"public."+table).Scan(&exists, &anyApp, &bypassAll); err != nil {
			t.Fatalf("after %s: read privileges on %s: %v", after, table, err)
		}
		switch {
		case !exists:
			t.Errorf("after %s: public.%s is listed in noAccessForApp but does not exist — "+
				"a renamed table would leave its replacement unguarded", after, table)
		case anyApp:
			t.Errorf("after %s: crypto_app holds a privilege on public.%s — the REVOKE ALL in schema.sql's "+
				"ROLE GRANTS block is missing, runs before the blanket GRANT, or is followed by a GRANT", after, table)
		case !bypassAll:
			t.Errorf("after %s: crypto_bypass cannot read and write public.%s — admin-service's usage collector uses that pool", after, table)
		}
	}

	// Sequences have the identical ordering flaw (GRANT ... ON ALL SEQUENCES).
	// MATERIALIZED forces the relkind filter ahead of has_sequence_privilege,
	// which errors on non-sequence relations.
	assertNone(t, fresh, after, "sequences without crypto_app USAGE", `
		WITH s AS MATERIALIZED (
			SELECT c.oid, n.nspname, c.relname
			  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			 WHERE n.nspname IN ('public','audit') AND c.relkind = 'S')
		SELECT nspname || '.' || relname FROM s
		 WHERE NOT has_sequence_privilege('crypto_app', oid, 'USAGE') ORDER BY 1`)

	// Views likewise — except the three matviews crypto_app is DELIBERATELY
	// revoked from (it reads them through the tenant-scoped *_tenant wrappers).
	// Naming them explicitly means this also fails if a REVOKE stops running
	// after the blanket grant, i.e. the other polarity of the same ordering bug.
	assertNone(t, fresh, after, "views without crypto_app SELECT", `
		SELECT n.nspname || '.' || c.relname
		  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname IN ('public','audit') AND c.relkind IN ('v','m')
		   AND NOT has_table_privilege('crypto_app', c.oid, 'SELECT')
		   AND c.relname NOT IN ('mv_location_finding_summary','mv_remediation_queue','tenant_cost_summary')
		 ORDER BY 1`)

	// The deliberate narrowings must have SURVIVED the relocated blanket grant —
	// they only hold if they still run after it.
	assertNone(t, fresh, after, "cross-tenant matviews still readable by crypto_app", `
		SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = 'public'
		   AND c.relname IN ('mv_location_finding_summary','mv_remediation_queue','tenant_cost_summary')
		   AND has_table_privilege('crypto_app', c.oid, 'SELECT')
		 ORDER BY 1`)

	// ...while the tenant-scoped wrapper views and crypto_bypass's deliberate
	// cross-tenant lane stay open.
	assertNone(t, fresh, after, "expected grants missing after the narrowing REVOKEs", `
		SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = 'public' AND (
		       (c.relname IN ('mv_location_finding_summary_tenant','mv_remediation_queue_tenant')
		        AND NOT has_table_privilege('crypto_app', c.oid, 'SELECT'))
		    OR (c.relname IN ('mv_location_finding_summary','mv_remediation_queue','tenant_cost_summary')
		        AND NOT has_table_privilege('crypto_bypass', c.oid, 'SELECT')))
		 ORDER BY 1`)
}

// openNamed reopens TEST_DATABASE_URL against a different database name.
func openNamed(t *testing.T, dbName string) *sql.DB {
	t.Helper()
	u, err := url.Parse(os.Getenv(testdb.URLEnv))
	if err != nil {
		t.Fatalf("parse %s: %v", testdb.URLEnv, err)
	}
	u.Path = "/" + dbName
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatalf("open %s: %v", dbName, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("ping %s: %v", dbName, err)
	}
	return db
}

// assertNone fails with the offending relation names, which are the actionable
// part of the diagnosis — a bare count would say "9" and nothing else.
func assertNone(t *testing.T, db *sql.DB, after, what, query string) {
	t.Helper()
	rows, err := db.Query(query)
	if err != nil {
		t.Fatalf("%s: query: %v", what, err)
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("%s: scan: %v", what, err)
		}
		names = append(names, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("%s: rows: %v", what, err)
	}
	if len(names) > 0 {
		t.Errorf("%s after %s of schema.sql (%d):\n  %s\n\n"+
			"The blanket \"GRANT ... ON ALL TABLES/SEQUENCES\" is expanded once. Anything "+
			"created after it in schema.sql gets nothing. Keep the ROLE GRANTS block last.",
			what, after, len(names), strings.Join(names, "\n  "))
	}
}
