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
//  2. It applies the schema exactly ONCE. A second apply is what masked this for
//     so long: by then every table exists when the GRANT runs.
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

	// Every ordinary and partitioned table in both schemas must be fully
	// reachable by crypto_app. Anything listed here is a table that was created
	// after the blanket grant.
	assertNone(t, fresh, "tables without full crypto_app DML", `
		SELECT n.nspname || '.' || c.relname
		  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname IN ('public','audit') AND c.relkind IN ('r','p')
		   AND NOT (has_table_privilege('crypto_app', c.oid, 'SELECT')
		        AND has_table_privilege('crypto_app', c.oid, 'INSERT')
		        AND has_table_privilege('crypto_app', c.oid, 'UPDATE')
		        AND has_table_privilege('crypto_app', c.oid, 'DELETE'))
		 ORDER BY 1`)

	// Sequences have the identical ordering flaw (GRANT ... ON ALL SEQUENCES).
	// MATERIALIZED forces the relkind filter ahead of has_sequence_privilege,
	// which errors on non-sequence relations.
	assertNone(t, fresh, "sequences without crypto_app USAGE", `
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
	assertNone(t, fresh, "views without crypto_app SELECT", `
		SELECT n.nspname || '.' || c.relname
		  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname IN ('public','audit') AND c.relkind IN ('v','m')
		   AND NOT has_table_privilege('crypto_app', c.oid, 'SELECT')
		   AND c.relname NOT IN ('mv_location_finding_summary','mv_remediation_queue','tenant_cost_summary')
		 ORDER BY 1`)

	// The deliberate narrowings must have SURVIVED the relocated blanket grant —
	// they only hold if they still run after it.
	assertNone(t, fresh, "cross-tenant matviews still readable by crypto_app", `
		SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = 'public'
		   AND c.relname IN ('mv_location_finding_summary','mv_remediation_queue','tenant_cost_summary')
		   AND has_table_privilege('crypto_app', c.oid, 'SELECT')
		 ORDER BY 1`)

	// ...while the tenant-scoped wrapper views and crypto_bypass's deliberate
	// cross-tenant lane stay open.
	assertNone(t, fresh, "expected grants missing after the narrowing REVOKEs", `
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
func assertNone(t *testing.T, db *sql.DB, what, query string) {
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
		t.Errorf("%s after a fresh SINGLE apply of schema.sql (%d):\n  %s\n\n"+
			"The blanket \"GRANT ... ON ALL TABLES/SEQUENCES\" is expanded once. Anything "+
			"created after it in schema.sql gets nothing. Keep the ROLE GRANTS block last.",
			what, len(names), strings.Join(names, "\n  "))
	}
}
