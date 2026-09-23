package testdb

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
)

// appRolePassword is a throwaway password the harness assigns RLSAppRole (which
// ships NOLOGIN) so a test can open a real connection as the non-owner app role.
const appRolePassword = "rls_test_app_pw"

// ConnectAsAppRole opens a *sql.DB connected as the non-owner RLSAppRole, so a
// repository under test runs subject to RLS exactly as it will in production
// (rather than under the owner connection, which bypasses RLS). It ensures the
// role + grants exist, gives it LOGIN + a known password via the owner
// connection, derives the app-role DSN from TEST_DATABASE_URL by swapping the
// userinfo, opens it, and registers cleanup.
func ConnectAsAppRole(t *testing.T, owner *sql.DB) *sql.DB {
	t.Helper()
	EnsureRLSAppRole(t, owner)
	// ALTER ROLE updates the role's pg_authid tuple; concurrent with another
	// binary's grant/apply it fails "tuple concurrently updated" — so it takes
	// the same advisory lock AND the same retry as the grants above it.
	execUnderSchemaLock(t, owner, "grant LOGIN to "+RLSAppRole,
		[]string{`ALTER ROLE ` + RLSAppRole + ` LOGIN PASSWORD '` + appRolePassword + `'`})
	return openAsRole(t, RLSAppRole, appRolePassword)
}

// BypassRole is the BYPASSRLS role that ships in the schema (ADR platform-0001,
// Phase 2). Production services hold a second "bypassDB" handle connected as it,
// for the few reads whose tenant is not yet known — an invitation looked up by
// token, say. Tests that must exercise that handle open it with
// ConnectAsBypassRole.
const BypassRole = "crypto_bypass"

// bypassRolePassword is a throwaway password the harness assigns BypassRole
// (which ships NOLOGIN) so a test can open a real connection as it.
const bypassRolePassword = "rls_test_bypass_pw"

// ConnectAsBypassRole opens a *sql.DB connected as BypassRole — the production
// "bypassDB" handle. It re-asserts the role, its grants and LOGIN + a known
// password, then derives the DSN from TEST_DATABASE_URL by swapping the
// userinfo.
//
// Every statement below mutates CLUSTER-GLOBAL catalog state (pg_authid, the
// per-table ACLs). `go test ./...` runs one process per package IN PARALLEL, so
// without serialization this races any other package binary applying schema.sql
// or re-asserting its own grants against the same database — the two grant
// expansions lock the same pg_class rows in table order while the seed's DO
// blocks hold row locks, and Postgres resolves the cycle by killing one of them.
//
// That is not hypothetical: this helper lived in auth-service's internal/api
// package and took NO lock, which deadlocked against internal/auth's concurrent
// ApplySchemaAndSeed and failed the nightly `Test - auth-service` job roughly
// every other night with `deadlock detected` on the first GRANT. The
// local harness papered over it by running auth-service with `-p 1`, so it
// reproduced only in CI. Taking the same advisory lock as every other
// schema-mutating helper here is the actual fix — keep it.
func ConnectAsBypassRole(t *testing.T, owner *sql.DB) *sql.DB {
	t.Helper()
	stmts := []string{
		`DO $$ BEGIN CREATE ROLE ` + BypassRole + ` NOLOGIN BYPASSRLS;
		 EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,
		`GRANT USAGE ON SCHEMA public TO ` + BypassRole,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ` + BypassRole,
		`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ` + BypassRole,
		`GRANT EXECUTE ON FUNCTION public.set_tenant_context(uuid) TO ` + BypassRole,
		`ALTER ROLE ` + BypassRole + ` LOGIN PASSWORD '` + bypassRolePassword + `'`,
	}
	execUnderSchemaLock(t, owner, "ensure "+BypassRole, stmts)
	return openAsRole(t, BypassRole, bypassRolePassword)
}

// openAsRole derives a DSN from TEST_DATABASE_URL by swapping in role/password,
// opens it and registers cleanup. The role must already have LOGIN.
func openAsRole(t *testing.T, role, password string) *sql.DB {
	t.Helper()
	return openAsRoleOn(t, role, password, "")
}

// openAsRoleOn is openAsRole against database dbName on the same server ("" =
// TEST_DATABASE_URL's own database).
func openAsRoleOn(t *testing.T, role, password, dbName string) *sql.DB {
	t.Helper()
	u, err := url.Parse(os.Getenv(URLEnv))
	if err != nil {
		t.Fatalf("testdb: parse %s: %v", URLEnv, err)
	}
	u.User = url.UserPassword(role, password)
	if dbName != "" {
		u.Path = "/" + dbName
	}
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatalf("testdb: open as %s: %v", role, err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("testdb: ping as %s: %v", role, err)
	}
	if err := shareddb.RegisterSessionPool(db, "postgres", u.String()); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = shareddb.CloseWithSessionPool(db) })
	return db
}

// ConnectScratchAsAppRole opens scratch — a database from ScratchDatabase — as
// RLSAppRole, and ConnectScratchAsBypassRole as BypassRole. The privileges in
// force are the ones scratch's own schema.sql apply granted (roles are
// cluster-wide, privileges are per database), so a test can assert exactly what
// the shipped schema lets each role do to global tables such as
// platform_license — without writing them on the shared database.
func ConnectScratchAsAppRole(t *testing.T, scratch *sql.DB) *sql.DB {
	t.Helper()
	execUnderSchemaLock(t, Connect(t), "grant LOGIN to "+RLSAppRole,
		[]string{`ALTER ROLE ` + RLSAppRole + ` LOGIN PASSWORD '` + appRolePassword + `'`})
	return openAsRoleOn(t, RLSAppRole, appRolePassword, scratchName(t, scratch))
}

// ConnectScratchAsBypassRole: see ConnectScratchAsAppRole.
func ConnectScratchAsBypassRole(t *testing.T, scratch *sql.DB) *sql.DB {
	t.Helper()
	execUnderSchemaLock(t, Connect(t), "grant LOGIN to "+BypassRole,
		[]string{`ALTER ROLE ` + BypassRole + ` LOGIN PASSWORD '` + bypassRolePassword + `'`})
	return openAsRoleOn(t, BypassRole, bypassRolePassword, scratchName(t, scratch))
}

func scratchName(t *testing.T, scratch *sql.DB) string {
	t.Helper()
	var name string
	if err := scratch.QueryRow(`SELECT current_database()`).Scan(&name); err != nil {
		t.Fatalf("testdb: scratch database name: %v", err)
	}
	return name
}

// RLSAppRole is the non-owner, NOBYPASSRLS application role that ships in the
// schema (ADR platform-0001, Phase 2). Production services connect as it; in
// tests we reach the same effect by dropping the owner connection to it with
// SET LOCAL ROLE, so enforcement tests exercise the role that actually ships.
const RLSAppRole = "crypto_app"

// EnsureRLSAppRole idempotently makes sure RLSAppRole exists and carries the
// schema/table/function grants a tenant-scoped application role needs. The
// schema already creates and grants it; this re-asserts the same shape so the
// harness also works against a database loaded from a pre-Phase-2 schema. Safe
// to call repeatedly.
//
// The connection behind db must be a superuser or the table owner (the role
// TEST_DATABASE_URL already uses), so SET ROLE to RLSAppRole is permitted.
func EnsureRLSAppRole(t *testing.T, db *sql.DB) {
	t.Helper()
	stmts := []string{
		`DO $$ BEGIN CREATE ROLE ` + RLSAppRole + ` NOLOGIN NOBYPASSRLS;
		 EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,
		`GRANT USAGE ON SCHEMA public TO ` + RLSAppRole,
		`GRANT USAGE ON SCHEMA audit TO ` + RLSAppRole,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ` + RLSAppRole,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA audit TO ` + RLSAppRole,
		`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ` + RLSAppRole,
		`GRANT EXECUTE ON FUNCTION public.set_tenant_context(uuid) TO ` + RLSAppRole,
		`GRANT EXECUTE ON FUNCTION public.clear_tenant_context() TO ` + RLSAppRole,
		// Mirror schema.sql's view-isolation hardening: the blanket grant above
		// re-opens the cross-tenant materialized views, and production revokes
		// them from the app role again (they're reachable only through the
		// *_tenant wrapper views). Without this, tests would pass against
		// privileges production doesn't have.
		`DO $$ BEGIN IF to_regclass('public.mv_location_finding_summary') IS NOT NULL THEN
		   REVOKE ALL ON public.mv_location_finding_summary FROM ` + RLSAppRole + `; END IF; END $$;`,
		`DO $$ BEGIN IF to_regclass('public.mv_remediation_queue') IS NOT NULL THEN
		   REVOKE ALL ON public.mv_remediation_queue FROM ` + RLSAppRole + `; END IF; END $$;`,
		`DO $$ BEGIN IF to_regclass('public.tenant_cost_summary') IS NOT NULL THEN
		   REVOKE ALL ON public.tenant_cost_summary FROM ` + RLSAppRole + `; END IF; END $$;`,
		// And its licence hardening: the install's licence and identity are
		// read-only for the app role (only admin-service's reconciler, on the
		// bypass pool, writes them). Re-granting write here would let a test
		// pass a write production refuses.
		`DO $$ BEGIN IF to_regclass('public.platform_license') IS NOT NULL THEN
		   REVOKE ALL ON public.platform_license FROM ` + RLSAppRole + `;
		   GRANT SELECT ON public.platform_license TO ` + RLSAppRole + `; END IF; END $$;`,
		`DO $$ BEGIN IF to_regclass('public.platform_install') IS NOT NULL THEN
		   REVOKE ALL ON public.platform_install FROM ` + RLSAppRole + `;
		   GRANT SELECT ON public.platform_install TO ` + RLSAppRole + `; END IF; END $$;`,
	}
	// The MSP usage-metering ledger is read-only for the app role too, and the
	// dev signing key is not readable by it at all (schema.sql ROLE GRANTS).
	for _, table := range []string{"license_usage_events", "license_usage_snapshot_runs", "license_usage_daily", "license_usage_reports"} {
		stmts = append(stmts, `DO $$ BEGIN IF to_regclass('public.`+table+`') IS NOT NULL THEN
		   REVOKE ALL ON public.`+table+` FROM `+RLSAppRole+`;
		   GRANT SELECT ON public.`+table+` TO `+RLSAppRole+`; END IF; END $$;`)
	}
	stmts = append(stmts, `DO $$ BEGIN IF to_regclass('public.license_signing_dev_key') IS NOT NULL THEN
		   REVOKE ALL ON public.license_signing_dev_key FROM `+RLSAppRole+`; END IF; END $$;`)
	execUnderSchemaLock(t, db, "EnsureRLSAppRole", stmts)
}

// execUnderSchemaLock runs catalog-mutating statements under the schema
// advisory lock, retrying — per statement — the cross-binary races
// [RetryTransient] retries.
//
// The lock is necessary and NOT sufficient, which is why the retry is here too.
// It serializes these statements against schema APPLIERS and against each
// other, and that is not everything they race with: `GRANT … ON ALL TABLES IN
// SCHEMA public` rewrites a pg_class row per table and `ALTER ROLE` rewrites a
// pg_authid tuple, so ANY concurrent catalog update from another binary — a
// test creating a trigger or an index, a throwaway database being dropped — can
// lose the tuple under it, and the error names this GRANT rather than the thing
// that moved. Retried on exactly the class applySQLFiles retries: a real
// privilege problem is deterministic and still fails after the attempts, while
// a cross-binary catalog race fails a test that has nothing to do with roles.
// (Observed repeatedly across the eol, vulnerability and riskrollup legs of
// `make test-integration-db`.)
//
// Per STATEMENT, inside one lock acquisition, rather than re-running the whole
// block: only the statement that lost its tuple needs another snapshot, and
// releasing the advisory lock between attempts would let an applier in and make
// the next attempt race the same way again.
//
// ONE helper rather than a loop per caller. The retry first landed inside
// EnsureRLSAppRole alone, which left the ALTER ROLE one line later in
// ConnectAsAppRole — and the whole of ConnectAsBypassRole, the same CREATE ROLE
// + GRANT + ALTER ROLE sequence — exposed to the identical race. Fixing one
// statement of a sequence only moves the flake along it.
//
// ONCE per database, not once per call. Each of these blocks is an idempotent
// re-assertion of cluster-global catalog state, and `GRANT … ON ALL TABLES IN
// SCHEMA public` rewrites a pg_class row for EVERY table — so running it at each
// of the hundreds of ConnectAsAppRole / ConnectAsBypassRole calls in a parallel
// run was both the slow path and a standing deadlock source against ordinary DML
// in other binaries. The marker (see applied_marker.go) records the statement
// block's hash per database; a ForceApply* of schema.sql clears it, because that
// file rewrites the same ACLs. As with the file appliers, a marker that cannot be
// read or written means the statements simply run, which is the old behaviour.
func execUnderSchemaLock(t *testing.T, db *sql.DB, what string, stmts []string) {
	t.Helper()
	block := sqlFile{name: grantMarkerPrefix + what, body: strings.Join(stmts, ";\n")}
	withSchemaLock(t, db, func(ctx context.Context, conn *sql.Conn) {
		marked := ensureAppliedMarker(ctx, conn)
		if marked && alreadyApplied(ctx, conn, block) {
			return
		}
		for _, s := range stmts {
			const attempts = 4
			for i := 1; ; i++ {
				_, err := conn.ExecContext(ctx, s)
				if err == nil {
					break
				}
				if !IsTransientRace(err) || i == attempts {
					t.Fatalf("testdb: %s (attempt %d/%d): %v\nstmt: %s", what, i, attempts, err, s)
				}
				t.Logf("testdb: %s hit a cross-binary catalog race (attempt %d/%d), retrying: %v", what, i, attempts, err)
				time.Sleep(time.Duration(i) * 150 * time.Millisecond)
			}
		}
		if marked {
			recordApplied(ctx, conn, block)
		}
	})
}

// AsTenant runs fn inside a transaction that has (1) dropped to the non-owner
// RLSAppRole so RLS policies actually apply, and (2) set app.tenant_id to
// tenantID — exactly how a service connects as the app role and scopes a single
// request. The transaction is ALWAYS rolled back, so writes performed in fn
// leave no residue (the test asserts whether a write is permitted, not that it
// persists). Requires EnsureRLSAppRole to have been called.
//
// SET LOCAL ROLE and set_config(..., is_local=>true) are both transaction-local,
// so the role drop and tenant scope unwind automatically at rollback.
func AsTenant(t *testing.T, db *sql.DB, tenantID uuid.UUID, fn func(tx *sql.Tx)) {
	t.Helper()
	runScoped(t, db, &tenantID, fn)
}

// AsRoleNoTenant runs fn in a transaction dropped to RLSAppRole but with NO
// tenant context set — used to prove the fail-closed property (every
// tenant-scoped read returns zero rows when app.tenant_id is unset).
func AsRoleNoTenant(t *testing.T, db *sql.DB, fn func(tx *sql.Tx)) {
	t.Helper()
	runScoped(t, db, nil, fn)
}

func runScoped(t *testing.T, db *sql.DB, tenantID *uuid.UUID, fn func(tx *sql.Tx)) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("testdb: AsTenant begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`SET LOCAL ROLE ` + RLSAppRole); err != nil {
		t.Fatalf("testdb: SET LOCAL ROLE %s: %v", RLSAppRole, err)
	}
	if tenantID != nil {
		if _, err := tx.Exec(`SELECT set_tenant_context($1)`, *tenantID); err != nil {
			t.Fatalf("testdb: set_tenant_context: %v", err)
		}
	}
	fn(tx)
}
