package testdb

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"testing"

	"github.com/google/uuid"
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
	// binary's grant/apply it fails "tuple concurrently updated" — serialize
	// under the same advisory lock as the other schema-mutating helpers.
	withSchemaLock(t, owner, func(ctx context.Context, conn *sql.Conn) {
		if _, err := conn.ExecContext(ctx, `ALTER ROLE `+RLSAppRole+` LOGIN PASSWORD '`+appRolePassword+`'`); err != nil {
			t.Fatalf("testdb: grant LOGIN to %s: %v", RLSAppRole, err)
		}
	})
	u, err := url.Parse(os.Getenv(URLEnv))
	if err != nil {
		t.Fatalf("testdb: parse %s: %v", URLEnv, err)
	}
	u.User = url.UserPassword(RLSAppRole, appRolePassword)
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatalf("testdb: open as %s: %v", RLSAppRole, err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("testdb: ping as %s: %v", RLSAppRole, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
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
	}
	// Serialized under the schema advisory lock: concurrent GRANTs on the same
	// objects from parallel test binaries fail "tuple concurrently updated".
	withSchemaLock(t, db, func(ctx context.Context, conn *sql.Conn) {
		for _, s := range stmts {
			if _, err := conn.ExecContext(ctx, s); err != nil {
				t.Fatalf("testdb: EnsureRLSAppRole: %v\nstmt: %s", err, s)
			}
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
