package api

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// connectAsBypassRole opens a *sql.DB connected as the BYPASSRLS crypto_bypass
// role — the production "bypassDB" handle. The schema already creates and grants
// it; we re-assert LOGIN + a known password (mirroring testdb.ConnectAsAppRole)
// and derive the DSN from TEST_DATABASE_URL by swapping the userinfo.
func connectAsBypassRole(t *testing.T, owner *sql.DB) *sql.DB {
	t.Helper()
	const role = "crypto_bypass"
	const pw = "rls_test_bypass_pw"
	stmts := []string{
		`DO $$ BEGIN CREATE ROLE ` + role + ` NOLOGIN BYPASSRLS; EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ` + role,
		`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ` + role,
		`GRANT EXECUTE ON FUNCTION public.set_tenant_context(uuid) TO ` + role,
		`ALTER ROLE ` + role + ` LOGIN PASSWORD '` + pw + `'`,
	}
	for _, s := range stmts {
		if _, err := owner.Exec(s); err != nil {
			t.Fatalf("testdb: ensure %s: %v\nstmt: %s", role, err, s)
		}
	}
	u, err := url.Parse(os.Getenv(testdb.URLEnv))
	if err != nil {
		t.Fatalf("testdb: parse %s: %v", testdb.URLEnv, err)
	}
	u.User = url.UserPassword(role, pw)
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatalf("testdb: open as %s: %v", role, err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("testdb: ping as %s: %v", role, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestIntegration_InvitationAccept_FailClosedUnderAppRole proves the RLS
// fail-closed gap is fixed: an invitation created under tenant A can be looked
// up by its token and accepted while the service connects as the non-owner
// crypto_app role.
//
//   - The token lookup is auth-output (the invitation's tenant is unknown until
//     the token resolves), so under crypto_app with NO tenant context it returns
//     zero rows — that is exactly the "invitation invalid" bug. Routing the lookup
//     to the BYPASSRLS handle (lockPendingInvitation(bypassDB, …)) fixes it.
//   - The downstream user/invitation writes (materializeInvitedUser) still run
//     tenant-scoped under crypto_app via WithTenantTx, so RLS keeps enforcing
//     on them.
//
// Skips unless TEST_DATABASE_URL is set.
func TestIntegration_InvitationAccept_FailClosedUnderAppRole(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.EnsureRLSAppRole(t, owner)
	app := testdb.ConnectAsAppRole(t, owner) // production "db" (crypto_app, NOBYPASSRLS)
	bypass := connectAsBypassRole(t, owner)  // production "bypassDB" (crypto_bypass, BYPASSRLS)

	tA := testdb.NewTenant(t, owner)

	// assignUserRole needs a tenant_roles row by name; seed one (owner bypasses RLS).
	const roleName = "member"
	if _, err := owner.Exec(`INSERT INTO tenant_roles (tenant_id, name, display_name) VALUES ($1, $2, $3)`,
		tA, roleName, "Member"); err != nil {
		t.Fatalf("seed tenant_roles: %v", err)
	}

	// Create the invitation. createInvitation uses WithTenantTx; it runs fine on
	// the owner connection (set_tenant_context just sets the GUC). Use the app
	// handle here too to prove the tenant-known create path works under crypto_app.
	const email = "invitee@example.com"
	_, rawToken, err := createInvitation(app, tA, email, roleName, uuid.Nil)
	if err != nil {
		t.Fatalf("createInvitation under crypto_app: %v", err)
	}

	// Fail-closed proof: a raw token lookup under crypto_app with NO tenant context
	// set returns zero rows — this is the bug the bypass routing fixes.
	var leaked uuid.UUID
	rawErr := app.QueryRow(`SELECT tenant_id FROM public.invitations WHERE token_hash = $1`,
		hashInvitationToken(rawToken)).Scan(&leaked)
	if rawErr != sql.ErrNoRows {
		t.Fatalf("expected fail-closed (sql.ErrNoRows) for token lookup under crypto_app with no tenant context, got: %v", rawErr)
	}

	// The fix: lockPendingInvitation on the BYPASSRLS handle resolves the token.
	inv, err := lockPendingInvitation(bypass, rawToken)
	if err != nil {
		t.Fatalf("lockPendingInvitation(bypassDB): %v (the fail-closed gap is NOT fixed)", err)
	}
	if inv.tenantID != tA {
		t.Fatalf("resolved tenant = %s, want %s", inv.tenantID, tA)
	}

	// Accept: materialize the invited user under crypto_app. Its existence check,
	// user INSERT, role assignment, and mark-accepted all run tenant-scoped via
	// WithTenantTx — they must succeed under the NOBYPASSRLS role.
	userID, gotRole, err := materializeInvitedUser(context.Background(), app, inv, nil)
	if err != nil {
		t.Fatalf("materializeInvitedUser under crypto_app: %v", err)
	}
	if gotRole != roleName {
		t.Fatalf("assigned role = %q, want %q", gotRole, roleName)
	}

	// Verify on the bypass handle (cross-tenant read): the user exists and the
	// invitation is now accepted.
	var gotUserTenant uuid.UUID
	if err := bypass.QueryRow(`SELECT tenant_id FROM users WHERE id = $1`, userID).Scan(&gotUserTenant); err != nil {
		t.Fatalf("read materialized user: %v", err)
	}
	if gotUserTenant != tA {
		t.Fatalf("materialized user tenant = %s, want %s", gotUserTenant, tA)
	}
	var status string
	if err := bypass.QueryRow(`SELECT status FROM public.invitations WHERE id = $1`, inv.id).Scan(&status); err != nil {
		t.Fatalf("read invitation status: %v", err)
	}
	if status != "accepted" {
		t.Fatalf("invitation status = %q, want accepted", status)
	}
}
