package api

// DB-integration coverage for the ONE named role-delegation exception:
// tenant_admin may hand out billing_admin even though billing_admin holds
// billing.update and tenant_admin does not.
//
// The exception is declared in standards/permissions.yaml (`role_delegations:`)
// and generated into authrbac.RoleDelegations; authrbac.DelegatedPermissionNames
// decides whether a given call is covered by it. These tests run against a REAL
// Postgres with the REAL seeded system roles and their REAL grants, because the
// whole question is what the grant reconciliation actually put in
// tenant_role_permissions — a mocked answer would be assuming the conclusion.
//
// What each direction pins:
//
//	positive  — tenant_admin CAN now grant billing_admin (the bug)
//	negative  — tenant_admin still CANNOT grant anything else it lacks, and a
//	            role that merely holds billing.update is not covered: the
//	            exception is keyed on the ROLE PAIR, not on the permission
//	grantor   — a role that is not the named grantor gets no exemption
//	tenant    — the exemption does not cross a tenant boundary
//	holding   — tenant_admin did not itself gain billing.update, and still
//	            cannot mint it onto a role of its own
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	authrbac "github.com/vistasecurity/vistaplatform/auth-service/internal/rbac"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// roleIDOf returns the tenant's role id for roleName.
func (e *grantBoundsEnv) roleIDOf(t *testing.T, roleName string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := e.owner.QueryRow(
		`SELECT id FROM tenant_roles WHERE tenant_id = $1 AND name = $2`, e.tenant, roleName).Scan(&id); err != nil {
		t.Fatalf("look up role %q: %v", roleName, err)
	}
	return id
}

// permissionID returns the catalogue id for a permission name.
func permissionID(t *testing.T, db *sql.DB, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(`SELECT id FROM tenant_permissions WHERE name = $1`, name).Scan(&id); err != nil {
		t.Fatalf("look up permission %q: %v", name, err)
	}
	return id
}

// roleHasPermission reports whether the tenant's roleName currently grants
// permissionName.
func (e *grantBoundsEnv) roleHasPermission(t *testing.T, roleName, permissionName string) bool {
	t.Helper()
	var n int
	if err := e.owner.QueryRow(`
		SELECT COUNT(*) FROM tenant_role_permissions rp
		JOIN tenant_roles r ON r.id = rp.role_id
		JOIN tenant_permissions p ON p.id = rp.permission_id
		WHERE r.tenant_id = $1 AND r.name = $2 AND p.name = $3`,
		e.tenant, roleName, permissionName).Scan(&n); err != nil {
		t.Fatalf("check %s -> %s: %v", roleName, permissionName, err)
	}
	return n > 0
}

// assertDelegationPreconditions fails if the fixture does not actually contain
// the situation the exception exists for. Without this a green positive test
// could just mean "tenant_admin holds billing.update after all", which is the
// wrong fix wearing the right result.
func (e *grantBoundsEnv) assertDelegationPreconditions(t *testing.T) {
	t.Helper()
	if !e.roleHasPermission(t, "billing_admin", "billing.update") {
		t.Fatal("billing_admin does not hold billing.update — the fixture is not the situation under test")
	}
	if e.roleHasPermission(t, "tenant_admin", "billing.update") {
		t.Fatal("tenant_admin HOLDS billing.update — the guard would pass for the wrong reason, " +
			"and the exception is supposed to delegate the permission, not confer it")
	}
}

// --- positive: the bug -------------------------------------------------------

// Removing the billing_admin entry from role_delegations: in
// standards/permissions.yaml (and regenerating) makes this fail with 403.
func TestIntegration_RoleDelegation_TenantAdminCanGrantBillingAdmin(t *testing.T) {
	e := newGrantBoundsEnv(t)
	e.assertDelegationPreconditions(t)
	actor := e.newUserWithRole(t, "tenant-admin-delegates@example.com", "tenant_admin")
	target := e.newUserWithRole(t, "finance-contact@example.com", "viewer")

	eng := e.engine(actor, func(g *gin.RouterGroup) {
		g.PUT("/users/:id", UpdateUser(e.owner))
	})
	w := do(eng, http.MethodPut, "/api/v1/auth-service/users/"+target.String(),
		strings.NewReader(`{"role":"billing_admin"}`))

	if w.Code != http.StatusOK {
		t.Fatalf("UpdateUser: status = %d, want 200 — a tenant admin must be able to delegate billing "+
			"authority inside its own tenant; body=%s", w.Code, w.Body.String())
	}
	if got := e.roleOf(t, target); got != "billing_admin" {
		t.Fatalf("target role = %q, want billing_admin", got)
	}
}

// The same exception, through the other role-assignment guard
// (RBACService.AssignUserRole -> validateGrantable). Both call sites must honour
// it or the role still 403s from whichever picker uses that route.
func TestIntegration_RoleDelegation_TenantAdminCanGrantBillingAdminViaRBACAssign(t *testing.T) {
	e := newGrantBoundsEnv(t)
	e.assertDelegationPreconditions(t)
	actor := e.newUserWithRole(t, "tenant-admin-rbac-assign@example.com", "tenant_admin")
	target := e.newUserWithRole(t, "finance-rbac-assign@example.com", "viewer")

	svc := authrbac.NewRBACService(e.owner)
	if err := svc.AssignUserRole(e.tenant, target, e.roleIDOf(t, "billing_admin"), actor); err != nil {
		t.Fatalf("AssignUserRole(billing_admin) = %v, want nil", err)
	}
}

// --- negative: everything else is unchanged ---------------------------------

// A CUSTOM role that holds billing.update is NOT the billing_admin role, and
// the exception is keyed on the role pair rather than on the permission. If it
// were written as "tenant_admin may grant billing.update", this passes silently
// — which is why the guard checks the grantee role's identity and its
// is_system_role flag rather than looking only at the permission name.
//
// Driven through RBACService.AssignUserRole because that is the route that
// takes an arbitrary role id; UpdateUser's request binding only accepts the
// five system role names, so a custom role cannot reach its guard at all.
func TestIntegration_RoleDelegation_TenantAdminRefusedCustomRoleHoldingBillingUpdate(t *testing.T) {
	e := newGrantBoundsEnv(t)
	e.assertDelegationPreconditions(t)
	actor := e.newUserWithRole(t, "tenant-admin-custom-role@example.com", "tenant_admin")
	target := e.newUserWithRole(t, "target-custom-role@example.com", "viewer")

	var customRoleID uuid.UUID
	if err := e.owner.QueryRow(`
		INSERT INTO tenant_roles (tenant_id, name, display_name, is_system_role)
		VALUES ($1, 'finance_lookalike', 'Finance Lookalike', false) RETURNING id`,
		e.tenant).Scan(&customRoleID); err != nil {
		t.Fatalf("seed lookalike role: %v", err)
	}
	if _, err := e.owner.Exec(`
		INSERT INTO tenant_role_permissions (role_id, permission_id)
		VALUES ($1, $2)`, customRoleID, permissionID(t, e.owner, "billing.update")); err != nil {
		t.Fatalf("grant billing.update to lookalike role: %v", err)
	}

	err := authrbac.NewRBACService(e.owner).AssignUserRole(e.tenant, target, customRoleID, actor)
	var notHeld *authrbac.ErrPermissionNotHeld
	if !errors.As(err, &notHeld) {
		t.Fatalf("AssignUserRole(custom role holding billing.update) = %v, want *ErrPermissionNotHeld — "+
			"the exception is keyed on the billing_admin ROLE, not on the billing.update permission", err)
	}
	if got := e.roleOf(t, target); got != "viewer" {
		t.Fatalf("target role = %q, want it left at viewer", got)
	}
}

// The same claim isolated to the NAME check. The role above is refused by two
// independent conditions (not a system role, and not the named grantee), so it
// cannot tell which one is doing the work. This one IS a system role holding
// billing.update, so only the grantee-name check stands between a tenant admin
// and it.
func TestIntegration_RoleDelegation_TenantAdminRefusedOtherSystemRoleHoldingBillingUpdate(t *testing.T) {
	e := newGrantBoundsEnv(t)
	e.assertDelegationPreconditions(t)
	actor := e.newUserWithRole(t, "tenant-admin-sysrole@example.com", "tenant_admin")
	target := e.newUserWithRole(t, "target-sysrole@example.com", "viewer")

	var roleID uuid.UUID
	if err := e.owner.QueryRow(`
		INSERT INTO tenant_roles (tenant_id, name, display_name, is_system_role)
		VALUES ($1, 'treasury_admin', 'Treasury Admin', true) RETURNING id`,
		e.tenant).Scan(&roleID); err != nil {
		t.Fatalf("seed system lookalike role: %v", err)
	}
	if _, err := e.owner.Exec(`
		INSERT INTO tenant_role_permissions (role_id, permission_id)
		VALUES ($1, $2)`, roleID, permissionID(t, e.owner, "billing.update")); err != nil {
		t.Fatalf("grant billing.update: %v", err)
	}

	err := authrbac.NewRBACService(e.owner).AssignUserRole(e.tenant, target, roleID, actor)
	var notHeld *authrbac.ErrPermissionNotHeld
	if !errors.As(err, &notHeld) {
		t.Fatalf("AssignUserRole(unnamed system role holding billing.update) = %v, want "+
			"*ErrPermissionNotHeld — only billing_admin is delegable", err)
	}
}

// The exception names tenant_admin as the grantor. No other role inherits it,
// including one that can otherwise administer users.
func TestIntegration_RoleDelegation_SecurityAdminCannotGrantBillingAdmin(t *testing.T) {
	e := newGrantBoundsEnv(t)
	e.assertDelegationPreconditions(t)
	actor := e.newUserWithRole(t, "sec-admin-billing@example.com", "security_admin")
	target := e.newUserWithRole(t, "target-sec-billing@example.com", "viewer")

	eng := e.engine(actor, func(g *gin.RouterGroup) {
		g.PUT("/users/:id", UpdateUser(e.owner))
	})
	w := do(eng, http.MethodPut, "/api/v1/auth-service/users/"+target.String(),
		strings.NewReader(`{"role":"billing_admin"}`))

	assertPermissionNotHeld(t, w.Code, w.Body.String(), "UpdateUser(security_admin -> billing_admin)")
	if got := e.roleOf(t, target); got != "viewer" {
		t.Fatalf("target role = %q, want it left at viewer", got)
	}
}

// The grantor half of the pairing, isolated. security_admin above is refused
// over several permissions at once, so it cannot show which check fired. This
// actor holds EXACTLY billing_admin's grants minus billing.update — the same
// shape as tenant_admin, differing only in which role it is — so billing.update
// is the single thing standing in the way and the grantor name is the only
// reason the exemption does not apply.
func TestIntegration_RoleDelegation_NonGrantorRoleWithSameGapCannotGrantBillingAdmin(t *testing.T) {
	e := newGrantBoundsEnv(t)
	e.assertDelegationPreconditions(t)
	actor := e.newUserWithRole(t, "finance-deputy@example.com", "")
	target := e.newUserWithRole(t, "target-deputy@example.com", "viewer")

	var deputyRoleID uuid.UUID
	if err := e.owner.QueryRow(`
		INSERT INTO tenant_roles (tenant_id, name, display_name, is_system_role)
		VALUES ($1, 'finance_deputy', 'Finance Deputy', false) RETURNING id`,
		e.tenant).Scan(&deputyRoleID); err != nil {
		t.Fatalf("seed deputy role: %v", err)
	}
	if _, err := e.owner.Exec(`
		INSERT INTO tenant_role_permissions (role_id, permission_id)
		SELECT $1, rp.permission_id
		FROM tenant_role_permissions rp
		JOIN tenant_roles r ON r.id = rp.role_id
		JOIN tenant_permissions p ON p.id = rp.permission_id
		WHERE r.tenant_id = $2 AND r.name = 'billing_admin' AND p.name <> 'billing.update'`,
		deputyRoleID, e.tenant); err != nil {
		t.Fatalf("copy billing_admin grants minus billing.update: %v", err)
	}
	if _, err := e.owner.Exec(`
		INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, assigned_at, is_active)
		VALUES ($1, $2, $3, NOW(), true)`, actor, e.tenant, deputyRoleID); err != nil {
		t.Fatalf("assign deputy role: %v", err)
	}

	err := authrbac.NewRBACService(e.owner).AssignUserRole(
		e.tenant, target, e.roleIDOf(t, "billing_admin"), actor)
	var notHeld *authrbac.ErrPermissionNotHeld
	if !errors.As(err, &notHeld) {
		t.Fatalf("AssignUserRole(billing_admin) by a non-grantor role = %v, want *ErrPermissionNotHeld — "+
			"the exemption is keyed on the tenant_admin role, not on the shape of the gap", err)
	}
	if len(notHeld.Names) != 1 || notHeld.Names[0] != "billing.update" {
		t.Fatalf("missing = %v, want exactly [billing.update] — anything else means the fixture is "+
			"refused for an unrelated reason and proves nothing about the grantor check", notHeld.Names)
	}
}

// --- the cross-tenant case --------------------------------------------------

// The tenant-scoping proof. The exemption is resolved from the actor's roles
// "in THIS tenant"; if that conjunct ever detaches — the failure mode a
// generated grant predicate produced once before, where an unbracketed OR
// dropped the tenant scoping and both self-checks stayed green — then being
// tenant_admin ANYWHERE would delegate billing_admin EVERYWHERE.
//
// So the conjunct is made false directly: the same actor, the same delegation,
// a different tenant. The exemption must come back empty and the assignment
// must be refused. The home-tenant leg in the same test is what stops this
// passing for the trivial reason that the lookup never returns anything.
func TestIntegration_RoleDelegation_ExemptionDoesNotCrossTenants(t *testing.T) {
	home := newGrantBoundsEnv(t)
	home.assertDelegationPreconditions(t)
	actor := home.newUserWithRole(t, "tenant-admin-home@example.com", "tenant_admin")

	// A second tenant, with its own seeded system roles. The actor holds
	// nothing here.
	foreign := newGrantBoundsEnv(t)
	foreign.assertDelegationPreconditions(t)
	foreignTarget := foreign.newUserWithRole(t, "victim-foreign@example.com", "viewer")

	// Run the lookup TWO ways, and the first one is the load-bearing one.
	//
	// Under the crypto_app role, RLS hides the actor's home-tenant rows whether
	// or not the query says `r.tenant_id = $2` — so an app-role-only assertion
	// proves nothing about the conjunct. The owner handle is not subject to
	// those policies (tenant_roles/user_tenant_roles are not FORCE RLS and
	// crypto_user owns them), so there the WHERE clause is the only thing
	// standing between this actor and a foreign tenant's roles.
	ctx := context.Background()
	handles := []struct {
		name   string
		lookup func(t *testing.T, tenant, roleID uuid.UUID) map[string]struct{}
	}{
		{
			// Production's own transaction wrapper, no role drop: RLS is out of
			// the picture and only the SQL conjunct scopes the read.
			name: "owner, no RLS — the SQL conjunct is the only scoping",
			lookup: func(t *testing.T, tenant, roleID uuid.UUID) map[string]struct{} {
				t.Helper()
				var out map[string]struct{}
				if err := shareddatabase.WithTenantTx(ctx, home.owner, tenant, func(tx *sql.Tx) error {
					var err error
					out, err = authrbac.DelegatedPermissionNames(ctx, tx, tenant, actor, roleID)
					return err
				}); err != nil {
					t.Fatalf("DelegatedPermissionNames (owner): %v", err)
				}
				return out
			},
		},
		{
			name: "crypto_app role — RLS applies as well",
			lookup: func(t *testing.T, tenant, roleID uuid.UUID) map[string]struct{} {
				t.Helper()
				app := testdb.ConnectAsAppRole(t, home.owner)
				var out map[string]struct{}
				testdb.AsTenant(t, app, tenant, func(tx *sql.Tx) {
					var err error
					out, err = authrbac.DelegatedPermissionNames(ctx, tx, tenant, actor, roleID)
					if err != nil {
						t.Fatalf("DelegatedPermissionNames (app role): %v", err)
					}
				})
				return out
			},
		},
	}

	for _, h := range handles {
		// Leg 1 — home tenant: the exemption applies. Without this, leg 2 would
		// pass for the trivial reason that the lookup finds nothing anywhere.
		homeNames := h.lookup(t, home.tenant, home.roleIDOf(t, "billing_admin"))
		if _, ok := homeNames["billing.update"]; !ok {
			t.Fatalf("%s, home tenant: exemption = %v, want billing.update", h.name, homeNames)
		}

		// Leg 2 — the SAME actor, the SAME delegation, a DIFFERENT tenant.
		// Nothing. This is the tenant conjunct made false.
		foreignNames := h.lookup(t, foreign.tenant, foreign.roleIDOf(t, "billing_admin"))
		if len(foreignNames) != 0 {
			t.Fatalf("%s, foreign tenant: exemption = %v, want empty — a tenant admin of one tenant "+
				"must delegate nothing in another", h.name, foreignNames)
		}
	}

	// And the end-to-end refusal that follows from it.
	eng := foreign.engine(actor, func(g *gin.RouterGroup) {
		g.PUT("/users/:id", UpdateUser(foreign.owner))
	})
	w := do(eng, http.MethodPut, "/api/v1/auth-service/users/"+foreignTarget.String(),
		strings.NewReader(`{"role":"billing_admin"}`))

	assertPermissionNotHeld(t, w.Code, w.Body.String(), "UpdateUser(cross-tenant billing_admin)")
	if got := foreign.roleOf(t, foreignTarget); got != "viewer" {
		t.Fatalf("foreign target role = %q, want it left at viewer — a cross-tenant delegation landed", got)
	}
}

// --- delegating is not holding ----------------------------------------------

// The distinction the whole exception rests on. Dropping billing.update from
// tenant_admin's except_names in standards/permissions.yaml would make the
// positive test above pass too — and fail here, which is the point.
func TestIntegration_RoleDelegation_TenantAdminDoesNotItselfHoldBillingUpdate(t *testing.T) {
	e := newGrantBoundsEnv(t)

	if e.roleHasPermission(t, "tenant_admin", "billing.update") {
		t.Fatal("tenant_admin holds billing.update — delegating billing authority and being able to " +
			"change payment methods or cancel the subscription are different powers")
	}
	if !e.roleHasPermission(t, "tenant_admin", "billing.read") {
		t.Fatal("tenant_admin lost billing.read — it must still see invoices, usage and payment history")
	}
	if !e.roleHasPermission(t, "billing_admin", "billing.update") {
		t.Fatal("billing_admin lost billing.update — the role it delegates would be pointless")
	}
}

// The exception covers ASSIGNING billing_admin, not minting billing.update
// anywhere else. A tenant admin editing a role's permission set is unchanged,
// so it cannot put billing.update on a role of its own and then hold it.
func TestIntegration_RoleDelegation_TenantAdminCannotMintBillingUpdateOntoOwnRole(t *testing.T) {
	e := newGrantBoundsEnv(t)
	e.assertDelegationPreconditions(t)
	actor := e.newUserWithRole(t, "tenant-admin-mint@example.com", "tenant_admin")

	svc := authrbac.NewRBACService(e.owner)
	role, err := svc.CreateTenantRole(e.tenant, actor, authrbac.CreateRoleRequest{
		DisplayName:   "Ops Helpers",
		PermissionIDs: []string{permissionID(t, e.owner, "assets.read").String()},
	})
	if err != nil {
		t.Fatalf("CreateTenantRole: %v", err)
	}

	err = svc.UpdateRolePermissions(e.tenant, role.ID, actor,
		[]uuid.UUID{permissionID(t, e.owner, "billing.update")})
	var notHeld *authrbac.ErrPermissionNotHeld
	if !errors.As(err, &notHeld) {
		t.Fatalf("UpdateRolePermissions(billing.update) = %v, want *ErrPermissionNotHeld — the role "+
			"delegation must not reach the permission-set editor", err)
	}

	// Creating a role with it outright is refused for the same reason.
	if _, err := svc.CreateTenantRole(e.tenant, actor, authrbac.CreateRoleRequest{
		DisplayName:   "Finance Backdoor",
		PermissionIDs: []string{permissionID(t, e.owner, "billing.update").String()},
	}); !errors.As(err, &notHeld) {
		t.Fatalf("CreateTenantRole(billing.update) = %v, want *ErrPermissionNotHeld", err)
	}
}
