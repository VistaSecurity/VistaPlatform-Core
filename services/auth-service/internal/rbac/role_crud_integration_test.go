package rbac

// DB-integration coverage for tenant custom-role CRUD. Skips unless
// TEST_DATABASE_URL is set (see docsv4/internal/developer/standards/DB_INTEGRATION_TESTS.md);
// runs in the nightly test-backend job and locally via `make test-integration-db`.
//
// These run as the NON-OWNER app role (crypto_app, NOBYPASSRLS) — the RLS
// plain-pool sweep showed that owner-connection tests pass while every
// production query silently returns zero rows. The point of this file is to
// prove the SQL is valid Postgres AND survives RLS.

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// seedPermissions returns two ids from the global tenant_permissions catalogue,
// skipping the test if the catalogue is empty (an unseeded database).
func seedPermissions(t *testing.T, owner *sql.DB, n int) []uuid.UUID {
	t.Helper()
	rows, err := owner.Query(`SELECT id FROM tenant_permissions ORDER BY name LIMIT $1`, n)
	if err != nil {
		t.Fatalf("read permission catalogue: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if len(ids) < n {
		t.Skipf("tenant_permissions has %d rows, need %d — database is not seeded", len(ids), n)
	}
	return ids
}

// grantAll makes actorID hold every permission in the catalogue, via a throwaway
// role, so the escalation guard is satisfied and the test is about persistence.
func grantAll(t *testing.T, owner *sql.DB, tenantID, actorID uuid.UUID) {
	t.Helper()
	var roleID uuid.UUID
	if err := owner.QueryRow(`
		INSERT INTO tenant_roles (tenant_id, name, display_name, is_system_role)
		VALUES ($1, 'it_superuser', 'IT Superuser', false) RETURNING id`, tenantID).Scan(&roleID); err != nil {
		t.Fatalf("seed actor role: %v", err)
	}
	if _, err := owner.Exec(`
		INSERT INTO tenant_role_permissions (role_id, permission_id)
		SELECT $1, id FROM tenant_permissions ON CONFLICT DO NOTHING`, roleID); err != nil {
		t.Fatalf("seed actor grants: %v", err)
	}
	if _, err := owner.Exec(`
		INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, is_active)
		VALUES ($1, $2, $3, true)`, actorID, tenantID, roleID); err != nil {
		t.Fatalf("seed actor assignment: %v", err)
	}
}

func newIntegrationUser(t *testing.T, owner *sql.DB, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := owner.Exec(`
		INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name)
		VALUES ($1, $2, $3, 'x', 'IT', 'User')`, id, tenantID, "it-"+id.String()[:8]+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

func TestIntegration_TenantRoleCRUD_RoundTrip(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	tenantID := testdb.NewTenant(t, owner)

	perms := seedPermissions(t, owner, 2)
	actor := newIntegrationUser(t, owner, tenantID)
	grantAll(t, owner, tenantID, actor)

	svc := NewRBACService(app)

	// Create.
	role, err := svc.CreateTenantRole(tenantID, actor, CreateRoleRequest{
		DisplayName:   "IT Auditors",
		Description:   "integration test role",
		PermissionIDs: []string{perms[0].String()},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if role.Name != "it_auditors" {
		t.Fatalf("slug = %q", role.Name)
	}

	// Matrix reflects the initial grant.
	m, err := svc.GetPermissionMatrix(tenantID, role.ID, actor)
	if err != nil {
		t.Fatalf("matrix: %v", err)
	}
	if len(m.Permissions) == 0 {
		t.Fatal("matrix must carry the whole permission catalogue, not just the grants")
	}
	if len(m.GrantedPermissionIDs) != 1 || m.GrantedPermissionIDs[0] != perms[0] {
		t.Fatalf("granted = %v, want [%s]", m.GrantedPermissionIDs, perms[0])
	}
	if !m.Editable || m.IsSystemRole {
		t.Fatalf("a created role must be editable and non-system: %+v", m)
	}

	// Replace: swap perms[0] for perms[1]. The replacement must actually persist
	// — this is precisely what the old no-op stub reported success for.
	if err := svc.UpdateRolePermissions(tenantID, role.ID, actor, []uuid.UUID{perms[1]}); err != nil {
		t.Fatalf("update: %v", err)
	}
	m, err = svc.GetPermissionMatrix(tenantID, role.ID, actor)
	if err != nil {
		t.Fatalf("matrix after update: %v", err)
	}
	if len(m.GrantedPermissionIDs) != 1 || m.GrantedPermissionIDs[0] != perms[1] {
		t.Fatalf("after replace, granted = %v, want [%s]", m.GrantedPermissionIDs, perms[1])
	}

	// The role shows up in the list with a live permission count.
	roles, err := svc.GetTenantRoles(tenantID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var found bool
	for _, r := range roles {
		if r.ID == role.ID {
			found = true
			if r.PermissionCount != 1 {
				t.Fatalf("permission_count = %d, want 1", r.PermissionCount)
			}
			if r.IsSystemRole {
				t.Fatal("custom role listed as system")
			}
		}
	}
	if !found {
		t.Fatal("created role missing from the list")
	}

	// Delete (nobody holds it).
	if _, err := svc.DeleteTenantRole(tenantID, role.ID, nil); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := svc.GetPermissionMatrix(tenantID, role.ID, actor); !errors.Is(err, ErrRoleNotInTenant) {
		t.Fatalf("after delete, matrix returned %v, want ErrRoleNotInTenant", err)
	}
}

// System roles seeded by ensureTenantRoles are refused on every write verb — the
// answer must come from real data, not a stub.
func TestIntegration_SystemRoleIsReadOnly(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	tenantID := testdb.NewTenant(t, owner)

	var sysRoleID uuid.UUID
	if err := owner.QueryRow(`
		INSERT INTO tenant_roles (tenant_id, name, display_name, is_system_role)
		VALUES ($1, 'tenant_admin', 'Tenant Administrator', true) RETURNING id`, tenantID).Scan(&sysRoleID); err != nil {
		t.Fatalf("seed system role: %v", err)
	}

	svc := NewRBACService(app)
	actor := newIntegrationUser(t, owner, tenantID)

	if err := svc.UpdateRolePermissions(tenantID, sysRoleID, actor, nil); !errors.Is(err, ErrSystemRoleImmutable) {
		t.Fatalf("update system role: got %v, want ErrSystemRoleImmutable", err)
	}
	if _, err := svc.DeleteTenantRole(tenantID, sysRoleID, nil); !errors.Is(err, ErrSystemRoleImmutable) {
		t.Fatalf("delete system role: got %v, want ErrSystemRoleImmutable", err)
	}
	// ...but it is still readable.
	if _, err := svc.GetPermissionMatrix(tenantID, sysRoleID, actor); err != nil {
		t.Fatalf("read system role matrix: %v", err)
	}
}

// Delete semantics: blocked while held, and reassignment moves holders while
// skipping anyone who already holds the target (the unique-key hazard the seed's
// analyst retirement works around).
func TestIntegration_DeleteRoleHolderSemantics(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	tenantID := testdb.NewTenant(t, owner)

	perms := seedPermissions(t, owner, 1)
	actor := newIntegrationUser(t, owner, tenantID)
	grantAll(t, owner, tenantID, actor)
	svc := NewRBACService(app)

	doomed, err := svc.CreateTenantRole(tenantID, actor, CreateRoleRequest{
		DisplayName: "Doomed", PermissionIDs: []string{perms[0].String()},
	})
	if err != nil {
		t.Fatalf("create doomed: %v", err)
	}
	target, err := svc.CreateTenantRole(tenantID, actor, CreateRoleRequest{DisplayName: "Target"})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}

	// userA holds only `doomed`; userB holds both.
	userA := newIntegrationUser(t, owner, tenantID)
	userB := newIntegrationUser(t, owner, tenantID)
	for _, pair := range [][2]uuid.UUID{
		{userA, doomed.ID}, {userB, doomed.ID}, {userB, target.ID},
	} {
		if _, err := owner.Exec(`
			INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, is_active)
			VALUES ($1, $2, $3, true)`, pair[0], tenantID, pair[1]); err != nil {
			t.Fatalf("seed assignment: %v", err)
		}
	}

	// Blocked without a target.
	var inUse *ErrRoleInUse
	if _, err := svc.DeleteTenantRole(tenantID, doomed.ID, nil); !errors.As(err, &inUse) {
		t.Fatalf("held role delete: got %v, want *ErrRoleInUse", err)
	}
	if inUse.UserCount != 2 {
		t.Fatalf("holder count = %d, want 2", inUse.UserCount)
	}

	// With a target: userA moves, userB is skipped (already holds target) and
	// their doomed assignment is dropped instead.
	res, err := svc.DeleteTenantRole(tenantID, doomed.ID, &target.ID)
	if err != nil {
		t.Fatalf("reassigning delete: %v", err)
	}
	if res.ReassignedUsers != 1 {
		t.Fatalf("reassigned = %d, want 1 (userB already held the target)", res.ReassignedUsers)
	}

	var aHasTarget, bHasTarget, anyDoomed int
	if err := owner.QueryRow(`SELECT
			(SELECT COUNT(*) FROM user_tenant_roles WHERE user_id=$1 AND role_id=$3),
			(SELECT COUNT(*) FROM user_tenant_roles WHERE user_id=$2 AND role_id=$3),
			(SELECT COUNT(*) FROM tenant_roles WHERE id=$4)
		`, userA, userB, target.ID, doomed.ID).Scan(&aHasTarget, &bHasTarget, &anyDoomed); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if aHasTarget != 1 || bHasTarget != 1 || anyDoomed != 0 {
		t.Fatalf("post-delete state: userA=%d userB=%d doomedRoleRows=%d", aHasTarget, bHasTarget, anyDoomed)
	}
}

// The escalation guard must hold against real grant data: an actor who does not
// hold a permission cannot add it to a role.
func TestIntegration_EscalationGuardBlocksUnheldGrant(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	tenantID := testdb.NewTenant(t, owner)

	perms := seedPermissions(t, owner, 2)
	actor := newIntegrationUser(t, owner, tenantID)

	// The actor holds perms[0] only.
	var actorRole uuid.UUID
	if err := owner.QueryRow(`
		INSERT INTO tenant_roles (tenant_id, name, display_name, is_system_role)
		VALUES ($1, 'it_limited', 'IT Limited', false) RETURNING id`, tenantID).Scan(&actorRole); err != nil {
		t.Fatalf("seed actor role: %v", err)
	}
	if _, err := owner.Exec(`INSERT INTO tenant_role_permissions (role_id, permission_id) VALUES ($1, $2)`,
		actorRole, perms[0]); err != nil {
		t.Fatalf("seed actor grant: %v", err)
	}
	if _, err := owner.Exec(`
		INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, is_active)
		VALUES ($1, $2, $3, true)`, actor, tenantID, actorRole); err != nil {
		t.Fatalf("seed actor assignment: %v", err)
	}

	svc := NewRBACService(app)

	var notHeld *ErrPermissionNotHeld
	_, err := svc.CreateTenantRole(tenantID, actor, CreateRoleRequest{
		DisplayName:   "Escalated",
		PermissionIDs: []string{perms[1].String()},
	})
	if !errors.As(err, &notHeld) {
		t.Fatalf("create with unheld permission: got %v, want *ErrPermissionNotHeld", err)
	}

	// Granting what they DO hold succeeds.
	if _, err := svc.CreateTenantRole(tenantID, actor, CreateRoleRequest{
		DisplayName:   "Allowed",
		PermissionIDs: []string{perms[0].String()},
	}); err != nil {
		t.Fatalf("create with held permission: %v", err)
	}

	// And an id outside the catalogue is refused regardless.
	var unknown *ErrUnknownPermissions
	if _, err := svc.CreateTenantRole(tenantID, actor, CreateRoleRequest{
		DisplayName:   "Bogus",
		PermissionIDs: []string{uuid.NewString()},
	}); !errors.As(err, &unknown) {
		t.Fatalf("create with bogus permission: got %v, want *ErrUnknownPermissions", err)
	}
}

// end to end: a role belonging to another tenant is invisible and
// unwritable, on real data.
//
// NOTE on what this proves: there are TWO layers here — the explicit
// `AND tenant_id = $2` filter in roleMeta, and the RLS tenant_isolation policy on
// tenant_roles that WithTenantTx satisfies. This test still passes if the
// explicit filter is removed, because RLS catches it. The explicit filter is
// pinned separately by the sqlmock query-shape assertions in
// rbac_role_tenant_test.go, so removing either layer fails something.
func TestIntegration_CrossTenantRoleIsInvisible(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	tenantA := testdb.NewTenant(t, owner)
	tenantB := testdb.NewTenant(t, owner)

	actorA := newIntegrationUser(t, owner, tenantA)
	grantAll(t, owner, tenantA, actorA)

	var bRoleID uuid.UUID
	if err := owner.QueryRow(`
		INSERT INTO tenant_roles (tenant_id, name, display_name, is_system_role)
		VALUES ($1, 'b_only', 'B Only', false) RETURNING id`, tenantB).Scan(&bRoleID); err != nil {
		t.Fatalf("seed tenant B role: %v", err)
	}

	svc := NewRBACService(app)

	if _, err := svc.GetPermissionMatrix(tenantA, bRoleID, actorA); !errors.Is(err, ErrRoleNotInTenant) {
		t.Fatalf("matrix on foreign role: got %v, want ErrRoleNotInTenant", err)
	}
	if err := svc.UpdateRolePermissions(tenantA, bRoleID, actorA, nil); !errors.Is(err, ErrRoleNotInTenant) {
		t.Fatalf("update foreign role: got %v, want ErrRoleNotInTenant", err)
	}
	if _, err := svc.DeleteTenantRole(tenantA, bRoleID, nil); !errors.Is(err, ErrRoleNotInTenant) {
		t.Fatalf("delete foreign role: got %v, want ErrRoleNotInTenant", err)
	}

	// And tenant B's role survived every attempt.
	var still int
	if err := owner.QueryRow(`SELECT COUNT(*) FROM tenant_roles WHERE id = $1`, bRoleID).Scan(&still); err != nil {
		t.Fatal(err)
	}
	if still != 1 {
		t.Fatal("tenant B's role was destroyed by a tenant A request")
	}
}

// A role name that collides within the tenant is a 409-shaped conflict, not a
// 500 — and the unique key is per-tenant, so another tenant may reuse the name.
func TestIntegration_RoleNameConflictIsTyped(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	tenantID := testdb.NewTenant(t, owner)
	actor := newIntegrationUser(t, owner, tenantID)
	grantAll(t, owner, tenantID, actor)

	svc := NewRBACService(app)
	if _, err := svc.CreateTenantRole(tenantID, actor, CreateRoleRequest{DisplayName: "Dupes"}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := svc.CreateTenantRole(tenantID, actor, CreateRoleRequest{DisplayName: "Dupes"}); !errors.Is(err, ErrRoleNameConflict) {
		t.Fatalf("duplicate create: got %v, want ErrRoleNameConflict", err)
	}
}
