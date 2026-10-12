package rbac

// DB-integration coverage for two RBAC invariants. Skips unless
// TEST_DATABASE_URL is set; runs as the non-owner app role so RLS is in play.
//
//   - a user_tenant_roles row past expires_at grants nothing (the DB functions
//     other services use already honour it; this service's queries did not);
//   - the last tenant_admin assignment of a tenant cannot be removed.
//
// Mutation: drop `AND (ur.expires_at IS NULL OR ur.expires_at > now())` from
// GetUserPermissions / GetUserRoles / CheckPermission and the expiry test
// fails; drop the guard block in RemoveUserRole and the last-admin tests fail.

import (
	"database/sql"
	"errors"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func seedRole(t *testing.T, owner *sql.DB, tenantID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := owner.QueryRow(`
		INSERT INTO tenant_roles (tenant_id, name, display_name, is_system_role)
		VALUES ($1, $2, $2, false) RETURNING id`, tenantID, name).Scan(&id); err != nil {
		t.Fatalf("seed role %s: %v", name, err)
	}
	return id
}

func assign(t *testing.T, owner *sql.DB, tenantID, userID, roleID uuid.UUID, expiresSQL string) {
	t.Helper()
	if _, err := owner.Exec(`
		INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, is_active, expires_at)
		VALUES ($1, $2, $3, true, `+expiresSQL+`)`, userID, tenantID, roleID); err != nil {
		t.Fatalf("assign: %v", err)
	}
}

func TestIntegration_ExpiredRoleGrantsNothing(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	tenantID := testdb.NewTenant(t, owner)
	perms := seedPermissions(t, owner, 1)
	user := newIntegrationUser(t, owner, tenantID)

	live := seedRole(t, owner, tenantID, "it_live")
	expired := seedRole(t, owner, tenantID, "it_expired")
	for _, r := range []uuid.UUID{live, expired} {
		if _, err := owner.Exec(`INSERT INTO tenant_role_permissions (role_id, permission_id) VALUES ($1, $2)`, r, perms[0]); err != nil {
			t.Fatal(err)
		}
	}
	var permName string
	if err := owner.QueryRow(`SELECT name FROM tenant_permissions WHERE id = $1`, perms[0]).Scan(&permName); err != nil {
		t.Fatal(err)
	}
	svc := NewRBACService(app)

	// Only the expired assignment: nothing is granted.
	assign(t, owner, tenantID, user, expired, `now() - interval '1 hour'`)
	got, err := svc.GetUserPermissions(tenantID, user)
	if err != nil || len(got) != 0 {
		t.Fatalf("expired role: permissions = %v, err = %v; want none", got, err)
	}
	roles, err := svc.GetUserRoles(tenantID, user)
	if err != nil || len(roles) != 0 {
		t.Fatalf("expired role: roles = %v, err = %v; want none", roles, err)
	}
	if ok, err := svc.CheckPermission(tenantID, user, permName); err != nil || ok {
		t.Fatalf("expired role: CheckPermission = %v, err = %v; want false", ok, err)
	}

	// A live (future-expiry) assignment is honoured.
	assign(t, owner, tenantID, user, live, `now() + interval '1 hour'`)
	got, err = svc.GetUserPermissions(tenantID, user)
	if err != nil || len(got) != 1 {
		t.Fatalf("live role: permissions = %v, err = %v; want 1", got, err)
	}
	if ok, err := svc.CheckPermission(tenantID, user, permName); err != nil || !ok {
		t.Fatalf("live role: CheckPermission = %v, err = %v; want true", ok, err)
	}
}

func TestIntegration_RemoveRole_LastTenantAdminRefused(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	tenantID := testdb.NewTenant(t, owner)
	admin1 := newIntegrationUser(t, owner, tenantID)
	admin2 := newIntegrationUser(t, owner, tenantID)
	adminRole := seedRole(t, owner, tenantID, "tenant_admin")
	viewerRole := seedRole(t, owner, tenantID, "it_viewer")
	assign(t, owner, tenantID, admin1, adminRole, `NULL`)
	assign(t, owner, tenantID, admin1, viewerRole, `NULL`)
	svc := NewRBACService(app)

	// The only admin: refused, and the assignment is untouched.
	if err := svc.RemoveUserRole(tenantID, admin1, adminRole); !errors.Is(err, ErrLastTenantAdmin) {
		t.Fatalf("remove sole admin: err = %v, want ErrLastTenantAdmin", err)
	}
	var active bool
	if err := owner.QueryRow(`SELECT is_active FROM user_tenant_roles WHERE user_id=$1 AND role_id=$2`, admin1, adminRole).Scan(&active); err != nil || !active {
		t.Fatalf("sole admin assignment must stay active (active=%v err=%v)", active, err)
	}

	// Non-admin roles are unaffected by the guard.
	if err := svc.RemoveUserRole(tenantID, admin1, viewerRole); err != nil {
		t.Fatalf("remove non-admin role: %v", err)
	}

	// An EXPIRED second admin is not a safe fallback.
	assign(t, owner, tenantID, admin2, adminRole, `now() - interval '1 hour'`)
	if err := svc.RemoveUserRole(tenantID, admin1, adminRole); !errors.Is(err, ErrLastTenantAdmin) {
		t.Fatalf("remove admin with only an expired peer: err = %v, want ErrLastTenantAdmin", err)
	}

	// Through the handler it is a 409.
	h := NewRBACHandlersWithStore(svc)
	c, w := newCtx(tenantID.String(), gin.Params{
		{Key: "tenantId", Value: tenantID.String()},
		{Key: "userId", Value: admin1.String()},
		{Key: "roleId", Value: adminRole.String()},
	})
	h.RemoveRole(c)
	if w.Code != http.StatusConflict {
		t.Fatalf("handler status = %d, want 409; body=%s", w.Code, w.Body.String())
	}

	// With a second live admin, removal succeeds.
	if _, err := owner.Exec(`UPDATE user_tenant_roles SET expires_at = NULL WHERE user_id=$1 AND role_id=$2`, admin2, adminRole); err != nil {
		t.Fatal(err)
	}
	if err := svc.RemoveUserRole(tenantID, admin1, adminRole); err != nil {
		t.Fatalf("remove admin with a live peer: %v", err)
	}
}
