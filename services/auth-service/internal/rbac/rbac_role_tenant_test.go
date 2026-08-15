package rbac

//: service-layer defense — the role-scoped operations must reject a role
// that is not the caller's tenant's, so a cross-tenant roleId is refused even if
// the handler's path guard is ever bypassed. The refusal is structural: roleMeta
// filters on `tenant_id = $2`, so a foreign role yields no row and is
// indistinguishable from "no such role".

import (
	"errors"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func newRBACServiceMock(t *testing.T) (*RBACService, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	return &RBACService{db: db}, mock, func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet SQL expectations: %v", err)
		}
		_ = db.Close()
	}
}

// distinctive fragment of the role-identity query, which is also the tenant filter.
const roleMetaQuery = `FROM tenant_roles WHERE id = \$1 AND tenant_id = \$2`

// expectTenantTxBegin mirrors the WithTenantTx prologue (RLS Phase 3): a
// transaction that first sets app.tenant_id via set_tenant_context($1).
func expectTenantTxBegin(mock sqlmock.Sqlmock, tenantID uuid.UUID) {
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
}

// expectRoleMeta stubs the ownership/identity read. `found=false` models a role
// belonging to some other tenant (or no role at all) — no row comes back.
func expectRoleMeta(mock sqlmock.Sqlmock, roleID, tenantID uuid.UUID, found, isSystem bool) {
	q := mock.ExpectQuery(roleMetaQuery).WithArgs(roleID, tenantID)
	if !found {
		q.WillReturnRows(sqlmock.NewRows([]string{"name", "display_name", "description", "is_system_role"}))
		return
	}
	q.WillReturnRows(
		sqlmock.NewRows([]string{"name", "display_name", "description", "is_system_role"}).
			AddRow("custom_role", "Custom Role", "", isSystem),
	)
}

func TestGetPermissionMatrix_RejectsForeignRole(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, roleID, actorID := uuid.New(), uuid.New(), uuid.New()
	expectTenantTxBegin(mock, tenantID)
	expectRoleMeta(mock, roleID, tenantID, false, false)
	mock.ExpectRollback()

	if _, err := svc.GetPermissionMatrix(tenantID, roleID, actorID); !errors.Is(err, ErrRoleNotInTenant) {
		t.Fatalf("got %v, want ErrRoleNotInTenant", err)
	}
}

func TestUpdateRolePermissions_RejectsForeignRole(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, roleID, actorID := uuid.New(), uuid.New(), uuid.New()
	expectTenantTxBegin(mock, tenantID)
	expectRoleMeta(mock, roleID, tenantID, false, false)
	mock.ExpectRollback()

	if err := svc.UpdateRolePermissions(tenantID, roleID, actorID, []uuid.UUID{uuid.New()}); !errors.Is(err, ErrRoleNotInTenant) {
		t.Fatalf("got %v, want ErrRoleNotInTenant", err)
	}
}

func TestDeleteTenantRole_RejectsForeignRole(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, roleID := uuid.New(), uuid.New()
	expectTenantTxBegin(mock, tenantID)
	expectRoleMeta(mock, roleID, tenantID, false, false)
	mock.ExpectRollback()

	if _, err := svc.DeleteTenantRole(tenantID, roleID, nil); !errors.Is(err, ErrRoleNotInTenant) {
		t.Fatalf("got %v, want ErrRoleNotInTenant", err)
	}
}

// --- system roles are read-only on all three write verbs -------------------
//
// Not a preference: scripts/database/seed.sql's reconciliation DO block re-runs
// on every helm upgrade and would revert any edit to an is_system_role=true row.

func TestUpdateRolePermissions_RejectsSystemRole(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, roleID, actorID := uuid.New(), uuid.New(), uuid.New()
	expectTenantTxBegin(mock, tenantID)
	expectRoleMeta(mock, roleID, tenantID, true, true)
	mock.ExpectRollback()

	if err := svc.UpdateRolePermissions(tenantID, roleID, actorID, []uuid.UUID{uuid.New()}); !errors.Is(err, ErrSystemRoleImmutable) {
		t.Fatalf("got %v, want ErrSystemRoleImmutable", err)
	}
}

func TestDeleteTenantRole_RejectsSystemRole(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, roleID := uuid.New(), uuid.New()
	expectTenantTxBegin(mock, tenantID)
	expectRoleMeta(mock, roleID, tenantID, true, true)
	mock.ExpectRollback()

	if _, err := svc.DeleteTenantRole(tenantID, roleID, nil); !errors.Is(err, ErrSystemRoleImmutable) {
		t.Fatalf("got %v, want ErrSystemRoleImmutable", err)
	}
}

// A system role is still READABLE — only writes are refused.
func TestGetPermissionMatrix_SystemRoleIsReadableButNotEditable(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, roleID, actorID := uuid.New(), uuid.New(), uuid.New()
	permID := uuid.New()

	expectTenantTxBegin(mock, tenantID)
	expectRoleMeta(mock, roleID, tenantID, true, true)
	mock.ExpectQuery(`SELECT DISTINCT p.id`).WithArgs(actorID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(permID))
	mock.ExpectQuery(`FROM tenant_permissions p`).WithArgs(roleID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "description", "resource", "action", "granted"}).
			AddRow(permID, "users.read", "Read users", "users", "read", true))
	mock.ExpectCommit()

	m, err := svc.GetPermissionMatrix(tenantID, roleID, actorID)
	if err != nil {
		t.Fatalf("unexpected error for an owned system role: %v", err)
	}
	if !m.IsSystemRole || m.Editable {
		t.Fatalf("system role must report is_system_role=true, editable=false; got %+v", m)
	}
	if len(m.Permissions) != 1 || !m.Permissions[0].Granted || !m.Permissions[0].Grantable {
		t.Fatalf("unexpected matrix rows: %+v", m.Permissions)
	}
	if len(m.GrantedPermissionIDs) != 1 || m.GrantedPermissionIDs[0] != permID {
		t.Fatalf("granted_permission_ids = %v", m.GrantedPermissionIDs)
	}
}

// The matrix marks a permission the caller does not hold as not grantable, which
// is what lets the UI render it locked instead of letting the user try and 403.
func TestGetPermissionMatrix_MarksUnheldPermissionsNotGrantable(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, roleID, actorID := uuid.New(), uuid.New(), uuid.New()
	heldID, unheldID := uuid.New(), uuid.New()

	expectTenantTxBegin(mock, tenantID)
	expectRoleMeta(mock, roleID, tenantID, true, false)
	mock.ExpectQuery(`SELECT DISTINCT p.id`).WithArgs(actorID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(heldID))
	mock.ExpectQuery(`FROM tenant_permissions p`).WithArgs(roleID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "description", "resource", "action", "granted"}).
			AddRow(heldID, "users.read", "", "users", "read", false).
			AddRow(unheldID, "billing.update", "", "billing", "update", false))
	mock.ExpectCommit()

	m, err := svc.GetPermissionMatrix(tenantID, roleID, actorID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !m.Permissions[0].Grantable {
		t.Fatal("held permission must be grantable")
	}
	if m.Permissions[1].Grantable {
		t.Fatal("permission the caller does not hold must NOT be grantable")
	}
	if !m.Editable {
		t.Fatal("custom role must be editable")
	}
}
