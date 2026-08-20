package rbac

// Service-layer tests for tenant custom-role CRUD: permission replacement
// actually persisting, the two escalation guards, and delete semantics.
//
// These drive the real SQL through sqlmock, so the statements asserted here are
// the statements production issues. They do NOT prove the SQL is valid Postgres
// — see role_crud_integration_test.go (skipped without TEST_DATABASE_URL) for
// that.

import (
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// --- UpdateRolePermissions: the replacement actually persists ---------------

func TestUpdateRolePermissions_ReplacesGrants(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, roleID, actorID := uuid.New(), uuid.New(), uuid.New()
	keepID, addID, dropID := uuid.New(), uuid.New(), uuid.New()

	expectTenantTxBegin(mock, tenantID)
	expectRoleMeta(mock, roleID, tenantID, true, false)
	// Current grants: keep + drop.
	mock.ExpectQuery(`SELECT permission_id FROM tenant_role_permissions WHERE role_id = \$1`).
		WithArgs(roleID).
		WillReturnRows(sqlmock.NewRows([]string{"permission_id"}).AddRow(keepID).AddRow(dropID))
	// Catalogue bound: both requested ids resolve.
	mock.ExpectQuery(`SELECT id, name FROM tenant_permissions WHERE id = ANY\(\$1\)`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).
			AddRow(keepID, "users.read").AddRow(addID, "assets.read"))
	// Caller bound: only `addID` is new, and the caller holds it.
	mock.ExpectQuery(`SELECT DISTINCT p.id`).WithArgs(actorID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(addID).AddRow(keepID))
	mock.ExpectExec(`DELETE FROM tenant_role_permissions WHERE role_id = \$1`).
		WithArgs(roleID).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`INSERT INTO tenant_role_permissions`).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectCommit()

	if err := svc.UpdateRolePermissions(tenantID, roleID, actorID, []uuid.UUID{keepID, addID}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// An empty permission_ids array is "clear all" — the DELETE runs, the INSERT
// does not. This has to be explicit or "clear the role" would be unreachable.
func TestUpdateRolePermissions_EmptySetClearsGrants(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, roleID, actorID := uuid.New(), uuid.New(), uuid.New()

	expectTenantTxBegin(mock, tenantID)
	expectRoleMeta(mock, roleID, tenantID, true, false)
	mock.ExpectQuery(`SELECT permission_id FROM tenant_role_permissions WHERE role_id = \$1`).
		WithArgs(roleID).WillReturnRows(sqlmock.NewRows([]string{"permission_id"}))
	mock.ExpectExec(`DELETE FROM tenant_role_permissions WHERE role_id = \$1`).
		WithArgs(roleID).WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectCommit()

	if err := svc.UpdateRolePermissions(tenantID, roleID, actorID, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- escalation guard 1: nothing outside the catalogue -----------------------

func TestUpdateRolePermissions_RejectsPermissionOutsideCatalogue(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, roleID, actorID := uuid.New(), uuid.New(), uuid.New()
	realID, bogusID := uuid.New(), uuid.New()

	expectTenantTxBegin(mock, tenantID)
	expectRoleMeta(mock, roleID, tenantID, true, false)
	mock.ExpectQuery(`SELECT permission_id FROM tenant_role_permissions WHERE role_id = \$1`).
		WithArgs(roleID).WillReturnRows(sqlmock.NewRows([]string{"permission_id"}))
	mock.ExpectQuery(`SELECT id, name FROM tenant_permissions WHERE id = ANY\(\$1\)`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(realID, "users.read"))
	mock.ExpectRollback()

	err := svc.UpdateRolePermissions(tenantID, roleID, actorID, []uuid.UUID{realID, bogusID})
	var unknown *ErrUnknownPermissions
	if !errors.As(err, &unknown) {
		t.Fatalf("got %v, want *ErrUnknownPermissions", err)
	}
	if len(unknown.IDs) != 1 || unknown.IDs[0] != bogusID {
		t.Fatalf("unknown ids = %v, want [%s]", unknown.IDs, bogusID)
	}
}

// --- escalation guard 2: only grant what you hold ---------------------------

func TestUpdateRolePermissions_RejectsGrantingUnheldPermission(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, roleID, actorID := uuid.New(), uuid.New(), uuid.New()
	heldID, unheldID := uuid.New(), uuid.New()

	expectTenantTxBegin(mock, tenantID)
	expectRoleMeta(mock, roleID, tenantID, true, false)
	mock.ExpectQuery(`SELECT permission_id FROM tenant_role_permissions WHERE role_id = \$1`).
		WithArgs(roleID).WillReturnRows(sqlmock.NewRows([]string{"permission_id"}))
	mock.ExpectQuery(`SELECT id, name FROM tenant_permissions WHERE id = ANY\(\$1\)`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).
			AddRow(heldID, "users.read").AddRow(unheldID, "billing.update"))
	mock.ExpectQuery(`SELECT DISTINCT p.id`).WithArgs(actorID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(heldID))
	mock.ExpectRollback()

	err := svc.UpdateRolePermissions(tenantID, roleID, actorID, []uuid.UUID{heldID, unheldID})
	var notHeld *ErrPermissionNotHeld
	if !errors.As(err, &notHeld) {
		t.Fatalf("got %v, want *ErrPermissionNotHeld", err)
	}
	if len(notHeld.Names) != 1 || notHeld.Names[0] != "billing.update" {
		t.Fatalf("denied = %v, want [billing.update]", notHeld.Names)
	}
}

// The guard covers only the ADDED delta: an admin editing a role that already
// grants something they lack must not be forced to drop it.
func TestUpdateRolePermissions_AllowsKeepingAlreadyGrantedUnheldPermission(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, roleID, actorID := uuid.New(), uuid.New(), uuid.New()
	unheldButGranted := uuid.New()

	expectTenantTxBegin(mock, tenantID)
	expectRoleMeta(mock, roleID, tenantID, true, false)
	mock.ExpectQuery(`SELECT permission_id FROM tenant_role_permissions WHERE role_id = \$1`).
		WithArgs(roleID).
		WillReturnRows(sqlmock.NewRows([]string{"permission_id"}).AddRow(unheldButGranted))
	mock.ExpectQuery(`SELECT id, name FROM tenant_permissions WHERE id = ANY\(\$1\)`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(unheldButGranted, "billing.update"))
	// No caller-permission lookup: the added delta is empty, so the guard
	// short-circuits. (An expectation here would go unmet and fail the test.)
	mock.ExpectExec(`DELETE FROM tenant_role_permissions WHERE role_id = \$1`).
		WithArgs(roleID).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO tenant_role_permissions`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := svc.UpdateRolePermissions(tenantID, roleID, actorID, []uuid.UUID{unheldButGranted}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAssignUserRole_RejectsRoleWithUnheldPermission(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, userID, roleID, actorID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	heldID, unheldID := uuid.New(), uuid.New()

	expectTenantTxBegin(mock, tenantID)
	mock.ExpectQuery(`SELECT tenant_id FROM users WHERE id = \$1 AND deleted_at IS NULL`).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))
	mock.ExpectQuery(`SELECT tenant_id FROM tenant_roles WHERE id = \$1`).
		WithArgs(roleID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))
	mock.ExpectQuery(`SELECT permission_id FROM tenant_role_permissions WHERE role_id = \$1`).
		WithArgs(roleID).
		WillReturnRows(sqlmock.NewRows([]string{"permission_id"}).AddRow(heldID).AddRow(unheldID))
	// Delegation lookup: security_admin is named by no RoleDelegation, so the
	// exemption set is empty and the guard below is the unchanged one. (No
	// grantor-role query follows — the lookup short-circuits.)
	mock.ExpectQuery(`SELECT name, is_system_role FROM tenant_roles`).
		WithArgs(roleID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"name", "is_system_role"}).
			AddRow("security_admin", true))
	mock.ExpectQuery(`SELECT id, name FROM tenant_permissions WHERE id = ANY\(\$1\)`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).
			AddRow(heldID, "users.manage").AddRow(unheldID, "billing.update"))
	mock.ExpectQuery(`SELECT DISTINCT p.id`).WithArgs(actorID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(heldID))
	mock.ExpectRollback()

	err := svc.AssignUserRole(tenantID, userID, roleID, actorID)
	var notHeld *ErrPermissionNotHeld
	if !errors.As(err, &notHeld) {
		t.Fatalf("got %v, want *ErrPermissionNotHeld", err)
	}
	if len(notHeld.Names) != 1 || notHeld.Names[0] != "billing.update" {
		t.Fatalf("denied = %v, want [billing.update]", notHeld.Names)
	}
}

func TestAssignUserRole_AllowsRoleWhosePermissionsCallerHolds(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, userID, roleID, actorID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	permID := uuid.New()

	expectTenantTxBegin(mock, tenantID)
	mock.ExpectQuery(`SELECT tenant_id FROM users WHERE id = \$1 AND deleted_at IS NULL`).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))
	mock.ExpectQuery(`SELECT tenant_id FROM tenant_roles WHERE id = \$1`).
		WithArgs(roleID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))
	mock.ExpectQuery(`SELECT permission_id FROM tenant_role_permissions WHERE role_id = \$1`).
		WithArgs(roleID).
		WillReturnRows(sqlmock.NewRows([]string{"permission_id"}).AddRow(permID))
	mock.ExpectQuery(`SELECT name, is_system_role FROM tenant_roles`).
		WithArgs(roleID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"name", "is_system_role"}).AddRow("viewer", true))
	mock.ExpectQuery(`SELECT id, name FROM tenant_permissions WHERE id = ANY\(\$1\)`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(permID, "users.manage"))
	mock.ExpectQuery(`SELECT DISTINCT p.id`).WithArgs(actorID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(permID))
	mock.ExpectExec(`INSERT INTO user_tenant_roles`).
		WithArgs(userID, tenantID, roleID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := svc.AssignUserRole(tenantID, userID, roleID, actorID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- CreateTenantRole -------------------------------------------------------

func TestCreateTenantRole_CreatesCustomRoleWithGrants(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, actorID := uuid.New(), uuid.New()
	permID, newRoleID := uuid.New(), uuid.New()

	expectTenantTxBegin(mock, tenantID)
	mock.ExpectQuery(`SELECT id, name FROM tenant_permissions WHERE id = ANY\(\$1\)`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(permID, "assets.read"))
	mock.ExpectQuery(`SELECT DISTINCT p.id`).WithArgs(actorID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(permID))
	mock.ExpectQuery(`INSERT INTO tenant_roles`).
		WithArgs(tenantID, "auditors", "Auditors", "Read-only auditors").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(newRoleID, time.Now(), time.Now()))
	mock.ExpectExec(`INSERT INTO tenant_role_permissions`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	role, err := svc.CreateTenantRole(tenantID, actorID, CreateRoleRequest{
		DisplayName:   "Auditors",
		Description:   "Read-only auditors",
		PermissionIDs: []string{permID.String()},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.Name != "auditors" {
		t.Fatalf("slug = %q, want %q", role.Name, "auditors")
	}
	if role.IsSystemRole {
		t.Fatal("created roles must be is_system_role=false or the seed reconciliation would rewrite them")
	}
}

// The escalation guard applies at creation too — otherwise it would be trivially
// bypassable by creating the role instead of editing one.
func TestCreateTenantRole_RejectsGrantingUnheldPermission(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, actorID := uuid.New(), uuid.New()
	unheldID := uuid.New()

	expectTenantTxBegin(mock, tenantID)
	mock.ExpectQuery(`SELECT id, name FROM tenant_permissions WHERE id = ANY\(\$1\)`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(unheldID, "billing.update"))
	mock.ExpectQuery(`SELECT DISTINCT p.id`).WithArgs(actorID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectRollback()

	_, err := svc.CreateTenantRole(tenantID, actorID, CreateRoleRequest{
		DisplayName:   "Escalated",
		PermissionIDs: []string{unheldID.String()},
	})
	var notHeld *ErrPermissionNotHeld
	if !errors.As(err, &notHeld) {
		t.Fatalf("got %v, want *ErrPermissionNotHeld", err)
	}
}

func TestCreateTenantRole_RejectsUnusableName(t *testing.T) {
	svc, _, cleanup := newRBACServiceMock(t)
	defer cleanup()
	// display_name of only punctuation slugifies to "", and an explicit bad slug
	// is rejected outright. Neither reaches the database.
	for _, req := range []CreateRoleRequest{
		{DisplayName: "!!!"},
		{Name: "Has Spaces", DisplayName: "Whatever"},
		{Name: "9leading", DisplayName: "Whatever"},
	} {
		if _, err := svc.CreateTenantRole(uuid.New(), uuid.New(), req); !errors.Is(err, ErrInvalidRoleName) {
			t.Fatalf("req %+v: got %v, want ErrInvalidRoleName", req, err)
		}
	}
}

func TestSlugifyRoleName(t *testing.T) {
	cases := map[string]string{
		"Auditors":           "auditors",
		"Read Only Auditors": "read_only_auditors",
		"  Spaced  Out  ":    "spaced_out",
		"Ops/Sec — Team":     "ops_sec_team",
		"!!!":                "",
	}
	for in, want := range cases {
		if got := slugifyRoleName(in); got != want {
			t.Errorf("slugifyRoleName(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- DeleteTenantRole -------------------------------------------------------

// Default semantics: a role people still hold is REFUSED, with the holder count,
// so the UI can offer a reassignment target rather than silently moving people.
func TestDeleteTenantRole_BlocksWhenUsersHoldIt(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, roleID := uuid.New(), uuid.New()

	expectTenantTxBegin(mock, tenantID)
	expectRoleMeta(mock, roleID, tenantID, true, false)
	mock.ExpectQuery(`sso_group_role_mappings`).WithArgs(roleID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM user_tenant_roles`).WithArgs(roleID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))
	mock.ExpectRollback()

	_, err := svc.DeleteTenantRole(tenantID, roleID, nil)
	var inUse *ErrRoleInUse
	if !errors.As(err, &inUse) {
		t.Fatalf("got %v, want *ErrRoleInUse", err)
	}
	if inUse.UserCount != 3 {
		t.Fatalf("user count = %d, want 3", inUse.UserCount)
	}
}

// With an explicit target, holders are moved (skipping anyone who already holds
// the target — user_tenant_roles is unique on (user, tenant, role)), then the
// role and its residue are dropped. Same shape as the analyst retirement in
// scripts/database/seed.sql.
func TestDeleteTenantRole_ReassignsWhenTargetGiven(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, roleID, targetID := uuid.New(), uuid.New(), uuid.New()

	expectTenantTxBegin(mock, tenantID)
	expectRoleMeta(mock, roleID, tenantID, true, false)
	mock.ExpectQuery(`sso_group_role_mappings`).WithArgs(roleID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM user_tenant_roles`).WithArgs(roleID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	expectRoleMeta(mock, targetID, tenantID, true, false)
	mock.ExpectExec(`UPDATE user_tenant_roles utr`).WithArgs(targetID, tenantID, roleID).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`DELETE FROM user_tenant_roles WHERE role_id = \$1`).WithArgs(roleID, tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`DELETE FROM tenant_role_permissions WHERE role_id = \$1`).WithArgs(roleID).
		WillReturnResult(sqlmock.NewResult(0, 4))
	mock.ExpectExec(`DELETE FROM tenant_roles WHERE id = \$1`).WithArgs(roleID, tenantID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	res, err := svc.DeleteTenantRole(tenantID, roleID, &targetID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ReassignedUsers != 2 || res.ReassignedToID == nil || *res.ReassignedToID != targetID {
		t.Fatalf("unexpected result: %+v", res)
	}
}

// A reassignment target in another tenant must be refused by the same
// filter that protects the role being deleted.
func TestDeleteTenantRole_RejectsForeignReassignTarget(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, roleID, targetID := uuid.New(), uuid.New(), uuid.New()

	expectTenantTxBegin(mock, tenantID)
	expectRoleMeta(mock, roleID, tenantID, true, false)
	mock.ExpectQuery(`sso_group_role_mappings`).WithArgs(roleID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM user_tenant_roles`).WithArgs(roleID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	expectRoleMeta(mock, targetID, tenantID, false, false)
	mock.ExpectRollback()

	if _, err := svc.DeleteTenantRole(tenantID, roleID, &targetID); !errors.Is(err, ErrRoleNotInTenant) {
		t.Fatalf("got %v, want ErrRoleNotInTenant", err)
	}
}

// An unheld role deletes cleanly with no reassignment target.
func TestDeleteTenantRole_DeletesUnheldRole(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, roleID := uuid.New(), uuid.New()

	expectTenantTxBegin(mock, tenantID)
	expectRoleMeta(mock, roleID, tenantID, true, false)
	mock.ExpectQuery(`sso_group_role_mappings`).WithArgs(roleID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM user_tenant_roles`).WithArgs(roleID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectExec(`DELETE FROM user_tenant_roles WHERE role_id = \$1`).WithArgs(roleID, tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`DELETE FROM tenant_role_permissions WHERE role_id = \$1`).WithArgs(roleID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`DELETE FROM tenant_roles WHERE id = \$1`).WithArgs(roleID, tenantID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	res, err := svc.DeleteTenantRole(tenantID, roleID, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ReassignedUsers != 0 || res.ReassignedToID != nil {
		t.Fatalf("unexpected result: %+v", res)
	}
}

// Deleting a role wired into SSO would cascade-delete its group mappings and
// NULL a provider's default role — provisioning would silently stop. Refused.
func TestDeleteTenantRole_BlocksWhenReferencedBySSO(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, roleID := uuid.New(), uuid.New()

	expectTenantTxBegin(mock, tenantID)
	expectRoleMeta(mock, roleID, tenantID, true, false)
	mock.ExpectQuery(`sso_group_role_mappings`).WithArgs(roleID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectRollback()

	if _, err := svc.DeleteTenantRole(tenantID, roleID, nil); !errors.Is(err, ErrRoleReferencedBySSO) {
		t.Fatalf("got %v, want ErrRoleReferencedBySSO", err)
	}
}
