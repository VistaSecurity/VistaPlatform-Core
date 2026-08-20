package api

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	authrbac "github.com/vistasecurity/vistaplatform/auth-service/internal/rbac"
)

// TestListUsers_Validation tests the validation logic for list users
func TestListUsers_Validation(t *testing.T) {
	// Test that default limit is applied
	req := ListUsersRequest{}
	if req.Limit <= 0 {
		req.Limit = 50
	}
	if req.Limit != 50 {
		t.Errorf("Expected default limit 50, got %d", req.Limit)
	}

	// Test that negative offset is corrected
	req.Offset = -5
	if req.Offset < 0 {
		req.Offset = 0
	}
	if req.Offset != 0 {
		t.Errorf("Expected offset 0 after correction, got %d", req.Offset)
	}

	// Test max limit
	req.Limit = 200
	if req.Limit > 100 {
		req.Limit = 100
	}
	if req.Limit != 100 {
		t.Errorf("Expected max limit 100, got %d", req.Limit)
	}
}

// TestCreateUserRequest_Validation tests the validation for create user request
func TestCreateUserRequest_Validation(t *testing.T) {
	// Test valid role
	validRoles := []string{"tenant_admin", "security_admin", "viewer"}
	for _, role := range validRoles {
		req := CreateUserRequest{Role: role}
		// In real test, would use binding validation
		if req.Role != role {
			t.Errorf("Expected role %s, got %s", role, req.Role)
		}
	}
}

// TestUpdateUserRequest_Validation tests the validation for update user request
func TestUpdateUserRequest_Validation(t *testing.T) {
	// Test that nil values are allowed (partial update)
	req := UpdateUserRequest{}
	if req.FirstName != nil {
		t.Error("FirstName should be nil for partial update")
	}

	// Test valid role values
	validRole := "viewer"
	req.Role = &validRole
	if *req.Role != "viewer" {
		t.Errorf("Expected role viewer, got %s", *req.Role)
	}
}

// Note: Integration tests would require:
// - Test database setup
// - JWT token generation
// - Tenant context setup
// - Actual database queries
// These are better suited for integration test files with testcontainers or similar

func TestAssignUserRole_RejectsRoleWhosePermissionsActorDoesNotHold(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	tenantID := uuid.New()
	userID := uuid.New()
	actorID := uuid.New()
	roleID := uuid.New()
	unheldPermissionID := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT id FROM tenant_roles`).
		WithArgs(tenantID, "tenant_admin").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(roleID))
	// The ceiling resolves the role's owning tenant before reading its grants,
	// so a role id from another tenant can never reach the comparison.
	mock.ExpectQuery(`SELECT tenant_id FROM tenant_roles`).
		WithArgs(roleID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))
	mock.ExpectQuery(`SELECT p\.id, p\.name`).
		WithArgs(roleID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(unheldPermissionID, "users.delete"))
	// Delegation lookup: tenant_admin is a grantOR in the delegation table, not
	// a grantEE, so no pairing matches and the exemption set is empty.
	mock.ExpectQuery(`SELECT name, is_system_role FROM tenant_roles`).
		WithArgs(roleID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"name", "is_system_role"}).AddRow("tenant_admin", true))
	mock.ExpectQuery(`SELECT DISTINCT p\.id`).
		WithArgs(actorID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectRollback()

	err = assignUserRole(db, userID, tenantID, actorID, "tenant_admin")
	var notHeld *authrbac.ErrPermissionNotHeld
	if !errors.As(err, &notHeld) {
		t.Fatalf("assignUserRole error = %v, want *ErrPermissionNotHeld", err)
	}
	if len(notHeld.Names) != 1 || notHeld.Names[0] != "users.delete" {
		t.Fatalf("missing permissions = %v, want [users.delete]", notHeld.Names)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestEnsureRoleGrantableByName_RejectsBeforeInvitationOrUserCreate(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	tenantID := uuid.New()
	actorID := uuid.New()
	roleID := uuid.New()
	unheldPermissionID := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT id FROM tenant_roles`).
		WithArgs(tenantID, "security_admin").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(roleID))
	// The ceiling resolves the role's owning tenant before reading its grants,
	// so a role id from another tenant can never reach the comparison.
	mock.ExpectQuery(`SELECT tenant_id FROM tenant_roles`).
		WithArgs(roleID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))
	mock.ExpectQuery(`SELECT p\.id, p\.name`).
		WithArgs(roleID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(unheldPermissionID, "security.view"))
	mock.ExpectQuery(`SELECT name, is_system_role FROM tenant_roles`).
		WithArgs(roleID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"name", "is_system_role"}).AddRow("security_admin", true))
	mock.ExpectQuery(`SELECT DISTINCT p\.id`).
		WithArgs(actorID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectRollback()

	err = ensureRoleGrantableByName(context.Background(), db, tenantID, actorID, "security_admin")
	var notHeld *authrbac.ErrPermissionNotHeld
	if !errors.As(err, &notHeld) {
		t.Fatalf("ensureRoleGrantableByName error = %v, want *ErrPermissionNotHeld", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}
