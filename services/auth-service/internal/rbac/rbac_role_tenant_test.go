package rbac

//: service-layer defense — GetPermissionMatrix / UpdateRolePermissions must
// reject a role that is not the caller's tenant's, so a cross-tenant roleId is
// refused even when the (currently stubbed) impls are filled in.

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

// distinctive fragment of the ownership check query.
const ownershipQuery = `FROM tenant_roles WHERE id = \$1 AND tenant_id = \$2`

func expectOwnership(mock sqlmock.Sqlmock, roleID, tenantID uuid.UUID, owned bool) {
	// roleBelongsToTenant now runs inside WithTenantTx (RLS Phase 3), so the
	// ownership read is wrapped in a transaction that first sets app.tenant_id via
	// set_tenant_context($1). Mirror that prologue/epilogue here.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(ownershipQuery).
		WithArgs(roleID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(owned))
	mock.ExpectCommit()
}

func TestGetPermissionMatrix_RejectsForeignRole(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, roleID := uuid.New(), uuid.New()
	expectOwnership(mock, roleID, tenantID, false)

	if _, err := svc.GetPermissionMatrix(tenantID, roleID); !errors.Is(err, ErrRoleNotInTenant) {
		t.Fatalf("got %v, want ErrRoleNotInTenant", err)
	}
}

func TestUpdateRolePermissions_RejectsForeignRole(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, roleID := uuid.New(), uuid.New()
	expectOwnership(mock, roleID, tenantID, false)

	if err := svc.UpdateRolePermissions(tenantID, roleID, []uuid.UUID{uuid.New()}); !errors.Is(err, ErrRoleNotInTenant) {
		t.Fatalf("got %v, want ErrRoleNotInTenant", err)
	}
}

func TestGetPermissionMatrix_AllowsOwnedRole(t *testing.T) {
	svc, mock, cleanup := newRBACServiceMock(t)
	defer cleanup()
	tenantID, roleID := uuid.New(), uuid.New()
	expectOwnership(mock, roleID, tenantID, true)

	m, err := svc.GetPermissionMatrix(tenantID, roleID)
	if err != nil {
		t.Fatalf("unexpected error for an owned role: %v", err)
	}
	if m == nil {
		t.Fatal("expected a matrix for an owned role")
	}
}
