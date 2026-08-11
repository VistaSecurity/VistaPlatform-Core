package rbac

// Store interface for the RBAC HTTP handlers.
//
// Introduced for the spec-first API contract pilot — `RBACHandlers.GetCurrentUserPermissions`
// is one of the three cross-cutters the contract test exercises (see
// `services/auth-service/internal/api/cross_cutter_contract_test.go`).
// Depending on a small interface (rather than `*RBACService`) lets the
// handler be exercised with an in-memory stub — no database required.
//
// Production wiring through `router.go` (and ultimately `cmd/main.go`) is
// untouched: `*RBACService` satisfies this interface implicitly.
//
// The interface is the **union** of every method any handler in `handlers.go`
// calls — including the out-of-scope handlers (GetTenantRoles /
// GetTenantPermissions / GetUserRoles / GetUserPermissions / AssignUserRole /
// RemoveUserRole / GetPermissionMatrix / UpdateRolePermissions /
// CheckPermission). Listing them keeps `handlers.go` compilable without a
// concrete-service field; the contract-test stub fills in no-op returns for
// the methods this slice does not exercise. Same pattern as
// compliance-engine's `frameworkLicenseStore`.

import (
	"github.com/google/uuid"
)

// NewRBACHandlersWithStore is a test-only constructor that builds an
// `*RBACHandlers` from any rbacStore implementation (typically the
// in-memory stub used by the cross-cutter contract test in the api
// package). Production callers MUST use `NewRBACHandlers(*RBACService)`
// instead — this constructor exists solely to keep the contract test
// independent of a live database.
func NewRBACHandlersWithStore(store rbacStore) *RBACHandlers {
	return &RBACHandlers{rbacService: store}
}

// rbacStore is the persistence surface that `RBACHandlers` needs.
//
// In scope for this slice (used by `GetCurrentUserPermissions`):
//   - GetUserPermissions
//
// Out of scope but referenced elsewhere in handlers.go.
type rbacStore interface {
	// In scope.
	GetUserPermissions(tenantID, userID uuid.UUID) ([]Permission, error)

	// Out of scope but referenced.
	GetTenantRoles(tenantID uuid.UUID) ([]Role, error)
	GetTenantPermissions(tenantID uuid.UUID) ([]Permission, error)
	GetUserRoles(tenantID, userID uuid.UUID) ([]Role, error)
	AssignUserRole(tenantID, userID, roleID uuid.UUID) error
	RemoveUserRole(tenantID, userID, roleID uuid.UUID) error
	GetPermissionMatrix(tenantID, roleID uuid.UUID) (interface{}, error)
	UpdateRolePermissions(tenantID, roleID uuid.UUID, permissionIDs []uuid.UUID) error
	CheckPermission(tenantID, userID uuid.UUID, permission string) (bool, error)
}
