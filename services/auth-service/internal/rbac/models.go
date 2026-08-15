package rbac

import (
	"time"

	"github.com/google/uuid"
)

// Role represents a user role.
//
// DisplayName / IsSystemRole / PermissionCount / UserCount were added with
// tenant role CRUD: the Roles & Permissions screen needs to know which roles are
// built-in (read-only) and how many grants/holders each has. `Permissions` is the
// legacy embedded map — it has never been populated by any query and is retained
// only so the response shape stays backward compatible; use `PermissionCount`
// here and the matrix endpoint for the actual grants.
type Role struct {
	ID              uuid.UUID              `json:"id"`
	Name            string                 `json:"name"`
	DisplayName     string                 `json:"display_name"`
	Description     string                 `json:"description"`
	IsSystemRole    bool                   `json:"is_system_role"`
	PermissionCount int                    `json:"permission_count"`
	UserCount       int                    `json:"user_count"`
	Permissions     map[string]interface{} `json:"permissions"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

// Permission represents a permission
type Permission struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Resource    string    `json:"resource"`
	Action      string    `json:"action"`
}

// PermissionCheckRequest represents a permission check request
type PermissionCheckRequest struct {
	Permission string `json:"permission" binding:"required"`
}

// PermissionCheckResponse represents a permission check response
type PermissionCheckResponse struct {
	HasPermission bool `json:"has_permission"`
}

// RoleAssignmentRequest represents a role assignment request
type RoleAssignmentRequest struct {
	RoleID uuid.UUID `json:"role_id" binding:"required"`
}

// MatrixPermission is one row of a role's permission matrix: a catalogue entry
// plus whether this role currently grants it, and whether the calling user is
// allowed to turn it on.
//
// `Grantable` is false when the caller does not personally hold the permission.
// The caller may still leave an already-granted permission checked (the
// escalation guard only applies to permissions being ADDED), which is why
// `Granted` and `Grantable` are independent flags rather than one "editable"
// bit. A UI renders `granted && !grantable` as checked-but-locked.
type MatrixPermission struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Resource    string    `json:"resource"`
	Action      string    `json:"action"`
	Granted     bool      `json:"granted"`
	Grantable   bool      `json:"grantable"`
}

// PermissionMatrix is the full tenant permission catalogue annotated for one
// role — everything a matrix UI needs in a single response. `Permissions` is the
// WHOLE catalogue (not just the grants), ordered by resource then action, so the
// UI never has to join two endpoints to draw a checkbox grid.
type PermissionMatrix struct {
	RoleID       uuid.UUID `json:"role_id"`
	RoleName     string    `json:"role_name"`
	DisplayName  string    `json:"display_name"`
	Description  string    `json:"description"`
	IsSystemRole bool      `json:"is_system_role"`
	// Editable is false for system roles: their grants are re-asserted by the
	// seed reconciliation on every helm upgrade, so accepting an edit would be
	// a lie. A UI renders the whole matrix read-only when this is false.
	Editable    bool               `json:"editable"`
	Permissions []MatrixPermission `json:"permissions"`
	// GrantedPermissionIDs is the current grant set, for convenience — the same
	// information as the `granted` flags above.
	GrantedPermissionIDs []uuid.UUID `json:"granted_permission_ids"`
}

// CreateRoleRequest is the body of POST /tenant/:tenantId/roles.
//
// `name` is the stable internal slug (unique per tenant). It is optional: when
// omitted it is derived from display_name. It cannot be changed afterwards.
type CreateRoleRequest struct {
	Name          string   `json:"name"`
	DisplayName   string   `json:"display_name" binding:"required"`
	Description   string   `json:"description"`
	PermissionIDs []string `json:"permission_ids"`
}

// DeleteRoleResult reports what a role deletion actually did, so the response
// can be explicit about holder reassignment rather than leaving the caller to
// guess whether anyone lost access.
type DeleteRoleResult struct {
	RoleID           uuid.UUID  `json:"role_id"`
	ReassignedUsers  int        `json:"reassigned_users"`
	ReassignedToID   *uuid.UUID `json:"reassigned_to_role_id"`
	ReassignedToName string     `json:"reassigned_to_role_name,omitempty"`
}
