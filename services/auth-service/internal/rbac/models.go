package rbac

import (
	"time"

	"github.com/google/uuid"
)

// Role represents a user role
type Role struct {
	ID          uuid.UUID              `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Permissions map[string]interface{} `json:"permissions"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
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

// PermissionMatrix represents a role's permission matrix
type PermissionMatrix struct {
	RoleID      uuid.UUID    `json:"role_id"`
	Permissions []Permission `json:"permissions"`
}
