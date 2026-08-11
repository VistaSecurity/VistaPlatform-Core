package rbac

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RBACHandlers handles RBAC HTTP requests.
//
// The `rbacService` field is typed as a small interface (`rbacStore`, defined
// in stores.go) rather than the concrete `*RBACService`. This is what makes
// the cross-cutter `GET /user/permissions` handler exercisable from
// `services/auth-service/internal/api/cross_cutter_contract_test.go` with an
// in-memory stub — no DB required. `*RBACService` satisfies the interface
// implicitly, so production wiring through `router.go` (and ultimately
// `cmd/main.go`) is untouched.
type RBACHandlers struct {
	rbacService rbacStore
}

// NewRBACHandlers creates new RBAC handlers.
// Production callers pass the concrete *RBACService; tests pass an in-memory
// stub that satisfies rbacStore.
func NewRBACHandlers(rbacService *RBACService) *RBACHandlers {
	return &RBACHandlers{
		rbacService: rbacService,
	}
}

// requireTenantPathAccess parses the :tenantId path param and enforces that the
// authenticated caller's token tenant (set by RequireAuth) matches it. Writes the
// error response and returns ok=false on failure so callers can early-return.
// This is the verbatim check AssignRole / RemoveRole already perform inline;
// factored out here so the read handlers inherit identical behavior.
func requireTenantPathAccess(c *gin.Context) (uuid.UUID, bool) {
	tenantID, err := uuid.Parse(c.Param("tenantId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return uuid.Nil, false
	}
	jwtTenantID, err := uuid.Parse(c.GetString("tenantID"))
	if err != nil || jwtTenantID != tenantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to this tenant"})
		return uuid.Nil, false
	}
	return tenantID, true
}

// GetTenantRoles handles GET /tenant/:tenantId/roles
func (h *RBACHandlers) GetTenantRoles(c *gin.Context) {
	tenantID, ok := requireTenantPathAccess(c)
	if !ok {
		return
	}

	roles, err := h.rbacService.GetTenantRoles(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant roles"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"roles": roles})
}

// GetTenantPermissions handles GET /permissions
func (h *RBACHandlers) GetTenantPermissions(c *gin.Context) {
	// Get tenant ID from context (set by middleware)
	tenantIDStr, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, err := uuid.Parse(tenantIDStr.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	permissions, err := h.rbacService.GetTenantPermissions(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant permissions"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"permissions": permissions})
}

// GetUserRoles handles GET /tenant/:tenantId/users/:userId/roles
func (h *RBACHandlers) GetUserRoles(c *gin.Context) {
	tenantID, ok := requireTenantPathAccess(c)
	if !ok {
		return
	}

	userIDStr := c.Param("userId")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	roles, err := h.rbacService.GetUserRoles(tenantID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user roles"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"roles": roles})
}

// GetUserPermissions handles GET /tenant/:tenantId/users/:userId/permissions
func (h *RBACHandlers) GetUserPermissions(c *gin.Context) {
	tenantID, ok := requireTenantPathAccess(c)
	if !ok {
		return
	}

	userIDStr := c.Param("userId")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	permissions, err := h.rbacService.GetUserPermissions(tenantID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user permissions"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"permissions": permissions})
}

// GetCurrentUserPermissions handles GET /permissions (for current user)
func (h *RBACHandlers) GetCurrentUserPermissions(c *gin.Context) {
	// Get user and tenant from context (set by RequireAuth middleware)
	userIDStr, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in context"})
		return
	}

	tenantIDStr, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found in context"})
		return
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	tenantID, err := uuid.Parse(tenantIDStr.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	permissions, err := h.rbacService.GetUserPermissions(tenantID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user permissions"})
		return
	}

	// Convert permissions to simple string array for frontend
	permissionNames := make([]string, len(permissions))
	for i, perm := range permissions {
		permissionNames[i] = perm.Name
	}

	c.JSON(http.StatusOK, gin.H{"permissions": permissionNames})
}

// CheckPermission handles POST /permissions/check
func (h *RBACHandlers) CheckPermission(c *gin.Context) {
	// Get tenant ID and user ID from context (set by middleware)
	tenantID, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}

	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		// Try to parse as string if it's not a UUID
		if tenantIDStr, okStr := tenantID.(string); okStr {
			var err error
			tenantUUID, err = uuid.Parse(tenantIDStr)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID format"})
				return
			}
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID type"})
			return
		}
	}

	userUUID, ok := userID.(uuid.UUID)
	if !ok {
		// Try to parse as string if it's not a UUID
		if userIDStr, okStr := userID.(string); okStr {
			var err error
			userUUID, err = uuid.Parse(userIDStr)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
				return
			}
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID type"})
			return
		}
	}

	var req PermissionCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	hasPermission, err := h.rbacService.CheckPermission(tenantUUID, userUUID, req.Permission)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check permission"})
		return
	}

	c.JSON(http.StatusOK, PermissionCheckResponse{HasPermission: hasPermission})
}

// GetPermissionMatrix handles GET /tenant/:tenantId/roles/:roleId/matrix
func (h *RBACHandlers) GetPermissionMatrix(c *gin.Context) {
	// Cross-tenant guard: the :tenantId path must match the caller's
	// token tenant — the same protection the sibling role handlers enforce.
	tenantID, ok := requireTenantPathAccess(c)
	if !ok {
		return
	}

	roleID, err := uuid.Parse(c.Param("roleId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role ID"})
		return
	}

	matrix, err := h.rbacService.GetPermissionMatrix(tenantID, roleID)
	if err != nil {
		if errors.Is(err, ErrRoleNotInTenant) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get permission matrix"})
		return
	}

	c.JSON(http.StatusOK, matrix)
}

// UpdateRolePermissions handles PUT /tenant/:tenantId/roles/:roleId/permissions
func (h *RBACHandlers) UpdateRolePermissions(c *gin.Context) {
	// Cross-tenant guard: the :tenantId path must match the caller's
	// token tenant before any role rewrite.
	tenantID, ok := requireTenantPathAccess(c)
	if !ok {
		return
	}

	roleID, err := uuid.Parse(c.Param("roleId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role ID"})
		return
	}

	var req struct {
		PermissionIDs []string `json:"permission_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Parse permission IDs from strings to UUIDs
	permissionUUIDs := make([]uuid.UUID, 0, len(req.PermissionIDs))
	for _, idStr := range req.PermissionIDs {
		id, err := uuid.Parse(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid permission_id format",
				"details": fmt.Sprintf("Invalid UUID: %s", idStr),
			})
			return
		}
		permissionUUIDs = append(permissionUUIDs, id)
	}

	if err := h.rbacService.UpdateRolePermissions(tenantID, roleID, permissionUUIDs); err != nil {
		if errors.Is(err, ErrRoleNotInTenant) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update role permissions"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"role_id": roleID, "updated": len(permissionUUIDs)})
}

// AssignRole handles POST /tenant/:tenantId/users/:userId/roles
func (h *RBACHandlers) AssignRole(c *gin.Context) {
	tenantID, ok := requireTenantPathAccess(c)
	if !ok {
		return
	}

	userIDStr := c.Param("userId")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var req RoleAssignmentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if err := h.rbacService.AssignUserRole(tenantID, userID, req.RoleID); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Role or user not found"})
			return
		}
		if strings.Contains(msg, "not in tenant") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "User not in tenant"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign role"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id": userID,
		"role_id": req.RoleID,
		"message": "Role assigned",
	})
}

// RemoveRole handles DELETE /tenant/:tenantId/users/:userId/roles/:roleId
func (h *RBACHandlers) RemoveRole(c *gin.Context) {
	tenantID, ok := requireTenantPathAccess(c)
	if !ok {
		return
	}

	userIDStr := c.Param("userId")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	roleIDStr := c.Param("roleId")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role ID"})
		return
	}

	if err := h.rbacService.RemoveUserRole(tenantID, userID, roleID); err != nil {
		if err.Error() == "active role assignment not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Active role assignment not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove role"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id": userID,
		"role_id": roleID,
		"message": "Role removed",
	})
}
