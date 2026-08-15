package rbac

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	audithelpers "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
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

// actorID returns the authenticated user's id (set by RequireAuth). The role
// write paths need it for the escalation guard — a caller may only ADD
// permissions they themselves hold.
func actorID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.GetString("userID"))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in context"})
		return uuid.Nil, false
	}
	return id, true
}

// writeRoleError maps the service's typed refusals onto HTTP. Every branch is a
// deliberate, distinguishable answer so a UI can react (disable a checkbox, open
// a reassignment picker) instead of showing a generic failure.
//
// Returns false when err is not one of the known refusals, leaving the caller to
// emit its own 500.
func writeRoleError(c *gin.Context, err error) bool {
	var unknownPerms *ErrUnknownPermissions
	var notHeld *ErrPermissionNotHeld
	var inUse *ErrRoleInUse

	switch {
	case errors.Is(err, ErrRoleNotInTenant):
		c.JSON(http.StatusNotFound, gin.H{"error": "Role not found", "code": "role_not_found"})
	case errors.Is(err, ErrSystemRoleImmutable):
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Built-in roles are read-only — their permissions are re-applied on every platform upgrade",
			"code":  "system_role_immutable",
		})
	case errors.Is(err, ErrRoleNameConflict):
		c.JSON(http.StatusConflict, gin.H{"error": "A role with that name already exists", "code": "role_name_conflict"})
	case errors.Is(err, ErrInvalidRoleName):
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Role name must be lowercase letters, digits and underscores (2-50 chars)",
			"code":  "invalid_role_name",
		})
	case errors.Is(err, ErrInvalidPermissionID):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "invalid_permission_id"})
	case errors.Is(err, ErrReassignToSelf):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "reassign_to_self"})
	case errors.Is(err, ErrRoleReferencedBySSO):
		c.JSON(http.StatusConflict, gin.H{
			"error": "This role is used by SSO group mappings or as an SSO default role. Update the SSO configuration first.",
			"code":  "role_referenced_by_sso",
		})
	case errors.As(err, &unknownPerms):
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "One or more permission ids are not in the tenant permission catalogue",
			"code":  "unknown_permissions",
		})
	case errors.As(err, &notHeld):
		c.JSON(http.StatusForbidden, gin.H{
			"error":               "You can only grant permissions you hold yourself",
			"code":                "permission_not_held",
			"missing_permissions": notHeld.Names,
		})
	case errors.As(err, &inUse):
		c.JSON(http.StatusConflict, gin.H{
			"error":      "This role is still assigned to users",
			"code":       "role_in_use",
			"user_count": inUse.UserCount,
		})
	default:
		return false
	}
	return true
}

// logRoleAudit emits a tenant-role audit event. Best-effort, exactly like the
// sibling user mutations in internal/api/tenant_user_mutations.go: an audit
// transport failure must not fail the write the user just made.
func logRoleAudit(c *gin.Context, eventType, action string, roleID uuid.UUID, roleName string, metadata map[string]interface{}) {
	rawMW, exists := c.Get("audit_middleware")
	if !exists {
		return
	}
	mw, ok := rawMW.(*audithelpers.Middleware)
	if !ok {
		return
	}
	_ = audithelpers.LogWithContext(c.Request.Context(), mw,
		eventType, "user", action,
		"tenant_role", roleID.String(), roleName,
		nil, metadata,
		audithelpers.AuditMetadata{ResourceName: roleName})
}

// GetPermissionMatrix handles GET /tenant/:tenantId/roles/:roleId/matrix
func (h *RBACHandlers) GetPermissionMatrix(c *gin.Context) {
	// Cross-tenant guard: the :tenantId path must match the caller's
	// token tenant — the same protection the sibling role handlers enforce.
	tenantID, ok := requireTenantPathAccess(c)
	if !ok {
		return
	}
	actor, ok := actorID(c)
	if !ok {
		return
	}

	roleID, err := uuid.Parse(c.Param("roleId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role ID"})
		return
	}

	matrix, err := h.rbacService.GetPermissionMatrix(tenantID, roleID, actor)
	if err != nil {
		if writeRoleError(c, err) {
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
	actor, ok := actorID(c)
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

	if err := h.rbacService.UpdateRolePermissions(tenantID, roleID, actor, permissionUUIDs); err != nil {
		if writeRoleError(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update role permissions"})
		return
	}

	logRoleAudit(c, "tenant_role.permissions_set", "set_permissions", roleID, "", map[string]interface{}{
		"permission_ids":   req.PermissionIDs,
		"permission_count": len(permissionUUIDs),
	})

	c.JSON(http.StatusOK, gin.H{"role_id": roleID, "updated": len(permissionUUIDs)})
}

// CreateTenantRole handles POST /tenant/:tenantId/roles — creates a custom role
// (is_system_role = false) with an optional starting permission set.
func (h *RBACHandlers) CreateTenantRole(c *gin.Context) {
	tenantID, ok := requireTenantPathAccess(c)
	if !ok {
		return
	}
	actor, ok := actorID(c)
	if !ok {
		return
	}

	var req CreateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	role, err := h.rbacService.CreateTenantRole(tenantID, actor, req)
	if err != nil {
		if writeRoleError(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create role"})
		return
	}

	logRoleAudit(c, "tenant_role.created", "create", role.ID, role.Name, map[string]interface{}{
		"name":             role.Name,
		"display_name":     role.DisplayName,
		"permission_count": role.PermissionCount,
	})

	c.JSON(http.StatusCreated, gin.H{"role": role})
}

// DeleteTenantRole handles DELETE /tenant/:tenantId/roles/:roleId.
//
// Holders block the delete (409 `role_in_use`) unless `?reassign_to=<roleId>`
// names where they should go. See DeleteTenantRole in rbac.go for why the
// reassignment is opt-in rather than automatic.
func (h *RBACHandlers) DeleteTenantRole(c *gin.Context) {
	tenantID, ok := requireTenantPathAccess(c)
	if !ok {
		return
	}

	roleID, err := uuid.Parse(c.Param("roleId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role ID"})
		return
	}

	var reassignTo *uuid.UUID
	if raw := c.Query("reassign_to"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid reassign_to role ID"})
			return
		}
		reassignTo = &parsed
	}

	result, err := h.rbacService.DeleteTenantRole(tenantID, roleID, reassignTo)
	if err != nil {
		if writeRoleError(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete role"})
		return
	}

	logRoleAudit(c, "tenant_role.deleted", "delete", roleID, result.ReassignedToName, map[string]interface{}{
		"reassigned_users":      result.ReassignedUsers,
		"reassigned_to_role_id": result.ReassignedToID,
	})

	c.JSON(http.StatusOK, gin.H{
		"role_id":               result.RoleID,
		"reassigned_users":      result.ReassignedUsers,
		"reassigned_to_role_id": result.ReassignedToID,
		"message":               "Role deleted",
	})
}

// AssignRole handles POST /tenant/:tenantId/users/:userId/roles
func (h *RBACHandlers) AssignRole(c *gin.Context) {
	tenantID, ok := requireTenantPathAccess(c)
	if !ok {
		return
	}
	actor, ok := actorID(c)
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

	if err := h.rbacService.AssignUserRole(tenantID, userID, req.RoleID, actor); err != nil {
		if writeRoleError(c, err) {
			return
		}
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
