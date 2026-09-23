package handlers

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/models"

	"github.com/gin-gonic/gin"
)

// roleResponse is the JSON shape returned for a platform role: the embedded
// PlatformRole fields plus its permission names and user count.
type roleResponse struct {
	models.PlatformRole
	Permissions []string `json:"permissions"`
	UserCount   int      `json:"user_count"`
}

func ListPlatformRoles(store platformRBACStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		rows, err := store.ListRoles()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch platform roles"})
			return
		}

		var roles []roleResponse
		for _, row := range rows {
			resp := roleResponse{PlatformRole: row.PlatformRole, UserCount: row.UserCount}

			// Fetch permissions for this role
			perms, err := store.RolePermissionNames(row.ID.String())
			if err != nil {
				resp.Permissions = []string{} // Default to empty array
			} else {
				resp.Permissions = perms
			}

			roles = append(roles, resp)
		}

		c.JSON(http.StatusOK, gin.H{"roles": roles})
	}
}

func GetPlatformRole(store platformRBACStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleID := c.Param("id")

		row, err := store.GetRole(roleID)
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Platform role not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch platform role"})
			return
		}

		resp := roleResponse{PlatformRole: row.PlatformRole, UserCount: row.UserCount}

		// Fetch permissions for this role
		perms, err := store.RolePermissionNames(roleID)
		if err != nil {
			resp.Permissions = []string{} // Default to empty array
		} else {
			resp.Permissions = perms
		}

		c.JSON(http.StatusOK, gin.H{"role": resp})
	}
}

func CreatePlatformRole(store platformRBACStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Name        string `json:"name" binding:"required"`
			DisplayName string `json:"display_name" binding:"required"`
			Description string `json:"description"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		roleID, _, _, err := store.CreateRole(req.Name, req.DisplayName, req.Description)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create platform role"})
			return
		}

		recordPlatformAudit(c, PlatformAuditEntry{
			EventType:     "platform_role.created",
			Action:        "create",
			EventCategory: "system",
			ResourceType:  "platform_role",
			ResourceID:    roleID,
			Metadata: map[string]interface{}{
				"name":         req.Name,
				"display_name": req.DisplayName,
			},
		})

		c.JSON(http.StatusCreated, gin.H{
			"message": "Platform role created successfully",
			"role_id": roleID,
		})
	}
}

// UpdatePlatformRole renames a role or edits its description. It is gated like
// every other role edit (authorizeRoleEdit): the caller must hold every
// permission of the role, and only a super_admin may change a system role's
// display name — the name is what operators read when they pick a role to
// grant, so relabelling "Super Administrator" is a way to mislead them.
func UpdatePlatformRole(store platformRBACStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleUUID, ok := parseRoleIDParam(c)
		if !ok {
			return
		}
		roleID := roleUUID.String()

		var req struct {
			DisplayName *string `json:"display_name"`
			Description *string `json:"description"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		if req.DisplayName == nil && req.Description == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No fields to update"})
			return
		}

		row, err := store.GetRole(roleID)
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Platform role not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch platform role"})
			return
		}
		// Re-sending the current display name (an edit form sends every
		// field) is not a rename.
		renamesSystemRole := row.IsSystemRole && req.DisplayName != nil && *req.DisplayName != row.DisplayName
		if !authorizeRoleEdit(c, store, roleID, renamesSystemRole) {
			return
		}

		if err := store.UpdateRoleFields(roleID, req.DisplayName, req.Description); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update platform role"})
			return
		}

		recordPlatformAudit(c, PlatformAuditEntry{
			EventType:     "platform_role.updated",
			Action:        "update",
			EventCategory: "system",
			ResourceType:  "platform_role",
			ResourceID:    roleID,
		})

		c.JSON(http.StatusOK, gin.H{"message": "Platform role updated successfully"})
	}
}

// DeletePlatformRole deletes a custom role. System roles cannot be deleted, and
// the caller must hold every permission of the role (authorizeRoleEdit): a
// lesser operator does not delete a role that outranks them.
func DeletePlatformRole(store platformRBACStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleUUID, ok := parseRoleIDParam(c)
		if !ok {
			return
		}
		roleID := roleUUID.String()

		// Check if it's a system role
		isSystemRole, err := store.RoleIsSystem(roleID)
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Platform role not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch platform role"})
			return
		}

		if isSystemRole {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete system roles"})
			return
		}

		if !authorizeRoleEdit(c, store, roleID, false) {
			return
		}

		if err := store.DeleteRole(roleID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete platform role"})
			return
		}

		recordPlatformAudit(c, PlatformAuditEntry{
			EventType:     "platform_role.deleted",
			Action:        "delete",
			EventCategory: "system",
			ResourceType:  "platform_role",
			ResourceID:    roleID,
		})

		c.JSON(http.StatusOK, gin.H{"message": "Platform role deleted successfully"})
	}
}

// SetPlatformRolePermissions replaces a role's permission set. System roles are
// immutable: an attempt to modify one is rejected with 403. An empty
// permission_ids array clears all permissions. On success it returns 200 with
// the role's resulting permission ids.
func SetPlatformRolePermissions(store platformRBACStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleUUID, ok := parseRoleIDParam(c)
		if !ok {
			return
		}
		roleID := roleUUID.String()

		var req struct {
			PermissionIDs []string `json:"permission_ids"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		// The escalation check and the write must see the SAME ids. Postgres
		// accepts many spellings of one uuid (upper case, braces, no hyphens);
		// canonicalizing here — and rejecting anything that is not a uuid — is
		// what stops a spelling the check does not match from being written.
		// Duplicates collapse too, rather than failing the insert's primary key.
		permissionIDs, err := canonicalUUIDs(req.PermissionIDs)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid permission id: every permission_ids entry must be a UUID"})
			return
		}

		// System roles are immutable.
		isSystemRole, err := store.RoleIsSystem(roleID)
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Platform role not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch platform role"})
			return
		}
		if isSystemRole {
			c.JSON(http.StatusForbidden, gin.H{"error": "System role permissions cannot be modified"})
			return
		}

		if !authorizeRolePermissionEdit(c, store, roleUUID, permissionIDs) {
			return
		}

		if err := store.SetRolePermissions(roleID, permissionIDs); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update platform role permissions"})
			return
		}

		recordPlatformAudit(c, PlatformAuditEntry{
			EventType:     "platform_role.permissions_set",
			Action:        "set_permissions",
			EventCategory: "system",
			ResourceType:  "platform_role",
			ResourceID:    roleID,
			Metadata: map[string]interface{}{
				"permission_ids":   permissionIDs,
				"permission_count": len(permissionIDs),
			},
		})

		c.JSON(http.StatusOK, gin.H{"permission_ids": permissionIDs})
	}
}

// authorizeRolePermissionEdit stops platform_roles.manage from being a way
// around platform_roles.assign. Without it, an operator who may edit roles but
// not grant them could add super_admin's permissions to their own (custom)
// role, or to a role they then hand out, and escalate that way.
//
// The rules mirror role assignment (platform_role_assignment.go):
//
//   - you may not edit the permissions of your OWN role;
//   - you may only edit a role whose CURRENT permissions you all hold — a
//     lesser operator does not strip a role that outranks them;
//   - the new permission set must be within your own permissions.
//
// super_admin holds every permission, so the subset rules never stop it, and
// its own role is a system role the check above this one already refuses.
// On denial it writes the response (401/403/500) and returns false.
func authorizeRolePermissionEdit(c *gin.Context, store platformRBACStore, roleID uuid.UUID, permissionIDs []string) bool {
	caller, err := uuid.Parse(c.GetString("userID"))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Editing a platform role requires an authenticated platform user"})
		return false
	}

	callerRole, err := store.PlatformUserRole(caller.String())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify role"})
		return false
	}
	// Compared as uuid values, not strings, so no spelling of the id differs.
	if callerRole.RoleID != nil && *callerRole.RoleID == roleID {
		c.JSON(http.StatusForbidden, gin.H{"error": "You cannot change the permissions of your own role. Ask another administrator."})
		return false
	}

	missing, err := store.RolePermissionsNotHeldBy(caller.String(), roleID.String())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify role"})
		return false
	}
	if len(missing) > 0 {
		c.JSON(http.StatusForbidden, gin.H{
			"error":               "You cannot edit a role that holds permissions you do not have",
			"missing_permissions": missing,
		})
		return false
	}

	missing, err = store.PermissionsNotHeldBy(caller.String(), permissionIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify permissions"})
		return false
	}
	if len(missing) > 0 {
		c.JSON(http.StatusForbidden, gin.H{
			"error":               "You cannot grant permissions you do not hold",
			"missing_permissions": missing,
		})
		return false
	}
	return true
}

// authorizeRoleEdit gates renaming and deleting a role (PUT and DELETE
// /admin/roles/:id) by the same rank rule as editing its permissions: the
// caller must hold every permission the role grants — a lesser operator does
// not relabel or remove a role that outranks them. super_admin holds every
// permission, so the rule never stops it. renamesSystemRole additionally
// requires the caller to BE a super_admin. On denial it writes the response
// (401/403/500) and returns false.
func authorizeRoleEdit(c *gin.Context, store platformRBACStore, roleID string, renamesSystemRole bool) bool {
	caller, err := uuid.Parse(c.GetString("userID"))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Editing a platform role requires an authenticated platform user"})
		return false
	}

	missing, err := store.RolePermissionsNotHeldBy(caller.String(), roleID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify role"})
		return false
	}
	if len(missing) > 0 {
		c.JSON(http.StatusForbidden, gin.H{
			"error":               "You cannot edit a role that holds permissions you do not have",
			"missing_permissions": missing,
		})
		return false
	}

	if renamesSystemRole {
		ref, err := store.PlatformUserRole(caller.String())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify role"})
			return false
		}
		if ref.RoleName != superAdminRoleName {
			c.JSON(http.StatusForbidden, gin.H{"error": "Only a super administrator can rename a system role"})
			return false
		}
	}
	return true
}

// parseRoleIDParam reads the :id path parameter as a uuid. On failure it
// writes a 400 and returns ok=false. Handlers pass the canonical String() on,
// so the id every check sees is the id every write uses.
func parseRoleIDParam(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role ID"})
		return uuid.Nil, false
	}
	return id, true
}

// canonicalUUIDs parses every id with uuid.Parse and returns the canonical
// (lower-case, hyphenated) spellings, de-duplicated in first-seen order. Any
// id that does not parse fails the whole list. A nil or empty input returns
// an empty, non-nil slice, so "clear all" is explicit downstream.
func canonicalUUIDs(ids []string) ([]string, error) {
	out := make([]string, 0, len(ids))
	seen := make(map[uuid.UUID]bool, len(ids))
	for _, raw := range ids {
		id, err := uuid.Parse(raw)
		if err != nil {
			return nil, err
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id.String())
	}
	return out, nil
}

func ListPlatformPermissions(store platformRBACStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		permissions, err := store.ListPermissions()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch platform permissions"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"permissions": permissions})
	}
}

func GetPlatformPermission(store platformRBACStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		permissionID := c.Param("id")

		permission, err := store.GetPermission(permissionID)
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Platform permission not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch platform permission"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"permission": permission})
	}
}

func GetCurrentUserPermissions(provider userPermissionProvider) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user ID from context (set by auth middleware)
		userIDStr, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in context"})
			return
		}

		userIDString, ok := userIDStr.(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID format"})
			return
		}

		userID, err := uuid.Parse(userIDString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID format"})
			return
		}

		permissions, err := provider.GetPlatformUserPermissions(userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user permissions"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"permissions": permissions})
	}
}
