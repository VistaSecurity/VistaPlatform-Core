package handlers

import (
	"database/sql"
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

func UpdatePlatformRole(store platformRBACStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleID := c.Param("id")

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

func DeletePlatformRole(store platformRBACStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleID := c.Param("id")

		// Check if it's a system role
		isSystemRole, err := store.RoleIsSystem(roleID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Platform role not found"})
			return
		}

		if isSystemRole {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete system roles"})
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
		roleID := c.Param("id")

		var req struct {
			PermissionIDs []string `json:"permission_ids"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
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

		// Normalize a nil slice to an empty one so "clear all" is explicit.
		permissionIDs := req.PermissionIDs
		if permissionIDs == nil {
			permissionIDs = []string{}
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
