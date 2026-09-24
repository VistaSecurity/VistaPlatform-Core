package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// RBACMiddleware creates middleware for permission-based access control
type RBACMiddleware struct {
	rbacService *rbac.RBACService
}

// NewRBACMiddleware creates a new RBAC middleware
func NewRBACMiddleware(rbacService *rbac.RBACService) *RBACMiddleware {
	return &RBACMiddleware{
		rbacService: rbacService,
	}
}

// RequirePlatformPermission creates middleware that requires a specific platform permission
func (m *RBACMiddleware) RequirePlatformPermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Defense in depth: HMAC-verified internal service calls carry the
		// "system" userID sentinel, which is not a UUID. Skip the per-user
		// permission check for them so the uuid.Parse below never rejects a
		// legitimately authenticated internal call with "Invalid user ID format".
		// (admin-service does not accept internal calls today, but this keeps the
		// local RBAC copy consistent with shared/middleware/rbac.)
		if v, ok := c.Get("isInternalCall"); ok {
			if isInternal, _ := v.(bool); isInternal {
				c.Next()
				return
			}
		}

		// Get user ID from context (set by auth middleware)
		userIDStr, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in context"})
			c.Abort()
			return
		}

		userID, err := uuid.Parse(userIDStr.(string))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID format"})
			c.Abort()
			return
		}

		// Check platform permission
		hasPermission, err := m.rbacService.CheckPlatformPermission(userID, permission)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check permission"})
			c.Abort()
			return
		}

		if !hasPermission {
			c.JSON(http.StatusForbidden, gin.H{
				"error":               "Insufficient permissions",
				"required_permission": permission,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAnyPlatformPermission creates middleware that requires any of the specified platform permissions
func (m *RBACMiddleware) RequireAnyPlatformPermission(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Defense in depth: internal service calls bypass per-user RBAC (see
		// RequirePlatformPermission).
		if v, ok := c.Get("isInternalCall"); ok {
			if isInternal, _ := v.(bool); isInternal {
				c.Next()
				return
			}
		}

		// Get user ID from context
		userIDStr, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in context"})
			c.Abort()
			return
		}

		userID, err := uuid.Parse(userIDStr.(string))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID format"})
			c.Abort()
			return
		}

		// Check if user has any of the required permissions
		hasPermission := false
		for _, permission := range permissions {
			hasPerm, err := m.rbacService.CheckPlatformPermission(userID, permission)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check permission"})
				c.Abort()
				return
			}
			if hasPerm {
				hasPermission = true
				break
			}
		}

		if !hasPermission {
			c.JSON(http.StatusForbidden, gin.H{
				"error":                "Insufficient permissions",
				"required_permissions": permissions,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireTenantPermission creates middleware that requires a specific tenant permission
func (m *RBACMiddleware) RequireTenantPermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Defense in depth: internal service calls bypass per-user RBAC (see
		// RequirePlatformPermission).
		if v, ok := c.Get("isInternalCall"); ok {
			if isInternal, _ := v.(bool); isInternal {
				c.Next()
				return
			}
		}

		// Get user ID and tenant ID from context
		userIDStr, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in context"})
			c.Abort()
			return
		}

		tenantIDStr, exists := c.Get("tenantID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found in context"})
			c.Abort()
			return
		}

		userID, err := uuid.Parse(userIDStr.(string))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID format"})
			c.Abort()
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr.(string))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid tenant ID format"})
			c.Abort()
			return
		}

		// Check tenant permission
		hasPermission, err := m.rbacService.CheckPermission(userID, tenantID, permission)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check permission"})
			c.Abort()
			return
		}

		if !hasPermission {
			c.JSON(http.StatusForbidden, gin.H{
				"error":               "Insufficient permissions",
				"required_permission": permission,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
