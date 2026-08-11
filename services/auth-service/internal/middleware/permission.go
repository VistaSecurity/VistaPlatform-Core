package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	rbacsvc "github.com/vistasecurity/vistaplatform/auth-service/internal/rbac"
)

// RequirePermission ensures the authenticated user has a specific tenant permission
func RequirePermission(rbacService *rbacsvc.RBACService, permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDStr, ok := c.Get("userID")
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in context"})
			c.Abort()
			return
		}
		tenantIDStr, ok := c.Get("tenantID")
		if !ok {
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

		has, err := rbacService.CheckPermission(tenantID, userID, permission)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check permission"})
			c.Abort()
			return
		}
		if !has {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions", "required_permission": permission})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAnyPermission ensures the user has at least one of the provided permissions
func RequireAnyPermission(rbacService *rbacsvc.RBACService, permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDStr, ok := c.Get("userID")
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in context"})
			c.Abort()
			return
		}
		tenantIDStr, ok := c.Get("tenantID")
		if !ok {
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

		for _, p := range permissions {
			has, err := rbacService.CheckPermission(tenantID, userID, p)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check permission"})
				c.Abort()
				return
			}
			if has {
				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions", "required_any": strings.Join(permissions, ", ")})
		c.Abort()
	}
}

// RequirePlatformPermission checks platform-level permissions using RBAC
// Note: This requires the shared RBAC service to be available
// For auth-service, platform permissions should be checked at the service level
// This is kept for compatibility but should use shared/rbac middleware in production
func RequirePlatformPermission(rbacService interface {
	CheckPlatformPermission(userID uuid.UUID, permission string) (bool, error)
}, permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Defense in depth: HMAC-verified internal service calls carry the
		// "system" userID sentinel (not a UUID). Skip the per-user permission
		// check for them so uuid.Parse below never rejects a legitimately
		// authenticated internal call. Consistent with shared/middleware/rbac.
		if v, ok := c.Get("isInternalCall"); ok {
			if isInternal, _ := v.(bool); isInternal {
				c.Next()
				return
			}
		}

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

		hasPermission, err := rbacService.CheckPlatformPermission(userID, permission)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check platform permission"})
			c.Abort()
			return
		}

		if !hasPermission {
			c.JSON(http.StatusForbidden, gin.H{
				"error":               "Insufficient platform permissions",
				"required_permission": permission,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
