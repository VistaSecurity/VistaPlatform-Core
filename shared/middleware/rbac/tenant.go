package rbac

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// RequireTenantPermission requires user_has_permission($user, $tenant, $permission)
// after JWT auth and tenant middleware have set userID and tenantID in context.
func RequireTenantPermission(db *sql.DB, permission string) gin.HandlerFunc {
	if db == nil {
		return func(c *gin.Context) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "RBAC unavailable"})
			c.Abort()
		}
	}

	svc := rbac.NewRBACService(db)

	return func(c *gin.Context) {
		// HMAC-verified internal service calls have already cleared the trust
		// boundary in RequireJWTAuth (they bypass JWT entirely). They carry the
		// "system" userID sentinel, not a real user UUID, so the per-user
		// permission check below does not apply — and attempting it would parse
		// "system" as a UUID and fail with "Invalid user ID format". Trust the
		// signature and let the request through; tenant scoping still flows from
		// the signed X-Tenant-ID header set on the context.
		if middleware.IsInternalCall(c) {
			c.Next()
			return
		}

		userIDVal, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in context. Authentication required."})
			c.Abort()
			return
		}
		tenantIDVal, exists := c.Get("tenantID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found in context"})
			c.Abort()
			return
		}

		var userID uuid.UUID
		var err error
		switch v := userIDVal.(type) {
		case string:
			userID, err = uuid.Parse(v)
			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID format"})
				c.Abort()
				return
			}
		case uuid.UUID:
			userID = v
		default:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID type"})
			c.Abort()
			return
		}

		var tenantID uuid.UUID
		switch v := tenantIDVal.(type) {
		case string:
			tenantID, err = uuid.Parse(v)
			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid tenant ID format"})
				c.Abort()
				return
			}
		case uuid.UUID:
			tenantID = v
		default:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid tenant ID type"})
			c.Abort()
			return
		}

		has, err := svc.CheckPermission(userID, tenantID, permission)
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

		// PAT scope narrowing: the user's role grants this permission, but
		// a scope-narrowed PAT token may not include it. Enforce the intersection
		// so a read-only PAT can't act with the user's full role.
		if !middleware.PermissionWithinTokenScope(c, permission) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Permission outside token scope", "required_permission": permission})
			c.Abort()
			return
		}

		c.Next()
	}
}
