package rbac

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// RequirePlatformPermission requires one platform permission, resolved through
// platform_user_has_permission(). It is middleware.RequirePlatformAdmin — the
// single implementation of the platform permission gate — with the HMAC
// internal-call bypass in front of it.
//
// HMAC-verified internal service calls already cleared the trust boundary in
// RequireJWTAuth and carry the "system" userID sentinel rather than a real user
// UUID, so the per-user check does not apply to them (parsing "system" as a
// UUID would otherwise fail with "Invalid user ID format").
//
// Must be used after authentication middleware that sets userID and userType.
func RequirePlatformPermission(db *sql.DB, permission string) gin.HandlerFunc {
	gate := middleware.RequirePlatformAdmin(db, permission)

	return func(c *gin.Context) {
		if middleware.IsInternalCall(c) {
			c.Next()
			return
		}
		gate(c)
	}
}

// RequireAnyPlatformPermission creates middleware that requires any of the specified platform permissions
func RequireAnyPlatformPermission(db *sql.DB, permissions ...string) gin.HandlerFunc {
	rbacService := rbac.NewRBACService(db)

	return func(c *gin.Context) {
		// HMAC-verified internal service calls bypass per-user RBAC (see
		// RequirePlatformPermission for rationale).
		if middleware.IsInternalCall(c) {
			c.Next()
			return
		}

		if middleware.GetUserType(c) != middleware.UserTypePlatform {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Platform user required",
			})
			c.Abort()
			return
		}

		// Get user ID from context
		userIDVal, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "User ID not found in context. Authentication required.",
			})
			c.Abort()
			return
		}

		// Parse user ID
		var userID uuid.UUID
		var err error
		switch v := userIDVal.(type) {
		case string:
			userID, err = uuid.Parse(v)
			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": "Invalid user ID format",
				})
				c.Abort()
				return
			}
		case uuid.UUID:
			userID = v
		default:
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid user ID type",
			})
			c.Abort()
			return
		}

		// Check if user has any of the required permissions
		hasPermission := false
		for _, permission := range permissions {
			hasPerm, err := rbacService.CheckPlatformPermission(userID, permission)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to check platform permission",
				})
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
				"error":                "Insufficient platform permissions",
				"required_permissions": permissions,
			})
			c.Abort()
			return
		}

		// PAT scope narrowing: require at least one of the permissions to
		// be within the token's scope (always true for normal/unscoped tokens).
		scopeOK := false
		for _, permission := range permissions {
			if middleware.PermissionWithinTokenScope(c, permission) {
				scopeOK = true
				break
			}
		}
		if !scopeOK {
			c.JSON(http.StatusForbidden, gin.H{
				"error":                "Permission outside token scope",
				"required_permissions": permissions,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
