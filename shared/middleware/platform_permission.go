package middleware

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// platformPermissionQuery is the ONE question every platform gate asks. The
// function reads platform_users → platform_role_permissions → platform_permissions,
// so the answer is whatever Staff & Access ▸ Roles says the caller's role holds
// — not what the role is called.
const platformPermissionQuery = `SELECT platform_user_has_permission($1, $2)`

// RequirePlatformAdmin gates a route on ONE platform permission.
//
// It used to take no argument and switch on the JWT's role NAME, admitting
// super_admin, platform_admin and "support_admin" — a role that has never been
// seeded (the real one is support_agent). That made the permission matrix in
// Staff & Access ▸ Roles decorative for every service that used it: a custom
// role granted the right permission was refused, support_agent was refused
// routes its grants covered, and a role called platform_admin passed whatever
// its grants said. The caller now names the permission, and the answer comes
// from platform_user_has_permission() — the same function admin-service has
// always enforced through.
//
// Order of checks, each answering distinctly so a test can tell which one did:
//
//  1. a PLATFORM identity (userType=platform) — a tenant token is refused
//     whatever its role claim says (403 "Platform user required");
//  2. a parseable user id on the context (401);
//  3. platform_user_has_permission(user, permission) — 403
//     "Insufficient platform permissions" naming the permission, 500 when the
//     database cannot answer (fail closed);
// 4. a scope-narrowed token (read-only PAT) must carry the permission
//     in its scopes as well (403 "Permission outside token scope").
//
// There is deliberately NO bypass for HMAC internal calls here: the routes this
// guards are operator surfaces, and the old gate refused internal calls too.
// shared/middleware/rbac.RequirePlatformPermission is this same gate with the
// internal-call bypass in front of it, for routes that services call.
//
// A nil db yields a gate that answers 503 once identity is settled — the
// fail-closed answer for a service that cannot reach its RBAC store (a tenant
// token still gets the 403 above). An empty permission is a wiring
// bug and panics at construction, so it surfaces at startup rather than as a
// route that silently checks nothing.
func RequirePlatformAdmin(db *sql.DB, permission string) gin.HandlerFunc {
	if permission == "" {
		panic("middleware.RequirePlatformAdmin: permission must be named")
	}

	return func(c *gin.Context) {
		if GetUserType(c) != UserTypePlatform {
			c.JSON(http.StatusForbidden, gin.H{"error": "Platform user required"})
			c.Abort()
			return
		}

		userID, ok := platformUserID(c)
		if !ok {
			return // response already written
		}

		// Identity is decided without the database, so a tenant token is
		// refused as a tenant token even when the RBAC store is unreachable.
		if db == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "RBAC unavailable"})
			c.Abort()
			return
		}

		var has bool
		if err := db.QueryRowContext(c.Request.Context(), platformPermissionQuery, userID, permission).Scan(&has); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check platform permission"})
			c.Abort()
			return
		}
		if !has {
			c.JSON(http.StatusForbidden, gin.H{
				"error":               "Insufficient platform permissions",
				"required_permission": permission,
			})
			c.Abort()
			return
		}

		if !PermissionWithinTokenScope(c, permission) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":               "Permission outside token scope",
				"required_permission": permission,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// platformUserID reads the caller's id from the context, accepting both the
// uuid.UUID most services set and the string form StringifyUserID leaves
// behind. On failure it writes the 401 and aborts.
func platformUserID(c *gin.Context) (uuid.UUID, bool) {
	val, exists := c.Get(CtxKeyUserID)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in context. Authentication required."})
		c.Abort()
		return uuid.Nil, false
	}
	switch v := val.(type) {
	case uuid.UUID:
		return v, true
	case string:
		id, err := uuid.Parse(v)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID format"})
			c.Abort()
			return uuid.Nil, false
		}
		return id, true
	default:
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID type"})
		c.Abort()
		return uuid.Nil, false
	}
}
