package api

import (
	"database/sql"
	"net/http"

	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	audithelpers "github.com/vistasecurity/vistaplatform/shared/middleware/audit"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// UpdateTenantMemberStatusRequest is the JSON body for
// PUT /tenant/:tenantId/users/:userId/status (web-ui Settings → Users).
// The web-ui sends { "status": "active" | "suspended" }. The users table has
// no dedicated status column — membership status is the is_active boolean — so
// status values map onto is_active: active -> true, inactive/suspended -> false.
type UpdateTenantMemberStatusRequest struct {
	Status string `json:"status" binding:"required"`
}

// statusToIsActive validates an incoming status value against the allowed set
// and maps it to the users.is_active boolean. The allowed set mirrors what the
// web-ui sends (active/suspended) plus inactive for symmetry with the flat
// UpdateUser surface (which toggles is_active directly).
func statusToIsActive(status string) (bool, bool) {
	switch status {
	case "active":
		return true, true
	case "inactive", "suspended":
		return false, true
	default:
		return false, false
	}
}

// DeleteTenantMember handles DELETE /tenant/:tenantId/users/:userId — soft
// deletes a member of the given tenant. It mirrors the flat DeleteUser handler
// but derives the tenant from the path (with the same token-tenant-access check
// used by ListTenantUsers / InviteTenantMember) and verifies the target user
// belongs to :tenantId before mutating, preventing cross-tenant deletion.
func DeleteTenantMember(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
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

		currentUserIDStr := c.GetString("userID")
		currentUserID, _ := uuid.Parse(currentUserIDStr)

		// Prevent self-deletion
		if userID == currentUserID {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete yourself"})
			return
		}

		// Verify the target user belongs to this tenant before mutating.
		// RLS-scoped: users carries a tenant_isolation policy; tenant from path.
		var isActive bool
		verifyQuery := `SELECT is_active FROM users WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`
		err = shareddatabase.WithTenantTx(c.Request.Context(), db, tenantID, func(tx *sql.Tx) error {
			return tx.QueryRowContext(c.Request.Context(), verifyQuery, userID, tenantID).Scan(&isActive)
		})
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		if err != nil {
			logrus.WithError(err).WithField("user_id", userID).Error("Failed to verify user for deletion")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify user"})
			return
		}

		// Prevent deletion of the last admin in the tenant.
		userRole := getUserRole(db, userID, tenantID)
		isAdminRole := userRole == "tenant_admin" || userRole == "billing_admin"
		if isAdminRole && isActive {
			adminCount, countErr := countTenantAdmins(db, tenantID)
			if countErr == nil && adminCount <= 1 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete last admin in tenant"})
				return
			}
		}

		// Soft delete.
		// RLS-scoped write over users (tenant_isolation policy); tenant from path.
		deleteQuery := `
			UPDATE users
			SET deleted_at = NOW(), updated_at = NOW()
			WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		`
		var rowsAffected int64
		err = shareddatabase.WithTenantTx(c.Request.Context(), db, tenantID, func(tx *sql.Tx) error {
			result, e := tx.ExecContext(c.Request.Context(), deleteQuery, userID, tenantID)
			if e != nil {
				return e
			}
			rowsAffected, e = result.RowsAffected()
			return e
		})
		if err != nil {
			logrus.WithError(err).WithField("user_id", userID).Error("Failed to delete user")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
			return
		}
		if rowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		if rawMW, exists := c.Get("audit_middleware"); exists {
			if mw, ok := rawMW.(*audithelpers.Middleware); ok {
				_ = audithelpers.LogSimple(c.Request.Context(), mw,
					"user.deleted", "user", "delete",
					"user", userID.String(), "", true, "")
			}
		}

		c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
	}
}

// UpdateTenantMemberStatus handles PUT /tenant/:tenantId/users/:userId/status —
// activates/deactivates (suspends) a member of the given tenant. It applies the
// same token-tenant-access check as the sibling tenant-users routes and verifies
// the target user belongs to :tenantId before mutating.
func UpdateTenantMemberStatus(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
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

		var req UpdateTenantMemberStatusRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		isActive, valid := statusToIsActive(req.Status)
		if !valid {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid status", "details": req.Status})
			return
		}

		currentUserIDStr := c.GetString("userID")
		currentUserID, _ := uuid.Parse(currentUserIDStr)

		// Prevent self-deactivation (mirrors the flat UpdateUser safety check).
		if !isActive && userID == currentUserID {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot deactivate yourself"})
			return
		}

		// Verify the target user belongs to this tenant before mutating.
		// RLS-scoped: users carries a tenant_isolation policy; tenant from path.
		var existingIsActive bool
		verifyQuery := `SELECT is_active FROM users WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`
		err = shareddatabase.WithTenantTx(c.Request.Context(), db, tenantID, func(tx *sql.Tx) error {
			return tx.QueryRowContext(c.Request.Context(), verifyQuery, userID, tenantID).Scan(&existingIsActive)
		})
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		if err != nil {
			logrus.WithError(err).WithField("user_id", userID).Error("Failed to verify user")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify user"})
			return
		}

		// Prevent deactivating the last admin in the tenant.
		if !isActive {
			userRole := getUserRole(db, userID, tenantID)
			isAdminRole := userRole == "tenant_admin" || userRole == "billing_admin"
			if isAdminRole && existingIsActive {
				adminCount, countErr := countTenantAdmins(db, tenantID)
				if countErr == nil && adminCount <= 1 {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot deactivate last admin in tenant"})
					return
				}
			}
		}

		// RLS-scoped write over users (tenant_isolation policy); tenant from path.
		var user TenantUser
		updateQuery := `
			UPDATE users
			SET is_active = $1, updated_at = NOW()
			WHERE id = $2 AND tenant_id = $3 AND deleted_at IS NULL
			RETURNING id, tenant_id, email, first_name, last_name,
			          is_active, email_verified, last_login_at, created_at, updated_at
		`
		err = shareddatabase.WithTenantTx(c.Request.Context(), db, tenantID, func(tx *sql.Tx) error {
			return tx.QueryRowContext(c.Request.Context(), updateQuery, isActive, userID, tenantID).Scan(
				&user.ID, &user.TenantID, &user.Email, &user.FirstName, &user.LastName,
				&user.IsActive, &user.EmailVerified, &user.LastLoginAt,
				&user.CreatedAt, &user.UpdatedAt,
			)
		})
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		if err != nil {
			logrus.WithError(err).WithField("user_id", userID).Error("Failed to update user status")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user status"})
			return
		}

		// Populate role from RBAC system (consistent with sibling handlers).
		user.Role = getUserRole(db, userID, tenantID)

		if rawMW, exists := c.Get("audit_middleware"); exists {
			if mw, ok := rawMW.(*audithelpers.Middleware); ok {
				oldValues := map[string]interface{}{"is_active": existingIsActive}
				newValues := map[string]interface{}{"is_active": user.IsActive}
				_ = audithelpers.LogWithContext(c.Request.Context(), mw,
					"user.updated", "user", "update",
					"user", userID.String(), user.Email,
					oldValues, newValues,
					audithelpers.AuditMetadata{ResourceName: user.Email})
			}
		}

		c.JSON(http.StatusOK, gin.H{"user": user})
	}
}

// requireTenantPathAccess parses the :tenantId path param and enforces the same
// token-tenant-access check the other /tenant/:tenantId/* routes use: the
// authenticated caller's token tenant (set by RequireAuth) must match the path
// tenant. It writes the appropriate error response and returns ok=false when the
// check fails, so callers can early-return. This is the verbatim check from
// ListTenantUsers / InviteTenantMember, factored out so the mutation handlers
// inherit identical behavior.
func requireTenantPathAccess(c *gin.Context) (uuid.UUID, bool) {
	tenantIDStr := c.Param("tenantId")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return uuid.Nil, false
	}

	userTenantIDStr := c.GetString("tenantID")
	if userTenantIDStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found in token"})
		return uuid.Nil, false
	}

	userTenantID, err := uuid.Parse(userTenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID in token"})
		return uuid.Nil, false
	}

	if userTenantID != tenantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to this tenant"})
		return uuid.Nil, false
	}

	return tenantID, true
}
