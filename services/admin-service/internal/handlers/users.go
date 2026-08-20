package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/api"
	passwordsvc "github.com/vistasecurity/vistaplatform/shared/security/password"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func ListPlatformUsers(db *sql.DB) gin.HandlerFunc {
	return listPlatformUsersWithStore(newPlatformUserRepository(db))
}

func listPlatformUsersWithStore(store platformUserStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		if page < 1 {
			page = 1
		}
		pageSizeStr := c.Query("page_size")
		if pageSizeStr == "" {
			pageSizeStr = c.DefaultQuery("limit", "20")
		}
		pageSize, _ := strconv.Atoi(pageSizeStr)
		if pageSize == 0 || pageSize > 100 {
			pageSize = 20
		}
		offset := (page - 1) * pageSize

		users, total, err := store.ListPlatformUsers(c.Request.Context(), platformUserListFilters{
			Search:    strings.TrimSpace(c.Query("search")),
			Role:      strings.TrimSpace(c.Query("role")),
			Status:    strings.TrimSpace(c.Query("status")),
			SortBy:    strings.TrimSpace(c.Query("sort_by")),
			SortOrder: strings.ToLower(strings.TrimSpace(c.Query("sort_order"))),
			PageSize:  pageSize,
			Offset:    offset,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch platform users"})
			return
		}

		totalPages := 0
		if total > 0 {
			totalPages = (total + pageSize - 1) / pageSize
		}

		c.JSON(http.StatusOK, gin.H{
			"users": users,
			"pagination": gin.H{
				"page":        page,
				"page_size":   pageSize,
				"total":       total,
				"total_pages": totalPages,
				"has_next":    page < totalPages,
				"has_prev":    page > 1,
			},
		})
	}
}

func GetPlatformUser(db *sql.DB) gin.HandlerFunc {
	return getPlatformUserWithStore(newPlatformUserRepository(db))
}

func getPlatformUserWithStore(store platformUserStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, found, err := store.GetPlatformUser(c.Request.Context(), c.Param("id"))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch platform user"})
			return
		}
		if !found {
			c.JSON(http.StatusNotFound, gin.H{"error": "Platform user not found"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"user": user})
	}
}

// GetCurrentPlatformUser returns the authenticated platform user's profile.
func GetCurrentPlatformUser(db *sql.DB) gin.HandlerFunc {
	return getCurrentPlatformUserWithStore(newPlatformUserRepository(db))
}

func getCurrentPlatformUserWithStore(store platformUserStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDVal, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in context"})
			return
		}
		var userIDStr string
		switch v := userIDVal.(type) {
		case string:
			userIDStr = v
		case float64:
			userIDStr = fmt.Sprintf("%.0f", v)
		default:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID format"})
			return
		}
		if _, err := uuid.Parse(userIDStr); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID format"})
			return
		}

		user, found, err := store.GetPlatformUser(c.Request.Context(), userIDStr)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch platform user"})
			return
		}
		if !found {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Platform user not found"})
			return
		}

		roleStr := ""
		if user.Role != nil {
			roleStr = user.Role.Name
		}

		c.JSON(http.StatusOK, gin.H{
			"user": gin.H{
				"id":                    user.ID.String(),
				"email":                 user.Email,
				"first_name":            user.FirstName,
				"last_name":             user.LastName,
				"role":                  roleStr,
				"is_active":             user.IsActive,
				"email_verified":        user.EmailVerified,
				"force_password_change": user.ForcePasswordChange,
				"last_login_at":         user.LastLoginAt,
				"created_at":            user.CreatedAt,
				"updated_at":            user.UpdatedAt,
			},
		})
	}
}

// CreatePlatformUser creates a new platform admin user directly (password set by the caller).
// Accepts optional force_password_change flag.
// email_verified is set based on the admin_email_verification_required platform setting.
func CreatePlatformUser(db *sql.DB) gin.HandlerFunc {
	return createPlatformUserWithStore(newPlatformUserRepository(db), platformPasswordService)
}

func createPlatformUserWithStore(store platformUserStore, hasher passwordHasher) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Email               string    `json:"email" binding:"required,email"`
			Password            string    `json:"password" binding:"required,min=8"`
			FirstName           string    `json:"first_name" binding:"required"`
			LastName            string    `json:"last_name" binding:"required"`
			RoleID              uuid.UUID `json:"role_id" binding:"required"`
			ForcePasswordChange bool      `json:"force_password_change"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		ctx := c.Request.Context()

		roleExists, err := store.RoleExists(ctx, req.RoleID.String())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify role"})
			return
		}
		if !roleExists {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role_id"})
			return
		}

		if err := passwordsvc.ValidatePasswordStrengthWithMinLength(req.Password, store.PasswordMinLength(ctx)); err != nil {
			api.BadRequest(c, err.Error())
			return
		}
		hashedPassword, err := hasher.HashPassword(req.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}

		// Direct creation: email is auto-verified unless the platform setting says otherwise.
		emailVerified := !store.AdminEmailVerificationRequired(ctx)

		userID, createdAt, _, err := store.CreatePlatformUser(ctx, platformUserInsert{
			Email:               req.Email,
			PasswordHash:        hashedPassword,
			FirstName:           req.FirstName,
			LastName:            req.LastName,
			RoleID:              req.RoleID,
			EmailVerified:       emailVerified,
			ForcePasswordChange: req.ForcePasswordChange,
		})
		if err != nil {
			if errors.Is(err, errPlatformUserExists) {
				c.JSON(http.StatusConflict, gin.H{"error": "A user with that email address already exists"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create platform user"})
			return
		}

		recordPlatformAudit(c, PlatformAuditEntry{
			EventType:     "platform_user.created",
			Action:        "create",
			EventCategory: "user",
			ResourceType:  "platform_user",
			ResourceID:    userID,
			Metadata: map[string]interface{}{
				"email":   req.Email,
				"role_id": req.RoleID.String(),
			},
		})

		c.JSON(http.StatusCreated, gin.H{
			"message":    "Platform user created successfully",
			"user_id":    userID,
			"created_at": createdAt,
		})
	}
}

// InvitePlatformUser creates a platform admin user without a usable password and sends
// them a branded invitation email containing a one-time password-set link.
// Route: POST /api/v1/admin-service/admin/users/invite
func InvitePlatformUser(db *sql.DB) gin.HandlerFunc {
	return invitePlatformUserWithDeps(newPlatformUserRepository(db), platformPasswordService, dbEmailProvider{db}, dbBrandingProvider{db})
}

func invitePlatformUserWithDeps(store platformUserStore, hasher passwordHasher, email emailProvider, branding brandingProvider) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Determine who is inviting
		inviterIDVal, _ := c.Get("userID")
		inviterIDStr, _ := inviterIDVal.(string)

		var req struct {
			Email     string    `json:"email" binding:"required,email"`
			FirstName string    `json:"first_name" binding:"required"`
			LastName  string    `json:"last_name" binding:"required"`
			RoleID    uuid.UUID `json:"role_id" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: email, first_name, last_name, and role_id are required"})
			return
		}

		ctx := c.Request.Context()

		roleExists, err := store.RoleExists(ctx, req.RoleID.String())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify role"})
			return
		}
		if !roleExists {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role_id"})
			return
		}

		// Generate a token for the invite link (valid 24 hours)
		token, err := generateSecureToken()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate invitation token"})
			return
		}
		tokenExpires := time.Now().Add(24 * time.Hour)

		// A placeholder password hash — the user can't log in with it; they must set their
		// password via the invite link.
		placeholderHash, err := hasher.HashPassword(token[:16] + "!Aa9" + token[16:])
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal error"})
			return
		}

		// Resolve invited_by
		var invitedByID *uuid.UUID
		if inviterIDStr != "" {
			if id, err := uuid.Parse(inviterIDStr); err == nil {
				invitedByID = &id
			}
		}

		tokenHash := hashPasswordResetToken(token)
		userID, createdAt, err := store.CreateInvitedPlatformUser(ctx, platformUserInviteInsert{
			Email:           req.Email,
			PlaceholderHash: placeholderHash,
			FirstName:       req.FirstName,
			LastName:        req.LastName,
			RoleID:          req.RoleID,
			TokenHash:       tokenHash,
			TokenExpires:    tokenExpires,
			InvitedBy:       invitedByID,
		})
		if err != nil {
			if errors.Is(err, errPlatformUserExists) {
				c.JSON(http.StatusConflict, gin.H{"error": "A user with that email address already exists"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create invited user"})
			return
		}

		recordPlatformAudit(c, PlatformAuditEntry{
			EventType:     "platform_user.invited",
			Action:        "invite",
			EventCategory: "user",
			ResourceType:  "platform_user",
			ResourceID:    userID,
			Metadata: map[string]interface{}{
				"email":   req.Email,
				"role_id": req.RoleID.String(),
			},
		})

		// Build invite link and send email
		brand := branding.BrandConfig()
		resetLink := fmt.Sprintf("%s/reset-password?token=%s", strings.TrimRight(brand.AdminUIBase, "/"), token)

		// Resolve inviter display name
		inviterName := "A platform administrator"
		if name := store.InviterDisplayName(ctx, inviterIDStr); name != "" {
			inviterName = name
		}

		emailSvc, err := email.EmailSender()
		if err != nil {
			// User is created; log that email failed but don't fail the request.
			fmt.Printf("[ADMIN] WARN: Invitation email not sent to %s: %v\n", req.Email, err)
			c.JSON(http.StatusCreated, gin.H{
				"message":     "User created. Invitation email could not be sent — email is not configured.",
				"user_id":     userID,
				"invite_link": resetLink,
				"created_at":  createdAt,
			})
			return
		}

		if err := emailSvc.SendPlatformInviteEmail(req.Email, brand.PlatformName, inviterName, resetLink, store.EnabledAdminSsoProviderLabels(ctx)); err != nil {
			fmt.Printf("[ADMIN] WARN: Failed to send invitation email to %s: %v\n", req.Email, err)
			c.JSON(http.StatusCreated, gin.H{
				"message":     "User created. Invitation email failed to send — check SMTP configuration.",
				"user_id":     userID,
				"invite_link": resetLink,
				"created_at":  createdAt,
			})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"message":    fmt.Sprintf("Invitation sent to %s", req.Email),
			"user_id":    userID,
			"created_at": createdAt,
		})
	}
}

// UpdatePlatformUser updates profile fields, role, status, and force_password_change flag.
func UpdatePlatformUser(db *sql.DB) gin.HandlerFunc {
	return updatePlatformUserWithStore(newPlatformUserRepository(db))
}

func updatePlatformUserWithStore(store platformUserStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDStr := c.Param("id")
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}

		var req struct {
			FirstName           *string    `json:"first_name"`
			LastName            *string    `json:"last_name"`
			RoleID              *uuid.UUID `json:"role_id"`
			IsActive            *bool      `json:"is_active"`
			ForcePasswordChange *bool      `json:"force_password_change"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		ctx := c.Request.Context()

		if req.RoleID != nil {
			roleExists, err := store.RoleExists(ctx, req.RoleID.String())
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify role"})
				return
			}
			if !roleExists {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role_id"})
				return
			}
		}

		fields := platformUserUpdateFields{
			FirstName:           req.FirstName,
			LastName:            req.LastName,
			RoleID:              req.RoleID,
			IsActive:            req.IsActive,
			ForcePasswordChange: req.ForcePasswordChange,
		}

		if !fields.HasUpdates() {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No fields to update"})
			return
		}

		if err := store.UpdatePlatformUser(ctx, userID.String(), fields); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update platform user"})
			return
		}

		recordPlatformAudit(c, PlatformAuditEntry{
			EventType:     "platform_user.updated",
			Action:        "update",
			EventCategory: "user",
			ResourceType:  "platform_user",
			ResourceID:    userID.String(),
		})

		c.JSON(http.StatusOK, gin.H{"message": "Platform user updated successfully"})
	}
}

// AdminSetPassword lets a platform admin directly set a new password for any user.
// Optionally marks force_password_change so the user must change it on next login.
// Route: PUT /api/v1/admin-service/admin/users/:id/set-password
func AdminSetPassword(db *sql.DB) gin.HandlerFunc {
	return adminSetPasswordWithStore(newPlatformUserRepository(db), platformPasswordService)
}

func adminSetPasswordWithStore(store platformUserStore, hasher passwordHasher) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDStr := c.Param("id")
		if _, err := uuid.Parse(userIDStr); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}

		var req struct {
			NewPassword         string `json:"new_password" binding:"required,min=8"`
			ForcePasswordChange bool   `json:"force_password_change"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "new_password (min 8 characters) is required"})
			return
		}

		if err := passwordsvc.ValidatePasswordStrengthWithMinLength(req.NewPassword, store.PasswordMinLength(c.Request.Context())); err != nil {
			api.BadRequest(c, err.Error())
			return
		}
		newHash, err := hasher.HashPassword(req.NewPassword)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}

		affected, err := store.UpdatePlatformUserPassword(c.Request.Context(), userIDStr, newHash, req.ForcePasswordChange)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set password"})
			return
		}
		if affected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		recordPlatformAudit(c, PlatformAuditEntry{
			EventType:     "platform_user.password_set",
			Action:        "set_password",
			EventCategory: "user",
			ResourceType:  "platform_user",
			ResourceID:    userIDStr,
			Metadata: map[string]interface{}{
				"force_password_change": req.ForcePasswordChange,
			},
		})

		c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
	}
}

// AdminSendPasswordReset generates a password reset token and emails the user a branded
// reset link.  Both the token expiry (1 hour) and the link domain come from platform settings.
// Route: POST /api/v1/admin-service/admin/users/:id/send-password-reset
func AdminSendPasswordReset(db *sql.DB) gin.HandlerFunc {
	return adminSendPasswordResetWithDeps(newPlatformUserRepository(db), dbEmailProvider{db}, dbBrandingProvider{db})
}

func adminSendPasswordResetWithDeps(store platformUserStore, email emailProvider, branding brandingProvider) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDStr := c.Param("id")
		if _, err := uuid.Parse(userIDStr); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}

		ctx := c.Request.Context()

		// Fetch user email
		userEmail, found, err := store.ActiveUserEmail(ctx, userIDStr)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			return
		}
		if !found {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found or inactive"})
			return
		}

		token, err := generateSecureToken()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate reset token"})
			return
		}
		expires := time.Now().Add(1 * time.Hour)
		tokenHash := hashPasswordResetToken(token)

		if err := store.StorePasswordResetToken(ctx, userIDStr, tokenHash, expires); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store reset token"})
			return
		}

		brand := branding.BrandConfig()
		resetLink := fmt.Sprintf("%s/reset-password?token=%s", strings.TrimRight(brand.AdminUIBase, "/"), token)

		emailSvc, err := email.EmailSender()
		if err != nil {
			fmt.Printf("[ADMIN] WARN: Password reset email not sent to %s: %v\n", userEmail, err)
			c.JSON(http.StatusOK, gin.H{
				"message":    "Reset token generated. Email could not be sent — email is not configured.",
				"reset_link": resetLink,
			})
			return
		}

		if err := emailSvc.SendPlatformPasswordResetEmail(userEmail, brand.PlatformName, resetLink); err != nil {
			fmt.Printf("[ADMIN] WARN: Failed to send password reset email to %s: %v\n", userEmail, err)
			c.JSON(http.StatusOK, gin.H{
				"message":    "Reset token generated. Email failed to send — check SMTP configuration.",
				"reset_link": resetLink,
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Password reset email sent to %s", userEmail)})
	}
}

// DeletePlatformUser soft-deletes a platform user.
func DeletePlatformUser(db *sql.DB) gin.HandlerFunc {
	return deletePlatformUserWithStore(newPlatformUserRepository(db))
}

func deletePlatformUserWithStore(store platformUserStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDStr := c.Param("id")
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}

		if err := store.DeletePlatformUser(c.Request.Context(), userID.String()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete platform user"})
			return
		}

		recordPlatformAudit(c, PlatformAuditEntry{
			EventType:     "platform_user.deleted",
			Action:        "delete",
			EventCategory: "user",
			ResourceType:  "platform_user",
			ResourceID:    userID.String(),
		})

		c.JSON(http.StatusOK, gin.H{"message": "Platform user deleted successfully"})
	}
}
