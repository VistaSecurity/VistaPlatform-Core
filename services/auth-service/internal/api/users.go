package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
	authrbac "github.com/vistasecurity/vistaplatform/auth-service/internal/rbac"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/email"
	audithelpers "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	passwordsvc "github.com/vistasecurity/vistaplatform/shared/security/password"
	sharedservices "github.com/vistasecurity/vistaplatform/shared/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// TenantUser represents a user in a tenant
type TenantUser struct {
	ID            uuid.UUID  `json:"id"`
	TenantID      uuid.UUID  `json:"tenant_id"`
	Email         string     `json:"email"`
	FirstName     string     `json:"first_name"`
	LastName      string     `json:"last_name"`
	Role          string     `json:"role"`
	Roles         []string   `json:"roles"`
	IsActive      bool       `json:"is_active"`
	EmailVerified bool       `json:"email_verified"`
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	AuthMethods   []string   `json:"auth_methods"`
}

// InviteTenantUserRequest is the JSON body for POST /tenant/:tenantId/users/invite (web-ui).
type InviteTenantUserRequest struct {
	Email string `json:"email" binding:"required,email"`
	Role  string `json:"role" binding:"required"`
}

// ListUsersRequest represents query parameters for listing users
type ListUsersRequest struct {
	Role          string `form:"role"`
	IsActive      *bool  `form:"is_active"`
	EmailVerified *bool  `form:"email_verified"`
	Search        string `form:"search"`
	Limit         int    `form:"limit"`
	Offset        int    `form:"offset"`
}

// CreateUserRequest represents a request to create a user
type CreateUserRequest struct {
	Email                 string `json:"email" binding:"required,email"`
	Password              string `json:"password" binding:"required,min=8"`
	FirstName             string `json:"first_name" binding:"required"`
	LastName              string `json:"last_name" binding:"required"`
	Role                  string `json:"role" binding:"required,oneof=billing_admin tenant_admin security_admin viewer api_user"`
	SendVerificationEmail bool   `json:"send_verification_email"`
}

// UpdateUserRequest represents a request to update a user
type UpdateUserRequest struct {
	FirstName *string `json:"first_name"`
	LastName  *string `json:"last_name"`
	Role      *string `json:"role" binding:"omitempty,oneof=billing_admin tenant_admin security_admin viewer api_user"`
	IsActive  *bool   `json:"is_active"`
}

// ListUsersResponse represents the response for listing users
type ListUsersResponse struct {
	Users  []TenantUser `json:"users"`
	Total  int          `json:"total"`
	Limit  int          `json:"limit"`
	Offset int          `json:"offset"`
}

// passwordService is a shared password service instance
var passwordService = passwordsvc.NewPasswordService()

// ListUsers handles GET /users - List users in current tenant
func ListUsers(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context (set by RequireAuth middleware)
		tenantIDStr := c.GetString("tenantID")
		if tenantIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		// Parse query parameters
		var req ListUsersRequest
		if err := c.ShouldBindQuery(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid query parameters"})
			return
		}

		// Set defaults
		if req.Limit <= 0 || req.Limit > 100 {
			req.Limit = 50
		}
		if req.Offset < 0 {
			req.Offset = 0
		}

		// Build base WHERE clause with filters
		baseWhere := `u.tenant_id = $1 AND u.deleted_at IS NULL`
		args := []interface{}{tenantID}
		argIndex := 2

		// Add filters
		if req.Role != "" {
			baseWhere += fmt.Sprintf(` AND EXISTS (
				SELECT 1 FROM user_tenant_roles utr
				JOIN tenant_roles tr ON utr.role_id = tr.id
				WHERE utr.user_id = u.id AND utr.tenant_id = u.tenant_id
				  AND utr.is_active = true AND tr.name = $%d
			)`, argIndex)
			args = append(args, req.Role)
			argIndex++
		}
		if req.IsActive != nil {
			baseWhere += fmt.Sprintf(" AND u.is_active = $%d", argIndex)
			args = append(args, *req.IsActive)
			argIndex++
		}
		if req.EmailVerified != nil {
			baseWhere += fmt.Sprintf(" AND u.email_verified = $%d", argIndex)
			args = append(args, *req.EmailVerified)
			argIndex++
		}
		if req.Search != "" {
			baseWhere += fmt.Sprintf(" AND (u.email ILIKE $%d OR u.first_name ILIKE $%d OR u.last_name ILIKE $%d)", argIndex, argIndex, argIndex)
			searchPattern := "%" + req.Search + "%"
			args = append(args, searchPattern)
			argIndex++
		}

		// Get total count using the same filters.
		// RLS-scoped: users carries a tenant_isolation policy; tenant from token.
		countQuery := `SELECT COUNT(*) FROM users u WHERE ` + baseWhere
		var total int
		err = shareddatabase.WithTenantTx(c.Request.Context(), db, tenantID, func(tx *sql.Tx) error {
			return tx.QueryRowContext(c.Request.Context(), countQuery, args...).Scan(&total)
		})
		if err != nil {
			logrus.WithError(err).Error("Failed to count users")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count users"})
			return
		}

		// Build full query with role subquery, ordering and pagination
		query := fmt.Sprintf(`
			SELECT u.id, u.tenant_id, u.email, u.first_name, u.last_name,
			       COALESCE(
			           (SELECT tr.name
			            FROM user_tenant_roles utr
			            JOIN tenant_roles tr ON utr.role_id = tr.id
			            WHERE utr.user_id = u.id
			              AND utr.tenant_id = u.tenant_id
			              AND utr.is_active = true
			            ORDER BY utr.assigned_at DESC
			            LIMIT 1),
			           'viewer'
			       ) as role,
			       u.is_active, u.email_verified, u.last_login_at, u.created_at, u.updated_at
			FROM users u
			WHERE %s
			ORDER BY u.created_at DESC
			LIMIT $%d OFFSET $%d
		`, baseWhere, argIndex, argIndex+1)
		args = append(args, req.Limit, req.Offset)

		// Execute query.
		// RLS-scoped read over users (tenant_isolation policy); tenant from token.
		var users []TenantUser
		err = shareddatabase.WithTenantTx(c.Request.Context(), db, tenantID, func(tx *sql.Tx) error {
			rows, e := tx.QueryContext(c.Request.Context(), query, args...)
			if e != nil {
				return e
			}
			defer func() { _ = rows.Close() }()

			for rows.Next() {
				var user TenantUser
				if scanErr := rows.Scan(
					&user.ID, &user.TenantID, &user.Email, &user.FirstName, &user.LastName,
					&user.Role, &user.IsActive, &user.EmailVerified, &user.LastLoginAt,
					&user.CreatedAt, &user.UpdatedAt,
				); scanErr != nil {
					logrus.WithError(scanErr).Error("Failed to scan user row")
					continue
				}
				users = append(users, user)
			}
			return rows.Err()
		})
		if err != nil {
			logrus.WithError(err).Error("Failed to fetch users")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
			return
		}

		c.JSON(http.StatusOK, ListUsersResponse{
			Users:  users,
			Total:  total,
			Limit:  req.Limit,
			Offset: req.Offset,
		})
	}
}

// GetUser handles GET /users/:id - Get user details
func GetUser(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context
		tenantIDStr := c.GetString("tenantID")
		if tenantIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		// Get user ID from path
		userIDStr := c.Param("id")
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}

		// Query user (role comes from RBAC tables, not users table)
		query := `
			SELECT id, tenant_id, email, first_name, last_name,
			       is_active, email_verified, last_login_at, created_at, updated_at
			FROM users
			WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		`

		// RLS-scoped read over users (tenant_isolation policy); tenant from token.
		var user TenantUser
		err = shareddatabase.WithTenantTx(c.Request.Context(), db, tenantID, func(tx *sql.Tx) error {
			return tx.QueryRowContext(c.Request.Context(), query, userID, tenantID).Scan(
				&user.ID, &user.TenantID, &user.Email, &user.FirstName, &user.LastName,
				&user.IsActive, &user.EmailVerified, &user.LastLoginAt,
				&user.CreatedAt, &user.UpdatedAt,
			)
		})

		// Get role from RBAC system
		if err == nil {
			user.Role = getUserRole(db, userID, tenantID)
		}

		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		if err != nil {
			logrus.WithError(err).WithField("user_id", userID).Error("Failed to fetch user")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"user": user})
	}
}

// CreateUser handles POST /users - Create new user
func CreateUser(db *sql.DB, bypassDB *sql.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context
		tenantIDStr := c.GetString("tenantID")
		if tenantIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		// Parse request
		var req CreateUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		actorID, ok := requireActorID(c)
		if !ok {
			return
		}
		if err := ensureRoleGrantableByName(c.Request.Context(), db, tenantID, actorID, req.Role); err != nil {
			if writeRoleGrantError(c, err) {
				return
			}
			logrus.WithError(err).WithField("role", req.Role).Error("Failed to validate requested role")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate role"})
			return
		}

		// Check if email already exists in tenant.
		// RLS-scoped: users carries a tenant_isolation policy; tenant from token.
		var existingID uuid.UUID
		checkQuery := `SELECT id FROM users WHERE tenant_id = $1 AND email = $2 AND deleted_at IS NULL`
		err = shareddatabase.WithTenantTx(c.Request.Context(), db, tenantID, func(tx *sql.Tx) error {
			return tx.QueryRowContext(c.Request.Context(), checkQuery, tenantID, req.Email).Scan(&existingID)
		})
		if err == nil {
			c.JSON(http.StatusConflict, gin.H{"error": "Email already exists in this tenant"})
			return
		}
		if err != sql.ErrNoRows {
			logrus.WithError(err).Error("Failed to check email existence")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check email"})
			return
		}

		// Seat gate: reject before creating the user.
		if enforceUserSeatLimit(c, bypassDB, tenantID) {
			return
		}

		// Validate password strength
		if err := passwordsvc.ValidatePasswordStrengthWithPolicy(db, req.Password); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		// Hash password
		hashedPassword, err := passwordService.HashPassword(req.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}

		// Generate email verification token if needed
		var verificationToken *string
		var verificationExpires *time.Time
		emailVerified := false

		// Check tenant settings for email verification requirement
		// For now, default to requiring verification
		if req.SendVerificationEmail {
			token := uuid.New().String()
			verificationToken = &token
			expires := time.Now().Add(24 * time.Hour)
			verificationExpires = &expires
		}

		// Create user (role is managed via RBAC tables, not the users table)
		createQuery := `
			INSERT INTO users (tenant_id, email, password_hash, first_name, last_name,
			                   is_active, email_verified, email_verification_token, email_verification_expires)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			RETURNING id, created_at, updated_at
		`

		// RLS-scoped write over users (tenant_isolation policy); tenant from token.
		var userID uuid.UUID
		var createdAt, updatedAt time.Time
		err = shareddatabase.WithTenantTx(c.Request.Context(), db, tenantID, func(tx *sql.Tx) error {
			return tx.QueryRowContext(c.Request.Context(), createQuery,
				tenantID, req.Email, hashedPassword, req.FirstName, req.LastName,
				true, emailVerified, verificationToken, verificationExpires,
			).Scan(&userID, &createdAt, &updatedAt)
		})

		if err != nil {
			logrus.WithError(err).Error("Failed to create user")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
			return
		}

		// Assign RBAC role to the new user
		if err := assignUserRole(db, userID, tenantID, actorID, req.Role); err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"user_id": userID, "role": req.Role,
			}).Error("Failed to assign role to new user")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "User created but failed to assign role"})
			return
		}

		// Send verification email if requested. Resolve SMTP config from the
		// admin-UI-managed platform settings (DB) at send time, not from env.
		if req.SendVerificationEmail && verificationToken != nil {
			emailService, err := email.PlatformEmailService(db)
			if err != nil {
				logrus.WithError(err).WithField("email", req.Email).Warn("Email not configured — skipping verification email")
			} else {
				// Use first CORS origin as base URL, or default to localhost
				baseURL := "http://localhost:3000"
				if len(cfg.CORSOrigins) > 0 {
					baseURL = cfg.CORSOrigins[0]
				}
				verificationURL := fmt.Sprintf("%s/auth/verify-email?token=%s", baseURL, *verificationToken)
				if err := emailService.SendEmailVerificationEmail(req.Email, verificationURL); err != nil {
					logrus.WithError(err).WithField("email", req.Email).Warn("Failed to send verification email")
				}
			}
		}

		// Return created user (without password hash)
		user := TenantUser{
			ID:            userID,
			TenantID:      tenantID,
			Email:         req.Email,
			FirstName:     req.FirstName,
			LastName:      req.LastName,
			Role:          req.Role,
			Roles:         []string{req.Role},
			IsActive:      true,
			EmailVerified: emailVerified,
			CreatedAt:     createdAt,
			UpdatedAt:     updatedAt,
		}

		// Audit: log user creation
		if rawMW, exists := c.Get("audit_middleware"); exists {
			if mw, ok := rawMW.(*audithelpers.Middleware); ok {
				_ = audithelpers.LogSimple(c.Request.Context(), mw,
					"user.created", "user", "create",
					"user", userID.String(), req.Email, true, "")
			}
		}

		c.JSON(http.StatusCreated, gin.H{
			"message": "User created successfully",
			"user":    user,
		})
	}
}

// UpdateUser handles PUT /users/:id - Update user
func UpdateUser(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context
		tenantIDStr := c.GetString("tenantID")
		if tenantIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		// Get user ID from path
		userIDStr := c.Param("id")
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}

		// Get current user ID (to prevent self-modification issues)
		currentUserID, ok := requireActorID(c)
		if !ok {
			return
		}

		// Parse request
		var req UpdateUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}
		actorID := currentUserID

		// Verify user belongs to tenant (role comes from RBAC, not users table).
		// RLS-scoped: users carries a tenant_isolation policy; tenant from token.
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

		// Get existing role from RBAC system
		existingRole := getUserRole(db, userID, tenantID)

		// Safety checks
		if req.IsActive != nil && !*req.IsActive && userID == currentUserID {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot deactivate yourself"})
			return
		}

		// Check if trying to change role away from an admin-level role
		isAdminRole := existingRole == "tenant_admin" || existingRole == "billing_admin"
		if req.Role != nil && isAdminRole && *req.Role != "tenant_admin" && *req.Role != "billing_admin" && userID == currentUserID {
			// Check if this is the last admin
			adminCount, countErr := countTenantAdmins(db, tenantID)
			if countErr == nil && adminCount <= 1 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot change role of last admin in tenant"})
				return
			}
		}

		// Build dynamic update query (role is handled via RBAC, not users table)
		updates := []string{}
		args := []interface{}{}
		argIndex := 1

		if req.FirstName != nil {
			updates = append(updates, fmt.Sprintf("first_name = $%d", argIndex))
			args = append(args, *req.FirstName)
			argIndex++
		}
		if req.LastName != nil {
			updates = append(updates, fmt.Sprintf("last_name = $%d", argIndex))
			args = append(args, *req.LastName)
			argIndex++
		}
		if req.IsActive != nil {
			updates = append(updates, fmt.Sprintf("is_active = $%d", argIndex))
			args = append(args, *req.IsActive)
			argIndex++
		}

		// Handle role update via RBAC if requested
		if req.Role != nil {
			if err := assignUserRole(db, userID, tenantID, actorID, *req.Role); err != nil {
				if writeRoleGrantError(c, err) {
					return
				}
				logrus.WithError(err).WithFields(logrus.Fields{
					"user_id": userID, "role": *req.Role,
				}).Error("Failed to update user role")
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update role"})
				return
			}
		}

		// If only role was changed (no other fields), we still need to return the updated user
		if len(updates) == 0 && req.Role == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No fields to update"})
			return
		}

		var user TenantUser
		if len(updates) > 0 {
			updates = append(updates, "updated_at = NOW()")
			args = append(args, userID, tenantID)

			//nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
			updateQuery := fmt.Sprintf(`
				UPDATE users
				SET %s
				WHERE id = $%d AND tenant_id = $%d AND deleted_at IS NULL
				RETURNING id, tenant_id, email, first_name, last_name,
				          is_active, email_verified, last_login_at, created_at, updated_at
			`, strings.Join(updates, ", "), argIndex, argIndex+1)

			// RLS-scoped write over users (tenant_isolation policy); tenant from token.
			err = shareddatabase.WithTenantTx(c.Request.Context(), db, tenantID, func(tx *sql.Tx) error {
				return tx.QueryRowContext(c.Request.Context(), updateQuery, args...).Scan(
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
				logrus.WithError(err).WithField("user_id", userID).Error("Failed to update user")
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
				return
			}
		} else {
			// Only role was changed — re-fetch user.
			// RLS-scoped read over users (tenant_isolation policy); tenant from token.
			fetchQuery := `
				SELECT id, tenant_id, email, first_name, last_name,
				       is_active, email_verified, last_login_at, created_at, updated_at
				FROM users
				WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
			`
			err = shareddatabase.WithTenantTx(c.Request.Context(), db, tenantID, func(tx *sql.Tx) error {
				return tx.QueryRowContext(c.Request.Context(), fetchQuery, userID, tenantID).Scan(
					&user.ID, &user.TenantID, &user.Email, &user.FirstName, &user.LastName,
					&user.IsActive, &user.EmailVerified, &user.LastLoginAt,
					&user.CreatedAt, &user.UpdatedAt,
				)
			})
			if err != nil {
				logrus.WithError(err).WithField("user_id", userID).Error("Failed to fetch updated user")
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
				return
			}
		}

		// Populate role from RBAC system
		user.Role = getUserRole(db, userID, tenantID)

		// Audit: log user update with change details
		if rawMW, exists := c.Get("audit_middleware"); exists {
			if mw, ok := rawMW.(*audithelpers.Middleware); ok {
				oldValues := map[string]interface{}{"role": existingRole, "is_active": existingIsActive}
				newValues := map[string]interface{}{"role": user.Role, "is_active": user.IsActive}
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

// DeleteUser handles DELETE /users/:id - Soft delete user
func DeleteUser(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context
		tenantIDStr := c.GetString("tenantID")
		if tenantIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		// Get user ID from path
		userIDStr := c.Param("id")
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}

		// Get current user ID
		currentUserIDStr := c.GetString("userID")
		currentUserID, _ := uuid.Parse(currentUserIDStr)

		// Prevent self-deletion
		if userID == currentUserID {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete yourself"})
			return
		}

		// Verify user belongs to tenant and get role from RBAC.
		// RLS-scoped: users carries a tenant_isolation policy; tenant from token.
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

		// Get role from RBAC system
		userRole := getUserRole(db, userID, tenantID)

		// Prevent deletion of last admin
		isAdminRole := userRole == "tenant_admin" || userRole == "billing_admin"
		if isAdminRole && isActive {
			adminCount, countErr := countTenantAdmins(db, tenantID)
			if countErr == nil && adminCount <= 1 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete last admin in tenant"})
				return
			}
		}

		// Soft delete
		deleteQuery := `
			UPDATE users
			SET deleted_at = NOW(), updated_at = NOW()
			WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		`

		// RLS-scoped write over users (tenant_isolation policy); tenant from token.
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

		// Audit: log user deletion
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

// ListTenantUsers handles GET /tenant/:tenantId/users - List users in a specific tenant
// This endpoint is used by the web-ui to list users with roles from user_tenant_roles
func ListTenantUsers(db *sql.DB) gin.HandlerFunc {
	return ListTenantUsersWithStore(newTenantUsersRepo(db))
}

// ListTenantUsersWithStore is the store-backed implementation of ListTenantUsers,
// exercised directly by the contract test.
func ListTenantUsersWithStore(store tenantUsersStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from URL parameter
		tenantIDStr := c.Param("tenantId")
		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		// Verify the authenticated user has access to this tenant
		// Get tenant ID from context (set by RequireAuth middleware)
		userTenantIDStr := c.GetString("tenantID")
		if userTenantIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found in token"})
			return
		}

		userTenantID, err := uuid.Parse(userTenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID in token"})
			return
		}

		// Users can only list users in their own tenant
		if userTenantID != tenantID {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to this tenant"})
			return
		}

		users, err := store.ListTenantUsers(c.Request.Context(), tenantID)
		if err != nil {
			logrus.WithError(err).Error("Failed to fetch tenant users")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"users": users,
		})
	}
}

// enforceUserSeatLimit runs the max_users cap check: active users plus
// pending invitations vs the tenant's entitlement. Counts run on the BYPASSRLS
// handle (explicitly tenant-filtered) so enforced RLS can't zero them out and
// silently disable the gate. Writes the 403/500 response and returns true when
// the caller should stop.
func enforceUserSeatLimit(c *gin.Context, bypassDB *sql.DB, tenantID uuid.UUID) bool {
	check, err := sharedservices.NewLimitEnforcementService(bypassDB).CheckUserLimit(tenantID)
	if err != nil {
		logrus.WithError(err).Error("Failed to check user seat limit")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check user limit"})
		return true
	}
	if !check.Allowed {
		c.JSON(http.StatusForbidden, gin.H{
			"error":          check.Message,
			"current_usage":  check.CurrentUsage,
			"limit":          check.Limit,
			"upgrade_prompt": check.UpgradePrompt,
		})
		return true
	}
	return false
}

// InviteTenantMember handles POST /tenant/:tenantId/users/invite — creates a user and emails a password reset link.
func InviteTenantMember(cfg *config.Config, db *sql.DB, bypassDB *sql.DB, authService *auth.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantIDStr := c.Param("tenantId")
		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		userTenantIDStr := c.GetString("tenantID")
		if userTenantIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found in token"})
			return
		}
		userTenantID, err := uuid.Parse(userTenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID in token"})
			return
		}
		if userTenantID != tenantID {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to this tenant"})
			return
		}

		var req InviteTenantUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		roleName, err := mapInviteRoleName(req.Role)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role", "details": req.Role})
			return
		}

		if err := authService.EnsureDefaultTenantRoles(tenantID); err != nil {
			logrus.WithError(err).Error("Failed to ensure tenant roles for invite")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare tenant roles"})
			return
		}

		invitedBy, ok := requireActorID(c)
		if !ok {
			return
		}
		if err := ensureRoleGrantableByName(c.Request.Context(), db, tenantID, invitedBy, roleName); err != nil {
			if writeRoleGrantError(c, err) {
				return
			}
			// The role name is resolved against the tenant's own tenant_roles, so
			// "no such role" is a client error, not a server one.
			if errors.Is(err, errTenantRoleNotFound) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role", "details": req.Role})
				return
			}
			logrus.WithError(err).WithField("role", roleName).Error("Failed to validate invited role")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate role"})
			return
		}

		emailNorm := strings.ToLower(strings.TrimSpace(req.Email))

		// RLS-scoped: users carries a tenant_isolation policy; tenant from path.
		var existingID uuid.UUID
		err = shareddatabase.WithTenantTx(c.Request.Context(), db, tenantID, func(tx *sql.Tx) error {
			return tx.QueryRowContext(c.Request.Context(), `SELECT id FROM users WHERE tenant_id = $1 AND LOWER(email) = $2 AND deleted_at IS NULL`, tenantID, emailNorm).Scan(&existingID)
		})
		if err == nil {
			c.JSON(http.StatusConflict, gin.H{"error": "Email already exists in this tenant"})
			return
		}
		if err != sql.ErrNoRows {
			logrus.WithError(err).Error("Failed to check email existence for invite")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check email"})
			return
		}

		// Seat gate: reject before issuing the invitation.
		if enforceUserSeatLimit(c, bypassDB, tenantID) {
			return
		}

		// Auth-method-agnostic invite: issue a tokenized invitation and
		// email the accept link instead of creating a password account. The
		// invitee chooses password / Google / Microsoft at accept time; no users
		// row exists until then, so SSO acceptance no longer collides with a
		// pre-created password user. roleName was already mapped above.
		invitationID, rawToken, err := createInvitation(db, tenantID, emailNorm, roleName, invitedBy)
		if err != nil {
			logrus.WithError(err).Error("Failed to create invitation")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create invitation"})
			return
		}

		var tenantName string
		if err := db.QueryRow(`SELECT name FROM tenants WHERE id = $1`, tenantID).Scan(&tenantName); err != nil {
			// Non-fatal: the invitation already exists and is still worth
			// emailing. The tenant name is display-only in that email, so a
			// lookup failure degrades the message rather than the operation.
			logrus.WithError(err).WithField("tenant_id", tenantID).
				Warn("Failed to load tenant name for invitation email; sending without it")
		}
		sendInvitationEmail(db, cfg, emailNorm, rawToken, tenantName)

		if rawMW, exists := c.Get("audit_middleware"); exists {
			if mw, ok := rawMW.(*audithelpers.Middleware); ok {
				_ = audithelpers.LogSimple(c.Request.Context(), mw,
					"user.invited", "user", "create",
					"invitation", invitationID.String(), emailNorm, true, "")
			}
		}

		c.JSON(http.StatusCreated, gin.H{
			"invitation_id": invitationID.String(),
			"accept_url":    invitationAcceptURL(cfg, rawToken),
			"message":       "Invitation sent",
		})
	}
}

// mapInviteRoleName normalizes the role name an invite request carries to the
// internal tenant_roles.name it refers to.
//
// It deliberately does NOT decide which roles exist — that is the tenant's
// tenant_roles table, and the caller settles it with ensureRoleGrantableByName
// (roleIDByName + grant-bounds check). A hardcoded allowlist of four system
// roles used to live here, which meant the invite dialog offered options the
// endpoint always rejected with 400: billing_admin is seeded into EVERY tenant
// by ensureTenantRoles, and custom tenant roles could never match at all. The
// dropdown is populated from the unfiltered GET /tenant/{id}/roles list, so any
// row it shows must be invitable.
func mapInviteRoleName(in string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(in))
	switch s {
	// "member" historically mapped to analyst; analyst was retired and
	// folded into viewer, so both now resolve to viewer (also keeps legacy
	// invites that pass "analyst" working instead of erroring).
	case "member", "analyst":
		return "viewer", nil
	case "admin":
		return "tenant_admin", nil
	case "":
		return "", fmt.Errorf("role is required")
	}
	return s, nil
}

// --- RBAC helper functions ---
// These mirror the patterns in auth/service.go but work with *sql.DB directly,
// since the API handlers don't have access to the AuthService instance.

// getUserRole gets a user's primary RBAC role name.
// Returns the role name (e.g., "tenant_admin", "viewer") or "viewer" as default.
func getUserRole(db *sql.DB, userID, tenantID uuid.UUID) string {
	query := `
		SELECT tr.name
		FROM tenant_roles tr
		JOIN user_tenant_roles utr ON tr.id = utr.role_id
		WHERE utr.user_id = $1 AND tr.tenant_id = $2 AND utr.is_active = true
		  AND (utr.expires_at IS NULL OR utr.expires_at > NOW())
		ORDER BY utr.assigned_at DESC
		LIMIT 1
	`

	// RLS-scoped read over tenant_roles + user_tenant_roles; tenant is known.
	var roleName string
	err := shareddatabase.WithTenantTx(context.Background(), db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), query, userID, tenantID).Scan(&roleName)
	})
	if err != nil {
		return "viewer"
	}
	return roleName
}

func requireActorID(c *gin.Context) (uuid.UUID, bool) {
	userIDStr := c.GetString("userID")
	if userIDStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return uuid.Nil, false
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
		return uuid.Nil, false
	}
	return userID, true
}

func writeRoleGrantError(c *gin.Context, err error) bool {
	var notHeld *authrbac.ErrPermissionNotHeld
	switch {
	case errors.As(err, &notHeld):
		c.JSON(http.StatusForbidden, gin.H{
			"error":               "You can only grant permissions you hold yourself",
			"code":                "permission_not_held",
			"missing_permissions": notHeld.Names,
		})
		return true
	default:
		return false
	}
}

func ensureRoleGrantableByName(ctx context.Context, db *sql.DB, tenantID, actorID uuid.UUID, roleName string) error {
	return shareddatabase.WithTenantTx(ctx, db, tenantID, func(tx *sql.Tx) error {
		roleID, err := roleIDByName(ctx, tx, tenantID, roleName)
		if err != nil {
			return err
		}
		return validateRoleGrantable(ctx, tx, tenantID, actorID, roleID)
	})
}

// errTenantRoleNotFound reports that a role name does not exist in the tenant's
// tenant_roles. Since roles are now resolved from the table rather than a
// hardcoded allowlist, this is the "you asked for a role that isn't real"
// signal, and callers must answer 400 rather than 500.
var errTenantRoleNotFound = errors.New("role not found for tenant")

func roleIDByName(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, roleName string) (uuid.UUID, error) {
	var roleID uuid.UUID
	err := tx.QueryRowContext(ctx, `
		SELECT id FROM tenant_roles
		WHERE tenant_id = $1 AND name = $2
	`, tenantID, roleName).Scan(&roleID)
	if err != nil {
		if err == sql.ErrNoRows {
			return uuid.Nil, fmt.Errorf("%w: %s", errTenantRoleNotFound, roleName)
		}
		return uuid.Nil, fmt.Errorf("failed to get role ID: %w", err)
	}
	return roleID, nil
}

// validateRoleGrantable is the package-local alias for the shared ceiling in
// authrbac.ValidateRoleGrantable. The implementation moved there when the SSO
// provider-config write path had to enforce the same rule (see that function's
// doc comment); this stays so the call sites below read unchanged.
func validateRoleGrantable(ctx context.Context, tx *sql.Tx, tenantID, actorID, roleID uuid.UUID) error {
	return authrbac.ValidateRoleGrantable(ctx, tx, tenantID, actorID, roleID)
}

// assignUserRole assigns an RBAC role to a user in a tenant.
// If the user already has a role assignment for this role, it reactivates it.
func assignUserRole(db *sql.DB, userID, tenantID, actorID uuid.UUID, roleName string) error {
	// RLS-scoped: tenant_roles + user_tenant_roles both carry tenant_isolation
	// policies; tenant is known. The role lookup, deactivate, and reassign run
	// inside one WithTenantTx.
	return shareddatabase.WithTenantTx(context.Background(), db, tenantID, func(tx *sql.Tx) error {
		// Look up the role ID
		roleID, err := roleIDByName(context.Background(), tx, tenantID, roleName)
		if err != nil {
			return err
		}
		if err := validateRoleGrantable(context.Background(), tx, tenantID, actorID, roleID); err != nil {
			return err
		}

		// Deactivate any existing roles for this user in this tenant
		if _, err = tx.ExecContext(context.Background(), `
			UPDATE user_tenant_roles
			SET is_active = false
			WHERE user_id = $1 AND tenant_id = $2 AND is_active = true
		`, userID, tenantID); err != nil {
			return fmt.Errorf("failed to deactivate existing roles: %w", err)
		}

		// Assign the new role
		if _, err = tx.ExecContext(context.Background(), `
			INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, assigned_at, is_active)
			VALUES ($1, $2, $3, NOW(), true)
			ON CONFLICT (user_id, tenant_id, role_id)
			DO UPDATE SET is_active = true, assigned_at = NOW()
		`, userID, tenantID, roleID); err != nil {
			return fmt.Errorf("failed to assign role: %w", err)
		}

		return nil
	})
}

// countTenantAdmins counts the number of active admin-level users in a tenant
// (users with tenant_admin or billing_admin roles).
func countTenantAdmins(db *sql.DB, tenantID uuid.UUID) (int, error) {
	query := `
		SELECT COUNT(DISTINCT utr.user_id)
		FROM user_tenant_roles utr
		JOIN tenant_roles tr ON utr.role_id = tr.id
		JOIN users u ON utr.user_id = u.id
		WHERE utr.tenant_id = $1
		  AND tr.name IN ('tenant_admin', 'billing_admin')
		  AND utr.is_active = true
		  AND u.is_active = true
		  AND u.deleted_at IS NULL
	`

	// RLS-scoped: joins user_tenant_roles + tenant_roles + users (all
	// tenant_isolation tables); tenant is known.
	var count int
	err := shareddatabase.WithTenantTx(context.Background(), db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), query, tenantID).Scan(&count)
	})
	return count, err
}
