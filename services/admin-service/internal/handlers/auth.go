package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/shared/api"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/models"
	"github.com/vistasecurity/vistaplatform/shared/security/authpolicy"
	"github.com/vistasecurity/vistaplatform/shared/security/jwtkeys"
	passwordsvc "github.com/vistasecurity/vistaplatform/shared/security/password"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

type LoginResponse struct {
	User                models.PlatformUser `json:"user"`
	AccessToken         string              `json:"access_token"`
	RefreshToken        string              `json:"refresh_token"`
	ExpiresIn           int                 `json:"expires_in"`
	ForcePasswordChange bool                `json:"force_password_change"`
}

// RLS: platform-global, no tenant scope. Authenticates platform_users (a global
// table with no RLS policy); tenant context is irrelevant here.
func Login(db *sql.DB, jwtSecret string, refreshTokenService *auth.PlatformRefreshTokenService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		// Query platform user including the new onboarding columns
		var user models.PlatformUser
		var passwordHash string
		var roleName string
		query := `
			SELECT pu.id, pu.email, pu.first_name, pu.last_name, pu.role_id, pr.name as role_name,
			       pu.is_active, pu.email_verified, pu.force_password_change,
			       pu.last_login_at, pu.created_at, pu.updated_at, pu.password_hash, pu.locked_until
			FROM platform_users pu
			JOIN platform_roles pr ON pu.role_id = pr.id
			WHERE pu.email = $1 AND pu.is_active = true AND pu.deleted_at IS NULL
		`
		var lockedUntil sql.NullTime

		err := db.QueryRow(query, req.Email).Scan(
			&user.ID, &user.Email, &user.FirstName, &user.LastName, &user.RoleID, &roleName,
			&user.IsActive, &user.EmailVerified, &user.ForcePasswordChange,
			&user.LastLoginAt, &user.CreatedAt, &user.UpdatedAt, &passwordHash, &lockedUntil,
		)

		if err == sql.ErrNoRows {
			var userExists bool
			var isActive bool
			var hasRole bool
			var deletedAt sql.NullTime
			_ = db.QueryRow(`
				SELECT true, pu.is_active, pu.role_id IS NOT NULL, pu.deleted_at
				FROM platform_users pu
				WHERE pu.email = $1
			`, req.Email).Scan(&userExists, &isActive, &hasRole, &deletedAt)

			if !userExists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			} else if deletedAt.Valid {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Account has been deleted"})
			} else if !isActive {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Account is inactive"})
			} else if !hasRole {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "User account is missing a role. Please contact an administrator."})
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			}
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			return
		}

		if lockedUntil.Valid && lockedUntil.Time.After(time.Now()) {
			c.JSON(http.StatusLocked, gin.H{"error": "Account is locked. Please try again later."})
			return
		}

		// Verify password
		valid, err := platformPasswordService.VerifyPassword(req.Password, passwordHash)
		if err != nil || !valid {
			recordPlatformFailedLogin(db, user.ID)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		// Update last login and clear any expired failed-login state on success.
		now := time.Now()
		_, _ = db.Exec(
			"UPDATE platform_users SET last_login_at = $1, failed_login_attempts = 0, locked_until = NULL, updated_at = $1 WHERE id = $2",
			now, user.ID,
		)
		user.LastLoginAt = &now

		// The operator-configured session length (admin-ui Security > Policy ->
		// "Session timeout"), falling back to the historical 7 days. Resolved ONCE
		// per issuance and used for both the refresh JWT's exp claim and the
		// refresh_tokens row, so the two cannot drift apart.
		sessionTTL := authpolicy.SessionLifetime(db, defaultPlatformSessionTTL)

		// Generate tokens. When force_password_change is set the access token is
		// a LIMITED change-password-only session — the middleware refuses
		// everything else until the password is rotated, so the seeded default
		// credentials can never grant a working admin session.
		accessToken, refreshToken, err := generateTokens(user.ID.String(), user.Email, roleName, jwtSecret, user.ForcePasswordChange, sessionTTL)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
			return
		}

		// Store refresh token
		expiresAt := time.Now().Add(sessionTTL)
		familyID, err := refreshTokenService.StoreRefreshToken(
			user.ID, refreshToken, nil, expiresAt,
			c.ClientIP(), c.Request.UserAgent(),
		)
		if err != nil {
			fmt.Printf("[ADMIN] ERROR: Failed to store refresh token for user %s: %v\n", user.ID, err)
		} else {
			fmt.Printf("[ADMIN] INFO: Stored refresh token for user %s, family_id: %s\n", user.ID, familyID)
		}

		setPlatformAuthCookies(c, accessToken, 3600, int(sessionTTL.Seconds()), refreshToken, jwtSecret)

		c.JSON(http.StatusOK, LoginResponse{
			User:                user,
			AccessToken:         accessToken,
			RefreshToken:        refreshToken,
			ExpiresIn:           3600,
			ForcePasswordChange: user.ForcePasswordChange,
		})
	}
}

func recordPlatformFailedLogin(db *sql.DB, userID uuid.UUID) {
	policy := authpolicy.Lockout(db)
	now := time.Now()
	_, err := db.Exec(
		`UPDATE platform_users
		 SET failed_login_attempts = failed_login_attempts + 1,
		     locked_until = CASE
		         WHEN failed_login_attempts + 1 >= $1 THEN $2
		         ELSE locked_until
		     END,
		     updated_at = $3
		 WHERE id = $4`,
		policy.MaxAttempts, now.Add(policy.Duration), now, userID,
	)
	if err != nil {
		fmt.Printf("[ADMIN] WARN: Failed to record platform failed login attempt for user %s: %v\n", userID, err)
	}
}

// defaultPlatformRefreshCookieMaxAge is the historical fallback for tests or
// legacy call sites that do not pass a policy-controlled session lifetime.
const defaultPlatformRefreshCookieMaxAge = 7 * 24 * 3600

// setPlatformAuthCookies sets platform_access_token (httpOnly), optional platform_refresh_token
// (httpOnly), and platform_csrf_token. Using the "platform_" prefix keeps these cookies distinct
// from the tenant auth-service cookies (access_token / refresh_token / csrf_token) which share
// the same domain. Without distinct names, whichever service sets a cookie last overwrites the
// other service's session, causing cascading 401 loops for the other service.
func setPlatformAuthCookies(c *gin.Context, accessToken string, maxAgeSeconds, refreshMaxAgeSeconds int, refreshToken, jwtSecret string) {
	if refreshMaxAgeSeconds <= 0 {
		refreshMaxAgeSeconds = defaultPlatformRefreshCookieMaxAge
	}
	// Secure flag is set when either:
	//   1. ENFORCE_SECURE_COOKIES=true is set (production hardening — never trust
	//      a misconfigured upstream proxy to drop the X-Forwarded-Proto header), or
	//   2. The current request was forwarded over HTTPS by a proxy.
	secure := enforceSecureCookies
	if !secure {
		if s := c.GetHeader("X-Forwarded-Proto"); s == "https" {
			secure = true
		}
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "platform_access_token",
		Value:    accessToken,
		Domain:   cookieDomain,
		Path:     "/",
		MaxAge:   maxAgeSeconds,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})

	if refreshToken != "" {
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "platform_refresh_token",
			Value:    refreshToken,
			Domain:   cookieDomain,
			Path:     "/",
			MaxAge:   refreshMaxAgeSeconds,
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteStrictMode,
		})
	}

	// Session-bound CSRF token: HMAC(access-token jti), so it can't be
	// replayed across sessions.
	//
	// MaxAge tracks the REFRESH token, not the access token: admin-ui reads this
	// cookie's presence as "a session exists" and only then attempts a silent
	// refresh on a 401. Tying it to the access token made the signal disappear
	// exactly when the refresh was due, stranding the user on error cards with no
	// redirect to sign-in. The cookie authorizes nothing on its own — it is
	// validated against the current access token's jti/csrf claim.
	if csrfValue := sharedmw.CSRFTokenForAccessToken(jwtSecret, accessToken); csrfValue != "" {
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "platform_csrf_token",
			Value:    csrfValue,
			Domain:   cookieDomain,
			Path:     "/",
			MaxAge:   refreshMaxAgeSeconds,
			HttpOnly: false,
			Secure:   secure,
			SameSite: http.SameSiteStrictMode,
		})
	}
}

// clearPlatformAuthCookies expires all three platform auth cookies.
func clearPlatformAuthCookies(c *gin.Context) {
	secure := enforceSecureCookies
	if !secure {
		if s := c.GetHeader("X-Forwarded-Proto"); s == "https" {
			secure = true
		}
	}
	for _, name := range []string{"platform_access_token", "platform_refresh_token", "platform_csrf_token"} {
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     name,
			Value:    "",
			Domain:   cookieDomain,
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: name != "platform_csrf_token",
			Secure:   secure,
			SameSite: http.SameSiteStrictMode,
		})
	}
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func RefreshToken(db *sql.DB, jwtSecret string, refreshTokenService *auth.PlatformRefreshTokenService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req RefreshTokenRequest
		_ = c.ShouldBindJSON(&req)

		if req.RefreshToken == "" {
			if cookie, err := c.Cookie("platform_refresh_token"); err == nil && cookie != "" {
				req.RefreshToken = cookie
			}
		}
		if req.RefreshToken == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Refresh token required (cookie or body)"})
			return
		}

		claims, err := parsePlatformRefreshToken(req.RefreshToken, jwtSecret)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
			return
		}
		if claims["type"] != "refresh" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			return
		}

		userIDStr, ok := claims["user_id"].(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID in token"})
			return
		}
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID format"})
			return
		}

		var user models.PlatformUser
		var roleName string
		err = db.QueryRow(`
			SELECT pu.id, pu.email, pu.first_name, pu.last_name, pu.role_id, pr.name,
			       pu.is_active, pu.email_verified, pu.force_password_change,
			       pu.last_login_at, pu.created_at, pu.updated_at
			FROM platform_users pu
			JOIN platform_roles pr ON pu.role_id = pr.id
			WHERE pu.id = $1 AND pu.is_active = true AND pu.deleted_at IS NULL
		`, userIDStr).Scan(
			&user.ID, &user.Email, &user.FirstName, &user.LastName, &user.RoleID, &roleName,
			&user.IsActive, &user.EmailVerified, &user.ForcePasswordChange,
			&user.LastLoginAt, &user.CreatedAt, &user.UpdatedAt,
		)
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found or inactive"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			return
		}

		// The operator-configured session length (admin-ui Security > Policy ->
		// "Session timeout"), falling back to the historical 7 days. Resolved ONCE
		// per issuance and used for both the refresh JWT's exp claim and the
		// refresh_tokens row, so the two cannot drift apart.
		sessionTTL := authpolicy.SessionLifetime(db, defaultPlatformSessionTTL)

		// The flag is re-read from the DB above, so a rotation performed before
		// the password change still yields a limited access token.
		accessToken, newRefreshToken, err := generateTokens(user.ID.String(), user.Email, roleName, jwtSecret, user.ForcePasswordChange, sessionTTL)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
			return
		}

		expiresAt := time.Now().Add(sessionTTL)
		_, err = refreshTokenService.ValidateAndRotateToken(
			req.RefreshToken, userID, newRefreshToken, expiresAt,
			c.ClientIP(), c.Request.UserAgent(),
		)
		if err != nil {
			switch err {
			case auth.ErrTokenReuseDetected:
				// The family is already revoked inside ValidateAndRotateToken. We do NOT
				// call RevokeAllUserTokens here — that would nuke every other open session
				// for this user (all devices, all browsers) which is too aggressive for
				// what is typically a refresh race in development, not a real compromise.
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Token reuse detected - session revoked"})
			case auth.ErrInvalidToken, auth.ErrExpiredToken:
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to refresh token"})
			}
			return
		}

		setPlatformAuthCookies(c, accessToken, 3600, int(sessionTTL.Seconds()), newRefreshToken, jwtSecret)

		c.JSON(http.StatusOK, LoginResponse{
			User:                user,
			AccessToken:         accessToken,
			RefreshToken:        newRefreshToken,
			ExpiresIn:           3600,
			ForcePasswordChange: user.ForcePasswordChange,
		})
	}
}

// ChangePassword allows an authenticated platform user to change their own password.
// On success the force_password_change flag is cleared and the session is ROTATED:
// all outstanding refresh tokens are revoked and a fresh (unrestricted) token pair
// is issued for this browser. The rotation is what unwinds a limited
// pwd_change_required session — without it the cookie would keep carrying
// the restricted claim after the password change, and any pre-change refresh
// token could later mint a full session for whoever held the old password.
// Route: POST /api/v1/admin-service/admin/auth/change-password  (authenticated)
func ChangePassword(db *sql.DB, jwtSecret string, refreshTokenService *auth.PlatformRefreshTokenService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDVal, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
			return
		}
		userIDStr, ok := userIDVal.(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
			return
		}

		var req struct {
			CurrentPassword string `json:"current_password" binding:"required"`
			NewPassword     string `json:"new_password" binding:"required,min=8"`
			ConfirmPassword string `json:"confirm_password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "current_password, new_password, and confirm_password are required"})
			return
		}
		if req.NewPassword != req.ConfirmPassword {
			c.JSON(http.StatusBadRequest, gin.H{"error": "new_password and confirm_password do not match"})
			return
		}

		// Fetch current password hash plus the identity fields needed to
		// re-issue the session after the change.
		var currentHash, email, roleName string
		err := db.QueryRow(`
			SELECT pu.password_hash, pu.email, pr.name
			FROM platform_users pu
			JOIN platform_roles pr ON pu.role_id = pr.id
			WHERE pu.id = $1 AND pu.deleted_at IS NULL
		`, userIDStr).Scan(&currentHash, &email, &roleName)
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			return
		}

		// Verify current password
		valid, err := platformPasswordService.VerifyPassword(req.CurrentPassword, currentHash)
		if err != nil || !valid {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Current password is incorrect"})
			return
		}

		// Validate and hash new password
		if err := passwordsvc.ValidatePasswordStrengthWithPolicy(db, req.NewPassword); err != nil {
			api.BadRequest(c, err.Error())
			return
		}
		newHash, err := platformPasswordService.HashPassword(req.NewPassword)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}

		_, err = db.Exec(`
			UPDATE platform_users
			SET password_hash = $1,
			    force_password_change = false,
			    password_changed_at = NOW(),
			    updated_at = NOW()
			WHERE id = $2 AND deleted_at IS NULL
		`, newHash, userIDStr)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
			return
		}

		// Rotate the session: every refresh token minted under the old password
		// dies, and this browser gets a fresh, unrestricted pair. Best-effort on
		// storage (mirrors Login) — the password change itself has succeeded.
		if userID, parseErr := uuid.Parse(userIDStr); parseErr == nil {
			_ = refreshTokenService.RevokeAllUserTokens(userID)

			// The operator-configured session length (admin-ui Security > Policy ->
			// "Session timeout"), falling back to the historical 7 days. Resolved ONCE
			// per issuance and used for both the refresh JWT's exp claim and the
			// refresh_tokens row, so the two cannot drift apart.
			sessionTTL := authpolicy.SessionLifetime(db, defaultPlatformSessionTTL)

			accessToken, refreshToken, tokErr := generateTokens(userIDStr, email, roleName, jwtSecret, false, sessionTTL)
			if tokErr == nil {
				expiresAt := time.Now().Add(sessionTTL)
				if _, storeErr := refreshTokenService.StoreRefreshToken(
					userID, refreshToken, nil, expiresAt,
					c.ClientIP(), c.Request.UserAgent(),
				); storeErr != nil {
					fmt.Printf("[ADMIN] ERROR: Failed to store refresh token after password change for user %s: %v\n", userIDStr, storeErr)
				}
				setPlatformAuthCookies(c, accessToken, 3600, int(sessionTTL.Seconds()), refreshToken, jwtSecret)
			} else {
				fmt.Printf("[ADMIN] ERROR: Failed to re-issue session after password change for user %s: %v\n", userIDStr, tokErr)
			}
		}

		c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
	}
}

// ResetPassword resets a platform user's password using a time-limited token that was
// delivered via email (by InvitePlatformUser or AdminSendPasswordReset).
// Route: POST /api/v1/admin-service/auth/reset-password  (unauthenticated)
func ResetPassword(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Token           string `json:"token" binding:"required"`
			NewPassword     string `json:"new_password" binding:"required,min=8"`
			ConfirmPassword string `json:"confirm_password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "token, new_password, and confirm_password are required"})
			return
		}
		if req.NewPassword != req.ConfirmPassword {
			c.JSON(http.StatusBadRequest, gin.H{"error": "new_password and confirm_password do not match"})
			return
		}

		token := strings.TrimSpace(req.Token)
		tokenHash := hashPasswordResetToken(token)

		// Look up the user by token digest, checking expiry
		var userID uuid.UUID
		var expires time.Time
		err := db.QueryRow(`
			SELECT id, password_reset_expires
			FROM platform_users
			WHERE password_reset_token = $1 AND deleted_at IS NULL
		`, tokenHash).Scan(&userID, &expires)
		if err == sql.ErrNoRows {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired reset token"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			return
		}
		if time.Now().After(expires) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Reset token has expired. Please request a new one."})
			return
		}

		// Validate and hash new password
		if err := passwordsvc.ValidatePasswordStrengthWithPolicy(db, req.NewPassword); err != nil {
			api.BadRequest(c, err.Error())
			return
		}
		newHash, err := platformPasswordService.HashPassword(req.NewPassword)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}

		_, err = db.Exec(`
			UPDATE platform_users
			SET password_hash = $1,
			    force_password_change = false,
			    password_changed_at = NOW(),
			    password_reset_token = NULL,
			    password_reset_expires = NULL,
			    invitation_accepted_at = CASE
			        WHEN invitation_accepted_at IS NULL THEN NOW()
			        ELSE invitation_accepted_at
			    END,
			    email_verified = true,
			    updated_at = NOW()
			WHERE id = $2
		`, newHash, userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset password"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Password has been reset successfully. You can now log in."})
	}
}

// ForgotPassword is a public, unauthenticated endpoint.
// The user submits their email; if it matches an active platform user we generate a
// 1-hour reset token and send a branded email.  We always return 200 OK regardless
// of whether the email exists to prevent user-enumeration attacks.
func ForgotPassword(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Email string `json:"email" binding:"required,email"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "A valid email address is required"})
			return
		}

		email := strings.ToLower(strings.TrimSpace(req.Email))

		// Look up the user — silently succeed if not found (anti-enumeration).
		var userID string
		err := db.QueryRow(
			"SELECT id FROM platform_users WHERE email = $1 AND deleted_at IS NULL AND is_active = true",
			email,
		).Scan(&userID)
		if err == sql.ErrNoRows {
			// Return success so callers can't enumerate valid emails.
			c.JSON(http.StatusOK, gin.H{"message": "If that email is registered you will receive a reset link shortly."})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			return
		}

		token, err := generateSecureToken()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate reset token"})
			return
		}
		expires := time.Now().Add(1 * time.Hour)
		tokenHash := hashPasswordResetToken(token)

		_, err = db.Exec(`
			UPDATE platform_users
			SET password_reset_token = $1, password_reset_expires = $2, updated_at = NOW()
			WHERE id = $3
		`, tokenHash, expires, userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store reset token"})
			return
		}

		brand := getPlatformBrandConfig(db)
		resetLink := fmt.Sprintf("%s/reset-password?token=%s", strings.TrimRight(brand.AdminUIBase, "/"), token)

		emailSvc, emailErr := getEmailService(db)
		if emailErr != nil {
			fmt.Printf("[ADMIN] WARN: Forgot-password email not sent to %s: %v\n", email, emailErr)
			// Still return the anti-enumeration message; the token is valid in the DB.
			c.JSON(http.StatusOK, gin.H{"message": "If that email is registered you will receive a reset link shortly."})
			return
		}

		if err := emailSvc.SendPlatformPasswordResetEmail(email, brand.PlatformName, resetLink); err != nil {
			fmt.Printf("[ADMIN] WARN: Failed to send forgot-password email to %s: %v\n", email, err)
		}

		c.JSON(http.StatusOK, gin.H{"message": "If that email is registered you will receive a reset link shortly."})
	}
}

// Logout revokes all platform refresh tokens for the authenticated user and
// clears the three platform auth cookies. Route: POST /admin/auth/logout (protected).
func Logout(db *sql.DB, refreshTokenService *auth.PlatformRefreshTokenService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDVal, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
			return
		}
		userIDStr, _ := userIDVal.(string)
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
			return
		}
		_ = refreshTokenService.RevokeAllUserTokens(userID)
		clearPlatformAuthCookies(c)
		c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
	}
}

// generateTokens mints the platform access + refresh token pair.
//
// pwdChangeRequired marks the ACCESS token as a limited change-password-only
// session: the shared auth middleware rejects every request carrying the
// claim except the change-password / me / logout endpoints, so a user flagged
// force_password_change (e.g. the seeded default admin on its published
// password) cannot use the session for anything else. The refresh token stays
// unmarked — RefreshToken re-reads the flag from the DB on every rotation, so
// a refreshed access token is limited again until the password actually changes.
// platformSigner holds the ES256 key admin-service signs platform tokens with
//or nil when no key is provisioned — in which case token minting falls
// back to legacy shared-secret HS256 and the deployment behaves exactly as it
// did before. Set once at startup by InitTokenSigning; a package-level value
// rather than a parameter because generateTokens has four call sites and
// threading a signer through each would be churn with no benefit.
var platformSigner *jwtkeys.Signer

// InitTokenSigning configures asymmetric platform-token signing. Called once
// during server setup. Returns the active kid, or "" when signing stays on the
// legacy HS256 path.
func InitTokenSigning(s *jwtkeys.Signer) string {
	platformSigner = s
	return s.ActiveKID()
}

// PlatformSigner exposes the signer so the server can publish its JWKS.
func PlatformSigner() *jwtkeys.Signer { return platformSigner }

// signPlatformToken emits ES256 when a key is configured and legacy HS256
// otherwise. Both platform token mints go through here, so the algorithm is
// decided in exactly one place.
func signPlatformToken(claims jwt.Claims, jwtSecret string) (string, error) {
	if platformSigner != nil {
		return platformSigner.Sign(claims)
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(jwtSecret))
}

// platformTokenVerifier verifies tokens this service minted. When a signing
// key is configured the trusted public half comes from platformSigner (the
// same material published at /.well-known/jwks.json); the legacy shared secret
// remains so pre-cutover HS256 refresh tokens keep working until they expire.
//
// This must stay in lockstep with signPlatformToken: minting ES256 while
// verifying HMAC-only is exactly the bug shipped — login succeeded and
// every subsequent refresh 401'd.
func platformTokenVerifier(jwtSecret string) *jwtkeys.Verifier {
	var keys []jwtkeys.PublicKey
	if platformSigner != nil {
		keys = platformSigner.PublicKeys()
	}
	return jwtkeys.NewVerifier(keys, jwtSecret)
}

// parsePlatformRefreshToken verifies a platform refresh token and returns its
// claims. Extracted so the ES256 path is unit-testable without standing up the
// full RefreshToken handler (DB + cookie jar).
func parsePlatformRefreshToken(tokenString, jwtSecret string) (jwt.MapClaims, error) {
	verifier := platformTokenVerifier(jwtSecret)
	token, err := jwt.Parse(tokenString, verifier.Keyfunc(), verifier.ParserOptions()...)
	if err != nil || token == nil || !token.Valid {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("invalid refresh token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims, nil
}

// defaultPlatformSessionTTL is the platform-admin session length used when the
// operator has never saved a "Session timeout" on the Policy page. It is the
// value that was hardcoded in four places before that setting was wired up.
const defaultPlatformSessionTTL = 7 * 24 * time.Hour

func generateTokens(userID, email, role, jwtSecret string, pwdChangeRequired bool, refreshTTL time.Duration) (string, string, error) {
	// Access token (1 hour — matches the tenant auth-service default).
	// iss/aud match what auth-service issues so all services (e.g. audit-service) accept the token.
	accessClaims := jwt.MapClaims{
		"user_id": userID,
		"email":   email,
		"role":    role,
		"type":    "access",
		"iss":     "crypto-inventory-auth",
		"aud":     jwt.ClaimStrings{"crypto-inventory"},
		"exp":     time.Now().Add(time.Hour).Unix(),
		"iat":     time.Now().Unix(),
		// jti so the access token can be individually revoked via the
		// denylist.
		"jti": uuid.NewString(),
		// csrf carries the session's double-submit value in the token itself
		//so validating services no longer need the shared JWT secret
		// to recompute it. Empty on failure, which falls back to the legacy
		// HMAC(jti) derivation.
		"csrf": newPlatformCSRF(),
	}
	if pwdChangeRequired {
		accessClaims["pwd_change_required"] = true
	}
	accessTokenString, err := signPlatformToken(accessClaims, jwtSecret)
	if err != nil {
		return "", "", err
	}

	refreshClaims := jwt.MapClaims{
		"user_id": userID,
		"email":   email,
		"role":    role,
		"type":    "refresh",
		"iss":     "crypto-inventory-auth",
		"aud":     jwt.ClaimStrings{"crypto-inventory"},
		"exp":     time.Now().Add(refreshTTL).Unix(),
		"iat":     time.Now().Unix(),
	}
	refreshTokenString, err := signPlatformToken(refreshClaims, jwtSecret)
	if err != nil {
		return "", "", err
	}

	return accessTokenString, refreshTokenString, nil
}

// newPlatformCSRF mints the per-session double-submit value embedded in the
// platform access token. A failure returns "", which routes CSRF validation
// back to the legacy HMAC(jti) path rather than breaking login.
func newPlatformCSRF() string {
	v, err := sharedmw.NewCSRFClaim()
	if err != nil {
		return ""
	}
	return v
}
