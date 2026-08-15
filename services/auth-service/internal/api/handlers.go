package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/middleware"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/models"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	audithelpers "github.com/vistasecurity/vistaplatform/shared/middleware/audit"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// revokeCurrentAccessToken adds the access token on the current request to the
// shared revocation denylist, keyed by its jti with TTL = its remaining
// lifetime. This makes logout / change-password immediately invalidate the live
// access token across ALL services (the denylist is enforced data-plane since
//), not just the refresh token. Best-effort: a missing/unparseable token
// or a token with no jti is a silent no-op — the refresh-token revocation that
// the caller already performed still stands.
func (h *AuthHandlers) revokeCurrentAccessToken(c *gin.Context) {
	jti, exp, ok := currentAccessTokenJTIExp(c)
	if !ok {
		return
	}
	ttl := time.Until(exp)
	if ttl <= 0 {
		return // already expired — nothing to deny
	}
	if err := h.authService.RevokeJTI(c.Request.Context(), jti, ttl); err != nil {
		logrus.WithError(err).Warn("failed to denylist access token on logout/password-change")
	}
}

// currentAccessTokenJTIExp extracts the jti and expiry of the request's access
// token. The token has already been signature-validated by RequireAuth, so we
// only ParseUnverified here to read its claims. ok is false when no token is
// present, it can't be parsed, or it carries no jti.
func currentAccessTokenJTIExp(c *gin.Context) (jti string, exp time.Time, ok bool) {
	raw := bearerOrAccessCookieToken(c)
	if raw == "" {
		return "", time.Time{}, false
	}
	// Only the standard jti/exp registered claims are needed; the token was
	// already signature-validated by RequireAuth.
	var claims jwt.RegisteredClaims
	if _, _, err := jwt.NewParser().ParseUnverified(raw, &claims); err != nil {
		return "", time.Time{}, false
	}
	if claims.ID == "" || claims.ExpiresAt == nil {
		return "", time.Time{}, false
	}
	return claims.ID, claims.ExpiresAt.Time, true
}

// bearerOrAccessCookieToken pulls the raw JWT from the Authorization header or
// either of the well-known access-token cookies (tenant + platform).
func bearerOrAccessCookieToken(c *gin.Context) string {
	if h := c.GetHeader("Authorization"); len(h) >= 7 && h[:7] == "Bearer " {
		return h[7:]
	}
	for _, name := range []string{"access_token", "platform_access_token"} {
		if ck, err := c.Cookie(name); err == nil && ck != "" {
			return ck
		}
	}
	return ""
}

// AuthHandlers contains all authentication-related handlers.
//
// The `authService` field is typed as a small interface (`authServiceStore`,
// defined in auth_stores.go) rather than the concrete `*auth.AuthService`.
// This is what makes the cross-cutter `GET /auth/me` handler exercisable from
// `cross_cutter_contract_test.go` with an in-memory stub — no DB, no Redis,
// no real auth dependency tree. `*auth.AuthService` satisfies the interface
// implicitly, so production wiring through `router.go` (and ultimately
// `cmd/main.go`) is untouched. The interface declares every method any
// handler in this file calls, so out-of-scope handlers keep compiling
// against the interface — the contract-test stub fills in no-op returns for
// the methods this slice does not exercise.
type AuthHandlers struct {
	authService authServiceStore
	config      *config.Config
	rateLimiter *middleware.RateLimiter
}

// NewAuthHandlers creates a new instance of auth handlers.
// rateLimiter may be nil — handlers fall back to IP-only middleware
// rate-limiting in that case (e.g. tests, or when REDIS_URL is unset).
func NewAuthHandlers(authService *auth.AuthService, cfg *config.Config, rateLimiter *middleware.RateLimiter) *AuthHandlers {
	return &AuthHandlers{
		authService: authService,
		config:      cfg,
		rateLimiter: rateLimiter,
	}
}

// refreshCookieMaxAge is the lifetime of the refresh-token cookie, and hence of
// the whole session. The JS-readable csrf_token cookie shares it — see
// setAuthCookies.
const refreshCookieMaxAge = 7 * 24 * 60 * 60

// setAuthCookies sets httpOnly cookies for access and refresh tokens, plus a
// non-httpOnly CSRF token cookie that the frontend can read and echo back.
func (h *AuthHandlers) setAuthCookies(c *gin.Context, accessToken, refreshToken string) {
	secure := h.config.CookieSecure
	domain := h.config.CookieDomain

	// Access token — httpOnly, short-lived (matches JWT expiry)
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
		Domain:   domain,
		MaxAge:   int(h.config.JWTExpiry.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})

	// Refresh token — httpOnly, 7 days
	// Path must be "/" so the cookie is sent to both v1 and v2 refresh endpoints
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		Domain:   domain,
		MaxAge:   refreshCookieMaxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})

	// CSRF token — readable by JS (not httpOnly), double-submit pattern, and
	// bound to THIS session via HMAC(access-token jti) so it can't be replayed
	// across sessions.
	//
	// Its MaxAge tracks the REFRESH token, not the access token. The frontend
	// treats this cookie's presence as "a session exists" and only then attempts
	// a silent refresh on a 401. Expiring it with the access token made that
	// signal vanish exactly when the refresh was due: every request 401'd, the
	// refresh was never attempted, no session-expired redirect fired, and each
	// page rendered its own "Couldn't load …" card. The cookie grants nothing on
	// its own — validation is against the CURRENT access token's jti/csrf claim,
	// so a csrf cookie that outlives its access token simply fails until a
	// refresh reissues both.
	if csrfValue := sharedmw.CSRFTokenForAccessToken(h.config.JWTSecret, accessToken); csrfValue != "" {
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "csrf_token",
			Value:    csrfValue,
			Path:     "/",
			Domain:   domain,
			MaxAge:   refreshCookieMaxAge,
			HttpOnly: false,
			Secure:   secure,
			SameSite: http.SameSiteStrictMode,
		})
	}
}

// clearAuthCookies removes all auth-related cookies.
func (h *AuthHandlers) clearAuthCookies(c *gin.Context) {
	domain := h.config.CookieDomain
	secure := h.config.CookieSecure

	for _, name := range []string{"access_token", "csrf_token"} {
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			Domain:   domain,
			MaxAge:   -1,
			HttpOnly: name == "access_token",
			Secure:   secure,
			SameSite: http.SameSiteStrictMode,
		})
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		Domain:   domain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// setAuthCookiesResponseWriter is a standalone helper that sets httpOnly auth
// cookies directly on an http.ResponseWriter. Used by platform SSO flows that
// operate outside of AuthHandlers (e.g. PlatformSSOCallback, CompletePlatformSSORegistration).
func setAuthCookiesResponseWriter(w http.ResponseWriter, cfg *config.Config, accessExpirySeconds int, accessToken, refreshToken string) {
	secure := cfg.CookieSecure
	domain := cfg.CookieDomain

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
		Domain:   domain,
		MaxAge:   accessExpirySeconds,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		Domain:   domain,
		MaxAge:   refreshCookieMaxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})

	// Session-bound CSRF token. MaxAge tracks the refresh token — see
	// setAuthCookies for why.
	if csrfValue := sharedmw.CSRFTokenForAccessToken(cfg.JWTSecret, accessToken); csrfValue != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "csrf_token",
			Value:    csrfValue,
			Path:     "/",
			Domain:   domain,
			MaxAge:   refreshCookieMaxAge,
			HttpOnly: false,
			Secure:   secure,
			SameSite: http.SameSiteStrictMode,
		})
	}
}

// Register handles user registration
func (h *AuthHandlers) Register(c *gin.Context) {
	if rejectIfSignupDisabled(c, h.authService.GetDB()) {
		return
	}
	var req struct {
		models.RegisterRequest
		AcceptedLegal bool `json:"accepted_legal,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	currentLegal, err := fetchCurrentLegalDocuments(c.Request.Context(), h.authService.GetBypassDB())
	if err != nil {
		logrus.WithError(err).Error("Failed to check legal documents at registration")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}
	if len(currentLegal) > 0 && !req.AcceptedLegal {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "You must accept the Terms of Service and Privacy Policy to continue",
		})
		return
	}

	user, err := h.authService.Register(&req.RegisterRequest)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrEmailExists):
			c.JSON(http.StatusConflict, gin.H{
				"error": "Email already exists",
			})
		case errors.Is(err, auth.ErrPersonalEmail):
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Personal email addresses are not allowed. Please use your work email address",
			})
		case errors.Is(err, auth.ErrWeakPassword):
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
		default:
			logrus.WithError(err).Error("Failed to register user")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to register user",
			})
		}
		return
	}

	if len(currentLegal) > 0 {
		if _, err := recordLegalAcceptances(c.Request.Context(), h.authService.GetBypassDB(),
			user.TenantID, user.ID, c.ClientIP(), c.Request.UserAgent(), currentLegal); err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"tenant_id": user.TenantID, "user_id": user.ID,
			}).Error("Failed to record legal acceptance at registration")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
			return
		}
	}

	// Remove password hash from response
	user.PasswordHash = ""

	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully",
		"user":    user,
	})
}

// Login handles user authentication
func (h *AuthHandlers) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	// Per-email rate limit (defense against IP-rotation brute-force).
	// Middleware IP-keyed limiter still runs as a secondary defense.
	if h.rateLimiter != nil {
		allowed, retryAfter, err := h.rateLimiter.AllowByEmail(c.Request.Context(), req.Email)
		if err != nil {
			logrus.WithError(err).Warn("Per-email rate limiter unavailable on /auth/login — failing closed")
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "Authentication is temporarily unavailable. Please try again shortly.",
			})
			return
		}
		if !allowed {
			c.Header("Retry-After", fmt.Sprintf("%.0f", retryAfter.Seconds()))
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Too many sign-in attempts for this account. Try again later.",
				"retry_after": retryAfter.Seconds(),
			})
			return
		}
	}

	// Extract client IP and user agent for device fingerprint
	clientIP := c.ClientIP()
	userAgent := c.Request.UserAgent()

	authResponse, err := h.authService.Login(&req, clientIP, userAgent)
	if err != nil {
		// Audit: log failed login attempt
		if rawMW, exists := c.Get("audit_middleware"); exists {
			if mw, ok := rawMW.(*audithelpers.Middleware); ok {
				errMsg := err.Error()
				switch err {
				case auth.ErrInvalidCredentials:
					errMsg = "Invalid credentials"
				case auth.ErrUserInactive:
					errMsg = "User account inactive"
				case auth.ErrEmailNotVerified:
					errMsg = "Email not verified"
				case auth.ErrAccountLocked:
					errMsg = "Account temporarily locked"
				}
				ipAddr := c.ClientIP()
				ua := c.Request.UserAgent()
				resType := "user"
				// Attach the tenant and user the attempt was against when the
				// email resolves. Without them the entry is untenanted, and the
				// failed-login-burst detector drops untenanted alerts outright
				// (`alerts.tenant_id` is NOT NULL and RLS-partitioned) — so the
				// alert could never open no matter how many failures arrived.
				// Best-effort: an attempt against an unknown address stays
				// untenanted, and the lookup result is never reflected in the
				// response, so this reveals no account-existence signal.
				var tenantID, userID *uuid.UUID
				if existing, lookupErr := h.authService.GetUserByEmail(req.Email); lookupErr == nil && existing != nil {
					tid, uid := existing.TenantID, existing.ID
					tenantID, userID = &tid, &uid
				}
				_ = mw.LogActivity(c.Request.Context(), &audithelpers.ActivityLogRequest{
					TenantID:          tenantID,
					UserID:            userID,
					UserType:          "tenant",
					UserEmail:         &req.Email,
					EventType:         "user.login_failed",
					EventCategory:     "authentication",
					Action:            "login_failed",
					ResourceType:      &resType,
					Success:           false,
					ErrorMessage:      &errMsg,
					IPAddress:         &ipAddr,
					UserAgent:         &ua,
					RequiresAttention: true,
					ComplianceTags:    []string{"soc2", "iso27001", "pci-dss"},
					OccurredAt:        time.Now(),
				})
			}
		}

		switch err {
		case auth.ErrInvalidCredentials:
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid email or password",
			})
		case auth.ErrUserInactive:
			c.JSON(http.StatusForbidden, gin.H{
				"error": "User account is inactive",
			})
		case auth.ErrEmailNotVerified:
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Email not verified",
			})
		case auth.ErrAccountLocked:
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Account temporarily locked. Try again later.",
			})
		default:
			logrus.WithError(err).Error("Failed to authenticate user")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to authenticate user",
			})
		}
		return
	}

	// Audit: log successful login with full tenant and user context
	if rawMW, exists := c.Get("audit_middleware"); exists {
		if mw, ok := rawMW.(*audithelpers.Middleware); ok {
			tenantID := authResponse.User.TenantID
			userID := authResponse.User.ID
			email := authResponse.User.Email
			ipAddr := c.ClientIP()
			ua := c.Request.UserAgent()
			resType := "user"
			_ = mw.LogActivity(c.Request.Context(), &audithelpers.ActivityLogRequest{
				TenantID:       &tenantID,
				UserID:         &userID,
				UserType:       "tenant",
				UserEmail:      &email,
				EventType:      "user.login",
				EventCategory:  "authentication",
				Action:         "login",
				ResourceType:   &resType,
				ResourceID:     &userID,
				Success:        true,
				IPAddress:      &ipAddr,
				UserAgent:      &ua,
				ComplianceTags: []string{"soc2", "iso27001", "pci-dss"},
				OccurredAt:     time.Now(),
			})
		}
	}

	// Remove password hash from response
	authResponse.User.PasswordHash = ""

	// Set httpOnly cookies so frontends don't need localStorage
	h.setAuthCookies(c, authResponse.AccessToken, authResponse.RefreshToken)

	c.JSON(http.StatusOK, authResponse)
}

// Logout handles user logout
func (h *AuthHandlers) Logout(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Invalid user ID",
		})
		return
	}

	err = h.authService.Logout(userID)
	if err != nil {
		logrus.WithError(err).WithField("user_id", userID).Error("Failed to logout")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to logout",
		})
		return
	}

	// Kill the live access token too, not just refresh tokens.
	h.revokeCurrentAccessToken(c)

	// Audit: log logout with full tenant and user context
	if rawMW, exists := c.Get("audit_middleware"); exists {
		if mw, ok := rawMW.(*audithelpers.Middleware); ok {
			ipAddr := c.ClientIP()
			ua := c.Request.UserAgent()
			resType := "user"
			logEntry := &audithelpers.ActivityLogRequest{
				UserID:         &userID,
				UserType:       "tenant",
				EventType:      "user.logout",
				EventCategory:  "authentication",
				Action:         "logout",
				ResourceType:   &resType,
				ResourceID:     &userID,
				Success:        true,
				IPAddress:      &ipAddr,
				UserAgent:      &ua,
				ComplianceTags: []string{"soc2", "iso27001"},
				OccurredAt:     time.Now(),
			}
			if tenantIDStr := c.GetString("tenantID"); tenantIDStr != "" {
				if tid, err := uuid.Parse(tenantIDStr); err == nil {
					logEntry.TenantID = &tid
				}
			}
			if emailStr := c.GetString("email"); emailStr != "" {
				logEntry.UserEmail = &emailStr
			}
			_ = mw.LogActivity(c.Request.Context(), logEntry)
		}
	}

	// Clear auth cookies
	h.clearAuthCookies(c)

	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
	})
}

// RefreshToken handles token refresh
func (h *AuthHandlers) RefreshToken(c *gin.Context) {
	var req models.RefreshTokenRequest
	// Allow empty body — the refresh token may come from httpOnly cookie
	_ = c.ShouldBindJSON(&req)

	// Fall back to httpOnly cookie if no token in request body
	if req.RefreshToken == "" {
		if cookie, err := c.Cookie("refresh_token"); err == nil && cookie != "" {
			req.RefreshToken = cookie
		}
	}
	if req.RefreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Refresh token required",
		})
		return
	}

	// Extract client IP and user agent for device fingerprint
	clientIP := c.ClientIP()
	userAgent := c.Request.UserAgent()

	authResponse, err := h.authService.RefreshToken(req.RefreshToken, clientIP, userAgent)
	if err != nil {
		switch err {
		case auth.ErrInvalidToken, auth.ErrExpiredToken:
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired refresh token",
			})
		case auth.ErrTokenReuseDetected:
			logrus.WithError(err).Warn("Refresh token reuse detected")
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Token reuse detected - all sessions revoked for security",
			})
		case auth.ErrUserNotFound:
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Session invalid, please sign in again",
			})
		default:
			logrus.WithError(err).Error("Failed to refresh token")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to refresh token",
			})
		}
		return
	}

	// Remove password hash from response
	authResponse.User.PasswordHash = ""

	// Rotate auth cookies
	h.setAuthCookies(c, authResponse.AccessToken, authResponse.RefreshToken)

	c.JSON(http.StatusOK, authResponse)
}

// GetMe returns current user information along with tenant data
func (h *AuthHandlers) GetMe(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	// Handle type assertion safely
	var userIDStrValue string
	switch v := userIDStr.(type) {
	case string:
		userIDStrValue = v
	case uuid.UUID:
		userIDStrValue = v.String()
	default:
		logrus.WithField("type", fmt.Sprintf("%T", userIDStr)).Error("GetMe: userID in context has unexpected type")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Invalid user ID type",
		})
		return
	}

	if userIDStrValue == "" || userIDStrValue == "system" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	userID, err := uuid.Parse(userIDStrValue)
	if err != nil {
		logrus.WithError(err).WithField("user_id", userIDStrValue).Error("GetMe: failed to parse userID")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Invalid user ID",
		})
		return
	}

	user, err := h.authService.GetUserByID(userID)
	if err != nil {
		if err == auth.ErrUserNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User not found",
			})
		} else {
			logrus.WithError(err).WithField("user_id", userID).Error("Failed to get user")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get user",
			})
		}
		return
	}

	// Remove password hash from response
	user.PasswordHash = ""

	// Fetch tenant data
	tenant, err := h.authService.GetTenantByID(user.TenantID)
	if err != nil {
		// Log error but don't fail - user info is still valid
		c.JSON(http.StatusOK, gin.H{
			"user": user,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user":   user,
		"tenant": tenant,
	})
}

// UpdateMe handles user profile updates
func (h *AuthHandlers) UpdateMe(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Invalid user ID",
		})
		return
	}

	var req models.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	user, err := h.authService.UpdateUser(userID, &req)
	if err != nil {
		switch err {
		case auth.ErrEmailExists:
			c.JSON(http.StatusConflict, gin.H{
				"error": "Email already exists",
			})
		case auth.ErrUserNotFound:
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User not found",
			})
		default:
			logrus.WithError(err).WithField("user_id", userID).Error("Failed to update user")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to update user",
			})
		}
		return
	}

	// Remove password hash from response
	user.PasswordHash = ""

	c.JSON(http.StatusOK, gin.H{
		"message": "User updated successfully",
		"user":    user,
	})
}

// ListSessions returns active sessions for the current user
func (h *AuthHandlers) ListSessions(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Invalid user ID",
		})
		return
	}

	sessions, err := h.authService.GetUserSessions(userID)
	if err != nil {
		logrus.WithError(err).WithField("user_id", userID).Error("Failed to get sessions")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get sessions",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions": sessions,
	})
}

// RevokeSession revokes a specific session
func (h *AuthHandlers) RevokeSession(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Invalid user ID",
		})
		return
	}

	sessionIDStr := c.Param("id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid session ID",
		})
		return
	}

	err = h.authService.RevokeRefreshToken(userID, sessionID)
	if err != nil {
		if err == auth.ErrUserNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Session not found",
			})
		} else {
			logrus.WithError(err).WithField("session_id", sessionID).Error("Failed to revoke session")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to revoke session",
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Session revoked successfully",
	})
}

// ListConnections returns authentication connections for the current user
func (h *AuthHandlers) ListConnections(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Invalid user ID",
		})
		return
	}

	connections, err := h.authService.GetUserAuthMethods(userID)
	if err != nil {
		logrus.WithError(err).WithField("user_id", userID).Error("Failed to get connections")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get connections",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"connections": connections,
	})
}

// SetPrimaryAuth sets a connection as the primary authentication method
func (h *AuthHandlers) SetPrimaryAuth(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Invalid user ID",
		})
		return
	}

	connectionIDStr := c.Param("id")
	connectionID, err := uuid.Parse(connectionIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid connection ID",
		})
		return
	}

	err = h.authService.SetPrimaryAuthMethod(userID, connectionID)
	if err != nil {
		if err == auth.ErrUserNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Connection not found",
			})
		} else {
			logrus.WithError(err).WithField("connection_id", connectionID).Error("Failed to set primary auth")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to set primary auth",
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Primary authentication method updated",
	})
}

// UploadAvatar handles avatar file uploads
func (h *AuthHandlers) UploadAvatar(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Invalid user ID",
		})
		return
	}

	// Get uploaded file
	file, err := c.FormFile("avatar")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "No avatar file provided",
		})
		return
	}

	// Validate file size (5MB limit)
	if file.Size > 5*1024*1024 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "File too large. Maximum size is 5MB.",
		})
		return
	}

	// Validate the file by its MAGIC BYTES — not the attacker-controlled
	// Content-Type header or filename. SVG is rejected (no raster magic); it can
	// embed JavaScript and is a stored-XSS vector.
	allowedAvatarTypes := map[string]bool{
		"image/jpeg": true,
		"image/png":  true,
		"image/gif":  true,
		"image/webp": true,
	}
	img, ok := sniffImageType(file)
	if !ok || !allowedAvatarTypes[img.MIME] {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid file type. Only JPEG, PNG, GIF, and WebP images are allowed.",
		})
		return
	}

	// Generate unique filename — the extension is server-authoritative, derived
	// from the sniffed image type, never from the caller's filename.
	filename := fmt.Sprintf("%s%s", uuid.New().String(), img.Ext)

	// Create uploads directory if it doesn't exist
	uploadDir := "uploads/avatars"
	if err := os.MkdirAll(uploadDir, 0o750); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create upload directory",
		})
		return
	}

	// Save file
	filePath := filepath.Join(uploadDir, filename)
	if err := c.SaveUploadedFile(file, filePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to save file",
		})
		return
	}

	// Update user's avatar URL in database
	avatarURL := fmt.Sprintf("/uploads/avatars/%s", filename)
	err = h.authService.UpdateUserAvatar(userID, avatarURL)
	if err != nil {
		// Clean up uploaded file
		_ = os.Remove(filePath)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update avatar",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Avatar uploaded successfully",
		"avatar_url": avatarURL,
	})
}

// ChangePassword handles password changes
func (h *AuthHandlers) ChangePassword(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Invalid user ID",
		})
		return
	}

	var req models.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	err = h.authService.ChangePassword(userID, &req)
	if err != nil {
		// Audit: log failed password change
		if rawMW, exists := c.Get("audit_middleware"); exists {
			if mw, ok := rawMW.(*audithelpers.Middleware); ok {
				_ = audithelpers.LogSimple(c.Request.Context(), mw,
					"user.password_change_failed", "user", "password_change",
					"user", userID.String(), "", false, err.Error())
			}
		}

		switch err {
		case auth.ErrInvalidCredentials:
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Current password is incorrect",
			})
		case auth.ErrUserNotFound:
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User not found",
			})
		default:
			logrus.WithError(err).WithField("user_id", userID).Error("Failed to change password")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to change password",
			})
		}
		return
	}

	// Changing the password kills the live access token too, not just refresh
	// tokens — a password change should evict the current session
	// everywhere immediately.
	h.revokeCurrentAccessToken(c)

	// Audit: log successful password change
	if rawMW, exists := c.Get("audit_middleware"); exists {
		if mw, ok := rawMW.(*audithelpers.Middleware); ok {
			_ = audithelpers.LogSimple(c.Request.Context(), mw,
				"user.password_changed", "user", "password_change",
				"user", userID.String(), "", true, "")
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password changed successfully",
	})
}

// ForgotPassword handles password reset requests
func (h *AuthHandlers) ForgotPassword(c *gin.Context) {
	var req models.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	// Per-email rate limit — prevents one attacker from triggering an
	// avalanche of reset emails for a victim address by spraying many IPs.
	// Constant-time response either way so a denial here doesn't leak the
	// email's existence.
	if h.rateLimiter != nil {
		allowed, _, err := h.rateLimiter.AllowByEmail(c.Request.Context(), req.Email)
		if err != nil {
			logrus.WithError(err).Warn("Per-email rate limiter unavailable on /auth/password/forgot — failing closed")
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "Password reset is temporarily unavailable. Please try again shortly.",
			})
			return
		}
		if !allowed {
			c.JSON(http.StatusOK, gin.H{
				"message": "If the email exists, a password reset link has been sent",
			})
			return
		}
	}

	err := h.authService.ForgotPassword(&req)
	if err != nil {
		logrus.WithError(err).Error("Failed to process password reset request")
	}

	// Always return success for security (don't reveal if email exists)
	c.JSON(http.StatusOK, gin.H{
		"message": "If the email exists, a password reset link has been sent",
	})
}

// ResetPassword handles password reset with token
func (h *AuthHandlers) ResetPassword(c *gin.Context) {
	var req models.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	err := h.authService.ResetPassword(&req)
	if err != nil {
		switch err {
		case auth.ErrInvalidToken:
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid or expired reset token",
			})
		case auth.ErrExpiredToken:
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Reset token has expired",
			})
		default:
			logrus.WithError(err).Error("Failed to reset password")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to reset password",
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password reset successfully",
	})
}

// VerifyEmail handles email verification
func (h *AuthHandlers) VerifyEmail(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Verification token is required",
		})
		return
	}

	err := h.authService.VerifyEmail(token)
	if err != nil {
		switch err {
		case auth.ErrInvalidToken:
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid verification token",
			})
		case auth.ErrExpiredToken:
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Verification token has expired",
			})
		default:
			logrus.WithError(err).Error("Failed to verify email")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to verify email",
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Email verified successfully",
	})
}

// ResendEmailVerification handles resending email verification
func (h *AuthHandlers) ResendEmailVerification(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	// Get user by email — return same response regardless of whether user exists
	// to prevent user enumeration attacks
	successResponse := gin.H{"message": "If the email exists and is unverified, a verification email has been sent"}

	user, err := h.authService.GetUserByEmail(req.Email)
	if err != nil {
		if err == auth.ErrUserNotFound {
			c.JSON(http.StatusOK, successResponse)
			return
		}
		logrus.WithError(err).Error("Failed to get user for email verification resend")
		c.JSON(http.StatusOK, successResponse)
		return
	}

	// Check if already verified
	if user.EmailVerified {
		c.JSON(http.StatusOK, successResponse)
		return
	}

	// Send verification email
	err = h.authService.SendEmailVerification(user.ID)
	if err != nil {
		logrus.WithError(err).WithField("user_id", user.ID).Error("Failed to send verification email")
		c.JSON(http.StatusOK, successResponse)
		return
	}

	c.JSON(http.StatusOK, successResponse)
}

// AcceptEULA handles EULA acceptance
func (h *AuthHandlers) AcceptEULA(c *gin.Context) {
	// Get user ID from JWT token
	userIDStr, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid user ID",
		})
		return
	}

	var req struct {
		EulaVersion string `json:"eula_version" binding:"required"`
		Accepted    bool   `json:"accepted" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	if !req.Accepted {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "EULA must be accepted",
		})
		return
	}

	// Update user's EULA acceptance.
	// RLS: cross-tenant — runs on the bypass role (Phase 4). Self-service write on
	// users keyed only by the JWT's user id; tenant not threaded here. Wrapping
	// would fail closed.
	_, err = h.authService.GetBypassDB().Exec(`
		UPDATE users
		SET eula_accepted_at = NOW(),
		    eula_version = $1,
		    updated_at = NOW()
		WHERE id = $2
	`, req.EulaVersion, userID)

	if err != nil {
		logrus.WithError(err).WithField("user_id", userID).Error("Failed to accept EULA")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to accept EULA",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "EULA accepted successfully",
	})
}

// CompleteRegistration handles registration completion with tier selection
func (h *AuthHandlers) CompleteRegistration(c *gin.Context) {
	if rejectIfSignupDisabled(c, h.authService.GetDB()) {
		return
	}
	var req struct {
		models.RegisterRequest
		SubscriptionTierID *uuid.UUID `json:"subscription_tier_id,omitempty"`
		AcceptedLegal      bool       `json:"accepted_legal,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	// Legal gate: if any legal documents are currently published, the signup
	// must affirmatively accept them. Enforced server-side so the UI checkbox
	// can't be bypassed. No published docs => nothing to accept (gate passes).
	pendingDocs, err := fetchCurrentLegalDocuments(c.Request.Context(), h.authService.GetBypassDB())
	if err != nil {
		logrus.WithError(err).Error("Failed to check legal documents at registration")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}
	if len(pendingDocs) > 0 && !req.AcceptedLegal {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "You must accept the Terms of Service and Privacy Policy to continue",
		})
		return
	}
	if req.SubscriptionTierID != nil {
		if err := validateSelfServiceTierSelection(c.Request.Context(), h.authService.GetDB(), *req.SubscriptionTierID); err != nil {
			if errors.Is(err, errTierNotSelfSelectable) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "subscription tier is not available for self-service selection"})
				return
			}
			logrus.WithError(err).Error("Failed to validate subscription tier at registration")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
			return
		}
	}

	// Register user (this creates tenant and user)
	user, err := h.authService.Register(&req.RegisterRequest)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrEmailExists):
			c.JSON(http.StatusConflict, gin.H{
				"error": "Email already exists",
			})
		case errors.Is(err, auth.ErrPersonalEmail):
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Personal email addresses are not allowed. Please use your work email address",
			})
		case errors.Is(err, auth.ErrWeakPassword):
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
		default:
			logrus.WithError(err).Error("Failed to complete registration")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to register user",
			})
		}
		return
	}

	// Record the tenant founder's acceptance of the current legal documents as
	// an append-only evidence row (server-observed IP + UA). Fail closed: once
	// current legal documents exist, signup must not report success unless the
	// acceptance evidence was written.
	if len(pendingDocs) > 0 {
		if _, err := recordLegalAcceptances(c.Request.Context(), h.authService.GetBypassDB(),
			user.TenantID, user.ID, c.ClientIP(), c.Request.UserAgent(), pendingDocs); err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"tenant_id": user.TenantID, "user_id": user.ID,
			}).Error("Failed to record legal acceptance at signup")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
			return
		}
	}

	// Only trust the signup tier selection when it actually persisted; if the
	// UPDATE fails the tenant retains the default signup tier assigned at
	// creation (auth.DefaultSignupTierName) — skip trial bootstrap so we never
	// seed a tracking row against the wrong plan.
	tierSelectionApplied := req.SubscriptionTierID == nil
	if req.SubscriptionTierID != nil {
		// tenants is a GLOBAL table (no tenant_isolation policy). Left unwrapped.
		_, err = h.authService.GetDB().Exec(`
			UPDATE tenants
			SET subscription_tier_id = $1,
			    onboarding_status = 'tier_selected',
			    updated_at = NOW()
			WHERE id = $2
		`, *req.SubscriptionTierID, user.TenantID)

		if err != nil {
			// Log error but don't fail registration.
			// The tenant keeps the default signup tier assigned at creation.
			logrus.WithError(err).WithField("tenant_id", user.TenantID).
				Warn("Failed to persist subscription tier at registration completion")
		} else {
			tierSelectionApplied = true
		}
	}

	// Bootstrap a trial row if the selected tier is configured as a trial
	// tier (Free, today). No-op on paid tiers. Non-blocking — a failure
	// here doesn't roll back signup; the platform admin can manually run
	// TrialManager.CreateTrial if a tenant slips through without one.
	if tierSelectionApplied {
		if err := h.authService.BootstrapTrialIfApplicable(user.TenantID); err != nil {
			logrus.WithError(err).WithField("tenant_id", user.TenantID).
				Warn("Failed to bootstrap trial at signup")
		}
	}

	// Remove password hash from response
	user.PasswordHash = ""

	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully",
		"user":    user,
	})
}

// GetOnboardingStatus returns the current onboarding status for the authenticated user
func (h *AuthHandlers) GetOnboardingStatus(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid user ID",
		})
		return
	}

	var tenantID uuid.UUID
	var onboardingStatus string
	var eulaAcceptedAt, onboardingCompletedAt *time.Time
	var eulaVersion *string

	// RLS: cross-tenant — runs on the bypass role (Phase 4). Resolves the tenant
	// FROM the JWT's user id (tenant is the query OUTPUT). Wrapping would fail closed.
	err = h.authService.GetBypassDB().QueryRow(`
		SELECT u.tenant_id, t.onboarding_status, u.eula_accepted_at,
		       u.eula_version, u.onboarding_completed_at
		FROM users u
		JOIN tenants t ON u.tenant_id = t.id
		WHERE u.id = $1
	`, userID).Scan(&tenantID, &onboardingStatus, &eulaAcceptedAt, &eulaVersion, &onboardingCompletedAt)

	if err != nil {
		logrus.WithError(err).WithField("user_id", userID).Error("Failed to get onboarding status")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get onboarding status",
		})
		return
	}

	status := gin.H{
		"tenant_id":           tenantID,
		"onboarding_status":   onboardingStatus,
		"eula_accepted":       eulaAcceptedAt != nil,
		"onboarding_complete": onboardingCompletedAt != nil,
	}

	if eulaAcceptedAt != nil {
		status["eula_accepted_at"] = eulaAcceptedAt
		status["eula_version"] = eulaVersion
	}
	if onboardingCompletedAt != nil {
		status["onboarding_completed_at"] = onboardingCompletedAt
	}

	c.JSON(http.StatusOK, status)
}

// SelectTier handles tier selection for authenticated users
func (h *AuthHandlers) SelectTier(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
		return
	}

	var req struct {
		SubscriptionTierID uuid.UUID `json:"subscription_tier_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Get user's tenant_id.
	// RLS: cross-tenant — runs on the bypass role (Phase 4). Resolves tenant FROM
	// the JWT's user id (tenant is the query OUTPUT). Wrapping would fail closed.
	var tenantID uuid.UUID
	err = h.authService.GetBypassDB().QueryRow(
		"SELECT tenant_id FROM users WHERE id = $1", userID,
	).Scan(&tenantID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant"})
		return
	}

	if err := validateSelfServiceTierSelection(c.Request.Context(), h.authService.GetDB(), req.SubscriptionTierID); err != nil {
		if errors.Is(err, errTierNotSelfSelectable) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "subscription tier is not available for self-service selection"})
			return
		}
		logrus.WithError(err).WithField("tier_id", req.SubscriptionTierID).Error("Failed to validate subscription tier")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate tier"})
		return
	}

	// Update tenant tier.
	// tenants is a GLOBAL table (no tenant_isolation policy). Left unwrapped.
	_, err = h.authService.GetDB().Exec(`
		UPDATE tenants
		SET subscription_tier_id = $1,
		    onboarding_status = 'tier_selected',
		    updated_at = NOW()
		WHERE id = $2
	`, req.SubscriptionTierID, tenantID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update tier"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Tier selected successfully"})
}

var errTierNotSelfSelectable = errors.New("subscription tier is not self-service selectable")

func validateSelfServiceTierSelection(ctx context.Context, db *sql.DB, tierID uuid.UUID) error {
	if db == nil {
		return errors.New("database is not configured")
	}

	var selectable int
	err := db.QueryRowContext(ctx, `
		SELECT 1
		FROM subscription_tiers
		WHERE id = $1
		  AND is_active = true
		  AND COALESCE(is_custom, false) = false
		  AND owner_tenant_id IS NULL
		  AND COALESCE(is_trial, false) = true
	`, tierID).Scan(&selectable)
	if errors.Is(err, sql.ErrNoRows) {
		return errTierNotSelfSelectable
	}
	if err != nil {
		return err
	}
	return nil
}

// UpdateOnboardingProgress updates the onboarding workflow progress
func (h *AuthHandlers) UpdateOnboardingProgress(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid user ID",
		})
		return
	}

	var req struct {
		StepID    string                 `json:"step_id" binding:"required"`
		Completed bool                   `json:"completed"`
		Data      map[string]interface{} `json:"data,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	// Get default onboarding workflow.
	// RLS NOTE (flag for Phase 4): workflow_configurations carries a
	// tenant_isolation policy, but this query selects the platform-default row
	// (tenant_id IS NULL) with no app.tenant_id set. On the bypass role this is
	// fine; once a non-owner role enforces RLS this default row would be hidden
	// (`(NULL)::text = current_setting(...)` is NULL). The policy needs a
	// NULL-tenant default allowance before Phase 4 — same gap as
	// onboarding_repository.GetOnboardingWorkflowConfig. Left on the bypass path.
	var workflowID uuid.UUID
	err = h.authService.GetDB().QueryRow(`
		SELECT id FROM workflow_configurations
		WHERE workflow_type = 'onboarding' AND is_default = true
		LIMIT 1
	`).Scan(&workflowID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Onboarding workflow not found",
		})
		return
	}

	// Update or insert progress.
	// user_workflow_progress is a GLOBAL table (no tenant_isolation policy). Left unwrapped.
	_, err = h.authService.GetDB().Exec(`
		INSERT INTO user_workflow_progress (user_id, workflow_configuration_id, current_step, completed_steps, step_data, status)
		VALUES ($1, $2, 0, ARRAY[$3]::text[], $4::jsonb, 'in_progress')
		ON CONFLICT (user_id, workflow_configuration_id)
		DO UPDATE SET
			completed_steps = CASE
				WHEN $5 = true THEN completed_steps || ARRAY[$3]::text[]
				ELSE completed_steps
			END,
			step_data = step_data || $4::jsonb,
			updated_at = NOW()
	`, userID, workflowID, req.StepID, req.Data, req.Completed)

	if err != nil {
		logrus.WithError(err).WithField("user_id", userID).Error("Failed to update onboarding progress")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update onboarding progress",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Onboarding progress updated",
	})
}

// GetNotificationPreferences returns notification preferences for the current user
func (h *AuthHandlers) GetNotificationPreferences(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Invalid user ID",
		})
		return
	}

	prefs, err := h.authService.GetNotificationPreferences(userID)
	if err != nil {
		logrus.WithError(err).WithField("user_id", userID).Error("Failed to get notification preferences")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get notification preferences",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"preferences": prefs,
	})
}

// UpdateNotificationPreferences updates notification preferences for the current user
func (h *AuthHandlers) UpdateNotificationPreferences(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Invalid user ID",
		})
		return
	}

	var prefs map[string]interface{}
	if err := c.ShouldBindJSON(&prefs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	if err := h.authService.UpdateNotificationPreferences(userID, prefs); err != nil {
		logrus.WithError(err).WithField("user_id", userID).Error("Failed to update notification preferences")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update notification preferences",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Notification preferences updated successfully",
	})
}
