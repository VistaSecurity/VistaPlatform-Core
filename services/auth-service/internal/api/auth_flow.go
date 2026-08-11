package api

// Email-first authentication dispatcher.
//
// This is the flexible, frontend-agnostic login flow: the browser posts an
// email, gets back the list of methods that email may authenticate with, then
// authenticates with one of them. It is Core — every user, in every edition,
// hits this path to sign in.
//
// It used to live in `sso.go` alongside the SSO implementation, which made the
// file look Enterprise-only when in fact it holds the one code path no install
// can do without. The SSO half now lives in services/auth-service/ee/sso/ and
// reaches this file only through the SSOMethodEnumerator seam declared in
// edition.go — so a Core build enumerates password methods and nothing else,
// and never touches the sso_providers table from here.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// passwordMethod is the one login method every edition always offers.
func passwordMethod() map[string]interface{} {
	return map[string]interface{}{
		"type":    "password",
		"enabled": true,
	}
}

// AuthInitiate handles POST /auth/initiate - Initiate authentication
func AuthInitiate(bypassDB *sql.DB, redisClient *redis.Client, ssoMethods SSOMethodEnumerator) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Email string `json:"email" binding:"required,email"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
			return
		}

		// Create session
		sessionID := uuid.New().String()
		sessionData := map[string]interface{}{
			"email":      req.Email,
			"created_at": time.Now().Unix(),
		}
		sessionJSON, _ := json.Marshal(sessionData)

		// Store session in Redis (expires in 15 minutes)
		sessionKey := fmt.Sprintf("auth:session:%s", sessionID)
		redisClient.Set(context.Background(), sessionKey, sessionJSON, 15*time.Minute)

		// Get available auth methods for this email
		methods := []map[string]interface{}{}

		// Check if user exists
		// RLS: cross-tenant — runs on the bypass role (Phase 4). Resolves email → tenant at login (the tenant is the query OUTPUT, not yet known). Wrapping would fail closed.
		var userID uuid.UUID
		var tenantID uuid.UUID
		err := bypassDB.QueryRow(`
			SELECT id, tenant_id FROM users WHERE email = $1 AND deleted_at IS NULL
		`, strings.ToLower(req.Email)).Scan(&userID, &tenantID)

		// Password is offered either way: an unknown email falls through to
		// password registration, exactly as before the carve.
		methods = append(methods, passwordMethod())
		if err == nil {
			// Tenant-configured SSO providers. Always empty in Core.
			methods = append(methods, ssoMethods.TenantMethods(c.Request.Context(), tenantID)...)
		}

		c.JSON(http.StatusOK, gin.H{
			"session_id":        sessionID,
			"available_methods": methods,
		})
	}
}

// AuthMethods handles POST /auth/methods - Get available auth methods
func AuthMethods(bypassDB *sql.DB, ssoMethods SSOMethodEnumerator) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Email string `json:"email" binding:"required,email"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
			return
		}

		email := req.Email

		methods := []map[string]interface{}{}
		// tenantID of the resolved user, surfaced so the shared login page can
		// build the SSO authorize URL (/auth/sso/<provider_name>/authorize?
		// tenant_id=...) without a second round-trip. Empty when the user is
		// unknown — tenant ids are not secret (the authorize endpoint already
		// takes tenant_id as a public query param).
		var tenantIDStr string

		// Check if user exists
		// RLS: cross-tenant — runs on the bypass role (Phase 4). Resolves email → tenant at login (the tenant is the query OUTPUT, not yet known). Wrapping would fail closed.
		var userID uuid.UUID
		var tenantID uuid.UUID
		err := bypassDB.QueryRow(`
			SELECT id, tenant_id FROM users WHERE email = $1 AND deleted_at IS NULL
		`, strings.ToLower(email)).Scan(&userID, &tenantID)

		// Password is always offered; an unknown email gets password only.
		methods = append(methods, passwordMethod())

		if err == nil {
			tenantIDStr = tenantID.String()

			// Tenant-configured SSO providers. Always empty in Core, so a Core
			// build answers password-only and never reads sso_providers here.
			tenantSSO := ssoMethods.TenantMethods(c.Request.Context(), tenantID)
			methods = append(methods, tenantSSO...)

			// Platform ("social signup") SSO is only a fallback for tenants that
			// configured no SSO of their own. The enumerator additionally applies
			// the tenant's authentication policy and the user's linked platform
			// identities — all Enterprise concerns. Always empty in Core.
			if len(tenantSSO) == 0 {
				methods = append(methods, ssoMethods.PlatformMethods(c.Request.Context(), userID, tenantID)...)
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"email":     email,
			"tenant_id": tenantIDStr,
			"methods":   methods,
		})
	}
}

// AuthAuthenticate handles POST /auth/authenticate - Authenticate with selected method
func AuthAuthenticate(cfg *config.Config, db *sql.DB, bypassDB *sql.DB, redisClient *redis.Client, jwtService *auth.JWTService, ssoMethods SSOMethodEnumerator) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			SessionID   string                 `json:"session_id" binding:"required"`
			Method      string                 `json:"method" binding:"required"`
			Credentials map[string]interface{} `json:"credentials"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
			return
		}

		// Get session
		sessionKey := fmt.Sprintf("auth:session:%s", req.SessionID)
		sessionDataJSON, err := redisClient.Get(context.Background(), sessionKey).Result()
		if err == redis.Nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired session"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get session"})
			return
		}

		var sessionData map[string]interface{}
		if err := json.Unmarshal([]byte(sessionDataJSON), &sessionData); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse session data"})
			return
		}

		email, _ := sessionData["email"].(string)
		if email == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Email not found in session"})
			return
		}

		// Route to appropriate authentication method
		switch req.Method {
		case "password":
			password, ok := req.Credentials["password"].(string)
			if !ok {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Password is required"})
				return
			}

			// Use existing login logic
			authService := auth.NewAuthService(db, bypassDB, redisClient, jwtService)
			loginReq := &models.LoginRequest{
				Email:    email,
				Password: password,
			}
			clientIP := c.ClientIP()
			userAgent := c.GetHeader("User-Agent")
			authResponse, err := authService.Login(loginReq, clientIP, userAgent)

			if err != nil {
				switch err {
				case auth.ErrInvalidCredentials:
					c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
				case auth.ErrUserInactive:
					c.JSON(http.StatusForbidden, gin.H{"error": "User account is inactive"})
				case auth.ErrEmailNotVerified:
					c.JSON(http.StatusForbidden, gin.H{"error": "Email not verified"})
				default:
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Authentication failed"})
				}
				return
			}

			// Delete session
			redisClient.Del(context.Background(), sessionKey)

			c.JSON(http.StatusOK, gin.H{
				"access_token":  authResponse.AccessToken,
				"refresh_token": authResponse.RefreshToken,
				"expires_in":    authResponse.ExpiresIn,
				"user":          authResponse.User,
			})
			return
		case "sso":
			// For SSO, redirect to authorize endpoint
			providerID, ok := req.Credentials["provider_id"].(string)
			if !ok {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Provider ID is required for SSO"})
				return
			}

			// Get tenant ID from email
			// RLS: cross-tenant — runs on the bypass role (Phase 4). Resolves email → tenant at login (the tenant is the query OUTPUT, not yet known). Wrapping would fail closed.
			var tenantID uuid.UUID
			err = bypassDB.QueryRow(`
				SELECT tenant_id FROM users WHERE email = $1 AND deleted_at IS NULL
			`, strings.ToLower(email)).Scan(&tenantID)

			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "User not found"})
				return
			}

			// Resolving the provider — and therefore the authorize URL — is the
			// Enterprise half. Core's enumerator never resolves one, which lands
			// on the same 404 a Core install would reach anyway: with no SSO
			// config surface there are no providers to name.
			redirectURL, ok := ssoMethods.AuthorizeRedirect(c.Request.Context(), tenantID, providerID)
			if !ok {
				c.JSON(http.StatusNotFound, gin.H{"error": "SSO provider not found"})
				return
			}

			c.Redirect(http.StatusFound, redirectURL)
			return
		}

		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported authentication method"})
	}
}

// AuthComplete handles POST /auth/complete - Complete authentication
func AuthComplete(cfg *config.Config, db *sql.DB, bypassDB *sql.DB, redisClient *redis.Client, jwtService *auth.JWTService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			SessionID string `json:"session_id" binding:"required"`
			Token     string `json:"token"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
			return
		}

		// Get session
		sessionKey := fmt.Sprintf("auth:session:%s", req.SessionID)
		_, err := redisClient.Get(context.Background(), sessionKey).Result()
		if err == redis.Nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired session"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get session"})
			return
		}

		// Delete session
		redisClient.Del(context.Background(), sessionKey)

		// If token provided, validate and return user info
		if req.Token != "" {
			claims, err := jwtService.ValidateToken(req.Token)
			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
				return
			}

			// Get user
			// RLS: cross-tenant — runs on the bypass role (Phase 4). Looks up the user by primary key (id) from the validated token; tenant_id is not an input. Wrapping would fail closed.
			var userEmail string
			var userID, tenantID uuid.UUID
			err = bypassDB.QueryRow(`
				SELECT id, tenant_id, email FROM users WHERE id = $1
			`, claims.UserID).Scan(&userID, &tenantID, &userEmail)

			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
				return
			}

			// Get user's primary role from RBAC system
			// RLS-scoped: tenant_roles + user_tenant_roles tenant_isolation policies; tenant now known from the by-id user lookup above.
			var userRole string
			err = shareddatabase.WithTenantTx(c.Request.Context(), db, tenantID, func(tx *sql.Tx) error {
				return tx.QueryRowContext(c.Request.Context(), `
					SELECT tr.name
					FROM tenant_roles tr
					JOIN user_tenant_roles utr ON tr.id = utr.role_id
					WHERE utr.user_id = $1 AND tr.tenant_id = $2 AND utr.is_active = true
					  AND (utr.expires_at IS NULL OR utr.expires_at > NOW())
					ORDER BY utr.assigned_at DESC
					LIMIT 1
				`, userID, tenantID).Scan(&userRole)
			})
			if err != nil {
				// Default to "viewer" if no role found
				userRole = "viewer"
			}

			c.JSON(http.StatusOK, gin.H{
				"user": gin.H{
					"id":    userID.String(),
					"email": userEmail,
					"role":  userRole,
				},
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Authentication completed"})
	}
}
