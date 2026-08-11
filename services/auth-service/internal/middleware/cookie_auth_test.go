package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newTestJWTService() *auth.JWTService {
	return auth.NewJWTService("test-secret-32-chars-minimum!!", 15*time.Minute, 7*24*time.Hour)
}

func newTestConfig() *config.Config {
	return &config.Config{
		JWTSecret:   "test-secret-32-chars-minimum!!",
		Environment: "test",
	}
}

func TestRequireAuth_BearerToken(t *testing.T) {
	cfg := newTestConfig()
	jwtSvc := newTestJWTService()
	userID := uuid.New()
	tenantID := uuid.New()

	access, _, err := jwtSvc.GenerateTokens(userID, tenantID, "test@example.com", "tenant_admin")
	if err != nil {
		t.Fatalf("generate tokens: %v", err)
	}

	router := gin.New()
	router.GET("/protected", RequireAuth(cfg, jwtSvc), func(c *gin.Context) {
		c.JSON(200, gin.H{"user_id": c.GetString("userID")})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body = %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestRequireAuth_CookieFallback(t *testing.T) {
	cfg := newTestConfig()
	jwtSvc := newTestJWTService()
	userID := uuid.New()
	tenantID := uuid.New()

	access, _, err := jwtSvc.GenerateTokens(userID, tenantID, "test@example.com", "viewer")
	if err != nil {
		t.Fatalf("generate tokens: %v", err)
	}

	router := gin.New()
	router.GET("/protected", RequireAuth(cfg, jwtSvc), func(c *gin.Context) {
		c.JSON(200, gin.H{"user_id": c.GetString("userID")})
	})

	// GET with cookie — no CSRF required for safe methods
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: access})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body = %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestRequireAuth_CookieCSRFRequired(t *testing.T) {
	cfg := newTestConfig()
	jwtSvc := newTestJWTService()
	userID := uuid.New()
	tenantID := uuid.New()

	access, _, err := jwtSvc.GenerateTokens(userID, tenantID, "test@example.com", "tenant_admin")
	if err != nil {
		t.Fatalf("generate tokens: %v", err)
	}

	router := gin.New()
	router.POST("/action", RequireAuth(cfg, jwtSvc), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	// POST with cookie but no CSRF — should fail
	req := httptest.NewRequest(http.MethodPost, "/action", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: access})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d (missing CSRF); body = %s", w.Code, http.StatusForbidden, w.Body.String())
	}
}

func TestRequireAuth_CookieCSRFValid(t *testing.T) {
	cfg := newTestConfig()
	jwtSvc := newTestJWTService()
	userID := uuid.New()
	tenantID := uuid.New()

	access, _, err := jwtSvc.GenerateTokens(userID, tenantID, "test@example.com", "tenant_admin")
	if err != nil {
		t.Fatalf("generate tokens: %v", err)
	}

	router := gin.New()
	router.POST("/action", RequireAuth(cfg, jwtSvc), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	//: CSRF is now session-bound to the access token's jti.
	csrfToken := sharedmw.CSRFTokenForAccessToken(cfg.JWTSecret, access)

	// POST with matching CSRF cookie + header
	req := httptest.NewRequest(http.MethodPost, "/action", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: access})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	req.Header.Set("X-CSRF-Token", csrfToken)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body = %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestRequireAuth_CookieCSRFMismatch(t *testing.T) {
	cfg := newTestConfig()
	jwtSvc := newTestJWTService()
	userID := uuid.New()
	tenantID := uuid.New()

	access, _, err := jwtSvc.GenerateTokens(userID, tenantID, "test@example.com", "tenant_admin")
	if err != nil {
		t.Fatalf("generate tokens: %v", err)
	}

	router := gin.New()
	router.POST("/action", RequireAuth(cfg, jwtSvc), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	// POST with mismatched CSRF values
	req := httptest.NewRequest(http.MethodPost, "/action", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: access})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "cookie-value"})
	req.Header.Set("X-CSRF-Token", "different-header-value")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d (CSRF mismatch); body = %s", w.Code, http.StatusForbidden, w.Body.String())
	}
}

// TestRequireAuth_PlatformCookieFallback is the regression test for: a GET
// carrying only the platform cookie (platform_access_token), as admin-ui sends,
// must authenticate against auth-service rather than 401 → forced logout.
func TestRequireAuth_PlatformCookieFallback(t *testing.T) {
	cfg := newTestConfig()
	jwtSvc := newTestJWTService()
	userID := uuid.New()
	tenantID := uuid.New()

	access, _, err := jwtSvc.GenerateTokens(userID, tenantID, "admin@example.com", "platform_admin")
	if err != nil {
		t.Fatalf("generate tokens: %v", err)
	}

	router := gin.New()
	router.GET("/protected", RequireAuth(cfg, jwtSvc), func(c *gin.Context) {
		c.JSON(200, gin.H{"user_id": c.GetString("userID")})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "platform_access_token", Value: access})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body = %s", w.Code, http.StatusOK, w.Body.String())
	}
}

// TestRequireAuth_PlatformCookieCSRF confirms a state-mutating request that
// authenticates via the platform cookie has CSRF checked against the *platform*
// CSRF cookie (the pair matched), not the tenant csrf_token.
func TestRequireAuth_PlatformCookieCSRF(t *testing.T) {
	cfg := newTestConfig()
	jwtSvc := newTestJWTService()
	userID := uuid.New()
	tenantID := uuid.New()

	access, _, err := jwtSvc.GenerateTokens(userID, tenantID, "admin@example.com", "platform_admin")
	if err != nil {
		t.Fatalf("generate tokens: %v", err)
	}

	router := gin.New()
	router.POST("/action", RequireAuth(cfg, jwtSvc), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	csrfToken := sharedmw.CSRFTokenForAccessToken(cfg.JWTSecret, access)

	// Missing CSRF header → 403.
	req := httptest.NewRequest(http.MethodPost, "/action", nil)
	req.AddCookie(&http.Cookie{Name: "platform_access_token", Value: access})
	req.AddCookie(&http.Cookie{Name: "platform_csrf_token", Value: csrfToken})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("missing CSRF: status = %d, want %d; body = %s", w.Code, http.StatusForbidden, w.Body.String())
	}

	// Matching platform CSRF cookie + header → 200.
	req = httptest.NewRequest(http.MethodPost, "/action", nil)
	req.AddCookie(&http.Cookie{Name: "platform_access_token", Value: access})
	req.AddCookie(&http.Cookie{Name: "platform_csrf_token", Value: csrfToken})
	req.Header.Set("X-CSRF-Token", csrfToken)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("valid CSRF: status = %d, want %d; body = %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestRequireAuth_NoCredentials(t *testing.T) {
	cfg := newTestConfig()
	jwtSvc := newTestJWTService()

	router := gin.New()
	router.GET("/protected", RequireAuth(cfg, jwtSvc), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d; body = %s", w.Code, http.StatusUnauthorized, w.Body.String())
	}
}
