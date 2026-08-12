package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/models"
)

const testJWTSecret = "test-secret-key-for-auth-middleware"

func signAccessToken(t *testing.T, tenantID uuid.UUID) string {
	t.Helper()
	claims := &models.JWTClaims{
		UserID:   uuid.New(),
		TenantID: tenantID,
		Email:    "user@example.com",
		Role:     "platform_admin",
		Type:     "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return signed
}

// newAuthTestRouter builds a router whose protected route is guarded by
// RequireJWTAuth configured with the given access-token cookie name.
func newAuthTestRouter(accessCookie string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequireJWTAuth(AuthConfig{
		JWTSecret:         testJWTSecret,
		AccessTokenCookie: accessCookie,
	}))
	r.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

// TestRequireJWTAuth_AcceptsEitherCookieName is the regression test for:
// a service wired with one access-token cookie name must still authenticate a
// request that carries the well-known *alternate* cookie name. This is what
// lets admin-ui (carrying platform_access_token) reach services wired with the
// tenant default access_token, and vice versa, without a forced logout.
func TestRequireJWTAuth_AcceptsEitherCookieName(t *testing.T) {
	token := signAccessToken(t, uuid.Nil)

	cases := []struct {
		name          string
		serviceCookie string // AccessTokenCookie the service is configured with
		requestCookie string // cookie name actually present on the request
		wantStatus    int
	}{
		{"tenant service, tenant cookie", "access_token", "access_token", http.StatusOK},
		{"tenant service, platform cookie (fallback)", "access_token", "platform_access_token", http.StatusOK},
		{"platform service, platform cookie", "platform_access_token", "platform_access_token", http.StatusOK},
		{"platform service, tenant cookie (fallback)", "platform_access_token", "access_token", http.StatusOK},
		{"default service, platform cookie (fallback)", "", "platform_access_token", http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router := newAuthTestRouter(tc.serviceCookie)
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.AddCookie(&http.Cookie{Name: tc.requestCookie, Value: token})
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != tc.wantStatus {
				t.Fatalf("got status %d, want %d (body: %s)", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}

// TestRequireJWTAuth_StrictCookiePair verifies that StrictCookiePair disables the
// well-known alternate fallback: a platform service must accept ONLY the platform
// cookie pair, and must reject (401, not silent tenant identity) a request that
// carries only the tenant cookie. This is the fix for the admin-ui "save errors"
// 403: on a shared parent domain the browser sends both cookie sets, and the
// fallback would authenticate an expired platform session as the tenant.
func TestRequireJWTAuth_StrictCookiePair(t *testing.T) {
	token := signAccessToken(t, uuid.Nil)

	newStrictRouter := func() *gin.Engine {
		gin.SetMode(gin.TestMode)
		r := gin.New()
		r.Use(RequireJWTAuth(AuthConfig{
			JWTSecret:         testJWTSecret,
			AccessTokenCookie: "platform_access_token",
			CSRFCookie:        "platform_csrf_token",
			StrictCookiePair:  true,
		}))
		r.GET("/protected", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
		return r
	}

	cases := []struct {
		name          string
		requestCookie string
		wantStatus    int
	}{
		{"platform service, platform cookie", "platform_access_token", http.StatusOK},
		{"platform service, tenant cookie (NO fallback)", "access_token", http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.AddCookie(&http.Cookie{Name: tc.requestCookie, Value: token})
			w := httptest.NewRecorder()
			newStrictRouter().ServeHTTP(w, req)
			if w.Code != tc.wantStatus {
				t.Fatalf("got status %d, want %d (body: %s)", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}

// stubRevocationChecker is a test RevocationChecker that reports a fixed set of
// jtis as revoked.
type stubRevocationChecker struct{ revoked map[string]bool }

func (s stubRevocationChecker) IsRevoked(_ context.Context, jti string) bool {
	return s.revoked[jti]
}

// signAccessTokenWithJTI mints a valid access token carrying the given jti.
func signAccessTokenWithJTI(t *testing.T, jti string) string {
	t.Helper()
	claims := &models.JWTClaims{
		UserID:   uuid.New(),
		TenantID: uuid.New(),
		Email:    "user@example.com",
		Role:     "viewer",
		Type:     "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return signed
}

// TestRequireJWTAuth_RevokedJTIRejected is the regression: a validly-signed
// token whose jti is on the revocation denylist must be rejected with 401 by the
// shared middleware (this is what stops a "stopped" impersonation token from
// retaining data-plane access). A non-revoked jti still passes.
func TestRequireJWTAuth_RevokedJTIRejected(t *testing.T) {
	gin.SetMode(gin.TestMode)
	revokedJTI := "revoked-jti-123"
	checker := stubRevocationChecker{revoked: map[string]bool{revokedJTI: true}}

	newRouter := func() *gin.Engine {
		r := gin.New()
		r.Use(RequireJWTAuth(AuthConfig{JWTSecret: testJWTSecret, RevocationChecker: checker}))
		r.GET("/protected", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
		return r
	}

	// Revoked jti → 401 Token revoked.
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+signAccessTokenWithJTI(t, revokedJTI))
	w := httptest.NewRecorder()
	newRouter().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked jti: got %d, want 401 (body: %s)", w.Code, w.Body.String())
	}

	// A different, non-revoked jti → 200.
	req = httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+signAccessTokenWithJTI(t, "live-jti-456"))
	w = httptest.NewRecorder()
	newRouter().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("live jti: got %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
}

// TestRequireJWTAuth_NoCookieIsUnauthorized confirms the no-auth-at-all branch
// still returns 401 when neither cookie nor bearer token is present.
func TestRequireJWTAuth_NoCookieIsUnauthorized(t *testing.T) {
	router := newAuthTestRouter("access_token")
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401", w.Code)
	}
}

// TestRequireJWTAuth_CSRFEnforcedOnMatchedCookie confirms that a state-mutating
// request authenticated via the *fallback* cookie still has its CSRF checked
// against the CSRF cookie paired with the matched access cookie.
func TestRequireJWTAuth_CSRFEnforcedOnMatchedCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	jti := "csrf-session-jti"
	token := signAccessTokenWithJTI(t, jti)
	// The CSRF token is now SESSION-BOUND: HMAC(jti), not an arbitrary value.
	csrfVal := CSRFToken(testJWTSecret, jti)

	r := gin.New()
	// Service wired with tenant default; request carries the platform pair.
	r.Use(RequireJWTAuth(AuthConfig{JWTSecret: testJWTSecret, AccessTokenCookie: "access_token"}))
	r.POST("/protected", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	// Missing CSRF header → 403.
	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "platform_access_token", Value: token})
	req.AddCookie(&http.Cookie{Name: "platform_csrf_token", Value: csrfVal})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF header: got %d, want 403 (body: %s)", w.Code, w.Body.String())
	}

	// Matching, session-bound CSRF header + paired cookie → 200.
	req = httptest.NewRequest(http.MethodPost, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "platform_access_token", Value: token})
	req.AddCookie(&http.Cookie{Name: "platform_csrf_token", Value: csrfVal})
	req.Header.Set("X-CSRF-Token", csrfVal)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("valid CSRF: got %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
}

// TestRequireJWTAuth_CSRFBoundToSession: a CSRF token minted for a
// DIFFERENT session (a different access-token jti) is rejected even though the
// header equals the cookie — the old equality-only check would have passed it.
func TestRequireJWTAuth_CSRFBoundToSession(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Victim's live access token (session B).
	victimToken := signAccessTokenWithJTI(t, "victim-session-jti")
	// A CSRF token bound to a DIFFERENT session (the attacker's session A).
	foreignCSRF := CSRFToken(testJWTSecret, "attacker-session-jti")

	r := gin.New()
	r.Use(RequireJWTAuth(AuthConfig{JWTSecret: testJWTSecret}))
	r.POST("/protected", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	// header == cookie (== foreign CSRF), but not bound to victimToken's jti → 403.
	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: victimToken})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: foreignCSRF})
	req.Header.Set("X-CSRF-Token", foreignCSRF)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-session CSRF: got %d, want 403 (body: %s)", w.Code, w.Body.String())
	}
}

// signScopedPATToken mints a PAT-derived access token carrying scopes.
func signScopedPATToken(t *testing.T, scopes []string) string {
	t.Helper()
	claims := &models.JWTClaims{
		UserID:    uuid.New(),
		TenantID:  uuid.New(),
		Email:     "pat@example.com",
		Role:      "tenant_admin",
		Type:      "access",
		TokenType: "pat",
		Scopes:    scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("failed to sign scoped token: %v", err)
	}
	return signed
}

// TestRequireJWTAuth_PATScopeEnforcement: a scope-narrowed PAT token is
// allowed a permission within its scope and denied one outside it, while a
// normal (unscoped) login token is unaffected. The route stands in for an RBAC
// gate by consulting PermissionWithinTokenScope, which is the "token scopes"
// half of intersect(role permissions, token scopes).
func TestRequireJWTAuth_PATScopeEnforcement(t *testing.T) {
	gin.SetMode(gin.TestMode)

	newRouter := func(requiredPerm string) *gin.Engine {
		r := gin.New()
		r.Use(RequireJWTAuth(AuthConfig{JWTSecret: testJWTSecret}))
		r.GET("/p", func(c *gin.Context) {
			if !PermissionWithinTokenScope(c, requiredPerm) {
				c.JSON(http.StatusForbidden, gin.H{"error": "outside scope"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"ok": true})
		})
		return r
	}

	scoped := signScopedPATToken(t, []string{"assets.read", "compliance.read"})
	normal := signAccessToken(t, uuid.New()) // no scopes

	cases := []struct {
		name  string
		token string
		perm  string
		want  int
	}{
		{"scoped PAT, permission within scope", scoped, "assets.read", http.StatusOK},
		{"scoped PAT, permission outside scope", scoped, "settings.update", http.StatusForbidden},
		{"scoped PAT, write permission denied", scoped, "assets.manage", http.StatusForbidden},
		{"normal token, any permission allowed", normal, "settings.update", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/p", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			w := httptest.NewRecorder()
			newRouter(tc.perm).ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("got %d, want %d (body: %s)", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

// TestRequireJWTAuth_PasswordChangeRequiredGate pins the server-side
// enforcement of force_password_change: a token carrying the
// pwd_change_required claim is a limited session — every route is rejected
// with 403 except the change-password / me / logout suffixes, regardless of
// which service the token lands on. A normal token is unaffected.
func TestRequireJWTAuth_PasswordChangeRequiredGate(t *testing.T) {
	signLimitedToken := func(t *testing.T) string {
		t.Helper()
		claims := &models.JWTClaims{
			UserID:                 uuid.New(),
			Email:                  "su_admin@vistaplatform.invalid",
			Role:                   "super_admin",
			Type:                   "access",
			PasswordChangeRequired: true,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}
		signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testJWTSecret))
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}
		return signed
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequireJWTAuth(AuthConfig{JWTSecret: testJWTSecret}))
	ok := func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) }
	r.GET("/api/v1/admin-service/admin/tenants", ok)
	r.POST("/api/v1/admin-service/admin/settings", ok)
	r.GET("/api/v1/admin-service/admin/auth/me", ok)
	r.POST("/api/v1/admin-service/admin/auth/change-password", ok)
	r.POST("/api/v1/admin-service/admin/auth/logout", ok)

	limited := signLimitedToken(t)
	normal := signAccessToken(t, uuid.Nil)

	cases := []struct {
		name   string
		token  string
		method string
		path   string
		want   int
	}{
		{"limited token, normal GET route", limited, http.MethodGet, "/api/v1/admin-service/admin/tenants", http.StatusForbidden},
		{"limited token, normal POST route", limited, http.MethodPost, "/api/v1/admin-service/admin/settings", http.StatusForbidden},
		{"limited token, auth/me allowed", limited, http.MethodGet, "/api/v1/admin-service/admin/auth/me", http.StatusOK},
		{"limited token, change-password allowed", limited, http.MethodPost, "/api/v1/admin-service/admin/auth/change-password", http.StatusOK},
		{"limited token, logout allowed", limited, http.MethodPost, "/api/v1/admin-service/admin/auth/logout", http.StatusOK},
		{"normal token, normal route unaffected", normal, http.MethodGet, "/api/v1/admin-service/admin/tenants", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("got %d, want %d (body: %s)", w.Code, tc.want, w.Body.String())
			}
			if tc.want == http.StatusForbidden && !strings.Contains(w.Body.String(), "password_change_required") {
				t.Fatalf("403 body missing password_change_required code: %s", w.Body.String())
			}
		})
	}
}
