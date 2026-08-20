package middleware

// Regressions for two RequireAuth defects that both let a request authenticate
// as the wrong (or a dead) identity:
//
//   - the JWT revocation denylist that Logout / StopAdminImpersonation write to
//     was never consulted here, so auth-service was the one service that kept
//     honoring a revoked token until its natural expiry;
//   - the cookie-pair loop always tried the TENANT pair first, so on the shared
//     COOKIE_DOMAIN an operator holding both sessions authenticated as the
//     tenant user on platform-only routes.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// stubRevocation is an in-memory RevocationChecker. errored models a denylist
// backend failure, which must fail OPEN (report not-revoked) exactly like the
// Redis-backed checker does.
type stubRevocation struct {
	revoked map[string]bool
	calls   int
}

func (s *stubRevocation) IsRevoked(_ context.Context, jti string) bool {
	s.calls++
	return s.revoked[jti]
}

// echoIdentityRouter returns a router whose single route reports the identity
// RequireAuth resolved.
func echoIdentityRouter(handlers ...gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	h := append(handlers, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"user_id": c.GetString("userID"),
			"email":   c.GetString("email"),
			"role":    c.GetString("role"),
		})
	})
	r.GET("/protected", h...)
	return r
}

// The defect: a token on the denylist kept working against auth-service.
func TestRequireAuth_RejectsRevokedToken(t *testing.T) {
	cfg := newTestConfig()
	jwtSvc := newTestJWTService()

	access, _, err := jwtSvc.GenerateTokens(uuid.New(), uuid.New(), "user@example.com", "tenant_admin")
	if err != nil {
		t.Fatalf("generate tokens: %v", err)
	}
	claims, err := jwtSvc.ValidateToken(access)
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}
	if claims.ID == "" {
		t.Fatal("minted access token carries no jti; the denylist cannot key on it")
	}

	rc := &stubRevocation{revoked: map[string]bool{claims.ID: true}}
	router := echoIdentityRouter(RequireAuth(cfg, jwtSvc, WithRevocationChecker(rc)))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a revoked token; body = %s", w.Code, w.Body.String())
	}
	if rc.calls == 0 {
		t.Fatal("RequireAuth never consulted the revocation denylist")
	}
}

// Same check must apply to the cookie path — "Sign out" in web-ui revokes the
// cookie session, not a bearer token.
func TestRequireAuth_RejectsRevokedTokenFromCookie(t *testing.T) {
	cfg := newTestConfig()
	jwtSvc := newTestJWTService()

	access, _, err := jwtSvc.GenerateTokens(uuid.New(), uuid.New(), "user@example.com", "viewer")
	if err != nil {
		t.Fatalf("generate tokens: %v", err)
	}
	claims, err := jwtSvc.ValidateToken(access)
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}

	rc := &stubRevocation{revoked: map[string]bool{claims.ID: true}}
	router := echoIdentityRouter(RequireAuth(cfg, jwtSvc, WithRevocationChecker(rc)))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: access})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a revoked cookie session; body = %s", w.Code, w.Body.String())
	}
}

// The other polarity: a token that is NOT on the denylist must still pass. A
// guard that rejects everything is as broken as one that rejects nothing.
func TestRequireAuth_AllowsUnrevokedToken(t *testing.T) {
	cfg := newTestConfig()
	jwtSvc := newTestJWTService()

	access, _, err := jwtSvc.GenerateTokens(uuid.New(), uuid.New(), "user@example.com", "viewer")
	if err != nil {
		t.Fatalf("generate tokens: %v", err)
	}

	rc := &stubRevocation{revoked: map[string]bool{uuid.NewString(): true}}
	router := echoIdentityRouter(RequireAuth(cfg, jwtSvc, WithRevocationChecker(rc)))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an unrevoked token; body = %s", w.Code, w.Body.String())
	}
	if rc.calls == 0 {
		t.Fatal("RequireAuth never consulted the revocation denylist")
	}
}

// A denylist outage must fail OPEN, not lock everyone out — the documented
// posture shared/middleware also takes. A nil checker models "no denylist
// configured" (REDIS_URL unset).
func TestRequireAuth_FailsOpenWithoutRevocationChecker(t *testing.T) {
	cfg := newTestConfig()
	jwtSvc := newTestJWTService()

	access, _, err := jwtSvc.GenerateTokens(uuid.New(), uuid.New(), "user@example.com", "viewer")
	if err != nil {
		t.Fatalf("generate tokens: %v", err)
	}

	router := echoIdentityRouter(RequireAuth(cfg, jwtSvc, WithRevocationChecker(nil)))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (denylist unavailable must fail open); body = %s", w.Code, w.Body.String())
	}
}

// --- cookie-pair preference (platform-only route groups) --------------------

// mintPair returns an access token for a tenant user and one for a platform
// admin, as a browser on the shared COOKIE_DOMAIN would hold simultaneously.
func mintBothSessions(t *testing.T) (tenantToken, platformToken, tenantEmail, platformEmail string) {
	t.Helper()
	jwtSvc := newTestJWTService()
	var err error
	tenantEmail, platformEmail = "tenant.user@example.com", "platform.admin@example.com"
	tenantToken, _, err = jwtSvc.GenerateTokens(uuid.New(), uuid.New(), tenantEmail, "viewer")
	if err != nil {
		t.Fatalf("generate tenant tokens: %v", err)
	}
	platformToken, _, err = jwtSvc.GenerateTokens(uuid.New(), uuid.New(), platformEmail, "platform_admin")
	if err != nil {
		t.Fatalf("generate platform tokens: %v", err)
	}
	return
}

// The defect: with BOTH cookie pairs present the tenant pair matched first, so
// admin-ui's call to a platform-only route authenticated as the tenant user and
// the platform gate then denied it.
func TestRequireAuth_PlatformCookiesFirst_PrefersPlatformSession(t *testing.T) {
	cfg := newTestConfig()
	jwtSvc := newTestJWTService()
	tenantToken, platformToken, _, platformEmail := mintBothSessions(t)

	router := echoIdentityRouter(RequireAuth(cfg, jwtSvc, PlatformCookiesFirst()))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: tenantToken})
	req.AddCookie(&http.Cookie{Name: "platform_access_token", Value: platformToken})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); !jsonHasEmail(body, platformEmail) {
		t.Fatalf("authenticated identity = %s, want the platform session (%s)", body, platformEmail)
	}
}

// The tenant pair is still a FALLBACK, not forbidden: a caller holding only
// tenant cookies must still reach the route's platform-permission gate (and get
// its 403) rather than a 401 the UI would misread as session expiry.
func TestRequireAuth_PlatformCookiesFirst_StillAcceptsTenantPairAlone(t *testing.T) {
	cfg := newTestConfig()
	jwtSvc := newTestJWTService()
	tenantToken, _, tenantEmail, _ := mintBothSessions(t)

	router := echoIdentityRouter(RequireAuth(cfg, jwtSvc, PlatformCookiesFirst()))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: tenantToken})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); !jsonHasEmail(body, tenantEmail) {
		t.Fatalf("authenticated identity = %s, want the tenant session (%s)", body, tenantEmail)
	}
}

// Tenant-default routes must be unaffected: without the option the tenant pair
// still wins, which is what keeps web-ui behaviour unchanged.
func TestRequireAuth_DefaultOrderPrefersTenantSession(t *testing.T) {
	cfg := newTestConfig()
	jwtSvc := newTestJWTService()
	tenantToken, platformToken, tenantEmail, _ := mintBothSessions(t)

	router := echoIdentityRouter(RequireAuth(cfg, jwtSvc))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: tenantToken})
	req.AddCookie(&http.Cookie{Name: "platform_access_token", Value: platformToken})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); !jsonHasEmail(body, tenantEmail) {
		t.Fatalf("authenticated identity = %s, want the tenant session (%s)", body, tenantEmail)
	}
}

func jsonHasEmail(body, email string) bool {
	return strContains(body, `"email":"`+email+`"`)
}

func strContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
