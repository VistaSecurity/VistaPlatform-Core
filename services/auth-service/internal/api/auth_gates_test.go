package api

// Wiring tests for the auth gates in router.go. Each drives the REAL
// SetupRouter, so deleting the middleware line that closes a hole fails the
// test; a test of the middleware in isolation would stay green through exactly
// that deletion (the lesson).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/middleware"
	"github.com/vistasecurity/vistaplatform/shared/security/jwtkeys"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

const (
	gatesJWTSecret = "auth-gates-test-jwt-secret"
	gatesHMACKey   = "auth-gates-test-internal-hmac" // not a real credential
	gatesBase      = "/api/v1/auth-service"
)

// The internal-call verifier reads INTERNAL_AUTH_SECRET once per process, so it
// has to be in place before any test in this package builds a request.
func init() {
	if os.Getenv("INTERNAL_AUTH_SECRET") == "" {
		_ = os.Setenv("INTERNAL_AUTH_SECRET", gatesHMACKey)
	}
}

func gatesHMACSecret() string { return os.Getenv("INTERNAL_AUTH_SECRET") }

func newGatesDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, mock
}

func gatesRouter(t *testing.T, db *sql.DB, mutate func(*config.Config)) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{JWTSecret: gatesJWTSecret, JWTExpiry: time.Hour, JWTAcceptLegacyHMAC: true}
	if mutate != nil {
		mutate(cfg)
	}
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}) // never answers
	t.Cleanup(func() { _ = rdb.Close() })
	return SetupRouter(cfg, db, db, rdb, nil, EditionHooks{})
}

func internalReq(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	serviceauth.NewSigner(gatesHMACSecret()).SignRequest(req)
	return req
}

func serve(r *gin.Engine, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// INTERNAL_AUTH_SECRET is shared by every service, so an internal call must not
// reach the routes that mint a session as any user or rewrite another tenant's
// configuration. security-summary stays reachable: tenant-health-service reads
// it with exactly such a call.
func TestInternalCallsRefusedOnImpersonationAndTenantAdminRoutes(t *testing.T) {
	db, _ := newGatesDB(t)
	r := gatesRouter(t, db, nil)
	tenant := uuid.NewString()

	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPost, gatesBase + "/admin/impersonations", `{"tenant_id":"` + tenant + `","user_id":"` + uuid.NewString() + `","reason":"compromised pod"}`},
		{http.MethodPost, gatesBase + "/admin/impersonations/stop", `{"jti":"x"}`},
		{http.MethodGet, gatesBase + "/admin/impersonations/audit", ``},
		{http.MethodGet, gatesBase + "/admin/tenants/" + tenant + "/ui-config", ``},
		{http.MethodPut, gatesBase + "/admin/tenants/" + tenant + "/ui-config", `{}`},
		{http.MethodPut, gatesBase + "/tenant/ui-config", `{}`},
	} {
		w := serve(r, internalReq(tc.method, tc.path, tc.body))
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s with a valid internal HMAC: %d, want 403; body=%s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}

	// The legitimate internal caller still gets through the gates (the handler
	// then fails on the unmocked DB, which is not a 401/403).
	w := serve(r, internalReq(http.MethodGet, gatesBase+"/admin/tenants/"+tenant+"/security-summary", ""))
	if w.Code == http.StatusForbidden || w.Code == http.StatusUnauthorized {
		t.Errorf("security-summary with an internal call: %d, want it to reach the handler (tenant-health-service depends on it)", w.Code)
	}
}

func expectTenantPermission(mock sqlmock.Sqlmock, userID, tenantID uuid.UUID, permission string, granted bool) {
	mock.ExpectBegin()
	mock.ExpectExec(`set_tenant_context`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM tenant_permissions`).
		WithArgs(userID, tenantID, permission).
		WillReturnRows(sqlmock.NewRows([]string{"has"}).AddRow(granted))
	mock.ExpectCommit()
}

func gatesTenantToken(t *testing.T, userID, tenantID uuid.UUID, scopes []string) string {
	t.Helper()
	svc := auth.NewJWTService(gatesJWTSecret, time.Hour, time.Hour)
	if scopes != nil {
		tok, _, _, err := svc.GenerateScopedAccessTokenWithTTL(userID, tenantID, "pat@example.test", "tenant_admin", scopes, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	tok, _, err := svc.GenerateTokens(userID, tenantID, "admin@example.test", "tenant_admin")
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func bearer(method, path, token, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

// PUT /tenant is name/domain/billing_email only. The router-level proof is that
// a tenant admin holding settings.update is refused for the platform-only and
// plan-gated fields, naming the field, before anything is written.
func TestPutTenantRefusesPlatformOnlyFields(t *testing.T) {
	for _, field := range []string{"ui_config", "custom_branding", "settings"} {
		t.Run(field, func(t *testing.T) {
			db, mock := newGatesDB(t)
			userID, tenantID := uuid.New(), uuid.New()
			expectLiveTenantState(mock, tenantID)
			expectTenantPermission(mock, userID, tenantID, "settings.update", true)

			r := gatesRouter(t, db, nil)
			w := serve(r, bearer(http.MethodPut, gatesBase+"/tenant", gatesTenantToken(t, userID, tenantID, nil),
				`{"name":"Acme","`+field+`":{"x":1}}`))
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), field) {
				t.Fatalf("PUT /tenant with %s: %d %s, want 400 naming the field", field, w.Code, w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("the request did not get through the permission gate to the handler: %v", err)
			}
		})
	}
}

// A PAT-derived token is narrowed to its scopes: a read-only token acts as the
// user only for what it was scoped to, not for everything the user may do.
func TestScopedTokenCannotExceedItsScopes(t *testing.T) {
	userID, tenantID := uuid.New(), uuid.New()

	t.Run("users.create refused for a read-only PAT", func(t *testing.T) {
		db, mock := newGatesDB(t)
		expectLiveTenantState(mock, tenantID)
		// No RBAC query is expected: the scope check refuses first. If the scopes
		// were not carried into the context, the RBAC lookup would be attempted
		// and fail the request differently.
		r := gatesRouter(t, db, nil)
		w := serve(r, bearer(http.MethodPost, gatesBase+"/users", gatesTenantToken(t, userID, tenantID, []string{"inventory.read"}), `{}`))
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "users.create") {
			t.Fatalf("status = %d body=%s, want 403 naming users.create", w.Code, w.Body.String())
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a PAT cannot mint API tokens", func(t *testing.T) {
		db, mock := newGatesDB(t)
		expectLiveTenantState(mock, tenantID)
		r := gatesRouter(t, db, nil)
		w := serve(r, bearer(http.MethodPost, gatesBase+"/api-tokens", gatesTenantToken(t, userID, tenantID, []string{"inventory.read"}), `{}`))
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d body=%s, want 403", w.Code, w.Body.String())
		}
	})

	t.Run("a scope that names the permission still passes to RBAC", func(t *testing.T) {
		db, mock := newGatesDB(t)
		expectLiveTenantState(mock, tenantID)
		expectTenantPermission(mock, userID, tenantID, "users.create", true)
		r := gatesRouter(t, db, nil)
		w := serve(r, bearer(http.MethodPost, gatesBase+"/users", gatesTenantToken(t, userID, tenantID, []string{"users.create"}), `{}`))
		if w.Code == http.StatusForbidden || w.Code == http.StatusUnauthorized {
			t.Fatalf("status = %d body=%s, want the request to reach the handler", w.Code, w.Body.String())
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
}

// Gin trusted every peer, so ClientIP() was the leftmost X-Forwarded-For entry:
// whatever the client wrote. With no trusted proxies configured it is the TCP
// peer; with the ingress trusted it is the first address the ingress did not
// vouch for, still ignoring what a client prepended.
func TestRouterClientIPIgnoresSpoofedForwardedFor(t *testing.T) {
	probe := func(t *testing.T, trusted []string, remote, xff string) string {
		db, _ := newGatesDB(t)
		r := gatesRouter(t, db, func(c *config.Config) { c.TrustedProxies = trusted })
		r.GET("/_probe/ip", func(c *gin.Context) { c.String(http.StatusOK, c.ClientIP()) })
		req := httptest.NewRequest(http.MethodGet, "/_probe/ip", nil)
		req.RemoteAddr = remote
		req.Header.Set("X-Forwarded-For", xff)
		return serve(r, req).Body.String()
	}

	if got := probe(t, nil, "198.51.100.7:5555", "1.2.3.4"); got != "198.51.100.7" {
		t.Errorf("no trusted proxies: ClientIP = %q, want the TCP peer 198.51.100.7", got)
	}
	// Ingress at 10.0.0.9 appended the real client (203.0.113.5) after the
	// client's own forged entry.
	if got := probe(t, []string{"10.0.0.0/8"}, "10.0.0.9:5555", "6.6.6.6, 203.0.113.5"); got != "203.0.113.5" {
		t.Errorf("trusted ingress: ClientIP = %q, want 203.0.113.5 (the forged leftmost entry must not win)", got)
	}
	// An untrusted peer is not believed even when proxies are configured.
	if got := probe(t, []string{"10.0.0.0/8"}, "198.51.100.7:5555", "1.2.3.4"); got != "198.51.100.7" {
		t.Errorf("untrusted peer with proxies configured: ClientIP = %q, want 198.51.100.7", got)
	}
}

// With the legacy-HMAC switch off, an HS256 token signed with JWT_SECRET is
// refused by the real router (anyone holding the secret could otherwise mint a
// platform-admin session). It needs an ES256 signing key to be honoured: without
// one the service signs HS256 itself.
func TestRouterRejectsHS256WhenLegacyHMACOff(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := jwtkeys.EncodePrivatePEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUTH_JWT_SIGNING_KEY", string(pemBytes))

	forged := func() string {
		now := time.Now()
		claims := &auth.JWTClaims{
			UserID: uuid.New(), TenantID: uuid.Nil, Email: "forged@example.test", Role: "platform_admin", Type: "access",
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
				Issuer: "crypto-inventory-auth", Audience: jwt.ClaimStrings{"crypto-inventory"}, ID: uuid.NewString(),
			},
		}
		s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(gatesJWTSecret))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	status := func(accept bool) int {
		db, _ := newGatesDB(t)
		r := gatesRouter(t, db, func(c *config.Config) { c.JWTAcceptLegacyHMAC = accept })
		return serve(r, bearer(http.MethodGet, gatesBase+"/auth/me", forged(), "")).Code
	}
	if got := status(true); got == http.StatusUnauthorized {
		t.Fatalf("legacy HMAC on: forged-secret HS256 token got 401 — the control request is not reaching the verifier as expected")
	}
	if got := status(false); got != http.StatusUnauthorized {
		t.Fatalf("legacy HMAC off: HS256 token status = %d, want 401", got)
	}
}

// Credential, token and signup endpoints refuse when the limiter cannot answer.
// /auth/refresh was in the default class and sailed through a Redis outage.
func TestRouterAuthEndpointsFailClosedWhenLimiterDown(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, _ := newGatesDB(t)
	dead := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1, DialTimeout: 50 * time.Millisecond})
	t.Cleanup(func() { _ = dead.Close() })
	limiter := middleware.NewRateLimiter(dead, 100, time.Minute, 5)
	cfg := &config.Config{JWTSecret: gatesJWTSecret, JWTExpiry: time.Hour, JWTAcceptLegacyHMAC: true}
	r := SetupRouter(cfg, db, db, dead, limiter, EditionHooks{})

	for _, p := range []string{"/auth/refresh", "/auth/register/complete", "/auth/invitations/accept", "/auth/initiate", "/oauth/token"} {
		w := serve(r, httptest.NewRequest(http.MethodPost, gatesBase+p, strings.NewReader(`{}`)))
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("POST %s with the limiter down: %d, want 503", p, w.Code)
		}
	}
}
