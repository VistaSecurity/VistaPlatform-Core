package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/models"
	"github.com/vistasecurity/vistaplatform/shared/tenantstate"
)

// stubTenantState answers from a fixed map; unknown tenants are live.
type stubTenantState struct {
	blocked map[uuid.UUID]string
	err     error
	calls   int
}

type sessionTenantState struct {
	stubTenantState
	currentVersion int64
}

func (s *sessionTenantState) CheckSession(ctx context.Context, id uuid.UUID, tokenVersion int64) (string, bool, bool, error) {
	code, blocked, err := s.Check(ctx, id)
	return code, blocked, tokenVersion < s.currentVersion, err
}

// liveTenantState is the explicit "every tenant is live" checker for tests
// that are not about tenant state. It must be passed explicitly: a nil
// AuthConfig.TenantState is NOT "no check" — RequireJWTAuth then builds the
// real checker from DATABASE_URL, and the nightly test-backend job sets
// DATABASE_URL. There, a token for a random tenant id with no tenants row is
// refused 403 tenant_deleted ( item 2), so a test that leaves the field
// nil passes locally and in the PR gate and fails only in the nightly.
func liveTenantState() TenantStateChecker { return &stubTenantState{} }

func (s *stubTenantState) Check(_ context.Context, id uuid.UUID) (string, bool, error) {
	s.calls++
	if s.err != nil {
		return "", false, s.err
	}
	code, ok := s.blocked[id]
	return code, ok, nil
}

func signTenantToken(t *testing.T, tenantID uuid.UUID, tokenType string) string {
	t.Helper()
	claims := &models.JWTClaims{
		UserID:   uuid.New(),
		TenantID: tenantID,
		Email:    "user@example.com",
		Role:     "viewer",
		Type:     tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func signTenantTokenVersion(t *testing.T, tenantID uuid.UUID, version int64) string {
	t.Helper()
	claims := &models.JWTClaims{
		UserID: uuid.New(), TenantID: tenantID, Email: "user@example.com", Role: "viewer", Type: "access",
		TenantSessionVersion: version,
		RegisteredClaims:     jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func tenantStateRouter(checker TenantStateChecker) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequireJWTAuth(AuthConfig{
		JWTSecret:         testJWTSecret,
		AllowedTokenTypes: []string{"access", "impersonation"},
		TenantState:       checker,
	}))
	ok := func(c *gin.Context) { c.Status(http.StatusNoContent) }
	r.GET("/api/v1/inventory-service/assets", ok)
	r.POST("/api/v1/auth-service/auth/logout", ok)
	r.GET("/api/v1/inventory-service/auth/logout/extra", ok)
	return r
}

func doGet(r *gin.Engine, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func codeOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return body.Code
}

// TestRequireJWTAuth_RefusesBlockedTenant is the data-plane half of RC-4: an
// access token issued before its tenant was suspended or deleted must stop
// working. Mutation: delete the EnforceTenantState call in RequireJWTAuth and
// both blocked cases answer 204.
func TestRequireJWTAuth_RefusesBlockedTenant(t *testing.T) {
	suspended, deleted, live := uuid.New(), uuid.New(), uuid.New()
	r := tenantStateRouter(&stubTenantState{blocked: map[uuid.UUID]string{
		suspended: tenantstate.CodeSuspended,
		deleted:   tenantstate.CodeDeleted,
	}})

	if w := doGet(r, "/api/v1/inventory-service/assets", signTenantToken(t, live, "access")); w.Code != http.StatusNoContent {
		t.Fatalf("live tenant = %d, want 204; body=%s", w.Code, w.Body.String())
	}
	for id, want := range map[uuid.UUID]string{suspended: tenantstate.CodeSuspended, deleted: tenantstate.CodeDeleted} {
		w := doGet(r, "/api/v1/inventory-service/assets", signTenantToken(t, id, "access"))
		if w.Code != http.StatusForbidden || codeOf(t, w) != want {
			t.Errorf("blocked tenant = %d code=%q, want 403 %q; body=%s", w.Code, codeOf(t, w), want, w.Body.String())
		}
	}
}

func TestRequireJWTAuth_RefusesOldTenantSessionAfterReactivation(t *testing.T) {
	tenantID := uuid.New()
	checker := &sessionTenantState{currentVersion: 2}
	r := tenantStateRouter(checker)

	old := doGet(r, "/api/v1/inventory-service/assets", signTenantTokenVersion(t, tenantID, 1))
	if old.Code != http.StatusUnauthorized || codeOf(t, old) != "session_revoked" {
		t.Fatalf("old session = %d code=%q, want 401 session_revoked; body=%s", old.Code, codeOf(t, old), old.Body.String())
	}
	current := doGet(r, "/api/v1/inventory-service/assets", signTenantTokenVersion(t, tenantID, 2))
	if current.Code != http.StatusNoContent {
		t.Fatalf("current session = %d, want 204; body=%s", current.Code, current.Body.String())
	}
}

// TestRequireJWTAuth_TenantStateFailsClosed — an unreadable state is not
// permission. Mutation: return true from EnforceTenantState on error and this
// answers 204.
func TestRequireJWTAuth_TenantStateFailsClosed(t *testing.T) {
	r := tenantStateRouter(&stubTenantState{err: errors.New("db down")})
	w := doGet(r, "/api/v1/inventory-service/assets", signTenantToken(t, uuid.New(), "access"))
	if w.Code != http.StatusServiceUnavailable || codeOf(t, w) != tenantstate.CodeUnavailable {
		t.Fatalf("lookup error = %d code=%q, want 503 %q", w.Code, codeOf(t, w), tenantstate.CodeUnavailable)
	}
}

// TestRequireJWTAuth_TenantStateExemptions pins the three documented
// exemptions and that each is NARROW: platform tokens (no tenant) never hit the
// check; impersonation (a platform admin looking at a suspended tenant) is
// allowed; sign-out is reachable so the browser can clear its cookies — but a
// path that merely contains /auth/logout is not.
func TestRequireJWTAuth_TenantStateExemptions(t *testing.T) {
	blocked := uuid.New()
	stub := &stubTenantState{blocked: map[uuid.UUID]string{blocked: tenantstate.CodeSuspended}}
	r := tenantStateRouter(stub)

	if w := doGet(r, "/api/v1/inventory-service/assets", signTenantToken(t, uuid.Nil, "access")); w.Code != http.StatusNoContent {
		t.Errorf("platform token = %d, want 204", w.Code)
	}
	if stub.calls != 0 {
		t.Errorf("platform token consulted tenant state (%d calls)", stub.calls)
	}
	if w := doGet(r, "/api/v1/inventory-service/assets", signTenantToken(t, blocked, "impersonation")); w.Code != http.StatusNoContent {
		t.Errorf("impersonation of a suspended tenant = %d, want 204 (platform support access is allowed)", w.Code)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+signTenantToken(t, blocked, "access"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("sign-out for a suspended tenant = %d, want 204", w.Code)
	}

	if w := doGet(r, "/api/v1/inventory-service/auth/logout/extra", signTenantToken(t, blocked, "access")); w.Code != http.StatusForbidden {
		t.Errorf("a path merely containing /auth/logout = %d, want 403 (the exemption must be anchored)", w.Code)
	}
}

// TestResolveTenantStateChecker_DefaultsFromDatabaseURL pins the auto-wiring
// that makes every service enforce with no per-service code — the lesson
// (a fix whose dependency is not wired does nothing). Mutation: return nil
// instead of the env-built checker and the first assertion fails.
func TestResolveTenantStateChecker_DefaultsFromDatabaseURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://u:p@127.0.0.1:1/db?sslmode=disable")
	if ResolveTenantStateChecker(nil, "test") == nil {
		t.Fatal("DATABASE_URL set but no default checker was built")
	}
	t.Setenv("DATABASE_URL", "")
	if c := ResolveTenantStateChecker(nil, "test"); c != nil {
		t.Fatalf("no DATABASE_URL must resolve to a nil interface, got %#v", c)
	}
	explicit := &stubTenantState{}
	if ResolveTenantStateChecker(explicit, "test") != explicit {
		t.Fatal("an explicit checker must win")
	}
}

func TestIsTenantBlockAllowedPath(t *testing.T) {
	for path, want := range map[string]bool{
		"/api/v1/auth-service/auth/logout":        true,
		"/auth/logout":                            true,
		"/api/v1/auth-service/auth/me":            false,
		"/api/v1/auth-service/auth/logout/x":      false,
		"/a/b/c/d/auth/logout":                    false,
		"/api/v1/inventory-service/assets/logout": false,
	} {
		if got := IsTenantBlockAllowedPath(path); got != want {
			t.Errorf("IsTenantBlockAllowedPath(%q) = %v, want %v", path, got, want)
		}
	}
}
