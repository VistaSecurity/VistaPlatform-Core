package api

// DB-integration coverage for tenant suspension / deletion enforcement
// (admin-ui review RC-4, item 3). Skips unless TEST_DATABASE_URL is
// set (see docsv4/internal/developer/standards/DB_INTEGRATION_TESTS.md).
//
// Owner decision: a suspended, canceled or soft-deleted tenant is not usable.
// Before this change suspension wrote tenants.payment_status and deletion wrote
// tenants.deleted_at, and NOTHING on the login, refresh or request path read
// either column — the only effect of "Suspend" was that background scans
// stopped. These tests drive the REAL auth-service router (SetupRouter) over
// the non-owner app role and the bypass role, exactly as production wires them,
// so deleting the enforcement wiring turns them red — not just the helper.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/apitokens"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	passwordsvc "github.com/vistasecurity/vistaplatform/shared/security/password"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const suspensionTestSigningSecret = "test-secret-for-tenant-suspension"

// suspensionLoginCredential is the sign-in secret for the seeded tenant user.
// Deliberately not named *PASSWORD* (gitleaks treats that as a real secret).
const suspensionLoginCredential = "Susp3nd-Test!Login"

type suspensionFixture struct {
	owner    *sql.DB
	router   *gin.Engine
	tenantID uuid.UUID
	email    string
}

func newSuspensionFixture(t *testing.T) suspensionFixture {
	t.Helper()
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	bypass := testdb.ConnectAsBypassRole(t, owner)

	tenantID := testdb.NewTenant(t, owner)
	hash, err := passwordsvc.NewPasswordService().HashPassword(suspensionLoginCredential)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	userID := uuid.New()
	email := "susp-" + userID.String()[:8] + "@example.test"
	if _, err := owner.Exec(`
		INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, is_active, email_verified)
		VALUES ($1, $2, $3, $4, 'Sus', 'Pended', true, true)`, userID, tenantID, email, hash); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// The per-request tenant-state cache is disabled so a state change is
	// visible on the very next request; the cache's own expiry is pinned by
	// the unit tests in shared/tenantstate.
	t.Setenv("TENANT_STATE_CACHE_TTL", "0s")

	gin.SetMode(gin.TestMode)
	cfg := &config.Config{JWTSecret: suspensionTestSigningSecret, JWTExpiry: time.Hour}
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}) // never dialed: no rate limiter, no REDIS_URL
	t.Cleanup(func() { _ = rdb.Close() })
	return suspensionFixture{
		owner:    owner,
		router:   SetupRouter(cfg, app, bypass, rdb, nil, EditionHooks{}),
		tenantID: tenantID,
		email:    email,
	}
}

type suspensionTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (f suspensionFixture) login(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service/auth/login",
		strings.NewReader(`{"email":"`+f.email+`","password":"`+suspensionLoginCredential+`"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

func (f suspensionFixture) mustLogin(t *testing.T) suspensionTokens {
	t.Helper()
	w := f.login(t)
	if w.Code != http.StatusOK {
		t.Fatalf("login of a live tenant = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var tok suspensionTokens
	if err := json.Unmarshal(w.Body.Bytes(), &tok); err != nil || tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Fatalf("login returned no tokens: %v; body=%s", err, w.Body.String())
	}
	return tok
}

func (f suspensionFixture) refresh(t *testing.T, refreshToken string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service/auth/refresh",
		strings.NewReader(`{"refresh_token":"`+refreshToken+`"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

// me presents an already-issued access token to auth-service's own
// RequireAuth-protected GET /auth/me.
func (f suspensionFixture) me(t *testing.T, accessToken string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth-service/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

// dataPlane presents an already-issued access token to the SHARED
// RequireJWTAuth middleware every other service mounts, built the way those
// services build it: no explicit tenant checker, so the default one resolves
// from DATABASE_URL exactly as it does in a pod.
func dataPlane(t *testing.T, accessToken string) *httptest.ResponseRecorder {
	t.Helper()
	t.Setenv("DATABASE_URL", os.Getenv("TEST_DATABASE_URL"))
	r := gin.New()
	r.Use(sharedmw.RequireJWTAuth(sharedmw.AuthConfig{JWTSecret: suspensionTestSigningSecret}))
	r.GET("/api/v1/inventory-service/probe", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	req := httptest.NewRequest(http.MethodGet, "/api/v1/inventory-service/probe", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func assertRefused(t *testing.T, what string, w *httptest.ResponseRecorder, wantCode string) {
	t.Helper()
	if w.Code != http.StatusForbidden {
		t.Errorf("%s = %d, want 403 (%s); body=%.200s", what, w.Code, wantCode, w.Body.String())
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.Code != wantCode {
		t.Errorf("%s code = %q, want %q; body=%s", what, body.Code, wantCode, w.Body.String())
	}
}

// TestIntegration_TenantSuspension_BlocksLoginRefreshAndLiveTokens covers every
// state the owner named as "not usable".
func TestIntegration_TenantSuspension_BlocksLoginRefreshAndLiveTokens(t *testing.T) {
	cases := []struct {
		name     string
		mutate   string
		wantCode string
	}{
		{"suspended", `UPDATE tenants SET payment_status = 'suspended' WHERE id = $1`, "tenant_suspended"},
		{"canceled", `UPDATE tenants SET payment_status = 'canceled' WHERE id = $1`, "tenant_suspended"},
		{"soft-deleted", `UPDATE tenants SET deleted_at = NOW() WHERE id = $1`, "tenant_deleted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSuspensionFixture(t)

			// A live tenant works end to end — the baseline the refusals below
			// are measured against.
			tok := f.mustLogin(t)
			if w := f.me(t, tok.AccessToken); w.Code != http.StatusOK {
				t.Fatalf("live tenant /auth/me = %d; body=%s", w.Code, w.Body.String())
			}
			if w := dataPlane(t, tok.AccessToken); w.Code != http.StatusNoContent {
				t.Fatalf("live tenant data plane = %d; body=%s", w.Code, w.Body.String())
			}

			if _, err := f.owner.Exec(tc.mutate, f.tenantID); err != nil {
				t.Fatalf("mutate tenant: %v", err)
			}

			assertRefused(t, "login", f.login(t), tc.wantCode)
			assertRefused(t, "refresh", f.refresh(t, tok.RefreshToken), tc.wantCode)
			assertRefused(t, "existing access token on auth-service", f.me(t, tok.AccessToken), tc.wantCode)
			assertRefused(t, "existing access token on the shared data-plane middleware", dataPlane(t, tok.AccessToken), tc.wantCode)
		})
	}
}

// TestIntegration_TenantSuspension_Reactivation — lifting the suspension
// restores sign-in. A gate that refused every caller would pass the test above;
// this is the other polarity.
func TestIntegration_TenantSuspension_Reactivation(t *testing.T) {
	f := newSuspensionFixture(t)
	f.mustLogin(t)
	if _, err := f.owner.Exec(`UPDATE tenants SET payment_status = 'suspended' WHERE id = $1`, f.tenantID); err != nil {
		t.Fatal(err)
	}
	assertRefused(t, "login while suspended", f.login(t), "tenant_suspended")
	if _, err := f.owner.Exec(`UPDATE tenants SET payment_status = 'trial' WHERE id = $1`, f.tenantID); err != nil {
		t.Fatal(err)
	}
	tok := f.mustLogin(t)
	if w := f.me(t, tok.AccessToken); w.Code != http.StatusOK {
		t.Fatalf("reactivated tenant /auth/me = %d; body=%.300s", w.Code, w.Body.String())
	}
}

// TestIntegration_TenantSuspension_InvitationAcceptRefusedBeforeAccountExists —
// accepting an invitation into a suspended organization is refused, and is
// refused BEFORE the account is created: the invitation stays pending and no
// users row is left behind. Mutation: delete the early tenantstate.Gate check
// in AcceptInvitation — the session mint still refuses (403), but the users
// row now exists and the invitation is consumed, so the later assertions fail.
func TestIntegration_TenantSuspension_InvitationAcceptRefusedBeforeAccountExists(t *testing.T) {
	f := newSuspensionFixture(t)
	raw, hash, err := newInvitationToken()
	if err != nil {
		t.Fatal(err)
	}
	invitee := "invitee-" + uuid.NewString()[:8] + "@example.test"
	if _, err := f.owner.Exec(`
		INSERT INTO invitations (tenant_id, email, role, token_hash, status, expires_at)
		VALUES ($1, $2, 'viewer', $3, 'pending', NOW() + interval '1 day')`,
		f.tenantID, invitee, hash); err != nil {
		t.Fatalf("seed invitation: %v", err)
	}
	if _, err := f.owner.Exec(`UPDATE tenants SET payment_status = 'suspended' WHERE id = $1`, f.tenantID); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service/auth/invitations/accept",
		strings.NewReader(`{"token":"`+raw+`","password":"`+suspensionLoginCredential+`"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	assertRefused(t, "invitation accept", w, "tenant_suspended")

	var users int
	if err := f.owner.QueryRow(`SELECT count(*) FROM users WHERE lower(email) = lower($1)`, invitee).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if users != 0 {
		t.Fatalf("a users row was created for a suspended organization (%d rows)", users)
	}
	var status string
	if err := f.owner.QueryRow(`SELECT status FROM invitations WHERE token_hash = $1`, hash).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		t.Fatalf("invitation status = %q, want it left pending", status)
	}
}

// TestIntegration_TenantSuspension_PATExchangeRefused — a personal access token
// minted while the tenant was live exchanges for nothing once the tenant is
// deleted (the exchange is how mcp-service turns a PAT into a JWT).
func TestIntegration_TenantSuspension_PATExchangeRefused(t *testing.T) {
	const hmacKeyForTest = "suspension-test-internal-hmac" // not a real credential
	t.Setenv("INTERNAL_AUTH_SECRET", hmacKeyForTest)
	f := newSuspensionFixture(t)

	var userID uuid.UUID
	if err := f.owner.QueryRow(`SELECT id FROM users WHERE email = $1`, f.email).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	app := testdb.ConnectAsAppRole(t, f.owner)
	bypass := testdb.ConnectAsBypassRole(t, f.owner)
	_, plaintext, err := apitokens.NewService(app, bypass).Create(f.tenantID, userID, "suspension-test", nil, 30)
	if err != nil {
		t.Fatalf("mint PAT: %v", err)
	}

	exchange := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service/internal/api-tokens/exchange",
			strings.NewReader(`{"token":"`+plaintext+`"}`))
		req.Header.Set("Content-Type", "application/json")
		serviceauth.NewSigner(hmacKeyForTest).SignRequest(req)
		w := httptest.NewRecorder()
		f.router.ServeHTTP(w, req)
		return w
	}
	if w := exchange(); w.Code != http.StatusOK {
		t.Fatalf("live tenant PAT exchange = %d; body=%.300s", w.Code, w.Body.String())
	}
	if _, err := f.owner.Exec(`UPDATE tenants SET deleted_at = NOW() WHERE id = $1`, f.tenantID); err != nil {
		t.Fatal(err)
	}
	assertRefused(t, "PAT exchange", exchange(), "tenant_deleted")
}
