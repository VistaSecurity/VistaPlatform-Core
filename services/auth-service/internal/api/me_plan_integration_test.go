package api

// GET /auth/me on an Enterprise install, through the REAL SetupRouter over a
// real database: the copy guard for the one tenant-facing response that used
// to serialise the raw tenant row.
//
// The tenant is created by a real signup and then put where an Enterprise
// install's tenants used to sit before the reconciler normalised them — the
// seeded community tier, payment_status 'trial', a trial_ends_at. /auth/me
// must still read "Vista Platform Enterprise" with the licensee, and never
// "community" or "trial". Removing the plan resolver wiring from SetupRouter,
// or serialising models.Tenant again in GetMe, turns this red.
//
// Scratch database: it writes the install's one platform_license row. Skips
// without TEST_DATABASE_URL.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_GetMe_EnterprisePlanThroughTheRealRouter(t *testing.T) {
	owner := testdb.ScratchDatabase(t)
	app := testdb.ConnectScratchAsAppRole(t, owner)
	bypass := testdb.ConnectScratchAsBypassRole(t, owner)
	t.Cleanup(entitlements.FlushLicenseCache)

	gin.SetMode(gin.TestMode)
	cfg := &config.Config{JWTSecret: "test-secret-auth-me-plan", JWTExpiry: time.Hour}
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}) // never dialed on these paths
	t.Cleanup(func() { _ = rdb.Close() })
	router := SetupRouter(cfg, app, bypass, rdb, nil, EditionHooks{})

	// Sign up on Core (no licence yet), which creates the tenant and its first
	// user.
	id := uuid.NewString()[:8]
	email := "me-" + id + "@example.test"
	body := `{"email":"` + email + `","password":"Me!Plan-2026-xyz","first_name":"Me","last_name":"Plan","tenant_name":"Me Plan ` + id + `","accepted_legal":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service/auth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var reg struct {
		User struct {
			ID       uuid.UUID `json:"id"`
			TenantID uuid.UUID `json:"tenant_id"`
			Role     string    `json:"role"`
		} `json:"user"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reg); err != nil || reg.User.ID == uuid.Nil || reg.User.TenantID == uuid.Nil {
		t.Fatalf("register response has no user (err %v): %s", err, w.Body.String())
	}
	// Signup leaves the address unverified, so no session comes back: mint the
	// user's access token the way login would.
	access, _, err := auth.NewJWTService(cfg.JWTSecret, time.Hour, time.Hour).
		GenerateTokens(reg.User.ID, reg.User.TenantID, email, reg.User.Role)
	if err != nil {
		t.Fatal(err)
	}

	// The pre-normalisation Enterprise tenant, then the Enterprise licence.
	if _, err := owner.Exec(`UPDATE tenants SET subscription_tier_id = (SELECT id FROM subscription_tiers WHERE name = 'community'),
		payment_status = 'trial', trial_ends_at = now() + interval '30 days'
		WHERE id = (SELECT tenant_id FROM users WHERE email = $1)`, email); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`INSERT INTO platform_license (subject, edition, licensee, expires_at, token_sha256)
		VALUES ('it', 'enterprise', 'Acme Corp', now() + interval '90 days', 'x')`); err != nil {
		t.Fatal(err)
	}
	entitlements.FlushLicenseCache()

	me := func() (int, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth-service/auth/me", nil)
		req.Header.Set("Authorization", "Bearer "+access)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	code, got := me()
	if code != http.StatusOK {
		t.Fatalf("GET /auth/me: %d %s", code, got)
	}
	var resp struct {
		Tenant map[string]any     `json:"tenant"`
		Plan   *entitlements.Plan `json:"plan"`
	}
	if err := json.Unmarshal([]byte(got), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Tenant == nil {
		t.Fatalf("no tenant: %s", got)
	}
	if resp.Plan == nil || resp.Plan.Edition != entitlements.EditionEnterprise ||
		resp.Plan.DisplayName != entitlements.PlanDisplayNameEnterprise ||
		resp.Plan.Licensee == nil || *resp.Plan.Licensee != "Acme Corp" || resp.Plan.Trial != nil {
		t.Fatalf("plan = %+v, want Vista Platform Enterprise for Acme Corp, no trial: %s", resp.Plan, got)
	}
	lower := strings.ToLower(got)
	for _, word := range []string{"community", "trial"} {
		if strings.Contains(lower, word) {
			t.Errorf("Enterprise /auth/me contains %q: %s", word, got)
		}
	}
}
