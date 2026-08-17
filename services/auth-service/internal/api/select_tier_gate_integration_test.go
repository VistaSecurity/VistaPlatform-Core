package api

// DB-integration coverage for the tier-selection gate. Skips unless
// TEST_DATABASE_URL is set (see
// docsv4/internal/developer/standards/DB_INTEGRATION_TESTS.md); runs in the
// nightly test-backend job and locally via `make test-integration-db`.
//
// The sqlmock tests next door prove the route carries the middleware and that
// the entitlement SQL is shaped as intended. What only a real database can
// show:
//
//   - the RBAC gate resolves against the SEEDED role grants — viewer and
//     tenant_admin genuinely lack billing.update, billing_admin genuinely has
//     it (the grant matrix, not a stub returning false);
//   - the entitlement query survives RLS on billing_subscriptions running as
//     the non-owner app role (a plain-pool read there returns zero rows for
//     everyone, which would deny entitled tenants);
//   - onboarding still completes end to end for a brand-new tenant that has no
//     subscription at all.

import (
	"database/sql"
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
	"github.com/vistasecurity/vistaplatform/auth-service/internal/middleware"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/rbac"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// seedSystemRoles creates the three system roles this test cares about for
// tenantID and grants them from the tenant_permissions catalogue using the same
// filters standards/permissions.yaml declares (mirrored in
// internal/auth/role_grants_gen.go, which is package-private to `auth`). The
// filters are asserted, not assumed: seedSystemRoles fails if billing_admin
// does not end up holding billing.update or if viewer/tenant_admin do.
func seedSystemRoles(t *testing.T, owner *sql.DB, tenantID uuid.UUID) {
	t.Helper()
	roles := []struct{ name, grant string }{
		{"billing_admin", "(tp.resource = 'billing' OR tp.name IN ('settings.read', 'users.read'))"},
		{"tenant_admin", "tp.name <> 'billing.update'"},
		{"viewer", "tp.action = 'read' AND tp.resource <> 'billing'"},
	}
	for _, r := range roles {
		var roleID uuid.UUID
		if err := owner.QueryRow(`
			INSERT INTO tenant_roles (tenant_id, name, display_name, is_system_role)
			VALUES ($1, $2, $2, true) RETURNING id`, tenantID, r.name).Scan(&roleID); err != nil {
			t.Fatalf("seed role %s: %v", r.name, err)
		}
		if _, err := owner.Exec(`
			INSERT INTO tenant_role_permissions (role_id, permission_id)
			SELECT $1, tp.id FROM tenant_permissions tp WHERE `+r.grant+`
			ON CONFLICT DO NOTHING`, roleID); err != nil {
			t.Fatalf("grant role %s: %v", r.name, err)
		}
	}

	// The grant matrix must actually say what the gate depends on.
	for role, want := range map[string]bool{"billing_admin": true, "tenant_admin": false, "viewer": false} {
		var has bool
		if err := owner.QueryRow(`
			SELECT EXISTS (
				SELECT 1 FROM tenant_roles r
				JOIN tenant_role_permissions rp ON rp.role_id = r.id
				JOIN tenant_permissions tp ON tp.id = rp.permission_id
				WHERE r.tenant_id = $1 AND r.name = $2 AND tp.name = 'billing.update')`,
			tenantID, role).Scan(&has); err != nil {
			t.Fatalf("verify grant for %s: %v", role, err)
		}
		if has != want {
			t.Fatalf("%s holds billing.update = %v, want %v — the seeded role design changed; revisit the gate on POST /auth/select-tier (#1026)", role, has, want)
		}
	}
}

func newUserInRole(t *testing.T, owner *sql.DB, tenantID uuid.UUID, role string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := owner.Exec(`
		INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name)
		VALUES ($1, $2, $3, 'x', 'Tier', 'Tester')`, id, tenantID, "tier-"+id.String()[:8]+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := owner.Exec(`
		INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, is_active)
		SELECT $1, $2, id, true FROM tenant_roles WHERE tenant_id = $2 AND name = $3`,
		id, tenantID, role); err != nil {
		t.Fatalf("assign role %s: %v", role, err)
	}
	return id
}

// gatedSelectTierEngine mounts the route exactly as router.go does: the RBAC
// gate then the handler, both over the non-owner app role. The identity
// middleware stands in for RequireAuth (whose wiring the sqlmock router test
// covers), reading the acting user/tenant from test-only headers.
func gatedSelectTierEngine(app, bypass *sql.DB) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	rbacService := rbac.NewRBACService(app)
	// db = the non-owner app role (so RLS is real); bypassDB = the BYPASSRLS
	// pool, matching production — the user→tenant lookup is deliberately
	// cross-tenant (the tenant is the query OUTPUT).
	h := &AuthHandlers{authService: &stubAuthServiceStore{db: app, bypassDB: bypass}}
	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		c.Set("userID", c.GetHeader("X-Test-User"))
		c.Set("tenantID", c.GetHeader("X-Test-Tenant"))
		c.Next()
	})
	grp.POST("/auth/select-tier",
		middleware.RequirePermission(rbacService, "billing.update"),
		h.SelectTier)
	return r
}

func postSelectTier(t *testing.T, engine *gin.Engine, userID, tenantID, tierID uuid.UUID) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service/auth/select-tier",
		strings.NewReader(`{"subscription_tier_id":"`+tierID.String()+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-User", userID.String())
	req.Header.Set("X-Test-Tenant", tenantID.String())
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

func tierIDByName(t *testing.T, owner *sql.DB, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := owner.QueryRow(`SELECT id FROM subscription_tiers WHERE name = $1`, name).Scan(&id); err != nil {
		t.Skipf("subscription tier %q not present — database is not seeded: %v", name, err)
	}
	return id
}

func tenantTier(t *testing.T, owner *sql.DB, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.NullUUID
	if err := owner.QueryRow(`SELECT subscription_tier_id FROM tenants WHERE id = $1`, tenantID).Scan(&id); err != nil {
		t.Fatalf("read tenant tier: %v", err)
	}
	return id.UUID
}

// TestIntegration_SelectTier_RBACGate proves who may call it at all, against
// the real seeded grant matrix.
func TestIntegration_SelectTier_RBACGate(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	tenantID := testdb.NewTenant(t, owner)
	seedSystemRoles(t, owner, tenantID)

	freeTier := tierIDByName(t, owner, "free")
	engine := gatedSelectTierEngine(app, owner)

	for _, tc := range []struct {
		role string
		want int
	}{
		{"viewer", http.StatusForbidden},
		// tenant_admin is deliberately WITHOUT billing.update in the seeded
		// role design ("reads billing but cannot change it") — so it cannot
		// change the plan either. Flagged for the owner in.
		{"tenant_admin", http.StatusForbidden},
		{"billing_admin", http.StatusOK},
	} {
		t.Run(tc.role, func(t *testing.T) {
			user := newUserInRole(t, owner, tenantID, tc.role)
			w := postSelectTier(t, engine, user, tenantID, freeTier)
			if w.Code != tc.want {
				t.Fatalf("%s: status = %d, want %d; body=%s", tc.role, w.Code, tc.want, w.Body.String())
			}
			if tc.want == http.StatusForbidden && tenantTier(t, owner, tenantID) == freeTier {
				t.Fatalf("%s was refused but the tenant tier was written anyway", tc.role)
			}
		})
	}

	if got := tenantTier(t, owner, tenantID); got != freeTier {
		t.Fatalf("tenant tier = %s after the billing_admin call, want %s", got, freeTier)
	}
}

// TestIntegration_SelectTier_PaidTierNeedsActiveSubscription is the paywall:
// the same permitted caller is refused a paid tier until a subscription exists.
func TestIntegration_SelectTier_PaidTierNeedsActiveSubscription(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	tenantID := testdb.NewTenant(t, owner)
	seedSystemRoles(t, owner, tenantID)

	proTier := tierIDByName(t, owner, "pro")
	user := newUserInRole(t, owner, tenantID, "billing_admin")
	engine := gatedSelectTierEngine(app, owner)

	if w := postSelectTier(t, engine, user, tenantID, proTier); w.Code != http.StatusPaymentRequired {
		t.Fatalf("unsubscribed tenant: status = %d, want 402; body=%s", w.Code, w.Body.String())
	}
	if got := tenantTier(t, owner, tenantID); got == proTier {
		t.Fatal("a paid tier was assigned without a subscription — the paywall is not holding")
	}

	// Now give the tenant a real active subscription for that plan.
	var providerID uuid.UUID
	if err := owner.QueryRow(`
		INSERT INTO billing_providers (key, display_name, is_active)
		VALUES ($1, 'Test Provider', true) RETURNING id`, "test-"+uuid.NewString()[:8]).Scan(&providerID); err != nil {
		t.Fatalf("seed billing provider: %v", err)
	}
	t.Cleanup(func() { _, _ = owner.Exec(`DELETE FROM billing_providers WHERE id = $1`, providerID) })
	if _, err := owner.Exec(`
		INSERT INTO billing_subscriptions (tenant_id, provider_id, external_subscription_id, plan_key, status)
		VALUES ($1, $2, $3, 'pro', 'active')`, tenantID, providerID, "sub_"+uuid.NewString()[:8]); err != nil {
		t.Fatalf("seed subscription: %v", err)
	}

	if w := postSelectTier(t, engine, user, tenantID, proTier); w.Code != http.StatusOK {
		t.Fatalf("entitled tenant: status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if got := tenantTier(t, owner, tenantID); got != proTier {
		t.Fatalf("tenant tier = %s, want %s", got, proTier)
	}
}

// TestIntegration_Onboarding_CompletesWithoutSubscription is requirement 3 of
//: a brand-new tenant, with no subscription and no RBAC roles yet, must
// still be able to finish signup and land on the free tier. It drives the real
// POST /auth/register/complete handler over the real AuthService — the path the
// signup UI actually posts to (frontend-v2 complete-profile-page.tsx), which is
// NOT the gated select-tier route.
func TestIntegration_Onboarding_CompletesWithoutSubscription(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)

	freeTier := tierIDByName(t, owner, "free")

	cfg := &config.Config{JWTSecret: "test-secret-onboarding", JWTExpiry: time.Hour}
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer func() { _ = rdb.Close() }()
	jwtService := auth.NewJWTService(cfg.JWTSecret, time.Hour, 24*time.Hour)
	authService := auth.NewAuthService(app, owner, rdb, jwtService)
	handlers := NewAuthHandlers(authService, cfg, nil)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/v1/auth-service/auth/register/complete", handlers.CompleteRegistration)

	email := "founder-" + uuid.NewString()[:8] + "@example.test"
	body := `{"email":"` + email + `","password":"Hunter2Hunter2!","first_name":"New","last_name":"Founder",` +
		`"tenant_name":"Onboarding Test ` + uuid.NewString()[:6] + `","subscription_tier_id":"` + freeTier.String() + `","accepted_legal":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service/auth/register/complete", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("signup status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		User struct {
			ID       uuid.UUID `json:"id"`
			TenantID uuid.UUID `json:"tenant_id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode signup response: %v; body=%s", err, w.Body.String())
	}
	newTenant := resp.User.TenantID
	t.Cleanup(func() { _, _ = owner.Exec(`DELETE FROM tenants WHERE id = $1`, newTenant) })

	if got := tenantTier(t, owner, newTenant); got != freeTier {
		t.Fatalf("new tenant tier = %s, want the free tier %s — onboarding no longer assigns a tier", got, freeTier)
	}

	// And the same brand-new tenant may NOT be walked onto a paid tier through
	// the signup path either.
	paid := tierIDByName(t, owner, "pro")
	body = `{"email":"founder2-` + uuid.NewString()[:8] + `@example.test","password":"Hunter2Hunter2!","first_name":"A","last_name":"B",` +
		`"tenant_name":"Paid Attempt ` + uuid.NewString()[:6] + `","subscription_tier_id":"` + paid.String() + `","accepted_legal":true}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth-service/auth/register/complete", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("signup onto a paid tier: status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}
