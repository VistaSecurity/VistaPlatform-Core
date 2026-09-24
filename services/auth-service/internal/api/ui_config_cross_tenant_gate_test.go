package api

// The /tenant/:tenantId group takes the target tenant from the PATH, so a
// caller who clears its gate reads and writes ANY tenant's data. Before the
// platform-identity invariant landed, the group's only role check was
// RequireAnyRole("platform_admin", "super_admin") — a comparison against the
// role STRING in the JWT.
//
// That string is not platform-controlled. Tenant custom roles are validated
// against roleNamePattern (`^[a-z][a-z0-9_]{1,49}$`) with no reserved-name
// denylist, so a tenant admin can create a role literally named
// "platform_admin"; the login path then puts that name straight into the token
// (SELECT tr.name FROM tenant_roles ...). A tenant user could therefore GET and
// PUT the UI config of every other tenant on the platform.
//
// This is a WIRING test, in the same spirit as select_tier_gate_test.go. It
// drives the REAL SetupRouter, so deleting
// `tenantSecurity.Use(middleware.RequirePlatformIdentity())` from router.go
// fails it. The unit tests that accompany the fix exercise
// RequirePlatformIdentity in isolation and stay green through exactly that
// deletion — verified by mutation before this test was written.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
)

// crossTenantUIConfigRequest mints a TENANT token (tenant id present) whose
// role claim is the platform role string, and aims it at a DIFFERENT tenant's
// ui-config through the real router.
func crossTenantUIConfigRequest(t *testing.T, method, roleClaim string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	cfg := &config.Config{JWTSecret: "test-secret-for-cross-tenant-ui-config"}
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}) // never dialed on this path
	defer func() { _ = rdb.Close() }()

	router := SetupRouter(cfg, db, db, rdb, nil, EditionHooks{})

	attackerTenant := uuid.New()
	victimTenant := uuid.New()
	// The attacker's own tenant is live, so the refusal below has to come
	// from the identity gate, not from the tenant-state check.
	expectLiveTenantState(mock, attackerTenant)

	jwtService := auth.NewJWTService(cfg.JWTSecret, time.Hour, time.Hour)
	access, _, err := jwtService.GenerateTokens(uuid.New(), attackerTenant, "attacker@tenant.test", roleClaim)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}

	req := httptest.NewRequest(method,
		"/api/v1/auth-service/tenant/"+victimTenant.String()+"/ui-config",
		strings.NewReader(`{"primary_color":"#000000"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+access)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestTenantUIConfigByID_RejectsTenantTokenClaimingPlatformRole(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			w := crossTenantUIConfigRequest(t, method, "platform_admin")

			// 401 would also block the attack, but the identity check is what
			// must do it — the token itself is validly signed and unexpired.
			if w.Code != http.StatusForbidden {
				t.Fatalf("tenant token with role=%q reached %s /tenant/:tenantId/ui-config with status %d, want 403.\n"+
					"A tenant identity must never satisfy a platform gate, however its role string reads.\nbody: %s",
					"platform_admin", method, w.Code, w.Body.String())
			}
		})
	}
}

func TestTenantUIConfigByID_RejectsTenantTokenClaimingSuperAdmin(t *testing.T) {
	// The group allows two role strings; both must be identity-checked, or the
	// fix closes one door and leaves the other open.
	w := crossTenantUIConfigRequest(t, http.MethodPut, "super_admin")
	if w.Code != http.StatusForbidden {
		t.Fatalf("tenant token with role=\"super_admin\" reached PUT /tenant/:tenantId/ui-config with status %d, want 403.\nbody: %s",
			w.Code, w.Body.String())
	}
}

// The other polarity. A gate that rejected EVERY caller would satisfy the two
// tests above and lock platform admins out of the tenant-security endpoints —
// the same bug pointed the other way. A platform identity is a token with a nil
// tenant id, so mint one and assert it is NOT turned away at the gate.
//
// It cannot reach 200: the handler then queries an unmocked sqlmock. Asserting
// "not 403/401" is the honest assertion — it proves authorization passed, which
// is the only thing this test is about.
func TestTenantUIConfigByID_AllowsGenuinePlatformIdentity(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	cfg := &config.Config{JWTSecret: "test-secret-for-cross-tenant-ui-config"}
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer func() { _ = rdb.Close() }()

	router := SetupRouter(cfg, db, db, rdb, nil, EditionHooks{})

	jwtService := auth.NewJWTService(cfg.JWTSecret, time.Hour, time.Hour)
	// uuid.Nil tenant == platform identity, per the stamping rule in
	// auth-service's RequireAuth.
	access, _, err := jwtService.GenerateTokens(uuid.New(), uuid.Nil, "admin@platform.test", "platform_admin")
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/auth-service/tenant/"+uuid.New().String()+"/ui-config", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code == http.StatusForbidden || w.Code == http.StatusUnauthorized {
		t.Fatalf("genuine platform identity was rejected at the gate with %d — the invariant is over-strict and locks platform admins out of /tenant/:tenantId.\nbody: %s",
			w.Code, w.Body.String())
	}
}
