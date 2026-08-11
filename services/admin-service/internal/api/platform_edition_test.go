package api

// Edition read-out tests.
//
// This file has NO build tag and imports nothing from ee/, so it survives the
// open-source repo cut and keeps proving the invariant in a public checkout.
//
// What is actually at stake: admin-ui-v2 renders its navigation from this
// endpoint. If it wrongly reports "the management plane is here" on a Core
// build, the console offers a Tenants tab whose backend does not exist and the
// operator gets "couldn't load tenants" — the bug this endpoint exists to fix.
// If it wrongly reports "absent" on an Enterprise build, a paying deployment
// loses half its console. So BOTH directions are pinned here, and the
// Enterprise direction is exercised by wiring STUB hooks — non-nil funcs are
// exactly what the //go:build ee file supplies, and using stubs keeps this test
// importable from a tree with no ee/ in it.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/models"
)

// stubMSPHooks / stubBillingHooks stand in for what cmd/edition_ee.go wires.
// Only their non-nil-ness matters to the seam.
func stubMSPHook() func(MSPDeps) MSPRuntime { return func(MSPDeps) MSPRuntime { return nil } }
func stubBillingHook() func(BillingDeps) BillingRuntime {
	return func(BillingDeps) BillingRuntime { return nil }
}

func TestEditionInfo_ReportsHookPresence(t *testing.T) {
	cases := []struct {
		name        string
		hooks       EditionHooks
		wantEdition string
		wantMSP     bool
		wantBilling bool
	}{
		{
			name:        "core build: no ee wiring at all",
			hooks:       EditionHooks{},
			wantEdition: "core",
		},
		{
			name:        "enterprise build: both surfaces wired",
			hooks:       EditionHooks{RegisterMSP: stubMSPHook(), RegisterBilling: stubBillingHook()},
			wantEdition: "enterprise",
			wantMSP:     true,
			wantBilling: true,
		},
		{
			// Both hooks come from the same //go:build ee file today, but the
			// capability fields are independent by construction, so pin that.
			name:        "management plane without billing",
			hooks:       EditionHooks{RegisterMSP: stubMSPHook()},
			wantEdition: "enterprise",
			wantMSP:     true,
		},
		{
			name:        "billing without management plane",
			hooks:       EditionHooks{RegisterBilling: stubBillingHook()},
			wantEdition: "enterprise",
			wantBilling: true,
		},
		{
			// The token seeder and the tier pricer are NOT route surfaces.
			// A build carrying only those must not claim either capability.
			name:        "non-route hooks do not grant capabilities",
			hooks:       EditionHooks{ApplyEditionToken: func(*sql.DB) {}},
			wantEdition: "core",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.hooks.Info()
			if got.Edition != tc.wantEdition {
				t.Errorf("Edition = %q, want %q", got.Edition, tc.wantEdition)
			}
			if got.Capabilities.MSP != tc.wantMSP {
				t.Errorf("Capabilities.MSP = %v, want %v", got.Capabilities.MSP, tc.wantMSP)
			}
			if got.Capabilities.Billing != tc.wantBilling {
				t.Errorf("Capabilities.Billing = %v, want %v", got.Capabilities.Billing, tc.wantBilling)
			}
		})
	}
}

// TestPlatformEditionHandler_WireShape pins the JSON the console parses. The
// field names are a contract with admin-ui-v2/src/lib/edition.ts and the
// OpenAPI spec; renaming one silently turns every gate into "capability
// absent", which fails CLOSED and hides working surfaces.
func TestPlatformEditionHandler_WireShape(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/edition", PlatformEdition(EditionHooks{}.Info()))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/edition", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v (body %s)", err, w.Body.String())
	}
	if raw["edition"] != "core" {
		t.Errorf(`body["edition"] = %v, want "core"`, raw["edition"])
	}
	caps, ok := raw["capabilities"].(map[string]any)
	if !ok {
		t.Fatalf(`body["capabilities"] is %T, want object`, raw["capabilities"])
	}
	if caps["msp"] != false {
		t.Errorf(`capabilities.msp = %v, want false`, caps["msp"])
	}
	if caps["billing"] != false {
		t.Errorf(`capabilities.billing = %v, want false`, caps["billing"])
	}
}

// --- end-to-end through the real router --------------------------------------

const editionTestJWTSecret = "edition-test-secret-not-a-real-key"

// editionTestServer builds the real admin-service router with the given hooks.
// Same lazy-*sql.DB trick as router_core_test.go: nothing dials, and this
// endpoint touches no database at all.
func editionTestServer(t *testing.T, hooks EditionHooks) *Server {
	t.Helper()
	db, err := sql.Open("postgres", "postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewServerWithConnections(
		&config.Config{Environment: "test", JWTSecret: editionTestJWTSecret},
		db, db, hooks,
	)
}

// operatorToken mints a platform access token the real auth middleware accepts:
// no tenant_id (so the request is typed as a platform user), type "access", and
// no pwd_change_required. Nothing here reads the database.
func operatorToken(t *testing.T) string {
	t.Helper()
	claims := models.JWTClaims{
		UserID: uuid.New(),
		Email:  "operator@example.test",
		Role:   "platform_admin",
		Type:   "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(editionTestJWTSecret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

// getEdition drives GET /admin/platform/edition through the whole real chain —
// gin tree, auth middleware, handler — and returns the decoded body.
func getEdition(t *testing.T, srv *Server) (int, EditionInfo) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin-service/admin/platform/edition", nil)
	req.Header.Set("Authorization", "Bearer "+operatorToken(t))
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	var info EditionInfo
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &info); err != nil {
			t.Fatalf("unmarshal: %v (body %s)", err, w.Body.String())
		}
	}
	return w.Code, info
}

// TestPlatformEdition_CoreRouterReportsCore is the assertion that matters most:
// the endpoint has to be answerable, and honest, on a build with no ee/ tree.
func TestPlatformEdition_CoreRouterReportsCore(t *testing.T) {
	code, info := getEdition(t, editionTestServer(t, EditionHooks{}))
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a Core build MUST answer this route", code)
	}
	if info.Edition != "core" {
		t.Errorf("edition = %q, want %q", info.Edition, "core")
	}
	if info.Capabilities.MSP {
		t.Error("capabilities.msp = true on a Core router — the console would show a Tenants tab that 404s")
	}
	if info.Capabilities.Billing {
		t.Error("capabilities.billing = true on a Core router — the console would show Billing & Revenue that 404s")
	}
}

// TestPlatformEdition_EnterpriseRouterReportsCapabilities is the other
// direction. Without it, a gate hard-coded to "core" would look perfectly
// correct against the only deployment anyone can test locally.
func TestPlatformEdition_EnterpriseRouterReportsCapabilities(t *testing.T) {
	srv := editionTestServer(t, EditionHooks{RegisterMSP: stubMSPHook(), RegisterBilling: stubBillingHook()})
	code, info := getEdition(t, srv)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if info.Edition != "enterprise" {
		t.Errorf("edition = %q, want %q", info.Edition, "enterprise")
	}
	if !info.Capabilities.MSP {
		t.Error("capabilities.msp = false on an Enterprise router — a paying deployment would lose its Tenants tab")
	}
	if !info.Capabilities.Billing {
		t.Error("capabilities.billing = false on an Enterprise router — a paying deployment would lose Billing & Revenue")
	}
}

// TestPlatformEdition_RequiresAuth keeps the read-out off the public surface.
// It is not a secret, but it hangs off the platform-admin group and an
// unauthenticated 200 here would mean the group's middleware stopped applying.
func TestPlatformEdition_RequiresAuth(t *testing.T) {
	srv := editionTestServer(t, EditionHooks{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin-service/admin/platform/edition", nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", w.Code)
	}
}
