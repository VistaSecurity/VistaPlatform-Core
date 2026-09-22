package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/audit-service/internal/config"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/database"
)

// Wiring tests for the platform-identity gate on audit-service's
// platform-GLOBAL configuration surfaces (C4/H2, v1.0.0 security audit).
//
// These drive the REAL router — newRouter, the same function main() calls —
// rather than a hand-built stand-in, because the defect being fixed was never
// in a helper: the gate was simply absent from the route table. A test that
// exercised RequirePlatformIdentity in isolation would stay green with the
// `platformConfig.Use(...)` line deleted, which is precisely the failure mode
// the audit called out. Delete that line and
// TestProductionRouter_RetentionPoliciesRejectTenantAdmin goes red.
//
// The gate's 403 body ("Platform user required") is asserted, not just the
// status: with the handler bundle zero-valued and the DB wrapper holding no
// connection, the permission gate answers 503 for a tenant, so a bare
// "expect 403" would pass for the wrong reason (and keep passing if the gate
// were replaced by something that merely failed).

const testJWTSecret = "test-jwt-secret"

// mintToken issues an HS256 access token newRouter's RequireAuth accepts.
// A non-nil tenantID makes it a TENANT token (userType=tenant); empty makes it
// a PLATFORM token, which is exactly the distinction the gate turns on.
func mintToken(t *testing.T, role, tenantID string) string {
	t.Helper()
	userID := uuid.NewString()
	claims := jwt.MapClaims{
		"user_id": userID,
		"email":   "gate-test@example.com",
		"role":    role,
		"type":    "access",
		"iss":     "crypto-inventory-auth",
		"aud":     "crypto-inventory",
		"sub":     userID,
		"jti":     uuid.NewString(),
		"iat":     time.Now().Unix(),
		"nbf":     time.Now().Add(-time.Minute).Unix(),
		"exp":     time.Now().Add(time.Hour).Unix(),
	}
	if tenantID != "" {
		claims["tenant_id"] = tenantID
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func tenantAdminToken(t *testing.T) string {
	t.Helper()
	return mintToken(t, "tenant_admin", uuid.NewString())
}

func platformAdminToken(t *testing.T) string {
	t.Helper()
	return mintToken(t, "platform_admin", "")
}

// probeSIEMExporter is a stand-in for the Enterprise exporter. It mounts one
// route on whatever group main() hands RegisterRoutes, which is how this test
// observes WHICH group that is: a 200 for a tenant admin means the SIEM CRUD
// was mounted outside the platform gate, as it was before this fix.
type probeSIEMExporter struct{}

func (probeSIEMExporter) SendEvent(context.Context, map[string]interface{}) {}
func (probeSIEMExporter) LoadIntegrations(context.Context) error            { return nil }
func (probeSIEMExporter) Start(context.Context)                             {}
func (p probeSIEMExporter) RegisterRoutes(api *gin.RouterGroup) {
	api.GET("/audit-service/siem/integrations", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"integrations": []string{}})
	})
}

func newGateTestRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	mw := newTestAuditMiddleware(t)
	cfg := &config.Config{
		JWT:                config.JWTConfig{Secret: testJWTSecret},
		InternalAuthSecret: "test-internal-secret",
	}
	return newRouter(cfg, &database.DB{}, mw, routerHandlers{siemExport: probeSIEMExporter{}})
}

func doWithToken(t *testing.T, r *gin.Engine, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// assertPlatformGateRefused asserts the platform-identity gate — and not some
// other failure that happens to share its status — answered this request.
func assertPlatformGateRefused(t *testing.T, w *httptest.ResponseRecorder, what string) {
	t.Helper()
	if w.Code != http.StatusForbidden {
		t.Fatalf("%s = %d, want 403 (tenant identity must not reach platform-global config)", what, w.Code)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s: decode body %q: %v", what, w.Body.String(), err)
	}
	if body.Error != "Platform user required" {
		t.Fatalf("%s refused with %q, want the platform-identity gate's %q — a 403 from some other gate is not this fix",
			what, body.Error, "Platform user required")
	}
}

// C4: every retention-policy route, including the two that carried NO
// permission gate at all, refuses a tenant admin. Setting
// total_retention_days=0 here is what destroyed every tenant's audit history.
func TestProductionRouter_RetentionPoliciesRejectTenantAdmin(t *testing.T) {
	r := newGateTestRouter(t)
	token := tenantAdminToken(t)

	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/audit-service/retention-policies"},
		{http.MethodGet, "/api/v1/audit-service/retention-policies/" + uuid.NewString()},
		{http.MethodPost, "/api/v1/audit-service/retention-policies"},
		{http.MethodPut, "/api/v1/audit-service/retention-policies/" + uuid.NewString()},
	} {
		w := doWithToken(t, r, rt.method, rt.path, token)
		assertPlatformGateRefused(t, w, rt.method+" "+rt.path)
	}
}

// The other polarity: an over-strict gate that also locked out the platform
// admin would be the same bug pointed the other way, and admin-ui-v2's
// Security → Retention page is the surface that has to keep working. The
// handler bundle is zero-valued, so reaching it panics into gin's recovery —
// any answer that is NOT the identity gate's 403 proves the gate let the
// platform token through.
func TestProductionRouter_RetentionPoliciesAllowPlatformAdmin(t *testing.T) {
	r := newGateTestRouter(t)
	w := doWithToken(t, r, http.MethodGet, "/api/v1/audit-service/retention-policies", platformAdminToken(t))

	if w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), "Platform user required") {
		t.Fatalf("platform admin was refused by the platform-identity gate: %s", w.Body.String())
	}
}

// H2: the SIEM CRUD must be mounted INSIDE the platform gate. The probe
// exporter answers 200 unconditionally, so a 200 here means the group main()
// passed to RegisterRoutes was ungated.
func TestProductionRouter_SIEMRoutesRejectTenantAdmin(t *testing.T) {
	r := newGateTestRouter(t)
	w := doWithToken(t, r, http.MethodGet, "/api/v1/audit-service/siem/integrations", tenantAdminToken(t))
	assertPlatformGateRefused(t, w, "GET /siem/integrations")
}

func TestProductionRouter_SIEMRoutesAllowPlatformAdmin(t *testing.T) {
	r := newGateTestRouter(t)
	w := doWithToken(t, r, http.MethodGet, "/api/v1/audit-service/siem/integrations", platformAdminToken(t))
	if w.Code != http.StatusOK {
		t.Fatalf("platform admin GET /siem/integrations = %d (%s), want 200", w.Code, w.Body.String())
	}
}

// The gate belongs to the platform-global group only. The rest of the tenant
// API — the audit trail a tenant legitimately reads — must NOT have acquired
// it, which a group-level Use() on the wrong group would do silently.
func TestProductionRouter_TenantAuditTrailStillReachable(t *testing.T) {
	r := newGateTestRouter(t)
	w := doWithToken(t, r, http.MethodGet, "/api/v1/audit-service/activity-logs", tenantAdminToken(t))

	if w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), "Platform user required") {
		t.Fatalf("the platform gate leaked onto the tenant audit trail: %s", w.Body.String())
	}
}

var _ siemExporter = probeSIEMExporter{}
