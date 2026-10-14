package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus/hooks/test"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/capabilities"
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/handlers"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	"github.com/vistasecurity/vistaplatform/shared/models"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

const (
	testJWTSecret      = "maintenance-service-router-test-jwt-secret"
	testInternalSecret = "maintenance-service-router-test-internal-secret"
	statusPath         = adminPrefix + "/status"
)

// The permission query the REAL shared gate asks.
var permissionQuery = regexp.QuoteMeta(`SELECT platform_user_has_permission($1, $2)`)

type okPinger struct{}

func (okPinger) PingContext(context.Context) error { return nil }

type staticVersions struct{}

func (staticVersions) Versions(context.Context) (json.RawMessage, error) {
	return json.RawMessage(`{"skew_detected":false}`), nil
}

func newTestAuditMiddleware(t *testing.T) *auditmiddleware.Middleware {
	t.Helper()
	cfg := auditmiddleware.DefaultConfig()
	cfg.ServiceName = handlers.ServiceName
	cfg.BatchSize = 1000
	cfg.FlushInterval = time.Hour
	cfg.Timeout = 10 * time.Millisecond
	cfg.AuditServiceURL = "http://127.0.0.1:1"
	mw := auditmiddleware.NewMiddleware(cfg)
	t.Cleanup(mw.Stop)
	return mw
}

// newProductionRouter builds the SAME router main() serves, with the SAME auth
// constructor and the REAL shared permission gate over a sqlmock database.
// DATABASE_URL and REDIS_URL are cleared so the shared middleware's ambient
// checkers are not built from the host's environment.
func newProductionRouter(t *testing.T) (*gin.Engine, sqlmock.Sqlmock) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	t.Setenv("DATABASE_URL", "")
	t.Setenv("REDIS_URL", "")
	t.Setenv("INTERNAL_AUTH_SECRET", testInternalSecret)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	logger, _ := test.NewNullLogger()
	h := handlers.New(okPinger{}, nil, capabilities.NotKubernetes{}, staticVersions{}, handlers.Config{}, logger)
	h.SetUpdates(updatesRouterStub{})
	return newRouter(h, newTestAuditMiddleware(t), newAuthMiddleware(testJWTSecret), db, backupsTestOps()), mock
}

func platformToken(t *testing.T, userID uuid.UUID, tenantID uuid.UUID) string {
	t.Helper()
	claims := &models.JWTClaims{
		UserID:   userID,
		TenantID: tenantID,
		Email:    "operator@example.com",
		Role:     "platform_admin",
		Type:     "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func authed(method, path, token string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func do(r *gin.Engine, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// route is one mounted admin route and the permission it must require.
type route struct {
	method, path, permission string
}

// routes is the WHOLE admin surface. TestEveryMountedRouteIsListed fails when a
// route is mounted without being listed here, so no route escapes the gate
// tests below.
var routes = []route{
	{http.MethodGet, adminPrefix + "/status", rbac.PermissionPlatformHealth},
	{http.MethodGet, adminPrefix + "/updates", rbac.PermissionPlatformHealth},
	{http.MethodPost, adminPrefix + "/updates/check", rbac.PermissionPlatformMaintenance},
	{http.MethodPost, adminPrefix + "/updates/preflight", rbac.PermissionPlatformMaintenance},
	{http.MethodPost, adminPrefix + "/updates", rbac.PermissionPlatformMaintenance},
	{http.MethodPost, adminPrefix + "/rollbacks", rbac.PermissionPlatformMaintenance},
	{http.MethodGet, adminPrefix + "/releases", rbac.PermissionPlatformHealth},
	{http.MethodGet, adminPrefix + "/backups", rbac.PermissionPlatformHealth},
	{http.MethodPost, adminPrefix + "/backups", rbac.PermissionPlatformMaintenance},
	{http.MethodGet, adminPrefix + "/backups/123/download", rbac.PermissionPlatformMaintenance},
	{http.MethodDelete, adminPrefix + "/backups/123", rbac.PermissionPlatformMaintenance},
	{http.MethodGet, adminPrefix + "/runs", rbac.PermissionPlatformHealth},
	{http.MethodGet, adminPrefix + "/runs/123", rbac.PermissionPlatformHealth},
}

func TestEveryMountedRouteIsListed(t *testing.T) {
	r, _ := newProductionRouter(t)
	listed := map[string]bool{}
	for _, rt := range routes {
		listed[rt.method+" "+regexp.MustCompile(`/123(/|$)`).ReplaceAllString(rt.path, "/:id$1")] = true
	}
	for _, info := range r.Routes() {
		if info.Path == "/health" || info.Path == "/ready" {
			continue
		}
		if !listed[info.Method+" "+info.Path] {
			t.Errorf("route %s %s is mounted but not in the gate table", info.Method, info.Path)
		}
	}
	if got := len(r.Routes()) - 2; got != len(routes) {
		t.Errorf("mounted %d admin routes, gate table lists %d", got, len(routes))
	}
}

// No admin route answers without a platform session. Deleting admin.Use(auth)
// fails this test.
func TestAdminRoutes_RequireAuthentication(t *testing.T) {
	r, _ := newProductionRouter(t)
	for _, rt := range routes {
		if w := do(r, httptest.NewRequest(rt.method, rt.path, nil)); w.Code != http.StatusUnauthorized {
			t.Errorf("unauthenticated %s %s = %d, want 401", rt.method, rt.path, w.Code)
		}
	}
}

// A correctly signed HMAC service call is NOT a session on this surface: the
// rbac gate waives its check for internal calls, so honouring HMAC here would
// let the shared INTERNAL_AUTH_SECRET start an update.
func TestAdminRoutes_RefuseHMACServiceCalls(t *testing.T) {
	r, _ := newProductionRouter(t)
	signer := serviceauth.NewSigner(testInternalSecret)
	for _, rt := range routes {
		req := httptest.NewRequest(rt.method, rt.path, nil)
		signer.SignRequest(req)
		if w := do(r, req); w.Code != http.StatusUnauthorized {
			t.Errorf("HMAC-signed %s %s = %d, want 401", rt.method, rt.path, w.Code)
		}
	}
}

// A tenant session is refused whatever its role claim says.
func TestAdminRoutes_RefuseTenantSessions(t *testing.T) {
	r, _ := newProductionRouter(t)
	tok := platformToken(t, uuid.New(), uuid.New())
	for _, rt := range routes {
		if w := do(r, authed(rt.method, rt.path, tok)); w.Code != http.StatusForbidden {
			t.Errorf("tenant %s %s = %d, want 403", rt.method, rt.path, w.Code)
		}
	}
}

// Each route asks for ITS permission: a platform user without it gets 403
// naming it, one with it gets through. Moving a write verb off
// platform.maintenance (or the status read off platform.health) fails here.
func TestAdminRoutes_RequireTheirPermission(t *testing.T) {
	for _, rt := range routes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			r, mock := newProductionRouter(t)
			user := uuid.New()
			tok := platformToken(t, user, uuid.Nil)

			mock.ExpectQuery(permissionQuery).WithArgs(user, rt.permission).
				WillReturnRows(sqlmock.NewRows([]string{"has"}).AddRow(false))
			w := do(r, authed(rt.method, rt.path, tok))
			if w.Code != http.StatusForbidden {
				t.Fatalf("without %s: %d, want 403; body=%s", rt.permission, w.Code, w.Body.String())
			}
			var denied struct {
				Required string `json:"required_permission"`
			}
			_ = json.Unmarshal(w.Body.Bytes(), &denied)
			if denied.Required != rt.permission {
				t.Fatalf("403 names %q, want %q", denied.Required, rt.permission)
			}

			mock.ExpectQuery(permissionQuery).WithArgs(user, rt.permission).
				WillReturnRows(sqlmock.NewRows([]string{"has"}).AddRow(true))
			w = do(r, authed(rt.method, rt.path, tok))
			// Through the gate: the handler answered — 200 for a read, or
			// the handler's own answer for a write with no cluster behind it
			// (503 *_unavailable, 400 for an empty body, 404 for id 123).
			// What it must not be is the gate's 401/403 or a 501 stub.
			if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden || w.Code == http.StatusNotImplemented {
				t.Fatalf("with %s: %d, want the handler's answer; body=%s", rt.permission, w.Code, w.Body.String())
			}
			if rt.method == http.MethodGet && !strings.Contains(rt.path, "123") && w.Code != http.StatusOK {
				t.Fatalf("with %s: %d, want 200; body=%s", rt.permission, w.Code, w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// The probes answer without credentials.
func TestProbesArePublic(t *testing.T) {
	r, _ := newProductionRouter(t)
	for _, p := range []string{"/health", "/ready"} {
		if w := do(r, httptest.NewRequest(http.MethodGet, p, nil)); w.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", p, w.Code)
		}
	}
	probe := newProbeRouter(handlers.New(okPinger{}, nil, nil, nil, handlers.Config{}, nil))
	if w := do(probe, httptest.NewRequest(http.MethodGet, statusPath, nil)); w.Code != http.StatusNotFound {
		t.Errorf("the plaintext probe listener serves %s (%d); it must expose probes only", statusPath, w.Code)
	}
}
