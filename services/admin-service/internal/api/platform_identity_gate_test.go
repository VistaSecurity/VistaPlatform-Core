package api

// SECURITY: the admin console's API is for platform operators only. Both token
// families are signed by one key set and a Bearer header is not narrowed by
// StrictCookiePair, so a TENANT user's access token authenticates against
// AuthMiddleware. Five routes (/admin/user/permissions, /admin/auth/me,
// /admin/auth/change-password, /admin/platform/edition, /admin/auth/logout) sat
// on groups with no identity check at all and were safe only because each
// handler happens to look the caller up in platform_users (2026-09 audit,
// tenancy-rbac Low). RequirePlatformIdentity now answers first.
//
// Drives the REAL router (the Core build, no database reachable): a tenant
// token must be refused with the identity gate's own message -- which proves
// the gate answered, not a handler failing on the dead DB -- and a platform
// token must get past it (to whatever the handler then says, 500 included).
//
// Delete either RequirePlatformIdentity() line in server.go and the matching
// subtests go red.

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestPlatformIdentityGate_TenantTokenRefusedOnEveryUngatedAdminRoute(t *testing.T) {
	t.Setenv("DATABASE_URL", "") // keep the shared middleware from building a tenant-state checker
	t.Setenv("REDIS_URL", "")
	const secret = "platform-identity-gate-test"

	db, err := sql.Open("postgres", "postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := NewServerWithConnections(&config.Config{Environment: "test", JWTSecret: secret}, db, db, EditionHooks{})
	router := srv.Router()

	tenantTok := testdb.SignTenantToken(t, secret, uuid.New(), uuid.New(), "platform_admin") // role claim is free; it must not matter
	platformTok := testdb.SignPlatformToken(t, secret, uuid.New(), "super_admin")

	routes := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/admin-service/admin/user/permissions"},
		{http.MethodGet, "/api/v1/admin-service/admin/auth/me"},
		{http.MethodPost, "/api/v1/admin-service/admin/auth/change-password"},
		{http.MethodGet, "/api/v1/admin-service/admin/platform/edition"},
		{http.MethodPost, "/api/v1/admin-service/admin/auth/logout"},
	}
	call := func(method, path, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	for _, rt := range routes {
		rt := rt
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			w := call(rt.method, rt.path, tenantTok)
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Platform user required") {
				t.Fatalf("tenant token = %d %s; want 403 \"Platform user required\" from the identity gate", w.Code, w.Body.String())
			}
			w = call(rt.method, rt.path, platformTok)
			if w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), "Platform user required") {
				t.Fatalf("a PLATFORM token was refused by the identity gate: %s", w.Body.String())
			}
		})
	}
}
