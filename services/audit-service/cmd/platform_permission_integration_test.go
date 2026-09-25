package main

// RC-3 (admin-ui data review): an operator's access to audit-service is
// decided by platform_role_permissions, not by the role name on the token.
//
// Drives newRouter — the router main() serves — against the real
// platform_user_has_permission() on a schema-and-seed-loaded database. The
// handler bundle is zero-valued, so a request that passes the gates panics
// into gin's recovery (500); testdb.RefusedByPlatformGate reads the body to
// tell that apart from a gate refusal. Skipped unless TEST_DATABASE_URL is set
// (make test-integration-db).

import (
	"database/sql"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/audit-service/internal/config"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// auditPlatformRoutes is every audit-service route gated by RequirePermission,
// with the PLATFORM permission an operator needs for it.
func auditPlatformRoutes() []testdb.GatedRoute {
	id := uuid.NewString()
	read, manage := rbac.PermissionPlatformAudit, rbac.PermissionPlatformAuditManage
	p := func(s string) string { return "/api/v1/audit-service" + s }
	return []testdb.GatedRoute{
		{Method: http.MethodGet, Path: p("/activity-logs"), Permission: read},
		{Method: http.MethodGet, Path: p("/activity-logs/" + id), Permission: read},
		{Method: http.MethodGet, Path: p("/activity-logs/summary"), Permission: read},
		{Method: http.MethodGet, Path: p("/retention-policies"), Permission: read},
		{Method: http.MethodGet, Path: p("/retention-policies/" + id), Permission: read},
		{Method: http.MethodPost, Path: p("/retention-policies"), Permission: manage},
		{Method: http.MethodPut, Path: p("/retention-policies/" + id), Permission: manage},
		{Method: http.MethodGet, Path: p("/activity-logs/by-user"), Permission: read},
		{Method: http.MethodGet, Path: p("/activity-logs/by-resource"), Permission: read},
		{Method: http.MethodGet, Path: p("/activity-logs/by-resource/device/" + id), Permission: read},
		{Method: http.MethodGet, Path: p("/activity-logs/by-user/" + id), Permission: read},
		{Method: http.MethodPost, Path: p("/activity-logs/query"), Permission: read},
		{Method: http.MethodGet, Path: p("/activity-logs/export"), Permission: read},
		{Method: http.MethodPost, Path: p("/alert-rules"), Permission: manage},
		{Method: http.MethodPut, Path: p("/alert-rules/" + id), Permission: manage},
		{Method: http.MethodDelete, Path: p("/alert-rules/" + id), Permission: manage},
	}
}

func newPermissionGateRouter(t *testing.T) (*gin.Engine, *sql.DB, func(uuid.UUID, string) string) {
	t.Helper()
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{
		JWT:                config.JWTConfig{Secret: testJWTSecret},
		InternalAuthSecret: "test-internal-secret",
	}
	r := newRouter(cfg, &database.DB{DB: db}, newTestAuditMiddleware(t), routerHandlers{})
	return r, db, func(u uuid.UUID, role string) string { return testdb.SignPlatformToken(t, testJWTSecret, u, role) }
}

// Custom role WITH the mapped platform permission → through; role WITHOUT it
// (even holding every other platform permission, even with a platform_admin
// or super_admin role claim — the claims the old switch admitted on sight)
// → 403 naming the permission.
func TestIntegration_AuditRoutes_PlatformPermissionGates(t *testing.T) {
	r, db, sign := newPermissionGateRouter(t)
	testdb.CheckPlatformGates(t, db, r, sign, auditPlatformRoutes())
}

// The three seeded roles, before and after. super_admin passed every check by
// name and platform_admin passed every "audit.*" by prefix; both still pass
// every route (super_admin holds every platform permission, platform_admin is
// seeded platform.audit and platform.audit.manage). support_agent matched no
// case — the switch named a "support_admin" that has never been seeded — so it
// was refused even the reads its platform.audit grant names. It now reads, and
// still cannot write.
func TestIntegration_AuditRoutes_SeededRoles(t *testing.T) {
	r, db, sign := newPermissionGateRouter(t)
	routes := auditPlatformRoutes()
	got := testdb.SeededRoleVerdicts(t, db, r, sign, routes)
	for _, rt := range routes {
		for _, role := range []string{"super_admin", "platform_admin"} {
			if !got[role][rt.String()] {
				t.Errorf("%s: seeded %s was admitted before and is refused now", rt, role)
			}
		}
		wantSupport := rt.Permission == rbac.PermissionPlatformAudit
		if got["support_agent"][rt.String()] != wantSupport {
			t.Errorf("%s: seeded support_agent admitted=%t, want %t", rt, got["support_agent"][rt.String()], wantSupport)
		}
	}
}
