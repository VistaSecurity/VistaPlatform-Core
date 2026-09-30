package main

// RC-3 (admin-ui data review): an operator's access to audit-service is
// decided by platform_role_permissions, not by the role name on the token.
//
// Drives newRouter — the router main() serves — against the real
// platform_user_has_permission() on a schema-and-seed-loaded database, with
// the Core handler bundle main() builds, so a request that passes the gates
// reaches a real handler and gets that handler's own answer. Skipped unless
// TEST_DATABASE_URL is set (make test-integration-db).
//
// The bundle used to be zero-valued: every admitted request dereferenced a nil
// handler, gin's recovery turned the panic into a 500, and the gate verdicts
// still came out right because testdb.RefusedByPlatformGate tells a gate's 500
// from any other. That hid whether an admitted operator actually got an
// answer. failOn5xx now fails any 5xx the gates did not produce.

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/audit-service/internal/config"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/database"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/services"
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
	r := newRouter(cfg, &database.DB{DB: db}, newTestAuditMiddleware(t), coreRouterHandlers(db))
	return r, db, func(u uuid.UUID, role string) string { return testdb.SignPlatformToken(t, testJWTSecret, u, role) }
}

// coreRouterHandlers builds the handler bundle main() builds in a Core build
// (no scheduled-report runner), on db for both the app and
// the BYPASSRLS handle.
func coreRouterHandlers(db *sql.DB) routerHandlers {
	dbx := sqlx.NewDb(db, "postgres")
	activityLog := services.NewActivityLogService(db, db)
	alert := services.NewAlertService(db)
	return routerHandlers{
		activityLog:  handlers.NewActivityLogHandlerWithMonitoring(activityLog, alert, nil),
		jobExecution: handlers.NewJobExecutionHandler(services.NewJobExecutionService(db, db)),
		compliance: handlers.NewComplianceHandlerWithReportService(
			services.NewComplianceService(db, db), services.NewComplianceReportService(db, db)),
		retention: handlers.NewRetentionHandler(services.NewRetentionService(db, db)),
		alert:     handlers.NewAlertHandler(alert),
		alertRule: handlers.NewAlertRuleHandler(services.NewAlertRuleService(dbx, dbx)),
		analytics: handlers.NewAnalyticsHandler(services.NewAnalyticsService(db, db)),
	}
}

// failOn5xx wraps the router so that any 5xx a request gets, other than a
// gate's own "could not check the permission" 500/503, fails the test. The
// shared gate helpers only ask "refused or not", and a handler that panics or
// errors counts as "not refused" — so without this an admitted operator could
// be answered with a 500 on every route and both tests would stay green.
func failOn5xx(t *testing.T, h http.Handler) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		h.ServeHTTP(w, req)
		rec, ok := w.(*httptest.ResponseRecorder)
		if !ok {
			t.Fatalf("failOn5xx: %s %s was not served into a ResponseRecorder", req.Method, req.URL.Path)
		}
		if rec.Code >= http.StatusInternalServerError && !testdb.RefusedByPlatformGate(rec) {
			t.Errorf("%s %s: the handler answered %d %s", req.Method, req.URL.Path, rec.Code, rec.Body.String())
		}
	})
}

// Custom role WITH the mapped platform permission → through; role WITHOUT it
// (even holding every other platform permission, even with a platform_admin
// or super_admin role claim — the claims the old switch admitted on sight)
// → 403 naming the permission.
func TestIntegration_AuditRoutes_PlatformPermissionGates(t *testing.T) {
	r, db, sign := newPermissionGateRouter(t)
	testdb.CheckPlatformGates(t, db, failOn5xx(t, r), sign, auditPlatformRoutes())
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
	got := testdb.SeededRoleVerdicts(t, db, failOn5xx(t, r), sign, routes)
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
