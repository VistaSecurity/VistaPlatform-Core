package api

// RC-3 (admin-ui data review): the /admin operator routes are decided by
// platform_role_permissions, not by the role name on the token.
//
// Drives the REAL SetupRouter against the real platform_user_has_permission()
// on a schema-and-seed-loaded database. Handlers are real too, so a request
// that passes the gate gets whatever the handler answers (a 404 for a job id
// that does not exist, say); testdb.RefusedByPlatformGate reads the body to
// tell a gate refusal from a handler's own answer. Skipped unless
// TEST_DATABASE_URL is set (make test-integration-db).

import (
	"database/sql"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const diAdminGateSecret = "device-interrogation-admin-gate-test"

const diAdminPrefix = "/api/v1/device-interrogation-service/admin"

func diAdminRoutes() []testdb.GatedRoute {
	job := uuid.NewString()
	return []testdb.GatedRoute{
		{Method: http.MethodGet, Path: diAdminPrefix + "/metrics", Permission: rbac.PermissionPlatformHealth},
		{Method: http.MethodGet, Path: diAdminPrefix + "/agents", Permission: rbac.PermissionPlatformHealth},
		{Method: http.MethodGet, Path: diAdminPrefix + "/jobs", Permission: rbac.PermissionPlatformHealth},
		{Method: http.MethodGet, Path: diAdminPrefix + "/queues", Permission: rbac.PermissionPlatformHealth},
		{Method: http.MethodPost, Path: diAdminPrefix + "/jobs/" + job + "/retry", Permission: rbac.PermissionTenantsManage},
		{Method: http.MethodPost, Path: diAdminPrefix + "/jobs/" + job + "/cancel", Permission: rbac.PermissionTenantsManage},
	}
}

func newDIAdminGateRouter(t *testing.T) (*gin.Engine, *sql.DB, func(uuid.UUID, string) string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	t.Setenv("ENCRYPTION_MASTER_KEY", "test-key-for-admin-gate-tests-only")
	t.Setenv("NATS_URL", "")
	t.Setenv("AUDIT_LOGGING_ENABLED", "false")
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	r := SetupRouter(&config.Config{JWTSecret: diAdminGateSecret}, db, db, nil)
	return r, db, func(u uuid.UUID, role string) string { return testdb.SignPlatformToken(t, diAdminGateSecret, u, role) }
}

func TestIntegration_AdminRoutes_PermissionGates(t *testing.T) {
	r, db, sign := newDIAdminGateRouter(t)
	testdb.CheckPlatformGates(t, db, r, sign, diAdminRoutes())
}

// A reached handler answers for itself: GET /admin/jobs lists jobs with a 200
// for a custom role holding only platform.health.
func TestIntegration_AdminRoutes_CustomRoleReadsJobs(t *testing.T) {
	r, db, sign := newDIAdminGateRouter(t)
	user := testdb.NewPlatformUser(t, db, testdb.NewPlatformRole(t, db, rbac.PermissionPlatformHealth))
	w := testdb.DoPlatform(r, http.MethodGet, diAdminPrefix+"/jobs", sign(user, "noc_operator"))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /admin/jobs for a platform.health custom role = %d %s, want 200", w.Code, w.Body.String())
	}
}

// Seeded roles, before and after: super_admin and platform_admin were
// admitted to every /admin route by the role-name check and still are.
// support_agent was refused all of them (the check wanted a "support_admin"
// that has never been seeded); it holds platform.health, so it now gets the
// four READS the console already showed it (Fleet, Jobs & Queues, Job Repair's
// list) — and still not retry/cancel, which need tenants.manage.
func TestIntegration_AdminRoutes_SeededRoles(t *testing.T) {
	r, db, sign := newDIAdminGateRouter(t)
	routes := diAdminRoutes()
	got := testdb.SeededRoleVerdicts(t, db, r, sign, routes)
	for _, rt := range routes {
		for _, role := range []string{"super_admin", "platform_admin"} {
			if !got[role][rt.String()] {
				t.Errorf("%s: seeded %s was admitted before and is refused now", rt, role)
			}
		}
		wantSupport := rt.Method == http.MethodGet
		if got["support_agent"][rt.String()] != wantSupport {
			t.Errorf("%s: seeded support_agent admitted=%t, want %t", rt, got["support_agent"][rt.String()], wantSupport)
		}
	}
}

// Every /admin route in the real router is in the matrix above, and a
// platform user holding no permission is refused by the permission gate on
// each — a route mounted on the bare admin group fails here.
func TestIntegration_AdminRoutes_TableIsComplete(t *testing.T) {
	r, db, sign := newDIAdminGateRouter(t)

	n := 0
	for _, ri := range r.Routes() {
		if strings.HasPrefix(ri.Path, diAdminPrefix) {
			n++
		}
	}
	if n != len(diAdminRoutes()) {
		t.Fatalf("router mounts %d /admin routes, the gate matrix lists %d — add the new route to diAdminRoutes", n, len(diAdminRoutes()))
	}

	nobody := testdb.NewPlatformUser(t, db, testdb.NewPlatformRole(t, db))
	for _, rt := range diAdminRoutes() {
		w := testdb.DoPlatform(r, rt.Method, rt.Path, sign(nobody, "super_admin"))
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Insufficient platform permissions") {
			t.Errorf("%s: a platform user with no permissions got %d %s", rt, w.Code, w.Body.String())
		}
	}
}
