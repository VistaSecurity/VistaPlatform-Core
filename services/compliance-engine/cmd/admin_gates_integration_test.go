package main

// RC-3 (admin-ui data review): /compliance-engine/admin is decided by
// platform_role_permissions, not by the role name on the token.
//
// These drive registerAdminRoutes — the function main() calls — with stub
// handlers, against the real platform_user_has_permission() on a
// schema-and-seed-loaded database. Skipped unless TEST_DATABASE_URL is set
// (make test-integration-db).

import (
	"database/sql"
	"net/http"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/rbac"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const adminGateSecret = "compliance-admin-gate-test"

const adminPrefix = "/api/v1/compliance-engine/admin"

func reached(c *gin.Context) { c.String(http.StatusOK, "reached") }

// newAdminGateRouter builds the real admin route table with every handler
// stubbed, plus one probe route on the returned catalogue group — standing in
// for the Enterprise author seam, which mounts its drafting route there.
func newAdminGateRouter(db *sql.DB) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	api := r.Group("/api/v1")
	catalog := registerAdminRoutes(api, adminGateSecret, db, adminHandlers{
		reevaluateTenant: reached, listPlatformAlerts: reached,
		listFrameworks: reached, createFramework: reached, getFramework: reached,
		updateFramework: reached, deleteFramework: reached, publishFramework: reached,
		unpublishFramework: reached, listFrameworkVersions: reached, getFrameworkVersion: reached,
		createControl: reached, updateControl: reached, deleteControl: reached,
		listControlMeasurements: reached, addControlMeasurement: reached,
		updateControlMeasurement: reached, deleteControlMeasurement: reached,
		acceptFrameworkUpdate: reached, acceptControlUpdate: reached, acceptMeasurementUpdate: reached,
		listTemplates: reached, getTemplate: reached, createTemplate: reached,
		updateTemplate: reached, deleteTemplate: reached, applyTemplate: reached,
		provisionFramework: reached, listTenantSubscriptions: reached, cancelTenantSubscription: reached,
	})
	catalog.POST("/frameworks/:id/draft-controls", reached)
	return r
}

// adminGateRoutes is every route registerAdminRoutes mounts (plus the author
// probe) with the permission that must open it.
// TestIntegration_AdminRoutes_TableIsComplete fails if the router and this list
// disagree, so a new route cannot escape the matrix below.
func adminGateRoutes() []testdb.GatedRoute {
	id, other := uuid.NewString(), uuid.NewString()
	health, catalogs := rbac.PermissionPlatformHealth, rbac.PermissionCatalogsManage
	tRead, tManage := rbac.PermissionTenantsRead, rbac.PermissionTenantsManage
	p := func(s string) string { return adminPrefix + s }
	return []testdb.GatedRoute{
		{Method: http.MethodGet, Path: p("/alerts"), Permission: health},

		{Method: http.MethodPost, Path: p("/tenants/" + id + "/reevaluate"), Permission: tManage},
		{Method: http.MethodPost, Path: p("/provision-framework"), Permission: tManage},
		{Method: http.MethodDelete, Path: p("/tenants/" + id + "/subscriptions/" + other), Permission: tManage},
		{Method: http.MethodGet, Path: p("/tenants/" + id + "/subscriptions"), Permission: tRead},

		{Method: http.MethodGet, Path: p("/frameworks"), Permission: catalogs},
		{Method: http.MethodPost, Path: p("/frameworks"), Permission: catalogs},
		{Method: http.MethodGet, Path: p("/frameworks/" + id), Permission: catalogs},
		{Method: http.MethodPut, Path: p("/frameworks/" + id), Permission: catalogs},
		{Method: http.MethodDelete, Path: p("/frameworks/" + id), Permission: catalogs},
		{Method: http.MethodPost, Path: p("/frameworks/" + id + "/publish"), Permission: catalogs},
		{Method: http.MethodGet, Path: p("/frameworks/" + id + "/versions"), Permission: catalogs},
		{Method: http.MethodGet, Path: p("/frameworks/versions/" + other), Permission: catalogs},
		{Method: http.MethodPost, Path: p("/frameworks/" + id + "/unpublish"), Permission: catalogs},
		{Method: http.MethodPost, Path: p("/frameworks/" + id + "/controls"), Permission: catalogs},
		{Method: http.MethodPut, Path: p("/frameworks/" + id + "/controls/" + other), Permission: catalogs},
		{Method: http.MethodDelete, Path: p("/frameworks/" + id + "/controls/" + other), Permission: catalogs},
		{Method: http.MethodGet, Path: p("/controls/" + id + "/measurements"), Permission: catalogs},
		{Method: http.MethodPost, Path: p("/controls/" + id + "/measurements"), Permission: catalogs},
		{Method: http.MethodPut, Path: p("/controls/" + id + "/measurements/" + other), Permission: catalogs},
		{Method: http.MethodDelete, Path: p("/controls/" + id + "/measurements/" + other), Permission: catalogs},
		{Method: http.MethodPost, Path: p("/frameworks/" + id + "/accept-update"), Permission: catalogs},
		{Method: http.MethodPost, Path: p("/frameworks/" + id + "/controls/" + other + "/accept-update"), Permission: catalogs},
		{Method: http.MethodPost, Path: p("/controls/" + id + "/measurements/" + other + "/accept-update"), Permission: catalogs},
		{Method: http.MethodGet, Path: p("/templates"), Permission: catalogs},
		{Method: http.MethodGet, Path: p("/templates/" + id), Permission: catalogs},
		{Method: http.MethodPost, Path: p("/templates"), Permission: catalogs},
		{Method: http.MethodPut, Path: p("/templates/" + id), Permission: catalogs},
		{Method: http.MethodDelete, Path: p("/templates/" + id), Permission: catalogs},
		{Method: http.MethodPost, Path: p("/templates/" + id + "/apply"), Permission: catalogs},
		{Method: http.MethodPost, Path: p("/frameworks/" + id + "/draft-controls"), Permission: catalogs},
	}
}

func adminGateDB(t *testing.T) *sql.DB {
	t.Helper()
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	return db
}

func adminSigner(t *testing.T) func(uuid.UUID, string) string {
	return func(u uuid.UUID, role string) string { return testdb.SignPlatformToken(t, adminGateSecret, u, role) }
}

// Custom role WITH the permission → through; role WITHOUT it (even holding
// every other platform permission, even with a platform_admin / super_admin
// role claim) → 403 naming the permission.
func TestIntegration_AdminRoutes_PermissionGates(t *testing.T) {
	db := adminGateDB(t)
	testdb.CheckPlatformGates(t, db, newAdminGateRouter(db), adminSigner(t), adminGateRoutes())
}

// The three seeded roles, before and after. super_admin and platform_admin
// were admitted to every route by the role-name check and still are (both
// hold platform.health, tenants.read, tenants.manage and catalogs.manage).
// support_agent was refused everything — the check wanted "support_admin" —
// and now reaches exactly the READS its grants name: the platform alert list
// (platform.health) and a tenant's subscriptions (tenants.read). It gains no
// write.
func TestIntegration_AdminRoutes_SeededRoles(t *testing.T) {
	db := adminGateDB(t)
	routes := adminGateRoutes()
	got := testdb.SeededRoleVerdicts(t, db, newAdminGateRouter(db), adminSigner(t), routes)

	for _, rt := range routes {
		for _, role := range []string{"super_admin", "platform_admin"} {
			if !got[role][rt.String()] {
				t.Errorf("%s: seeded %s was admitted before and is refused now", rt, role)
			}
		}
		wantSupport := rt.Method == http.MethodGet &&
			(rt.Permission == rbac.PermissionPlatformHealth || rt.Permission == rbac.PermissionTenantsRead)
		if got["support_agent"][rt.String()] != wantSupport {
			t.Errorf("%s: seeded support_agent admitted=%t, want %t", rt, got["support_agent"][rt.String()], wantSupport)
		}
	}
}

// Every route under /admin is in the matrix. This part needs no database and
// therefore runs in every PR; a route mounted without a matrix entry fails
// even when DB integration tests are not configured.
func TestAdminRoutes_TableIsComplete(t *testing.T) {
	r := newAdminGateRouter(nil)
	var registered []string
	for _, ri := range r.Routes() {
		if strings.HasPrefix(ri.Path, adminPrefix) {
			registered = append(registered, ri.Method+" "+ri.Path)
		}
	}
	var listed []string
	for _, rt := range adminGateRoutes() {
		matches := make([]string, 0, 1)
		for _, route := range registered {
			method, pattern, _ := strings.Cut(route, " ")
			if method == rt.Method && routePatternMatches(pattern, rt.Path) {
				matches = append(matches, route)
			}
		}
		if len(matches) != 1 {
			t.Fatalf("gate matrix entry %s matches %d registered routes (%s)", rt, len(matches), strings.Join(matches, ", "))
		}
		listed = append(listed, matches[0])
	}
	sort.Strings(registered)
	sort.Strings(listed)
	if !slices.Equal(registered, listed) {
		t.Fatalf("router and gate matrix differ — add/remove the corresponding adminGateRoutes entry.\nregistered:\n%s\n\nlisted:\n%s",
			strings.Join(registered, "\n"), strings.Join(listed, "\n"))
	}
}

// A platform user holding no permission at all is refused by the permission
// gate on every matrix route. A route mounted on the bare authenticated group
// would pass this caller if the always-on table test above did not catch it.
func TestIntegration_AdminRoutes_EmptyRoleIsRefused(t *testing.T) {
	db := adminGateDB(t)
	r := newAdminGateRouter(db)
	nobody := testdb.NewPlatformUser(t, db, testdb.NewPlatformRole(t, db))
	token := testdb.SignPlatformToken(t, adminGateSecret, nobody, "super_admin")
	for _, rt := range adminGateRoutes() {
		w := testdb.DoPlatform(r, rt.Method, rt.Path, token)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Insufficient platform permissions") {
			t.Errorf("%s: a platform user with no permissions got %d %s", rt, w.Code, w.Body.String())
		}
	}
}

// routePatternMatches resolves a concrete gate-matrix path against Gin's
// registered path syntax. Matching the resolved route set (not just its
// length) prevents one missing route from being hidden by one stale entry.
func routePatternMatches(pattern, concrete string) bool {
	want, got := strings.Split(strings.Trim(pattern, "/"), "/"), strings.Split(strings.Trim(concrete, "/"), "/")
	for i := 0; i < len(want); i++ {
		if i >= len(got) {
			return false
		}
		if strings.HasPrefix(want[i], "*") {
			return true
		}
		if !strings.HasPrefix(want[i], ":") && want[i] != got[i] {
			return false
		}
	}
	return len(want) == len(got)
}
