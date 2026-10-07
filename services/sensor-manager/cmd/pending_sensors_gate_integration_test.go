package main

// SECURITY: the pending-registration list carries every outstanding
// registration_key, and a key is all a sensor needs to enrol into the tenant
// (POST /sensors/register is public). Listing them must need sensors.create --
// the permission to mint one -- not mere tenant membership.
//
// Drives registerPendingSensorRoutes -- the function main() calls -- behind the
// same RequireAuth + RequireTenant the real group applies, against the real
// user_has_permission(). Skipped unless TEST_DATABASE_URL is set
// (make test-integration-db).
//
// Delete the permission argument from the GET registration and
// TestIntegration_PendingSensors_ListNeedsSensorsCreate goes red.

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/middleware"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const pendingGateSecret = "sensor-pending-gate-test"

// tenantMember creates a user holding exactly the named permissions.
func tenantMember(t *testing.T, db *sql.DB, tenant uuid.UUID, label string, perms ...string) uuid.UUID {
	t.Helper()
	user := uuid.New()
	if _, err := db.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`,
		user, tenant, label+"-"+user.String()[:8]+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if len(perms) == 0 {
		return user
	}
	var role uuid.UUID
	if err := db.QueryRow(`INSERT INTO tenant_roles (tenant_id, name, display_name) VALUES ($1, $2, $2) RETURNING id`,
		tenant, label+"-"+user.String()[:8]).Scan(&role); err != nil {
		t.Fatal(err)
	}
	for _, p := range perms {
		res, err := db.Exec(`INSERT INTO tenant_role_permissions (role_id, permission_id) SELECT $1, id FROM tenant_permissions WHERE name = $2`, role, p)
		if err != nil {
			t.Fatal(err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			t.Fatalf("permission %q is not in the seeded catalogue", p)
		}
	}
	if _, err := db.Exec(`INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, is_active) VALUES ($1, $2, $3, true)`, user, tenant, role); err != nil {
		t.Fatal(err)
	}
	return user
}

func TestIntegration_PendingSensors_ListNeedsSensorsCreate(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("REDIS_URL", "")
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/api/v1/sensor-manager")
	g.Use(middleware.RequireAuth(pendingGateSecret), middleware.RequireTenant())
	reached := func(c *gin.Context) { c.String(http.StatusOK, "reached") }
	registerPendingSensorRoutes(g, db, reached, reached, reached)

	viewer := tenantMember(t, db, tenant, "viewer", "sensors.read", "assets.read", "discovery.read")
	nobody := tenantMember(t, db, tenant, "nobody")
	creator := tenantMember(t, db, tenant, "creator", "sensors.read", "sensors.create")

	get := func(user uuid.UUID) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sensor-manager/sensors/pending", nil)
		req.Header.Set("Authorization", "Bearer "+testdb.SignTenantToken(t, pendingGateSecret, user, tenant, "viewer"))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	for name, user := range map[string]uuid.UUID{"viewer (read-only)": viewer, "member with no permissions": nobody} {
		if w := get(user); w.Code != http.StatusForbidden {
			t.Errorf("%s: GET /sensors/pending = %d (%s), want 403 -- the list exposes registration keys", name, w.Code, w.Body.String())
		}
	}
	if w := get(creator); w.Code != http.StatusOK || w.Body.String() != "reached" {
		t.Errorf("sensors.create holder: GET /sensors/pending = %d (%s), want the handler reached", w.Code, w.Body.String())
	}
}
