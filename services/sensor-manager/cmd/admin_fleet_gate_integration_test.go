package main

// RC-3 (admin-ui data review): the cross-tenant Fleet read is decided by
// platform_role_permissions (platform.health), not by the role name on the
// token. Drives registerAdminFleetRoutes — the function main() calls — with a
// stub handler, against the real platform_user_has_permission(). Skipped unless
// TEST_DATABASE_URL is set (make test-integration-db).

import (
	"database/sql"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/rbac"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const fleetGateSecret = "sensor-fleet-gate-test"

var fleetRoutes = []testdb.GatedRoute{
	{Method: http.MethodGet, Path: "/api/v1/sensor-manager/admin/sensors", Permission: rbac.PermissionPlatformHealth},
}

func newFleetGateRouter(t *testing.T) (*gin.Engine, *sql.DB, func(uuid.UUID, string) string) {
	t.Helper()
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	registerAdminFleetRoutes(r.Group("/api/v1"), fleetGateSecret, db, func(c *gin.Context) {
		c.String(http.StatusOK, "reached")
	})
	return r, db, func(u uuid.UUID, role string) string { return testdb.SignPlatformToken(t, fleetGateSecret, u, role) }
}

func TestIntegration_AdminFleet_PermissionGate(t *testing.T) {
	r, db, sign := newFleetGateRouter(t)
	testdb.CheckPlatformGates(t, db, r, sign, fleetRoutes)
}

// super_admin and platform_admin were admitted by the role-name check and
// still are. support_agent was refused (the check wanted a "support_admin"
// that has never been seeded) although it holds platform.health and the
// console shows it the Fleet section; it now reads the fleet.
func TestIntegration_AdminFleet_SeededRoles(t *testing.T) {
	r, db, sign := newFleetGateRouter(t)
	got := testdb.SeededRoleVerdicts(t, db, r, sign, fleetRoutes)
	for _, role := range []string{"super_admin", "platform_admin", "support_agent"} {
		if !got[role][fleetRoutes[0].String()] {
			t.Errorf("seeded %s is refused the fleet read", role)
		}
	}
}
