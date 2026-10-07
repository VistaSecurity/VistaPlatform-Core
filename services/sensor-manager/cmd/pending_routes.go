package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// registerPendingSensorRoutes mounts the registration-key management routes on
// the tenant-authenticated /sensor-manager group.
//
// A pending registration's registration_key is the ONLY credential a sensor
// needs to enrol: POST /sensors/register is public, and the address check
// against ip_address is a self-reported cross-check, not authentication (see
// RegisterSensor). Whoever can LIST the keys can enrol a sensor into the
// tenant and from then on submit discoveries as it. The list therefore needs the
// same permission as minting a key (sensors.create), not mere membership:
// before this, any tenant user -- a viewer included -- read every outstanding
// key.
//
// The page that renders the list (Discovery -> Sensors & Agents -> Pending
// registrations) already hides itself on an error response, so a viewer simply
// no longer sees a section they could do nothing useful with.
//
// main() and the gate test both call this, so the test drives the real route
// table rather than a copy of it.
func registerPendingSensorRoutes(g *gin.RouterGroup, db *sql.DB, create, list, del gin.HandlerFunc) {
	g.POST("/sensors/pending", sharedrbac.RequireTenantPermission(db, rbac.PermissionSensorsCreate), create)
	g.GET("/sensors/pending", sharedrbac.RequireTenantPermission(db, rbac.PermissionSensorsCreate), list)
	g.DELETE("/sensors/pending/:key", sharedrbac.RequireTenantPermission(db, rbac.PermissionSensorsDelete), del)
}
