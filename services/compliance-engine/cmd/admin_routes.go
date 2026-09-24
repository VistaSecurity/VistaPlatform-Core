package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/middleware"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// adminHandlers are the /compliance-engine/admin handlers. They are gathered
// into one value so main() and the gate tests build the SAME route table: the
// tests hand in stubs and drive the real registerAdminRoutes, so deleting a
// gate below fails a test instead of passing one that exercised a copy.
type adminHandlers struct {
	reevaluateTenant gin.HandlerFunc

	listPlatformAlerts gin.HandlerFunc

	listFrameworks        gin.HandlerFunc
	createFramework       gin.HandlerFunc
	getFramework          gin.HandlerFunc
	updateFramework       gin.HandlerFunc
	deleteFramework       gin.HandlerFunc
	publishFramework      gin.HandlerFunc
	unpublishFramework    gin.HandlerFunc
	listFrameworkVersions gin.HandlerFunc
	getFrameworkVersion   gin.HandlerFunc

	createControl gin.HandlerFunc
	updateControl gin.HandlerFunc
	deleteControl gin.HandlerFunc

	listControlMeasurements  gin.HandlerFunc
	addControlMeasurement    gin.HandlerFunc
	updateControlMeasurement gin.HandlerFunc
	deleteControlMeasurement gin.HandlerFunc

	// Seeded-content "update available" → accept (decision 4, RC-12).
	acceptFrameworkUpdate   gin.HandlerFunc
	acceptControlUpdate     gin.HandlerFunc
	acceptMeasurementUpdate gin.HandlerFunc

	listTemplates  gin.HandlerFunc
	getTemplate    gin.HandlerFunc
	createTemplate gin.HandlerFunc
	updateTemplate gin.HandlerFunc
	deleteTemplate gin.HandlerFunc
	applyTemplate  gin.HandlerFunc

	provisionFramework       gin.HandlerFunc
	listTenantSubscriptions  gin.HandlerFunc
	cancelTenantSubscription gin.HandlerFunc
}

// registerAdminRoutes mounts the platform-operator routes under
// /compliance-engine/admin and returns the catalogue group, which main() hands
// to the Enterprise author seam so its drafting route inherits the same gate
// as the rest of framework authoring.
//
// Every route sits on a sub-group that requires a PLATFORM identity AND a named
// platform permission, resolved through platform_user_has_permission(). It used
// to be one group behind a role-NAME check (super_admin | platform_admin |
// a never-seeded "support_admin"), which made Staff & Access ▸ Roles
// decorative here: a custom role with the right grant was refused, and a
// role called platform_admin passed regardless of its grants.
//
// The permission for each group matches what admin-ui-v2 gates the page on:
//
//	observe   platform.health  System Health ▸ Alerts
//	catalog   catalogs.manage  Catalog ▸ Frameworks (read AND write: the
//	                           catalogue is an authoring surface)
//	tenants   tenants.read     a tenant's framework subscriptions
//	tenantOps tenants.manage   re-evaluate a tenant; provision / cancel a
//	                           tenant's framework subscription
//
// super_admin and platform_admin — the two roles the old check admitted — hold
// all four, so they reach exactly what they reached before.
//
// No route may be mounted on `admin` itself; it would carry authentication and
// nothing else. TestAdminRoutes_EveryRouteIsPermissionGated enumerates the
// table and fails on one.
func registerAdminRoutes(api *gin.RouterGroup, jwtSecret string, rawDB *sql.DB, h adminHandlers) (catalog *gin.RouterGroup) {
	admin := api.Group("/compliance-engine/admin")
	admin.Use(middleware.RequirePlatformAuth(jwtSecret))
	admin.Use(middleware.StringifyUserID())

	observe := admin.Group("", sharedmw.RequirePlatformAdmin(rawDB, rbac.PermissionPlatformHealth))
	// Platform-track stateful alerts (service_down, tenant_health_degraded)
	// raised under the sentinel platform tenant. Read-only here.
	observe.GET("/alerts", h.listPlatformAlerts)

	tenantOps := admin.Group("", sharedmw.RequirePlatformAdmin(rawDB, rbac.PermissionTenantsManage))
	// ADR-0015: manual per-tenant re-evaluation (extraordinary).
	tenantOps.POST("/tenants/:tenantId/reevaluate", h.reevaluateTenant)
	// Framework provisioning (admin → tenant).
	tenantOps.POST("/provision-framework", h.provisionFramework)
	tenantOps.DELETE("/tenants/:tenantId/subscriptions/:frameworkId", h.cancelTenantSubscription)

	tenants := admin.Group("", sharedmw.RequirePlatformAdmin(rawDB, rbac.PermissionTenantsRead))
	tenants.GET("/tenants/:tenantId/subscriptions", h.listTenantSubscriptions)

	catalog = admin.Group("", sharedmw.RequirePlatformAdmin(rawDB, rbac.PermissionCatalogsManage))
	// Platform framework management
	catalog.GET("/frameworks", h.listFrameworks)
	catalog.POST("/frameworks", h.createFramework)
	catalog.GET("/frameworks/:id", h.getFramework)
	catalog.PUT("/frameworks/:id", h.updateFramework)
	catalog.DELETE("/frameworks/:id", h.deleteFramework)
	catalog.POST("/frameworks/:id/publish", h.publishFramework)
	catalog.GET("/frameworks/:id/versions", h.listFrameworkVersions)
	catalog.GET("/frameworks/versions/:versionId", h.getFrameworkVersion)
	catalog.POST("/frameworks/:id/unpublish", h.unpublishFramework)

	// Platform framework controls
	catalog.POST("/frameworks/:id/controls", h.createControl)
	catalog.PUT("/frameworks/:id/controls/:controlId", h.updateControl)
	catalog.DELETE("/frameworks/:id/controls/:controlId", h.deleteControl)

	// Platform framework control measurements
	catalog.GET("/controls/:id/measurements", h.listControlMeasurements)
	catalog.POST("/controls/:id/measurements", h.addControlMeasurement)
	catalog.PUT("/controls/:id/measurements/:measurementId", h.updateControlMeasurement)
	catalog.DELETE("/controls/:id/measurements/:measurementId", h.deleteControlMeasurement)

	// Accept the update an upgrade offered for a shipped row the admin had
	// edited (decision 4, RC-12). Same gate as editing the row.
	catalog.POST("/frameworks/:id/accept-update", h.acceptFrameworkUpdate)
	catalog.POST("/frameworks/:id/controls/:controlId/accept-update", h.acceptControlUpdate)
	catalog.POST("/controls/:id/measurements/:measurementId/accept-update", h.acceptMeasurementUpdate)

	// Measurement templates
	catalog.GET("/templates", h.listTemplates)
	catalog.GET("/templates/:id", h.getTemplate)
	catalog.POST("/templates", h.createTemplate)
	catalog.PUT("/templates/:id", h.updateTemplate)
	catalog.DELETE("/templates/:id", h.deleteTemplate)
	catalog.POST("/templates/:id/apply", h.applyTemplate)

	return catalog
}
