package main

import (
	"context"
	"database/sql"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// mountDcimSavedFilterRoutes mounts Saved Filters (BUILD_PLAN row 5.4) under
// /inventory-service/dcim/saved-filters. Everything needs assets.read -- a
// filter is a predicate over assets the caller can already list -- and the
// handler/service apply the finer rule: a personal filter is its owner's, and
// publishing or touching a shared one needs settings.update.
//
// main() calls this; dcim_saved_filter_routes_test.go drives the same function.
func mountDcimSavedFilterRoutes(v2 gin.IRouter, rawDB *sql.DB, h *handlers.DcimSavedFilterHandler) {
	read := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsRead)
	g := v2.Group("/inventory-service/dcim/saved-filters")
	g.Use(changes.Middleware())
	g.GET("", read, h.List)
	g.POST("", read, h.Create)
	g.PUT("/:id", read, h.Update)
	g.DELETE("/:id", read, h.Delete)
}

// savedFilterCanShare resolves "may publish to the organisation" from
// settings.update through the same RBAC service the route gates use.
func savedFilterCanShare(rawDB *sql.DB) handlers.CanShareFunc {
	svc := rbac.NewRBACService(rawDB)
	return func(_ context.Context, tenant, user uuid.UUID) (bool, error) {
		return svc.CheckPermission(user, tenant, rbac.PermissionSettingsUpdate)
	}
}
