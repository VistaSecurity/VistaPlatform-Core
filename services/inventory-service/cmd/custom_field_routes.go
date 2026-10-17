package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// mountCustomFieldRoutes mounts custom field definitions and choice sets
// (DCIM BUILD_PLAN row 5.1) under /inventory-service/dcim on the
// JWT-authenticated v2 group: reads behind dcim.read (every DCIM detail page
// renders the definitions), writes behind custom_fields.manage, with
// changes.Middleware putting the actor and request id on the context for the
// change record.
//
// One literal registration per route, so the spec-route scanner
// (shared/api/spectest) sees each path. main() calls this;
// custom_field_routes_test.go drives the same function.
func mountCustomFieldRoutes(v2 gin.IRouter, rawDB *sql.DB, h *handlers.CustomFieldHandler) {
	read := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimRead)
	manage := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionCustomFieldsManage)

	g := v2.Group("/inventory-service/dcim")
	g.Use(changes.Middleware())
	g.GET("/custom-fields", read, h.List("custom-fields"))
	g.POST("/custom-fields", manage, h.Create("custom-fields"))
	g.GET("/custom-fields/:id", read, h.Get("custom-fields"))
	g.PATCH("/custom-fields/:id", manage, h.Update("custom-fields"))
	g.DELETE("/custom-fields/:id", manage, h.Delete("custom-fields"))
	g.GET("/custom-field-choice-sets", read, h.List("custom-field-choice-sets"))
	g.POST("/custom-field-choice-sets", manage, h.Create("custom-field-choice-sets"))
	g.GET("/custom-field-choice-sets/:id", read, h.Get("custom-field-choice-sets"))
	g.PATCH("/custom-field-choice-sets/:id", manage, h.Update("custom-field-choice-sets"))
	g.DELETE("/custom-field-choice-sets/:id", manage, h.Delete("custom-field-choice-sets"))
}
