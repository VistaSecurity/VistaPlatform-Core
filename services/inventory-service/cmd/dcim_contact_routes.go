package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// mountDcimContactRoutes mounts contacts, contact roles, contact assignments
// and image attachments (DCIM BUILD_PLAN row 2.8) under /inventory-service/dcim
// on the JWT-authenticated v2 group: reads behind dcim.read, writes behind
// dcim.manage, with changes.Middleware attributing every change.
//
// One literal registration per route, so the spec-route scanner
// (shared/api/spectest) sees each path. main() calls this;
// dcim_contact_routes_test.go drives the same function over every route.
func mountDcimContactRoutes(v2 gin.IRouter, rawDB *sql.DB, ch *handlers.ContactHandler, ih *handlers.ImageHandler) {
	read := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimRead)
	manage := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimManage)

	d := v2.Group("/inventory-service/dcim")
	d.Use(changes.Middleware())
	d.GET("/contacts", read, ch.List("contacts"))
	d.POST("/contacts", manage, ch.Create("contacts"))
	d.GET("/contacts/:id", read, ch.Get("contacts"))
	d.PATCH("/contacts/:id", manage, ch.Update("contacts"))
	d.DELETE("/contacts/:id", manage, ch.Delete("contacts"))
	d.GET("/contact-roles", read, ch.List("contact-roles"))
	d.POST("/contact-roles", manage, ch.Create("contact-roles"))
	d.GET("/contact-roles/:id", read, ch.Get("contact-roles"))
	d.PATCH("/contact-roles/:id", manage, ch.Update("contact-roles"))
	d.DELETE("/contact-roles/:id", manage, ch.Delete("contact-roles"))
	d.GET("/contact-assignments", read, ch.List("contact-assignments"))
	d.POST("/contact-assignments", manage, ch.Create("contact-assignments"))
	d.GET("/contact-assignments/:id", read, ch.Get("contact-assignments"))
	d.PATCH("/contact-assignments/:id", manage, ch.Update("contact-assignments"))
	d.DELETE("/contact-assignments/:id", manage, ch.Delete("contact-assignments"))
	d.GET("/objects/:kind/:id/contacts", read, ch.ListForObject)
	d.POST("/objects/:kind/:id/contacts", manage, ch.AssignToObject)
	d.GET("/objects/:kind/:id/images", read, ih.ListForObject)
	d.POST("/objects/:kind/:id/images", manage, ih.Upload)
	d.GET("/images", read, ih.List)
	d.GET("/images/:id", read, ih.Get)
	d.GET("/images/:id/download", read, ih.Download)
	d.DELETE("/images/:id", manage, ih.Delete)
}
