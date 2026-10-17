package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// mountCircuitRoutes mounts circuits (DCIM BUILD_PLAN row 4.1) under
// /inventory-service/circuits on the JWT-authenticated v2 group: every read
// behind circuits.read, every write behind circuits.manage (row 0.6's
// permissions), with changes.Middleware putting the actor and request id on
// the context for the change record. A platform-seeded circuit type is refused
// on write by the service (403 read_only), not by a gate.
//
// One literal registration per route, so the spec-route scanner
// (shared/api/spectest) sees each path. main() calls this;
// circuit_routes_test.go drives the same function over every route.
func mountCircuitRoutes(v2 gin.IRouter, rawDB *sql.DB, h *handlers.CircuitHandler) {
	read := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionCircuitsRead)
	manage := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionCircuitsManage)

	g := v2.Group("/inventory-service/circuits")
	g.Use(changes.Middleware())
	g.GET("/providers", read, h.List("providers"))
	g.POST("/providers", manage, h.Create("providers"))
	g.GET("/providers/:id", read, h.Get("providers"))
	g.PATCH("/providers/:id", manage, h.Update("providers"))
	g.DELETE("/providers/:id", manage, h.Delete("providers"))
	g.GET("/provider-accounts", read, h.List("provider-accounts"))
	g.POST("/provider-accounts", manage, h.Create("provider-accounts"))
	g.GET("/provider-accounts/:id", read, h.Get("provider-accounts"))
	g.PATCH("/provider-accounts/:id", manage, h.Update("provider-accounts"))
	g.DELETE("/provider-accounts/:id", manage, h.Delete("provider-accounts"))
	g.GET("/provider-networks", read, h.List("provider-networks"))
	g.POST("/provider-networks", manage, h.Create("provider-networks"))
	g.GET("/provider-networks/:id", read, h.Get("provider-networks"))
	g.PATCH("/provider-networks/:id", manage, h.Update("provider-networks"))
	g.DELETE("/provider-networks/:id", manage, h.Delete("provider-networks"))
	g.GET("/circuit-types", read, h.List("circuit-types"))
	g.POST("/circuit-types", manage, h.Create("circuit-types"))
	g.GET("/circuit-types/:id", read, h.Get("circuit-types"))
	g.PATCH("/circuit-types/:id", manage, h.Update("circuit-types"))
	g.DELETE("/circuit-types/:id", manage, h.Delete("circuit-types"))
	g.GET("/circuits", read, h.List("circuits"))
	g.POST("/circuits", manage, h.Create("circuits"))
	g.GET("/circuits/:id", read, h.Get("circuits"))
	g.PATCH("/circuits/:id", manage, h.Update("circuits"))
	g.DELETE("/circuits/:id", manage, h.Delete("circuits"))
	g.GET("/circuit-terminations", read, h.List("circuit-terminations"))
	g.POST("/circuit-terminations", manage, h.Create("circuit-terminations"))
	g.GET("/circuit-terminations/:id", read, h.Get("circuit-terminations"))
	g.PATCH("/circuit-terminations/:id", manage, h.Update("circuit-terminations"))
	g.DELETE("/circuit-terminations/:id", manage, h.Delete("circuit-terminations"))
	g.GET("/circuit-groups", read, h.List("circuit-groups"))
	g.POST("/circuit-groups", manage, h.Create("circuit-groups"))
	g.GET("/circuit-groups/:id", read, h.Get("circuit-groups"))
	g.PATCH("/circuit-groups/:id", manage, h.Update("circuit-groups"))
	g.DELETE("/circuit-groups/:id", manage, h.Delete("circuit-groups"))
	g.GET("/circuit-group-assignments", read, h.List("circuit-group-assignments"))
	g.POST("/circuit-group-assignments", manage, h.Create("circuit-group-assignments"))
	g.GET("/circuit-group-assignments/:id", read, h.Get("circuit-group-assignments"))
	g.PATCH("/circuit-group-assignments/:id", manage, h.Update("circuit-group-assignments"))
	g.DELETE("/circuit-group-assignments/:id", manage, h.Delete("circuit-group-assignments"))
}
