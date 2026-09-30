package main

import (
	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
)

// mountSourceImportRoutes mounts the internal source-import surface
// (platform ADR-0002 D3) on a group of its own, behind the HMAC-only gate.
//
// Its own group, not the JWT-gated /api/v1 group: JWTMiddleware admits a
// signed service call AND a user token, and these routes must admit only the
// first. main() calls this; source_import_routes_test.go drives the same
// function, so deleting the gate or re-homing the routes onto the user group
// fails a test rather than shipping.
func mountSourceImportRoutes(r gin.IRouter, h *handlers.SourceImportHandler, internalSecret string) {
	internal := r.Group("/api/v1")
	internal.Use(handlers.RequireSignedServiceCall(internalSecret))
	handlers.RegisterSourceImportRoutes(internal, h)
}
