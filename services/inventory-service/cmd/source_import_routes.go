package main

import (
	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
)

// mountSourceImportRoutes mounts the internal source surface (platform ADR-0002
// D3 / D4) on a group of its own, behind the HMAC-only gate: the source-import
// writes (/internal/sources/*) and, since M3, the CI export reads
// (/internal/ci-export/*) a system-of-record connector running outside this
// service uses.
//
// Its own group, not the JWT-gated /api/v1 group: JWTMiddleware admits a
// signed service call AND a user token, and these routes must admit only the
// first. main() calls this; source_import_routes_test.go drives the same
// function, so deleting the gate or re-homing the routes onto the user group
// fails a test rather than shipping.
func mountSourceImportRoutes(r gin.IRouter, h *handlers.SourceImportHandler, ci *handlers.CIExportHandler, internalSecret string) {
	internal := r.Group("/api/v1")
	internal.Use(handlers.RequireSignedServiceCall(internalSecret))
	handlers.RegisterSourceImportRoutes(internal, h)
	handlers.RegisterCIExportRoutes(internal, ci)
}
