package main

import (
	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
)

// mountSightingRoutes mounts the internal sightings route (platform ADR-0003
// D3 step 2) on a group of its own behind the HMAC-only gate, exactly as
// mountSourceImportRoutes does for the source routes: a signed service call
// naming one tenant, and nothing else — no JWT fallback. main() calls this;
// sighting_routes_test.go drives the same function, so deleting the gate or
// re-homing the route onto the user group fails a test.
func mountSightingRoutes(r gin.IRouter, h *handlers.SightingHandler, internalSecret string) {
	internal := r.Group("/api/v1")
	internal.Use(handlers.RequireSignedServiceCall(internalSecret))
	handlers.RegisterSightingRoutes(internal, h)
}
