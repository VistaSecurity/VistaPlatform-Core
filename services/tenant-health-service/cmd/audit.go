package main

import (
	"github.com/gin-gonic/gin"

	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// attachAuditLogging mounts the shared audit middleware on the platform-admin
// API router.
//
// Every /api/v1/tenant-health-service route is cross-tenant: it reads a named
// tenant's health, alerts, metrics and insights, and POST /calculate
// recalculates and writes health scores. "Which platform admin looked at (or
// recalculated) which tenant" is exactly what the audit trail is for, and this
// service recorded none of it.
//
// /health is excluded by the shared config's SkipPaths, so kubelet probes and
// the About-page aggregator do not enter the trail.
func attachAuditLogging(router *gin.Engine, mw *auditmiddleware.Middleware) {
	router.Use(func(c *gin.Context) {
		c.Set("audit_middleware", mw)
		c.Next()
	})
	router.Use(mw.LogRequest())
}
