package main

import (
	"github.com/gin-gonic/gin"

	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// attachAuditLogging mounts the shared audit middleware on the API router.
//
// Every write verb here changes the platform or exports its data (a backup
// download is the whole database), so the request-level trail is mounted from
// the first work package: no route added later can ship without it. /health
// is excluded by the shared config's SkipPaths.
func attachAuditLogging(router *gin.Engine, mw *auditmiddleware.Middleware) {
	router.Use(func(c *gin.Context) {
		c.Set("audit_middleware", mw)
		c.Next()
	})
	router.Use(mw.LogRequest())
}
