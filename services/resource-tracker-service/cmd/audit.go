package main

import (
	"strings"

	"github.com/gin-gonic/gin"

	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// metricsIngestPath is the one resource-tracker surface deliberately kept OUT
// of the audit trail.
//
// POST /api/v1/resource-tracker/metrics is HMAC-only service-to-service metrics
// ingest, pushed on a timer by every backend in the platform. It carries no
// actor, records no decision, and would contribute thousands of identical
// entries a day. The cost of that is not storage — it is that the entries which
// DO matter stop being findable.
const metricsIngestPath = "/api/v1/resource-tracker/metrics"

// auditedPrefixes are the resource-tracker surfaces that belong in the audit
// trail: the JWT-guarded `api` group and the gateway-routed
// `resource-tracker-service` namespace admin-ui-v2 actually calls.
//
// Both read a named tenant's resource usage, cost trend and cost analysis, plus
// platform-wide rollups across every tenant. "Which admin pulled which tenant's
// usage and cost figures" is exactly what an audit trail is for, and this
// service recorded none of it.
//
// Note the first prefix also covers the second (`/api/v1/resource-tracker` is a
// prefix of `/api/v1/resource-tracker-service`); both are listed so the intent
// survives a future rename of either group.
var auditedPrefixes = []string{
	"/api/v1/resource-tracker",
	"/api/v1/resource-tracker-service",
}

// shouldAuditPath reports whether a request path belongs in the audit trail.
func shouldAuditPath(path string) bool {
	if path == metricsIngestPath {
		return false
	}
	for _, prefix := range auditedPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// attachAuditLogging mounts the shared audit middleware, restricted to the
// surfaces shouldAuditPath selects.
//
// HONEST CAVEAT, so the next reader does not read it as a bug: the
// /api/v1/resource-tracker-service group accepts BOTH platform-admin JWTs and
// HMAC service auth — tenant-health-service polls
// /tenant/:id/resource-summary S2S. Those polls will appear in the trail as
// actor-less entries. That noise is the accepted trade-off for auditing the
// namespace admin-ui-v2 actually calls (owner decision); it is not an
// oversight, and it is not a reason to drop the group. Only the pure-S2S
// metrics ingest above is excluded.
//
// /health is additionally excluded by the shared config's SkipPaths, so kubelet
// probes never enter the trail.
func attachAuditLogging(router *gin.Engine, mw *auditmiddleware.Middleware) {
	logRequest := mw.LogRequest()
	router.Use(func(c *gin.Context) {
		c.Set("audit_middleware", mw)
		if !shouldAuditPath(c.Request.URL.Path) {
			c.Next()
			return
		}
		logRequest(c)
	})
}
