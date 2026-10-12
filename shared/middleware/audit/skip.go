package audit

import "github.com/gin-gonic/gin"

// skipContextKey is the gin context key Skip sets and LogRequest honours.
const skipContextKey = "audit_skip"

// Skip is a route-level opt-out from LogRequest: put it in the handler chain of
// a route whose requests must not become activity-log rows.
//
//	agentRoutes.POST(sensors, "/heartbeat", audit.Skip(), handler.Heartbeat)
//
// It exists for machine-only liveness traffic (collector heartbeats, job
// polls). Those arrive every few seconds per collector, so recording them
// fills the tenant's Activity log with rows no person did and scales linearly
// with the fleet, burying the user actions the log is for. Config.SkipPaths
// cannot do this: it prefix-matches the literal path, so it cannot express
// /sensors/:id/heartbeat.
//
// Use it ONLY for liveness and polling. A collector submitting data
// (discoveries, results, inventory, registration, certificate rotation) stays
// audited.
//
// Skip runs inside the route's chain, so a request refused earlier (by an
// authentication middleware on the group) never reaches it and is still
// recorded: failed authentication attempts against these routes stay visible.
func Skip() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(skipContextKey, true)
	}
}
