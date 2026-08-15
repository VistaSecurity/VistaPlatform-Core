package api

import (
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/config"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// auditedPrefixes are the monitoring-service surfaces that belong in the audit
// trail. Both are platform-admin only:
//
//   - /logs — the compliance-log read + SIEM export surface. Reading and
//     exporting the platform's log corpus is a data-access event; that this
//     particular surface was itself unaudited is the sharpest version of the
//     gap being closed here.
//   - /alerting — threshold create/update/delete mutate monitoring
//     configuration, i.e. what the platform will and will not warn about.
//
// Everything else this service serves is operational telemetry polled on a
// timer by dashboards and the About page: status, admin status, platform
// summaries, gateway proxying, trends, version. Auditing those would add
// thousands of entries a day that record nothing anyone would ever look up,
// and the cost of that is not storage — it is that the entries that DO matter
// stop being findable. Skipping them is a deliberate triage decision, not an
// oversight.
var auditedPrefixes = []string{
	"/api/v1/monitoring-service/logs",
	"/api/v1/monitoring-service/alerting",
}

// monitoringAuditConfig builds the audit config for this service: everything
// off by default, on for auditedPrefixes.
//
// The shared middleware skips by prefix rather than selecting by prefix, so
// "audit only these two" is expressed as its complement. The Skip decision is
// therefore computed in auditSkipDecision, which the tests drive directly.
func monitoringAuditConfig(cfg *config.Config) *auditmiddleware.Config {
	c := auditmiddleware.ServiceConfig(
		"monitoring-service", cfg.UseMTLS, cfg.ClientCertPath, cfg.ClientKeyPath, cfg.PlatformCACertPath,
	)
	return c
}

// shouldAuditPath reports whether a request path belongs in the audit trail.
func shouldAuditPath(path string) bool {
	for _, prefix := range auditedPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// attachAuditLogging mounts the shared audit middleware, restricted to the
// surfaces shouldAuditPath selects.
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
