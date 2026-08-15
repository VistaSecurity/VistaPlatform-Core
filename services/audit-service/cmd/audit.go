package main

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// ingestPath is the S2S activity-log ingest endpoint, and jobLogIngestPrefix
// covers the three job-execution-log ingest endpoints. Both are the HMAC-only
// `internal` group every other service writes through.
//
// They are the two reasons this service needs a method-aware skip rather than a
// plain prefix list:
//
//  1. Auditing them would be self-referential. Each stored entry is delivered by
//     a POST to /activity-logs; auditing that POST writes another entry, which
//     is delivered by another POST. Skipping ingest breaks the loop at the
//     first hop.
//  2. GET /activity-logs — reading the audit trail — shares its path with the
//     ingest POST, and reading the trail is exactly the event that must be
//     recorded. A path-only skip would silence it.
const (
	ingestPath         = "/api/v1/audit-service/activity-logs"
	jobLogIngestPrefix = "/api/v1/audit-service/job-execution-logs/"
)

// auditedPrefix is the service's own API namespace. Everything under it is a
// query, export, or configuration change against the audit trail itself:
// reading and exporting activity logs, generating compliance reports, and
// creating/updating/deleting retention policies and alert rules.
//
// That this surface — the audit trail's own read and export path — was itself
// unaudited is the sharpest instance of the gap this work closes.
const auditedPrefix = "/api/v1/audit-service"

// shouldAuditRequest reports whether a request belongs in the audit trail.
func shouldAuditRequest(method, path string) bool {
	if method == http.MethodPost {
		if path == ingestPath || strings.HasPrefix(path, jobLogIngestPrefix) {
			return false
		}
	}
	return strings.HasPrefix(path, auditedPrefix)
}

// attachAuditLogging mounts the shared audit middleware, restricted to the
// surfaces shouldAuditRequest selects.
//
// /health and /ready are additionally excluded by the shared config's
// SkipPaths, so kubelet probes never enter the trail.
func attachAuditLogging(router *gin.Engine, mw *auditmiddleware.Middleware) {
	logRequest := mw.LogRequest()
	router.Use(func(c *gin.Context) {
		c.Set("audit_middleware", mw)
		if !shouldAuditRequest(c.Request.Method, c.Request.URL.Path) {
			c.Next()
			return
		}
		logRequest(c)
	})
}
