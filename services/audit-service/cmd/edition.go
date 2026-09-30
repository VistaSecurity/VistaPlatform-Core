package main

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/services"
)

// editionHooks are the extension points the Enterprise build fills in.
//
// The zero value is the Core edition: every hook nil, meaning compliance
// reports are generated on demand but never on a schedule. That is a supported
// product configuration, not a degraded one — Core's promise is the audit
// substrate itself: logging, ingestion, query, export, retention, alerting,
// analytics, on-demand compliance reports, and the export feed other services
// read the trail from. What Enterprise adds here is scheduled delivery.
//
// SIEM export used to be the second hook. It moved out of this service
// entirely (platform ADR-0002 M1): an Enterprise service now reads the audit
// trail through the export feed (internal/services/export_feed.go) and keeps
// its own durable cursor, so this binary no longer carries any SIEM code in
// either edition.
//
// The Enterprise build supplies real implementations from cmd/edition_ee.go,
// which is guarded by `//go:build ee` and imports services/audit-service/ee/.
// Neither that file nor the ee/ tree exists in the open-source repository, so a
// Core checkout cannot accidentally link Enterprise code — there is nothing to
// link. See docsv4/internal/operations/OPEN_SOURCE_CARVE_TRACKER.md §5.5.
//
// Hooks are wired at process start (init) rather than resolved per request:
// this boundary decides which *code* is present, while shared/entitlements
// decides which *tenant* may use it.
type editionHooks struct {
	// NewScheduledReports constructs the cron-driven compliance-report runner.
	// Nil in Core, so the /scheduled-reports routes are never mounted and no
	// scheduler goroutine starts. Takes Core's *ComplianceReportService: the
	// dependency direction is Enterprise → Core, so on-demand generation stays
	// entirely in Core.
	NewScheduledReports func(db, bypassDB *sqlx.DB, compliance *services.ComplianceReportService) scheduledReportRunner
}

// scheduledReportRunner is the lifecycle surface main() drives for scheduled
// compliance reports.
type scheduledReportRunner interface {
	// Start loads the enabled schedules and starts the cron scheduler.
	Start(ctx context.Context) error

	// RegisterRoutes mounts the scheduled-report endpoints on the
	// authenticated /api/v1 group, gating them itself.
	RegisterRoutes(api *gin.RouterGroup)
}

// hooks is the active edition. Core leaves it zero; the Enterprise build
// replaces it from an init() in cmd/edition_ee.go.
var hooks editionHooks

// edition reports the build's edition for startup logging, so an operator can
// tell from the first log line which binary is running.
func edition() string {
	if hooks.NewScheduledReports == nil {
		return "core"
	}
	return "enterprise"
}
