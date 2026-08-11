package main

import (
	"context"
	"database/sql"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/services"
)

// editionHooks are the extension points the Enterprise build fills in.
//
// The zero value is the Core edition: every hook nil, meaning audit events are
// logged but never forwarded to a SIEM, and compliance reports are generated on
// demand but never on a schedule. That is a supported product configuration,
// not a degraded one — Core's promise is the audit substrate itself: logging,
// ingestion, query, export, retention, alerting, analytics, and on-demand
// compliance reports. What Enterprise adds is the outbound plumbing.
//
// The Enterprise build supplies real implementations from cmd/edition_ee.go,
// which is guarded by `//go:build ee` and imports services/audit-service/ee/.
// Neither that file nor the ee/ tree exists in the open-source repository, so a
// Core checkout cannot accidentally link Enterprise code — there is nothing to
// link. See docsv4/internal/operations/OPEN_SOURCE_CARVE_TRACKER.md §5.5.
//
// Hooks are wired at process start (init) rather than resolved per request:
// this boundary decides which *code* is present, while shared/entitlements
// decides which *tenant* may use it. Neither of these two features carries an
// entitlement gate today; adding one is separate work and belongs on the
// Enterprise side of this seam.
type editionHooks struct {
	// NewSIEMExporter constructs the outbound SIEM exporter. Nil in Core, so
	// the /siem/* routes are never mounted, the batch flusher never starts,
	// and audit-event ingestion skips the SIEM tee.
	NewSIEMExporter func(db, bypassDB *sql.DB) siemExporter

	// NewScheduledReports constructs the cron-driven compliance-report runner.
	// Nil in Core, so the /scheduled-reports routes are never mounted and no
	// scheduler goroutine starts. Takes Core's *ComplianceReportService: the
	// dependency direction is Enterprise → Core, so on-demand generation stays
	// entirely in Core.
	NewScheduledReports func(db, bypassDB *sqlx.DB, compliance *services.ComplianceReportService) scheduledReportRunner
}

// siemExporter is the lifecycle surface main() drives. It extends the narrow
// handlers.SIEMForwarder seam (SendEvent) that audit-event ingestion consumes,
// so a single value serves both roles and a Core nil converts cleanly to a nil
// forwarder.
type siemExporter interface {
	handlers.SIEMForwarder

	// LoadIntegrations reads the configured SIEM destinations.
	LoadIntegrations(ctx context.Context) error

	// Start begins the background batch flusher.
	Start(ctx context.Context)

	// RegisterRoutes mounts the integration-management endpoints on the
	// authenticated /api/v1 group, gating them itself.
	RegisterRoutes(api *gin.RouterGroup)
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
	if hooks.NewSIEMExporter == nil && hooks.NewScheduledReports == nil {
		return "core"
	}
	return "enterprise"
}
