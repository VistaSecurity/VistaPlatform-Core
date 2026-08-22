package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vistasecurity/vistaplatform/audit-service/internal/config"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/database"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/jobs"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/middleware"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/services"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/subscribers"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
	"github.com/vistasecurity/vistaplatform/shared/version"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Connect to database
	db, err := database.NewConnection(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Test database connection
	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	// Connect the BYPASSRLS handle for deliberately cross-tenant audit work
	// (NULL-tenant platform/system writes, cross-tenant retention sweeps, the
	// scheduled-report runner, and by-id lifecycle updates). Reads
	// BYPASS_DATABASE_URL, falling back to DATABASE_URL pre-flip.
	bypassDB, err := shareddatabase.ConnectBypass()
	if err != nil {
		log.Fatalf("Failed to connect to bypass database: %v", err)
	}
	defer func() { _ = bypassDB.Close() }()
	bypassDBX := sqlx.NewDb(bypassDB, "postgres")

	// Initialize services
	activityLogService := services.NewActivityLogService(db.DB, bypassDB)
	jobExecutionService := services.NewJobExecutionService(db.DB, bypassDB)
	complianceService := services.NewComplianceService(db.DB, bypassDB)
	retentionService := services.NewRetentionService(db.DB, bypassDB)
	complianceReportService := services.NewComplianceReportService(db.DB, bypassDB)
	alertService := services.NewAlertServiceWithConfig(
		db.DB,
		cfg.UseMTLS,
		cfg.ClientCertPath,
		cfg.ClientKeyPath,
		cfg.PlatformCACertPath,
	)
	analyticsService := services.NewAnalyticsService(db.DB, bypassDB)

	// Enterprise capabilities (nil in a Core build — see cmd/edition.go).
	// Audit logging, ingestion, query, export, retention, alerting, analytics
	// and on-demand compliance reports are Core and always present; only the
	// outbound plumbing below is edition-gated.
	log.Printf("audit-service edition: %s", edition())

	var siemExport siemExporter
	if hooks.NewSIEMExporter != nil {
		siemExport = hooks.NewSIEMExporter(db.DB, bypassDB)
	}

	var scheduledReports scheduledReportRunner
	if hooks.NewScheduledReports != nil {
		scheduledReports = hooks.NewScheduledReports(sqlx.NewDb(db.DB, "postgres"), bypassDBX, complianceReportService)
	}

	// NATS client will be wired to alertService after initialization below

	// Load alert rules and SIEM integrations
	if err := alertService.LoadRules(context.Background()); err != nil {
		log.Printf("WARNING: Failed to load alert rules: %v", err)
	}
	if siemExport != nil {
		if err := siemExport.LoadIntegrations(context.Background()); err != nil {
			log.Printf("WARNING: Failed to load SIEM integrations: %v", err)
		}
	}

	// Start scheduled report scheduler
	if scheduledReports != nil {
		if err := scheduledReports.Start(context.Background()); err != nil {
			log.Printf("WARNING: Failed to start scheduled report scheduler: %v", err)
		}
	}

	// Initialize handlers. siemExport is passed as the SIEM tee: nil in Core,
	// where ingestion writes the audit event and simply forwards it nowhere.
	activityLogHandler := handlers.NewActivityLogHandlerWithMonitoring(activityLogService, alertService, siemExport)
	jobExecutionHandler := handlers.NewJobExecutionHandler(jobExecutionService)
	complianceHandler := handlers.NewComplianceHandlerWithReportService(complianceService, complianceReportService)
	retentionHandler := handlers.NewRetentionHandler(retentionService)
	alertHandler := handlers.NewAlertHandler(alertService)
	alertRuleHandler := handlers.NewAlertRuleHandler(services.NewAlertRuleService(sqlx.NewDb(db.DB, "postgres"), bypassDBX))
	analyticsHandler := handlers.NewAnalyticsHandler(analyticsService)

	// Set Gin mode
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Audit logging for audit-service's OWN API surface. Which requests are
	// recorded — and why the S2S ingest endpoints are not — is decided in
	// audit.go; see attachAuditLogging.
	auditMiddleware := auditmiddleware.NewMiddleware(auditmiddleware.ServiceConfig(
		"audit-service",
		cfg.UseMTLS,
		cfg.ClientCertPath,
		cfg.ClientKeyPath,
		cfg.PlatformCACertPath,
	))
	defer auditMiddleware.Stop()

	router := newRouter(cfg, db, auditMiddleware, routerHandlers{
		activityLog:      activityLogHandler,
		jobExecution:     jobExecutionHandler,
		compliance:       complianceHandler,
		retention:        retentionHandler,
		alert:            alertHandler,
		alertRule:        alertRuleHandler,
		analytics:        analyticsHandler,
		siemExport:       siemExport,
		scheduledReports: scheduledReports,
	})

	// Health check server (HTTP, port 8080)
	healthRouter := gin.New()
	healthRouter.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "audit-service",
			"version": version.Get(),
		})
	})

	healthServer := &http.Server{
		Addr:              cfg.Server.Host + ":" + cfg.Server.Port,
		Handler:           healthRouter,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// API server (HTTPS with mTLS, port 8443)
	var apiServer *http.Server
	if cfg.UseMTLS {
		var err error
		apiServer, err = sharedhttp.NewMTLSServer(
			cfg.ServiceCertPath,
			cfg.ServiceKeyPath,
			cfg.PlatformCACertPath,
			router,
		)
		if err != nil {
			log.Fatalf("Failed to create mTLS server: %v", err)
		}
		apiServer.Addr = cfg.Server.Host + ":" + cfg.TLSPort
		apiServer.ReadHeaderTimeout = 5 * time.Second
		apiServer.ReadTimeout = 10 * time.Second
		apiServer.WriteTimeout = 15 * time.Second
		apiServer.IdleTimeout = 60 * time.Second
	} else {
		// Fallback to HTTP if mTLS disabled
		apiServer = &http.Server{
			Addr:              cfg.Server.Host + ":" + cfg.Server.Port,
			Handler:           router,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
	}

	// Start health check server (only when mTLS is enabled - API server on different port)
	// When mTLS is disabled, API server includes /health endpoint on same port
	if cfg.UseMTLS {
		go func() {
			log.Printf("Health check server starting on %s:%s", cfg.Server.Host, cfg.Server.Port)
			if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start health server: %v", err)
			}
		}()
	}

	// Start API server
	go func() {
		if cfg.UseMTLS {
			log.Printf("🚀 Audit Service API server starting on %s:%s (mTLS)", cfg.Server.Host, cfg.TLSPort)
			log.Printf("📊 Ready to serve audit logging")
			if err := apiServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		} else {
			log.Printf("🚀 Audit Service API server starting on %s:%s (HTTP fallback)", cfg.Server.Host, cfg.Server.Port)
			log.Printf("📊 Ready to serve audit logging")
			if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		}
	}()

	log.Printf("🚀 Audit Service starting on %s:%s", cfg.Server.Host, cfg.Server.Port)
	log.Printf("📊 Ready to serve audit logging")

	// Initialize S3 archival service (optional)
	var s3ArchivalService *services.S3ArchivalService
	if cfg.S3.Enabled {
		var err error
		s3ArchivalService, err = services.NewS3ArchivalService(&cfg.S3)
		if err != nil {
			log.Printf("WARNING: Failed to initialize S3 archival: %v", err)
		} else {
			log.Println("✅ S3 archival service initialized")
		}
	}

	// Initialize NATS subscriber for audit event ingestion (replaces HTTP fallback)
	var auditSubscriber *subscribers.AuditSubscriber
	natsClient, natsErr := events.NewNATSClient("")
	if natsErr != nil {
		log.Printf("WARNING: NATS unavailable, audit events will only be received via HTTP: %v", natsErr)
	} else {
		auditSubscriber = subscribers.NewAuditSubscriber(natsClient, activityLogService, alertService)
		if err := auditSubscriber.Start(); err != nil {
			log.Printf("WARNING: Failed to start NATS audit subscriber: %v", err)
		} else {
			log.Println("NATS audit subscriber started on audit.activity-logs")
		}
		// Wire NATS to AlertService for event-driven notification publishing
		alertService.SetNATSClient(natsClient)
		log.Println("NATS client wired to AlertService for notification publishing")
	}

	// Start background services
	var retentionJob *jobs.RetentionJob
	if s3ArchivalService != nil && s3ArchivalService.IsEnabled() {
		retentionJob = jobs.NewRetentionJobWithS3(retentionService, jobExecutionService, s3ArchivalService, activityLogService)
	} else {
		retentionJob = jobs.NewRetentionJob(retentionService, jobExecutionService)
	}
	go retentionJob.Start(context.Background())

	// Start partition manager (creates future partitions automatically)
	partitionManager := jobs.NewPartitionManager(db.DB)
	go partitionManager.Start(context.Background())

	// Start the daily posture-snapshot job (ADR-0007) — feeds the dashboard
	// posture trend line. Kill-switch: POSTURE_SNAPSHOT_JOB_ENABLED=false.
	if cfg.PostureSnapshotEnabled {
		postureSnapshotJob := jobs.NewPostureSnapshotJob(
			db.DB,
			jobExecutionService,
			cfg.InventoryServiceURL,
			cfg.UseMTLS,
			cfg.ClientCertPath,
			cfg.ClientKeyPath,
			cfg.PlatformCACertPath,
		)
		go postureSnapshotJob.Start(context.Background())
	} else {
		log.Println("POSTURE_SNAPSHOT_JOB_ENABLED=false; posture snapshot job disabled")
	}

	// Start SIEM batch flusher (Enterprise only)
	if siemExport != nil {
		siemExport.Start(context.Background())
	}

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Stop NATS subscriber
	if auditSubscriber != nil {
		auditSubscriber.Stop()
	}
	if natsClient != nil {
		if err := natsClient.GracefulShutdown(ctx); err != nil {
			log.Printf("NATS client forced to shutdown: %v", err)
		}
	}

	// Shutdown both servers
	if err := healthServer.Shutdown(ctx); err != nil {
		log.Printf("Health server forced to shutdown: %v", err)
	}
	if err := apiServer.Shutdown(ctx); err != nil {
		log.Printf("API server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}

// routerHandlers bundles the handlers newRouter registers. It exists only to
// keep newRouter's signature readable; main() fills every field.
type routerHandlers struct {
	activityLog      *handlers.ActivityLogHandler
	jobExecution     *handlers.JobExecutionHandler
	compliance       *handlers.ComplianceHandler
	retention        *handlers.RetentionHandler
	alert            *handlers.AlertHandler
	alertRule        *handlers.AlertRuleHandler
	analytics        *handlers.AnalyticsHandler
	siemExport       siemExporter
	scheduledReports scheduledReportRunner
}

// newRouter builds the router main() serves: audit logging and every route
// group.
//
// It exists as a function so a test can exercise the REAL router rather than a
// hand-built stand-in. audit_test.go assembles its own gin.Engine and calls
// attachAuditLogging on it, which stays green even when nothing mounts the
// middleware in the running service — the wiring, not the helper, is what has
// to be under test. Mounting here, in the same function that registers the
// routes, means "routes but no audit middleware" is not a state main() can
// reach by deleting a line.
func newRouter(
	cfg *config.Config,
	db *database.DB,
	auditMiddleware *auditmiddleware.Middleware,
	h routerHandlers,
) *gin.Engine {
	// Initialize router
	router := gin.Default()

	// Audit logging for audit-service's OWN API surface. Mounted before the
	// route groups so it wraps every handler registered below. Which requests
	// are recorded — and why the S2S ingest endpoints are not — is decided in
	// audit.go; see attachAuditLogging.
	attachAuditLogging(router, auditMiddleware)

	// Health check endpoint (no auth required)
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "audit-service",
			"version": version.Get(),
		})
	})

	router.GET("/ready", func(c *gin.Context) {
		if err := db.Ping(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unhealthy", "error": "Service health check failed"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})

	// Internal service-to-service ingestion endpoints (HMAC auth required)
	// These are called by the shared audit middleware from other services within the Docker network.
	// Access is verified via HMAC-SHA256 signature using INTERNAL_AUTH_SECRET.
	internal := router.Group("/api/v1")
	internal.Use(middleware.RequireInternalAuth(cfg.InternalAuthSecret))
	{
		internal.POST("/audit-service/activity-logs", h.activityLog.LogActivity)
		internal.POST("/audit-service/job-execution-logs/start", h.jobExecution.LogJobStart)
		internal.POST("/audit-service/job-execution-logs/:id/progress", h.jobExecution.LogJobProgress)
		internal.POST("/audit-service/job-execution-logs/:id/complete", h.jobExecution.LogJobCompletion)
	}

	// API routes with authentication (user-facing queries and management)
	api := router.Group("/api/v1")
	api.Use(middleware.RequireAuth(cfg))
	// RLS: Tenant isolation uses WHERE tenant_id=$X in queries (primary) and PostgreSQL
	// RLS policies (defense-in-depth). For RLS session-variable enforcement, use
	// shared/database.WithTenantContext() at the repository level — never db.Exec().
	{
		// Activity log query endpoints
		api.GET("/audit-service/activity-logs", h.activityLog.GetActivityLogs)
		api.GET("/audit-service/activity-logs/:id", h.activityLog.GetActivityLogByID)
		api.GET("/audit-service/activity-logs/summary", h.activityLog.GetActivityLogsSummary)
		// SECURITY: these by-id queries take a client-supplied UUID; gate on
		// audit.read and tenant-scope in the handler so a tenant can't read another
		// tenant's activity. Mirrors the by-resource/:.../:... trail above.
		api.GET("/audit-service/activity-logs/by-user", middleware.RequirePermission(db.DB, rbac.PermissionAuditRead), h.activityLog.GetActivityLogsByUser)
		api.GET("/audit-service/activity-logs/by-resource", middleware.RequirePermission(db.DB, rbac.PermissionAuditRead), h.activityLog.GetActivityLogsByResource)
		api.GET("/audit-service/activity-logs/by-resource/:resource_type/:resource_id", h.activityLog.GetResourceAuditTrail) // NEW
		api.GET("/audit-service/activity-logs/by-user/:user_id", h.activityLog.GetUserActivityTimeline)                      // NEW
		api.POST("/audit-service/activity-logs/query", h.activityLog.QueryActivityLogs)
		api.GET("/audit-service/activity-logs/export", h.activityLog.ExportActivityLogs)

		// Job execution log query endpoint
		api.GET("/audit-service/job-execution-logs", h.jobExecution.GetJobExecutionLogs)

		// Compliance endpoints
		api.GET("/audit-service/compliance-reports/summary", h.compliance.GetComplianceSummary)
		api.GET("/audit-service/compliance-reports/validate-retention", h.compliance.ValidateRetentionPolicies)
		api.GET("/audit-service/compliance-reports/templates", h.compliance.GetComplianceReportTemplates)
		api.POST("/audit-service/compliance-reports/generate", h.compliance.GenerateComplianceReport)

		// Retention policy endpoints.
		// SECURITY: writes gated on audit.manage (blocks tenant viewers).
		// retention_policies + siem/integrations are platform-GLOBAL config (no
		// tenant_id column) — the durable fix is a platform-admin-only gate (or
		// tenant-scoping the tables), pending the product decision.
		// Since audit.manage is a real, seeded tenant permission resolved
		// from tenant_role_permissions, not a role name this service made up.
		api.GET("/audit-service/retention-policies", h.retention.GetRetentionPolicies)
		api.GET("/audit-service/retention-policies/:id", h.retention.GetRetentionPolicyByID)
		api.POST("/audit-service/retention-policies", middleware.RequirePermission(db.DB, rbac.PermissionAuditManage), h.retention.CreateRetentionPolicy)
		api.PUT("/audit-service/retention-policies/:id", middleware.RequirePermission(db.DB, rbac.PermissionAuditManage), h.retention.UpdateRetentionPolicy)

		// Built-in audit alert rules (read-only view of the in-memory engine).
		//
		// GET /alerts and POST /alerts/:id/acknowledge used to sit here. They
		// were the sole data source for Remediation → Triage and neither did
		// anything: GetAlerts returned a hardcoded empty list and
		// AcknowledgeAlert only wrote a log line, so the page showed "Inbox
		// zero" forever and an acknowledgement was confirmed but never stored.
		// Both, and the page, were removed. Audit-rule alerts that map onto a
		// registry alert type reach the tenant through the stateful alert rail
		// (alerts.raise → compliance-engine → Remediation → Alerts), which
		// persists them with a real lifecycle.
		api.GET("/audit-service/alerts/rules", h.alert.GetAlertRules)

		// Custom Alert Rule endpoints (NEW)
		api.POST("/audit-service/alert-rules", middleware.RequirePermission(db.DB, rbac.PermissionAuditManage), h.alertRule.CreateAlertRule)
		api.GET("/audit-service/alert-rules", h.alertRule.GetAlertRules)
		api.GET("/audit-service/alert-rules/:id", h.alertRule.GetAlertRuleByID)
		api.PUT("/audit-service/alert-rules/:id", middleware.RequirePermission(db.DB, rbac.PermissionAuditManage), h.alertRule.UpdateAlertRule)
		api.DELETE("/audit-service/alert-rules/:id", middleware.RequirePermission(db.DB, rbac.PermissionAuditManage), h.alertRule.DeleteAlertRule)

		// Removed: GET /alert-instances and POST /alert-instances/:id/{acknowledge,resolve}.
		// They read and updated audit.alert_instances, a table with no INSERT
		// anywhere in the tree — so the list could only ever return empty and
		// the two mutations could only ever 404. Nothing in either UI called
		// them. This is the same defect as the Triage page removed in,
		// one layer down.
		//
		// Not given a producer, because the rules above are a rule *store*, not
		// an engine: nothing evaluates audit.alert_rules. A producer would mean
		// building an evaluator AND a second stateful alert store beside the
		// working one — the outcome ADR-0006 rejected. Alerts that fire reach
		// the tenant through the stateful rail (alerts.raise → compliance-engine
		// → Remediation → Alerts), which owns alert lifecycle.

		// Scheduled Report endpoints (Enterprise). Absent in a Core build — the
		// runner owns its own routes and permission gating; see
		// ee/scheduledreports. Core still generates compliance reports on
		// demand via /compliance-reports/generate above.
		if h.scheduledReports != nil {
			h.scheduledReports.RegisterRoutes(api)
		}

		// SIEM integration endpoints (Enterprise). Absent in a Core build. The
		// exporter owns its own routes and permission gating, including the
		// audit.manage gate on the read (SIEM integrations are
		// platform-global config, not per-tenant data) and secret redaction.
		if h.siemExport != nil {
			h.siemExport.RegisterRoutes(api)
		}

		// Analytics endpoints
		api.GET("/audit-service/analytics/user-activity", h.analytics.GetUserActivity)
		api.GET("/audit-service/analytics/access-patterns", h.analytics.GetAccessPatterns)
		api.GET("/audit-service/analytics/compliance-gaps", h.analytics.GetComplianceGaps)
		api.GET("/audit-service/analytics/dashboard", h.analytics.GetDashboardMetrics)
	}

	return router
}
