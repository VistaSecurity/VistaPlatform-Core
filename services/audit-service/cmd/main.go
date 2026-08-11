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
	defer db.Close()

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
	alertService.LoadRules(context.Background())
	if siemExport != nil {
		siemExport.LoadIntegrations(context.Background())
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

	// Initialize router
	router := gin.Default()

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
		internal.POST("/audit-service/activity-logs", activityLogHandler.LogActivity)
		internal.POST("/audit-service/job-execution-logs/start", jobExecutionHandler.LogJobStart)
		internal.POST("/audit-service/job-execution-logs/:id/progress", jobExecutionHandler.LogJobProgress)
		internal.POST("/audit-service/job-execution-logs/:id/complete", jobExecutionHandler.LogJobCompletion)
	}

	// API routes with authentication (user-facing queries and management)
	api := router.Group("/api/v1")
	api.Use(middleware.RequireAuth(cfg))
	// RLS: Tenant isolation uses WHERE tenant_id=$X in queries (primary) and PostgreSQL
	// RLS policies (defense-in-depth). For RLS session-variable enforcement, use
	// shared/database.WithTenantContext() at the repository level — never db.Exec().
	{
		// Activity log query endpoints
		api.GET("/audit-service/activity-logs", activityLogHandler.GetActivityLogs)
		api.GET("/audit-service/activity-logs/:id", activityLogHandler.GetActivityLogByID)
		api.GET("/audit-service/activity-logs/summary", activityLogHandler.GetActivityLogsSummary)
		// SECURITY: these by-id queries take a client-supplied UUID; gate on
		// audit.read and tenant-scope in the handler so a tenant can't read another
		// tenant's activity. Mirrors the by-resource/:.../:... trail above.
		api.GET("/audit-service/activity-logs/by-user", middleware.RequirePermission("audit.read"), activityLogHandler.GetActivityLogsByUser)
		api.GET("/audit-service/activity-logs/by-resource", middleware.RequirePermission("audit.read"), activityLogHandler.GetActivityLogsByResource)
		api.GET("/audit-service/activity-logs/by-resource/:resource_type/:resource_id", activityLogHandler.GetResourceAuditTrail) // NEW
		api.GET("/audit-service/activity-logs/by-user/:user_id", activityLogHandler.GetUserActivityTimeline)                      // NEW
		api.POST("/audit-service/activity-logs/query", activityLogHandler.QueryActivityLogs)
		api.GET("/audit-service/activity-logs/export", activityLogHandler.ExportActivityLogs)

		// Job execution log query endpoint
		api.GET("/audit-service/job-execution-logs", jobExecutionHandler.GetJobExecutionLogs)

		// Compliance endpoints
		api.GET("/audit-service/compliance-reports/summary", complianceHandler.GetComplianceSummary)
		api.GET("/audit-service/compliance-reports/validate-retention", complianceHandler.ValidateRetentionPolicies)
		api.GET("/audit-service/compliance-reports/templates", complianceHandler.GetComplianceReportTemplates)
		api.POST("/audit-service/compliance-reports/generate", complianceHandler.GenerateComplianceReport)

		// Retention policy endpoints.
		// SECURITY: writes interim-gated to audit.manage (blocks tenant
		// viewers). retention_policies + siem/integrations are platform-GLOBAL
		// config (no tenant_id column) — the durable fix is a platform-admin-only
		// gate (or tenant-scoping the tables), pending the product decision.
		api.GET("/audit-service/retention-policies", retentionHandler.GetRetentionPolicies)
		api.GET("/audit-service/retention-policies/:id", retentionHandler.GetRetentionPolicyByID)
		api.POST("/audit-service/retention-policies", middleware.RequirePermission("audit.manage"), retentionHandler.CreateRetentionPolicy)
		api.PUT("/audit-service/retention-policies/:id", middleware.RequirePermission("audit.manage"), retentionHandler.UpdateRetentionPolicy)

		// Alert endpoints (legacy)
		api.GET("/audit-service/alerts/rules", alertHandler.GetAlertRules)
		api.GET("/audit-service/alerts", alertHandler.GetAlerts)
		api.POST("/audit-service/alerts/:id/acknowledge", middleware.RequirePermission("audit.manage"), alertHandler.AcknowledgeAlert)

		// Custom Alert Rule endpoints (NEW)
		api.POST("/audit-service/alert-rules", middleware.RequirePermission("audit.manage"), alertRuleHandler.CreateAlertRule)
		api.GET("/audit-service/alert-rules", alertRuleHandler.GetAlertRules)
		api.GET("/audit-service/alert-rules/:id", alertRuleHandler.GetAlertRuleByID)
		api.PUT("/audit-service/alert-rules/:id", middleware.RequirePermission("audit.manage"), alertRuleHandler.UpdateAlertRule)
		api.DELETE("/audit-service/alert-rules/:id", middleware.RequirePermission("audit.manage"), alertRuleHandler.DeleteAlertRule)
		api.GET("/audit-service/alert-instances", alertRuleHandler.GetAlertInstances)
		api.POST("/audit-service/alert-instances/:id/acknowledge", middleware.RequirePermission("audit.manage"), alertRuleHandler.AcknowledgeAlert)
		api.POST("/audit-service/alert-instances/:id/resolve", middleware.RequirePermission("audit.manage"), alertRuleHandler.ResolveAlert)

		// Scheduled Report endpoints (Enterprise). Absent in a Core build — the
		// runner owns its own routes and permission gating; see
		// ee/scheduledreports. Core still generates compliance reports on
		// demand via /compliance-reports/generate above.
		if scheduledReports != nil {
			scheduledReports.RegisterRoutes(api)
		}

		// SIEM integration endpoints (Enterprise). Absent in a Core build. The
		// exporter owns its own routes and permission gating, including the
		// audit.manage gate on the read (SIEM integrations are
		// platform-global config, not per-tenant data) and secret redaction.
		if siemExport != nil {
			siemExport.RegisterRoutes(api)
		}

		// Analytics endpoints
		api.GET("/audit-service/analytics/user-activity", analyticsHandler.GetUserActivity)
		api.GET("/audit-service/analytics/access-patterns", analyticsHandler.GetAccessPatterns)
		api.GET("/audit-service/analytics/compliance-gaps", analyticsHandler.GetComplianceGaps)
		api.GET("/audit-service/analytics/dashboard", analyticsHandler.GetDashboardMetrics)
	}

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
		auditSubscriber = subscribers.NewAuditSubscriber(natsClient, activityLogService)
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
		natsClient.GracefulShutdown(ctx)
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
