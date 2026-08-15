package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/config"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/database"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/handlers"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/jobs"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/middleware"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	resourcetracking "github.com/vistasecurity/vistaplatform/shared/middleware/resource-tracking"
	trial_lock "github.com/vistasecurity/vistaplatform/shared/middleware/trial_lock"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
	sharedservices "github.com/vistasecurity/vistaplatform/shared/services"
	"github.com/vistasecurity/vistaplatform/shared/version"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

func main() {
	// Which edition is this binary? Logged first so an operator can tell from
	// the top of the log whether the custom-policy authoring and
	// threshold-override surfaces exist at all in this process.
	log.Printf("⚙️  compliance-engine edition: %s", edition())

	// Load configuration
	cfg := config.Load()

	// Connect to database
	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Second pool for deliberately cross-tenant work (Phase 4 RLS flip). Under the
	// role split DATABASE_URL → crypto_app (NOBYPASSRLS, subject to RLS) while
	// BYPASS_DATABASE_URL → crypto_bypass (BYPASSRLS). The annotated cross-tenant
	// sweeps/enumerators run on this handle so they don't fail closed under RLS.
	// ConnectBypass falls back to DATABASE_URL when BYPASS_DATABASE_URL is unset,
	// so pre-flip deployments are unchanged.
	bypassSQLDB, err := shareddatabase.ConnectBypass()
	if err != nil {
		log.Fatalf("Failed to connect to bypass database: %v", err)
	}
	bypassDB := sqlx.NewDb(bypassSQLDB, "postgres")
	defer func() { _ = bypassDB.Close() }()

	// Initialize services
	complianceService := services.NewComplianceService(db)
	scenarioService := services.NewScenarioService(db)
	overrideService := services.NewOverrideService(db)
	platformFrameworkService := services.NewPlatformFrameworkService(db)
	tenantFrameworkService := services.NewTenantFrameworkService(db)
	frameworkLicenseService := services.NewFrameworkLicenseService(db)
	limitService := sharedservices.NewLimitEnforcementService(db.DB)
	measurementExtractor := services.NewMeasurementExtractor(db)
	ruleEvaluator := services.NewRuleEvaluator(db, measurementExtractor)
	evaluationService := services.NewEvaluationService(db, ruleEvaluator)
	templateService := services.NewTemplateService(db)
	mappingsService := services.NewMappingsService(db)

	// Initialize metrics service
	metricsService := services.NewMetricsService()
	// The evaluator counts not-assessed controls and failed measurement checks
	// here: excluding a control from the score is only defensible while
	// the exclusion is visible on /metrics.
	ruleEvaluator.SetMetrics(metricsService)

	// Initialize handlers
	complianceHandlers := handlers.NewComplianceHandlers(complianceService, mappingsService)
	findingsService := services.NewFindingsService(db, bypassDB, ruleEvaluator, frameworkLicenseService, evaluationService, metricsService)
	workspaceHandlers := handlers.NewWorkspaceHandlers(evaluationService, scenarioService, overrideService, findingsService)
	metricsHandlers := handlers.NewMetricsHandlers(metricsService)
	platformFrameworkHandlers := handlers.NewPlatformFrameworkHandlers(platformFrameworkService)
	tenantFrameworkHandlers := handlers.NewTenantFrameworkHandlers(tenantFrameworkService, frameworkLicenseService)
	frameworkLicenseHandlers := handlers.NewFrameworkLicenseHandlers(frameworkLicenseService)
	measurementHandlers := handlers.NewMeasurementHandlers(db)
	templateHandlers := handlers.NewTemplateHandlers(templateService)

	// Enterprise: applying a measurement template to a tenant-authored
	// framework control is custom-policy authoring. Core leaves this unwired
	// and that path returns services.ErrCustomPoliciesUnavailable.
	if hooks.NewTenantMeasurementAuthor != nil {
		if author := hooks.NewTenantMeasurementAuthor(db); author != nil {
			templateService.SetTenantAuthor(author)
		}
	}

	// Initialize framework context service and handlers (consolidated API)
	frameworkContextService := services.NewFrameworkContextService(db, frameworkLicenseService, evaluationService)
	frameworkContextHandlers := handlers.NewFrameworkContextHandlers(frameworkContextService)

	// Initialize shared NATS client (used by event subscriber + ticket service)
	var natsClient *events.NATSClient
	natsClient, err = events.NewNATSClient("")
	if err != nil {
		log.Printf("⚠️  Warning: Failed to initialize NATS client: %v. Event-driven features will be degraded.", err)
	} else {
		defer natsClient.Close()
	}

	// ADR-0014: wire the reconcile enqueuer so framework activation/publish enqueue
	// per-tenant reconcile jobs drained by the worker in EventSubscriberService.
	var reconcileEnqueuer *services.ReconcileEnqueuer
	if natsClient != nil {
		reconcileEnqueuer = services.NewReconcileEnqueuer(natsClient, bypassDB)
		frameworkLicenseService.SetReconcileEnqueuer(reconcileEnqueuer)
		platformFrameworkService.SetReconcileEnqueuer(reconcileEnqueuer)
	}

	// Initialize unified ticket service (uses NATS for notifications)
	ticketService := services.NewTicketService(db, bypassDB, natsClient)
	ticketHandlers := handlers.NewTicketHandlers(ticketService)

	// Stateful alert engine: dedupe-on-raise, evidence chain,
	// ack/snooze/resolve lifecycle, ticket bridge.
	// mTLS-aware: the engine's NATS-down HTTP fallback to notification-service
	// must present a client certificate when the service mesh is on.
	alertEngine := services.NewAlertEngineServiceWithConfig(db, bypassDB, natsClient, ticketService,
		cfg.UseMTLS, cfg.ClientCertPath, cfg.ClientKeyPath, cfg.PlatformCACertPath)
	alertHandlers := handlers.NewAlertHandlers(alertEngine)

	// Alert catalog (§8.2): registry types + tenant settings + rung ladders.
	alertCatalog := services.NewAlertCatalogService(db)
	alertCatalogHandlers := handlers.NewAlertCatalogHandlers(alertCatalog)

	// Initialize remediation plan service
	planService := services.NewRemediationPlanService(db, bypassDB, natsClient)
	planHandlers := handlers.NewRemediationPlanHandlers(planService)

	// Set Gin mode
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize router
	router := gin.Default()

	// Resource tracking middleware
	trackerConfig := resourcetracking.DefaultConfig()
	trackerConfig.ServiceName = "compliance-engine"
	trackerConfig.TrackerURL = os.Getenv("RESOURCE_TRACKER_URL")
	if trackerConfig.TrackerURL == "" {
		trackerConfig.TrackerURL = sharedconfig.PeerURL("resource-tracker-service", sharedconfig.MTLSEnabled())
	}
	// mTLS configuration
	trackerConfig.UseMTLS = cfg.UseMTLS
	trackerConfig.ClientCertPath = cfg.ClientCertPath
	trackerConfig.ClientKeyPath = cfg.ClientKeyPath
	trackerConfig.PlatformCACertPath = cfg.PlatformCACertPath
	router.Use(resourcetracking.Middleware(trackerConfig))

	// Audit logging middleware
	auditConfig := auditmiddleware.DefaultConfig()
	auditConfig.ServiceName = "compliance-engine"
	auditConfig.AuditServiceURL = os.Getenv("AUDIT_SERVICE_URL")
	if auditConfig.AuditServiceURL == "" {
		if cfg.UseMTLS {
			auditConfig.AuditServiceURL = "https://audit-service:8443"
		} else {
			auditConfig.AuditServiceURL = sharedconfig.PeerURL("audit-service", sharedconfig.MTLSEnabled())
		}
	}
	auditConfig.Enabled = os.Getenv("AUDIT_LOGGING_ENABLED") != "false"
	// mTLS configuration
	auditConfig.UseMTLS = cfg.UseMTLS
	auditConfig.ClientCertPath = cfg.ClientCertPath
	auditConfig.ClientKeyPath = cfg.ClientKeyPath
	auditConfig.PlatformCACertPath = cfg.PlatformCACertPath
	auditMiddleware := auditmiddleware.NewMiddleware(auditConfig)
	router.Use(auditMiddleware.LogRequest())

	// CORS is handled by Traefik API gateway - no need for duplicate headers

	// Health check
	router.GET("/health", complianceHandlers.Health)

	// Metrics endpoint (no auth required for monitoring-service scraping)
	router.GET("/metrics", metricsHandlers.GetMetrics)
	router.GET("/metrics/health", metricsHandlers.GetMetricsHealth)

	// Raw *sql.DB reference for the shared RBAC middleware.
	// compliance-engine's database.Connect returns *sqlx.DB, which embeds *sql.DB.
	rawDB := db.DB

	// API routes (service namespace must be compliance-engine per standards)
	api := router.Group("/api/v1")
	compliance := api.Group("/compliance-engine")

	// Apply authentication middleware to all compliance routes
	compliance.Use(middleware.RequireAuth(cfg.JWTSecret))
	compliance.Use(middleware.StringifyUserID())
	// Trial-lock middleware gates writes when the calling tenant is in
	// PhaseLocked. Reads and the billing/auth allow-list pass through.
	compliance.Use(trial_lock.Middleware(rawDB, nil))
	// RLS: Tenant isolation uses WHERE tenant_id=$X in queries (primary) and PostgreSQL
	// RLS policies (defense-in-depth). For RLS session-variable enforcement, use
	// shared/database.WithTenantContext() at the repository level — never db.Exec().
	{
		// Framework catalog (updated to return published frameworks)
		compliance.GET("/frameworks", tenantFrameworkHandlers.ListPublishedFrameworks)
		compliance.GET("/frameworks/:id", tenantFrameworkHandlers.ViewFramework)

		// Published frameworks (tenant read-only access)
		// Note: ListPublishedFrameworks returns summary-only for unlicensed frameworks.
		// ViewFramework requires an active license to see full control details.
		compliance.GET("/frameworks/published", tenantFrameworkHandlers.ListPublishedFrameworks)
		compliance.GET("/frameworks/published/:id", tenantFrameworkHandlers.ViewFramework)
		// CopyFramework removed: tenants subscribe to platform frameworks instead of copying them.

		// Tenant frameworks — READ ONLY in Core. Authoring (POST/PUT/DELETE on
		// frameworks, controls, and measurement rules) is the Enterprise
		// custom_policies feature and is mounted by the edition hook below.
		compliance.GET("/frameworks/tenant", tenantFrameworkHandlers.ListTenantFrameworks)
		compliance.GET("/frameworks/tenant/:id", tenantFrameworkHandlers.GetTenantFramework)
		compliance.GET("/frameworks/tenant/controls/:id/measurements", tenantFrameworkHandlers.ListControlMeasurements)

		// Measurement types catalog
		compliance.GET("/measurement-types", measurementHandlers.ListMeasurementTypes)
		compliance.GET("/measurement-types/:code", measurementHandlers.GetMeasurementType)

		// Compliance rules management
		compliance.GET("/rules", complianceHandlers.GetComplianceRules)
		compliance.GET("/rules/:id", complianceHandlers.GetComplianceRule)
		compliance.POST("/rules", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), complianceHandlers.CreateComplianceRule)

		// Compliance checks and reports. Running a check writes findings,
		// so it counts as a compliance.update (not a read).
		compliance.POST("/checks", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), complianceHandlers.RunComplianceCheck)
		compliance.GET("/reports", complianceHandlers.GetComplianceReports)
		compliance.GET("/legacy/summary", complianceHandlers.GetComplianceSummary)

		// Workspace endpoints (v1 MVP)
		compliance.GET("/summary", workspaceHandlers.GetSummary)
		compliance.POST("/evaluate/multiple", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), workspaceHandlers.EvaluateMultipleFrameworks)
		compliance.GET("/compliance/score", workspaceHandlers.GetComplianceScore)
		compliance.GET("/frameworks/status", workspaceHandlers.GetFrameworkStatus)
		compliance.GET("/controls/:id", workspaceHandlers.GetControlDetails)

		// Framework licensing and subscriptions
		compliance.GET("/frameworks/licenses", frameworkLicenseHandlers.ListLicensedFrameworks)
		compliance.GET("/frameworks/available", frameworkLicenseHandlers.GetAvailableFrameworks)
		compliance.GET("/frameworks/default", frameworkLicenseHandlers.GetDefaultFramework)
		compliance.POST("/frameworks/licenses", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), frameworkLicenseHandlers.SelectFrameworks)                   // Legacy: batch select
		compliance.POST("/frameworks/subscribe", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), frameworkLicenseHandlers.SubscribeFramework)                // New: self-service subscribe
		compliance.DELETE("/frameworks/subscribe/:frameworkId", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), frameworkLicenseHandlers.CancelSubscription) // New: cancel subscription
		compliance.PUT("/frameworks/default", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), frameworkLicenseHandlers.SetDefaultFramework)                  // New: set default framework
		compliance.PUT("/frameworks/licenses/unlock", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), frameworkLicenseHandlers.UnlockFrameworks)             // Legacy compat

		// User framework preferences. These persist a per-user setting
		// (handler uses ctx user ID, not a tenant resource), so the JWT
		// alone is enough — no tenant permission required. A viewer
		// setting their own default framework is fine.
		compliance.GET("/frameworks/user-preference", frameworkLicenseHandlers.GetUserFrameworkPreference)
		compliance.PUT("/frameworks/user-preference", frameworkLicenseHandlers.SetUserFrameworkPreference)
		compliance.DELETE("/frameworks/user-preference", frameworkLicenseHandlers.ClearUserFrameworkPreference)

		// Enterprise edition routes. Both hooks are nil in a Core build, so
		// these surfaces simply do not exist there — no 404-returning stub, no
		// dead handler. Inside an Enterprise build the per-tenant entitlement
		// gate (custom_policies / threshold_overrides) still applies on top.
		if hooks.RegisterPolicyAuthoringRoutes != nil {
			hooks.RegisterPolicyAuthoringRoutes(compliance, db, rawDB, limitService)
		}
		if hooks.RegisterThresholdOverrideRoutes != nil {
			hooks.RegisterThresholdOverrideRoutes(compliance, db, rawDB)
		}

		// Consolidated framework context endpoint (reduces multiple API calls to one).
		// batch-evaluate writes findings — same reasoning as POST /checks.
		compliance.GET("/frameworks/context", frameworkContextHandlers.GetFrameworkContext)
		compliance.POST("/frameworks/batch-evaluate", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), frameworkContextHandlers.BatchEvaluateFrameworks)

		// Scenario management
		compliance.POST("/scenarios", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), workspaceHandlers.CreateScenario)
		compliance.PUT("/scenarios/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), workspaceHandlers.UpdateScenario)
		compliance.GET("/scenarios", workspaceHandlers.ListScenarios)
		compliance.GET("/scenarios/:id", workspaceHandlers.GetScenario)
		compliance.DELETE("/scenarios/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), workspaceHandlers.DeleteScenario)

		// Override management
		compliance.POST("/overrides", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), workspaceHandlers.CreateOverride)
		compliance.GET("/overrides", workspaceHandlers.ListOverrides)
		compliance.DELETE("/overrides/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), workspaceHandlers.DeleteOverride)

		// Finding assignment
		compliance.POST("/findings/:id/assign", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), workspaceHandlers.AssignFindingOwner)
		compliance.DELETE("/findings/:id/assign", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), workspaceHandlers.UnassignFindingOwner)
		compliance.GET("/findings/:id/evidence-id", workspaceHandlers.GetEvidenceId)

		// Finding workflow status
		compliance.PUT("/findings/:id/workflow-status", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), workspaceHandlers.UpdateFindingWorkflowStatus)
		compliance.GET("/findings/:id/history", workspaceHandlers.GetFindingHistory)
		compliance.GET("/assets/:assetId/findings", workspaceHandlers.GetFindingsByAsset)
		compliance.GET("/findings", workspaceHandlers.ListFindings)
		compliance.GET("/findings/statistics", workspaceHandlers.GetFindingStatistics)
		compliance.GET("/findings/by-control", workspaceHandlers.GetFindingsByControl)

		// Unified ticket management. Tickets are a unified table (categories:
		// compliance, certificate, remediation, vulnerability, operational,
		// general) but the handlers live here, so we gate them with
		// compliance.update. If finer-grained ticket scoping is needed
		// later, introduce a tickets.* permission family — that's a
		// seed.sql + RDS migration change, deferred.
		compliance.GET("/tickets", ticketHandlers.ListTickets)
		compliance.POST("/tickets", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), ticketHandlers.CreateTicket)
		compliance.GET("/tickets/stats", ticketHandlers.GetTicketStats)
		compliance.GET("/tickets/progress", ticketHandlers.GetTicketProgress)
		compliance.GET("/tickets/:id", ticketHandlers.GetTicket)
		compliance.PUT("/tickets/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), ticketHandlers.UpdateTicket)
		compliance.DELETE("/tickets/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), ticketHandlers.DeleteTicket)
		compliance.GET("/tickets/:id/comments", ticketHandlers.ListComments)
		compliance.POST("/tickets/:id/comments", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), ticketHandlers.AddComment)

		// Stateful alerts. Reads open to members; lifecycle mutations
		// (ack/snooze/resolve/ticket) behind alerts.manage. /alerts/stats is
		// registered before /alerts/:id so gin routes the static path first.
		alertsManage := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAlertsManage)
		compliance.GET("/alerts", alertHandlers.ListAlerts)
		compliance.GET("/alerts/stats", alertHandlers.GetAlertStats)
		compliance.GET("/alerts/:id", alertHandlers.GetAlert)
		compliance.POST("/alerts/:id/acknowledge", alertsManage, alertHandlers.AcknowledgeAlert)
		compliance.POST("/alerts/:id/snooze", alertsManage, alertHandlers.SnoozeAlert)
		compliance.POST("/alerts/:id/unsnooze", alertsManage, alertHandlers.UnsnoozeAlert)
		compliance.POST("/alerts/:id/resolve", alertsManage, alertHandlers.ResolveAlert)
		compliance.POST("/alerts/:id/ticket", alertsManage, alertHandlers.CreateTicketFromAlert)

		// Alert catalog (Settings → Alert Rules): registry + tenant state +
		// effective ladders. Reads open; edits behind alerts.manage.
		compliance.GET("/alert-catalog", alertCatalogHandlers.GetCatalog)
		compliance.PUT("/alert-catalog/:type", alertsManage, alertCatalogHandlers.UpdateCatalogEntry)

		// Remediation plans
		compliance.GET("/plans", planHandlers.ListPlans)
		compliance.POST("/plans", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), planHandlers.CreatePlan)
		// Batch ticket -> plan back-link lookup. MUST be registered before /plans/:id
		// so gin does not mistake "for-tickets" for a plan ID.
		compliance.GET("/plans/for-tickets", planHandlers.ListPlansForTickets)
		compliance.GET("/plans/:id", planHandlers.GetPlan)
		compliance.PUT("/plans/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), planHandlers.UpdatePlan)
		compliance.DELETE("/plans/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), planHandlers.DeletePlan)
		compliance.GET("/plans/:id/items", planHandlers.ListPlanItems)
		compliance.POST("/plans/:id/items", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), planHandlers.AddPlanItem)
		compliance.POST("/plans/:id/items/bulk", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), planHandlers.AddPlanItemsBulk)
		compliance.DELETE("/plans/:id/items/:itemId", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), planHandlers.RemovePlanItem)
		compliance.PUT("/plans/:id/items/:itemId/ticket", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), planHandlers.LinkTicketToItem)
		compliance.GET("/plans/:id/progress", planHandlers.GetPlanProgress)

		// Legacy workspace endpoint (for backward compatibility)
		compliance.GET("/workspace/summary", complianceHandlers.GetWorkspaceSummary)

		// Mappings (admin-only in future)
		compliance.GET("/mappings", complianceHandlers.ListMappings)
		compliance.GET("/mappings/:id", complianceHandlers.GetMapping)
		compliance.POST("/mappings", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), complianceHandlers.CreateMapping)
		compliance.PUT("/mappings/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), complianceHandlers.UpdateMapping)
		compliance.DELETE("/mappings/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionComplianceUpdate), complianceHandlers.DeleteMapping)
	}

	// Admin routes (platform admin only)
	admin := api.Group("/compliance-engine/admin")
	admin.Use(middleware.RequirePlatformAuth(cfg.JWTSecret))
	admin.Use(middleware.StringifyUserID())
	admin.Use(middleware.RequirePlatformAdmin())
	{
		// ADR-0015: manual per-tenant re-evaluation (platform-admin, extraordinary).
		admin.POST("/tenants/:tenantId/reevaluate", handlers.NewAdminReconcileHandler(reconcileEnqueuer).ReevaluateTenant)

		// Platform-track stateful alerts (service_down, tenant_health_degraded)
		// raised under the sentinel platform tenant. Read-only here; ack/snooze
		// UI is a fast-follow.
		admin.GET("/alerts", alertHandlers.ListPlatformAlerts)

		// Platform framework management
		admin.GET("/frameworks", platformFrameworkHandlers.ListFrameworks)
		admin.POST("/frameworks", platformFrameworkHandlers.CreateFramework)
		admin.GET("/frameworks/:id", platformFrameworkHandlers.GetFramework)
		admin.PUT("/frameworks/:id", platformFrameworkHandlers.UpdateFramework)
		admin.DELETE("/frameworks/:id", platformFrameworkHandlers.DeleteFramework)
		admin.POST("/frameworks/:id/publish", platformFrameworkHandlers.PublishFramework)
		admin.GET("/frameworks/:id/versions", platformFrameworkHandlers.ListFrameworkVersions)
		admin.GET("/frameworks/versions/:versionId", platformFrameworkHandlers.GetFrameworkVersion)
		admin.POST("/frameworks/:id/unpublish", func(c *gin.Context) {
			// Unpublish is same as archiving
			idStr := c.Param("id")
			id, err := uuid.Parse(idStr)
			if err != nil {
				c.JSON(400, gin.H{"error": "Invalid framework ID"})
				return
			}
			userIDStr, _ := c.Get("userID")
			userID, _ := uuid.Parse(userIDStr.(string))
			input := models.PublishFrameworkInput{Status: "archived"}
			framework, err := platformFrameworkService.PublishFramework(id, &input, userID)
			if err != nil {
				c.JSON(500, gin.H{"error": "Internal server error"})
				return
			}
			c.JSON(200, gin.H{"message": "Framework unpublished successfully", "framework": framework})
		})

		// Platform framework controls
		admin.POST("/frameworks/:id/controls", platformFrameworkHandlers.CreateControl)
		admin.PUT("/frameworks/:id/controls/:controlId", platformFrameworkHandlers.UpdateControl)
		admin.DELETE("/frameworks/:id/controls/:controlId", platformFrameworkHandlers.DeleteControl)

		// Platform framework control measurements
		admin.GET("/controls/:id/measurements", platformFrameworkHandlers.ListControlMeasurements)
		admin.POST("/controls/:id/measurements", platformFrameworkHandlers.AddControlMeasurement)
		admin.PUT("/controls/:id/measurements/:measurementId", platformFrameworkHandlers.UpdateControlMeasurement)
		admin.DELETE("/controls/:id/measurements/:measurementId", platformFrameworkHandlers.DeleteControlMeasurement)

		// Measurement templates
		admin.GET("/templates", templateHandlers.ListTemplates)
		admin.GET("/templates/:id", templateHandlers.GetTemplate)
		admin.POST("/templates", templateHandlers.CreateTemplate)
		admin.PUT("/templates/:id", templateHandlers.UpdateTemplate)
		admin.DELETE("/templates/:id", templateHandlers.DeleteTemplate)

		// Framework provisioning (admin → tenant)
		admin.POST("/provision-framework", frameworkLicenseHandlers.AdminProvisionFramework)
		admin.GET("/tenants/:tenantId/subscriptions", frameworkLicenseHandlers.AdminListTenantSubscriptions)
		admin.DELETE("/tenants/:tenantId/subscriptions/:frameworkId", frameworkLicenseHandlers.AdminCancelTenantSubscription)
		admin.POST("/templates/:id/apply", templateHandlers.ApplyTemplate)
	}

	// Initialize and start event subscriber
	var eventSubscriber *services.EventSubscriberService
	if natsClient != nil {
		eventSubscriber = services.NewEventSubscriberService(natsClient, findingsService, metricsService)
		if err := eventSubscriber.Start(); err != nil {
			log.Printf("⚠️  Warning: Failed to start event subscriber: %v. Event-driven findings will not be available.", err)
		} else {
			log.Printf("📡 Event subscriber started, listening for compliance events")
		}
		defer func() {
			if eventSubscriber != nil {
				if err := eventSubscriber.Stop(); err != nil {
					log.Printf("Error stopping event subscriber: %v", err)
				}
			}
		}()
	}

	// Alert lifecycle subscriber: alerts.raise / alerts.resolve + the
	// certificate-expiring translation (the alert engine owns cert alert
	// notifications; notification-service's cert subscriber was retired to
	// avoid double-sends).
	if natsClient != nil {
		alertSubscriber := services.NewAlertSubscriber(natsClient, alertEngine)
		if err := alertSubscriber.Start(); err != nil {
			log.Printf("⚠️  Warning: Failed to start alert subscriber: %v. Stateful alerts will not open from events.", err)
		} else {
			log.Printf("🔔 Alert subscriber started (alerts.raise/resolve + certificate.expiring)")
		}
		defer alertSubscriber.Stop()
	}

	// Wake snoozed alerts whose snooze window elapsed (evidence event appended).
	alertEngine.StartSnoozeExpirySweeper(15 * time.Minute)
	defer alertEngine.Stop()

	// Certificate ladder scan (§8.3): evaluates every tenant's certs against
	// their effective rung ladder (baseline/preference + policy rungs) every
	// 12h — raises/escalates through the alert engine and auto-resolves
	// renewed or deleted certs with an observation.
	certLadderJob := jobs.NewCertLadderScanJob(db, bypassDB, alertCatalog, alertEngine, 12*time.Hour)
	certLadderJob.Start()
	defer certLadderJob.Stop()
	log.Printf("🪜 Certificate ladder scan started (12h interval)")

	// Operational heartbeat detectors: raise a fixed high-severity alert when a
	// sensor or discovery agent stops reporting for >15m, auto-resolve when the
	// heartbeat returns. Scanned every 5m so an alert opens within ~5m of the
	// dwell window elapsing.
	sensorOfflineJob := jobs.NewSensorOfflineScanJob(db, bypassDB, alertCatalog, alertEngine, 5*time.Minute)
	sensorOfflineJob.Start()
	defer sensorOfflineJob.Stop()
	agentOfflineJob := jobs.NewDiscoveryAgentOfflineScanJob(db, bypassDB, alertCatalog, alertEngine, 5*time.Minute)
	agentOfflineJob.Start()
	defer agentOfflineJob.Stop()
	log.Printf("📡 Sensor/agent offline detectors started (5m interval, 15m dwell)")

	// Asset-limit detector: warn as a tenant's infrastructure-asset count nears
	// its plan entitlement (80% info → 95% high), auto-resolve below the rung.
	assetLimitJob := jobs.NewAssetLimitScanJob(db, bypassDB, alertCatalog, alertEngine, 1*time.Hour)
	assetLimitJob.Start()
	defer assetLimitJob.Stop()
	log.Printf("📊 Asset-limit detector started (1h interval)")

	// Compliance policy detectors over the ADR-0014 materialized state:
	// control_noncompliant (one alert per control with active findings in an
	// activated framework, severity from the control) and compliance_score_drop
	// (framework score fell >10 points vs ~24h ago). Both auto-resolve when the
	// condition clears.
	controlNoncompliantJob := jobs.NewControlNoncompliantScanJob(db, bypassDB, alertCatalog, alertEngine, 30*time.Minute)
	controlNoncompliantJob.Start()
	defer controlNoncompliantJob.Stop()
	scoreDropJob := jobs.NewComplianceScoreDropScanJob(db, bypassDB, alertCatalog, alertEngine, 1*time.Hour)
	scoreDropJob.Start()
	defer scoreDropJob.Stop()
	log.Printf("📉 Compliance policy detectors started (control-noncompliant 30m, score-drop 1h)")

	// Discovery-job-failed detector: one medium alert per failed discovery job
	// not yet superseded by a later successful run; auto-resolves when a
	// subsequent run succeeds. Polls discovery_jobs (no completion event).
	discoveryJobFailedJob := jobs.NewDiscoveryJobFailedScanJob(db, bypassDB, alertCatalog, alertEngine, 5*time.Minute)
	discoveryJobFailedJob.Start()
	defer discoveryJobFailedJob.Stop()
	log.Printf("🔎 Discovery-job-failed detector started (5m interval)")

	// Platform-track detectors: raise stateful alerts under the sentinel
	// platform tenant (services.PlatformAlertTenantID) for platform admins.
	// service_down (critical, from service_health_events) + tenant_health_degraded
	// (medium/high, from tenant_health.overall_score). Both auto-resolve on
	// recovery. delivery_failure_rate is still planned (no per-channel delivery
	// outcome source wired yet).
	serviceDownJob := jobs.NewServiceDownScanJob(db, bypassDB, alertCatalog, alertEngine, 2*time.Minute)
	serviceDownJob.Start()
	defer serviceDownJob.Stop()
	tenantHealthJob := jobs.NewTenantHealthDegradedScanJob(db, bypassDB, alertCatalog, alertEngine, 15*time.Minute)
	tenantHealthJob.Start()
	defer tenantHealthJob.Stop()
	log.Printf("🛰️  Platform-track detectors started (service-down 2m, tenant-health 15m)")

	// Alert retention: daily cleanup of resolved, non-ticket-linked alerts
	// older than ALERT_RETENTION_DAYS (default 90); ticket-linked alerts are
	// kept so their tickets never dangle. Companion to notification-log
	// retention (which couldn't safely touch this stateful table).
	alertRetentionJob := jobs.NewAlertRetentionCleanupJob(bypassDB, jobs.AlertRetentionDays(), 24*time.Hour)
	alertRetentionJob.Start()
	defer alertRetentionJob.Stop()
	log.Printf("🧹 Alert retention cleanup started (%dd, resolved + unticketed)", jobs.AlertRetentionDays())

	// Initialize and start background jobs
	jobCtx, jobCancel := context.WithCancel(context.Background())
	defer jobCancel()

	// Start stale finding cleanup job (runs every 24 hours)
	staleCleanupJob := jobs.NewStaleFindingCleanupJob(bypassDB, findingsService, 90, 7, 1000)
	go staleCleanupJob.StartPeriodic(jobCtx, 24*time.Hour)
	log.Printf("🧹 Stale finding cleanup job started (runs every 24 hours)")

	// ADR-0015: the periodic + on-boot full-tenant ReevaluationJob is REMOVED. A
	// finding only changes when its inputs change (asset state or control definition),
	// both event-driven; there is no reason to re-evaluate a tenant's whole inventory
	// on a schedule. Restart drains the durable NATS backlog and nothing else. The
	// on-boot O(assets²) sweep was the v3.1.0 OOM root cause.

	// Start ticket due date checker (runs every hour)
	go ticketService.StartDueDateChecker(jobCtx)
	log.Printf("🎫 Ticket due date checker started (runs every hour)")

	// Start remediation plan overdue checker (runs every hour)
	go planService.StartOverdueChecker(jobCtx)
	log.Printf("📋 Remediation plan overdue checker started (runs every hour)")

	// Health check server (HTTP, port 8080)
	healthRouter := gin.New()
	healthRouter.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "compliance-engine",
			"version": version.Get(),
		})
	})

	healthServer := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           healthRouter,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// API server (HTTPS with mTLS, port 8443)
	var apiServer *http.Server
	if cfg.UseMTLS {
		apiServer, err = sharedhttp.NewMTLSServer(
			cfg.ServiceCertPath,
			cfg.ServiceKeyPath,
			cfg.PlatformCACertPath,
			router,
		)
		if err != nil {
			log.Fatalf("Failed to create mTLS server: %v", err)
		}
		apiServer.Addr = ":" + cfg.TLSPort
		apiServer.ReadHeaderTimeout = 5 * time.Second
		apiServer.ReadTimeout = 10 * time.Second
		apiServer.WriteTimeout = 15 * time.Second
		apiServer.IdleTimeout = 60 * time.Second
	} else {
		// Fallback to HTTP if mTLS disabled
		apiServer = &http.Server{
			Addr:              ":" + cfg.Port,
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
			log.Printf("Health check server starting on port %s", cfg.Port)
			if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start health server: %v", err)
			}
		}()
	}

	// Start API server
	go func() {
		if cfg.UseMTLS {
			log.Printf("🚀 Compliance Engine API server starting on port %s (mTLS)", cfg.TLSPort)
			log.Printf("📋 Ready to enforce compliance standards")
			if err := apiServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		} else {
			log.Printf("🚀 Compliance Engine API server starting on port %s (HTTP fallback)", cfg.Port)
			log.Printf("📋 Ready to enforce compliance standards")
			if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down compliance-engine...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop background jobs
	log.Println("Stopping background jobs...")
	jobCancel()

	// Gracefully shutdown event subscriber first
	if eventSubscriber != nil {
		log.Println("Stopping event subscriber...")
		if err := eventSubscriber.GracefulShutdown(ctx); err != nil {
			log.Printf("Error during event subscriber shutdown: %v", err)
		}
	}

	// Shutdown both servers
	if err := healthServer.Shutdown(ctx); err != nil {
		log.Printf("Health server forced to shutdown: %v", err)
	}
	if err := apiServer.Shutdown(ctx); err != nil {
		log.Printf("API server forced to shutdown: %v", err)
	}

	log.Println("compliance-engine stopped")
}
