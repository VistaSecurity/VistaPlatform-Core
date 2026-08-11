package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/config"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/jobs"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	"github.com/vistasecurity/vistaplatform/shared/events"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	resourcetracking "github.com/vistasecurity/vistaplatform/shared/middleware/resource-tracking"
	trial_lock "github.com/vistasecurity/vistaplatform/shared/middleware/trial_lock"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
	"github.com/vistasecurity/vistaplatform/shared/version"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	// Load configuration
	cfg := config.Load()

	log.Printf("inventory-service edition: %s", edition())

	// Connect to database
	db, err := database.NewConnection(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Initialize services
	assetService := services.NewAssetService(db)
	networkSpaceService := services.NewNetworkSpaceService(db)
	locationService := services.NewLocationService(db)
	networkSegmentService := services.NewNetworkSegmentService(db, locationService)
	serviceIdentificationService := services.NewServiceIdentificationService(db)
	assetService.SetEnrichmentServices(networkSegmentService, serviceIdentificationService)
	lifecycleService := services.NewAssetLifecycleService(db)
	discoveryService, err := services.NewDiscoveryService(cfg)
	if err != nil {
		log.Fatalf("Failed to create discovery service: %v", err)
	}
	revalidationService := services.NewRevalidationService(db, discoveryService, assetService, lifecycleService)
	eventPublisher, _ := services.NewEventPublisherService()
	certificateService := services.NewCertificateService(db, eventPublisher)
	algorithmService := services.NewAlgorithmService(db)
	unifiedInventoryService := services.NewUnifiedInventoryService(db)
	cryptoImplService := services.NewCryptoImplementationService(db)
	cryptoRisksService := services.NewCryptoRisksService(db)
	remediationService := services.NewRemediationService(db, algorithmService)

	// Initialize handlers
	assetHandler := handlers.NewAssetHandler(assetService, db)
	assetApprovalHandler := handlers.NewAssetApprovalHandler(assetService)
	discoveryHandler := handlers.NewDiscoveryHandler(assetService, discoveryService)
	discoveryHandler.SetDB(db)
	cryptoAssetsHandler := handlers.NewCryptoAssetsHandler(assetService)
	integrationsHandler := handlers.NewIntegrationsHandler(assetService)
	networkSpaceHandler := handlers.NewNetworkSpaceHandler(networkSpaceService)
	networkSpaceHandler.SetNetworkSegmentService(networkSegmentService)
	assetLifecycleHandler := handlers.NewAssetLifecycleHandler(lifecycleService, revalidationService, assetService)
	certificateHandler := handlers.NewCertificateHandler(certificateService)
	algorithmHandler := handlers.NewAlgorithmHandler(algorithmService)
	unifiedInventoryHandler := handlers.NewUnifiedInventoryHandler(unifiedInventoryService)
	cryptoImplHandler := handlers.NewCryptoImplementationHandler(cryptoImplService)
	cryptoRisksHandler := handlers.NewCryptoRisksHandlers(cryptoRisksService)
	remediationHandler := handlers.NewRemediationHandler(remediationService)
	externalConnectionsService := services.NewExternalConnectionsService(db, algorithmService)
	externalConnectionsService.SetServiceIdentificationService(serviceIdentificationService)
	assetService.SetExternalConnectionsService(externalConnectionsService)
	externalConnectionsHandler := handlers.NewExternalConnectionsHandler(externalConnectionsService)
	locationHandler := handlers.NewLocationHandler(locationService)
	networkSegmentHandler := handlers.NewNetworkSegmentHandler(networkSegmentService)
	operationalService := services.NewOperationalService(db)
	remediationTemplateService := services.NewRemediationTemplateService()
	operationalHandler := handlers.NewOperationalHandler(operationalService, remediationTemplateService)

	// Setup Gin router
	r := gin.Default()
	r.Use(sharedmw.SecurityHeaders())

	// CORS middleware - allow requests from frontend origins
	// This is needed when requests bypass Traefik API gateway (e.g., direct service access)
	// In production, CORS_ORIGINS env var should be set to allowed domains
	corsConfig := cors.DefaultConfig()
	corsOrigins := os.Getenv("CORS_ORIGINS")
	if corsOrigins != "" {
		corsConfig.AllowOrigins = strings.Split(corsOrigins, ",")
	} else {
		// Default for local development
		corsConfig.AllowOrigins = []string{
			"http://localhost:3000",
			"http://localhost:3005",
			"http://localhost:3006",
			"http://localhost:5173",
			"http://localhost:5174",
		}
	}
	corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	corsConfig.AllowHeaders = []string{"Origin", "Content-Type", "Authorization", "X-Requested-With", "X-Impersonate-Tenant", "X-Tenant-ID", "X-User-ID", "Accept"}
	corsConfig.AllowCredentials = true
	corsConfig.ExposeHeaders = []string{"Content-Length", "Content-Type"}
	r.Use(cors.New(corsConfig))

	// Resource tracking middleware
	trackerConfig := resourcetracking.DefaultConfig()
	trackerConfig.ServiceName = "inventory-service"
	trackerConfig.TrackerURL = os.Getenv("RESOURCE_TRACKER_URL")
	if trackerConfig.TrackerURL == "" {
		trackerConfig.TrackerURL = sharedconfig.PeerURL("resource-tracker-service", sharedconfig.MTLSEnabled())
	}
	// mTLS configuration
	trackerConfig.UseMTLS = cfg.UseMTLS
	trackerConfig.ClientCertPath = cfg.ClientCertPath
	trackerConfig.ClientKeyPath = cfg.ClientKeyPath
	trackerConfig.PlatformCACertPath = cfg.PlatformCACertPath
	r.Use(resourcetracking.Middleware(trackerConfig))

	// Audit logging middleware
	auditConfig := auditmiddleware.DefaultConfig()
	auditConfig.ServiceName = "inventory-service"
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

	// Store audit middleware in a way handlers can access it
	// We'll use a middleware to set it in context
	r.Use(func(c *gin.Context) {
		c.Set("audit_middleware", auditMiddleware)
		c.Next()
	})
	r.Use(auditMiddleware.LogRequest())

	// Health check endpoint (no auth required)
	r.GET("/health", assetHandler.Health)

	// Raw *sql.DB reference for RBAC middleware. The inventory-service's
	// database.DB wraps *sqlx.DB which embeds *sql.DB; sharedrbac.RequireTenantPermission
	// needs the raw *sql.DB.
	rawDB := db.DB.DB

	// API routes with JWT middleware
	// Apply middleware to all routes under /api/v1
	api := r.Group("/api/v1")
	api.Use(handlers.JWTMiddleware(cfg, db))
	// Trial lock middleware — gates writes when the calling tenant has
	// hard-locked. Reads and the billing/auth allow-list pass through.
	// Unauthenticated traffic (no tenant in context) is also passed.
	api.Use(trial_lock.Middleware(rawDB, nil))
	// RLS: Tenant isolation uses WHERE tenant_id=$X in queries (primary) and PostgreSQL
	// RLS policies (defense-in-depth). For RLS session-variable enforcement, use
	// shared/database.WithTenantContext() at the repository level — never db.Exec().
	{
		// Inventory service endpoints under service namespace (gateway-visible)
		// IMPORTANT: Register specific routes BEFORE dynamic routes to avoid conflicts
		// Reads are JWT-scoped (tenant_id baked into query); writes are
		// permission-gated below via sharedrbac.RequireTenantPermission.
		api.GET("/inventory-service/assets", assetHandler.GetAssets)
		api.POST("/inventory-service/assets", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsCreate), assetHandler.CreateAsset)
		api.POST("/inventory-service/assets/bulk", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsCreate), assetHandler.CreateAssetsBulk)
		api.GET("/inventory-service/assets/search", assetHandler.SearchAssets)
		api.GET("/inventory-service/assets/facets", assetHandler.GetAssetFacets)             // Before /:id
		api.GET("/inventory-service/assets/stats", assetHandler.GetAssetStats)               // Before /:id to avoid route conflict
		api.GET("/inventory-service/assets/recent-count", assetHandler.GetRecentAssetsCount) // Before /:id to avoid route conflict
		// Approval routes must come before /:id route to avoid route conflicts
		log.Printf("[ROUTE] Registering POST /api/v1/inventory-service/assets/approve")
		api.POST("/inventory-service/assets/approve", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), assetApprovalHandler.ApproveAssets)
		log.Printf("[ROUTE] Registering POST /api/v1/inventory-service/assets/deny")
		api.POST("/inventory-service/assets/deny", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), assetApprovalHandler.DenyAssets)
		api.GET("/inventory-service/assets/:id", assetHandler.GetAssetByID)
		api.PUT("/inventory-service/assets/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), assetHandler.UpdateAsset)
		api.DELETE("/inventory-service/assets/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsDelete), assetHandler.DeleteAsset)
		api.POST("/inventory-service/assets/:id/restore", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), assetHandler.RestoreAsset)
		api.GET("/inventory-service/assets/:id/crypto", assetHandler.GetAssetCrypto)
		api.GET("/inventory-service/assets/:id/history", assetHandler.GetAssetHistory)
		api.GET("/inventory-service/risk/summary", assetHandler.GetRiskSummary)
		api.GET("/inventory-service/risk/posture/trend", assetHandler.GetPostureTrend)
		api.GET("/inventory-service/pqc/summary", assetHandler.GetPQCReadinessSummary)
		// External connections (3rd party public internet connections observed by sensors).
		// Treated as assets for permission purposes — an upsert is create-or-update.
		api.POST("/inventory-service/external-connections", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsCreate), externalConnectionsHandler.UpsertExternalConnection)
		api.GET("/inventory-service/external-connections", externalConnectionsHandler.ListExternalConnections)
		api.GET("/inventory-service/external-connections/summary", externalConnectionsHandler.GetExternalConnectionsSummary)
		api.GET("/inventory-service/external-connections/:id", externalConnectionsHandler.GetExternalConnection)
		api.GET("/inventory-service/external-connections/:id/history", externalConnectionsHandler.GetExternalConnectionHistory)
		api.DELETE("/inventory-service/external-connections/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsDelete), externalConnectionsHandler.DeleteExternalConnection)
		// Elevate a 3rd-party connection to a managed/monitored asset. Served by the asset handler (it owns asset creation + cert materialization).
		api.POST("/inventory-service/external-connections/:id/elevate", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), assetHandler.ElevateExternalConnection)
		// Tenant activity endpoints - For tenant health service
		api.GET("/inventory-service/tenant/:id/activity-summary", assetHandler.GetTenantActivitySummary)
		// Certificate endpoints
		api.GET("/inventory-service/certificates", certificateHandler.GetCertificates)
		api.GET("/inventory-service/certificates/expiring", certificateHandler.GetExpiringCertificates)
		api.GET("/inventory-service/certificates/search", certificateHandler.SearchCertificates)
		api.GET("/inventory-service/certificates/by-issuer/:issuer", certificateHandler.GetCertificatesByIssuer)
		api.POST("/inventory-service/certificates", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsManage), certificateHandler.CreateCertificate)
		api.POST("/inventory-service/certificates/upload", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsManage), certificateHandler.UploadCertificate)
		api.POST("/inventory-service/certificates/rebuild-all-chains", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsManage), certificateHandler.RebuildAllCertificateChains)
		api.GET("/inventory-service/certificates/:id", certificateHandler.GetCertificateByID)
		api.GET("/inventory-service/certificates/:id/chain", certificateHandler.GetCertificateChain)
		api.GET("/inventory-service/certificates/:id/history", certificateHandler.GetCertificateHistory)
		api.PUT("/inventory-service/certificates/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), certificateHandler.UpdateCertificate)
		api.POST("/inventory-service/certificates/:id/rebuild-chain", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), certificateHandler.RebuildCertificateChain)
		// Algorithm endpoints
		api.GET("/inventory-service/algorithms", algorithmHandler.ListAlgorithms)
		api.GET("/inventory-service/algorithms/pqc", algorithmHandler.GetPQCAlgorithms)
		api.GET("/inventory-service/algorithms/non-pqc", algorithmHandler.GetNonPQCAlgorithms)
		api.GET("/inventory-service/algorithms/pqc/standardized", algorithmHandler.GetStandardizedPQCAlgorithms)
		api.GET("/inventory-service/algorithms/:code", algorithmHandler.GetAlgorithmByCode)
		api.GET("/inventory-service/algorithms/:code/recommendations", algorithmHandler.GetAlgorithmRecommendations)
		api.GET("/inventory-service/algorithms/:code/usage", algorithmHandler.GetAlgorithmUsage)
		api.POST("/inventory-service/algorithms/recommendations/batch", algorithmHandler.GetBatchRecommendations)
		// Algorithm source-of-truth edits (ADR-0003 Phase 1): create/edit/deprecate
		// rows in the global crypto rating catalog. Gated on the seeded
		// algorithms.manage platform permission and audited.
		api.POST("/inventory-service/algorithms", sharedrbac.RequirePlatformPermission(rawDB, rbac.PermissionAlgorithmsManage), algorithmHandler.CreateAlgorithm)
		api.PUT("/inventory-service/algorithms/:code", sharedrbac.RequirePlatformPermission(rawDB, rbac.PermissionAlgorithmsManage), algorithmHandler.UpdateAlgorithm)
		// PQC migration progress
		api.GET("/inventory-service/pqc/progress", algorithmHandler.GetPQCProgress)
		// Unified inventory endpoint
		api.GET("/inventory-service/crypto-inventory", unifiedInventoryHandler.GetUnifiedInventory)
		// Crypto configurations endpoints
		api.GET("/inventory-service/crypto-implementations", cryptoImplHandler.GetCryptoImplementations)
		api.GET("/inventory-service/crypto-implementations/:id", cryptoImplHandler.GetCryptoImplementationByID)
		api.GET("/inventory-service/crypto-implementations/:id/remediation", remediationHandler.GetRemediationForCryptoImplementation)
		// Crypto risks endpoints
		api.GET("/inventory-service/crypto-risks/summary", cryptoRisksHandler.GetSummary)
		api.GET("/inventory-service/crypto-risks/export", cryptoRisksHandler.ExportRisks)
		api.GET("/inventory-service/crypto-risks", cryptoRisksHandler.ListRisks)
		api.GET("/inventory-service/crypto-risks/:id", cryptoRisksHandler.GetRisk)
		// Remediation guidance endpoints
		api.GET("/inventory-service/remediation/algorithm/:code", remediationHandler.GetRemediationByAlgorithm)
		// Crypto assets
		api.GET("/inventory-service/keys", cryptoAssetsHandler.ListKeys)
		api.GET("/inventory-service/keys/:id", cryptoAssetsHandler.GetKeyByID)
		api.GET("/inventory-service/keys/:id/implementations", cryptoAssetsHandler.GetKeyImplementations)
		api.GET("/inventory-service/libraries", cryptoAssetsHandler.ListLibraries)
		api.GET("/inventory-service/mappings", cryptoAssetsHandler.GetMappings)
		api.POST("/inventory-service/crypto/:id/attach-library", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), cryptoAssetsHandler.AttachLibrary)
		api.POST("/inventory-service/crypto/:id/attach-key", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), cryptoAssetsHandler.AttachKey)
		api.POST("/inventory-service/libraries", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsCreate), cryptoAssetsHandler.CreateLibrary)
		// Tenant integrations. No `integrations.*` permission exists in
		// tenant_permissions today; mapped to assets.{create,update,delete}
		// since integrations are an asset-acquisition mechanism. Revisit
		// if a dedicated integrations permission family is added.
		api.GET("/inventory-service/integrations", integrationsHandler.List)
		api.POST("/inventory-service/integrations", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsCreate), integrationsHandler.Create)
		api.PUT("/inventory-service/integrations/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), integrationsHandler.Update)
		api.DELETE("/inventory-service/integrations/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsDelete), integrationsHandler.Delete)
		// Network spaces — subnet → location mapping is tenant config.
		api.GET("/inventory-service/network-spaces", networkSpaceHandler.GetNetworkSpaces)
		api.POST("/inventory-service/network-spaces", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionSettingsUpdate), networkSpaceHandler.SaveNetworkSpaces)
		api.POST("/inventory-service/network-spaces/classify-assets", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsManage), networkSpaceHandler.ReclassifyAssets)

		// Discovery endpoints
		api.GET("/inventory-service/discovery/capabilities", discoveryHandler.GetCapabilities)
		api.PUT("/inventory-service/discovery/capabilities", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDiscoveryManage), discoveryHandler.UpdateCapabilities)
		api.POST("/inventory-service/discovery/jobs", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDiscoveryCreate), discoveryHandler.CreateJob)
		api.GET("/inventory-service/discovery/jobs/:id", discoveryHandler.GetJob)
		api.GET("/inventory-service/discovery/jobs/:id/results", discoveryHandler.GetJobResults)
		api.POST("/inventory-service/discovery/jobs/:id/import", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDiscoveryCreate), discoveryHandler.ImportJobResults)
		api.POST("/inventory-service/discovery/jobs/:id/cancel", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDiscoveryUpdate), discoveryHandler.CancelJob)
		api.POST("/inventory-service/discovery/jobs/:id/rerun", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDiscoveryCreate), discoveryHandler.RerunJob)

		// Direct routes without service prefix (for backward compatibility).
		// Same permission-gating policy as the /inventory-service/* block above.
		// IMPORTANT: Register specific routes BEFORE dynamic routes to avoid conflicts
		api.GET("/assets", assetHandler.GetAssets)
		api.POST("/assets", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsCreate), assetHandler.CreateAsset)
		api.GET("/assets/search", assetHandler.SearchAssets)
		api.GET("/assets/facets", assetHandler.GetAssetFacets) // Before /:id
		// Approval routes must come before /:id route to avoid route conflicts
		log.Printf("[ROUTE] Registering POST /api/v1/assets/approve")
		api.POST("/assets/approve", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), assetApprovalHandler.ApproveAssets)
		log.Printf("[ROUTE] Registering POST /api/v1/assets/deny")
		api.POST("/assets/deny", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), assetApprovalHandler.DenyAssets)
		api.GET("/assets/:id", assetHandler.GetAssetByID)
		api.PUT("/assets/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), assetHandler.UpdateAsset)
		api.DELETE("/assets/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsDelete), assetHandler.DeleteAsset)
		api.POST("/assets/:id/restore", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), assetHandler.RestoreAsset)
		api.GET("/assets/:id/crypto", assetHandler.GetAssetCrypto)
		api.GET("/assets/:id/history", assetHandler.GetAssetHistory)
		api.GET("/risk/summary", assetHandler.GetRiskSummary)
		api.GET("/risk/posture/trend", assetHandler.GetPostureTrend)
		// Direct crypto
		api.GET("/keys", cryptoAssetsHandler.ListKeys)
		api.GET("/keys/:id", cryptoAssetsHandler.GetKeyByID)
		api.GET("/keys/:id/implementations", cryptoAssetsHandler.GetKeyImplementations)
		api.GET("/libraries", cryptoAssetsHandler.ListLibraries)
		api.GET("/mappings", cryptoAssetsHandler.GetMappings)
		api.POST("/crypto/:id/attach-library", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), cryptoAssetsHandler.AttachLibrary)
		api.POST("/crypto/:id/attach-key", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), cryptoAssetsHandler.AttachKey)
		api.POST("/libraries", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsCreate), cryptoAssetsHandler.CreateLibrary)
		// Direct integrations
		api.GET("/integrations", integrationsHandler.List)
		api.POST("/integrations", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsCreate), integrationsHandler.Create)
		api.PUT("/integrations/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), integrationsHandler.Update)
		api.DELETE("/integrations/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsDelete), integrationsHandler.Delete)
		// Direct network spaces
		api.GET("/network-spaces", networkSpaceHandler.GetNetworkSpaces)
		api.POST("/network-spaces", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionSettingsUpdate), networkSpaceHandler.SaveNetworkSpaces)
		api.POST("/network-spaces/classify-assets", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsManage), networkSpaceHandler.ReclassifyAssets)

		// Discovery direct routes
		// Register OPTIONS handlers for CORS preflight
		// IMPORTANT: More specific routes must come before less specific ones
		api.GET("/discovery/capabilities", discoveryHandler.GetCapabilities)
		api.PUT("/discovery/capabilities", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDiscoveryManage), discoveryHandler.UpdateCapabilities)
		api.OPTIONS("/discovery/jobs", func(c *gin.Context) { c.Status(http.StatusNoContent) })
		api.POST("/discovery/jobs", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDiscoveryCreate), discoveryHandler.CreateJob)
		// Specific routes first (with /results, /import, etc.)
		api.GET("/discovery/jobs/:id/results", discoveryHandler.GetJobResults)
		api.OPTIONS("/discovery/jobs/:id/import", func(c *gin.Context) { c.Status(http.StatusNoContent) })
		api.POST("/discovery/jobs/:id/import", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDiscoveryCreate), discoveryHandler.ImportJobResults)
		api.OPTIONS("/discovery/jobs/:id/cancel", func(c *gin.Context) { c.Status(http.StatusNoContent) })
		api.POST("/discovery/jobs/:id/cancel", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDiscoveryUpdate), discoveryHandler.CancelJob)
		api.OPTIONS("/discovery/jobs/:id/rerun", func(c *gin.Context) { c.Status(http.StatusNoContent) })
		api.POST("/discovery/jobs/:id/rerun", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDiscoveryCreate), discoveryHandler.RerunJob)
		// General route last
		api.OPTIONS("/discovery/jobs/:id", func(c *gin.Context) { c.Status(http.StatusNoContent) })
		api.GET("/discovery/jobs/:id", discoveryHandler.GetJob)

		// Asset lifecycle endpoints
		api.GET("/inventory-service/assets/stale", assetLifecycleHandler.GetStaleAssets)
		api.POST("/inventory-service/assets/stale/rescan", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), assetLifecycleHandler.RescanAssets)
		api.POST("/inventory-service/assets/stale/archive", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), assetLifecycleHandler.ArchiveAssets)
		api.POST("/inventory-service/assets/revalidate", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), assetLifecycleHandler.RevalidateAssets)
		// Active Scan (): on-demand crypto scan of selected assets.
		api.POST("/inventory-service/assets/scan", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), assetLifecycleHandler.ScanAssets)
		api.GET("/inventory-service/lifecycle/policy", assetLifecycleHandler.GetPolicy)
		api.PUT("/inventory-service/lifecycle/policy", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionSettingsUpdate), assetLifecycleHandler.UpdatePolicy)

		// Hard delete (admin-only)
		api.DELETE("/inventory-service/assets/:id/hard", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsManage), assetHandler.HardDeleteAsset)
	}

	// =================================================================
	// API v2 - CMDB-aligned terminology
	// =================================================================
	// v2 endpoints use industry-standard CMDB terminology:
	//   "assets" -> "infrastructure-assets"
	//   "crypto-implementations" -> "crypto-configurations"
	// Same handlers, same logic - only the route paths change.
	// v1 endpoints remain functional for backward compatibility.
	// =================================================================
	apiv2 := r.Group("/api/v2")
	apiv2.Use(handlers.JWTMiddleware(cfg, db))
	// RLS: Tenant isolation uses WHERE tenant_id=$X in queries (primary) and PostgreSQL
	// RLS policies (defense-in-depth). For RLS session-variable enforcement, use
	// shared/database.WithTenantContext() at the repository level — never db.Exec().
	{
		// Infrastructure Assets (CMDB: Configuration Items - Servers/Endpoints/Services)
		// Reads JWT-scoped; writes permission-gated.
		apiv2.GET("/inventory-service/infrastructure-assets", assetHandler.GetAssets)
		apiv2.POST("/inventory-service/infrastructure-assets", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsCreate), assetHandler.CreateAsset)
		apiv2.POST("/inventory-service/infrastructure-assets/bulk", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsCreate), assetHandler.CreateAssetsBulk)
		apiv2.GET("/inventory-service/infrastructure-assets/search", assetHandler.SearchAssets)
		apiv2.GET("/inventory-service/infrastructure-assets/facets", assetHandler.GetAssetFacets)
		apiv2.GET("/inventory-service/infrastructure-assets/stats", assetHandler.GetAssetStats)
		apiv2.GET("/inventory-service/infrastructure-assets/recent-count", assetHandler.GetRecentAssetsCount)
		apiv2.POST("/inventory-service/infrastructure-assets/approve", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), assetApprovalHandler.ApproveAssets)
		apiv2.POST("/inventory-service/infrastructure-assets/deny", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), assetApprovalHandler.DenyAssets)
		apiv2.GET("/inventory-service/infrastructure-assets/stale", assetLifecycleHandler.GetStaleAssets)
		apiv2.POST("/inventory-service/infrastructure-assets/stale/rescan", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), assetLifecycleHandler.RescanAssets)
		apiv2.POST("/inventory-service/infrastructure-assets/stale/archive", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), assetLifecycleHandler.ArchiveAssets)
		apiv2.POST("/inventory-service/infrastructure-assets/revalidate", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), assetLifecycleHandler.RevalidateAssets)
		// Active Scan (): on-demand crypto scan of selected assets.
		apiv2.POST("/inventory-service/infrastructure-assets/scan", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), assetLifecycleHandler.ScanAssets)
		apiv2.POST("/inventory-service/infrastructure-assets/enrich-all", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsManage), assetHandler.EnrichAllAssets)
		apiv2.PUT("/inventory-service/infrastructure-assets/:id/service", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), assetHandler.UpdateAssetService)
		apiv2.GET("/inventory-service/infrastructure-assets/:id", assetHandler.GetAssetByID)
		apiv2.PUT("/inventory-service/infrastructure-assets/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), assetHandler.UpdateAsset)
		apiv2.DELETE("/inventory-service/infrastructure-assets/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsDelete), assetHandler.DeleteAsset)
		apiv2.POST("/inventory-service/infrastructure-assets/:id/restore", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), assetHandler.RestoreAsset)
		apiv2.GET("/inventory-service/infrastructure-assets/:id/crypto", assetHandler.GetAssetCrypto)
		apiv2.GET("/inventory-service/infrastructure-assets/:id/certificates", certificateHandler.GetCertificatesByAsset)
		apiv2.GET("/inventory-service/infrastructure-assets/:id/history", assetHandler.GetAssetHistory)
		// Hard delete is destructive and irrecoverable — require assets.manage,
		// not just assets.delete, to mark it as elevated.
		apiv2.DELETE("/inventory-service/infrastructure-assets/:id/hard", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsManage), assetHandler.HardDeleteAsset)

		// Risk summary
		apiv2.GET("/inventory-service/risk/summary", assetHandler.GetRiskSummary)
		apiv2.GET("/inventory-service/risk/posture/trend", assetHandler.GetPostureTrend)
		apiv2.GET("/inventory-service/pqc/summary", assetHandler.GetPQCReadinessSummary)
		apiv2.GET("/inventory-service/pqc/progress", algorithmHandler.GetPQCProgress)

		// External connections (3rd party public internet connections observed by sensors)
		apiv2.POST("/inventory-service/external-connections", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsCreate), externalConnectionsHandler.UpsertExternalConnection)
		apiv2.GET("/inventory-service/external-connections", externalConnectionsHandler.ListExternalConnections)
		apiv2.GET("/inventory-service/external-connections/summary", externalConnectionsHandler.GetExternalConnectionsSummary)
		apiv2.GET("/inventory-service/external-connections/:id", externalConnectionsHandler.GetExternalConnection)
		apiv2.GET("/inventory-service/external-connections/:id/history", externalConnectionsHandler.GetExternalConnectionHistory)
		apiv2.DELETE("/inventory-service/external-connections/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsDelete), externalConnectionsHandler.DeleteExternalConnection)
		// Elevate a 3rd-party connection to a managed/monitored asset. Served by the asset handler (it owns asset creation + cert materialization).
		apiv2.POST("/inventory-service/external-connections/:id/elevate", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), assetHandler.ElevateExternalConnection)

		// Certificates (CMDB: cmdb_ci_certificate)
		apiv2.GET("/inventory-service/certificates", certificateHandler.GetCertificates)
		apiv2.GET("/inventory-service/certificates/expiring", certificateHandler.GetExpiringCertificates)
		apiv2.GET("/inventory-service/certificates/search", certificateHandler.SearchCertificates)
		apiv2.GET("/inventory-service/certificates/by-issuer/:issuer", certificateHandler.GetCertificatesByIssuer)
		apiv2.POST("/inventory-service/certificates", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsManage), certificateHandler.CreateCertificate)
		apiv2.POST("/inventory-service/certificates/upload", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsManage), certificateHandler.UploadCertificate)
		apiv2.POST("/inventory-service/certificates/rebuild-all-chains", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsManage), certificateHandler.RebuildAllCertificateChains)
		apiv2.GET("/inventory-service/certificates/:id", certificateHandler.GetCertificateByID)
		apiv2.GET("/inventory-service/certificates/:id/chain", certificateHandler.GetCertificateChain)
		apiv2.GET("/inventory-service/certificates/:id/history", certificateHandler.GetCertificateHistory)
		apiv2.PUT("/inventory-service/certificates/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), certificateHandler.UpdateCertificate)
		apiv2.POST("/inventory-service/certificates/:id/rebuild-chain", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), certificateHandler.RebuildCertificateChain)

		// Algorithms
		apiv2.GET("/inventory-service/algorithms", algorithmHandler.ListAlgorithms)
		apiv2.GET("/inventory-service/algorithms/pqc", algorithmHandler.GetPQCAlgorithms)
		apiv2.GET("/inventory-service/algorithms/non-pqc", algorithmHandler.GetNonPQCAlgorithms)
		apiv2.GET("/inventory-service/algorithms/pqc/standardized", algorithmHandler.GetStandardizedPQCAlgorithms)
		apiv2.GET("/inventory-service/algorithms/:code", algorithmHandler.GetAlgorithmByCode)
		apiv2.GET("/inventory-service/algorithms/:code/recommendations", algorithmHandler.GetAlgorithmRecommendations)
		apiv2.GET("/inventory-service/algorithms/:code/usage", algorithmHandler.GetAlgorithmUsage)
		apiv2.POST("/inventory-service/algorithms/recommendations/batch", algorithmHandler.GetBatchRecommendations)
		// Algorithm source-of-truth edits (ADR-0003 Phase 1): create/edit/deprecate
		// rows in the global crypto rating catalog. Gated on the seeded
		// algorithms.manage platform permission and audited.
		apiv2.POST("/inventory-service/algorithms", sharedrbac.RequirePlatformPermission(rawDB, rbac.PermissionAlgorithmsManage), algorithmHandler.CreateAlgorithm)
		apiv2.PUT("/inventory-service/algorithms/:code", sharedrbac.RequirePlatformPermission(rawDB, rbac.PermissionAlgorithmsManage), algorithmHandler.UpdateAlgorithm)

		// Unified inventory
		apiv2.GET("/inventory-service/crypto-inventory", unifiedInventoryHandler.GetUnifiedInventory)

		// Crypto Configurations (CMDB-aligned, replaces crypto-implementations)
		apiv2.GET("/inventory-service/crypto-configurations", cryptoImplHandler.GetCryptoImplementations)
		apiv2.GET("/inventory-service/crypto-configurations/:id", cryptoImplHandler.GetCryptoImplementationByID)
		apiv2.GET("/inventory-service/crypto-configurations/:id/remediation", remediationHandler.GetRemediationForCryptoImplementation)

		// Asset↔Certificate relationship edges (for visualizers and any feature
		// that needs precise per-asset cert linkage without hydrating
		// crypto_implementations on the asset list response).
		apiv2.GET("/inventory-service/asset-certificate-links", cryptoImplHandler.GetAssetCertificateLinks)

		// Crypto Risks
		apiv2.GET("/inventory-service/crypto-risks/summary", cryptoRisksHandler.GetSummary)
		apiv2.GET("/inventory-service/crypto-risks/export", cryptoRisksHandler.ExportRisks)
		apiv2.GET("/inventory-service/crypto-risks", cryptoRisksHandler.ListRisks)
		apiv2.GET("/inventory-service/crypto-risks/:id", cryptoRisksHandler.GetRisk)

		// Remediation guidance
		apiv2.GET("/inventory-service/remediation/algorithm/:code", remediationHandler.GetRemediationByAlgorithm)

		// Keys and Libraries (CMDB: cmdb_ci_credential / crypto components)
		apiv2.GET("/inventory-service/keys", cryptoAssetsHandler.ListKeys)
		apiv2.GET("/inventory-service/keys/:id", cryptoAssetsHandler.GetKeyByID)
		apiv2.GET("/inventory-service/keys/:id/implementations", cryptoAssetsHandler.GetKeyImplementations)
		apiv2.GET("/inventory-service/libraries", cryptoAssetsHandler.ListLibraries)
		apiv2.GET("/inventory-service/mappings", cryptoAssetsHandler.GetMappings)
		apiv2.POST("/inventory-service/crypto/:id/attach-library", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), cryptoAssetsHandler.AttachLibrary)
		apiv2.POST("/inventory-service/crypto/:id/attach-key", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), cryptoAssetsHandler.AttachKey)
		apiv2.POST("/inventory-service/libraries", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsCreate), cryptoAssetsHandler.CreateLibrary)

		// Tenant integrations — see note above the v1 block.
		apiv2.GET("/inventory-service/integrations", integrationsHandler.List)
		apiv2.POST("/inventory-service/integrations", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsCreate), integrationsHandler.Create)
		apiv2.PUT("/inventory-service/integrations/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), integrationsHandler.Update)
		apiv2.DELETE("/inventory-service/integrations/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsDelete), integrationsHandler.Delete)

		// Network spaces — tenant config.
		apiv2.GET("/inventory-service/network-spaces", networkSpaceHandler.GetNetworkSpaces)
		apiv2.POST("/inventory-service/network-spaces", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionSettingsUpdate), networkSpaceHandler.SaveNetworkSpaces)
		apiv2.POST("/inventory-service/network-spaces/classify-assets", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsManage), networkSpaceHandler.ReclassifyAssets)

		// Locations (operational context) — tenant config; treated as settings.
		apiv2.GET("/inventory-service/locations", locationHandler.GetLocations)
		apiv2.GET("/inventory-service/locations/tree", locationHandler.GetLocationTree)
		apiv2.POST("/inventory-service/locations", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionSettingsUpdate), locationHandler.CreateLocation)
		apiv2.GET("/inventory-service/locations/:id", locationHandler.GetLocation)
		apiv2.PUT("/inventory-service/locations/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionSettingsUpdate), locationHandler.UpdateLocation)
		apiv2.DELETE("/inventory-service/locations/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionSettingsUpdate), locationHandler.DeleteLocation)
		apiv2.GET("/inventory-service/locations/:id/assets", locationHandler.GetLocationAssets)
		apiv2.GET("/inventory-service/locations/:id/summary", locationHandler.GetLocationSummary)

		// Network segments (operational context) — tenant config.
		apiv2.GET("/inventory-service/network-segments", networkSegmentHandler.GetNetworkSegments)
		apiv2.POST("/inventory-service/network-segments", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionSettingsUpdate), networkSegmentHandler.CreateNetworkSegment)
		apiv2.POST("/inventory-service/network-segments/classify-asset", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsManage), networkSegmentHandler.ClassifyAsset)
		apiv2.POST("/inventory-service/network-segments/bulk", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionSettingsUpdate), networkSegmentHandler.CreateNetworkSegmentsBulk)
		apiv2.POST("/inventory-service/network-segments/reclassify-all", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsManage), networkSegmentHandler.ReclassifyAllAssets)
		apiv2.POST("/inventory-service/network-segments/migrate-from-spaces", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionSettingsUpdate), networkSegmentHandler.MigrateFromNetworkSpaces)
		apiv2.GET("/inventory-service/network-segments/:id", networkSegmentHandler.GetNetworkSegment)
		apiv2.PUT("/inventory-service/network-segments/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionSettingsUpdate), networkSegmentHandler.UpdateNetworkSegment)
		apiv2.DELETE("/inventory-service/network-segments/:id", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionSettingsUpdate), networkSegmentHandler.DeleteNetworkSegment)

		// Operational overview and remediation queue (materialized views).
		// Ticket CRUD lives in compliance-engine under
		// /api/v1/compliance-engine/tickets, not here.
		apiv2.GET("/inventory-service/operational/locations-summary", operationalHandler.GetLocationsSummary)
		apiv2.GET("/inventory-service/operational/locations/:id/environments", operationalHandler.GetLocationEnvironments)
		apiv2.GET("/inventory-service/operational/locations/:id/environments/:env/assets", operationalHandler.GetEnvironmentAssets)
		apiv2.GET("/inventory-service/operational/remediation-queue/stats", operationalHandler.GetRemediationStats)
		apiv2.GET("/inventory-service/operational/remediation-queue", operationalHandler.GetRemediationQueue)
		apiv2.GET("/inventory-service/operational/remediation-templates", operationalHandler.GetRemediationTemplates)

		// Discovery endpoints
		apiv2.GET("/inventory-service/discovery/capabilities", discoveryHandler.GetCapabilities)
		apiv2.PUT("/inventory-service/discovery/capabilities", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDiscoveryManage), discoveryHandler.UpdateCapabilities)
		apiv2.POST("/inventory-service/discovery/jobs", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDiscoveryCreate), discoveryHandler.CreateJob)
		apiv2.GET("/inventory-service/discovery/jobs/:id", discoveryHandler.GetJob)
		apiv2.GET("/inventory-service/discovery/jobs/:id/results", discoveryHandler.GetJobResults)
		apiv2.POST("/inventory-service/discovery/jobs/:id/import", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDiscoveryCreate), discoveryHandler.ImportJobResults)
		apiv2.POST("/inventory-service/discovery/jobs/:id/cancel", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDiscoveryUpdate), discoveryHandler.CancelJob)
		apiv2.POST("/inventory-service/discovery/jobs/:id/rerun", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDiscoveryCreate), discoveryHandler.RerunJob)

		// Asset lifecycle
		apiv2.GET("/inventory-service/lifecycle/policy", assetLifecycleHandler.GetPolicy)
		apiv2.PUT("/inventory-service/lifecycle/policy", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionSettingsUpdate), assetLifecycleHandler.UpdatePolicy)

		// Tenant activity endpoints
		apiv2.GET("/inventory-service/tenant/:id/activity-summary", assetHandler.GetTenantActivitySummary)

		// CMDB / ITSM sync with EXTERNAL systems (ServiceNow, Device42,
		// SolarWinds, Oomnitza) is an Enterprise capability. In Core the hook
		// is nil and these routes are never mounted — the internal CMDB above
		// is unaffected. The Enterprise implementation owns its own RBAC
		// gating; see services/inventory-service/ee/cmdbsync/routes.go.
		if hooks.RegisterCMDBSyncRoutes != nil {
			hooks.RegisterCMDBSyncRoutes(apiv2, db, rawDB, assetService, os.Getenv("ENCRYPTION_MASTER_KEY"))
		}
	}

	// Health check server (HTTP, port 8080)
	healthRouter := gin.New()
	healthRouter.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "inventory-service",
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
		apiServer, err = sharedhttp.NewMTLSServer(
			cfg.ServiceCertPath,
			cfg.ServiceKeyPath,
			cfg.PlatformCACertPath,
			r,
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
			Handler:           r,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
	}

	log.Printf("🚀 Inventory Service starting")
	log.Printf("📊 Ready to serve crypto asset inventory")

	// Initialize NATS client for event-driven communication
	natsClient, natsErr := events.NewNATSClient("")
	if natsErr != nil {
		log.Printf("WARNING: NATS unavailable, will use HTTP fallback for audit job logging: %v", natsErr)
	}
	defer func() {
		if natsClient != nil {
			natsClient.Close()
		}
	}()

	// Start background job for stale asset detection
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	staleDetector := jobs.NewStaleAssetDetector(db, lifecycleService)
	if natsClient != nil {
		staleDetector.SetNATSClient(natsClient)
		log.Println("NATS client wired to StaleAssetDetector for audit job event publishing")
	}
	go staleDetector.Start(ctx)

	// ADR-0015 §6: scheduled certificate-expiry scan. Escalating owner alerts via the
	// existing certificate.expiring notification path + a certificate.changed bridge
	// that makes compliance re-evaluate a cert the day it expires (no scheduled re-eval).
	certExpiryJob := jobs.NewCertificateExpiryScanJob(db, eventPublisher)
	go certExpiryJob.Start(ctx)
	log.Println("Certificate expiry scan job started")

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
			log.Printf("Inventory service API server starting on %s:%s (mTLS)", cfg.Server.Host, cfg.TLSPort)
			if err := apiServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		} else {
			log.Printf("Inventory service API server starting on %s:%s (HTTP fallback)", cfg.Server.Host, cfg.Server.Port)
			if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down inventory service...")

	// Give outstanding requests 30 seconds to complete
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Stop background job
	cancel()

	// Shutdown both servers
	if err := healthServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("Health server forced to shutdown: %v", err)
	}
	if err := apiServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("API server forced to shutdown: %v", err)
	}

	log.Println("Inventory service stopped")
}
