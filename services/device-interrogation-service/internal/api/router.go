package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/certificates"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/config"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/middleware"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	"github.com/vistasecurity/vistaplatform/shared/events"
	sharedmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	sharednetwork "github.com/vistasecurity/vistaplatform/shared/network"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
	"github.com/vistasecurity/vistaplatform/shared/version"
)

// SetupRouter initializes and configures the Gin router. db is the RLS-scoped
// (crypto_app) connection; bypassDB is the BYPASSRLS (crypto_bypass) connection
// used by the agent bootstrap/auth, agent-outbound, cross-tenant admin, and
// background-worker paths. Pre-flip both handles resolve to the same connection.
func SetupRouter(cfg *config.Config, db, bypassDB *sql.DB, redis *redis.Client) *gin.Engine {
	router := gin.New()

	// Middleware
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// Health check endpoint
	router.GET("/health", healthCheck)
	router.GET("/ready", readinessCheck(db, redis))

	// Audit logging middleware
	auditConfig := auditmiddleware.DefaultConfig()
	auditConfig.ServiceName = "device-interrogation-service"
	auditConfig.AuditServiceURL = os.Getenv("AUDIT_SERVICE_URL")
	if auditConfig.AuditServiceURL == "" {
		if cfg.UseMTLS {
			auditConfig.AuditServiceURL = "https://audit-service:8443"
		} else {
			auditConfig.AuditServiceURL = sharedconfig.PeerURL("audit-service", sharedconfig.MTLSEnabled())
		}
	}
	auditConfig.Enabled = os.Getenv("AUDIT_LOGGING_ENABLED") != "false"
	auditConfig.UseMTLS = cfg.UseMTLS
	auditConfig.ClientCertPath = cfg.ClientCertPath
	auditConfig.ClientKeyPath = cfg.ClientKeyPath
	auditConfig.PlatformCACertPath = cfg.PlatformCACertPath
	auditMiddleware := auditmiddleware.NewMiddleware(auditConfig)

	router.Use(func(c *gin.Context) {
		c.Set("audit_middleware", auditMiddleware)
		c.Next()
	})
	router.Use(auditMiddleware.LogRequest())

	// API routes with service prefix
	api := router.Group("/api")
	v1 := api.Group("/v1")

	// Initialize services
	deviceService := services.NewDeviceService(db)
	jobQueueService := services.NewJobQueueService(db, bypassDB, redis)

	// Initialize discovery integration service (shared instance for notification publishing)
	discoveryIntegrationService := services.NewDiscoveryIntegrationService(db, bypassDB)

	// Wire NATS client to job queue and discovery integration for event publishing.
	// Retain the client (may stay nil if NATS is unconfigured/unavailable) so the
	// platform-admin queues endpoint can read live JetStream stream/consumer info.
	var natsClient *events.NATSClient
	if cfg.NATSURL != "" {
		client, natsErr := events.NewNATSClient(cfg.NATSURL)
		if natsErr != nil {
			log.Printf("WARNING: NATS unavailable for job publishing, will rely on DB polling: %v", natsErr)
		} else {
			natsClient = client
			jobQueueService.SetNATSClient(natsClient)
			log.Printf("NATS client wired to JobQueueService for device.jobs.submit publishing")
			discoveryIntegrationService.SetNATSClient(natsClient)
			log.Printf("NATS client wired to DiscoveryIntegrationService for notification publishing")
		}
	}

	schedulerService := services.NewSchedulerService(db, bypassDB, jobQueueService)
	healthMetricsService := services.NewHealthMetricsService(db, bypassDB)

	// Get encryption key for integration handlers
	encryptionKey := os.Getenv("ENCRYPTION_MASTER_KEY")

	// Initialize handlers
	deviceHandlers := handlers.NewDeviceHandlers(deviceService, db, bypassDB, redis)
	scheduleHandlers := handlers.NewScheduleHandlers(schedulerService)
	healthHandlers := handlers.NewHealthHandlers(healthMetricsService)
	integrationHandlers := handlers.NewIntegrationHandlers(db, bypassDB, encryptionKey)
	jobHandlers := handlers.NewJobHandlers(db, bypassDB)
	adminQueuesHandler := handlers.NewAdminQueuesHandler(natsClient)

	deviceInterrogationGroup := v1.Group("/device-interrogation-service")

	// Auto-registration endpoint for platform services (service account auth)
	deviceInterrogationGroup.POST("/agents/auto-register", sharedmiddleware.ServiceAccountAuth(db), handlers.AutoRegisterAgentHandler(db, bypassDB))

	// Tenant device agent bootstrap (registration key + CSR only; same model as sensor-manager /sensors/register)
	deviceInterrogationGroup.POST("/agents/register", registerAgentPublicHandler(db, bypassDB, redis))

	// Binary agent outbound routes: AgentAuth (fail-closed mTLS when AgentMTLSRequired), not tenant JWT — mirrors sensor-manager SensorAuth
	agentOutbound := deviceInterrogationGroup.Group("/agents")
	agentOutbound.Use(middleware.AgentAuth(db, bypassDB, cfg.AgentMTLSRequired))
	{
		agentOutbound.GET("/:id/jobs", getAgentJobsHandler(db, bypassDB, redis))
		agentOutbound.POST("/:id/results", submitAgentResultsHandler(db, bypassDB, redis))
		agentOutbound.POST("/:id/heartbeat", agentHeartbeatHandler(db, bypassDB, redis))
		// Autonomous pre-expiry cert renewal. Under AgentAuth like the
		// rest of the outbound surface — mirrors sensor-manager's rotate route.
		agentOutbound.POST("/:id/certificates/rotate", rotateAgentCertificateHandler(db, bypassDB))
	}

	// Apply authentication middleware to all other device interrogation routes.
	// Per-route RBAC gates use the discovery.* tenant permission vocabulary
	// (read / create / update / manage), which is the permission set seeded
	// specifically for device interrogation (see seed.sql tenant_permissions:
	// "View discovery jobs, devices, and interrogation results", etc.). Reads
	// require discovery.read; creating devices/schedules requires
	// discovery.create; mutating them requires discovery.update; high-privilege
	// actions (running interrogations/discovery, deletes, and cloud-credential
	// integration management) require discovery.manage. Without these gates any
	// authenticated tenant user — including a read-only viewer — could create
	// cloud-credential integrations, trigger interrogations/scans, and delete
	// devices.
	deviceInterrogationGroup.Use(middleware.RequireAuth(cfg.JWTSecret))
	{
		// Cloud integrations routes (tenant-scoped). Integrations hold cloud
		// credentials, so create/update/delete require discovery.manage.
		integrations := deviceInterrogationGroup.Group("/integrations")
		{
			integrations.GET("", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryRead), integrationHandlers.ListIntegrations)
			integrations.POST("", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryManage), integrationHandlers.CreateIntegration)
			integrations.GET("/:id", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryRead), integrationHandlers.GetIntegration)
			integrations.PUT("/:id", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryManage), integrationHandlers.UpdateIntegration)
			integrations.DELETE("/:id", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryManage), integrationHandlers.DeleteIntegration)
			integrations.POST("/:id/test", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryRead), integrationHandlers.TestConnection)
		}

		// Interrogation jobs routes
		jobs := deviceInterrogationGroup.Group("/jobs")
		{
			jobs.GET("", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryRead), jobHandlers.ListJobs)
			jobs.GET("/stats", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryRead), jobHandlers.GetJobStats)
			jobs.GET("/active", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryRead), jobHandlers.GetActiveJobs)
			jobs.GET("/:id", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryRead), jobHandlers.GetJob)
			jobs.GET("/:id/results", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryRead), jobHandlers.GetJobResults)
			jobs.POST("/:id/retry", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryUpdate), jobHandlers.RetryJob)
			jobs.POST("/:id/cancel", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryUpdate), jobHandlers.CancelJob)
		}

		// Device management routes
		devices := deviceInterrogationGroup.Group("/devices")
		{
			devices.POST("", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryCreate), deviceHandlers.CreateDevice)
			devices.POST("/discover-and-create", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryCreate), deviceHandlers.DiscoverAndCreateDevice)
			devices.GET("", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryRead), deviceHandlers.ListDevices)
			devices.POST("/bulk-interrogate", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryManage), deviceHandlers.BulkInterrogateDevices)
			devices.GET("/:id", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryRead), deviceHandlers.GetDevice)
			devices.PUT("/:id", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryUpdate), deviceHandlers.UpdateDevice)
			devices.DELETE("/:id", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryManage), deviceHandlers.DeleteDevice)
			devices.POST("/:id/interrogate", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryManage), deviceHandlers.InterrogateDevice)
			devices.POST("/:id/test-connection", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryRead), deviceHandlers.TestConnection)
			devices.GET("/:id/health", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryRead), healthHandlers.GetDeviceHealth)
			devices.GET("/:id/health/timeline", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryRead), healthHandlers.GetDeviceHealthTimeline)
		}

		// Agent management routes (tenant UI / API — JWT). Outbound jobs/results/heartbeat are on agentOutbound + AgentAuth.
		agents := deviceInterrogationGroup.Group("/agents")
		{
			agents.GET("", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryRead), listAgentsHandler(db, bypassDB, redis))
		}

		// Cloud discovery routes — these actively run discovery/interrogation.
		cloud := deviceInterrogationGroup.Group("/cloud")
		{
			cloud.POST("/discover", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryManage), discoverCloudResourcesHandler(db, bypassDB, discoveryIntegrationService))
			cloud.POST("/interrogate", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryManage), interrogateCloudResourceHandler(db, bypassDB))
		}

		// Scheduled interrogations routes
		schedules := deviceInterrogationGroup.Group("/schedules")
		{
			schedules.POST("", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryCreate), scheduleHandlers.CreateSchedule)
			schedules.GET("", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryRead), scheduleHandlers.ListSchedules)
			schedules.GET("/:id", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryRead), scheduleHandlers.GetSchedule)
			schedules.PUT("/:id", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryUpdate), scheduleHandlers.UpdateSchedule)
			schedules.DELETE("/:id", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryManage), scheduleHandlers.DeleteSchedule)
			schedules.POST("/:id/trigger", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryManage), scheduleHandlers.TriggerSchedule)
			schedules.GET("/:id/history", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryRead), scheduleHandlers.GetScheduleHistory)
			schedules.POST("/:id/enable", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryUpdate), scheduleHandlers.EnableSchedule)
			schedules.POST("/:id/disable", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryUpdate), scheduleHandlers.DisableSchedule)
		}

		// Admin routes for platform overview (requires platform admin role).
		// These aggregate data across ALL tenants (no tenant_id filter), so the
		// WHOLE group is gated at platform-admin — a tenant JWT must never reach
		// them. Group-level so no route can be added ungated by mistake; keeps
		// /metrics gated (matching) and covers the agents/jobs/queues lists.
		admin := deviceInterrogationGroup.Group("/admin", middleware.RequirePlatformAuth(cfg.JWTSecret), sharedmiddleware.RequirePlatformAdmin())
		{
			admin.GET("/metrics", healthHandlers.GetPlatformHealth)
			admin.GET("/agents", adminListAgentsHandler(db, bypassDB, redis))
			admin.GET("/jobs", jobHandlers.ListAdminJobs)
			admin.POST("/jobs/:id/retry", jobHandlers.RetryJobAdmin)
			admin.POST("/jobs/:id/cancel", jobHandlers.CancelJobAdmin)
			admin.GET("/queues", adminQueuesHandler.ListQueues)
		}

		// Experimental encryption detection routes
		experimentalHandlers := handlers.NewExperimentalHandlers(db)
		experimentalActionHandlers := handlers.NewExperimentalActionHandlers(db, bypassDB, encryptionKey)
		experimental := deviceInterrogationGroup.Group("/experimental")
		{
			// Read endpoints
			experimental.GET("/stats", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryRead), experimentalHandlers.GetExperimentalStats)
			experimental.GET("/kms-keys", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryRead), experimentalHandlers.ListKMSKeys)
			experimental.GET("/database-encryption", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryRead), experimentalHandlers.ListDatabaseEncryptionStates)
			experimental.GET("/ssh-keys", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryRead), experimentalHandlers.ListSSHKeys)
			experimental.GET("/code-findings", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryRead), experimentalHandlers.ListCodeFindings)
			experimental.GET("/aws-integrations", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryRead), experimentalActionHandlers.ListAWSIntegrations)

			// Action endpoints — these actively scan/interrogate using cloud creds.
			experimental.POST("/kms-keys/discover", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryManage), experimentalActionHandlers.DiscoverKMSKeys)
			experimental.POST("/database-encryption/interrogate", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryManage), experimentalActionHandlers.InterrogateDatabase)
			experimental.POST("/ssh-keys/scan", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryManage), experimentalActionHandlers.ScanSSHKeys)
			experimental.POST("/code-findings/scan", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryManage), experimentalActionHandlers.ScanRepository)
		}
	}

	return router
}

// healthCheck returns a simple health status
func healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"service":   "device-interrogation-service",
		"timestamp": gin.H{},
		"version":   version.Get(),
	})
}

// readinessCheck checks if the service is ready to handle requests
func readinessCheck(db *sql.DB, redis *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check database connection
		if err := db.Ping(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "not ready",
				"error":  "database connection failed",
			})
			return
		}

		// Check Redis connection
		if err := redis.Ping(c.Request.Context()).Err(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "not ready",
				"error":  "redis connection failed",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":  "ready",
			"service": "device-interrogation-service",
		})
	}
}

// Agent handlers
func listAgentsHandler(db, bypassDB *sql.DB, redis *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context
		tenantIDVal, exists := c.Get("tenantID")
		if !exists {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
			return
		}

		tenantID, ok := tenantIDVal.(uuid.UUID)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		agentService := services.NewAgentService(db, bypassDB, redis)
		agents, err := agentService.ListAgents(c.Request.Context(), tenantID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"agents": agents,
			"count":  len(agents),
		})
	}
}

// adminListAgentsHandler lists interrogation agents across ALL tenants for the
// platform-admin Fleet view (read-only). Gated by RequirePlatformAdmin in the
// router. Unlike listAgentsHandler it deliberately omits any tenant_id filter.
func adminListAgentsHandler(db, bypassDB *sql.DB, redis *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Optional operator-scope narrowing: filter the cross-tenant roll-up to one
		// tenant server-side, so other tenants' rows are never shipped to the client.
		// Validate as a UUID (reject a malformed value with 400 rather than letting it
		// surface as a 500 from the typed tenant_id column).
		tenantFilter := c.Query("tenant_id")
		if tenantFilter != "" {
			if _, err := uuid.Parse(tenantFilter); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id"})
				return
			}
		}

		agentService := services.NewAgentService(db, bypassDB, redis)
		agents, err := agentService.ListAllAgents(c.Request.Context(), tenantFilter)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"agents": agents,
			"count":  len(agents),
		})
	}
}

func registerAgentPublicHandler(db, bypassDB *sql.DB, redis *redis.Client) gin.HandlerFunc {
	agentService := services.NewAgentService(db, bypassDB, redis)
	cfg, _ := config.Load()
	certService := certificates.NewCertificateService(db, bypassDB, cfg.EncryptionMasterKey)

	return func(c *gin.Context) {
		var req models.RegisterAgentRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		agent, err := agentService.RegisterDeviceAgentBootstrap(c.Request.Context(), req)
		if err != nil {
			if errors.Is(err, services.ErrInvalidDeviceAgentRegistrationKey) {
				log.Printf("device agent registration key rejected: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Invalid, expired, or already-used registration key, or this key is not for a device interrogation agent",
				})
				return
			}
			if errors.Is(err, services.ErrAgentIDConflict) {
				c.JSON(http.StatusConflict, gin.H{"error": "Agent id is already registered; use a new agent id or reuse your saved configuration"})
				return
			}
			if strings.Contains(err.Error(), "registration key") {
				sharedapi.ErrorResponse(c, http.StatusBadRequest, "Invalid or expired registration key", err)
				return
			}
			log.Printf("RegisterDeviceAgentBootstrap: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		response := models.RegisterAgentResponse{
			AgentID: agent.ID,
		}

		if req.CSR != "" {
			certPEM, err := certService.IssueCertificate(agent.TenantID, agent.ID, req.CSR)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to issue certificate from CSR"})
				return
			}
			response.ClientCert = certPEM

			caManager := certificates.NewCAManager(db, bypassDB)
			ca, err := caManager.GetActiveCA(agent.TenantID)
			if err == nil {
				response.ServerCACert = ca.CACertPEM
			}

			// follow-up: server-trust switch. The per-tenant CA above is
			// the agent's CLIENT-cert issuer. With fail-closed agent mTLS the
			// agent connects to the dedicated passthrough listener, whose SERVER
			// cert is the per-service mesh cert (platform-CA-signed, NOT the
			// tenant CA). Hand the agent the platform CA as its server trust
			// anchor so server verification succeeds; the agent keeps presenting
			// its per-tenant client cert. Falls back to the tenant CA when mTLS
			// isn't enforced (dev/compose) or the platform CA isn't mounted.
			if cfg != nil && cfg.AgentMTLSRequired {
				if pca, perr := os.ReadFile(cfg.PlatformCACertPath); perr == nil && len(pca) > 0 {
					response.ServerCACert = string(pca)
				} else {
					log.Printf("registerAgent: AGENT_MTLS_REQUIRED set but platform CA unreadable at %s: %v", cfg.PlatformCACertPath, perr)
				}
				//: registration happens on the edge host (no client cert
				// yet); everything after must reach the mTLS passthrough
				// listener. Advertise that URL so the agent switches over.
				response.ControlPlaneURL = cfg.AgentMTLSAdvertisedURL
			}

			response.CertificateExpiresAt = time.Now().AddDate(1, 0, 0).Format(time.RFC3339)
		}

		c.JSON(http.StatusCreated, response)
	}
}

func getAgentJobsHandler(db, bypassDB *sql.DB, redis *redis.Client) gin.HandlerFunc {
	agentService := services.NewAgentService(db, bypassDB, redis)
	return func(c *gin.Context) {
		idStr := c.Param("id")
		agentID, err := uuid.Parse(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid agent ID"})
			return
		}

		job, err := agentService.GetNextJob(c.Request.Context(), agentID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		if job == nil {
			c.Status(http.StatusNoContent)
			return
		}

		c.JSON(http.StatusOK, job)
	}
}

func submitAgentResultsHandler(db, bypassDB *sql.DB, redis *redis.Client) gin.HandlerFunc {
	agentService := services.NewAgentService(db, bypassDB, redis)
	return func(c *gin.Context) {
		idStr := c.Param("id")
		agentID, err := uuid.Parse(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid agent ID"})
			return
		}

		var result models.JobResult
		if err := c.ShouldBindJSON(&result); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		if err := agentService.SubmitJobResult(c.Request.Context(), agentID, &result); err != nil {
			// Cross-tenant / unknown-job attempts are reported as 404 (no leak of
			// which job ids exist or belong to other tenants) —.
			if errors.Is(err, services.ErrJobTenantMismatch) || errors.Is(err, services.ErrAgentNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "Job not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Result submitted successfully"})
	}
}

func agentHeartbeatHandler(db, bypassDB *sql.DB, redis *redis.Client) gin.HandlerFunc {
	agentService := services.NewAgentService(db, bypassDB, redis)
	return func(c *gin.Context) {
		idStr := c.Param("id")
		agentID, err := uuid.Parse(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid agent ID"})
			return
		}

		// Body is optional and lenient: older agents send {status,timestamp}
		// or nothing. Anything present refreshes the recorded value; anything
		// absent leaves it alone. ip_address and interfaces must be
		// self-reported — the platform's view of the connection is a proxy or
		// node address, never the agent's.
		var beat struct {
			Version    string                           `json:"version"`
			IPAddress  string                           `json:"ip_address"`
			Interfaces []sharednetwork.InterfaceAddress `json:"interfaces"`
		}
		_ = c.ShouldBindJSON(&beat)

		if err := agentService.UpdateHeartbeatWithHost(c.Request.Context(), agentID, beat.Version, beat.IPAddress, beat.Interfaces); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Heartbeat received"})
	}
}

// Cloud discovery handlers
func discoverCloudResourcesHandler(db, bypassDB *sql.DB, discoveryIntegrationService *services.DiscoveryIntegrationService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context (set by middleware)
		tenantIDVal, exists := c.Get("tenantID")
		if !exists {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
			return
		}

		tenantID, ok := tenantIDVal.(uuid.UUID)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		// Get user ID from context (if available)
		userIDVal, exists := c.Get("userID")
		userID := uuid.Nil
		if exists {
			if uid, ok := userIDVal.(uuid.UUID); ok {
				userID = uid
			}
		}
		if userID == uuid.Nil {
			userID = uuid.MustParse("00000000-0000-0000-0000-000000000000")
		}

		var req models.DiscoverCloudResourcesRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		// Get master key from environment variable
		masterKey := os.Getenv("ENCRYPTION_MASTER_KEY")
		if masterKey == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption master key not configured"})
			return
		}

		// Use the shared discovery integration service (with NATS wired)
		discoveryIntegration := discoveryIntegrationService
		jobMetadata := map[string]interface{}{
			"integration_id": req.IntegrationID.String(),
			"resource_types": req.ResourceTypes,
			"regions":        req.Regions,
			"source":         "cloud_api",
		}

		jobID, err := discoveryIntegration.CreateDiscoveryJob(c.Request.Context(), tenantID, userID, "cloud_api", jobMetadata)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create discovery job"})
			return
		}

		// IMPORTANT: Mark discovery job as started IMMEDIATELY (before async processing)
		// This prevents cluster-sensor-service from picking up this job via its polling
		// mechanism (which looks for 'queued' jobs older than 1 minute)
		if err := discoveryIntegration.MarkJobStarted(c.Request.Context(), jobID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start discovery job"})
			return
		}

		// Create a device_job for UI visibility (interrogation jobs page shows device_jobs)
		// Status is set to in_progress since we've already started processing
		jobQueue := services.NewJobQueueService(db, bypassDB, nil)
		deviceJobReq := models.CreateDeviceJobRequest{
			TenantID:      tenantID,
			JobType:       models.JobTypeCloudDiscovery,
			IntegrationID: &req.IntegrationID,
			Parameters: map[string]interface{}{
				"discovery_job_id": jobID.String(),
				"integration_id":   req.IntegrationID.String(),
				"resource_types":   req.ResourceTypes,
				"regions":          req.Regions,
			},
		}
		deviceJob, err := jobQueue.CreateJob(c.Request.Context(), deviceJobReq)
		if err != nil {
			log.Printf("Warning: failed to create device_job for UI visibility: %v", err)
			// Non-fatal, continue with discovery
		} else {
			// Mark device_job as in_progress immediately
			if updateErr := jobQueue.UpdateJobStatus(c.Request.Context(), deviceJob.ID, models.JobStatusInProgress, nil, nil); updateErr != nil {
				log.Printf("Warning: failed to update device_job to in_progress: %v", updateErr)
			}
		}

		// Capture audit middleware reference before goroutine (request context won't be available later)
		var auditMW *auditmiddleware.Middleware
		if mw, exists := c.Get("audit_middleware"); exists {
			auditMW, _ = mw.(*auditmiddleware.Middleware)
		}

		// Run discovery asynchronously in background
		go func() {
			ctx := context.Background() // Use background context since request context will be cancelled

			// Ensure job status is always updated on exit (completed or failed), including on panic
			var statusUpdated bool
			var deviceJobStatusUpdated bool
			defer func() {
				if r := recover(); r != nil {
					if !statusUpdated {
						discoveryIntegration.UpdateJobStatus(ctx, jobID, "failed", stringPtr(fmt.Sprintf("Panic: %v", r)))
					}
					if deviceJob != nil && !deviceJobStatusUpdated {
						errMsg := fmt.Sprintf("Panic: %v", r)
						jobQueue.UpdateJobStatus(ctx, deviceJob.ID, models.JobStatusFailed, nil, &errMsg)
					}
				}
			}()

			// Discover resources
			cloudService := services.NewCloudDiscoveryService(db, bypassDB, masterKey)

			// Determine cloud provider - use explicit value or auto-detect from integration
			cloudProvider := req.CloudProvider
			if cloudProvider == "" {
				detectedProvider, err := cloudService.GetIntegrationCloudProvider(ctx, tenantID, req.IntegrationID)
				if err != nil {
					failMsg := fmt.Sprintf("Failed to detect cloud provider: %v", err)
					discoveryIntegration.UpdateJobStatus(ctx, jobID, "failed", stringPtr(failMsg))
					statusUpdated = true
					if deviceJob != nil {
						jobQueue.UpdateJobStatus(ctx, deviceJob.ID, models.JobStatusFailed, nil, &failMsg)
						deviceJobStatusUpdated = true
					}
					discoveryIntegration.SendDiscoveryNotification(ctx, tenantID,
						"job_failed", "Cloud discovery failed: "+failMsg,
						jobID, nil,
					)
					return
				}
				cloudProvider = detectedProvider
			}

			var devices []models.Device
			switch cloudProvider {
			case "aws":
				devices, err = cloudService.DiscoverAWSResources(ctx, tenantID, req.IntegrationID, req.ResourceTypes, req.Regions)
			case "azure":
				devices, err = cloudService.DiscoverAzureResources(ctx, tenantID, req.IntegrationID, req.ResourceTypes, req.ResourceGroups)
			case "gcp":
				devices, err = cloudService.DiscoverGCPResources(ctx, tenantID, req.IntegrationID, req.ResourceTypes)
			default:
				discoveryIntegration.UpdateJobStatus(ctx, jobID, "failed", stringPtr(fmt.Sprintf("Unknown cloud provider: %s", cloudProvider)))
				statusUpdated = true
				if deviceJob != nil {
					errMsg := fmt.Sprintf("Unknown cloud provider: %s", cloudProvider)
					jobQueue.UpdateJobStatus(ctx, deviceJob.ID, models.JobStatusFailed, nil, &errMsg)
					deviceJobStatusUpdated = true
				}
				return
			}

			if err != nil {
				discoveryIntegration.UpdateJobStatus(ctx, jobID, "failed", stringPtr(err.Error()))
				statusUpdated = true
				if deviceJob != nil {
					errMsg := err.Error()
					jobQueue.UpdateJobStatus(ctx, deviceJob.ID, models.JobStatusFailed, nil, &errMsg)
					deviceJobStatusUpdated = true
				}
				// Send failure notification to notification service (Slack, etc.)
				discoveryIntegration.SendDiscoveryNotification(ctx, tenantID,
					"job_failed",
					fmt.Sprintf("Cloud discovery failed: %s", err.Error()),
					jobID, map[string]interface{}{
						"cloud_provider": cloudProvider,
					},
				)
				return
			}

			// Write discovered devices into sensor_discoveries table for unified processing
			// by discovery-processor-service (same pipeline as sensor discoveries)
			inserted, sdErr := cloudService.WriteSensorDiscoveries(ctx, tenantID, jobID.String(), req.IntegrationID, cloudProvider, devices)
			if sdErr != nil {
				log.Printf("ERROR: Failed to write sensor discoveries: %v", sdErr)
			} else {
				log.Printf("Cloud discovery wrote %d sensor_discoveries for batch %s (%d devices)", inserted, jobID.String(), len(devices))
			}

			// Audit: log cloud discovery completion
			if auditMW != nil {
				_ = auditmiddleware.LogSimple(ctx, auditMW,
					"discovery.cloud_completed", "discovery", "discover",
					"discovery_job", jobID.String(),
					fmt.Sprintf("%s discovery: %d resources found", cloudProvider, len(devices)),
					true, "")
			}

			// Mark job as completed; on failure set to failed so job does not stay "running"
			if err := discoveryIntegration.MarkJobCompleted(ctx, jobID); err != nil {
				log.Printf("Failed to mark discovery job as completed: %v", err)
				discoveryIntegration.UpdateJobStatus(ctx, jobID, "failed", stringPtr(fmt.Sprintf("Could not update status: %v", err)))
			}
			statusUpdated = true

			// Send completion notification to notification service (Slack, etc.)
			discoveryIntegration.SendDiscoveryNotification(ctx, tenantID,
				"job_completed",
				fmt.Sprintf("Cloud discovery completed: %d %s resources found", len(devices), cloudProvider),
				jobID, map[string]interface{}{
					"cloud_provider": cloudProvider,
					"devices_found":  len(devices),
				},
			)
			// If new findings were discovered, send a new_findings notification too
			if len(devices) > 0 {
				discoveryIntegration.SendDiscoveryNotification(ctx, tenantID,
					"new_findings",
					fmt.Sprintf("Cloud discovery found %d new resources requiring review", len(devices)),
					jobID, map[string]interface{}{
						"cloud_provider": cloudProvider,
						"finding_count":  len(devices),
					},
				)
			}

			// Update device_job status to completed (or failed if discovery_job update failed)
			if deviceJob != nil {
				if !statusUpdated {
					// Discovery job update failed, mark device_job as failed too
					errMsg := "Discovery job status update failed"
					if updateErr := jobQueue.UpdateJobStatus(ctx, deviceJob.ID, models.JobStatusFailed, nil, &errMsg); updateErr != nil {
						log.Printf("ERROR: Failed to update device_job status to failed: %v", updateErr)
					}
				} else {
					// Count crypto-config assets from devices (matches platform_agent_worker semantics)
					assetsCount := 0
					for i := range devices {
						if devices[i].Metadata != nil {
							if configs, ok := devices[i].Metadata["crypto_configs"].([]interface{}); ok {
								assetsCount += len(configs)
							}
						}
					}
					result := &models.JobResult{
						JobID:       deviceJob.ID,
						Success:     true,
						CompletedAt: time.Now(),
						Metadata: map[string]interface{}{
							"devices_count": len(devices),
							"assets_count":  assetsCount,
						},
					}
					// Store result so UI can show "X asset(s) discovered"
					if updateErr := jobQueue.UpdateJobStatus(ctx, deviceJob.ID, models.JobStatusCompleted, result, nil); updateErr != nil {
						log.Printf("ERROR: Failed to update device_job status to completed: %v", updateErr)
					}
				}
				deviceJobStatusUpdated = true
			}
		}()

		// Return immediately with job ID - client can poll for status
		c.JSON(http.StatusAccepted, gin.H{
			"job_id":  jobID.String(),
			"status":  "queued",
			"message": "Discovery job queued successfully. Use the job ID to check status.",
		})
	}
}

func stringPtr(s string) *string {
	return &s
}

func interrogateCloudResourceHandler(db, bypassDB *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context (set by middleware)
		tenantIDVal, exists := c.Get("tenantID")
		if !exists {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
			return
		}

		tenantID, ok := tenantIDVal.(uuid.UUID)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		var req models.InterrogateCloudResourceRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		// Get master key from environment variable
		masterKey := os.Getenv("ENCRYPTION_MASTER_KEY")
		if masterKey == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption master key not configured"})
			return
		}

		// Interrogate the specific cloud resource
		cloudService := services.NewCloudDiscoveryService(db, bypassDB, masterKey)

		// Determine cloud provider - use explicit value or auto-detect from integration
		cloudProvider := req.CloudProvider
		if cloudProvider == "" {
			detectedProvider, err := cloudService.GetIntegrationCloudProvider(c.Request.Context(), tenantID, req.IntegrationID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to detect cloud provider"})
				return
			}
			cloudProvider = detectedProvider
		}

		// For now, use the same discovery logic but filter to the specific resource
		// In the future, this could be enhanced to do deeper interrogation of a single resource
		var devices []models.Device
		var err error
		switch cloudProvider {
		case "aws":
			devices, err = cloudService.DiscoverAWSResources(
				c.Request.Context(),
				tenantID,
				req.IntegrationID,
				[]string{req.ResourceType},
				[]string{}, // Empty regions means all regions
			)
		case "azure":
			devices, err = cloudService.DiscoverAzureResources(
				c.Request.Context(),
				tenantID,
				req.IntegrationID,
				[]string{req.ResourceType},
				[]string{}, // Empty resource groups means all
			)
		case "gcp":
			devices, err = cloudService.DiscoverGCPResources(
				c.Request.Context(),
				tenantID,
				req.IntegrationID,
				[]string{req.ResourceType},
			)
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Unknown cloud provider: %s", cloudProvider)})
			return
		}

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		// Filter to the specific resource by identifier (ARN for AWS, resource ID for Azure)
		var targetDevice *models.Device
		for i := range devices {
			if devices[i].Metadata != nil {
				// Check for AWS ARN
				if req.ResourceARN != "" {
					if arn, ok := devices[i].Metadata["arn"].(string); ok && arn == req.ResourceARN {
						targetDevice = &devices[i]
						break
					}
				}
				// Check for Azure resource ID
				if req.ResourceID != "" {
					if azureID, ok := devices[i].Metadata["azure_resource_id"].(string); ok && azureID == req.ResourceID {
						targetDevice = &devices[i]
						break
					}
				}
			}
		}

		if targetDevice == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Resource not found"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"resource_arn":  req.ResourceARN,
			"resource_id":   req.ResourceID,
			"resource_type": req.ResourceType,
			"device":        targetDevice,
		})
	}
}
