package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/database"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/handlers"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/middleware"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/services"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	resourcetracking "github.com/vistasecurity/vistaplatform/shared/middleware/resource-tracking"
	trial_lock "github.com/vistasecurity/vistaplatform/shared/middleware/trial_lock"
	rbac "github.com/vistasecurity/vistaplatform/shared/rbac"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Connect to database
	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		if os.Getenv("ENV") == "development" {
			log.Printf("[dev] DB unavailable, continuing with in-memory features: %v", err)
			db = nil
		} else {
			log.Fatalf("Failed to connect to database: %v", err)
		}
	} else {
		defer db.Close()
	}

	// Bypass connection for the deliberately cross-tenant paths (registration
	// bootstrap, by-id/by-key lookups, cross-tenant sweeps). Reads
	// BYPASS_DATABASE_URL and falls back to DATABASE_URL, so pre-flip it resolves
	// to the same (owner) connection and behavior is unchanged. After the Phase 4
	// role split it points at the BYPASSRLS crypto_bypass role. Only opened when
	// the primary db is up; otherwise the dev in-memory path is preserved.
	var bypassDB *sql.DB
	if db != nil {
		bypassDB, err = shareddatabase.ConnectBypass()
		if err != nil {
			log.Fatalf("Failed to connect to bypass database: %v", err)
		}
		defer func() { _ = bypassDB.Close() }()
	}

	// Initialize services
	sensorService := services.NewSensorService(db, bypassDB)
	var repo database.SensorRepository
	var sensorServiceV2 *services.SensorServiceV2
	if db != nil {
		repo = database.NewSensorRepository(db, bypassDB)
		sensorServiceV2 = services.NewSensorServiceV2(repo)
	}

	// Initialize S3 downloader if configured
	var s3Downloader *services.S3Downloader
	if cfg.S3ArtifactsBucket != "" {
		var err error
		s3Downloader, err = services.NewS3Downloader(cfg.S3ArtifactsBucket, cfg.S3ArtifactsRegion, cfg.S3ArtifactsVersion)
		if err != nil {
			log.Printf("⚠️  Failed to initialize S3 downloader: %v (continuing without S3 fallback)", err)
		} else {
			log.Printf("✅ S3 downloader initialized (bucket: %s, version: %s)", cfg.S3ArtifactsBucket, cfg.S3ArtifactsVersion)
		}
	}

	// Initialize discovery job service if database is available
	var discoveryJobService *services.DiscoveryJobService
	if db != nil {
		discoveryJobService = services.NewDiscoveryJobService(db)
	}

	// Initialize PCAP service if database is available
	var pcapService *services.PcapService
	if db != nil {
		pcapService = services.NewPcapService(db, bypassDB)
	}

	// Initialize NATS client (optional - PCAP upload works without it, job just won't auto-process)
	var natsClient *events.NATSClient
	natsURL := os.Getenv("NATS_URL")
	if natsURL != "" {
		var natsErr error
		natsClient, natsErr = events.NewNATSClient(natsURL)
		if natsErr != nil {
			log.Printf("Warning: Failed to connect to NATS: %v (PCAP uploads will work but events won't be published)", natsErr)
		} else {
			log.Printf("NATS client connected for PCAP job events")
		}
	}

	// Initialize logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logLevel, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logger.SetLevel(logLevel)

	// Start system sensor health monitor (updates platform sensor status for all tenants)
	if db != nil {
		healthService := services.NewSystemSensorHealthService(
			db,
			os.Getenv("CLUSTER_SENSOR_SERVICE_URL"),
			os.Getenv("DEVICE_INTERROGATION_SERVICE_URL"),
		)
		go healthService.Start(context.Background())

		// Start the offline reaper so tenant sensors that stop checking in are
		// transitioned 'active' -> 'offline' (the heartbeat path handles the
		// reverse). Without this a dead sensor shows "active" forever.
		reaper := services.NewSensorReaperService(db)
		go reaper.Start(context.Background())
	}

	// Initialize handlers with both legacy and V2 services
	handler := handlers.NewHandlerWithBoth(sensorService, sensorServiceV2, repo, db)
	// Set logger on handler
	if handler != nil {
		// Handler now has logger initialized in NewHandlerWithBoth
		// But we can update it with the configured logger if needed
		// For now, the logger is initialized in the handler constructor
	}
	// Set encryption key for certificate operations
	if cfg.EncryptionMasterKey != "" {
		handler.SetEncryptionKey(cfg.EncryptionMasterKey)
	}
	if s3Downloader != nil {
		handler.SetS3Downloader(s3Downloader)
	}
	if discoveryJobService != nil {
		handler.SetDiscoveryJobService(discoveryJobService)
	}
	if pcapService != nil {
		handler.SetPcapService(pcapService)
	}
	if natsClient != nil {
		handler.SetNATSClient(natsClient)
	}

	// Set Gin mode
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize router
	router := gin.Default()

	// Add panic recovery middleware
	router.Use(gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		log.Printf("⚠️  Panic recovered: %v", recovered)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Internal server error",
		})
		c.Abort()
	}))

	// Resource tracking middleware
	trackerConfig := resourcetracking.DefaultConfig()
	trackerConfig.ServiceName = "sensor-manager"
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
	auditConfig.ServiceName = "sensor-manager"
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

	// CORS is handled by Traefik API gateway - no need for duplicate headers

	// Health check
	router.GET("/health", handler.Health)

	// API routes with service prefix for consistency
	// This follows the microservices pattern where each service has its own namespace
	// under the API gateway. This ensures:
	// 1. Clear service boundaries
	// 2. Consistent routing through the API gateway
	// 3. Centralized authentication and rate limiting
	// 4. Future-proof for additional services

	// API routes with authentication
	api := router.Group("/api/v1")
	sensorManager := api.Group("/sensor-manager")

	// Register public endpoint BEFORE applying auth middleware
	sensorManager.POST("/sensors/register", handler.RegisterSensor)

	// Auto-registration endpoint for platform services (bootstrap mTLS certificate auth)
	if db != nil && cfg.EncryptionMasterKey != "" {
		sensorManager.POST("/sensors/auto-register", middleware.BootstrapAuth(db, cfg.EncryptionMasterKey), handler.AutoRegisterSensor)
	}

	// NOTE: Sensor binary downloads are not served by the platform. Binaries are
	// published as signed GitHub Release assets; operators can also build from
	// source with `make build-sensor`. See docsv4/core/features/SENSOR_REGISTRATION.md.

	// Sensor-specific routes (outbound-only, sensor auth). These bypass tenant auth because sensors authenticate differently.
	sensors := sensorManager.Group("/sensors/:sensor_id")
	// Sensor-specific auth with certificate chain validation
	// Pass db and encryption key for certificate validation (db may be nil in dev mode)
	var dbForAuth *sql.DB
	var bypassDBForAuth *sql.DB
	if db != nil {
		dbForAuth = db
		bypassDBForAuth = bypassDB
	}
	sensors.Use(middleware.SensorAuth(dbForAuth, bypassDBForAuth, cfg.EncryptionMasterKey, cfg.SensorMTLSRequired)) // Sensor-specific auth (fail-closed mTLS when SensorMTLSRequired), no tenant required
	{
		// Outbound-only communication endpoints
		sensors.POST("/heartbeat", handler.Heartbeat)
		// Polling endpoint moved to avoid duplicate with management GET /sensors/:sensor_id/commands
		sensors.GET("/commands/poll", handler.PollCommands)
		sensors.POST("/commands/:command_id/ack", handler.AcknowledgeCommand)
		sensors.GET("/webhook-config", handler.GetWebhookConfig)

		// Discovery submission
		sensors.POST("/discoveries", handler.SubmitDiscoveries)

		// Autonomous certificate rotation (sensor renews its own cert before
		// expiry). Sensor-authenticated, NOT tenant-JWT — this is what the sensor
		// binary's pre-expiry renewal loop calls. Was previously mis-registered on
		// the tenant-admin group below and 401'd every renewal.
		sensors.POST("/certificates/rotate", handler.RotateSensorCertificate)

		// Air-gapped export
		sensors.POST("/exports", handler.SubmitAirGappedExport)

		// Legacy endpoints (for backward compatibility)
		sensors.POST("/health", handler.ReportHealth)
		sensors.GET("/config", handler.GetSensorConfig)
	}

	// Now apply auth middleware to all routes registered after this point
	sensorManager.Use(middleware.RequireAuth(cfg.JWTSecret))
	sensorManager.Use(middleware.RequireTenant())
	// Trial-lock middleware gates writes when the calling tenant has
	// hard-locked. db can be nil in dev mode — skip registration then.
	if db != nil {
		sensorManager.Use(trial_lock.Middleware(db, nil))
	}
	// RLS defense-in-depth: PostgreSQL RLS policies enforce tenant isolation at the
	// database level via app.tenant_id session variable. Queries in handlers use
	// WHERE tenant_id = $X as the primary isolation mechanism. For operations that
	// need RLS session-variable enforcement, use shared/database.WithTenantContext()
	// which pins SET and queries to the same pooled connection.
	{
		// Registration management. Reads are JWT-scoped to tenant.
		sensorManager.POST("/sensors/pending", sharedrbac.RequireTenantPermission(db, rbac.PermissionSensorsCreate), handler.CreatePendingSensor)
		sensorManager.GET("/sensors/pending", handler.GetPendingSensors)
		sensorManager.DELETE("/sensors/pending/:key", sharedrbac.RequireTenantPermission(db, rbac.PermissionSensorsDelete), handler.DeletePendingSensor)

		// Fingerprint of the CA behind this platform's edge certificate, shown
		// beside a new registration key so the operator has a channel other
		// than the agent's own connection to verify it against. Tenant-scoped
		// auth only — the value is a public certificate fingerprint, identical
		// for every tenant, and carries nothing tenant-specific.
		sensorManager.GET("/platform-ca", handler.GetPlatformCA)

		// Admin settings (tenant-wide sensor admin defaults).
		sensorManager.GET("/admin/settings", handler.GetAdminSettings)
		sensorManager.PUT("/admin/settings", sharedrbac.RequireTenantPermission(db, rbac.PermissionSettingsUpdate), handler.UpdateAdminSettings)

		// Discovery orchestrator. CreateDiscoveryJob is user-initiated;
		// ReceiveDiscoveryResults is sensor-callback (JWT auth here is
		// legacy; the sensor-auth path is preferred for new callers).
		sensorManager.POST("/discovery/jobs", sharedrbac.RequireTenantPermission(db, rbac.PermissionDiscoveryCreate), handler.CreateDiscoveryJob)
		sensorManager.POST("/discovery/jobs/:id/results", handler.ReceiveDiscoveryResults)

		// PCAP upload endpoints (tenant RBAC)
		pcap := sensorManager.Group("/pcap")
		pcap.POST("/upload", sharedrbac.RequireTenantPermission(db, rbac.PermissionPcapUpload), handler.UploadPcap)
		pcap.GET("/jobs", sharedrbac.RequireTenantPermission(db, rbac.PermissionPcapRead), handler.ListPcapJobs)
		pcap.GET("/jobs/:id", sharedrbac.RequireTenantPermission(db, rbac.PermissionPcapRead), handler.GetPcapJob)
		pcap.DELETE("/jobs/:id", sharedrbac.RequireTenantPermission(db, rbac.PermissionPcapDelete), handler.DeletePcapJob)

		// Sensor management routes. Reads are JWT-scoped; writes are
		// permission-gated. Certificate rotation/revocation requires the
		// elevated sensors.manage permission since it can break a running
		// sensor's mTLS connection.
		sensorManager.GET("/sensors", handler.GetSensors)
		sensorManager.GET("/sensors/stats", handler.GetSensorStats)
		sensorManager.GET("/sensors/discovery-counts", handler.GetSensorDiscoveryCounts)
		sensorManager.GET("/sensors/:sensor_id", handler.GetSensor)
		sensorManager.PUT("/sensors/:sensor_id/status", sharedrbac.RequireTenantPermission(db, rbac.PermissionSensorsUpdate), handler.UpdateSensorStatus)
		sensorManager.DELETE("/sensors/:sensor_id", sharedrbac.RequireTenantPermission(db, rbac.PermissionSensorsDelete), handler.DeleteSensor)
		sensorManager.POST("/sensors/:sensor_id/commands", sharedrbac.RequireTenantPermission(db, rbac.PermissionSensorsUpdate), handler.CreateSensorCommand)
		sensorManager.GET("/sensors/:sensor_id/commands", handler.GetSensorCommands)
		sensorManager.GET("/sensors/:sensor_id/health", handler.GetSensorHealth)
		sensorManager.GET("/sensors/:sensor_id/health/history", handler.GetSensorHealthHistory)
		sensorManager.GET("/sensors/:sensor_id/discoveries", handler.GetSensorDiscoveries)

		// Sensor configuration endpoints
		sensorManager.PUT("/sensors/:sensor_id/interfaces", sharedrbac.RequireTenantPermission(db, rbac.PermissionSensorsUpdate), handler.UpdateSensorInterfaces)
		sensorManager.PUT("/sensors/:sensor_id/config", sharedrbac.RequireTenantPermission(db, rbac.PermissionSensorsUpdate), handler.UpdateSensorConfig)
		sensorManager.POST("/sensors/:sensor_id/regenerate-certificates", sharedrbac.RequireTenantPermission(db, rbac.PermissionSensorsManage), handler.RegenerateSensorCertificates)

		// Tenant-wide capture defaults (applies to all active sensors for the tenant)
		sensorManager.PUT("/admin/capture-defaults", sharedrbac.RequireTenantPermission(db, rbac.PermissionSettingsUpdate), handler.UpdateTenantCaptureDefaults)

		// Certificate management endpoints. Rotation is the sensor's own
		// autonomous renewal and lives on the SensorAuth group above; admins force
		// a fresh cert via regenerate-certificates. Revoke stays admin-gated.
		sensorManager.GET("/sensors/:sensor_id/certificate", handler.GetSensorCertificate)
		sensorManager.POST("/sensors/:sensor_id/certificates/revoke", sharedrbac.RequireTenantPermission(db, rbac.PermissionSensorsManage), handler.RevokeSensorCertificate)

	}

	// Platform-admin cross-tenant Fleet view (READ-ONLY). No tenant context:
	// platform admins roll up sensors across ALL tenants. Gated by the
	// platform-admin role check (mirrors device-interrogation-service's
	// /admin/* gate). This deliberately omits the tenant filter that isolates
	// the tenant-scoped /sensors list, so it MUST stay behind RequirePlatformAdmin.
	adminFleet := api.Group("/sensor-manager/admin")
	adminFleet.Use(middleware.RequirePlatformAuth(cfg.JWTSecret))
	adminFleet.Use(middleware.RequirePlatformAdmin())
	{
		adminFleet.GET("/sensors", handler.GetAdminSensors)
	}

	// Platform-level endpoints (no tenant context required, for monitoring service)
	platform := api.Group("/sensor-manager/platform")
	platform.Use(middleware.RequireAuth(cfg.JWTSecret))
	// These endpoints require platform.health permission
	platform.Use(sharedrbac.RequirePlatformPermission(db, rbac.PermissionPlatformHealth))
	{
		platform.GET("/sensor-stats", handler.GetPlatformSensorStats)
	}

	// Internal endpoints for service-to-service calls (HMAC; additionally protected by mTLS/network policy)
	internal := api.Group("/sensor-manager/internal")
	internal.Use(middleware.RequireInternalHMAC())
	{
		internal.POST("/pcap/jobs/:id/results", handler.UpdatePcapJobResults)
	}

	// Health check server (HTTP, port 8080)
	healthRouter := gin.New()
	healthRouter.GET("/health", handler.Health)

	port := cfg.Port
	if port == "" {
		port = "8080"
	}

	healthServer := &http.Server{
		Addr:              ":" + port,
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
			Addr:              ":" + port,
			Handler:           router,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
	}

	// Sensor-mTLS passthrough listener (port 8444). When SensorMTLSRequired,
	// sensors reach /sensors/:sensor_id/{heartbeat,commands/poll,...} via edge
	// TLS passthrough so their per-tenant client cert terminates here. This
	// listener requires a client cert (RequireAnyClientCert); SensorAuth
	// verifies it against the sensor's tenant CA. Kept separate from the 8443
	// mesh listener, which verifies against the Platform CA and would reject
	// per-tenant sensor certs at the handshake.
	var agentServer *http.Server
	if cfg.SensorMTLSRequired {
		agentServer, err = sharedhttp.NewAgentMTLSServer(cfg.ServiceCertPath, cfg.ServiceKeyPath, router)
		if err != nil {
			log.Fatalf("Failed to create sensor-mTLS server: %v", err)
		}
		agentServer.Addr = ":" + cfg.AgentTLSPort
	}

	// Start health check server (only when mTLS is enabled - API server on different port)
	// When mTLS is disabled, API server includes /health endpoint on same port
	if cfg.UseMTLS {
		go func() {
			log.Printf("Health check server starting on port %s", port)
			if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start health server: %v", err)
			}
		}()
	}

	// Start sensor-mTLS listener
	if agentServer != nil {
		go func() {
			log.Printf("🔐 Sensor Manager sensor-mTLS listener starting on port %s (passthrough, client cert required)", cfg.AgentTLSPort)
			if err := agentServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start sensor-mTLS listener: %v", err)
			}
		}()
	}

	// Start API server
	go func() {
		if cfg.UseMTLS {
			log.Printf("🚀 Sensor Manager API server starting on port %s (mTLS)", cfg.TLSPort)
			log.Printf("📡 Ready to manage network sensors")
			if err := apiServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		} else {
			log.Printf("🚀 Sensor Manager API server starting on port %s (HTTP fallback)", port)
			log.Printf("📡 Ready to manage network sensors")
			if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down sensor-manager...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown both servers
	if err := healthServer.Shutdown(ctx); err != nil {
		log.Printf("Health server forced to shutdown: %v", err)
	}
	if err := apiServer.Shutdown(ctx); err != nil {
		log.Printf("API server forced to shutdown: %v", err)
	}
	if agentServer != nil {
		if err := agentServer.Shutdown(ctx); err != nil {
			log.Printf("Sensor-mTLS listener forced to shutdown: %v", err)
		}
	}

	log.Println("sensor-manager stopped")
}
