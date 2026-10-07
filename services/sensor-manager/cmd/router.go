package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/handlers"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/middleware"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	resourcetracking "github.com/vistasecurity/vistaplatform/shared/middleware/resource-tracking"
	trial_lock "github.com/vistasecurity/vistaplatform/shared/middleware/trial_lock"
	rbac "github.com/vistasecurity/vistaplatform/shared/rbac"
)

// setupRouter builds the service's gin engine and returns, beside it, the
// route surface of the sensor-mTLS passthrough listener: exactly the
// SensorAuth routes a sensor calls once it holds its client certificate.
// Everything else on the engine (registration, the tenant API, the
// platform-admin and platform routes, the HMAC internal routes, /health)
// answers 404 on that listener. TCP passthrough skips every edge deny, so this
// list is the only thing standing between a self-signed client certificate and
// those routes (pentest-readiness D2).
func setupRouter(cfg *config.Config, handler *handlers.Handler, db, bypassDB *sql.DB) (*gin.Engine, *sharedhttp.AgentRoutes) {
	agentRoutes := sharedhttp.NewAgentRoutes()

	router := gin.Default()

	// FIRST, before any route: confines the sensor-mTLS listener to
	// agentRoutes (a no-op on the mesh/HTTP listener). gin copies global
	// middleware into a route when the route is registered, so a route added
	// above this line would be unguarded.
	router.Use(sharedhttp.AgentListenerGuard)

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
		agentRoutes.POST(sensors, "/heartbeat", handler.Heartbeat)
		// Polling endpoint moved to avoid duplicate with management GET /sensors/:sensor_id/commands
		agentRoutes.GET(sensors, "/commands/poll", handler.PollCommands)
		agentRoutes.POST(sensors, "/commands/:command_id/ack", handler.AcknowledgeCommand)
		agentRoutes.GET(sensors, "/webhook-config", handler.GetWebhookConfig)

		// Discovery submission. A dispatched discovery job's results come in
		// here too — tagged discovery_method=active and carrying the job_id —
		// so they flow StoreDiscoveries → sensor_discoveries → discovery-
		// processor exactly like passive data.
		agentRoutes.POST(sensors, "/discoveries", handler.SubmitDiscoveries)

		// Dispatched discovery job completion. Sensor-authenticated,
		// because the sensor is the caller: it marks the job the platform
		// handed it as completed/failed with counts. The results themselves
		// travelled through /discoveries above.
		agentRoutes.POST(sensors, "/discovery-jobs/:job_id/complete", handler.CompleteDiscoveryJob)

		// A planned scan's per-host reports ( WP2b): each host the
		// sensor finishes, stored as the job's work unit, and an empty batch
		// as the progress ping that keeps the job's lease. The answer tells
		// the sensor to stop when the job was cancelled or has ended.
		agentRoutes.POST(sensors, "/discovery-jobs/:job_id/units", handler.ReportDiscoveryJobUnits)

		// Autonomous certificate rotation (sensor renews its own cert before
		// expiry). Sensor-authenticated, NOT tenant-JWT — this is what the sensor
		// binary's pre-expiry renewal loop calls. Was previously mis-registered on
		// the tenant-admin group below and 401'd every renewal.
		agentRoutes.POST(sensors, "/certificates/rotate", handler.RotateSensorCertificate)

		// Air-gapped export
		agentRoutes.POST(sensors, "/exports", handler.SubmitAirGappedExport)

		// Legacy endpoints (for backward compatibility)
		agentRoutes.POST(sensors, "/health", handler.ReportHealth)
		agentRoutes.GET(sensors, "/config", handler.GetSensorConfig)
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
		registerPendingSensorRoutes(sensorManager, db, handler.CreatePendingSensor, handler.GetPendingSensors, handler.DeletePendingSensor)

		// Fingerprint of the CA behind this platform's edge certificate, shown
		// beside a new registration key so the operator has a channel other
		// than the agent's own connection to verify it against. Tenant-scoped
		// auth only — the value is a public certificate fingerprint, identical
		// for every tenant, and carries nothing tenant-specific.
		sensorManager.GET("/platform-ca", handler.GetPlatformCA)

		// REMOVED: GET/PUT /admin/settings. The PUT overwrote a process-global
		// struct (pending-key cap, key lifetime, address validation) that every
		// tenant's registration reads, so any tenant holding settings.update
		// reconfigured every other tenant; no client called either route. The
		// limits are now fixed (handlers.currentRegistrationLimits). Do not
		// re-add a write without tenant-scoped storage.

		// REMOVED: POST /discovery/jobs and POST /discovery/jobs/:id/results.
		//
		// The first was a second, inert way to create a discovery job — a
		// queued discovery_jobs row with no targets that nothing dispatched.
		// The second was the tenant-JWT results intake a sensor could never
		// call (sensors authenticate by mTLS/HMAC on the `sensors` group, not
		// by a user's JWT), which wrote discovery_findings but never
		// sensor_discoveries — so even a caller that reached it produced
		// results inventory never saw. Discovery jobs are created through
		// inventory-service (POST /api/v1/inventory-service/discovery/jobs),
		// a dispatched job's results arrive through the sensor's ordinary
		// POST /sensors/:sensor_id/discoveries batch route, and its completion
		// through POST /sensors/:sensor_id/discovery-jobs/:job_id/complete
		// above.

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

		// Desired-state configuration. Distinct from the
		// UpdateSensorConfig route above, which queues a one-shot command and
		// persists nothing: these record what the sensor SHOULD be and
		// reconcile it against what the sensor reports.
		//
		// Gated on sensors.read to view and sensors.update to change — the line
		// this repo already draws between configuration and destructive or
		// credential operations, and the same gating the agent routes use, so
		// one fleet on one page has one permission model.
		sensorConfig := handlers.NewSensorConfigHandler(db)
		sensorManager.GET("/sensors/config/defaults", sharedrbac.RequireTenantPermission(db, rbac.PermissionSensorsRead), sensorConfig.GetSensorFleetDefaults)
		sensorManager.PUT("/sensors/config/defaults", sharedrbac.RequireTenantPermission(db, rbac.PermissionSensorsUpdate), sensorConfig.PutSensorFleetDefaults)
		sensorManager.GET("/sensors/:sensor_id/desired-config", sharedrbac.RequireTenantPermission(db, rbac.PermissionSensorsRead), sensorConfig.GetSensorDesiredConfig)
		sensorManager.PUT("/sensors/:sensor_id/desired-config", sharedrbac.RequireTenantPermission(db, rbac.PermissionSensorsUpdate), sensorConfig.PutSensorDesiredConfig)
		// A read of configuration, gated like the other reads: the operator most
		// likely to ask "why is this on" is the one who cannot change it.
		sensorManager.GET("/sensors/:sensor_id/desired-config/history", sharedrbac.RequireTenantPermission(db, rbac.PermissionSensorsRead), sensorConfig.GetSensorConfigHistory)

		// Certificate management endpoints. Rotation is the sensor's own
		// autonomous renewal and lives on the SensorAuth group above; admins force
		// a fresh cert via regenerate-certificates. Revoke stays admin-gated.
		sensorManager.GET("/sensors/:sensor_id/certificate", handler.GetSensorCertificate)
		sensorManager.POST("/sensors/:sensor_id/certificates/revoke", sharedrbac.RequireTenantPermission(db, rbac.PermissionSensorsManage), handler.RevokeSensorCertificate)

	}

	// Platform-admin cross-tenant Fleet view (READ-ONLY) — see
	// registerAdminFleetRoutes for the gate.
	registerAdminFleetRoutes(api, cfg.JWTSecret, db, handler.GetAdminSensors)

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

	return router, agentRoutes
}

// newSensorMTLSServer builds the sensor-mTLS passthrough listener: router
// confined to agentRoutes, behind a handshake that requires a client
// certificate (SensorAuth verifies it).
func newSensorMTLSServer(cfg *config.Config, router *gin.Engine, agentRoutes *sharedhttp.AgentRoutes) (*http.Server, error) {
	srv, err := sharedhttp.NewAgentMTLSServer(cfg.ServiceCertPath, cfg.ServiceKeyPath, router, agentRoutes)
	if err != nil {
		return nil, err
	}
	srv.Addr = ":" + cfg.AgentTLSPort
	return srv, nil
}
