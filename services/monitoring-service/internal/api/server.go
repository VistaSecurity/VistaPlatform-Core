package api

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/config"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/middleware"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/models"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/services"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	rbac "github.com/vistasecurity/vistaplatform/shared/rbac"
	"github.com/vistasecurity/vistaplatform/shared/version"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Server struct {
	config            *config.Config
	db                *sql.DB
	healthService     healthStatusProvider
	healthStore       healthStore
	metricsService    metricsProvider
	logStorageService *services.LogStorageService
	alertingService   alertingProvider
}

func NewServer(cfg *config.Config, db, bypassDB *sql.DB, healthService *services.HealthService, metricsService *services.MetricsService, logStorageService *services.LogStorageService, alertingService *services.AlertingService) *Server {
	return &Server{
		config:            cfg,
		db:                db,
		healthService:     healthService,
		healthStore:       newHealthStore(db, bypassDB),
		metricsService:    metricsService,
		logStorageService: logStorageService,
		alertingService:   alertingService,
	}
}

// newServerWithHealth builds a Server with just the health dependencies the
// tenant /status handlers need. It exists so those handlers can be driven
// against in-memory stubs in the contract test (ADR-0001); production wiring
// goes through NewServer.
func newServerWithHealth(healthService healthStatusProvider, store healthStore) *Server {
	return &Server{
		healthService: healthService,
		healthStore:   store,
	}
}

// newServerWithAlerting builds a Server with just the alerting dependency the
// platform alerting handlers need. It exists so those handlers can be driven
// against an in-memory stub in the contract test (ADR-0001); production wiring
// goes through NewServer.
func newServerWithAlerting(alertingService alertingProvider) *Server {
	return &Server{alertingService: alertingService}
}

// newServerWithMetrics builds a Server with just the metrics dependency the
// trends handler needs (contract test seam; production wiring is NewServer).
func newServerWithMetrics(metricsService metricsProvider) *Server {
	return &Server{metricsService: metricsService}
}

// newServerWithHealthAndMetrics builds a Server for the admin-status handler,
// which overlays platform metrics on the health snapshot.
func newServerWithHealthAndMetrics(healthService healthStatusProvider, metricsService metricsProvider) *Server {
	return &Server{healthService: healthService, metricsService: metricsService}
}

func (s *Server) Start(addr string) error {
	// Set Gin mode
	if s.config.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create router
	router := gin.New()

	// Middleware
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(sharedmw.SecurityHeaders())

	// CORS is handled by Traefik API gateway - no need for duplicate headers

	// Health check endpoint. Includes version info so the About-page
	// aggregator (and operators tail-curling /health) can spot version
	// skew across the running deployment in one glance.
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "monitoring-service",
			"version": version.Get(),
		})
	})

	// API routes
	api := router.Group("/api/v1")
	{
		// Status endpoints for tenant UI
		status := api.Group("/monitoring-service/status")
		// Apply authentication middleware to tenant status routes
		status.Use(middleware.RequireAuth(s.config.JWTSecret), middleware.StringifyUserID())
		status.Use(middleware.RequireTenant())
		{
			status.GET("/system", s.getSystemStatus)
			status.GET("/metrics", s.getSystemMetrics)
			status.GET("/health/overview", s.getHealthOverview)
			status.GET("/services/:name", s.getServiceStatus)
			status.GET("/incidents", s.getIncidentHistory)
		}

		// Admin status endpoints
		admin := api.Group("/admin-service/status")
		// Apply authentication middleware to admin status routes
		admin.Use(middleware.RequireAuth(s.config.JWTSecret), middleware.StringifyUserID())
		// Note: Admin routes don't require tenant context as they're platform-level
		{
			admin.GET("/system", s.getAdminSystemStatus)
			admin.GET("/metrics", s.getAdminSystemMetrics)
			admin.GET("/tenants", s.getTenantStatuses)
			admin.GET("/tenants/:id", s.getTenantStatus)
			admin.GET("/services/:name", s.getServiceStatus)
			admin.GET("/incidents", s.getIncidentHistory)
			admin.GET("/monitoring", s.getMonitoringData)
		}

		// Platform metrics endpoints - For admin-service dashboard consumption
		// These endpoints require platform.analytics or platform.health permissions
		platform := api.Group("/monitoring-service/platform")
		platform.Use(middleware.RequirePlatformAuth(s.config.JWTSecret), middleware.StringifyUserID())
		platform.Use(sharedrbac.RequireAnyPlatformPermission(s.db, rbac.PermissionPlatformAnalytics, rbac.PermissionPlatformHealth))
		// Note: Platform routes don't require tenant context as they're platform-level
		{
			platform.GET("/summary", s.getPlatformSummary)
			platform.GET("/services/:name", s.getPlatformServiceMetrics)
			platform.GET("/incidents", s.getPlatformIncidents)
			platform.GET("/uptime", s.getPlatformUptime)
		}

		// Compliance logging endpoints - Phase 2.2
		// These endpoints require platform.logs.read permission
		logs := api.Group("/monitoring-service/logs")
		logs.Use(middleware.RequirePlatformAuth(s.config.JWTSecret), middleware.StringifyUserID())
		logs.Use(sharedrbac.RequirePlatformPermission(s.db, rbac.PermissionPlatformLogsRead))
		{
			logs.GET("", s.getLogs)                       // GET /monitoring-service/logs - List logs with pagination
			logs.GET("/:id", s.getLog)                    // GET /monitoring-service/logs/:id - Get single log with signed URL
			logs.GET("/siem/export", s.exportLogsForSIEM) // GET /monitoring-service/logs/siem/export - Export logs in SIEM format
		}

		// Alerting endpoints - Phase 1.5
		// These endpoints require platform.health permission
		alerting := api.Group("/monitoring-service/alerting")
		alerting.Use(middleware.RequirePlatformAuth(s.config.JWTSecret), middleware.StringifyUserID())
		alerting.Use(sharedrbac.RequirePlatformPermission(s.db, rbac.PermissionPlatformHealth))
		{
			alerting.GET("/thresholds", s.GetAlertThresholds)          // GET /monitoring-service/alerting/thresholds - List alert thresholds
			alerting.GET("/thresholds/:id", s.GetAlertThreshold)       // GET /monitoring-service/alerting/thresholds/:id - Get single threshold
			alerting.POST("/thresholds", s.CreateAlertThreshold)       // POST /monitoring-service/alerting/thresholds - Create threshold
			alerting.PUT("/thresholds/:id", s.UpdateAlertThreshold)    // PUT /monitoring-service/alerting/thresholds/:id - Update threshold
			alerting.DELETE("/thresholds/:id", s.DeleteAlertThreshold) // DELETE /monitoring-service/alerting/thresholds/:id - Delete threshold
			alerting.GET("/history", s.GetAlertHistory)                // GET /monitoring-service/alerting/history - Get alert history
		}

		// Historical trends endpoints - Phase 1.5
		// These endpoints require platform.health permission
		trends := api.Group("/monitoring-service/trends")
		trends.Use(middleware.RequirePlatformAuth(s.config.JWTSecret), middleware.StringifyUserID())
		trends.Use(sharedrbac.RequirePlatformPermission(s.db, rbac.PermissionPlatformHealth))
		{
			trends.GET("", s.GetHistoricalTrends) // GET /monitoring-service/trends - Get historical trends
		}

		// Gateway proxy endpoints — serve Traefik dashboard API data server-side to avoid
		// browser CORS restrictions. Protected by platform.health permission.
		gateway := api.Group("/monitoring-service/gateway")
		gateway.Use(middleware.RequirePlatformAuth(s.config.JWTSecret), middleware.StringifyUserID())
		gateway.Use(sharedrbac.RequirePlatformPermission(s.db, rbac.PermissionPlatformHealth))
		{
			gateway.GET("/overview", s.getGatewayOverview)
			gateway.GET("/routers", s.getGatewayRouters)
			gateway.GET("/services", s.getGatewayServices)
			gateway.GET("/middlewares", s.getGatewayMiddlewares)
		}

		// Admin platform status — reachable via gateway under /monitoring-service prefix.
		// Returns live service health (GetSystemStatus) without requiring tenant context.
		// NOTE: The /admin-service/status/... routes above are NOT dead code (an
		// earlier version of this comment said so): the registry's admin_plane
		// service_overrides deliberately routes /admin-service/status/** to THIS
		// service, and the admin host serves it. They carry only RequireAuth —
		// the tenant-host deny is the control keeping their cross-tenant data
		// off the public host. This group is the same data on the conventional
		// /monitoring-service prefix, with the platform gate applied directly.
		adminStatus := api.Group("/monitoring-service/admin")
		adminStatus.Use(middleware.RequirePlatformAuth(s.config.JWTSecret), middleware.StringifyUserID())
		{
			adminStatus.GET("/status", s.getAdminSystemStatus)
			adminStatus.GET("/metrics", s.getAdminSystemMetrics)
		}

		// Tenant performance endpoints - For tenant health service
		tenantMetrics := api.Group("/monitoring-service/tenant")
		tenantMetrics.Use(middleware.RequireAuth(s.config.JWTSecret), middleware.StringifyUserID())
		// Note: These routes are for admin platform use, not tenant UI
		{
			tenantMetrics.GET("/:id/performance-summary", s.getTenantPerformanceSummary)
		}

		// Version aggregator for the web-UI About page. Any authenticated
		// user (tenant or platform admin) can read this — version info is
		// not sensitive and the About page exists so any user can answer
		// "what version am I on?" without admin-side access. The handler
		// fans out to every Go service's /health and computes alignment.
		api.GET("/monitoring-service/version",
			middleware.RequireAuth(s.config.JWTSecret),
			middleware.StringifyUserID(),
			NewVersionAggregator(s.peerServiceURLs(), s.peerVersionClient()).Handle,
		)
	}

	// Health check server (HTTP, port 8080)
	healthRouter := gin.New()
	healthRouter.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "monitoring-service",
			"version": version.Get(),
		})
	})

	healthServer := &http.Server{
		Addr:              addr,
		Handler:           healthRouter,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// API server (HTTPS with mTLS, port 8443)
	var apiServer *http.Server
	if s.config.UseMTLS {
		var err error
		apiServer, err = sharedhttp.NewMTLSServer(
			s.config.ServiceCertPath,
			s.config.ServiceKeyPath,
			s.config.PlatformCACertPath,
			router,
		)
		if err != nil {
			return err
		}
		apiServer.Addr = ":" + s.config.TLSPort
		apiServer.ReadHeaderTimeout = 5 * time.Second
		apiServer.ReadTimeout = 10 * time.Second
		apiServer.WriteTimeout = 15 * time.Second
		apiServer.IdleTimeout = 60 * time.Second
	} else {
		// Fallback to HTTP if mTLS disabled
		apiServer = &http.Server{
			Addr:              addr,
			Handler:           router,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
	}

	// Start health check server (only when mTLS is enabled - API server on different port)
	// When mTLS is disabled, API server includes /health endpoint on same port
	if s.config.UseMTLS {
		go func() {
			log.Printf("Health check server starting on %s", addr)
			if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start health server: %v", err)
			}
		}()
	}

	// Start API server
	go func() {
		if s.config.UseMTLS {
			log.Printf("Monitoring service API server starting on :%s (mTLS)", s.config.TLSPort)
			if err := apiServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		} else {
			log.Printf("Monitoring service API server starting on %s (HTTP - includes /health)", addr)
			if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down monitoring service...")

	// Give outstanding requests 30 seconds to complete
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown both servers
	if err := healthServer.Shutdown(ctx); err != nil {
		log.Printf("Health server forced to shutdown: %v", err)
	}
	if err := apiServer.Shutdown(ctx); err != nil {
		log.Printf("API server forced to shutdown: %v", err)
	}

	return nil
}

// peerServiceURLs returns the Go-service base URLs the version aggregator
// fans out to. The source is the runtime services map, but it's filtered
// and patched:
//
//   - Infra entries (postgres/redis/influxdb/nats/grafana) and the gateway
//     don't expose a VistaPlatform-style /health response — including them
//     would just clutter the About page with "unreachable" rows.
//   - The config map historically omits monitoring-service (self) and
//     pcap-processor. Both expose /health on port 8080 like every other
//     Go service, so we add them here using their in-cluster Service DNS
//     names. This keeps the About page accurate without forcing every
//     deployment profile to re-declare them in the monitoring config.
func (s *Server) peerServiceURLs() map[string]string {
	skip := map[string]bool{
		"postgres":    true,
		"redis":       true,
		"influxdb":    true,
		"nats":        true,
		"grafana":     true,
		"api-gateway": true,
	}
	out := make(map[string]string, len(s.config.Services)+2)
	for name, svc := range s.config.Services {
		if skip[name] || !svc.Enabled {
			continue
		}
		out[name] = svc.URL
	}
	// Self + the two services missing from the legacy config map. Probing
	// self via the in-cluster DNS name (rather than localhost) keeps the
	// aggregator's response shape consistent — every row goes through the
	// same HTTP path.
	if _, ok := out["monitoring-service"]; !ok {
		out["monitoring-service"] = sharedconfig.PeerURL("monitoring-service", sharedconfig.MTLSEnabled())
	}
	if _, ok := out["pcap-processor"]; !ok {
		out["pcap-processor"] = sharedconfig.PeerURL("pcap-processor", sharedconfig.MTLSEnabled())
	}
	return out
}

// peerVersionClient builds the HTTP client the version aggregator uses to probe
// peers. Under mTLS the peer URLs are https://<svc>:8443 (the mTLS listener),
// so the probe MUST present this service's client certificate and trust the
// platform CA — exactly like every other service-to-service call (cf.
// jobs.NewAlertEvaluator). A plain client would fail the handshake on every
// probe and render the whole fleet "unreachable" on the About page.
//
// If mTLS is on but the certs can't be loaded, we log and fall back to a plain
// client: the page will (correctly) show peers as unreachable rather than the
// service failing to start over a diagnostics endpoint.
func (s *Server) peerVersionClient() *http.Client {
	const probeTimeout = 3 * time.Second
	if !sharedconfig.MTLSEnabled() {
		return &http.Client{Timeout: probeTimeout}
	}
	client, err := sharedhttp.NewMTLSClient(
		s.config.ClientCertPath,
		s.config.ClientKeyPath,
		s.config.PlatformCACertPath,
	)
	if err != nil {
		log.Printf("[version-aggregator] mTLS client init failed (%v); peers on the mTLS listener will read unreachable", err)
		return &http.Client{Timeout: probeTimeout}
	}
	client.Timeout = probeTimeout
	return client
}

func (s *Server) getSystemStatus(c *gin.Context) {
	status := s.healthService.GetSystemStatus()
	c.JSON(http.StatusOK, status)
}

func (s *Server) getSystemMetrics(c *gin.Context) {
	status := s.healthService.GetSystemStatus()
	c.JSON(http.StatusOK, status.Metrics)
}

func (s *Server) getServiceStatus(c *gin.Context) {
	serviceName := c.Param("name")

	// Get service status from health service
	status := s.healthService.GetSystemStatus()

	for _, service := range status.Services {
		if service.Name == serviceName {
			c.JSON(http.StatusOK, service)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})
}

func (s *Server) getIncidentHistory(c *gin.Context) {
	// For now, return empty incident history
	// This could be expanded to query a incidents table
	c.JSON(http.StatusOK, []interface{}{})
}

func (s *Server) getHealthOverview(c *gin.Context) {
	// Get system status
	systemStatus := s.healthService.GetSystemStatus()

	// Get sensor stats by querying the sensors table directly
	// Note: This is acceptable for monitoring service since it's responsible for
	// aggregating system health metrics across all services
	var sensorStats struct {
		ActiveSensors int `json:"active_sensors"`
		TotalSensors  int `json:"total_sensors"`
	}

	active, total, err := s.healthStore.GetSensorStats()
	if err != nil {
		// Log error but don't fail - sensor stats are optional
		log.Printf("Warning: Failed to fetch sensor stats: %v", err)
		active, total = 0, 0
	}
	sensorStats.ActiveSensors = active
	sensorStats.TotalSensors = total

	// Determine overall status
	overallStatus := systemStatus.OverallStatus
	if overallStatus == "" {
		overallStatus = "healthy"
		if systemStatus.Metrics.DownServices > 0 {
			overallStatus = "degraded"
		}
		if systemStatus.Metrics.DownServices > systemStatus.Metrics.HealthyServices {
			overallStatus = "down"
		}
	}

	// Check database health
	dbHealthy := true
	if err := s.healthStore.PingDB(); err != nil {
		dbHealthy = false
		if overallStatus == "healthy" {
			overallStatus = "degraded"
		}
	}

	// Map service statuses to the expected format
	serviceStatuses := make([]models.SystemHealthOverviewService, len(systemStatus.Services))
	for i, svc := range systemStatus.Services {
		serviceStatuses[i] = models.SystemHealthOverviewService{
			Name:           svc.Name,
			Status:         models.ServiceStatusType(svc.Status),
			ResponseTimeMs: svc.ResponseTime,
			LastChecked:    svc.LastChecked.Format(time.RFC3339),
		}
	}

	dbStatus := models.ServiceStatusType("healthy")
	dbMessage := ""
	if !dbHealthy {
		dbStatus = models.ServiceStatusType("down")
		dbMessage = "Database connection failed"
	}

	c.JSON(http.StatusOK, models.SystemHealthOverview{
		OverallStatus: models.OverallStatusType(overallStatus),
		Sensors: models.SystemHealthOverviewSensors{
			Active: sensorStats.ActiveSensors,
			Total:  sensorStats.TotalSensors,
		},
		Services: serviceStatuses,
		Database: models.SystemHealthOverviewDatabase{
			Status:  dbStatus,
			Message: dbMessage,
		},
		LastUpdated: time.Now().Format(time.RFC3339),
	})
}

func (s *Server) getAdminSystemStatus(c *gin.Context) {
	status := s.healthService.GetSystemStatus()

	// Add platform metrics
	platformMetrics, err := s.metricsService.GetPlatformMetrics()
	if err == nil {
		status.Metrics.TotalTenants = platformMetrics.TotalTenants
		status.Metrics.ActiveTenants = platformMetrics.ActiveTenants
		status.Metrics.TotalUsers = platformMetrics.TotalUsers
		status.Metrics.TotalAssets = platformMetrics.TotalAssets
	}

	c.JSON(http.StatusOK, status)
}

func (s *Server) getAdminSystemMetrics(c *gin.Context) {
	status := s.healthService.GetSystemStatus()

	// Add platform metrics
	platformMetrics, err := s.metricsService.GetPlatformMetrics()
	if err == nil {
		status.Metrics.TotalTenants = platformMetrics.TotalTenants
		status.Metrics.ActiveTenants = platformMetrics.ActiveTenants
		status.Metrics.TotalUsers = platformMetrics.TotalUsers
		status.Metrics.TotalAssets = platformMetrics.TotalAssets
	}

	c.JSON(http.StatusOK, status.Metrics)
}

func (s *Server) getTenantStatuses(c *gin.Context) {
	tenants, err := s.healthService.GetTenantStatuses()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, tenants)
}

func (s *Server) getTenantStatus(c *gin.Context) {
	tenantID := c.Param("id")

	tenants, err := s.healthService.GetTenantStatuses()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	for _, tenant := range tenants {
		if tenant.TenantID == tenantID {
			c.JSON(http.StatusOK, tenant)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
}

func (s *Server) getMonitoringData(c *gin.Context) {
	// For now, return basic monitoring data
	// This could be expanded to query InfluxDB for time-series data
	c.JSON(http.StatusOK, gin.H{
		"message": "Monitoring data endpoint - integrate with InfluxDB for time-series data",
	})
}

// getPlatformSummary returns aggregated platform metrics summary
func (s *Server) getPlatformSummary(c *gin.Context) {
	// Default to last 24 hours
	endTime := time.Now()
	startTime := endTime.Add(-24 * time.Hour)

	// Parse optional query parameters
	if startStr := c.Query("start"); startStr != "" {
		if parsed, err := time.Parse(time.RFC3339, startStr); err == nil {
			startTime = parsed
		}
	}
	if endStr := c.Query("end"); endStr != "" {
		if parsed, err := time.Parse(time.RFC3339, endStr); err == nil {
			endTime = parsed
		}
	}

	summary, err := s.metricsService.GetPlatformMetricsSummary(startTime, endTime)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get platform metrics summary",
		})
		return
	}

	c.JSON(http.StatusOK, summary)
}

// getPlatformServiceMetrics returns detailed metrics for a specific service
func (s *Server) getPlatformServiceMetrics(c *gin.Context) {
	serviceName := c.Param("name")

	// Parse window parameter (default to 1 hour)
	window := time.Hour
	if windowStr := c.Query("window"); windowStr != "" {
		switch windowStr {
		case "1m":
			window = time.Minute
		case "1h":
			window = time.Hour
		case "1d":
			window = 24 * time.Hour
		default:
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid window parameter. Must be '1m', '1h', or '1d'",
			})
			return
		}
	}

	metrics, err := s.metricsService.GetServiceMetrics(serviceName, window)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get service metrics",
		})
		return
	}

	c.JSON(http.StatusOK, metrics)
}

// getPlatformIncidents returns recent incidents
func (s *Server) getPlatformIncidents(c *gin.Context) {
	limit := 100
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	incidents, err := s.metricsService.GetIncidentHistory(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get incident history",
		})
		return
	}

	c.JSON(http.StatusOK, incidents)
}

// getPlatformUptime returns system uptime statistics
func (s *Server) getPlatformUptime(c *gin.Context) {
	stats, err := s.metricsService.GetUptimeStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get uptime stats",
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// getTenantPerformanceSummary returns performance metrics for a specific tenant
func (s *Server) getTenantPerformanceSummary(c *gin.Context) {
	tenantIDStr := c.Param("id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	summary, err := s.metricsService.GetTenantPerformanceSummary(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get tenant performance summary",
		})
		return
	}

	c.JSON(http.StatusOK, summary)
}
