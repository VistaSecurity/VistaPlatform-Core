package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/config"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/database"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/middleware"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/registration"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/services"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	trial_lock "github.com/vistasecurity/vistaplatform/shared/middleware/trial_lock"
	"github.com/vistasecurity/vistaplatform/shared/version"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Connect to database
	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Connect the BYPASSRLS (crypto_bypass) handle used by the deliberately
	// cross-tenant paths annotated `// RLS: cross-tenant — runs on the bypass
	// role (Phase 4)` (the pollForStuckJobs sweep and the job-id-keyed
	// GetJob/UpdateJobStatus/GetJobResults, where no tenant is threaded). It
	// reads BYPASS_DATABASE_URL and falls back to DATABASE_URL when unset, so
	// this is behavior-neutral until the role split is flipped. This service is
	// sqlx-based, so wrap the *sql.DB.
	bypassSQLDB, err := shareddatabase.ConnectBypass()
	if err != nil {
		log.Fatalf("Failed to connect bypass database: %v", err)
	}
	bypassDB := sqlx.NewDb(bypassSQLDB, "postgres")
	defer func() { _ = bypassDB.Close() }()

	// Initialize services
	discoveryService := services.NewDiscoveryService(db, bypassDB)
	rateLimiter := services.NewRateLimiter(db)
	alertService, err := services.NewAlertService(db, cfg)
	if err != nil {
		log.Fatalf("Failed to create alert service: %v", err)
	}

	// Initialize shared NATS client
	natsClient, err := events.NewNATSClient("")
	if err != nil {
		log.Printf("Warning: Failed to connect to NATS: %v. Job processing will be unavailable.", err)
	}
	defer func() {
		if natsClient != nil {
			natsClient.Close()
		}
	}()

	// Wire NATS to AlertService for event-driven notification publishing
	if natsClient != nil {
		alertService.SetNATSClient(natsClient)
		log.Println("NATS client wired to AlertService for notification publishing")
	}

	// Initialize handlers
	discoveryHandler := handlers.NewDiscoveryHandler(discoveryService, rateLimiter, alertService, natsClient)

	// Set Gin mode
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize router
	router := gin.Default()

	// Audit logging middleware
	auditConfig := auditmiddleware.DefaultConfig()
	auditConfig.ServiceName = "cluster-sensor-service"
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
	router.GET("/health", discoveryHandler.Health)

	// API routes
	api := router.Group("/api/v1")
	discovery := api.Group("/discovery")

	// Apply authentication middleware to all discovery routes
	discovery.Use(middleware.RequireAuth(cfg.JWTSecret))
	discovery.Use(middleware.RequireTenant())
	// Trial-lock middleware gates writes when the calling tenant is in
	// PhaseLocked. Discovery job dispatch in particular is a paid feature
	// path locked tenants shouldn't reach.
	discovery.Use(trial_lock.Middleware(db.DB, nil))
	{
		// Job management
		discovery.POST("/jobs", discoveryHandler.CreateJob)
		discovery.GET("/jobs", discoveryHandler.GetJobs)
		discovery.GET("/jobs/:id", discoveryHandler.GetJob)
		discovery.POST("/jobs/:id/cancel", discoveryHandler.CancelJob)
		discovery.POST("/jobs/:id/retry", discoveryHandler.RetryJob)
		discovery.GET("/jobs/:id/status", discoveryHandler.GetJobStatus)

		// Results management
		discovery.GET("/jobs/:id/results", discoveryHandler.GetJobResults)
		discovery.POST("/jobs/:id/approve", discoveryHandler.ApproveResults)
		discovery.POST("/jobs/:id/reject", discoveryHandler.RejectResults)

		// Approval queue
		discovery.GET("/approvals", discoveryHandler.GetApprovalQueue)
		discovery.POST("/approvals/bulk-approve", discoveryHandler.BulkApprove)
		discovery.POST("/approvals/bulk-reject", discoveryHandler.BulkReject)

		// Configuration
		discovery.GET("/config/rate-limits", discoveryHandler.GetRateLimits)
		discovery.PUT("/config/rate-limits", discoveryHandler.UpdateRateLimits)
		discovery.GET("/config/alerts", discoveryHandler.GetAlertConfigs)
		discovery.PUT("/config/alerts", discoveryHandler.UpdateAlertConfigs)
	}

	// Health check server (HTTP, port 8080)
	healthRouter := gin.New()
	healthRouter.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "cluster-sensor-service",
			"version": version.Get(),
		})
	})

	healthServer := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      healthRouter,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
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
		apiServer.Addr = ":" + cfg.TLSPort
		apiServer.ReadTimeout = 30 * time.Second
		apiServer.WriteTimeout = 30 * time.Second
		apiServer.IdleTimeout = 120 * time.Second
	} else {
		// Fallback to HTTP if mTLS disabled
		apiServer = &http.Server{
			Addr:         ":" + cfg.Port,
			Handler:      router,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
		}
	}

	// Start background job processor
	jobProcessor := services.NewJobProcessor(db, bypassDB, discoveryService, rateLimiter, alertService, natsClient)
	go jobProcessor.Start()

	// Auto-register platform sensor for all tenants (using bootstrap mTLS).
	// Skip silently if the bootstrap cert isn't mounted — that's the normal state
	// for K8s deploys that haven't pre-staged tenant mTLS material. The sensor still
	// runs; auto-register is a convenience, not a requirement.
	bootstrapCertReady := db != nil && cfg.BootstrapCertPath != ""
	if bootstrapCertReady {
		if _, statErr := os.Stat(cfg.BootstrapCertPath); statErr != nil {
			if os.IsNotExist(statErr) {
				log.Printf("ℹ️  Bootstrap cert not present at %s; skipping auto-registration (sensor still runs, register tenants manually via the UI)", cfg.BootstrapCertPath)
			} else {
				log.Printf("⚠️  Bootstrap cert stat failed at %s: %v; skipping auto-registration", cfg.BootstrapCertPath, statErr)
			}
			bootstrapCertReady = false
		}
	}
	if bootstrapCertReady {
		go func() {
			// Wait a bit for database to be fully ready
			time.Sleep(2 * time.Second)

			var err error
			regService, err := registration.NewAutoRegisterService(cfg, db)
			if err != nil {
				log.Printf("⚠️  Failed to initialize auto-registration service: %v", err)
				return
			}

			log.Printf("🔄 Registering platform discovery sensor for all tenants...")
			if err := regService.RegisterForAllTenants(); err != nil {
				log.Printf("⚠️  Auto-registration completed with errors: %v", err)
			} else {
				log.Printf("✅ Platform discovery sensor registered successfully for all tenants")
			}

			// Start certificate expiration monitoring
			if regService != nil {
				go regService.MonitorCertificateExpiration()
			}
		}()
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
			log.Printf("🚀 Cluster Sensor Service API server starting on port %s (mTLS)", cfg.TLSPort)
			log.Printf("🔍 Ready to process discovery jobs")
			if err := apiServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		} else {
			log.Printf("🚀 Cluster Sensor Service API server starting on port %s (HTTP fallback)", cfg.Port)
			log.Printf("🔍 Ready to process discovery jobs")
			if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down cluster-sensor-service...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop job processor
	jobProcessor.Stop()

	// Shutdown both servers
	if err := healthServer.Shutdown(ctx); err != nil {
		log.Printf("Health server forced to shutdown: %v", err)
	}
	if err := apiServer.Shutdown(ctx); err != nil {
		log.Printf("API server forced to shutdown: %v", err)
	}

	log.Println("cluster-sensor-service stopped")
}
