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
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/aws"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/config"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/jobs"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/repository"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/service"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/subscribers"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	"github.com/vistasecurity/vistaplatform/shared/version"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	// Initialize logger
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Load configuration
	cfg := config.Load()

	// Get configuration from environment (legacy - keep for compatibility)
	port := cfg.Port
	databaseURL := cfg.DatabaseURL
	env := cfg.Environment
	logLevel := cfg.LogLevel

	// Set log level
	switch logLevel {
	case "debug":
		logger.SetLevel(logrus.DebugLevel)
	case "info":
		logger.SetLevel(logrus.InfoLevel)
	case "warn":
		logger.SetLevel(logrus.WarnLevel)
	case "error":
		logger.SetLevel(logrus.ErrorLevel)
	}

	// Set Gin mode
	if env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	logger.WithFields(logrus.Fields{
		"port":      port,
		"env":       env,
		"log_level": logLevel,
	}).Info("Starting Resource Tracker Service")

	// Initialize database connection
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		logger.WithError(err).Fatal("Failed to connect to database")
	}
	defer db.Close()

	// Test database connection
	if err := db.Ping(); err != nil {
		logger.WithError(err).Fatal("Failed to ping database")
	}

	logger.Info("Database connection established")

	// Bypass connection for deliberately cross-tenant (`// RLS: cross-tenant`)
	// paths — platform rollups and AWS cost-sync. Under crypto_app these fail
	// closed; ConnectBypass resolves to the BYPASSRLS crypto_bypass role
	// (BYPASS_DATABASE_URL), falling back to DATABASE_URL pre-flip.
	bypassDB, err := shareddatabase.ConnectBypass()
	if err != nil {
		logger.WithError(err).Fatal("Failed to open bypass database connection")
	}
	defer func() { _ = bypassDB.Close() }()

	logger.Info("Bypass database connection established")

	// Initialize repositories
	resourceRepo := repository.NewResourceRepository(db, bypassDB)
	awsCostRepo := repository.NewAWSCostRepository(db, bypassDB, logger)
	var integrationRepo *repository.IntegrationRepository
	if cfg.CostExplorerEnabled {
		var repoErr error
		integrationRepo, repoErr = repository.NewIntegrationRepository(db, bypassDB, cfg.EncryptionKey, logger)
		if repoErr != nil {
			logger.WithError(repoErr).Warn("Failed to initialize integration repository; disabling AWS cost sync")
		}
		if repoErr != nil || integrationRepo == nil {
			cfg.CostExplorerEnabled = false
		}
	}

	// Initialize AWS Cost Explorer service (if enabled)
	var awsCostService *aws.CostExplorerService
	if cfg.CostExplorerEnabled {
		ctx := context.Background()
		creds, credErr := integrationRepo.GetLatestAWSIntegration(ctx)
		if credErr != nil {
			logger.WithError(credErr).Warn("Failed to load AWS integration credentials. AWS cost integration will be disabled.")
			cfg.CostExplorerEnabled = false
		} else {
			region := creds.Region
			if region == "" {
				region = cfg.AWSRegion
			}
			accountID := creds.AccountID
			if accountID == "" {
				accountID = cfg.AWSAccountID
			}

			awsCostService, err = aws.NewCostExplorerServiceWithStaticCredentials(region, accountID, cfg.TenantTagKey, creds.AccessKey, creds.SecretKey, creds.SessionToken, logger)
			if err != nil {
				logger.WithError(err).Warn("Failed to initialize AWS Cost Explorer service with integration credentials. AWS cost integration will be disabled.")
				cfg.CostExplorerEnabled = false
			} else {
				logger.WithFields(logrus.Fields{
					"aws_account_id": accountID,
					"region":         region,
				}).Info("AWS Cost Explorer service initialized with platform integration credentials")
			}
		}
	}

	// Initialize service
	resourceService := service.NewResourceService(resourceRepo, awsCostRepo, awsCostService, cfg.CostExplorerEnabled, logger)

	// Initialize AWS cost service (if enabled)
	var awsCostServiceBusiness *service.AWSCostService
	if cfg.CostExplorerEnabled && awsCostService != nil {
		awsCostServiceBusiness = service.NewAWSCostService(awsCostRepo, awsCostService, logger)
	}

	// Initialize handlers
	resourceHandlers := handlers.NewResourceHandlers(resourceService, awsCostServiceBusiness, logger)

	// Audit logging. Which surfaces are audited (and which one is not) is
	// decided in audit.go — see attachAuditLogging.
	auditMiddleware := auditmiddleware.NewMiddleware(auditmiddleware.ServiceConfig(
		"resource-tracker-service",
		cfg.UseMTLS,
		cfg.ClientCertPath,
		cfg.ClientKeyPath,
		cfg.PlatformCACertPath,
	))
	defer auditMiddleware.Stop()

	router := newRouter(cfg, resourceHandlers, auditMiddleware)

	// Initialize NATS subscriber for metrics ingestion (replaces HTTP fallback)
	var metricsSubscriber *subscribers.MetricsSubscriber
	natsClient, natsErr := events.NewNATSClient("")
	if natsErr != nil {
		logger.WithError(natsErr).Warn("NATS unavailable, metrics will only be received via HTTP")
	} else {
		metricsSubscriber = subscribers.NewMetricsSubscriber(natsClient, resourceService)
		if err := metricsSubscriber.Start(); err != nil {
			logger.WithError(err).Warn("Failed to start NATS metrics subscriber")
		} else {
			logger.Info("NATS metrics subscriber started on metrics.system")
		}
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize and start AWS cost sync job (if enabled)
	if cfg.CostExplorerEnabled && awsCostService != nil {
		costSyncJob := jobs.NewAWSCostSyncJob(awsCostRepo, awsCostService, cfg.CostExplorerEnabled, cfg.CostSyncInterval, logger)
		go costSyncJob.Start(ctx)
		logger.Info("AWS Cost Sync Job started")
	}

	// Health check server (HTTP, port 8080)
	healthRouter := gin.New()
	healthRouter.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "resource-tracker-service",
			"version": version.Get(),
		})
	})

	healthServer := &http.Server{
		Addr:    ":" + port,
		Handler: healthRouter,
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
			logger.WithError(err).Fatal("Failed to create mTLS server")
		}
		apiServer.Addr = ":" + cfg.TLSPort
	} else {
		// Fallback to HTTP if mTLS disabled
		apiServer = &http.Server{
			Addr:    ":" + port,
			Handler: router,
		}
	}

	// Start health check server (only when mTLS is enabled - API server on different port)
	// When mTLS is disabled, API server includes /health endpoint on same port
	if cfg.UseMTLS {
		go func() {
			logger.WithField("port", port).Info("Health check server starting")
			if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.WithError(err).Fatal("Failed to start health server")
			}
		}()
	}

	// Start API server
	go func() {
		if cfg.UseMTLS {
			logger.WithField("port", cfg.TLSPort).Info("Resource Tracker Service API server starting (mTLS)")
			if err := apiServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				logger.WithError(err).Fatal("Failed to start API server")
			}
		} else {
			logger.WithField("port", port).Info("Resource Tracker Service API server starting (HTTP fallback)")
			if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.WithError(err).Fatal("Failed to start API server")
			}
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")
	cancel()

	// Give outstanding requests 30 seconds to complete
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Stop NATS subscriber
	if metricsSubscriber != nil {
		metricsSubscriber.Stop()
	}
	if natsClient != nil {
		natsClient.GracefulShutdown(shutdownCtx)
	}

	// Shutdown both servers
	if err := healthServer.Shutdown(shutdownCtx); err != nil {
		logger.WithError(err).Error("Health server forced to shutdown")
	}
	if err := apiServer.Shutdown(shutdownCtx); err != nil {
		logger.WithError(err).Error("API server forced to shutdown")
	}

	logger.Info("Server stopped")
}
