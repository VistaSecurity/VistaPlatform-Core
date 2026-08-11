package main

import (
	"context"
	"database/sql"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/api"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/config"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/jobs"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/services"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/subscribers"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	// Load configuration
	cfg := config.Load()

	// Initialize database connection for log storage
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Initialize the BYPASSRLS (crypto_bypass) connection used by the deliberately
	// cross-tenant paths annotated `// RLS: cross-tenant — runs on the bypass role
	// (Phase 4)` (the SIEM log store + retention sweeps over platform_log_metadata,
	// the sensor-stats system overview, and the resource-collector tenants
	// enumerator). Reads BYPASS_DATABASE_URL, falling back to DATABASE_URL when the
	// role split is not yet deployed.
	bypassDB, err := shareddatabase.ConnectBypass()
	if err != nil {
		log.Fatalf("Failed to open bypass database: %v", err)
	}
	defer func() { _ = bypassDB.Close() }()

	// Initialize services
	healthService := services.NewHealthService(cfg)
	metricsService := services.NewMetricsService(cfg)
	alertingService := services.NewAlertingService(db)
	notificationService := services.NewNotificationService(db)

	// Initialize log storage service and retention job
	var logStorageService *services.LogStorageService
	var retentionJob *jobs.LogRetentionJob
	var incidentHook *services.IncidentResponseHook
	if cfg.IncidentHooksEnabled && notificationService != nil {
		incidentCreator := services.NewNotificationIncidentCreator(notificationService)
		incidentHook = services.NewIncidentResponseHook(db, incidentCreator, true)
	}
	if cfg.S3Bucket != "" && cfg.S3KMSKeyID != "" {
		logStorageService, err = services.NewLogStorageService(db, bypassDB, cfg.S3Bucket, cfg.S3Region, cfg.S3KMSKeyID, incidentHook)
		if err != nil {
			log.Printf("Warning: Failed to initialize log storage service: %v. Compliance logging will be disabled.", err)
		} else {
			// Initialize S3 client for retention job
			// Note: LogStorageService already has an S3 client, but we need one for the retention job
			// For now, we'll create a separate client (can be optimized later)
			// Create a temporary context for AWS config loading
			awsCtx := context.Background()
			awsCfg, err := awsconfig.LoadDefaultConfig(awsCtx,
				awsconfig.WithRegion(cfg.S3Region),
			)
			if err == nil {
				s3Client := s3.NewFromConfig(awsCfg)
				retentionJob = jobs.NewLogRetentionJob(db, bypassDB, s3Client, cfg.S3Bucket)
				log.Println("Log retention job initialized")
			}
		}
	}

	// Initialize API server
	server := api.NewServer(cfg, db, bypassDB, healthService, metricsService, logStorageService, alertingService)

	// Initialize resource collector
	resourceCollector := jobs.NewResourceCollector(logrus.StandardLogger(), db, bypassDB)

	// Initialize metrics aggregator
	metricsAggregator := jobs.NewMetricsAggregator(cfg, healthService, metricsService)

	// Initialize alert evaluator (runs every 5 minutes)
	alertEvaluator, err := jobs.NewAlertEvaluator(
		alertingService,
		notificationService,
		metricsService,
		cfg,
		5*time.Minute, // Evaluate alerts every 5 minutes
	)
	if err != nil {
		log.Fatalf("Failed to create alert evaluator: %v", err)
	}

	// Initialize NATS subscriber for real-time asset discovery metrics
	var discoverySubscriber *subscribers.DiscoverySubscriber
	natsClient, natsErr := events.NewNATSClient("")
	if natsErr != nil {
		log.Printf("WARNING: NATS unavailable for discovery subscriber: %v", natsErr)
	} else {
		discoverySubscriber = subscribers.NewDiscoverySubscriber(natsClient, metricsService)
		if err := discoverySubscriber.Start(); err != nil {
			log.Printf("WARNING: Failed to start NATS discovery subscriber: %v", err)
		} else {
			log.Println("NATS discovery subscriber started on inventory.lifecycle.asset.discovered")
		}
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start resource collector in background
	go resourceCollector.Start(ctx)

	// Start metrics aggregator in background
	go metricsAggregator.Start(ctx)

	// Start alert evaluator in background
	go alertEvaluator.Start(ctx)

	// Start log retention job in background (if enabled)
	if retentionJob != nil {
		go retentionJob.Start(ctx, cfg.RetentionJobInterval)
		log.Println("Log retention job started")
	}

	// Start cleanup job for old metrics (runs daily)
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		// Run immediately, then daily
		metricsAggregator.CleanupOldMetrics()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				metricsAggregator.CleanupOldMetrics()
			}
		}
	}()

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Start server in background
	go func() {
		log.Printf("Starting monitoring service on port %s", port)
		if err := server.Start(":" + port); err != nil {
			log.Fatal("Failed to start server:", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down monitoring service...")
	cancel() // Stop resource collector

	// Stop NATS subscriber
	if discoverySubscriber != nil {
		discoverySubscriber.Stop()
	}
	if natsClient != nil {
		natsClient.Close()
	}

	log.Println("Monitoring service stopped")
}
