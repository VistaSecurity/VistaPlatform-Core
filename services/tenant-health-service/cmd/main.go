package main

import (
	"context"
	"database/sql"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/jobs"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/repository"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/service"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/subscribers"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	// Configure Logrus
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetOutput(os.Stdout)
	logLevel, err := logrus.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		logLevel = logrus.InfoLevel // Default to Info
	}
	logrus.SetLevel(logLevel)

	// Database connection
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		logrus.Fatal("DATABASE_URL environment variable not set")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		logrus.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if err = db.Ping(); err != nil {
		logrus.Fatalf("Failed to ping database: %v", err)
	}
	logrus.Info("Successfully connected to the database!")

	// Bypass-role connection (BYPASSRLS crypto_bypass) for the cross-tenant
	// platform-admin queries that would FAIL CLOSED under the RLS-subject
	// crypto_app role. Falls back to DATABASE_URL when BYPASS_DATABASE_URL is
	// unset (pre-flip deployments resolve both to the same owner connection).
	bypassDB, err := shareddatabase.ConnectBypass()
	if err != nil {
		logrus.Fatalf("Failed to connect to bypass database: %v", err)
	}
	defer func() { _ = bypassDB.Close() }()

	// Setup Gin router
	router := gin.Default()

	// Initialize repository, service, and handlers
	healthRepo := repository.NewHealthRepository(db, bypassDB)
	healthService := service.NewHealthService(healthRepo)
	healthHandlers := handlers.NewHealthHandlers(healthService)

	// Register routes (auth wired inside: platform-admin JWT + platform.health gate)
	jwtSecret := os.Getenv("JWT_SECRET")
	internalSecret := os.Getenv("INTERNAL_AUTH_SECRET")
	healthHandlers.RegisterRoutes(router, jwtSecret, internalSecret, db)

	// Initialize NATS subscriber for real-time health recalculation
	var lifecycleSubscriber *subscribers.LifecycleSubscriber
	natsClient, natsErr := events.NewNATSClient("")
	if natsErr != nil {
		logrus.WithError(natsErr).Warn("NATS unavailable, health scores will only update on polling interval")
	} else {
		lifecycleSubscriber = subscribers.NewLifecycleSubscriber(natsClient, healthService)
		if err := lifecycleSubscriber.Start(); err != nil {
			logrus.WithError(err).Warn("Failed to start NATS lifecycle subscriber")
		} else {
			logrus.Info("NATS lifecycle subscriber started (asset.risk_changed, asset.enriched)")
		}
	}

	// Initialize health calculator job
	healthCalculator := jobs.NewHealthCalculator(healthService, healthRepo)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start health calculator job in background
	go healthCalculator.Start(ctx)

	// Start server in background
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Default port
	}

	go func() {
		logrus.Infof("Tenant Health Service starting on port %s", port)
		if err := router.Run(":" + port); err != nil {
			logrus.Fatalf("Failed to run server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logrus.Info("Shutting down tenant health service...")
	cancel() // Stop health calculator job

	// Stop NATS subscriber
	if lifecycleSubscriber != nil {
		lifecycleSubscriber.Stop()
	}
	if natsClient != nil {
		natsClient.Close()
	}

	logrus.Info("Tenant health service stopped")
}
