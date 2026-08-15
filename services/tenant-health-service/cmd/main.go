package main

import (
	"context"
	"database/sql"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/jobs"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/repository"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/service"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/subscribers"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
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

	// mTLS posture is needed here (audit-service peer URL + client cert) as
	// well as by the listener setup further down.
	useMTLS := sharedconfig.GetEnvAsBool("USE_MTLS", true)

	// Audit logging. Every route below /api/v1/tenant-health-service is a
	// cross-tenant platform-admin surface: it reads one tenant's health,
	// alerts, metrics and insights, and POST /calculate writes health scores.
	// "Which admin looked at (or recalculated) which tenant" is precisely what
	// an audit trail is for, and this service had none. Volume is low — the
	// only client is admin-ui-v2 — so no additional skips beyond /health.
	auditMiddleware := auditmiddleware.NewMiddleware(auditmiddleware.ServiceConfig(
		"tenant-health-service",
		useMTLS,
		sharedconfig.GetEnv("CLIENT_CERT_PATH", "/app/certs/client-cert.pem"),
		sharedconfig.GetEnv("CLIENT_KEY_PATH", "/app/certs/client-key.pem"),
		sharedconfig.GetEnv("PLATFORM_CA_CERT_PATH", "/app/certs/platform-ca-cert.pem"),
	))
	defer auditMiddleware.Stop()

	// Initialize repository, service, and handlers
	healthRepo := repository.NewHealthRepository(db, bypassDB)
	healthService := service.NewHealthService(healthRepo)
	healthHandlers := handlers.NewHealthHandlers(healthService)

	// Setup Gin router (audit logging + routes; see newRouter in router.go)
	jwtSecret := os.Getenv("JWT_SECRET")
	internalSecret := os.Getenv("INTERNAL_AUTH_SECRET")
	router := newRouter(healthHandlers, auditMiddleware, jwtSecret, internalSecret, db)

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

	// mTLS configuration (M-14: tenant-health-service previously never read
	// these and always called router.Run() on plaintext :8080 regardless of
	// USE_MTLS, so under serviceMtls.enabled it never started a :8443
	// listener like every other backend. monitoring-service's version
	// aggregator and any S2S caller using PeerURL() reach peers on
	// https://<svc>:8443 under mTLS — this service answered "connection
	// refused" there, reporting as unreachable/degraded on the About page
	// despite being healthy, and made it unreachable to S2S callers.
	tlsPort := sharedconfig.GetEnv("TLS_PORT", "8443")
	serviceCertPath := sharedconfig.GetEnv("SERVICE_CERT_PATH", "/app/certs/server-cert.pem")
	serviceKeyPath := sharedconfig.GetEnv("SERVICE_KEY_PATH", "/app/certs/server-key.pem")
	platformCACertPath := sharedconfig.GetEnv("PLATFORM_CA_CERT_PATH", "/app/certs/platform-ca-cert.pem")

	// Probe-only router for the plaintext :8080 listener kubelet uses (it
	// can't present a client cert). Only /health — same handler the main
	// router already serves unauthenticated, kept on a separate gin.Engine
	// so the plaintext port never exposes the platform-admin API surface.
	probeRouter := gin.New()
	probeRouter.GET("/health", healthHandlers.HealthCheck)

	apiPort := port
	if useMTLS {
		apiPort = tlsPort
	}
	servers, err := sharedhttp.StartDualListeners(sharedhttp.DualListenerConfig{
		APIHandler:   router,
		ProbeHandler: probeRouter,
		UseMTLS:      useMTLS,
		APIPort:      apiPort,
		ProbePort:    port,
		CertPath:     serviceCertPath,
		KeyPath:      serviceKeyPath,
		CACertPath:   platformCACertPath,
	})
	if err != nil {
		logrus.Fatalf("Failed to start HTTP listeners: %v", err)
	}

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

	// Shutdown HTTP listeners
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := servers.Shutdown(shutdownCtx); err != nil {
		logrus.WithError(err).Warn("Error shutting down HTTP listeners")
	}

	logrus.Info("Tenant health service stopped")
}
