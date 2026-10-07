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
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/services"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
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
		defer func() { _ = db.Close() }()
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
			bypassDB,
			os.Getenv("CLUSTER_SENSOR_SERVICE_URL"),
			os.Getenv("DEVICE_INTERROGATION_SERVICE_URL"),
		)
		go healthService.Start(context.Background())

		// Start the offline reaper so tenant sensors that stop checking in are
		// transitioned 'active' -> 'offline' (the heartbeat path handles the
		// reverse). Without this a dead sensor shows "active" forever.
		reaper := services.NewSensorReaperService(db, bypassDB)
		go reaper.Start(context.Background())
	}

	// Initialize handlers with both legacy and V2 services
	// The handler's logger is initialized inside NewHandlerWithBoth.
	handler := handlers.NewHandlerWithBoth(sensorService, sensorServiceV2, repo, db, bypassDB)
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

	// Initialize router. The agent listener serves only agentRoutes of it.
	router, agentRoutes := setupRouter(cfg, handler, db, bypassDB)

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
	// TLS passthrough so their per-tenant client cert terminates here. It
	// serves agentRoutes ONLY (setupRouter): passthrough skips every edge deny,
	// so the rest of the router answers 404 on this port. This
	// listener requires a client cert (RequireAnyClientCert); SensorAuth
	// verifies it against the sensor's tenant CA. Kept separate from the 8443
	// mesh listener, which verifies against the Platform CA and would reject
	// per-tenant sensor certs at the handshake.
	var agentServer *http.Server
	if cfg.SensorMTLSRequired {
		agentServer, err = newSensorMTLSServer(cfg, router, agentRoutes)
		if err != nil {
			log.Fatalf("Failed to create sensor-mTLS server: %v", err)
		}
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
