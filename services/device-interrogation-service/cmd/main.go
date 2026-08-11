package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/api"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/config"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/database"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/registration"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	"github.com/vistasecurity/vistaplatform/shared/version"

	"github.com/gin-gonic/gin"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize database
	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Bypass connection for the deliberately cross-tenant paths (agent
	// bootstrap/auth resolution, agent outbound jobs/results/heartbeat,
	// cross-tenant admin lists, background worker sweeps, CA-key lookup by id).
	// Reads BYPASS_DATABASE_URL and falls back to DATABASE_URL, so pre-flip it
	// resolves to the same (owner) connection and behavior is unchanged. After the
	// Phase 4 role split it points at the BYPASSRLS crypto_bypass role.
	bypassDB, err := shareddatabase.ConnectBypass()
	if err != nil {
		log.Fatalf("Failed to connect to bypass database: %v", err)
	}
	defer func() { _ = bypassDB.Close() }()

	// Initialize Redis
	redis, err := database.ConnectRedis(cfg.RedisURL)
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer redis.Close()

	// Set Gin mode
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize services for platform agent worker
	cloudService := services.NewCloudDiscoveryService(db, bypassDB, cfg.EncryptionMasterKey)
	deviceService := services.NewDeviceService(db)
	deviceInterrogationService := services.NewDeviceInterrogationService(db, bypassDB, cfg.EncryptionMasterKey)

	// Initialize platform agent worker
	platformWorker := services.NewPlatformAgentWorker(
		db,
		bypassDB,
		redis,
		cloudService,
		deviceService,
		deviceInterrogationService,
	)

	// Start platform agent worker in background
	go platformWorker.Start()

	// Interrogation schedule sweep. Without this loop nothing ever calls
	// SchedulerService.ProcessDueSchedules, so tenant-created cron schedules
	// never fire.
	var schedulerWorker *services.SchedulerWorker
	if services.SchedulerWorkerEnabled() {
		jobQueue := services.NewJobQueueService(db, bypassDB, redis)
		schedulerWorker = services.NewSchedulerWorker(
			services.NewSchedulerService(db, bypassDB, jobQueue),
			services.SchedulerWorkerInterval(),
		)
		go schedulerWorker.Start()
	} else {
		log.Println("⚠️  INTERROGATION_SCHEDULER_ENABLED=false — scheduled interrogations will not fire")
	}

	// Platform device-agent self-heartbeat. The auto-registration below stamps
	// device_agents.last_heartbeat once at boot and never again, so the
	// discovery_agent_offline detector flags the in-cluster agent ~15 minutes
	// after every start. This keeps the row fresh for as long as the
	// process is actually running.
	platformHeartbeat := services.NewPlatformAgentHeartbeat(bypassDB, 0)
	go platformHeartbeat.Start()

	// Auto-register platform agent for all tenants
	var regService *registration.AutoRegisterService
	if cfg.ServiceAccountToken != "" && db != nil {
		go func() {
			// Wait a bit for database to be fully ready
			time.Sleep(2 * time.Second)

			var err error
			regService, err = registration.NewAutoRegisterService(cfg, db)
			if err != nil {
				log.Printf("⚠️  Failed to initialize auto-registration service: %v", err)
				return
			}

			log.Printf("🔄 Registering platform device interrogation agent for all tenants...")
			if err := regService.RegisterForAllTenants(); err != nil {
				log.Printf("⚠️  Auto-registration completed with errors: %v", err)
			} else {
				log.Printf("✅ Platform device interrogation agent registered successfully for all tenants")
			}

			// Start certificate expiration monitoring
			if regService != nil {
				go regService.MonitorCertificateExpiration()
			}
		}()
	} else {
		if cfg.ServiceAccountToken == "" {
			log.Printf("⚠️  DEVICE_INTERROGATION_SERVICE_TOKEN not set, skipping auto-registration")
		}
	}

	// Initialize router
	router := api.SetupRouter(cfg, db, bypassDB, redis)

	// Health check server (HTTP, port 8080)
	healthRouter := gin.New()
	healthRouter.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "device-interrogation-service",
			"version": version.Get(),
		})
	})

	healthServer := &http.Server{
		Addr:              ":" + cfg.Port,
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
			Addr:              ":" + cfg.Port,
			Handler:           router,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
	}

	// Agent-mTLS passthrough listener (port 8444). When AgentMTLSRequired,
	// device agents reach /agents/:id/{jobs,results,heartbeat} via edge TLS
	// passthrough so their per-tenant client cert terminates here. This
	// listener requires a client cert (RequireAnyClientCert); AgentAuth
	// verifies it against the agent's tenant CA. Kept separate from the 8443
	// mesh listener, which verifies against the Platform CA and would reject
	// per-tenant agent certs at the handshake.
	var agentServer *http.Server
	if cfg.AgentMTLSRequired {
		agentServer, err = sharedhttp.NewAgentMTLSServer(cfg.ServiceCertPath, cfg.ServiceKeyPath, router)
		if err != nil {
			log.Fatalf("Failed to create agent-mTLS server: %v", err)
		}
		agentServer.Addr = ":" + cfg.AgentTLSPort
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

	// Start agent-mTLS listener
	if agentServer != nil {
		go func() {
			log.Printf("Device interrogation agent-mTLS listener starting on port %s (passthrough, client cert required)", cfg.AgentTLSPort)
			if err := agentServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start agent-mTLS listener: %v", err)
			}
		}()
	}

	// Start API server
	go func() {
		if cfg.UseMTLS {
			log.Printf("Device interrogation service API server starting on port %s (mTLS)", cfg.TLSPort)
			if err := apiServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		} else {
			log.Printf("Device interrogation service API server starting on port %s (HTTP fallback)", cfg.Port)
			if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down device interrogation service...")

	// Stop platform agent worker
	platformWorker.Stop()
	if schedulerWorker != nil {
		schedulerWorker.Stop()
	}
	platformHeartbeat.Stop()

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
	if agentServer != nil {
		if err := agentServer.Shutdown(ctx); err != nil {
			log.Printf("Agent-mTLS listener forced to shutdown: %v", err)
		}
	}

	log.Println("Device interrogation service stopped")
}
