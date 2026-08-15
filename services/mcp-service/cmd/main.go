package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vistasecurity/vistaplatform/mcp-service/internal/auditlog"
	"github.com/vistasecurity/vistaplatform/mcp-service/internal/config"
	"github.com/vistasecurity/vistaplatform/mcp-service/internal/platform"
	"github.com/vistasecurity/vistaplatform/mcp-service/internal/server"
	"github.com/vistasecurity/vistaplatform/mcp-service/internal/tools"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	"github.com/vistasecurity/vistaplatform/shared/version"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg := config.Load()

	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// One outbound client for all platform hops; mTLS when the mesh is on.
	httpc := &http.Client{Timeout: 30 * time.Second}
	if cfg.UseMTLS {
		var err error
		httpc, err = sharedhttp.NewMTLSClient(cfg.ClientCertPath, cfg.ClientKeyPath, cfg.PlatformCACertPath)
		if err != nil {
			log.Fatalf("Failed to create mTLS client: %v", err)
		}
		httpc.Timeout = 30 * time.Second
	}

	// Audit: this is the one interface built to hand bulk tenant data to a
	// non-human consumer, so every tool invocation and every credential
	// decision is recorded — through the same shared audit path the other
	// services use, not a store of its own.
	auditConfig := auditmiddleware.DefaultConfig()
	auditConfig.ServiceName = "mcp-service"
	auditConfig.AuditServiceURL = os.Getenv("AUDIT_SERVICE_URL")
	if auditConfig.AuditServiceURL == "" {
		auditConfig.AuditServiceURL = sharedconfig.PeerURL("audit-service", cfg.UseMTLS)
	}
	auditConfig.Enabled = os.Getenv("AUDIT_LOGGING_ENABLED") != "false"
	auditConfig.UseMTLS = cfg.UseMTLS
	auditConfig.ClientCertPath = cfg.ClientCertPath
	auditConfig.ClientKeyPath = cfg.ClientKeyPath
	auditConfig.PlatformCACertPath = cfg.PlatformCACertPath
	if !auditConfig.Enabled {
		// Turning the record off is a deliberate operator act; it should never
		// be something a later reader has to infer from an empty audit table.
		log.Printf("⚠️  AUDIT_LOGGING_ENABLED=false — MCP tool invocations will NOT be recorded")
	}
	auditMiddleware := auditmiddleware.NewMiddleware(auditConfig)
	defer auditMiddleware.Stop()
	recorder := auditlog.NewRecorder(auditMiddleware)

	exchanger := platform.NewExchanger(cfg.AuthServiceURL, httpc, recorder)
	client := platform.NewClient(httpc, cfg.InventoryServiceURL, cfg.ComplianceEngineURL, cfg.CBOMServiceURL)

	mcpServer := server.NewMCPServer(&tools.Deps{Client: client, Audit: recorder})
	handler := server.NewHandler(mcpServer, exchanger, recorder)
	router := server.NewRouter(handler)

	// Health-only listener on the plain port when mTLS serves the API on 8443
	// (kubelet probes need plaintext) — same dual-listener shape as every
	// other backend.
	healthRouter := gin.New()
	healthRouter.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy", "service": "mcp-service", "version": version.Get()})
	})
	healthServer := &http.Server{
		Addr:              cfg.Server.Host + ":" + cfg.Server.Port,
		Handler:           healthRouter,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

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
		apiServer.Addr = cfg.Server.Host + ":" + cfg.TLSPort
		apiServer.ReadHeaderTimeout = 5 * time.Second
		apiServer.ReadTimeout = 10 * time.Second
		apiServer.WriteTimeout = 120 * time.Second
		apiServer.IdleTimeout = 60 * time.Second
	} else {
		apiServer = &http.Server{
			Addr:              cfg.Server.Host + ":" + cfg.Server.Port,
			Handler:           router,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      120 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
	}

	if cfg.UseMTLS {
		go func() {
			log.Printf("Health check server starting on %s:%s", cfg.Server.Host, cfg.Server.Port)
			if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start health server: %v", err)
			}
		}()
	}

	go func() {
		if cfg.UseMTLS {
			log.Printf("🚀 MCP Service starting on %s:%s (mTLS), endpoint %s", cfg.Server.Host, cfg.TLSPort, server.MCPPath)
			if err := apiServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		} else {
			log.Printf("🚀 MCP Service starting on %s:%s (HTTP), endpoint %s", cfg.Server.Host, cfg.Server.Port, server.MCPPath)
			if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := healthServer.Shutdown(ctx); err != nil {
		log.Printf("Health server forced to shutdown: %v", err)
	}
	if err := apiServer.Shutdown(ctx); err != nil {
		log.Printf("API server forced to shutdown: %v", err)
	}
	log.Println("Server exited")
}
