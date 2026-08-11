package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vistasecurity/vistaplatform/mcp-service/internal/config"
	"github.com/vistasecurity/vistaplatform/mcp-service/internal/platform"
	"github.com/vistasecurity/vistaplatform/mcp-service/internal/server"
	"github.com/vistasecurity/vistaplatform/mcp-service/internal/tools"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
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

	exchanger := platform.NewExchanger(cfg.AuthServiceURL, httpc)
	client := platform.NewClient(httpc, cfg.InventoryServiceURL, cfg.ComplianceEngineURL, cfg.CBOMServiceURL)

	mcpServer := server.NewMCPServer(&tools.Deps{Client: client})
	handler := server.NewHandler(mcpServer, exchanger)
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
