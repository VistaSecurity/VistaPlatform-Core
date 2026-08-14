package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/client"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/config"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/converter"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/database"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/processor"
	"github.com/vistasecurity/vistaplatform/shared/approval"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	"github.com/vistasecurity/vistaplatform/shared/version"
)

// healthyJSON returns the standard /health success body for this service,
// including the version block consumed by the About-page aggregator.
func healthyJSON() string {
	body := map[string]interface{}{
		"status":  "healthy",
		"service": "discovery-processor-service",
		"version": version.Get(),
	}
	b, _ := json.Marshal(body)
	return string(b)
}

func main() {
	// Load configuration
	cfg := config.Load()

	// Connect to database (RLS-scoped crypto_app handle for all per-tenant work)
	db, err := database.NewConnection(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Connect the BYPASSRLS handle (crypto_bypass via BYPASS_DATABASE_URL, falls
	// back to DATABASE_URL pre-flip) used only by the cross-tenant batch poller.
	bypassSQLDB, err := shareddatabase.ConnectBypass()
	if err != nil {
		log.Fatalf("Failed to connect bypass database: %v", err)
	}
	bypassDB := sqlx.NewDb(bypassSQLDB, "postgres")
	defer func() { _ = bypassDB.Close() }()

	// Initialize services
	converter := converter.NewSensorDiscoveryConverter()
	approvalService := approval.NewService(db.DB.DB)
	inventoryClient, err := client.NewInventoryClient(cfg)
	if err != nil {
		log.Fatalf("Failed to create inventory client: %v", err)
	}
	batchProcessor := processor.NewBatchProcessor(db.DB, converter, approvalService, inventoryClient)
	discoveryProcessor := processor.NewDiscoveryProcessor(db.DB, bypassDB, batchProcessor, cfg)

	// Setup HTTP server for API endpoints (metrics/status/health)
	mux := http.NewServeMux()

	// Health check endpoint (always available)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		// Check database connection
		if err := db.Ping(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"status":"unhealthy","error":"database connection failed"}`)
			return
		}

		// Check inventory-service reachability (simple check)
		if cfg.InventoryServiceURL == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"status":"unhealthy","error":"inventory service URL not configured"}`)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, healthyJSON())
	})

	// Metrics endpoint (simple version - can be enhanced with Prometheus later)
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "# Discovery Processor Service Metrics\n")
		fmt.Fprintf(w, "# Poll interval: %d seconds\n", cfg.PollIntervalSeconds)
		fmt.Fprintf(w, "# Batch size: %d\n", cfg.BatchSize)
		fmt.Fprintf(w, "# Concurrent batches: %d\n", cfg.ConcurrentBatches)
		// TODO: Add actual metrics (batches processed, findings processed, etc.)
	})

	// Status endpoint
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"service": "discovery-processor-service",
			"status": "running",
			"poll_interval_seconds": %d,
			"batch_size": %d,
			"concurrent_batches": %d
		}`, cfg.PollIntervalSeconds, cfg.BatchSize, cfg.ConcurrentBatches)
	})

	// Health check server (HTTP, port 8080) - used separately when mTLS is enabled
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		// Check database connection
		if err := db.Ping(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"status":"unhealthy","error":"database connection failed"}`)
			return
		}

		// Check inventory-service reachability (simple check)
		if cfg.InventoryServiceURL == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"status":"unhealthy","error":"inventory service URL not configured"}`)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, healthyJSON())
	})

	healthServer := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: healthMux,
	}

	// API server (HTTPS with mTLS, port 8443)
	var apiServer *http.Server
	if cfg.UseMTLS {
		var err error
		apiServer, err = sharedhttp.NewMTLSServer(
			cfg.ServiceCertPath,
			cfg.ServiceKeyPath,
			cfg.PlatformCACertPath,
			mux,
		)
		if err != nil {
			log.Fatalf("Failed to create mTLS server: %v", err)
		}
		apiServer.Addr = ":" + cfg.TLSPort
	} else {
		// Fallback to HTTP if mTLS disabled
		apiServer = &http.Server{
			Addr:    ":" + cfg.Port,
			Handler: mux,
		}
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
			log.Printf("Discovery Processor Service API server starting on port %s (mTLS)", cfg.TLSPort)
			if err := apiServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		} else {
			log.Printf("Discovery Processor Service API server starting on port %s (HTTP fallback)", cfg.Port)
			if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		}
	}()

	// Start discovery processor in a goroutine
	processorDone := make(chan error, 1)
	go func() {
		log.Println("Starting discovery processor...")
		processorDone <- discoveryProcessor.Start()
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		log.Printf("Received signal: %v. Shutting down gracefully...", sig)
	case err := <-processorDone:
		if err != nil {
			log.Printf("Discovery processor stopped with error: %v", err)
		} else {
			log.Println("Discovery processor stopped")
		}
	}

	// Graceful shutdown
	log.Println("Stopping discovery processor...")
	discoveryProcessor.Stop()

	// Wait for in-flight batches to complete (max 30s)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown both servers
	log.Println("Shutting down HTTP servers...")
	if err := healthServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("Error shutting down health server: %v", err)
	}
	if err := apiServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("Error shutting down API server: %v", err)
	}

	log.Println("Shutdown complete")
}
