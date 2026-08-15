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

	"github.com/vistasecurity/vistaplatform/pcap-processor/internal/config"
	"github.com/vistasecurity/vistaplatform/pcap-processor/internal/database"
	"github.com/vistasecurity/vistaplatform/pcap-processor/internal/processor"
	"github.com/vistasecurity/vistaplatform/shared/events"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	"github.com/vistasecurity/vistaplatform/shared/version"
)

func main() {
	log.Println("Starting pcap-processor service...")

	// Load configuration
	cfg := config.Load()

	// Connect to PostgreSQL
	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()
	log.Println("Connected to PostgreSQL")

	// Connect to NATS
	natsClient, err := events.NewNATSClient(cfg.NATSUrl)
	if err != nil {
		log.Fatalf("Failed to connect to NATS: %v", err)
	}
	defer natsClient.Close()
	log.Println("Connected to NATS")

	// Audit logging. pcap-processor serves no tenant HTTP surface (only
	// /health), so there is no request middleware to mount — the audit
	// middleware is used here purely as the transport for consumer-path
	// events emitted per PCAP job. Same store, same batching, same NATS/HTTP
	// fallback as every HTTP service's LogRequest.
	auditMiddleware := auditmiddleware.NewMiddleware(auditmiddleware.ServiceConfig(
		"pcap-processor", cfg.UseMTLS, cfg.ClientCertPath, cfg.ClientKeyPath, cfg.PlatformCACertPath,
	))
	defer auditMiddleware.Stop()

	// Create processor
	proc := processor.New(db, cfg, natsClient, auditMiddleware)

	// Create subscriber and subscribe to pcap jobs
	subscriber := events.NewSubscriber(natsClient)
	err = subscriber.Subscribe(events.SubscriptionConfig{
		Stream:            "PCAP_JOBS",
		Subject:           events.SubjectPcapJobsProcess,
		Durable:           "pcap-processor",
		QueueGroup:        "pcap-processor",
		MaxDeliver:        3,
		AckWait:           6 * time.Minute,
		ProcessingTimeout: 5 * time.Minute,
	}, proc.HandlePcapJob)
	if err != nil {
		log.Fatalf("Failed to subscribe to pcap jobs: %v", err)
	}
	log.Printf("Subscribed to %s", events.SubjectPcapJobsProcess)

	// HTTP surface: /health only (pcap-processor is primarily a NATS
	// consumer with no other API surface). Registered on both listeners —
	// see StartDualListeners below for why there are two.
	healthHandler := func(w http.ResponseWriter, r *http.Request) {
		if err := db.Ping(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"status":"unhealthy","error":"database connection failed"}`)
			return
		}
		if !natsClient.IsConnected() {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"status":"unhealthy","error":"NATS not connected"}`)
			return
		}
		body, _ := json.Marshal(map[string]interface{}{
			"status":  "healthy",
			"service": "pcap-processor",
			"version": version.Get(),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, string(body))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)

	probeMux := http.NewServeMux()
	probeMux.HandleFunc("/health", healthHandler)

	// M-14 fix: pcap-processor previously ran a single plaintext :8080
	// server unconditionally and never started a :8443 mTLS listener, even
	// when USE_MTLS was true. Under serviceMtls.enabled, monitoring-service's
	// version aggregator and any S2S caller using PeerURL() reach every
	// other backend on https://<svc>:8443 — pcap-processor answered
	// "connection refused" there, showing as a permanently unreachable/
	// degraded row on the About page despite the pod being healthy.
	// StartDualListeners gives it the same shape every other backend uses:
	// the real handler on :8443 under mTLS, plus a plaintext :8080 /health
	// listener for kubelet probes (which can't present a client cert).
	apiPort := cfg.Port
	if cfg.UseMTLS {
		apiPort = cfg.TLSPort
	}
	dlCfg := sharedhttp.DualListenerConfig{
		APIHandler:   mux,
		ProbeHandler: probeMux,
		UseMTLS:      cfg.UseMTLS,
		APIPort:      apiPort,
		ProbePort:    cfg.Port,
		CertPath:     cfg.ServiceCertPath,
		KeyPath:      cfg.ServiceKeyPath,
		CACertPath:   cfg.PlatformCACertPath,
	}
	servers, err := sharedhttp.StartDualListeners(dlCfg)
	if err != nil {
		log.Fatalf("Failed to start HTTP listeners: %v", err)
	}

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	sig := <-sigChan
	log.Printf("Received signal: %v. Shutting down gracefully...", sig)

	// Drain subscriptions to finish in-flight messages
	log.Println("Draining NATS subscriptions...")
	if err := subscriber.Drain(); err != nil {
		log.Printf("Error draining subscriptions: %v", err)
	}

	// Shutdown HTTP listeners
	log.Println("Shutting down HTTP listeners...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := servers.Shutdown(shutdownCtx); err != nil {
		log.Printf("Error shutting down HTTP listeners: %v", err)
	}

	log.Println("Shutdown complete")
}
