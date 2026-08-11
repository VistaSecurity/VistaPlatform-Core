package main

import (
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

	// Create processor
	proc := processor.New(db, cfg, natsClient)

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

	// Start health check HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
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
	})

	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: mux,
	}

	go func() {
		log.Printf("Health check server starting on port %s", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start health server: %v", err)
		}
	}()

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

	// Shutdown health server
	log.Println("Shutting down health server...")
	if err := server.Close(); err != nil {
		log.Printf("Error shutting down health server: %v", err)
	}

	log.Println("Shutdown complete")
}
