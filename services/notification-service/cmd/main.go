package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/api"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/config"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/services"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/subscribers"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Initialize database connection using shared pool config
	sqlDB, err := shareddatabase.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() { _ = sqlDB.Close() }()
	db := sqlx.NewDb(sqlDB, "postgres")

	// BYPASSRLS handle (crypto_bypass; falls back to DATABASE_URL pre-flip) for
	// the platform NULL-tenant notification_history paths that cannot satisfy
	// RLS WITH CHECK / cannot be seen by crypto_app (Phase 4).
	bypassSQLDB, err := shareddatabase.ConnectBypass()
	if err != nil {
		log.Fatalf("Failed to connect to bypass database: %v", err)
	}
	defer func() { _ = bypassSQLDB.Close() }()
	bypassDB := sqlx.NewDb(bypassSQLDB, "postgres").DB

	// Initialize notification service
	notificationService := services.NewNotificationService(db, bypassDB, cfg)

	// Initialize NATS subscribers for notification event ingestion.
	// NOTE: the certificate-expiry subscriber was retired — the alert engine
	// in compliance-engine now consumes inventory.lifecycle.certificate.expiring,
	// opens/escalates the stateful alert, and fans out through notifications.send
	// like any other producer. Keeping both would double-send every cert event.
	var notifSubscriber *subscribers.NotificationSubscriber
	natsClient, natsErr := events.NewNATSClient("")
	if natsErr != nil {
		log.Printf("WARNING: NATS unavailable, notifications will only be received via HTTP: %v", natsErr)
	} else {
		notifSubscriber = subscribers.NewNotificationSubscriber(natsClient, notificationService)
		if err := notifSubscriber.Start(); err != nil {
			log.Printf("WARNING: Failed to start NATS notification subscriber: %v", err)
		} else {
			log.Println("NATS notification subscriber started on notifications.send")
		}
	}

	// Get port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Initialize API server
	server := api.NewServer(cfg, db, bypassDB, notificationService)

	// Start server in a goroutine
	go func() {
		log.Printf("Notification service starting on port %s", port)
		if err := server.Start(":" + port); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Digest flush worker: delivers batched 'digest_*' notifications once each
	// batch's window elapses. Immediate delivery is unaffected.
	digestStop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-digestStop:
				return
			case <-ticker.C:
				if n, err := notificationService.FlushDueDigests(context.Background()); err != nil {
					log.Printf("digest flush error: %v", err)
				} else if n > 0 {
					log.Printf("digest flush delivered %d batched notification(s)", n)
				}
			}
		}
	}()
	log.Println("Digest flush worker started (1m interval)")

	// Delivery retry worker: re-attempts channel sends that failed, with
	// exponential backoff and a bounded attempt count, scoped to the individual
	// failed channel. Kill-switch NOTIFICATION_DELIVERY_RETRY_ENABLED=false
	// disables both enqueuing and this drain (house pattern, matching
	// compliance-engine's COMPLIANCE_RECONCILE_WORKER_ENABLED).
	retryStop := make(chan struct{})
	if services.DeliveryRetryEnabled() {
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-retryStop:
					return
				case <-ticker.C:
					if n, err := notificationService.RetryDueDeliveries(context.Background()); err != nil {
						log.Printf("delivery retry error: %v", err)
					} else if n > 0 {
						log.Printf("delivery retry redelivered %d notification(s)", n)
					}
				}
			}
		}()
		log.Printf("Delivery retry worker started (30s interval, max %d attempts)", services.MaxDeliveryAttempts())
	} else {
		log.Println("Delivery retry DISABLED (NOTIFICATION_DELIVERY_RETRY_ENABLED=false); a failed channel send is attempted once and lost")
	}

	// Retention cleanup worker: age out delivery logs (notification_history +
	// terminal delivery-queue rows) daily. Disabled if retention <= 0.
	retentionStop := make(chan struct{})
	go func() {
		retentionDays := services.HistoryRetentionDays()
		if retentionDays <= 0 {
			log.Println("Notification history retention cleanup disabled")
			return
		}
		// Run once shortly after boot, then daily.
		run := func() {
			if n, err := notificationService.CleanupOldHistory(context.Background(), retentionDays); err != nil {
				log.Printf("history retention cleanup error: %v", err)
			} else if n > 0 {
				log.Printf("history retention cleanup removed %d row(s) older than %dd", n, retentionDays)
			}
		}
		first := time.NewTimer(5 * time.Minute)
		defer first.Stop()
		select {
		case <-retentionStop:
			return
		case <-first.C:
			run()
		}
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-retentionStop:
				return
			case <-ticker.C:
				run()
			}
		}
	}()
	log.Printf("History retention cleanup worker started (%dd retention)", services.HistoryRetentionDays())

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down notification service...")

	close(digestStop)
	close(retryStop)
	close(retentionStop)

	// Stop NATS subscribers
	if notifSubscriber != nil {
		notifSubscriber.Stop()
	}
	if natsClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := natsClient.GracefulShutdown(ctx); err != nil {
			log.Printf("NATS client failed to shut down gracefully: %v", err)
		}
	}

	log.Println("Notification service stopped")
}
