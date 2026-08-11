package main

import (
	"context"
	"database/sql"
	"flag"
	"log"
	"os"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func main() {
	var (
		dbURL     = flag.String("db-url", "", "PostgreSQL connection URL (default: from DATABASE_URL env)")
		natsURL   = flag.String("nats-url", "", "NATS connection URL (default: from NATS_URL env)")
		tenantSlug = flag.String("tenant", "demo-corp", "Tenant slug to trigger evaluation for")
		wait      = flag.Bool("wait", false, "Wait for evaluation to complete and verify findings")
		timeout   = flag.Duration("timeout", 60*time.Second, "Timeout for waiting for evaluation")
	)
	flag.Parse()

	// Get database URL
	if *dbURL == "" {
		*dbURL = os.Getenv("DATABASE_URL")
		if *dbURL == "" {
			*dbURL = "postgres://crypto_user:crypto_pass_dev@localhost:5432/crypto_inventory?sslmode=disable"
		}
	}

	// Get NATS URL
	if *natsURL == "" {
		*natsURL = os.Getenv("NATS_URL")
		if *natsURL == "" {
			*natsURL = "nats://nats_user:nats_pass_dev@localhost:4222"
		}
	}

	// Connect to database
	db, err := sql.Open("postgres", *dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	// Get tenant ID
	var tenantID uuid.UUID
	err = db.QueryRow("SELECT id FROM tenants WHERE slug = $1 AND deleted_at IS NULL", *tenantSlug).Scan(&tenantID)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Fatalf("Tenant '%s' not found", *tenantSlug)
		}
		log.Fatalf("Failed to query tenant: %v", err)
	}

	log.Printf("Found tenant: %s (ID: %s)", *tenantSlug, tenantID)

	// Get all infrastructure assets for this tenant
	rows, err := db.Query(`
		SELECT id, hostname
		FROM network_assets
		WHERE tenant_id = $1
		AND deleted_at IS NULL
		ORDER BY created_at ASC
	`, tenantID)
	if err != nil {
		log.Fatalf("Failed to query infrastructure assets: %v", err)
	}
	defer rows.Close()

	var assetIDs []uuid.UUID
	var assetHostnames []string
	for rows.Next() {
		var assetID uuid.UUID
		var hostname string
		if err := rows.Scan(&assetID, &hostname); err != nil {
			log.Printf("Failed to scan asset: %v", err)
			continue
		}
		assetIDs = append(assetIDs, assetID)
		assetHostnames = append(assetHostnames, hostname)
	}

	if err := rows.Err(); err != nil {
		log.Fatalf("Error iterating infrastructure assets: %v", err)
	}

	log.Printf("Found %d infrastructure assets for tenant '%s'", len(assetIDs), *tenantSlug)

	// Also get all certificates for this tenant (they need separate evaluation)
	certRows, err := db.Query(`
		SELECT id, common_name
		FROM certificates
		WHERE tenant_id = $1
		ORDER BY created_at ASC
	`, tenantID)
	if err != nil {
		log.Fatalf("Failed to query certificates: %v", err)
	}
	defer certRows.Close()

	var certIDs []uuid.UUID
	for certRows.Next() {
		var certID uuid.UUID
		var commonName string
		if err := certRows.Scan(&certID, &commonName); err != nil {
			log.Printf("Failed to scan certificate: %v", err)
			continue
		}
		certIDs = append(certIDs, certID)
	}

	if err := certRows.Err(); err != nil {
		log.Fatalf("Error iterating certificates: %v", err)
	}

	log.Printf("Found %d certificates for tenant '%s'", len(certIDs), *tenantSlug)

	// Combine both asset types
	allAssetIDs := append(assetIDs, certIDs...)

	if len(allAssetIDs) == 0 {
		log.Printf("No assets found for tenant '%s'", *tenantSlug)
		return
	}

	log.Printf("Found %d total assets for tenant '%s'", len(allAssetIDs), *tenantSlug)

	// Connect to NATS
	natsClient, err := events.NewNATSClient(*natsURL)
	if err != nil {
		log.Fatalf("Failed to connect to NATS: %v", err)
	}
	defer natsClient.Close()

	// Wait for NATS to be ready
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := natsClient.HealthCheck(ctx); err != nil {
		log.Fatalf("NATS health check failed: %v", err)
	}

	log.Printf("Connected to NATS")

	// Create publisher
	publisher := events.NewNATSPublisher(natsClient, "compliance")
	defer publisher.Close()

	// Publish events for all assets (infrastructure assets + certificates)
	// Use bulk publish for efficiency if we have many assets
	if len(allAssetIDs) > 10 {
		log.Printf("Publishing bulk asset changed event for %d assets...", len(allAssetIDs))
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := publisher.PublishBulkAssetChanged(ctx, tenantID, allAssetIDs, events.ChangeTypeUpdated, "demo_seeding"); err != nil {
			log.Fatalf("Failed to publish bulk asset changed event: %v", err)
		}
		log.Printf("✅ Published bulk asset changed event")
	} else {
		log.Printf("Publishing individual asset changed events...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for i, assetID := range allAssetIDs {
			if err := publisher.PublishAssetChanged(ctx, tenantID, assetID, events.ChangeTypeUpdated, "demo_seeding"); err != nil {
				log.Printf("Failed to publish event for asset %d: %v", i, err)
				continue
			}
			if (i+1)%10 == 0 {
				log.Printf("Published events for %d/%d assets...", i+1, len(allAssetIDs))
			}
		}
		log.Printf("✅ Published asset changed events for %d assets", len(allAssetIDs))
	}

	// Optionally wait and verify findings
	if *wait {
		log.Printf("Waiting for evaluation to complete (timeout: %v)...", *timeout)
		startTime := time.Now()
		deadline := startTime.Add(*timeout)

		// Poll for findings
		for time.Now().Before(deadline) {
			var count int
			err := db.QueryRow(`
				SELECT COUNT(*)
				FROM compliance_findings
				WHERE tenant_id = $1
				AND detection_state = 'ACTIVE'
			`, tenantID).Scan(&count)
			if err != nil {
				log.Printf("Failed to query findings: %v", err)
				time.Sleep(2 * time.Second)
				continue
			}

			if count > 0 {
				log.Printf("✅ Found %d active compliance findings", count)
				return
			}

			time.Sleep(2 * time.Second)
		}

		log.Printf("⚠️  Timeout waiting for findings. They may still be processing.")
	}
}
