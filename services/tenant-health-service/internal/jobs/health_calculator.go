package jobs

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/repository"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/service"
)

// HealthCalculator periodically calculates health scores for all active tenants
type HealthCalculator struct {
	healthService *service.HealthService
	repo          *repository.HealthRepository
	db            *sql.DB
	logger        *logrus.Logger
	interval      time.Duration
	workers       int
}

// NewHealthCalculator creates a new health calculator job
func NewHealthCalculator(healthService *service.HealthService, repo *repository.HealthRepository) *HealthCalculator {
	// Get database connection for tenant queries
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "postgres://crypto_user:crypto_pass_dev@localhost:5432/crypto_inventory?sslmode=disable"
	}

	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database for HealthCalculator: %v", err)
	}

	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database for HealthCalculator: %v", err)
	}

	interval := 30 * time.Minute // Default: calculate every 30 minutes
	if intervalStr := os.Getenv("HEALTH_CALCULATION_INTERVAL"); intervalStr != "" {
		if parsed, err := time.ParseDuration(intervalStr); err == nil {
			interval = parsed
		}
	}

	workers := 5 // Default: 5 concurrent workers
	if workersStr := os.Getenv("HEALTH_CALCULATION_WORKERS"); workersStr != "" {
		var parsed int
		if n, err := fmt.Sscanf(workersStr, "%d", &parsed); err == nil && n == 1 && parsed > 0 {
			workers = parsed
		}
	}

	return &HealthCalculator{
		healthService: healthService,
		repo:          repo,
		db:            db,
		logger:        logrus.New(),
		interval:      interval,
		workers:       workers,
	}
}

// Start begins the health calculation process
func (hc *HealthCalculator) Start(ctx context.Context) {
	hc.logger.WithField("interval", hc.interval).Info("Starting health calculator job")
	hc.logger.WithField("workers", hc.workers).Info("Health calculator configured")

	ticker := time.NewTicker(hc.interval)
	defer ticker.Stop()

	// Calculate immediately on start
	hc.calculateAllTenantHealth(ctx)

	for {
		select {
		case <-ctx.Done():
			hc.logger.Info("Health calculator stopping")
			if err := hc.db.Close(); err != nil {
				hc.logger.WithError(err).Warn("Failed to close health calculator database connection")
			}
			return
		case <-ticker.C:
			hc.calculateAllTenantHealth(ctx)
		}
	}
}

// calculateAllTenantHealth calculates health scores for all active tenants
func (hc *HealthCalculator) calculateAllTenantHealth(ctx context.Context) {
	hc.logger.Info("Starting health calculation cycle for all tenants")

	// Get all active tenant IDs
	tenantIDs, err := hc.repo.GetAllActiveTenantIDs()
	if err != nil {
		hc.logger.WithError(err).Error("Failed to get active tenant IDs")
		return
	}

	if len(tenantIDs) == 0 {
		hc.logger.Info("No active tenants found")
		return
	}

	hc.logger.WithField("tenant_count", len(tenantIDs)).Info("Calculating health for tenants")

	// Use worker pool to process tenants concurrently
	tenantChan := make(chan uuid.UUID, len(tenantIDs))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < hc.workers; i++ {
		wg.Add(1)
		go hc.worker(ctx, tenantChan, &wg)
	}

	// Send tenant IDs to channel
	for _, tenantID := range tenantIDs {
		select {
		case <-ctx.Done():
			close(tenantChan)
			wg.Wait()
			return
		case tenantChan <- tenantID:
		}
	}

	close(tenantChan)
	wg.Wait()

	hc.logger.WithField("tenant_count", len(tenantIDs)).Info("Completed health calculation cycle")
}

// worker processes tenant health calculations from the channel
func (hc *HealthCalculator) worker(ctx context.Context, tenantChan <-chan uuid.UUID, wg *sync.WaitGroup) {
	defer wg.Done()

	for tenantID := range tenantChan {
		select {
		case <-ctx.Done():
			return
		default:
			// Calculate health for this tenant
			_, err := hc.healthService.CalculateTenantHealthAuto(tenantID)
			if err != nil {
				hc.logger.WithError(err).
					WithField("tenant_id", tenantID).
					Error("Failed to calculate health for tenant")
			} else {
				hc.logger.WithField("tenant_id", tenantID).
					Debug("Successfully calculated health for tenant")
			}
		}
	}
}
