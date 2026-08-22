package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/aws"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/repository"
)

// AWSCostSyncJob handles periodic synchronization of AWS costs
type AWSCostSyncJob struct {
	costRepo     *repository.AWSCostRepository
	costService  *aws.CostExplorerService
	enabled      bool
	syncInterval time.Duration
	log          *logrus.Logger
}

// NewAWSCostSyncJob creates a new AWS cost sync job
func NewAWSCostSyncJob(costRepo *repository.AWSCostRepository, costService *aws.CostExplorerService, enabled bool, syncInterval string, log *logrus.Logger) *AWSCostSyncJob {
	// Parse sync interval (e.g., "1h", "24h", "30m")
	interval := parseInterval(syncInterval)
	if interval == 0 {
		interval = 1 * time.Hour // Default to 1 hour
		log.Warnf("Invalid sync interval '%s', defaulting to 1h", syncInterval)
	}

	return &AWSCostSyncJob{
		costRepo:     costRepo,
		costService:  costService,
		enabled:      enabled,
		syncInterval: interval,
		log:          log,
	}
}

// Start begins the background job
func (j *AWSCostSyncJob) Start(ctx context.Context) {
	if !j.enabled {
		j.log.Info("AWS Cost Sync Job is disabled")
		return
	}

	if j.costService == nil {
		j.log.Warn("AWS Cost Explorer service not initialized, cost sync job will not run")
		return
	}

	j.log.WithFields(logrus.Fields{
		"interval": j.syncInterval,
	}).Info("Starting AWS Cost Sync Job")

	// Run immediately on start
	j.syncCosts(ctx)

	// Then run periodically
	ticker := time.NewTicker(j.syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			j.log.Info("AWS Cost Sync Job stopped")
			return
		case <-ticker.C:
			j.syncCosts(ctx)
		}
	}
}

// syncCosts performs the actual cost synchronization
func (j *AWSCostSyncJob) syncCosts(ctx context.Context) {
	j.log.Info("Starting AWS cost synchronization")

	// Determine sync period
	now := time.Now()
	// Sync last 7 days by default (AWS Cost Explorer typically has 24-48 hour delay)
	periodStart := now.AddDate(0, 0, -7)
	periodEnd := now.AddDate(0, 0, -1) // Yesterday (to account for AWS delay)

	// Record sync job
	jobID, err := j.costRepo.RecordSyncJob(ctx, "incremental", periodStart, periodEnd, nil)
	if err != nil {
		j.log.WithError(err).Error("Failed to record sync job")
		return
	}

	// Sync platform-wide costs (this will update the job status on completion)
	err = j.syncPlatformCosts(ctx, periodStart, periodEnd, jobID)
	if err != nil {
		errorMsg := err.Error()
		j.log.WithError(err).Error("Failed to sync platform costs")
		updateErr := j.costRepo.UpdateSyncJob(ctx, *jobID, "failed", 0, 0, &errorMsg)
		if updateErr != nil {
			j.log.WithError(updateErr).Error("Failed to update sync job status")
		}
		return
	}
}

// syncPlatformCosts syncs costs for the entire platform
func (j *AWSCostSyncJob) syncPlatformCosts(ctx context.Context, startDate, endDate time.Time, jobID *uuid.UUID) error {
	j.log.WithFields(logrus.Fields{
		"period_start": startDate.Format("2006-01-02"),
		"period_end":   endDate.Format("2006-01-02"),
	}).Info("Syncing platform-wide AWS costs")

	// Get costs from AWS Cost Explorer
	costs, err := j.costService.GetTotalPlatformCosts(ctx, startDate, endDate)
	if err != nil {
		return fmt.Errorf("failed to retrieve costs from AWS: %w", err)
	}

	if len(costs) == 0 {
		j.log.Warn("No costs retrieved from AWS Cost Explorer")
		return nil
	}

	// Store costs in database
	err = j.costRepo.StoreCostData(ctx, costs)
	if err != nil {
		return fmt.Errorf("failed to store cost data: %w", err)
	}

	// Calculate total cost
	var totalCost float64
	for _, cost := range costs {
		totalCost += cost.Amount
	}

	// Update job with statistics
	err = j.costRepo.UpdateSyncJob(ctx, *jobID, "completed", len(costs), totalCost, nil)
	if err != nil {
		j.log.WithError(err).Error("Failed to update sync job with statistics")
	}

	j.log.WithFields(logrus.Fields{
		"records_synced": len(costs),
		"total_cost_usd": totalCost,
	}).Info("Successfully synced AWS costs")

	return nil
}

// parseInterval parses a duration string (e.g., "1h", "30m", "24h")
func parseInterval(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return d
}
