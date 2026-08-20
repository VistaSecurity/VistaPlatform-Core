package jobs

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/services"
)

// RetentionJob handles automated retention policy execution
type RetentionJob struct {
	retentionService    *services.RetentionService
	jobExecutionService *services.JobExecutionService
	s3ArchivalService   *services.S3ArchivalService
	activityLogService  *services.ActivityLogService
	interval            time.Duration
	logger              *log.Logger
}

// NewRetentionJob creates a new retention job (without S3)
func NewRetentionJob(retentionService *services.RetentionService, jobExecutionService *services.JobExecutionService) *RetentionJob {
	interval := 24 * time.Hour // Default: run daily
	return &RetentionJob{
		retentionService:    retentionService,
		jobExecutionService: jobExecutionService,
		interval:            interval,
		logger:              log.New(log.Writer(), "[RetentionJob] ", log.LstdFlags),
	}
}

// NewRetentionJobWithS3 creates a new retention job with S3 archival support
func NewRetentionJobWithS3(
	retentionService *services.RetentionService,
	jobExecutionService *services.JobExecutionService,
	s3ArchivalService *services.S3ArchivalService,
	activityLogService *services.ActivityLogService,
) *RetentionJob {
	interval := 24 * time.Hour // Default: run daily
	return &RetentionJob{
		retentionService:    retentionService,
		jobExecutionService: jobExecutionService,
		s3ArchivalService:   s3ArchivalService,
		activityLogService:  activityLogService,
		interval:            interval,
		logger:              log.New(log.Writer(), "[RetentionJob] ", log.LstdFlags),
	}
}

// Start begins the retention job process
func (j *RetentionJob) Start(ctx context.Context) {
	j.logger.Printf("Starting retention job (interval: %v)", j.interval)

	// Run immediately on start
	j.executeRetention(ctx)

	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			j.logger.Println("Stopping retention job")
			return
		case <-ticker.C:
			j.executeRetention(ctx)
		}
	}
}

// executeRetention runs retention policies
func (j *RetentionJob) executeRetention(ctx context.Context) {
	j.logger.Println("Running retention job cycle")

	// Get all active retention policies
	policies, err := j.retentionService.GetRetentionPolicies(ctx)
	if err != nil {
		j.logger.Printf("ERROR: Failed to get retention policies: %v", err)
		return
	}

	if len(policies) == 0 {
		j.logger.Println("No retention policies found")
		return
	}

	j.logger.Printf("Processing %d retention policies", len(policies))

	// Process each policy
	for _, policy := range policies {
		if !policy.IsActive {
			continue
		}

		select {
		case <-ctx.Done():
			return
		default:
			j.processPolicy(ctx, policy)
		}
	}

	j.logger.Println("Completed retention job cycle")
}

// processPolicy processes a single retention policy
func (j *RetentionJob) processPolicy(ctx context.Context, policy services.RetentionPolicy) {
	jobID := uuid.New()
	jobName := fmt.Sprintf("Retention: %s", policy.PolicyName)

	// Use job execution service directly
	logID, err := j.jobExecutionService.LogJobStart(ctx, jobID, "retention", jobName, nil, nil, map[string]interface{}{
		"policy_id":   policy.ID.String(),
		"policy_name": policy.PolicyName,
	})
	if err != nil {
		j.logger.Printf("WARNING: Failed to log retention job start: %v", err)
		return
	}

	j.logger.Printf("Retention job logged with ID: %s", logID)

	// Archive logs (move to cold storage)
	archivedCount := 0
	var archiveS3Keys []string
	if policy.ColdStorageDays != nil {
		logIDs, err := j.retentionService.GetLogsForArchival(ctx, &policy)
		if err != nil {
			j.logger.Printf("ERROR: Failed to get logs for archival: %v", err)
			errorMsg := err.Error()
			_ = j.jobExecutionService.LogJobCompletion(ctx, logID, "failed", &errorMsg, nil)
			return
		}

		if len(logIDs) > 0 {
			j.logger.Printf("Archiving %d logs for policy %s", len(logIDs), policy.PolicyName)

			// Check if S3 archival is available
			if j.s3ArchivalService != nil && j.s3ArchivalService.IsEnabled() && j.activityLogService != nil {
				// Fetch the actual log entries for archival
				logs, err := j.activityLogService.GetActivityLogsByIDs(ctx, logIDs)
				if err != nil {
					j.logger.Printf("ERROR: Failed to fetch logs for archival: %v", err)
					errorMsg := err.Error()
					_ = j.jobExecutionService.LogJobCompletion(ctx, logID, "failed", &errorMsg, nil)
					return
				}

				// Archive to S3
				result, err := j.s3ArchivalService.ArchiveLogs(ctx, logs, policy.TenantID)
				if err != nil {
					j.logger.Printf("ERROR: Failed to archive logs to S3: %v", err)
					errorMsg := err.Error()
					_ = j.jobExecutionService.LogJobCompletion(ctx, logID, "failed", &errorMsg, nil)
					return
				}

				archivedCount = result.LogsArchived
				archiveS3Keys = append(archiveS3Keys, result.S3Key)
				j.logger.Printf("Archived %d logs to S3: %s", result.LogsArchived, result.S3Key)

				// Mark logs as archived in the database. This stamp is the ONLY
				// evidence the later delete step consults (FilterArchivedLogs),
				// so a failure here must fail the whole policy run rather than
				// warn: unstamped rows are re-selected next cycle and
				// re-uploaded under a fresh S3 key, and the cycle would
				// otherwise still report logs_archived: N. Returning here also
				// skips the delete step, which is the safe direction.
				if err := j.retentionService.MarkLogsAsArchived(ctx, logIDs, result.S3Key); err != nil {
					j.logger.Printf("ERROR: Failed to mark logs as archived: %v", err)
					errorMsg := err.Error()
					_ = j.jobExecutionService.LogJobCompletion(ctx, logID, "failed", &errorMsg, nil)
					return
				}
			} else {
				// S3 not enabled - just log the count
				j.logger.Println("S3 archival not configured, skipping actual archival")
				archivedCount = len(logIDs)
			}

			_ = j.jobExecutionService.LogJobProgress(ctx, logID, len(logIDs), len(logIDs), 0)
		}
	}

	// Delete logs (past retention period)
	deleteLogIDs, err := j.retentionService.GetLogsForDeletion(ctx, &policy)
	if err != nil {
		j.logger.Printf("ERROR: Failed to get logs for deletion: %v", err)
		errorMsg := err.Error()
		_ = j.jobExecutionService.LogJobCompletion(ctx, logID, "failed", &errorMsg, nil)
		return
	}

	deletedCount := 0
	if len(deleteLogIDs) > 0 {
		j.logger.Printf("Deleting %d logs for policy %s", len(deleteLogIDs), policy.PolicyName)

		// Only delete logs that have been archived (if archival is enabled)
		if j.s3ArchivalService != nil && j.s3ArchivalService.IsEnabled() {
			// Verify logs are archived before deletion
			archivedLogIDs, err := j.retentionService.FilterArchivedLogs(ctx, deleteLogIDs)
			if err != nil {
				j.logger.Printf("ERROR: Failed to filter archived logs: %v", err)
				errorMsg := err.Error()
				_ = j.jobExecutionService.LogJobCompletion(ctx, logID, "failed", &errorMsg, nil)
				return
			}

			if len(archivedLogIDs) > 0 {
				if err := j.retentionService.DeleteLogs(ctx, archivedLogIDs); err != nil {
					j.logger.Printf("ERROR: Failed to delete logs: %v", err)
					errorMsg := err.Error()
					_ = j.jobExecutionService.LogJobCompletion(ctx, logID, "failed", &errorMsg, nil)
					return
				}
				deletedCount = len(archivedLogIDs)
			}
		} else {
			// S3 not enabled - delete directly (data loss risk!)
			j.logger.Println("WARNING: Deleting logs without S3 archival - data will be lost")
			if err := j.retentionService.DeleteLogs(ctx, deleteLogIDs); err != nil {
				j.logger.Printf("ERROR: Failed to delete logs: %v", err)
				errorMsg := err.Error()
				_ = j.jobExecutionService.LogJobCompletion(ctx, logID, "failed", &errorMsg, nil)
				return
			}
			deletedCount = len(deleteLogIDs)
		}

		_ = j.jobExecutionService.LogJobProgress(ctx, logID, len(deleteLogIDs), len(deleteLogIDs), 0)
	}

	// Log job completion
	completionMetadata := map[string]interface{}{
		"policy_id":     policy.ID.String(),
		"logs_archived": archivedCount,
		"logs_deleted":  deletedCount,
	}
	if len(archiveS3Keys) > 0 {
		completionMetadata["s3_keys"] = archiveS3Keys
	}

	_ = j.jobExecutionService.LogJobCompletion(ctx, logID, "completed", nil, completionMetadata)
}
