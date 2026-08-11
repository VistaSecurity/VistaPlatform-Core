package jobs

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
)

// StaleFindingCleanupJob archives findings that have been INACTIVE for more than the retention period.
//
// bypassDB is the BYPASSRLS handle (crypto_bypass): the archive sweep in Run is
// deliberately cross-tenant (no tenant_id filter) and would fail closed on the
// RLS-bound crypto_app role (Phase 4).
type StaleFindingCleanupJob struct {
	bypassDB        *sqlx.DB
	findingService  *services.FindingsService
	retentionDays   int
	gracePeriodDays int
	batchSize       int
}

// NewStaleFindingCleanupJob creates a new stale finding cleanup job. bypassDB is the
// BYPASSRLS pool used for the cross-tenant archive sweep.
func NewStaleFindingCleanupJob(bypassDB *sqlx.DB, findingService *services.FindingsService, retentionDays, gracePeriodDays, batchSize int) *StaleFindingCleanupJob {
	if retentionDays <= 0 {
		retentionDays = 90 // Default 90 days
	}
	if gracePeriodDays <= 0 {
		gracePeriodDays = 7 // Default 7 days grace period before auto-close
	}
	if batchSize <= 0 {
		batchSize = 1000 // Default batch size
	}
	return &StaleFindingCleanupJob{
		bypassDB:        bypassDB,
		findingService:  findingService,
		retentionDays:   retentionDays,
		gracePeriodDays: gracePeriodDays,
		batchSize:       batchSize,
	}
}

// Run executes the cleanup job
func (j *StaleFindingCleanupJob) Run(ctx context.Context) error {
	log.Printf("[StaleFindingCleanup] Starting cleanup job (retention: %d days, grace period: %d days)", j.retentionDays, j.gracePeriodDays)

	// First, auto-close findings that have been INACTIVE for the grace period
	if j.findingService != nil {
		if err := j.findingService.AutoCloseInactiveFindings(ctx, j.gracePeriodDays); err != nil {
			log.Printf("[StaleFindingCleanup] Warning: Failed to auto-close inactive findings: %v", err)
		}
	}

	cutoffDate := time.Now().AddDate(0, 0, -j.retentionDays)
	archivedCount := 0

	for {
		// RLS: cross-tenant sweep — archives stale INACTIVE findings across ALL tenants
		// (no tenant_id filter). Runs on the bypass role (Phase 4); not wrapped in
		// WithTenantTx because it is intentionally tenant-agnostic.
		// Get batch of stale findings
		query := `
			UPDATE compliance_findings
			SET detection_state = 'ARCHIVED',
			    updated_at = NOW()
			WHERE detection_state = 'INACTIVE'
			  AND last_seen < $1
			  AND id IN (
			      SELECT id FROM compliance_findings
			      WHERE detection_state = 'INACTIVE'
			        AND last_seen < $1
			      LIMIT $2
			  )
			RETURNING id
		`

		var archivedIDs []string
		err := j.bypassDB.SelectContext(ctx, &archivedIDs, query, cutoffDate, j.batchSize)
		if err != nil {
			return fmt.Errorf("failed to archive findings: %w", err)
		}

		if len(archivedIDs) == 0 {
			break // No more findings to archive
		}

		archivedCount += len(archivedIDs)
		log.Printf("[StaleFindingCleanup] Archived %d findings (total: %d)", len(archivedIDs), archivedCount)

		// Small delay to avoid overwhelming the database
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}

	log.Printf("[StaleFindingCleanup] Cleanup complete: archived %d findings", archivedCount)
	return nil
}

// StartPeriodic starts the job on a schedule
func (j *StaleFindingCleanupJob) StartPeriodic(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run immediately on start
	if err := j.Run(ctx); err != nil {
		log.Printf("[StaleFindingCleanup] Error in initial run: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := j.Run(ctx); err != nil {
				log.Printf("[StaleFindingCleanup] Error in periodic run: %v", err)
			}
		}
	}
}
