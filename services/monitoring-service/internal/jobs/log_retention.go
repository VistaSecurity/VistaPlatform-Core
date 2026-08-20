package jobs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
)

// LogRetentionJob handles retention policy enforcement for compliance logging
// Archives logs older than 90 days and deletes logs older than 365 days.
//
// RLS: cross-tenant — runs on the bypass role (Phase 4). This is a background
// retention sweep over platform_log_metadata (an RLS-policied table) keyed on
// timestamp/status across ALL tenants, not a single-tenant operation, so it is
// not wrapped in WithTenantTx.
type LogRetentionJob struct {
	db          *sql.DB
	bypassDB    *sql.DB // BYPASSRLS handle for the cross-tenant platform_log_metadata sweeps
	s3Client    *s3.Client
	bucket      string
	hotDays     int // Default: 90 days for hot storage
	archiveDays int // Default: 365 days total (archive after 90 days)
	logger      *log.Logger
}

// NewLogRetentionJob creates a new log retention job.
//
// bypassDB is the BYPASSRLS (crypto_bypass) handle used by the
// platform_log_metadata archive/delete sweeps — that table is RLS-policied but
// the sweep is keyed on timestamp/status across ALL tenants, so under crypto_app
// it would fail closed.
func NewLogRetentionJob(db, bypassDB *sql.DB, s3Client *s3.Client, bucket string) *LogRetentionJob {
	hotDays := 90
	archiveDays := 365

	return &LogRetentionJob{
		db:          db,
		bypassDB:    bypassDB,
		s3Client:    s3Client,
		bucket:      bucket,
		hotDays:     hotDays,
		archiveDays: archiveDays,
		logger:      log.New(log.Writer(), "[LogRetentionJob] ", log.LstdFlags),
	}
}

// Start begins the retention policy job execution
// Runs at the configured interval to enforce retention policies
func (j *LogRetentionJob) Start(ctx context.Context, interval time.Duration) {
	j.logger.Println("Starting log retention job")

	// Run immediately on start
	j.runRetentionPolicy(ctx)

	if interval <= 0 {
		interval = 24 * time.Hour
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			j.logger.Println("Stopping log retention job")
			return
		case <-ticker.C:
			j.runRetentionPolicy(ctx)
		}
	}
}

// runRetentionPolicy executes the retention policy enforcement
func (j *LogRetentionJob) runRetentionPolicy(ctx context.Context) {
	j.logger.Println("Running retention policy enforcement")

	jobID := uuid.New()
	startTime := time.Now()

	// Record job start
	err := j.recordJobStart(ctx, jobID, "full_retention", startTime)
	if err != nil {
		j.logger.Printf("ERROR: Failed to record job start: %v", err)
		return
	}

	// Step 1: Archive logs older than 90 days (move from hot to archive)
	// Both step errors are kept and joined below. Reusing one `err` let the
	// delete step's (usually nil) result overwrite an archive failure, so a
	// failed archive was recorded as a completed job.
	archivedCount, archiveErr := j.archiveOldLogs(ctx, jobID)
	if archiveErr != nil {
		j.logger.Printf("ERROR: Failed to archive logs: %v", archiveErr)
	}

	// Step 2: Delete logs older than 365 days (soft delete for compliance)
	deletedCount, deleteErr := j.deleteOldLogs(ctx, jobID)
	if deleteErr != nil {
		j.logger.Printf("ERROR: Failed to delete logs: %v", deleteErr)
	}

	// Step 3: Cleanup S3 objects for deleted logs (optional - keep for compliance)
	// Note: For compliance, we may want to keep S3 objects even after soft delete
	// This is configurable based on compliance requirements

	duration := time.Since(startTime)

	// Record job completion
	if err := j.recordJobCompletion(ctx, jobID, archivedCount, deletedCount, 0, duration, errors.Join(archiveErr, deleteErr)); err != nil {
		j.logger.Printf("ERROR: Failed to record job completion: %v", err)
		return
	}

	j.logger.Printf("Retention policy completed: archived %d, deleted %d logs in %v", archivedCount, deletedCount, duration)
}

// archiveOldLogs archives logs older than hot retention period (90 days)
func (j *LogRetentionJob) archiveOldLogs(ctx context.Context, jobID uuid.UUID) (int, error) {
	archiveThreshold := time.Now().AddDate(0, 0, -j.hotDays)

	query := `
		UPDATE platform_log_metadata
		SET status = 'archived',
		    archived_at = NOW(),
		    updated_at = NOW()
		WHERE status = 'active'
		  AND retention_policy = '90-days-hot'
		  AND timestamp < $1
		  AND archived_at IS NULL
	`

	result, err := j.bypassDB.ExecContext(ctx, query, archiveThreshold)
	if err != nil {
		return 0, fmt.Errorf("failed to archive logs: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	j.logger.Printf("Archived %d logs older than %d days", rowsAffected, j.hotDays)
	return int(rowsAffected), nil
}

// deleteOldLogs soft deletes logs older than archive retention period (365 days)
func (j *LogRetentionJob) deleteOldLogs(ctx context.Context, jobID uuid.UUID) (int, error) {
	deleteThreshold := time.Now().AddDate(0, 0, -j.archiveDays)

	query := `
		UPDATE platform_log_metadata
		SET status = 'deleted',
		    deleted_at = NOW(),
		    updated_at = NOW()
		WHERE status IN ('active', 'archived')
		  AND timestamp < $1
		  AND deleted_at IS NULL
	`

	result, err := j.bypassDB.ExecContext(ctx, query, deleteThreshold)
	if err != nil {
		return 0, fmt.Errorf("failed to delete logs: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	j.logger.Printf("Soft deleted %d logs older than %d days", rowsAffected, j.archiveDays)
	return int(rowsAffected), nil
}

// recordJobStart records the start of a retention job
func (j *LogRetentionJob) recordJobStart(ctx context.Context, jobID uuid.UUID, jobType string, startTime time.Time) error {
	query := `
		INSERT INTO platform_log_retention_jobs (
			id, job_type, execution_status, started_at, created_at
		) VALUES (
			$1, $2, 'running', $3, NOW()
		)
	`

	_, err := j.db.ExecContext(ctx, query, jobID, jobType, startTime)
	return err
}

// recordJobCompletion records the completion of a retention job
func (j *LogRetentionJob) recordJobCompletion(ctx context.Context, jobID uuid.UUID, archived, deleted, scrubbed int, duration time.Duration, jobError error) error {
	status := "completed"
	errorMessage := ""
	if jobError != nil {
		status = "failed"
		errorMessage = jobError.Error()
	}

	// Two things this statement gets wrong if you write it the obvious way, and
	// neither is visible from Go — the row simply never leaves 'running':
	//
	//  1. No updated_at. platform_log_retention_jobs has created_at /
	//     started_at / completed_at only (see schema.sql); setting updated_at
	//     raised 42703. completed_at already carries the finish timestamp.
	//  2. The counters must be cast. `$2 + $3 + $4` is `unknown + unknown`,
	//     which Postgres refuses as ambiguous (42725, "operator is not
	//     unique") — a parameter only borrows a type from the column it is
	//     assigned to, never from an arithmetic expression.
	query := `
		UPDATE platform_log_retention_jobs
		SET execution_status = $1,
		    logs_processed = $2::int + $3::int + $4::int,
		    logs_archived = $2::int,
		    logs_deleted = $3::int,
		    logs_scrubbed = $4::int,
		    completed_at = NOW(),
		    duration_ms = $5,
		    error_message = $6
		WHERE id = $7
	`

	_, err := j.db.ExecContext(ctx, query, status, archived, deleted, scrubbed, int(duration.Milliseconds()), errorMessage, jobID)
	return err
}

// GetRetentionJobHistory returns recent retention job execution history
func (j *LogRetentionJob) GetRetentionJobHistory(ctx context.Context, limit int) ([]RetentionJobRecord, error) {
	if limit <= 0 {
		limit = 10
	}

	query := `
		SELECT id, job_type, execution_status, logs_processed, logs_archived,
		       logs_deleted, logs_scrubbed, started_at, completed_at, duration_ms,
		       error_message, created_at
		FROM platform_log_retention_jobs
		ORDER BY started_at DESC
		LIMIT $1
	`

	rows, err := j.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query retention jobs: %w", err)
	}
	defer rows.Close()

	var records []RetentionJobRecord
	for rows.Next() {
		var record RetentionJobRecord
		var completedAt, errorMessage sql.NullString
		var durationMs sql.NullInt64

		err := rows.Scan(
			&record.ID, &record.JobType, &record.Status,
			&record.LogsProcessed, &record.LogsArchived,
			&record.LogsDeleted, &record.LogsScrubbed,
			&record.StartedAt, &completedAt, &durationMs,
			&errorMessage, &record.CreatedAt,
		)
		if err != nil {
			continue
		}

		if completedAt.Valid {
			parsed, _ := time.Parse(time.RFC3339, completedAt.String)
			record.CompletedAt = &parsed
		}
		if durationMs.Valid {
			duration := time.Duration(durationMs.Int64) * time.Millisecond
			record.Duration = &duration
		}
		if errorMessage.Valid {
			record.ErrorMessage = &errorMessage.String
		}

		records = append(records, record)
	}

	return records, nil
}

// RetentionJobRecord represents a retention job execution record
type RetentionJobRecord struct {
	ID            uuid.UUID
	JobType       string
	Status        string
	LogsProcessed int
	LogsArchived  int
	LogsDeleted   int
	LogsScrubbed  int
	StartedAt     time.Time
	CompletedAt   *time.Time
	Duration      *time.Duration
	ErrorMessage  *string
	CreatedAt     time.Time
}
