package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	stdlog "log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

type JobExecutionService struct {
	db       *sql.DB
	bypassDB *sql.DB
}

func NewJobExecutionService(db, bypassDB *sql.DB) *JobExecutionService {
	return &JobExecutionService{db: db, bypassDB: bypassDB}
}

// LogJobStart logs the start of a job execution
func (s *JobExecutionService) LogJobStart(ctx context.Context, jobID uuid.UUID, jobType, jobName string, tenantID, initiatedBy *uuid.UUID, metadata map[string]interface{}) (uuid.UUID, error) {
	logID := uuid.New()
	now := time.Now()

	metadataJSON, _ := json.Marshal(metadata)

	query := `
		INSERT INTO audit.job_execution_logs (
			id, job_id, job_type, job_name, tenant_id, initiated_by,
			status, started_at, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	jobNamePtr := &jobName
	if jobName == "" {
		jobNamePtr = nil
	}

	args := []interface{}{
		logID, jobID, jobType, jobNamePtr, tenantID, initiatedBy,
		"running", now, metadataJSON, now,
	}

	// RLS-scoped write on audit.job_execution_logs. A tenant-scoped job carries a
	// non-nil tenantID — wrap so app.tenant_id satisfies the policy's WITH CHECK.
	// System/background jobs (posture snapshot, retention, partition) pass nil:
	// the row's tenant_id is NULL, the policy cannot match it, and there is no
	// tenant in hand — that write stays on the bypass role.
	if tenantID != nil {
		err := shareddatabase.WithTenantTx(ctx, s.db, *tenantID, func(tx *sql.Tx) error {
			_, e := tx.ExecContext(ctx, query, args...)
			return e
		})
		return logID, err
	}

	// RLS: cross-tenant — system job with NULL tenant_id, runs on the bypass role (Phase 4).
	_, err := s.bypassDB.ExecContext(ctx, query, args...)
	return logID, err
}

// LogJobProgress updates job progress
func (s *JobExecutionService) LogJobProgress(ctx context.Context, logID uuid.UUID, itemsProcessed, itemsSucceeded, itemsFailed int) error {
	query := `
		UPDATE audit.job_execution_logs
		SET items_processed = $1,
		    items_succeeded = $2,
		    items_failed = $3
		WHERE id = $4
	`

	// RLS: cross-tenant — updates the job row by id only (no tenant in hand;
	// callers include system jobs whose row has a NULL tenant_id), runs on the
	// bypass role (Phase 4).
	_, err := s.bypassDB.ExecContext(ctx, query, itemsProcessed, itemsSucceeded, itemsFailed, logID)
	return err
}

// LogJobCompletion logs job completion
func (s *JobExecutionService) LogJobCompletion(ctx context.Context, logID uuid.UUID, status string, errorMessage *string, errorDetails map[string]interface{}) error {
	now := time.Now()

	// Calculate duration.
	// RLS: cross-tenant — looks the job row up by id only (no tenant in hand;
	// system jobs have a NULL tenant_id), runs on the bypass role (Phase 4).
	var startedAt time.Time
	err := s.bypassDB.QueryRowContext(ctx, "SELECT started_at FROM audit.job_execution_logs WHERE id = $1", logID).Scan(&startedAt)
	if err != nil {
		return err
	}

	durationMs := int(now.Sub(startedAt).Milliseconds())

	var errorDetailsJSON []byte
	if errorDetails != nil {
		errorDetailsJSON, _ = json.Marshal(errorDetails)
	}

	query := `
		UPDATE audit.job_execution_logs
		SET status = $1,
		    completed_at = $2,
		    duration_ms = $3,
		    error_message = $4,
		    error_details = $5
		WHERE id = $6
	`

	// RLS: cross-tenant — updates the job row by id only (no tenant in hand),
	// runs on the bypass role (Phase 4).
	_, err = s.bypassDB.ExecContext(ctx, query, status, now, durationMs, errorMessage, errorDetailsJSON, logID)
	return err
}

// GetJobExecutionLogs retrieves job execution logs with filtering
func (s *JobExecutionService) GetJobExecutionLogs(ctx context.Context, filters models.JobExecutionLogFilters) ([]models.JobExecutionLog, int, error) {
	var conditions []string
	var args []interface{}
	argIndex := 1

	// Build WHERE clause
	if filters.JobID != nil {
		conditions = append(conditions, fmt.Sprintf("job_id = $%d", argIndex))
		args = append(args, *filters.JobID)
		argIndex++
	}

	if len(filters.JobType) > 0 {
		conditions = append(conditions, fmt.Sprintf("job_type = ANY($%d)", argIndex))
		args = append(args, pq.Array(filters.JobType))
		argIndex++
	}

	if filters.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, *filters.TenantID)
		argIndex++
	}

	if filters.InitiatedBy != nil {
		conditions = append(conditions, fmt.Sprintf("initiated_by = $%d", argIndex))
		args = append(args, *filters.InitiatedBy)
		argIndex++
	}

	if len(filters.Status) > 0 {
		conditions = append(conditions, fmt.Sprintf("status = ANY($%d)", argIndex))
		args = append(args, pq.Array(filters.Status))
		argIndex++
	}

	if filters.StartDate != nil {
		conditions = append(conditions, fmt.Sprintf("started_at >= $%d", argIndex))
		args = append(args, *filters.StartDate)
		argIndex++
	}

	if filters.EndDate != nil {
		conditions = append(conditions, fmt.Sprintf("started_at <= $%d", argIndex))
		args = append(args, *filters.EndDate)
		argIndex++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM audit.job_execution_logs %s", whereClause)

	// Build ORDER BY
	sortBy := filters.SortBy
	if sortBy == "" {
		sortBy = "started_at"
	}
	sortOrder := filters.SortOrder
	if sortOrder == "" {
		sortOrder = "DESC"
	}

	// Whitelist allowed sort columns to prevent SQL injection
	validSortColumns := map[string]string{
		"job_id":          "job_id",
		"job_type":        "job_type",
		"job_name":        "job_name",
		"status":          "status",
		"started_at":      "started_at",
		"completed_at":    "completed_at",
		"duration_ms":     "duration_ms",
		"items_processed": "items_processed",
		"items_succeeded": "items_succeeded",
		"items_failed":    "items_failed",
		"created_at":      "created_at",
	}
	safeSortBy, ok := validSortColumns[sortBy]
	if !ok {
		safeSortBy = "started_at"
	}
	if sortOrder != "ASC" && sortOrder != "asc" {
		sortOrder = "DESC"
	}

	// Build LIMIT and OFFSET
	page := filters.Page
	if page < 1 {
		page = 1
	}
	pageSize := filters.PageSize
	if pageSize < 1 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize

	// Build final query
	//nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
	query := fmt.Sprintf(`
		SELECT 
			id, job_id, job_type, job_name, tenant_id, initiated_by,
			status, started_at, completed_at, duration_ms,
			items_processed, items_succeeded, items_failed,
			error_message, error_details, metadata, created_at
		FROM audit.job_execution_logs
		%s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d
	`, whereClause, safeSortBy, sortOrder, argIndex, argIndex+1)

	selectArgs := append(append([]interface{}{}, args...), pageSize, offset)

	var logs []models.JobExecutionLog
	var total int

	run := func(db jobLogQueryer) error {
		if err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
			return err
		}

		rows, err := db.QueryContext(ctx, query, selectArgs...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var log models.JobExecutionLog
			var errorDetailsJSON, metadataJSON []byte

			if err := rows.Scan(
				&log.ID, &log.JobID, &log.JobType, &log.JobName, &log.TenantID, &log.InitiatedBy,
				&log.Status, &log.StartedAt, &log.CompletedAt, &log.DurationMs,
				&log.ItemsProcessed, &log.ItemsSucceeded, &log.ItemsFailed,
				&log.ErrorMessage, &errorDetailsJSON, &metadataJSON, &log.CreatedAt,
			); err != nil {
				return err
			}

			// Parse JSON fields. A decode failure must not read as "this job
			// recorded no error details".
			if len(errorDetailsJSON) > 0 {
				if err := json.Unmarshal(errorDetailsJSON, &log.ErrorDetails); err != nil {
					stdlog.Printf("[JobExecution] Failed to decode error_details for job log %s: %v", log.ID, err)
				}
			}
			if len(metadataJSON) > 0 {
				if err := json.Unmarshal(metadataJSON, &log.Metadata); err != nil {
					stdlog.Printf("[JobExecution] Failed to decode metadata for job log %s: %v", log.ID, err)
				}
			}

			logs = append(logs, log)
		}
		return rows.Err()
	}

	// RLS-scoped read on audit.job_execution_logs. Tenant callers pass a non-nil
	// TenantID (the explicit WHERE tenant_id is the primary control); platform /
	// system callers pass nil and read cross-tenant (system jobs also have NULL
	// tenant_id rows that a tenant-scoped session could not see).
	if filters.TenantID != nil {
		if err := shareddatabase.WithTenantTx(ctx, s.db, *filters.TenantID, func(tx *sql.Tx) error {
			return run(tx)
		}); err != nil {
			return nil, 0, err
		}
		return logs, total, nil
	}

	// RLS: cross-tenant — platform job-log read (filters.TenantID == nil), runs on
	// the bypass role (Phase 4).
	if err := run(s.bypassDB); err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}

// jobLogQueryer is the subset of *sql.DB / *sql.Tx the job-log reads need.
type jobLogQueryer interface {
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}
