package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// SchedulerService handles scheduled interrogation jobs
type SchedulerService struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) connection used by the
	// cross-tenant background sweep (ProcessDueSchedules); per-schedule writes use
	// WithTenantTx under the resolved tenantID.
	bypassDB   *sql.DB
	jobQueue   *JobQueueService
	cronParser cron.Parser
}

// InterrogationSchedule represents a scheduled interrogation
type InterrogationSchedule struct {
	ID             uuid.UUID              `json:"id"`
	TenantID       uuid.UUID              `json:"tenant_id"`
	Name           string                 `json:"name"`
	Description    string                 `json:"description,omitempty"`
	CronExpression string                 `json:"cron_expression"`
	TargetType     string                 `json:"target_type"` // "device" or "cloud_integration"
	TargetID       uuid.UUID              `json:"target_id"`
	IsEnabled      bool                   `json:"is_enabled"`
	LastRunAt      *time.Time             `json:"last_run_at,omitempty"`
	LastRunStatus  string                 `json:"last_run_status,omitempty"` // scheduleRunPending / scheduleRunSuccess / scheduleRunFailed
	LastRunJobID   *uuid.UUID             `json:"last_run_job_id,omitempty"`
	NextRunAt      *time.Time             `json:"next_run_at,omitempty"`
	SuccessCount   int                    `json:"success_count"`
	FailureCount   int                    `json:"failure_count"`
	Parameters     map[string]interface{} `json:"parameters,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
	DeletedAt      *time.Time             `json:"deleted_at,omitempty"`
}

// CreateScheduleRequest represents a request to create a schedule
type CreateScheduleRequest struct {
	Name           string                 `json:"name" binding:"required"`
	Description    string                 `json:"description,omitempty"`
	CronExpression string                 `json:"cron_expression" binding:"required"`
	TargetType     string                 `json:"target_type" binding:"required"` // "device" or "cloud_integration"
	TargetID       uuid.UUID              `json:"target_id" binding:"required"`
	IsEnabled      *bool                  `json:"is_enabled,omitempty"`
	Parameters     map[string]interface{} `json:"parameters,omitempty"`
}

// UpdateScheduleRequest represents a request to update a schedule
type UpdateScheduleRequest struct {
	Name           *string                `json:"name,omitempty"`
	Description    *string                `json:"description,omitempty"`
	CronExpression *string                `json:"cron_expression,omitempty"`
	IsEnabled      *bool                  `json:"is_enabled,omitempty"`
	Parameters     map[string]interface{} `json:"parameters,omitempty"`
}

// ScheduleHistory represents a schedule execution history record
type ScheduleHistory struct {
	ID           uuid.UUID  `json:"id"`
	ScheduleID   uuid.UUID  `json:"schedule_id"`
	JobID        uuid.UUID  `json:"job_id"`
	Status       string     `json:"status"`
	StartedAt    time.Time  `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	ErrorMessage string     `json:"error_message,omitempty"`
	AssetsFound  int        `json:"assets_found"`
}

// NewSchedulerService creates a new scheduler service. db is the RLS-scoped
// (crypto_app) connection; bypassDB is the BYPASSRLS (crypto_bypass) connection
// for the cross-tenant due-schedule sweep. Pre-flip both handles resolve to the
// same connection.
func NewSchedulerService(db, bypassDB *sql.DB, jobQueue *JobQueueService) *SchedulerService {
	return &SchedulerService{
		db:         db,
		bypassDB:   bypassDB,
		jobQueue:   jobQueue,
		cronParser: cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow),
	}
}

// rowScanner abstracts *sql.Row and *sql.Rows for scanSchedule.
type rowScanner interface {
	Scan(dest ...interface{}) error
}

// scanSchedule scans the canonical 18-column schedule row shared by
// Create/Get/List/Update. description and last_run_status are nullable
// columns (NULL on every fresh row) but plain strings on the struct, so they
// go through sql.NullString — scanning them directly broke every Create and
// List call once a fresh schedule existed.
func scanSchedule(r rowScanner) (*InterrogationSchedule, error) {
	schedule := &InterrogationSchedule{}
	var parametersJSONB []byte
	var description, lastRunStatus, lastRunJobID sql.NullString

	if err := r.Scan(
		&schedule.ID, &schedule.TenantID, &schedule.Name, &description,
		&schedule.CronExpression, &schedule.TargetType, &schedule.TargetID,
		&schedule.IsEnabled, &schedule.LastRunAt, &lastRunStatus,
		&lastRunJobID, &schedule.NextRunAt, &schedule.SuccessCount,
		&schedule.FailureCount, &parametersJSONB, &schedule.CreatedAt,
		&schedule.UpdatedAt, &schedule.DeletedAt,
	); err != nil {
		return nil, err
	}

	schedule.Description = description.String
	schedule.LastRunStatus = lastRunStatus.String
	if len(parametersJSONB) > 0 {
		_ = json.Unmarshal(parametersJSONB, &schedule.Parameters)
	}
	if lastRunJobID.Valid {
		id, _ := uuid.Parse(lastRunJobID.String)
		schedule.LastRunJobID = &id
	}

	return schedule, nil
}

// CreateSchedule creates a new interrogation schedule
func (s *SchedulerService) CreateSchedule(ctx context.Context, tenantID uuid.UUID, req CreateScheduleRequest) (*InterrogationSchedule, error) {
	// Validate cron expression
	_, err := s.cronParser.Parse(req.CronExpression)
	if err != nil {
		return nil, fmt.Errorf("invalid cron expression: %w", err)
	}

	// Calculate next run time
	nextRun := s.calculateNextRun(req.CronExpression)

	scheduleID := uuid.New()
	now := time.Now()

	// Default to enabled if not specified
	isEnabled := true
	if req.IsEnabled != nil {
		isEnabled = *req.IsEnabled
	}

	// Convert parameters to JSON
	parametersJSON, _ := json.Marshal(req.Parameters)
	if parametersJSON == nil {
		parametersJSON = []byte("{}")
	}

	query := `
		INSERT INTO interrogation_schedules (
			id, tenant_id, name, description, cron_expression,
			target_type, target_id, is_enabled, next_run_at,
			success_count, failure_count, parameters, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING id, tenant_id, name, description, cron_expression,
			target_type, target_id, is_enabled, last_run_at, last_run_status,
			last_run_job_id, next_run_at, success_count, failure_count,
			parameters, created_at, updated_at, deleted_at
	`

	// RLS-scoped write on `interrogation_schedules`: tenantID is an input → WithTenantTx.
	var schedule *InterrogationSchedule
	err = shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, query,
			scheduleID, tenantID, req.Name, req.Description, req.CronExpression,
			req.TargetType, req.TargetID, isEnabled, nextRun,
			0, 0, parametersJSON, now, now,
		)
		var sErr error
		schedule, sErr = scanSchedule(row)
		return sErr
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create schedule: %w", err)
	}

	return schedule, nil
}

// GetSchedule retrieves a schedule by ID, scoped to tenantID (interrogation_schedules
// is RLS-scoped). tenantID is threaded from the caller (handlers hold it; the
// background sweep resolves it per row).
func (s *SchedulerService) GetSchedule(ctx context.Context, tenantID, scheduleID uuid.UUID) (*InterrogationSchedule, error) {
	query := `
		SELECT id, tenant_id, name, description, cron_expression,
			target_type, target_id, is_enabled, last_run_at, last_run_status,
			last_run_job_id, next_run_at, success_count, failure_count,
			parameters, created_at, updated_at, deleted_at
		FROM interrogation_schedules
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`

	var schedule *InterrogationSchedule
	found := false
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		sc, scanErr := scanSchedule(tx.QueryRowContext(ctx, query, scheduleID, tenantID))
		if scanErr == sql.ErrNoRows {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		schedule = sc
		found = true
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("schedule not found")
	}

	return schedule, nil
}

// ListSchedules lists all schedules for a tenant
func (s *SchedulerService) ListSchedules(ctx context.Context, tenantID uuid.UUID) ([]*InterrogationSchedule, error) {
	query := `
		SELECT id, tenant_id, name, description, cron_expression,
			target_type, target_id, is_enabled, last_run_at, last_run_status,
			last_run_job_id, next_run_at, success_count, failure_count,
			parameters, created_at, updated_at, deleted_at
		FROM interrogation_schedules
		WHERE tenant_id = $1 AND deleted_at IS NULL
		ORDER BY created_at DESC
	`

	// RLS-scoped read on `interrogation_schedules`: WithTenantTx sets app.tenant_id.
	var schedules []*InterrogationSchedule
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx, query, tenantID)
		if e != nil {
			return fmt.Errorf("failed to list schedules: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			schedule, scanErr := scanSchedule(rows)
			if scanErr != nil {
				return fmt.Errorf("failed to scan schedule: %w", scanErr)
			}
			schedules = append(schedules, schedule)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return schedules, nil
}

// UpdateSchedule updates a schedule, scoped to tenantID (interrogation_schedules
// is RLS-scoped).
func (s *SchedulerService) UpdateSchedule(ctx context.Context, tenantID, scheduleID uuid.UUID, req UpdateScheduleRequest) (*InterrogationSchedule, error) {
	// Build dynamic update query
	updates := []string{"updated_at = $1"}
	args := []interface{}{time.Now()}
	argIndex := 2

	if req.Name != nil {
		updates = append(updates, fmt.Sprintf("name = $%d", argIndex))
		args = append(args, *req.Name)
		argIndex++
	}
	if req.Description != nil {
		updates = append(updates, fmt.Sprintf("description = $%d", argIndex))
		args = append(args, *req.Description)
		argIndex++
	}
	if req.CronExpression != nil {
		// Validate cron expression
		_, err := s.cronParser.Parse(*req.CronExpression)
		if err != nil {
			return nil, fmt.Errorf("invalid cron expression: %w", err)
		}
		updates = append(updates, fmt.Sprintf("cron_expression = $%d", argIndex))
		args = append(args, *req.CronExpression)
		argIndex++

		// Update next run time
		nextRun := s.calculateNextRun(*req.CronExpression)
		updates = append(updates, fmt.Sprintf("next_run_at = $%d", argIndex))
		args = append(args, nextRun)
		argIndex++
	}
	if req.IsEnabled != nil {
		updates = append(updates, fmt.Sprintf("is_enabled = $%d", argIndex))
		args = append(args, *req.IsEnabled)
		argIndex++
	}
	if req.Parameters != nil {
		parametersJSON, _ := json.Marshal(req.Parameters)
		updates = append(updates, fmt.Sprintf("parameters = $%d", argIndex))
		args = append(args, parametersJSON)
		argIndex++
	}

	//nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
	query := fmt.Sprintf(`
		UPDATE interrogation_schedules
		SET %s
		WHERE id = $%d AND tenant_id = $%d AND deleted_at IS NULL
		RETURNING id, tenant_id, name, description, cron_expression,
			target_type, target_id, is_enabled, last_run_at, last_run_status,
			last_run_job_id, next_run_at, success_count, failure_count,
			parameters, created_at, updated_at, deleted_at
	`, strings.Join(updates, ", "), argIndex, argIndex+1)

	args = append(args, scheduleID, tenantID)

	var schedule *InterrogationSchedule
	found := false
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		sc, scanErr := scanSchedule(tx.QueryRowContext(ctx, query, args...))
		if scanErr == sql.ErrNoRows {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		schedule = sc
		found = true
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update schedule: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("schedule not found")
	}

	return schedule, nil
}

// DeleteSchedule soft deletes a schedule, scoped to tenantID.
func (s *SchedulerService) DeleteSchedule(ctx context.Context, tenantID, scheduleID uuid.UUID) error {
	query := `
		UPDATE interrogation_schedules
		SET deleted_at = $1, updated_at = $1
		WHERE id = $2 AND tenant_id = $3 AND deleted_at IS NULL
	`

	var rowsAffected int64
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		result, e := tx.ExecContext(ctx, query, time.Now(), scheduleID, tenantID)
		if e != nil {
			return e
		}
		rowsAffected, e = result.RowsAffected()
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to delete schedule: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("schedule not found")
	}

	return nil
}

// TriggerSchedule manually triggers a schedule, scoped to tenantID.
func (s *SchedulerService) TriggerSchedule(ctx context.Context, tenantID, scheduleID uuid.UUID) (*models.DeviceJob, error) {
	schedule, err := s.GetSchedule(ctx, tenantID, scheduleID)
	if err != nil {
		return nil, err
	}

	// Create a job based on the schedule target type.
	//
	// Neither the target address nor the credentials are set here, and that is
	// deliberate: a schedule stores an operator-supplied parameter map and no
	// credentials at all, so both are resolved from the device row at dispatch
	// in AgentService.GetNextJob (enrichJobTarget / resolveJobCredentials) —
	// the single choke point every creation path passes through, and the last
	// place that can still see the device. Filling them in here as well would
	// only freeze a snapshot taken when the schedule fired.
	var jobRequest models.CreateDeviceJobRequest
	jobRequest.TenantID = schedule.TenantID
	jobRequest.Parameters = schedule.Parameters

	switch schedule.TargetType {
	case "device":
		jobRequest.JobType = models.JobTypeDeviceInterrogation
		jobRequest.DeviceID = &schedule.TargetID
	case "cloud_integration":
		jobRequest.JobType = models.JobTypeCloudDiscovery
		jobRequest.IntegrationID = &schedule.TargetID
	default:
		return nil, fmt.Errorf("unknown target type: %s", schedule.TargetType)
	}

	// Create the job
	job, err := s.jobQueue.CreateJob(ctx, jobRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to create job: %w", err)
	}

	// Update schedule with last run info
	now := time.Now()
	nextRun := s.calculateNextRun(schedule.CronExpression)

	updateQuery := `
		UPDATE interrogation_schedules
		SET last_run_at = $1, last_run_job_id = $2, last_run_status = $3,
			next_run_at = $4, updated_at = $1
		WHERE id = $5 AND tenant_id = $6
	`
	err = shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		if _, e := tx.ExecContext(ctx, updateQuery, now, job.ID, scheduleRunPending, nextRun, scheduleID, tenantID); e != nil {
			return e
		}
		// Open the run's history row now, while it is still 'pending'. The
		// outcome is stamped onto this same row by recordScheduleOutcome when
		// the job reaches a terminal status — keyed by job id, so a run appears
		// in the history exactly once whether or not it ever finishes. A run
		// that is dropped on the floor stays visibly 'pending' instead of
		// vanishing, which is the honest record of what happened.
		_, e := tx.ExecContext(ctx, `
			INSERT INTO schedule_history (schedule_id, job_id, status, started_at)
			VALUES ($1, $2, $3, $4)`,
			scheduleID, job.ID, scheduleRunPending, now)
		return e
	})
	if err != nil {
		// Log but don't fail - the job was created
		fmt.Printf("Warning: failed to update schedule last run: %v\n", err)
	}

	return job, nil
}

// GetScheduleHistory retrieves execution history for a schedule, scoped to
// tenantID (schedule_history RLS isolates via its parent interrogation_schedules).
func (s *SchedulerService) GetScheduleHistory(ctx context.Context, tenantID, scheduleID uuid.UUID, limit int) ([]*ScheduleHistory, error) {
	if limit <= 0 {
		limit = 50
	}

	query := `
		SELECT sh.id, sh.schedule_id, sh.job_id, sh.status, sh.started_at,
			sh.completed_at, sh.error_message, sh.assets_found
		FROM schedule_history sh
		WHERE sh.schedule_id = $1
		ORDER BY sh.started_at DESC
		LIMIT $2
	`

	var history []*ScheduleHistory
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx, query, scheduleID, limit)
		if e != nil {
			return fmt.Errorf("failed to get schedule history: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			record := &ScheduleHistory{}
			if scanErr := rows.Scan(
				&record.ID, &record.ScheduleID, &record.JobID, &record.Status,
				&record.StartedAt, &record.CompletedAt, &record.ErrorMessage,
				&record.AssetsFound,
			); scanErr != nil {
				return fmt.Errorf("failed to scan history record: %w", scanErr)
			}
			history = append(history, record)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return history, nil
}

// Schedule run-outcome vocabulary. These are the values written to
// interrogation_schedules.last_run_status and schedule_history.status, and they
// are the values the Scheduled Scans page reads — it colours a run red on
// exactly "failed". The Go side previously documented "failure", which nothing
// wrote and the UI would not have recognised if it had.
const (
	scheduleRunPending = "pending"
	scheduleRunSuccess = "success"
	scheduleRunFailed  = "failed"
)

// recordScheduleOutcome attributes a finished device job back to the
// interrogation schedule that dispatched it: it writes/updates the job's
// schedule_history row and refreshes the schedule's last_run_status and
// success/failure counters.
//
// Before this existed, TriggerSchedule wrote last_run_status='pending' and
// nothing ever moved it, success_count/failure_count were inserted as 0 and
// never incremented, and schedule_history had a reader (GET
// /schedules/:id/history) with no producer at all. A nightly interrogation that
// had failed for a month looked identical to one succeeding.
//
// Idempotent on purpose, because a terminal status can legitimately be written
// twice for one job (the platform worker marks a job completed, then
// ProcessJobResults can mark it failed on a broken platform-sensor invariant):
//   - the history row is keyed by job id — updated in place, never appended to
//   - the counters are RECOMPUTED from schedule_history rather than incremented,
//     so no sequence of repeated or reordered calls can drift them
//
// A stale completion can arrive after the schedule has fired again. Resolve the
// schedule through schedule_history, so that old run still updates its own
// history row and counters; only the current job may rewrite last_run_status.
//
// RLS: keyed by job id with no tenant input (the owning tenant is the OUTPUT),
// called from JobQueueService.UpdateJobStatus → bypass role, same as its caller.
func recordScheduleOutcome(
	ctx context.Context,
	db *sql.DB,
	jobID uuid.UUID,
	status models.DeviceJobStatus,
	errorMessage *string,
	result *models.JobResult,
) error {
	var outcome string
	switch status {
	case models.JobStatusCompleted:
		outcome = scheduleRunSuccess
	case models.JobStatusFailed:
		outcome = scheduleRunFailed
	default:
		return nil // Not a terminal status — nothing to attribute yet.
	}

	// Which schedule dispatched this job? Most jobs are ad-hoc and match nothing.
	var scheduleID uuid.UUID
	var startedAt time.Time
	err := db.QueryRowContext(ctx, `
		SELECT h.schedule_id, h.started_at
		FROM schedule_history h
		JOIN interrogation_schedules s ON s.id = h.schedule_id
		WHERE h.job_id = $1 AND s.deleted_at IS NULL
		UNION ALL
		SELECT s.id, COALESCE(s.last_run_at, NOW())
		FROM interrogation_schedules s
		WHERE s.last_run_job_id = $1
		  AND s.deleted_at IS NULL
		  AND NOT EXISTS (SELECT 1 FROM schedule_history h WHERE h.job_id = $1)
		LIMIT 1`, jobID).Scan(&scheduleID, &startedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to resolve schedule for job %s: %w", jobID, err)
	}

	assetsFound := jobResultAssetCount(result)

	res, err := db.ExecContext(ctx, `
		UPDATE schedule_history
		SET status = $1, completed_at = NOW(), error_message = $2, assets_found = $3
		WHERE schedule_id = $4 AND job_id = $5`,
		outcome, errorMessage, assetsFound, scheduleID, jobID)
	if err != nil {
		return fmt.Errorf("failed to update schedule history for job %s: %w", jobID, err)
	}
	updated, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to inspect schedule history update for job %s: %w", jobID, err)
	}
	if updated == 0 {
		if _, err := db.ExecContext(ctx, `
			INSERT INTO schedule_history (
				schedule_id, job_id, status, started_at, completed_at, error_message, assets_found
			) VALUES ($1, $2, $3, $4, NOW(), $5, $6)`,
			scheduleID, jobID, outcome, startedAt, errorMessage, assetsFound,
		); err != nil {
			return fmt.Errorf("failed to insert schedule history for job %s: %w", jobID, err)
		}
	}

	if _, err := db.ExecContext(ctx, `
		UPDATE interrogation_schedules s
		SET last_run_status = CASE WHEN s.last_run_job_id = $5 THEN $1 ELSE s.last_run_status END,
		    success_count = (SELECT count(*) FROM schedule_history h
		                      WHERE h.schedule_id = s.id AND h.status = $2),
		    failure_count = (SELECT count(*) FROM schedule_history h
		                      WHERE h.schedule_id = s.id AND h.status = $3),
		    updated_at = NOW()
		WHERE s.id = $4`,
		outcome, scheduleRunSuccess, scheduleRunFailed, scheduleID, jobID,
	); err != nil {
		return fmt.Errorf("failed to update schedule %s from job %s: %w", scheduleID, jobID, err)
	}

	return nil
}

// dueScheduleBatch bounds how many schedules one sweep claims, so a backlog
// cannot turn a single pass into an unbounded burst of jobs.
const dueScheduleBatch = 100

// ProcessDueSchedules finds and triggers all schedules that are due to run.
// The SchedulerWorker calls this on an interval; nothing else should.
//
// Claiming and triggering are two phases on purpose. Phase 1 opens ONE
// transaction, selects due rows FOR UPDATE SKIP LOCKED and advances their
// next_run_at inside it, which is what makes the claim exclusive: the original
// version issued the same SELECT ... FOR UPDATE SKIP LOCKED through
// QueryContext, i.e. in its own implicit transaction that committed the instant
// the statement finished, so the row locks were released before any caller
// looked at them and every replica would have claimed and triggered the same
// schedule. Phase 2 triggers outside the transaction so a slow job creation
// never holds row locks.
func (s *SchedulerService) ProcessDueSchedules(ctx context.Context) (int, error) {
	type dueSchedule struct {
		scheduleID, tenantID uuid.UUID
		name                 string
	}

	// RLS: cross-tenant background sweep (no single tenant) → bypass role. Each
	// matched row carries its tenant_id; TriggerSchedule then runs under that
	// resolved tenant via WithTenantTx.
	tx, err := s.bypassDB.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin due-schedule claim: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		SELECT id, tenant_id, name, cron_expression
		FROM interrogation_schedules
		WHERE is_enabled = true
			AND next_run_at IS NOT NULL
			AND next_run_at <= $1
			AND deleted_at IS NULL
		ORDER BY next_run_at ASC
		LIMIT $2
		FOR UPDATE SKIP LOCKED
	`, time.Now(), dueScheduleBatch)
	if err != nil {
		return 0, fmt.Errorf("failed to query due schedules: %w", err)
	}

	var due []dueSchedule
	var nextRuns []*time.Time
	for rows.Next() {
		var scheduleID, tenantID uuid.UUID
		var name, cronExpr string
		if scanErr := rows.Scan(&scheduleID, &tenantID, &name, &cronExpr); scanErr != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("failed to scan due schedule: %w", scanErr)
		}
		due = append(due, dueSchedule{scheduleID: scheduleID, tenantID: tenantID, name: name})
		nextRuns = append(nextRuns, s.calculateNextRun(cronExpr))
	}
	if rErr := rows.Err(); rErr != nil {
		_ = rows.Close()
		return 0, fmt.Errorf("failed to iterate due schedules: %w", rErr)
	}
	_ = rows.Close()

	// Advance next_run_at while the rows are still locked. A schedule whose cron
	// expression no longer parses gets next_run_at cleared rather than left in
	// the past, so it stops being re-claimed every sweep instead of hot-looping.
	for i, d := range due {
		if _, uErr := tx.ExecContext(ctx,
			`UPDATE interrogation_schedules SET next_run_at = $1, updated_at = NOW() WHERE id = $2`,
			nextRuns[i], d.scheduleID,
		); uErr != nil {
			return 0, fmt.Errorf("failed to claim schedule %s: %w", d.scheduleID, uErr)
		}
	}
	if cErr := tx.Commit(); cErr != nil {
		return 0, fmt.Errorf("failed to commit due-schedule claim: %w", cErr)
	}

	var triggered int
	for _, d := range due {
		// Trigger the schedule under its own tenant scope.
		if _, tErr := s.TriggerSchedule(ctx, d.tenantID, d.scheduleID); tErr != nil {
			log.Printf("[SchedulerService] Failed to trigger schedule %s (%s): %v", d.name, d.scheduleID, tErr)
			continue
		}
		triggered++
	}

	return triggered, nil
}

// calculateNextRun calculates the next run time from a cron expression
func (s *SchedulerService) calculateNextRun(cronExpr string) *time.Time {
	schedule, err := s.cronParser.Parse(cronExpr)
	if err != nil {
		return nil
	}

	nextRun := schedule.Next(time.Now())
	return &nextRun
}

// ParseCronExpression parses a cron expression and returns human-readable info
func (s *SchedulerService) ParseCronExpression(cronExpr string) (description string, nextRun *time.Time, err error) {
	_, err = s.cronParser.Parse(cronExpr)
	if err != nil {
		return "", nil, fmt.Errorf("invalid cron expression: %w", err)
	}

	nextRun = s.calculateNextRun(cronExpr)

	// Generate a human-readable description
	description = s.describeCron(cronExpr)

	return description, nextRun, nil
}

// describeCron generates a human-readable description of a cron expression
func (s *SchedulerService) describeCron(cronExpr string) string {
	parts := strings.Fields(cronExpr)
	if len(parts) != 5 {
		return "Custom schedule"
	}

	minute, hour, dom, month, dow := parts[0], parts[1], parts[2], parts[3], parts[4]

	// Common patterns
	if minute == "0" && hour == "*" && dom == "*" && month == "*" && dow == "*" {
		return "Every hour at minute 0"
	}
	if minute == "0" && hour == "0" && dom == "*" && month == "*" && dow == "*" {
		return "Daily at midnight"
	}
	if minute == "0" && hour == "0" && dom == "*" && month == "*" && dow == "0" {
		return "Weekly on Sunday at midnight"
	}
	if minute == "0" && hour == "0" && dom == "1" && month == "*" && dow == "*" {
		return "Monthly on the 1st at midnight"
	}

	return fmt.Sprintf("At %s:%s", hour, minute)
}
