package handlers

import (
	"context"
	"database/sql"
	"strconv"

	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// jobStore is the persistence surface the job handlers depend on. Declaring it
// as an interface (the concrete jobRepository satisfies it) is what makes the
// handlers exercisable from the contract test with an in-memory stub — no
// database — per the spec-first contract recipe (ADR-0001). The inline SQL the
// handlers used to run was relocated verbatim into jobRepository below; no
// query or behavior changed.
type jobStore interface {
	ListJobs(ctx context.Context, tenantID uuid.UUID, f JobListFilters) ([]InterrogationJob, int, error)
	// ListAdminJobs lists interrogation jobs across ALL tenants for the
	// platform-admin Jobs & Queues view. It deliberately omits the tenant_id
	// filter (RLS is inert; the WHERE tenant_id elsewhere is the only isolation,
	// dropped here on purpose) and joins tenants for per-row identity. Callers
	// MUST gate this behind RequirePlatformAdmin.
	ListAdminJobs(ctx context.Context, f JobListFilters) ([]AdminInterrogationJob, int, error)
	GetJob(ctx context.Context, tenantID, jobID uuid.UUID) (*InterrogationJob, error)
	GetJobStats(ctx context.Context, tenantID uuid.UUID) (JobStats, error)
	GetActiveJobs(ctx context.Context, tenantID uuid.UUID) ([]InterrogationJob, error)
	// GetJobResultStatus reports a job's status and raw results JSON for the
	// results endpoint; found=false when no such job exists for the tenant.
	// resultsJSON is "" when the job has not produced results yet.
	GetJobResultStatus(ctx context.Context, tenantID, jobID uuid.UUID) (status, resultsJSON string, found bool, err error)
	// GetJobStatus is used by retry/cancel to gate on the current state.
	GetJobStatus(ctx context.Context, tenantID, jobID uuid.UUID) (status string, found bool, err error)
	// GetJobStatusAdmin reads a job's status + owning tenant by id with NO tenant
	// scope — for the platform-admin (Support cockpit) retry/cancel. Callers MUST
	// gate behind RequirePlatformAdmin.
	GetJobStatusAdmin(ctx context.Context, jobID uuid.UUID) (status string, tenantID uuid.UUID, found bool, err error)
	// ResetJobToPending / CancelJobByID mutate one job by id; tenantID is threaded
	// from the caller (the tenant retry/cancel holds it from context; the admin
	// path resolves it from GetJobStatusAdmin) so the write is RLS-scoped.
	ResetJobToPending(ctx context.Context, tenantID, jobID uuid.UUID) error
	CancelJobByID(ctx context.Context, tenantID, jobID uuid.UUID) error
}

// JobListFilters carries the parsed query parameters for ListJobs.
type JobListFilters struct {
	Page          int
	PageSize      int
	Status        []string
	JobType       string
	DeviceID      string
	IntegrationID string
	// TenantID optionally narrows the cross-tenant admin roll-up to one tenant
	// (operator scope). Empty = all tenants. Ignored by the tenant-scoped ListJobs
	// (that path already filters by the context tenant).
	TenantID string
}

// jobRepository is the SQL-backed jobStore. The queries here are moved verbatim
// from the former inline handler SQL.
type jobRepository struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) connection used by the
	// cross-tenant admin paths (ListAdminJobs, GetJobStatusAdmin). Pre-flip it
	// resolves to the same connection as db.
	bypassDB *sql.DB
}

func newJobRepository(db, bypassDB *sql.DB) *jobRepository {
	return &jobRepository{db: db, bypassDB: bypassDB}
}

const jobSelectColumns = `
	SELECT dj.id, dj.tenant_id, dj.job_type, dj.status,
		   dj.device_id, d.hostname as device_name, d.device_type,
		   dj.integration_id, pi.integration_name, pi.integration_type as cloud_provider,
		   dj.started_at, dj.completed_at, dj.error_message,
		   dj.results, dj.created_at, dj.deleted_at as updated_at,
		   dj.agent_id, da.name as agent_name
	FROM device_jobs dj
	LEFT JOIN devices d ON dj.device_id = d.id
	LEFT JOIN platform_integrations pi ON dj.integration_id = pi.id
	LEFT JOIN device_agents da ON dj.agent_id = da.id
	WHERE dj.tenant_id = $1 AND dj.deleted_at IS NULL
`

func (r *jobRepository) ListJobs(ctx context.Context, tenantID uuid.UUID, f JobListFilters) ([]InterrogationJob, int, error) {
	offset := (f.Page - 1) * f.PageSize

	query := jobSelectColumns
	countQuery := `SELECT COUNT(*) FROM device_jobs WHERE tenant_id = $1 AND deleted_at IS NULL`
	args := []interface{}{tenantID}
	argNum := 2

	if len(f.Status) > 0 {
		query += " AND dj.status = ANY($" + strconv.Itoa(argNum) + ")"
		countQuery += " AND status = ANY($" + strconv.Itoa(argNum) + ")"
		args = append(args, f.Status)
		argNum++
	}
	if f.JobType != "" {
		query += " AND dj.job_type = $" + strconv.Itoa(argNum)
		countQuery += " AND job_type = $" + strconv.Itoa(argNum)
		args = append(args, f.JobType)
		argNum++
	}
	if f.DeviceID != "" {
		query += " AND dj.device_id = $" + strconv.Itoa(argNum)
		countQuery += " AND device_id = $" + strconv.Itoa(argNum)
		args = append(args, f.DeviceID)
		argNum++
	}
	if f.IntegrationID != "" {
		query += " AND dj.integration_id = $" + strconv.Itoa(argNum)
		countQuery += " AND integration_id = $" + strconv.Itoa(argNum)
		args = append(args, f.IntegrationID)
		argNum++
	}

	query += " ORDER BY dj.created_at DESC LIMIT $" + strconv.Itoa(argNum) + " OFFSET $" + strconv.Itoa(argNum+1) //nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
	args = append(args, f.PageSize, offset)

	var total int
	countArgs := args[:len(args)-2] // Remove limit/offset for count
	jobs := make([]InterrogationJob, 0)
	// RLS-scoped read on `device_jobs`: WithTenantTx sets app.tenant_id; the
	// explicit WHERE dj.tenant_id = $1 is kept as the primary control.
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		if e := tx.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); e != nil {
			return e
		}
		rows, e := tx.QueryContext(ctx, query, args...)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var job InterrogationJob
			var updatedAt sql.NullTime
			var resultsRaw []byte
			var agentName *string

			if scanErr := rows.Scan(
				&job.ID, &job.TenantID, &job.JobType, &job.Status,
				&job.DeviceID, &job.DeviceName, &job.DeviceType,
				&job.IntegrationID, &job.IntegrationName, &job.CloudProvider,
				&job.StartedAt, &job.CompletedAt, &job.ErrorMessage,
				&resultsRaw, &job.CreatedAt, &updatedAt,
				&job.AgentID, &agentName,
			); scanErr != nil {
				continue
			}

			if updatedAt.Valid {
				job.UpdatedAt = updatedAt.Time
			} else {
				job.UpdatedAt = job.CreatedAt
			}
			if job.StartedAt != nil && job.CompletedAt != nil {
				duration := int(job.CompletedAt.Sub(*job.StartedAt).Seconds())
				job.DurationSeconds = &duration
			}
			if len(resultsRaw) > 0 {
				job.AssetsDiscovered = assetsDiscoveredFromResults(string(resultsRaw))
			}
			job.Executor = executorLabel(job.AgentID, agentName)
			jobs = append(jobs, job)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}
	return jobs, total, nil
}

// ListAdminJobs runs the ListJobs query WITHOUT the tenant_id filter, adding a
// tenants LEFT JOIN for per-row name/slug and selecting the assigned worker
// (dj.agent_id). Same filter/pagination semantics as ListJobs minus tenant scope.
func (r *jobRepository) ListAdminJobs(ctx context.Context, f JobListFilters) ([]AdminInterrogationJob, int, error) {
	offset := (f.Page - 1) * f.PageSize

	query := `
		SELECT dj.id, dj.tenant_id, t.name AS tenant_name, t.slug AS tenant_slug,
			   dj.job_type, dj.status,
			   dj.device_id, d.hostname as device_name, d.device_type,
			   dj.integration_id, pi.integration_name, pi.integration_type as cloud_provider,
			   dj.agent_id AS worker,
			   dj.started_at, dj.completed_at, dj.error_message,
			   dj.results, dj.created_at, dj.updated_at
		FROM device_jobs dj
		LEFT JOIN tenants t ON t.id = dj.tenant_id
		LEFT JOIN devices d ON dj.device_id = d.id
		LEFT JOIN platform_integrations pi ON dj.integration_id = pi.id
		WHERE dj.deleted_at IS NULL
	`
	countQuery := `SELECT COUNT(*) FROM device_jobs WHERE deleted_at IS NULL`
	args := []interface{}{}
	argNum := 1

	if len(f.Status) > 0 {
		query += " AND dj.status = ANY($" + strconv.Itoa(argNum) + ")"
		countQuery += " AND status = ANY($" + strconv.Itoa(argNum) + ")"
		args = append(args, f.Status)
		argNum++
	}
	if f.JobType != "" {
		query += " AND dj.job_type = $" + strconv.Itoa(argNum)
		countQuery += " AND job_type = $" + strconv.Itoa(argNum)
		args = append(args, f.JobType)
		argNum++
	}
	if f.DeviceID != "" {
		query += " AND dj.device_id = $" + strconv.Itoa(argNum)
		countQuery += " AND device_id = $" + strconv.Itoa(argNum)
		args = append(args, f.DeviceID)
		argNum++
	}
	if f.IntegrationID != "" {
		query += " AND dj.integration_id = $" + strconv.Itoa(argNum)
		countQuery += " AND integration_id = $" + strconv.Itoa(argNum)
		args = append(args, f.IntegrationID)
		argNum++
	}
	if f.TenantID != "" {
		query += " AND dj.tenant_id = $" + strconv.Itoa(argNum)
		countQuery += " AND tenant_id = $" + strconv.Itoa(argNum)
		args = append(args, f.TenantID)
		argNum++
	}

	query += " ORDER BY dj.created_at DESC LIMIT $" + strconv.Itoa(argNum) + " OFFSET $" + strconv.Itoa(argNum+1) //nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
	args = append(args, f.PageSize, offset)

	var total int
	countArgs := args[:len(args)-2] // Remove limit/offset for count
	// RLS: cross-tenant admin roll-up (tenant filter intentionally dropped or
	// operator-narrowed) → bypass role. Gated by RequirePlatformAdmin.
	if err := r.bypassDB.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := r.bypassDB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	jobs := make([]AdminInterrogationJob, 0)
	for rows.Next() {
		var job AdminInterrogationJob
		var tenantName, tenantSlug sql.NullString
		var updatedAt sql.NullTime
		var resultsRaw []byte

		if err := rows.Scan(
			&job.ID, &job.TenantID, &tenantName, &tenantSlug,
			&job.JobType, &job.Status,
			&job.DeviceID, &job.DeviceName, &job.DeviceType,
			&job.IntegrationID, &job.IntegrationName, &job.CloudProvider,
			&job.Worker,
			&job.StartedAt, &job.CompletedAt, &job.ErrorMessage,
			&resultsRaw, &job.CreatedAt, &updatedAt,
		); err != nil {
			continue
		}

		job.TenantName = tenantName.String
		job.TenantSlug = tenantSlug.String
		if updatedAt.Valid {
			job.UpdatedAt = updatedAt.Time
		} else {
			job.UpdatedAt = job.CreatedAt
		}
		if job.StartedAt != nil && job.CompletedAt != nil {
			duration := int(job.CompletedAt.Sub(*job.StartedAt).Seconds())
			job.DurationSeconds = &duration
		}
		if len(resultsRaw) > 0 {
			job.AssetsDiscovered = assetsDiscoveredFromResults(string(resultsRaw))
		}
		jobs = append(jobs, job)
	}
	return jobs, total, nil
}

func (r *jobRepository) GetJob(ctx context.Context, tenantID, jobID uuid.UUID) (*InterrogationJob, error) {
	query := `
		SELECT dj.id, dj.tenant_id, dj.job_type, dj.status,
			   dj.device_id, d.hostname as device_name, d.device_type,
			   dj.integration_id, pi.integration_name, pi.integration_type as cloud_provider,
			   dj.started_at, dj.completed_at, dj.error_message,
			   dj.results, dj.created_at,
			   dj.agent_id, da.name as agent_name
		FROM device_jobs dj
		LEFT JOIN devices d ON dj.device_id = d.id
		LEFT JOIN platform_integrations pi ON dj.integration_id = pi.id
		LEFT JOIN device_agents da ON dj.agent_id = da.id
		WHERE dj.id = $1 AND dj.tenant_id = $2 AND dj.deleted_at IS NULL
	`

	var job InterrogationJob
	var resultsRaw []byte
	var agentName *string
	found := false
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		scanErr := tx.QueryRowContext(ctx, query, jobID, tenantID).Scan(
			&job.ID, &job.TenantID, &job.JobType, &job.Status,
			&job.DeviceID, &job.DeviceName, &job.DeviceType,
			&job.IntegrationID, &job.IntegrationName, &job.CloudProvider,
			&job.StartedAt, &job.CompletedAt, &job.ErrorMessage,
			&resultsRaw, &job.CreatedAt,
			&job.AgentID, &agentName,
		)
		if scanErr == sql.ErrNoRows {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		found = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}

	job.UpdatedAt = job.CreatedAt
	if len(resultsRaw) > 0 {
		job.AssetsDiscovered = assetsDiscoveredFromResults(string(resultsRaw))
	}
	job.Executor = executorLabel(job.AgentID, agentName)
	return &job, nil
}

func (r *jobRepository) GetJobStats(ctx context.Context, tenantID uuid.UUID) (JobStats, error) {
	stats := JobStats{}
	query := `
		SELECT
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE status = 'pending') as pending,
			COUNT(*) FILTER (WHERE status = 'in_progress') as in_progress,
			COUNT(*) FILTER (WHERE status = 'completed') as completed,
			COUNT(*) FILTER (WHERE status = 'failed') as failed,
			COUNT(*) FILTER (WHERE status = 'completed' AND completed_at > NOW() - INTERVAL '24 hours') as completed_24h,
			COUNT(*) FILTER (WHERE status = 'failed' AND completed_at > NOW() - INTERVAL '24 hours') as failed_24h,
			AVG(EXTRACT(EPOCH FROM (completed_at - started_at))) FILTER (WHERE status = 'completed' AND started_at IS NOT NULL AND completed_at IS NOT NULL) as avg_duration
		FROM device_jobs
		WHERE tenant_id = $1 AND deleted_at IS NULL
	`

	var avgDuration sql.NullFloat64
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, tenantID).Scan(
			&stats.Total, &stats.Pending, &stats.InProgress, &stats.Completed, &stats.Failed,
			&stats.Last24h.Completed, &stats.Last24h.Failed, &avgDuration,
		)
	})
	if err != nil {
		return JobStats{}, err
	}
	if avgDuration.Valid {
		stats.AverageDurationSeconds = &avgDuration.Float64
	}
	return stats, nil
}

func (r *jobRepository) GetActiveJobs(ctx context.Context, tenantID uuid.UUID) ([]InterrogationJob, error) {
	query := `
		SELECT dj.id, dj.tenant_id, dj.job_type, dj.status,
			   dj.device_id, d.hostname as device_name, d.device_type,
			   dj.integration_id, pi.integration_name, pi.integration_type as cloud_provider,
			   dj.started_at, dj.created_at
		FROM device_jobs dj
		LEFT JOIN devices d ON dj.device_id = d.id
		LEFT JOIN platform_integrations pi ON dj.integration_id = pi.id
		WHERE dj.tenant_id = $1
		  AND dj.status IN ('pending', 'assigned', 'in_progress')
		  AND dj.deleted_at IS NULL
		ORDER BY dj.created_at DESC
		LIMIT 50
	`

	jobs := make([]InterrogationJob, 0)
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx, query, tenantID)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var job InterrogationJob
			if scanErr := rows.Scan(
				&job.ID, &job.TenantID, &job.JobType, &job.Status,
				&job.DeviceID, &job.DeviceName, &job.DeviceType,
				&job.IntegrationID, &job.IntegrationName, &job.CloudProvider,
				&job.StartedAt, &job.CreatedAt,
			); scanErr != nil {
				continue
			}
			job.UpdatedAt = job.CreatedAt
			jobs = append(jobs, job)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return jobs, nil
}

func (r *jobRepository) GetJobResultStatus(ctx context.Context, tenantID, jobID uuid.UUID) (string, string, bool, error) {
	query := `
		SELECT dj.status, COALESCE(dj.results::text, '')
		FROM device_jobs dj
		WHERE dj.id = $1 AND dj.tenant_id = $2 AND dj.deleted_at IS NULL
	`
	var status, results string
	found := false
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		scanErr := tx.QueryRowContext(ctx, query, jobID, tenantID).Scan(&status, &results)
		if scanErr == sql.ErrNoRows {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		found = true
		return nil
	})
	if err != nil {
		return "", "", false, err
	}
	return status, results, found, nil
}

func (r *jobRepository) GetJobStatus(ctx context.Context, tenantID, jobID uuid.UUID) (string, bool, error) {
	var status string
	found := false
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		scanErr := tx.QueryRowContext(ctx,
			"SELECT status FROM device_jobs WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL",
			jobID, tenantID,
		).Scan(&status)
		if scanErr == sql.ErrNoRows {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		found = true
		return nil
	})
	if err != nil {
		return "", false, err
	}
	return status, found, nil
}

// GetJobStatusAdmin reads a job's status + owning tenant by id with NO tenant
// scope (the cross-tenant Support cockpit). RLS: tenant is the OUTPUT → bypass
// role. Gated by RequirePlatformAdmin.
func (r *jobRepository) GetJobStatusAdmin(ctx context.Context, jobID uuid.UUID) (string, uuid.UUID, bool, error) {
	var status string
	var tenantID uuid.UUID
	err := r.bypassDB.QueryRowContext(ctx,
		"SELECT status, tenant_id FROM device_jobs WHERE id = $1 AND deleted_at IS NULL",
		jobID,
	).Scan(&status, &tenantID)
	if err == sql.ErrNoRows {
		return "", uuid.Nil, false, nil
	}
	if err != nil {
		return "", uuid.Nil, false, err
	}
	return status, tenantID, true, nil
}

func (r *jobRepository) ResetJobToPending(ctx context.Context, tenantID, jobID uuid.UUID) error {
	return shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			"UPDATE device_jobs SET status = 'pending', error_message = NULL, started_at = NULL, completed_at = NULL WHERE id = $1 AND tenant_id = $2",
			jobID, tenantID,
		)
		return err
	})
}

func (r *jobRepository) CancelJobByID(ctx context.Context, tenantID, jobID uuid.UUID) error {
	return shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			"UPDATE device_jobs SET status = 'cancelled', completed_at = NOW() WHERE id = $1 AND tenant_id = $2",
			jobID, tenantID,
		)
		return err
	})
}
