package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// JobQueueService handles device job queue operations
type JobQueueService struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) connection used by the
	// agent-outbound and background-worker paths that are keyed by agent/job id
	// (the owning tenant is the OUTPUT, not an input) and the cross-tenant
	// platform job sweep. Pre-flip it resolves to the same connection as db.
	bypassDB   *sql.DB
	redis      *redis.Client
	natsClient *events.NATSClient
}

// NewJobQueueService creates a new job queue service. db is the RLS-scoped
// (crypto_app) connection; bypassDB is the BYPASSRLS (crypto_bypass) connection
// for the keyed-by-id / cross-tenant paths. Pre-flip both handles resolve to the
// same connection.
func NewJobQueueService(db, bypassDB *sql.DB, redis *redis.Client) *JobQueueService {
	return &JobQueueService{
		db:       db,
		bypassDB: bypassDB,
		redis:    redis,
	}
}

// SetNATSClient sets the NATS client for event publishing.
func (s *JobQueueService) SetNATSClient(client *events.NATSClient) {
	s.natsClient = client
}

// CreateJob creates a new device interrogation or cloud discovery job
func (s *JobQueueService) CreateJob(ctx context.Context, req models.CreateDeviceJobRequest) (*models.DeviceJob, error) {
	jobID := uuid.New()
	now := time.Now()

	// Set default expiration (1 hour for pending jobs)
	expiresAt := req.ExpiresAt
	if expiresAt == nil {
		exp := now.Add(1 * time.Hour)
		expiresAt = &exp
	}

	// Convert credentials and parameters to JSONB
	// Use empty JSON object {} if nil, to avoid "invalid input syntax for type json" errors
	var credentialsJSON []byte
	if req.Credentials != nil {
		var err error
		credentialsJSON, err = json.Marshal(req.Credentials)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal credentials: %w", err)
		}
	} else {
		credentialsJSON = []byte("{}")
	}

	// Default to empty object if parameters is nil
	parametersJSON := []byte("{}")
	if req.Parameters != nil {
		var err error
		parametersJSON, err = json.Marshal(req.Parameters)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal parameters: %w", err)
		}
	}

	query := `
		INSERT INTO device_jobs (
			id, tenant_id, job_type, device_id, integration_id, agent_id, status,
			credentials, parameters, created_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, tenant_id, job_type, device_id, agent_id, status,
			credentials, parameters, results, error_message,
			created_at, assigned_at, started_at, completed_at, expires_at, deleted_at
	`

	job := &models.DeviceJob{}
	var credentialsJSONB, parametersJSONB, resultsJSONB []byte
	var deviceID, agentID sql.NullString

	// RLS-scoped write on `device_jobs`: req.TenantID is an input, so set
	// app.tenant_id to it for the INSERT (satisfies WITH CHECK).
	err := shareddatabase.WithTenantTx(ctx, s.db, req.TenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query,
			jobID, req.TenantID, string(req.JobType), req.DeviceID, req.IntegrationID, req.AgentID,
			string(models.JobStatusPending), credentialsJSON, parametersJSON, now, expiresAt,
		).Scan(
			&job.ID, &job.TenantID, &job.JobType, &deviceID, &agentID, &job.Status,
			&credentialsJSONB, &parametersJSONB, &resultsJSONB, &job.ErrorMessage,
			&job.CreatedAt, &job.AssignedAt, &job.StartedAt, &job.CompletedAt, &job.ExpiresAt, &job.DeletedAt,
		)
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create job: %w", err)
	}

	// Parse JSONB fields
	if deviceID.Valid {
		id, _ := uuid.Parse(deviceID.String)
		job.DeviceID = &id
	}
	if agentID.Valid {
		id, _ := uuid.Parse(agentID.String)
		job.AgentID = &id
	}
	if len(credentialsJSONB) > 0 {
		_ = json.Unmarshal(credentialsJSONB, &job.Credentials)
	}
	if len(parametersJSONB) > 0 {
		_ = json.Unmarshal(parametersJSONB, &job.Parameters)
	}
	if len(resultsJSONB) > 0 {
		_ = json.Unmarshal(resultsJSONB, &job.Results)
	}

	// Publish job event to NATS for immediate processing by subscribers
	if s.natsClient != nil && s.natsClient.IsConnected() {
		jobEvent := events.DeviceJobEvent{
			EventID:   uuid.New(),
			TenantID:  req.TenantID,
			JobID:     jobID.String(),
			JobType:   string(req.JobType),
			Timestamp: now,
		}
		if err := events.PublishJSON(s.natsClient, events.SubjectDeviceJobsSubmit, jobEvent); err != nil {
			log.Printf("[JobQueueService] Failed to publish device job to NATS (will rely on DB polling): %v", err)
		} else {
			log.Printf("[JobQueueService] Published device job %s to NATS", jobID)
		}
	}

	return job, nil
}

// resolveAgentTenant returns the owning tenant of a registered device agent.
// It runs on the bypass role (the tenant is the OUTPUT of an agent-id lookup,
// mirroring AgentAuth). Callers use it to scope agent-outbound job access to the
// agent's own tenant, so a compromised or spoofed agent id cannot reach another
// tenant's jobs even when agent mTLS is not enforced. Returns ErrAgentNotFound
// when the id is unknown or soft-deleted.
func (s *JobQueueService) resolveAgentTenant(ctx context.Context, agentID uuid.UUID) (uuid.UUID, error) {
	var tenantID uuid.UUID
	err := s.bypassDB.QueryRowContext(ctx,
		`SELECT tenant_id FROM device_agents WHERE id = $1 AND deleted_at IS NULL`,
		agentID,
	).Scan(&tenantID)
	if err == sql.ErrNoRows {
		return uuid.Nil, ErrAgentNotFound
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to resolve agent tenant: %w", err)
	}
	return tenantID, nil
}

// GetNextJobForAgent retrieves the next pending job for a specific agent with Redis locking
func (s *JobQueueService) GetNextJobForAgent(ctx context.Context, agentID uuid.UUID) (*models.DeviceJob, error) {
	// Resolve the agent's owning tenant up front and constrain every candidate
	// job to it. Without this the `agent_id IS NULL` branch below would hand ANY
	// tenant's unassigned device_interrogation job (credentials included) to the
	// first agent that polls, regardless of which tenant the agent belongs to
	//. Tenant isolation on this bypass-role path is enforced HERE.
	agentTenant, err := s.resolveAgentTenant(ctx, agentID)
	if err != nil {
		if errors.Is(err, ErrAgentNotFound) {
			return nil, nil // Unknown agent → no job, not an error.
		}
		return nil, err
	}

	// Use Redis lock to prevent concurrent job assignment
	lockKey := fmt.Sprintf("device_job:lock:agent:%s", agentID.String())
	lockTTL := 30 * time.Second

	// Try to acquire lock
	acquired, err := s.redis.SetNX(ctx, lockKey, "locked", lockTTL).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}
	if !acquired {
		// Another process is already assigning a job to this agent
		return nil, nil
	}
	defer s.redis.Del(ctx, lockKey)

	// Atomically claim the next pending job for this agent (or unassigned
	// device_interrogation jobs) WITHIN THE AGENT'S OWN TENANT. The row lock must
	// live in the same statement that marks the job assigned; a standalone SELECT
	// ... FOR UPDATE in autocommit releases the lock before the UPDATE.
	now := time.Now()
	query := `
		WITH candidate AS (
			SELECT id
			FROM device_jobs
			WHERE status = 'pending'
				AND deleted_at IS NULL
				AND tenant_id = $2
				AND (expires_at IS NULL OR expires_at > NOW())
				AND (
					(agent_id = $1 AND job_type = 'device_interrogation') OR
					(agent_id IS NULL AND job_type = 'device_interrogation')
				)
			ORDER BY created_at ASC
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		UPDATE device_jobs dj
		SET agent_id = $1, status = 'assigned', assigned_at = $3, updated_at = $3
		FROM candidate
		WHERE dj.id = candidate.id
		RETURNING dj.id, dj.tenant_id, dj.job_type, dj.device_id, dj.agent_id, dj.status,
			credentials, parameters, results, error_message,
			created_at, assigned_at, started_at, completed_at, expires_at, deleted_at
	`

	// RLS: agent-outbound — keyed by agent id, tenant is the OUTPUT → bypass role.
	job := &models.DeviceJob{}
	var credentialsJSONB, parametersJSONB, resultsJSONB []byte
	var deviceID, agentIDStr sql.NullString

	err = s.bypassDB.QueryRowContext(ctx, query, agentID, agentTenant, now).Scan(
		&job.ID, &job.TenantID, &job.JobType, &deviceID, &agentIDStr, &job.Status,
		&credentialsJSONB, &parametersJSONB, &resultsJSONB, &job.ErrorMessage,
		&job.CreatedAt, &job.AssignedAt, &job.StartedAt, &job.CompletedAt, &job.ExpiresAt, &job.DeletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil // No job available
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query job: %w", err)
	}

	// Parse JSONB fields
	if deviceID.Valid {
		id, _ := uuid.Parse(deviceID.String)
		job.DeviceID = &id
	}
	if agentIDStr.Valid {
		id, _ := uuid.Parse(agentIDStr.String)
		job.AgentID = &id
	}
	if len(credentialsJSONB) > 0 {
		_ = json.Unmarshal(credentialsJSONB, &job.Credentials)
	}
	if len(parametersJSONB) > 0 {
		_ = json.Unmarshal(parametersJSONB, &job.Parameters)
	}
	if len(resultsJSONB) > 0 {
		_ = json.Unmarshal(resultsJSONB, &job.Results)
	}

	return job, nil
}

// GetNextJobForPlatform retrieves the next pending job for platform internal agent
func (s *JobQueueService) GetNextJobForPlatform(ctx context.Context) (*models.DeviceJob, error) {
	// Use Redis lock to prevent concurrent job assignment
	lockKey := "device_job:lock:platform"
	lockTTL := 30 * time.Second

	// Try to acquire lock
	acquired, err := s.redis.SetNX(ctx, lockKey, "locked", lockTTL).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}
	if !acquired {
		// Another process is already assigning a job
		return nil, nil
	}
	defer s.redis.Del(ctx, lockKey)

	// Atomically claim the next pending job for platform (cloud_discovery or
	// device_interrogation with no agent_id). Keep the lock and status update in
	// one statement so an agent poll cannot claim the same unassigned job.
	now := time.Now()
	query := `
		WITH candidate AS (
			SELECT id
			FROM device_jobs
			WHERE status = 'pending'
				AND deleted_at IS NULL
				AND (expires_at IS NULL OR expires_at > NOW())
				AND (
					job_type = 'cloud_discovery' OR
					(job_type = 'device_interrogation' AND agent_id IS NULL)
				)
			ORDER BY created_at ASC
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		UPDATE device_jobs dj
		SET status = 'assigned', assigned_at = $1, updated_at = $1
		FROM candidate
		WHERE dj.id = candidate.id
		RETURNING dj.id, dj.tenant_id, dj.job_type, dj.device_id, dj.agent_id, dj.integration_id, dj.status,
			credentials, parameters, results, error_message,
			created_at, assigned_at, started_at, completed_at, expires_at, deleted_at
	`

	// RLS: cross-tenant background sweep (no single tenant) → bypass role.
	job := &models.DeviceJob{}
	var credentialsJSONB, parametersJSONB, resultsJSONB []byte
	var deviceID, agentIDStr, integrationIDStr sql.NullString

	err = s.bypassDB.QueryRowContext(ctx, query, now).Scan(
		&job.ID, &job.TenantID, &job.JobType, &deviceID, &agentIDStr, &integrationIDStr, &job.Status,
		&credentialsJSONB, &parametersJSONB, &resultsJSONB, &job.ErrorMessage,
		&job.CreatedAt, &job.AssignedAt, &job.StartedAt, &job.CompletedAt, &job.ExpiresAt, &job.DeletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil // No job available
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query job: %w", err)
	}

	// Parse JSONB fields and UUIDs
	if deviceID.Valid {
		id, _ := uuid.Parse(deviceID.String)
		job.DeviceID = &id
	}
	if agentIDStr.Valid {
		id, _ := uuid.Parse(agentIDStr.String)
		job.AgentID = &id
	}
	if integrationIDStr.Valid {
		id, _ := uuid.Parse(integrationIDStr.String)
		job.IntegrationID = &id
	}
	if len(credentialsJSONB) > 0 {
		_ = json.Unmarshal(credentialsJSONB, &job.Credentials)
	}
	if len(parametersJSONB) > 0 {
		_ = json.Unmarshal(parametersJSONB, &job.Parameters)
	}
	if len(resultsJSONB) > 0 {
		_ = json.Unmarshal(resultsJSONB, &job.Results)
	}

	return job, nil
}

// UpdateJobStatus updates job status and optionally stores results.
//
// RLS: keyed by job id with no tenant input (the owning tenant is the OUTPUT).
// Called from the agent-outbound result path, the background worker, and the
// async cloud-discovery goroutine — none of which carry app.tenant_id — so it
// runs on the bypass role.
func (s *JobQueueService) UpdateJobStatus(
	ctx context.Context,
	jobID uuid.UUID,
	status models.DeviceJobStatus,
	result *models.JobResult,
	errorMessage *string,
) error {
	now := time.Now()

	// Marshal results to JSON; use nil interface (not nil []byte) when no result
	// so the pq driver sends SQL NULL rather than an invalid empty byte value for JSONB columns
	var resultsJSON interface{}
	if result != nil {
		marshaled, err := json.Marshal(result)
		if err != nil {
			return fmt.Errorf("failed to marshal results: %w", err)
		}
		resultsJSON = marshaled
	}

	// Build update query based on status
	var query string
	var args []interface{}

	switch status {
	case models.JobStatusInProgress:
		query = `
			UPDATE device_jobs
			SET status = $1, started_at = $2, updated_at = $2
			WHERE id = $3
		`
		args = []interface{}{string(status), now, jobID}
	case models.JobStatusCompleted:
		query = `
			UPDATE device_jobs
			SET status = $1, completed_at = $2, results = $3, error_message = $4, updated_at = $2
			WHERE id = $5
		`
		args = []interface{}{string(status), now, resultsJSON, errorMessage, jobID}
	case models.JobStatusFailed:
		query = `
			UPDATE device_jobs
			SET status = $1, completed_at = $2, results = $3, error_message = $4, updated_at = $2
			WHERE id = $5
		`
		args = []interface{}{string(status), now, resultsJSON, errorMessage, jobID}
	default:
		query = `
			UPDATE device_jobs
			SET status = $1, updated_at = $2
			WHERE id = $3
		`
		args = []interface{}{string(status), now, jobID}
	}

	_, err := s.bypassDB.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update job status: %w", err)
	}

	// Reconcile the interrogation schedule that dispatched this job, if any.
	//
	// This is the hook point precisely because it is the ONE choke point every
	// executor passes through — the in-cluster platform worker, an agent
	// submitting results, the async cloud-discovery goroutine and the
	// dispatch-failure paths in GetNextJob all land here. Attaching the outcome
	// to any single executor would have left the schedule stuck on 'pending'
	// whenever a different one ran the job.
	//
	// Non-fatal: a job's own status is the record of record; failing to attribute
	// it to a schedule must never fail the status update itself.
	if err := recordScheduleOutcome(ctx, s.bypassDB, jobID, status, errorMessage, result); err != nil {
		log.Printf("[JobQueueService] Warning: failed to record schedule outcome for job %s: %v", jobID, err)
	}

	return nil
}

// jobResultAssetCount reports how many assets a job result actually delivered.
//
// len(result.Assets) alone is not it: the in-cluster device-interrogation
// executor materializes its assets itself and forwards an intentionally EMPTY
// asset list (that emptiness is what prevents double-materialization), carrying
// the real figure in Metadata["assets_count"]. The cloud-discovery paths use the
// same metadata key. Reading only the slice reports 0 for a run that discovered
// a dozen devices.
func jobResultAssetCount(result *models.JobResult) int {
	if result == nil {
		return 0
	}
	if n := len(result.Assets); n > 0 {
		return n
	}
	switch v := result.Metadata["assets_count"].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64: // survives a JSON round-trip through device_jobs.results
		return int(v)
	}
	return 0
}

// RecordDiscoveryJob stamps onto a device job the discovery job its results have
// ALREADY been materialized into, so the result processor reuses that job rather
// than creating a second one.
//
// The in-cluster executor interrogates through DeviceInterrogationService, which
// creates its own discovery job and writes the targets and findings there. The
// result processor only knew to reuse an existing discovery job when this
// parameter was set — and nothing set it — so every in-cluster interrogation
// left behind a second discovery job that no executor ever picks up. It sits
// `queued` forever on Discovery → Discovery Jobs, owning zero targets and zero
// findings, while the job's processing log points at that empty job instead of
// the one holding the real results.
//
// RLS: keyed by job id with no tenant input (the owning tenant is the OUTPUT),
// called from the background worker → bypass role, like UpdateJobStatus.
func (s *JobQueueService) RecordDiscoveryJob(ctx context.Context, jobID, discoveryJobID uuid.UUID) error {
	if discoveryJobID == uuid.Nil {
		return fmt.Errorf("failed to record discovery job: discovery job id is required")
	}
	_, err := s.bypassDB.ExecContext(ctx, `
		UPDATE device_jobs
		SET parameters = jsonb_set(COALESCE(parameters, '{}'::jsonb), '{discovery_job_id}', to_jsonb($1::text), true),
		    updated_at = now()
		WHERE id = $2`, discoveryJobID.String(), jobID)
	if err != nil {
		return fmt.Errorf("failed to record discovery job on device job: %w", err)
	}
	return nil
}

// GetJobByID retrieves a job by its ID.
//
// integration_id is part of the projection. It was missing, so every consumer
// of this method saw IntegrationID == nil on a cloud discovery job — which is
// how a scheduled cloud discovery came to be recorded as
// executed_via=device_interrogation / execution_mode=sensors. Its sibling
// GetNextJobForPlatform always selected the column; this one did not.
//
// RLS: keyed by job id with no tenant input (the owning tenant is the OUTPUT) —
// used by the result processor before the tenant is known — so it runs on the
// bypass role.
func (s *JobQueueService) GetJobByID(ctx context.Context, jobID uuid.UUID) (*models.DeviceJob, error) {
	query := `
		SELECT id, tenant_id, job_type, device_id, agent_id, integration_id, status,
			credentials, parameters, results, error_message,
			created_at, assigned_at, started_at, completed_at, expires_at, deleted_at
		FROM device_jobs
		WHERE id = $1 AND deleted_at IS NULL
	`

	job := &models.DeviceJob{}
	var credentialsJSONB, parametersJSONB, resultsJSONB []byte
	var deviceID, agentIDStr, integrationIDStr sql.NullString

	err := s.bypassDB.QueryRowContext(ctx, query, jobID).Scan(
		&job.ID, &job.TenantID, &job.JobType, &deviceID, &agentIDStr, &integrationIDStr, &job.Status,
		&credentialsJSONB, &parametersJSONB, &resultsJSONB, &job.ErrorMessage,
		&job.CreatedAt, &job.AssignedAt, &job.StartedAt, &job.CompletedAt, &job.ExpiresAt, &job.DeletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("job not found: %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query job: %w", err)
	}

	// Parse JSONB fields
	if deviceID.Valid {
		id, _ := uuid.Parse(deviceID.String)
		job.DeviceID = &id
	}
	if agentIDStr.Valid {
		id, _ := uuid.Parse(agentIDStr.String)
		job.AgentID = &id
	}
	if integrationIDStr.Valid {
		id, _ := uuid.Parse(integrationIDStr.String)
		job.IntegrationID = &id
	}
	if len(credentialsJSONB) > 0 {
		_ = json.Unmarshal(credentialsJSONB, &job.Credentials)
	}
	if len(parametersJSONB) > 0 {
		_ = json.Unmarshal(parametersJSONB, &job.Parameters)
	}
	if len(resultsJSONB) > 0 {
		_ = json.Unmarshal(resultsJSONB, &job.Results)
	}

	return job, nil
}
