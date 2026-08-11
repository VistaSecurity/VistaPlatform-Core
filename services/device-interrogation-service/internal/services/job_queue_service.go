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

	// Find next pending job for this agent (or unassigned device_interrogation
	// jobs) WITHIN THE AGENT'S OWN TENANT.
	query := `
		SELECT id, tenant_id, job_type, device_id, agent_id, status,
			credentials, parameters, results, error_message,
			created_at, assigned_at, started_at, completed_at, expires_at, deleted_at
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
	`

	// RLS: agent-outbound — keyed by agent id, tenant is the OUTPUT → bypass role.
	job := &models.DeviceJob{}
	var credentialsJSONB, parametersJSONB, resultsJSONB []byte
	var deviceID, agentIDStr sql.NullString

	err = s.bypassDB.QueryRowContext(ctx, query, agentID, agentTenant).Scan(
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

	// Assign job to agent and mark as assigned
	now := time.Now()
	updateQuery := `
		UPDATE device_jobs
		SET agent_id = $1, status = 'assigned', assigned_at = $2, updated_at = $2
		WHERE id = $3
	`
	_, err = s.bypassDB.ExecContext(ctx, updateQuery, agentID, now, job.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to assign job: %w", err)
	}

	job.AgentID = &agentID
	job.Status = models.JobStatusAssigned
	job.AssignedAt = &now

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

	// Find next pending job for platform (cloud_discovery or device_interrogation with no agent_id)
	query := `
		SELECT id, tenant_id, job_type, device_id, agent_id, integration_id, status,
			credentials, parameters, results, error_message,
			created_at, assigned_at, started_at, completed_at, expires_at, deleted_at
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
	`

	// RLS: cross-tenant background sweep (no single tenant) → bypass role.
	job := &models.DeviceJob{}
	var credentialsJSONB, parametersJSONB, resultsJSONB []byte
	var deviceID, agentIDStr, integrationIDStr sql.NullString

	err = s.bypassDB.QueryRowContext(ctx, query).Scan(
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

	// Mark as assigned (agent_id remains NULL for platform jobs)
	now := time.Now()
	updateQuery := `
		UPDATE device_jobs
		SET status = 'assigned', assigned_at = $1, updated_at = $1
		WHERE id = $2
	`
	_, err = s.bypassDB.ExecContext(ctx, updateQuery, now, job.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to assign job: %w", err)
	}

	job.Status = models.JobStatusAssigned
	job.AssignedAt = &now

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

	return nil
}

// GetJobByID retrieves a job by its ID.
//
// RLS: keyed by job id with no tenant input (the owning tenant is the OUTPUT) —
// used by the result processor before the tenant is known — so it runs on the
// bypass role.
func (s *JobQueueService) GetJobByID(ctx context.Context, jobID uuid.UUID) (*models.DeviceJob, error) {
	query := `
		SELECT id, tenant_id, job_type, device_id, agent_id, status,
			credentials, parameters, results, error_message,
			created_at, assigned_at, started_at, completed_at, expires_at, deleted_at
		FROM device_jobs
		WHERE id = $1 AND deleted_at IS NULL
	`

	job := &models.DeviceJob{}
	var credentialsJSONB, parametersJSONB, resultsJSONB []byte
	var deviceID, agentIDStr sql.NullString

	err := s.bypassDB.QueryRowContext(ctx, query, jobID).Scan(
		&job.ID, &job.TenantID, &job.JobType, &deviceID, &agentIDStr, &job.Status,
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
