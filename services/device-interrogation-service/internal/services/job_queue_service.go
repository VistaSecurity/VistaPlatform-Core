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
	var job *models.DeviceJob
	err := shareddatabase.WithTenantTx(ctx, s.db, req.TenantID, func(tx *sql.Tx) error {
		var err error
		job, err = s.createJobTx(ctx, tx, jobID, req)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.publishJob(job)
	return job, nil
}

// createJobTx lets durable producers commit their receipt and job together.
// The caller publishes only after that transaction commits; polling recovers a
// process exit between commit and publish.
func (s *JobQueueService) createJobTx(ctx context.Context, tx *sql.Tx, jobID uuid.UUID, req models.CreateDeviceJobRequest) (*models.DeviceJob, error) {
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
			id, tenant_id, job_type, asset_id, integration_id, agent_id, status,
			credentials, parameters, created_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, tenant_id, job_type, asset_id, agent_id, status,
			credentials, parameters, results, error_message,
			created_at, assigned_at, started_at, completed_at, expires_at, deleted_at
	`

	job := &models.DeviceJob{}
	var credentialsJSONB, parametersJSONB, resultsJSONB []byte
	var assetID, agentID sql.NullString

	// RLS-scoped write on `device_jobs`: req.TenantID is an input, so set
	// app.tenant_id to it for the INSERT (satisfies WITH CHECK).
	err := tx.QueryRowContext(ctx, query,
		jobID, req.TenantID, string(req.JobType), req.AssetID, req.IntegrationID, req.AgentID,
		string(models.JobStatusPending), credentialsJSON, parametersJSON, now, expiresAt,
	).Scan(
		&job.ID, &job.TenantID, &job.JobType, &assetID, &agentID, &job.Status,
		&credentialsJSONB, &parametersJSONB, &resultsJSONB, &job.ErrorMessage,
		&job.CreatedAt, &job.AssignedAt, &job.StartedAt, &job.CompletedAt, &job.ExpiresAt, &job.DeletedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create job: %w", err)
	}

	// Parse JSONB fields
	if assetID.Valid {
		id, _ := uuid.Parse(assetID.String)
		job.AssetID = &id
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

	job.IntegrationID = req.IntegrationID
	return job, nil
}

func (s *JobQueueService) publishJob(job *models.DeviceJob) {
	// Publish job event to NATS for immediate processing by subscribers
	if s.natsClient != nil && s.natsClient.IsConnected() {
		jobEvent := events.DeviceJobEvent{
			EventID:   uuid.New(),
			TenantID:  job.TenantID,
			JobID:     job.ID.String(),
			JobType:   string(job.JobType),
			Timestamp: job.CreatedAt,
		}
		if err := events.PublishJSON(s.natsClient, events.SubjectDeviceJobsSubmit, jobEvent); err != nil {
			log.Printf("[JobQueueService] Failed to publish device job to NATS (will rely on DB polling): %v", err)
		} else {
			log.Printf("[JobQueueService] Published device job %s to NATS", job.ID)
		}
	}

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

	return s.claimAuthorizedJob(ctx, &agentID, &agentTenant)
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

	return s.claimAuthorizedJob(ctx, nil, nil)
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

	// device_jobs.error_message is the one field the job-results projection
	// (handlers/job_results.go) never touches: results are enumerated field by
	// field and Asset.Metadata additionally walked by RedactMap, while the
	// job-level error string is served verbatim by GET /jobs and GET /jobs/:id.
	//
	// The strings that reach here are built from runtime material — a vendor
	// error, a Go *url.Error that prints the whole request URL — so they get the
	// value-shaped half of the same redactor the results get. This is the
	// BACKSTOP; the real fix for the PAN-OS case was taking the API key out of
	// the URL. A backstop is here because the next vendor has not been checked.
	errorMessage = redactedErrorMessage(errorMessage)

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
		SELECT id, tenant_id, job_type, asset_id, agent_id, integration_id, status,
			credentials, parameters, results, error_message,
			created_at, assigned_at, started_at, completed_at, expires_at, deleted_at
		FROM device_jobs
		WHERE id = $1 AND deleted_at IS NULL
	`

	job := &models.DeviceJob{}
	var credentialsJSONB, parametersJSONB, resultsJSONB []byte
	var assetID, agentIDStr, integrationIDStr sql.NullString

	err := s.bypassDB.QueryRowContext(ctx, query, jobID).Scan(
		&job.ID, &job.TenantID, &job.JobType, &assetID, &agentIDStr, &integrationIDStr, &job.Status,
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
	if assetID.Valid {
		id, _ := uuid.Parse(assetID.String)
		job.AssetID = &id
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
