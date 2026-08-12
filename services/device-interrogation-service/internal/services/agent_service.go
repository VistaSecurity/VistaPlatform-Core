package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/config"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// ErrInvalidDeviceAgentRegistrationKey means the key cannot be used for device agent bootstrap
// (missing, expired, used, wrong profile, etc.).
var ErrInvalidDeviceAgentRegistrationKey = errors.New("invalid device agent registration key")

// ErrAgentIDConflict means the proposed agent id is already registered (primary key conflict).
var ErrAgentIDConflict = errors.New("agent id already exists")

// ErrAgentNotFound means no registered (non-deleted) device agent matches the id.
var ErrAgentNotFound = errors.New("agent not found")

// ErrJobTenantMismatch means a job does not belong to the acting agent's tenant.
var ErrJobTenantMismatch = errors.New("job does not belong to agent tenant")

// AgentService handles agent business logic
type AgentService struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) connection used by the
	// cross-tenant paths: agent bootstrap (registration-key lookup), the
	// agent-outbound jobs/results/heartbeat (keyed by agent id, tenant is the
	// output) and the cross-tenant admin roll-up. Pre-flip it resolves to the
	// same connection as db.
	bypassDB        *sql.DB
	jobQueue        *JobQueueService
	resultProcessor *ResultProcessor
	encryptionKey   string
}

// NewAgentService creates a new agent service. db is the RLS-scoped (crypto_app)
// connection; bypassDB is the BYPASSRLS (crypto_bypass) connection used by the
// cross-tenant/agent-outbound paths. Pre-flip both handles resolve to the same
// connection.
func NewAgentService(db, bypassDB *sql.DB, redis *redis.Client) *AgentService {
	jobQueue := NewJobQueueService(db, bypassDB, redis)
	resultProcessor := NewResultProcessor(db, bypassDB)
	encryptionKey := config.GetEnv("ENCRYPTION_MASTER_KEY", "")
	return &AgentService{
		db:              db,
		bypassDB:        bypassDB,
		jobQueue:        jobQueue,
		resultProcessor: resultProcessor,
		encryptionKey:   encryptionKey,
	}
}

// RegisterDeviceAgentBootstrap registers an agent using a pending registration key (no JWT).
// It resolves the tenant from pending_sensor_registrations, requires profile device_interrogation,
// and marks the pending row used in the same transaction as the agent insert (same pattern as sensor-manager RegisterSensor).
//
// RLS: cross-tenant — runs on the bypass role (Phase 4). The tenant is the OUTPUT
// of the registration-key lookup, so app.tenant_id cannot be set before the
// device_agents INSERT — the whole flow runs pre-tenant-resolution on bypassDB.
func (s *AgentService) RegisterDeviceAgentBootstrap(ctx context.Context, req models.RegisterAgentRequest) (*models.Agent, error) {
	tx, err := s.bypassDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var tenantID uuid.UUID
	var profile string
	// Carry the operator-supplied name/description forward from the pending
	// registration so the enrolled agent is identifiable in the fleet list —
	// otherwise device_agents.name/profile stay NULL and the UI has nothing to
	// label the row with.
	var pendingName, pendingDescription sql.NullString
	pendingQuery := `
		SELECT tenant_id, profile, name, description FROM pending_sensor_registrations
		WHERE registration_key = $1 AND status = 'pending' AND expires_at > NOW()
		FOR UPDATE`
	err = tx.QueryRowContext(ctx, pendingQuery, req.RegistrationKey).Scan(&tenantID, &profile, &pendingName, &pendingDescription)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w", ErrInvalidDeviceAgentRegistrationKey)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to verify registration key: %w", err)
	}
	if profile != "device_interrogation" {
		return nil, fmt.Errorf("%w: not a device interrogation agent key", ErrInvalidDeviceAgentRegistrationKey)
	}
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("%w: missing tenant", ErrInvalidDeviceAgentRegistrationKey)
	}

	// Global uniqueness check — runs on the bypass handle, not `tx` (see the
	// method comment: a tenant-scoped tx cannot see another tenant's burned key).
	if err := s.validateRegistrationKeyWithQuerier(ctx, s.bypassDB, tenantID, req.RegistrationKey); err != nil {
		return nil, err
	}

	var agentID uuid.UUID
	if req.AgentID != "" {
		agentID, err = uuid.Parse(req.AgentID)
		if err != nil {
			return nil, fmt.Errorf("invalid agent_id format in request: %w", err)
		}
	} else {
		agentID = uuid.New()
	}

	now := time.Now()
	insertQuery := `
		INSERT INTO device_agents (
			id, tenant_id, registration_key, name, description, platform, profile, version, status, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, tenant_id, name, platform, profile, version, status, last_heartbeat, created_at, updated_at
	`
	agent := &models.Agent{}
	err = tx.QueryRowContext(ctx, insertQuery,
		agentID, tenantID, req.RegistrationKey, pendingName, pendingDescription, req.Platform, profile, req.Version, "active", now, now,
	).Scan(
		&agent.ID, &agent.TenantID, &agent.Name, &agent.Platform, &agent.Profile, &agent.Version,
		&agent.Status, &agent.LastHeartbeat, &agent.CreatedAt, &agent.UpdatedAt,
	)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return nil, fmt.Errorf("%w: %v", ErrAgentIDConflict, err)
		}
		return nil, fmt.Errorf("failed to register agent: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE pending_sensor_registrations SET status = 'used', used_at = NOW() WHERE registration_key = $1`,
		req.RegistrationKey,
	); err != nil {
		return nil, fmt.Errorf("failed to mark registration key used: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit registration: %w", err)
	}
	return agent, nil
}

// RegisterAgent registers a new device agent. tenantID is an INPUT, so the
// validation read and the INSERT both run inside one WithTenantTx (sets
// app.tenant_id; device_agents is RLS-scoped). The validation runs on the same
// tx so it is tenant-scoped too.
func (s *AgentService) RegisterAgent(ctx context.Context, tenantID uuid.UUID, req models.RegisterAgentRequest) (*models.Agent, error) {
	// Determine agent ID: use proposed ID from CSR if provided, otherwise generate new one
	var agentID uuid.UUID
	if req.AgentID != "" {
		// Agent proposed an ID in CSR
		var err error
		agentID, err = uuid.Parse(req.AgentID)
		if err != nil {
			return nil, fmt.Errorf("invalid agent_id format in request: %w", err)
		}
	} else {
		// Legacy flow: generate agent ID
		agentID = uuid.New()
	}

	now := time.Now()

	query := `
		INSERT INTO device_agents (
			id, tenant_id, registration_key, platform, version, status, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, tenant_id, registration_key, platform, version, status, last_heartbeat, created_at, updated_at
	`

	agent := &models.Agent{}
	var tenantIDOut uuid.UUID
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		// Global uniqueness check — deliberately on the bypass handle rather than
		// this tx, so a key already burned by another tenant is still rejected.
		if vErr := s.validateRegistrationKeyWithQuerier(ctx, s.bypassDB, tenantID, req.RegistrationKey); vErr != nil {
			return fmt.Errorf("registration key validation failed: %w", vErr)
		}
		return tx.QueryRowContext(ctx, query,
			agentID, tenantID, req.RegistrationKey, req.Platform, req.Version, "active", now, now,
		).Scan(
			&agent.ID, &tenantIDOut, &agent.RegistrationKey, &agent.Platform, &agent.Version,
			&agent.Status, &agent.LastHeartbeat, &agent.CreatedAt, &agent.UpdatedAt,
		)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to register agent: %w", err)
	}

	return agent, nil
}

type registrationKeyQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// validateRegistrationKeyWithQuerier rejects a registration key that has already
// been consumed.
//
// RLS: the reuse check is GLOBAL by design — the query deliberately carries no
// tenant filter, because a key burned by any tenant must not be reusable by
// another. Callers therefore pass the BYPASSRLS handle, not their tenant tx.
// Handed a tenant-scoped tx under enforced RLS the SELECT can only see the
// caller's own agents, silently narrowing a cross-tenant uniqueness check to a
// per-tenant one. There is no UNIQUE index on device_agents.registration_key,
// so this check is the only control — nothing downstream would catch the miss.
func (s *AgentService) validateRegistrationKeyWithQuerier(ctx context.Context, q registrationKeyQuerier, _ uuid.UUID, registrationKey string) error {
	if len(registrationKey) < 16 {
		return fmt.Errorf("registration key is too short (minimum 16 characters)")
	}

	if len(registrationKey) > 255 {
		return fmt.Errorf("registration key is too long (maximum 255 characters)")
	}

	var existingID uuid.UUID
	checkQuery := `
		SELECT id FROM device_agents
		WHERE registration_key = $1 AND deleted_at IS NULL
		LIMIT 1
	`
	err := q.QueryRowContext(ctx, checkQuery, registrationKey).Scan(&existingID)
	if err == nil {
		return fmt.Errorf("registration key has already been used")
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("failed to check registration key: %w", err)
	}

	return nil
}

// ListAgents lists all agents for a tenant
func (s *AgentService) ListAgents(ctx context.Context, tenantID uuid.UUID) ([]*models.Agent, error) {
	query := `
		SELECT id, tenant_id, name, platform, profile, version, status, last_heartbeat, created_at, updated_at
		FROM device_agents
		WHERE tenant_id = $1 AND deleted_at IS NULL
		ORDER BY created_at DESC
	`

	// RLS-scoped read on `device_agents`: WithTenantTx sets app.tenant_id; the
	// explicit WHERE tenant_id = $1 is kept as the primary control.
	var agents []*models.Agent
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx, query, tenantID)
		if e != nil {
			return fmt.Errorf("failed to list agents: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			agent := &models.Agent{}
			var tenantIDOut uuid.UUID
			if scanErr := rows.Scan(
				&agent.ID, &tenantIDOut, &agent.Name, &agent.Platform, &agent.Profile, &agent.Version,
				&agent.Status, &agent.LastHeartbeat, &agent.CreatedAt, &agent.UpdatedAt,
			); scanErr != nil {
				return fmt.Errorf("failed to scan agent: %w", scanErr)
			}
			agents = append(agents, agent)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return agents, nil
}

// ListAllAgents lists interrogation agents across ALL tenants for the
// platform-admin Fleet view. It deliberately omits the tenant_id WHERE clause
// (RLS is inert here — tenant isolation elsewhere is the explicit WHERE tenant_id
// filter, which this admin roll-up intentionally drops) and joins tenants for
// per-row tenant identity. Callers MUST gate this behind RequirePlatformAdmin.
//
// tenantID optionally narrows the cross-tenant roll-up to one tenant (operator
// scope). Empty = all tenants. When set it is applied as a parameterized
// WHERE a.tenant_id = $1 so other tenants' rows are never shipped to the client.
func (s *AgentService) ListAllAgents(ctx context.Context, tenantID string) ([]*models.AdminAgent, error) {
	query := `
		SELECT a.id, a.tenant_id, t.name AS tenant_name, t.slug AS tenant_slug,
		       a.name, a.platform, a.profile, a.version, a.status,
		       a.last_heartbeat, a.created_at, a.updated_at
		FROM device_agents a
		LEFT JOIN tenants t ON t.id = a.tenant_id
		WHERE a.deleted_at IS NULL
	`
	args := []interface{}{}
	if tenantID != "" {
		query += " AND a.tenant_id = $1"
		args = append(args, tenantID)
	}
	query += " ORDER BY a.created_at DESC"

	// RLS: cross-tenant — runs on the bypass role. The tenant_id filter is
	// intentionally dropped (or operator-narrowed) here; gated by RequirePlatformAdmin.
	rows, err := s.bypassDB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list all agents: %w", err)
	}
	defer rows.Close()

	var agents []*models.AdminAgent
	for rows.Next() {
		agent := &models.AdminAgent{}
		var tenantName, tenantSlug sql.NullString
		err := rows.Scan(
			&agent.ID, &agent.TenantID, &tenantName, &tenantSlug,
			&agent.Name, &agent.Platform, &agent.Profile, &agent.Version,
			&agent.Status, &agent.LastHeartbeat, &agent.CreatedAt, &agent.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan agent: %w", err)
		}
		agent.TenantName = tenantName.String
		agent.TenantSlug = tenantSlug.String
		agents = append(agents, agent)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate agents: %w", err)
	}

	return agents, nil
}

// GetNextJob retrieves the next pending job for an agent
func (s *AgentService) GetNextJob(ctx context.Context, agentID uuid.UUID) (*models.Job, error) {
	deviceJob, err := s.jobQueue.GetNextJobForAgent(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get next job: %w", err)
	}
	if deviceJob == nil {
		return nil, nil // No job available
	}

	// Convert DeviceJob to Job model for agent
	job := deviceJob.ToJob()

	// Seal the credentials for THIS agent before the job leaves the platform.
	// The stored payload is in one of the platform's internal shapes, none of
	// which the agent could parse; this is where it becomes the one
	// canonical envelope shared/agentcreds defines. Done before the job is
	// marked in_progress so a credential failure leaves a clearly failed job
	// rather than one stuck in progress.
	if len(job.Credentials) > 0 {
		sealed, sealErr := s.sealJobCredentials(ctx, agentID, job)
		if sealErr != nil {
			// Fail the job loudly instead of handing over an unusable payload:
			// the tenant sees the reason in the job list, and the agent moves
			// on to the next job rather than retrying a poisoned one forever.
			msg := fmt.Sprintf("failed to prepare credentials for agent: %v", sealErr)
			if updErr := s.jobQueue.UpdateJobStatus(ctx, deviceJob.ID, models.JobStatusFailed, nil, &msg); updErr != nil {
				return nil, fmt.Errorf("%s (and failed to record it: %w)", msg, updErr)
			}
			return nil, nil
		}
		job.Credentials = sealed
	}

	// Mark job as in_progress
	err = s.jobQueue.UpdateJobStatus(ctx, deviceJob.ID, models.JobStatusInProgress, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to update job status: %w", err)
	}

	return job, nil
}

// sealJobCredentials resolves the claiming agent's registration key and seals
// the job's credentials with it.
//
// RLS: agent-outbound — keyed by agent id, tenant is the OUTPUT → bypass role,
// same as every other read on this path.
func (s *AgentService) sealJobCredentials(ctx context.Context, agentID uuid.UUID, job *models.Job) (map[string]interface{}, error) {
	var registrationKey sql.NullString
	err := s.bypassDB.QueryRowContext(ctx,
		`SELECT registration_key FROM device_agents WHERE id = $1 AND deleted_at IS NULL`,
		agentID,
	).Scan(&registrationKey)
	if err == sql.ErrNoRows {
		return nil, ErrAgentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to resolve agent registration key: %w", err)
	}

	return SealCredentialsForAgent(job.Credentials, job.ID.String(), registrationKey.String, s.encryptionKey)
}

// SubmitJobResult submits job execution results.
//
// The agent is authenticated only by its id (the mTLS CN when AGENT_MTLS_REQUIRED
// is on; nothing when it's off), and result.JobID is attacker-controllable, so
// before writing anything we confirm the target job belongs to the acting agent's
// tenant — and to this agent when the job is agent-assigned. Without this guard an
// agent could complete/fail another tenant's jobs and inject forged discovery
// findings into their inventory. Returns ErrAgentNotFound /
// ErrJobTenantMismatch on a cross-tenant attempt.
func (s *AgentService) SubmitJobResult(ctx context.Context, agentID uuid.UUID, result *models.JobResult) error {
	agentTenant, err := s.jobQueue.resolveAgentTenant(ctx, agentID)
	if err != nil {
		return err
	}
	job, err := s.jobQueue.GetJobByID(ctx, result.JobID)
	if err != nil {
		// Unknown/deleted job: report the same as a cross-tenant mismatch so a
		// caller cannot probe which job ids exist.
		if errors.Is(err, sql.ErrNoRows) {
			return ErrJobTenantMismatch
		}
		return fmt.Errorf("failed to load job for result submission: %w", err)
	}
	if job.TenantID != agentTenant {
		return ErrJobTenantMismatch
	}
	// A job explicitly assigned to a different agent (same tenant) is not this
	// agent's to complete.
	if job.AgentID != nil && *job.AgentID != agentID {
		return ErrJobTenantMismatch
	}

	// Update job status and store results
	status := models.JobStatusCompleted
	var errorMsg *string
	if !result.Success {
		status = models.JobStatusFailed
		errorMsg = &result.Error
	}

	err = s.jobQueue.UpdateJobStatus(ctx, result.JobID, status, result, errorMsg)
	if err != nil {
		return fmt.Errorf("failed to update job status: %w", err)
	}

	// Process results and create discovery findings
	if result.Success && len(result.Assets) > 0 {
		err = s.resultProcessor.ProcessJobResults(ctx, result.JobID, result)
		if err != nil {
			// Log error but don't fail the submission
			fmt.Printf("Warning: failed to process job results: %v\n", err)
		}
	}

	return nil
}

// UpdateHeartbeat updates agent heartbeat timestamp.
//
// RLS: agent-outbound ingestion — keyed by agent id, the tenant is the OUTPUT,
// so this runs on the bypass role (mirrors sensor-manager heartbeat handling).
// UpdateHeartbeat stamps liveness and, when the agent reports one, refreshes
// its recorded binary version. version follows heartbeat semantics: empty means
// "not reported" and leaves the stored value untouched (older agents send no
// version), so a pre-stamping binary can never blank a good value.
func (s *AgentService) UpdateHeartbeat(ctx context.Context, agentID uuid.UUID, version string) error {
	query := `
		UPDATE device_agents
		SET last_heartbeat = $1, updated_at = $1,
		    version = COALESCE(NULLIF($3, ''), version)
		WHERE id = $2
	`

	_, err := s.bypassDB.ExecContext(ctx, query, time.Now(), agentID, version)
	if err != nil {
		return fmt.Errorf("failed to update heartbeat: %w", err)
	}

	return nil
}
