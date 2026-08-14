package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/config"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	sharednetwork "github.com/vistasecurity/vistaplatform/shared/network"
)

// ErrInvalidDeviceAgentRegistrationKey means the key cannot be used for device agent bootstrap
// (missing, expired, used, wrong profile, etc.).
var ErrInvalidDeviceAgentRegistrationKey = errors.New("invalid device agent registration key")

// ErrAgentIDConflict means the proposed agent id is already registered (primary key conflict).
var ErrAgentIDConflict = errors.New("agent id already exists")

// ErrAgentNotFound means no registered (non-deleted) device agent matches the id.
var ErrAgentNotFound = errors.New("agent not found")

// ErrPlatformAgentProtected means the delete targeted the in-cluster platform
// agent's per-tenant row (platform='platform'), which is not the tenant's to
// remove.
var ErrPlatformAgentProtected = errors.New("platform-managed agents cannot be deleted")

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

// ListAgents lists all agents for a tenant, with the detail the fleet UI needs to
// render a discovery agent as itself rather than as a sensor with empty columns:
// the operator's description, the host's full address inventory, and a summary of
// the work the agent has actually done.
//
// Both extras are LEFT JOIN LATERAL rather than separate round-trips — the roster
// is small and per-tenant, and an N+1 over agent_addresses would be paid on every
// page load for data that is always wanted.
func (s *AgentService) ListAgents(ctx context.Context, tenantID uuid.UUID) ([]*models.Agent, error) {
	query := `
		SELECT a.id, a.tenant_id, a.name, a.description, a.platform, a.profile, a.version,
		       a.status, a.ip_address, a.last_heartbeat, a.created_at, a.updated_at,
		       COALESCE(j.job_count, 0), j.last_job_at,
		       addr.addresses
		FROM device_agents a
		LEFT JOIN LATERAL (
			SELECT COUNT(*) AS job_count,
			       MAX(COALESCE(dj.completed_at, dj.started_at, dj.created_at)) AS last_job_at
			FROM device_jobs dj
			WHERE dj.agent_id = a.id AND dj.deleted_at IS NULL
		) j ON TRUE
		LEFT JOIN LATERAL (
			SELECT json_agg(
				json_build_object(
					'interface_name', aa.interface_name,
					-- host() not ::text: the cast appends the prefix, so a bare-IP
					-- comparison downstream would never match.
					'address', host(aa.address),
					'prefix_length', aa.prefix_length,
					'is_primary', aa.is_primary
				) ORDER BY aa.is_primary DESC, aa.interface_name
			) AS addresses
			FROM agent_addresses aa
			WHERE aa.device_agent_id = a.id
		) addr ON TRUE
		WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
		ORDER BY a.created_at DESC
	`

	// RLS-scoped read on `device_agents` (and the joined `device_jobs` /
	// `agent_addresses`, both RLS tables): WithTenantTx sets app.tenant_id; the
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
			var addressesJSON []byte
			if scanErr := rows.Scan(
				&agent.ID, &tenantIDOut, &agent.Name, &agent.Description, &agent.Platform,
				&agent.Profile, &agent.Version, &agent.Status, &agent.IPAddress,
				&agent.LastHeartbeat, &agent.CreatedAt, &agent.UpdatedAt,
				&agent.JobCount, &agent.LastJobAt, &addressesJSON,
			); scanErr != nil {
				return fmt.Errorf("failed to scan agent: %w", scanErr)
			}
			// json_agg over no rows yields SQL NULL, not '[]'. Normalize here so
			// the field is always an array on the wire.
			agent.Addresses = []models.AgentAddress{}
			if len(addressesJSON) > 0 {
				if jsonErr := json.Unmarshal(addressesJSON, &agent.Addresses); jsonErr != nil {
					return fmt.Errorf("failed to decode agent addresses: %w", jsonErr)
				}
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

// DeleteAgent soft-deletes a device agent and settles everything that pointed at
// it. Completes the model device_agents.deleted_at was created for: the column and
// the `deleted_at IS NULL` filters have existed since the table was added, but
// nothing ever wrote the column, so an enrolled agent could never be removed.
//
// Four effects, one transaction, in this order:
//
//  1. Soft-delete the agent row. Zero rows affected → ErrAgentNotFound, so a
//     wrong id (or another tenant's id, which RLS + the tenant_id filter make
//     indistinguishable from a wrong one) changes nothing.
//  2. Release the agent's PENDING jobs back to the unassigned pool. device_jobs
//     has ON DELETE SET NULL for a hard delete, which a soft delete never fires,
//     so without this the queued work is stranded: GetNextJobForAgent will not
//     hand an agent_id-pinned job to anyone else, and the deleted agent can no
//     longer claim it. Nulling agent_id puts it back where the in-cluster
//     PlatformAgentWorker (or another agent in the tenant) will pick it up.
//  3. Fail the agent's IN-PROGRESS jobs. The deleted agent will never report a
//     result — its next SubmitJobResult is rejected upstream — so those jobs would
//     otherwise sit in_progress forever. They are failed rather than released
//     because the work may already have run; re-queueing could double-execute an
//     interrogation against a live device.
//  4. Revoke the agent's certificates. Deleting the row already fails closed (see
//     below), but leaving a valid client certificate bound to a decommissioned
//     identity is not a state worth choosing.
//
// The agent binary keeps running on the operator's host and keeps polling. That
// is handled, and was already handled before this method existed: every
// agent-outbound path resolves the agent with `deleted_at IS NULL` —
// middleware.AgentAuth (404 "Agent not registered"), JobQueueService's
// resolveAgentTenant, and sealJobCredentials — so a deleted agent is rejected at
// the door and gets no jobs and no credentials. Deleting is therefore safe to do
// while the agent is live; it just will not uninstall it, which the UI says.
func (s *AgentService) DeleteAgent(ctx context.Context, tenantID, agentID uuid.UUID) error {
	// RLS-scoped writes on device_agents / device_jobs / agent_certificates:
	// WithTenantTx sets app.tenant_id; every statement also carries an explicit
	// tenant_id filter as the primary control.
	return shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		// The in-cluster platform agent auto-registers a row per tenant
		// (handlers/auto_registration.go stamps platform='platform'). It is the
		// tenant's handle to a shared service, not a deployment they own —
		// deleting it removes it from their fleet view and stops its heartbeat
		// row being theirs, while the service keeps running. Refused for the same
		// reason the platform sensor rows are: same class of row, same silence.
		var platform string
		if err := tx.QueryRowContext(ctx, `
			SELECT platform FROM device_agents
			WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`,
			agentID, tenantID).Scan(&platform); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrAgentNotFound
			}
			return fmt.Errorf("failed to load agent for deletion: %w", err)
		}
		if platform == "platform" {
			return ErrPlatformAgentProtected
		}

		res, err := tx.ExecContext(ctx, `
			UPDATE device_agents
			SET deleted_at = NOW(), updated_at = NOW()
			WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`,
			agentID, tenantID)
		if err != nil {
			return fmt.Errorf("failed to delete agent: %w", err)
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to confirm agent deletion: %w", err)
		}
		if affected == 0 {
			return ErrAgentNotFound
		}

		// Release pending jobs that CAN be re-dispatched. The `device_id IS NOT
		// NULL` filter is not defensive padding — it is the device_jobs
		// `valid_job_assignment` CHECK, which permits an unassigned
		// device_interrogation job only when it names a device. That constraint is
		// right: the in-cluster worker resolves an unassigned job's target by
		// re-reading the device row, so a job with neither an agent nor a device
		// is one nothing can execute. Nulling agent_id on those would abort the
		// whole delete on a constraint violation.
		if _, err := tx.ExecContext(ctx, `
			UPDATE device_jobs
			SET agent_id = NULL
			WHERE agent_id = $1 AND tenant_id = $2
			  AND status = 'pending' AND device_id IS NOT NULL AND deleted_at IS NULL`,
			agentID, tenantID); err != nil {
			return fmt.Errorf("failed to release pending jobs: %w", err)
		}

		// Everything still pinned to the agent is now unrunnable and must be
		// failed rather than left to sit:
		//   - in_progress — the deleted agent will never report a result.
		//   - pending with no device_id — nothing else can resolve its target
		//     (and the CHECK above forbids un-assigning it).
		// The two get different messages because they are different situations,
		// and a tenant reading the job list should not have to guess which.
		if _, err := tx.ExecContext(ctx, `
			UPDATE device_jobs
			SET status = 'failed',
			    error_message = CASE WHEN status = 'in_progress' THEN $3 ELSE $4 END,
			    completed_at = NOW()
			WHERE agent_id = $1 AND tenant_id = $2
			  AND status IN ('pending', 'assigned', 'in_progress') AND deleted_at IS NULL`,
			agentID, tenantID, agentDeletedJobError, agentDeletedUnrunnableJobError); err != nil {
			return fmt.Errorf("failed to fail unrunnable jobs: %w", err)
		}

		if _, err := tx.ExecContext(ctx, `
			UPDATE agent_certificates
			SET revoked_at = NOW(), revocation_reason = 'agent_deleted', updated_at = NOW()
			WHERE agent_id = $1 AND tenant_id = $2 AND revoked_at IS NULL`,
			agentID, tenantID); err != nil {
			return fmt.Errorf("failed to revoke agent certificates: %w", err)
		}

		return nil
	})
}

// agentDeletedJobError is what a tenant sees on a job that was mid-flight when
// its agent was removed. It names the cause rather than leaving a bare timeout,
// because the job did not fail on its own merits.
const agentDeletedJobError = "the agent assigned to this job was deleted before it reported a result"

// agentDeletedUnrunnableJobError covers the queued jobs that could not be handed
// back to the pool because they name no device — nothing else can resolve their
// target, so they die with the agent. Re-create them against a device to run them.
const agentDeletedUnrunnableJobError = "the agent assigned to this job was deleted, and the job names no device for another agent to pick up"

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
		       a.ip_address, a.last_heartbeat, a.created_at, a.updated_at
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
			&agent.Status, &agent.IPAddress, &agent.LastHeartbeat, &agent.CreatedAt, &agent.UpdatedAt,
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

	// Fill in the device's address from the device row before the job leaves
	// the platform. The in-cluster worker re-reads the device by device_id, so
	// creation paths were free to omit the address and one (the scheduler,
	// which forwards an operator-stored parameter map verbatim) still can. An
	// agent has no database and only gets this payload, so the address has to
	// be resolved here — the last point that can still see the device row.
	if job.Type == string(models.JobTypeDeviceInterrogation) {
		if err := s.enrichJobTarget(ctx, deviceJob.TenantID, job); err != nil {
			// Fail loudly rather than dispatching a job the agent cannot
			// execute. Without this the agent interrogates whatever an empty
			// address resolves to and reports a misleading connection or auth
			// error against its own host.
			msg := fmt.Sprintf("cannot dispatch job to agent: %v", err)
			if updErr := s.jobQueue.UpdateJobStatus(ctx, deviceJob.ID, models.JobStatusFailed, nil, &msg); updErr != nil {
				return nil, fmt.Errorf("%s (and failed to record it: %w)", msg, updErr)
			}
			return nil, nil
		}

		// Same shape of gap, one field over: the scheduler creates jobs without
		// credentials at all. The in-cluster worker re-reads them off the device
		// row (DeviceInterrogationService.getDeviceCredentials), so a
		// credential-less job runs fine there and the omission was invisible;
		// an agent gets only this payload and would authenticate with nothing.
		if err := s.resolveJobCredentials(ctx, deviceJob.TenantID, job); err != nil {
			msg := fmt.Sprintf("cannot dispatch job to agent: %v", err)
			if updErr := s.jobQueue.UpdateJobStatus(ctx, deviceJob.ID, models.JobStatusFailed, nil, &msg); updErr != nil {
				return nil, fmt.Errorf("%s (and failed to record it: %w)", msg, updErr)
			}
			return nil, nil
		}
	}

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

// ErrJobHasNoTarget reports that a device-interrogation job carries no address
// the agent could connect to.
var ErrJobHasNoTarget = errors.New("device has no hostname, IP address, or management URL")

// enrichJobTarget copies the device's addressing from the device row into the
// job parameters, and reports ErrJobHasNoTarget when there is nothing to copy.
//
// Parameters already on the job win: a scheduled job may deliberately target a
// specific address, and the job's own payload is the more specific intent.
//
// RLS: agent-outbound — keyed by agent id, tenant is the OUTPUT → bypass role,
// same as sealJobCredentials. The read is constrained to the job's own tenant
// so this path cannot hand one tenant's device address to another's agent
//
func (s *AgentService) enrichJobTarget(ctx context.Context, tenantID uuid.UUID, job *models.Job) error {
	if job.Parameters == nil {
		job.Parameters = map[string]interface{}{}
	}
	if job.DeviceID == nil {
		// Nothing to look up — the payload is all there is.
		if hasAnyTarget(job.Parameters) {
			return nil
		}
		return ErrJobHasNoTarget
	}

	var hostname, ipAddress, managementURL sql.NullString
	err := s.bypassDB.QueryRowContext(ctx,
		`SELECT hostname, ip_address, management_url
		   FROM devices
		  WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`,
		*job.DeviceID, tenantID,
	).Scan(&hostname, &ipAddress, &managementURL)
	if err == sql.ErrNoRows {
		return fmt.Errorf("device %s not found", *job.DeviceID)
	}
	if err != nil {
		return fmt.Errorf("failed to resolve device address: %w", err)
	}

	setIfAbsent(job.Parameters, "hostname", hostname)
	setIfAbsent(job.Parameters, "ip_address", ipAddress)
	setIfAbsent(job.Parameters, "management_url", managementURL)

	if !hasAnyTarget(job.Parameters) {
		return ErrJobHasNoTarget
	}
	return nil
}

// setIfAbsent writes a non-empty SQL string into params under key, leaving any
// value already present untouched.
func setIfAbsent(params map[string]interface{}, key string, v sql.NullString) {
	if !v.Valid || v.String == "" {
		return
	}
	if existing, ok := params[key].(string); ok && existing != "" {
		return
	}
	params[key] = v.String
}

// hasAnyTarget reports whether the parameters carry an address the agent could
// connect to.
func hasAnyTarget(params map[string]interface{}) bool {
	for _, key := range []string{"hostname", "ip_address", "management_url"} {
		if s, ok := params[key].(string); ok && s != "" {
			return true
		}
	}
	return false
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
	return s.UpdateHeartbeatWithHost(ctx, agentID, version, "", nil)
}

// UpdateHeartbeatWithHost additionally records what the agent reported about its
// own network position: its primary address and full address inventory.
//
// Both follow heartbeat semantics — empty means "not reported" and leaves the
// stored value alone, so an older agent that sends neither cannot blank what a
// newer one recorded. The address must come from the agent because the platform
// cannot observe it: NAT and ingress rewrite the connection source long before
// the request arrives.
func (s *AgentService) UpdateHeartbeatWithHost(ctx context.Context, agentID uuid.UUID, version, ipAddress string, addrs []sharednetwork.InterfaceAddress) error {
	query := `
		UPDATE device_agents
		SET last_heartbeat = $1, updated_at = $1,
		    version = COALESCE(NULLIF($3, ''), version),
		    ip_address = COALESCE(NULLIF($4, ''), ip_address)
		WHERE id = $2
	`

	_, err := s.bypassDB.ExecContext(ctx, query, time.Now(), agentID, version, ipAddress)
	if err != nil {
		return fmt.Errorf("failed to update heartbeat: %w", err)
	}

	if len(addrs) == 0 {
		return nil
	}

	// agent_addresses is RLS-scoped via its owner, and this is an agent-facing
	// call with no tenant in context, so the write runs on the bypass handle —
	// the same pattern as the heartbeat UPDATE above.
	tx, err := s.bypassDB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin address reconcile: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM agent_addresses WHERE device_agent_id = $1`, agentID); err != nil {
		return fmt.Errorf("failed to clear agent addresses: %w", err)
	}

	// At most one primary reaches the database (a partial unique index enforces
	// it), so keep the first rather than failing the whole set.
	seenPrimary := false
	for _, a := range addrs {
		if a.Address == "" || a.InterfaceName == "" {
			continue
		}
		isPrimary := a.IsPrimary && !seenPrimary
		if isPrimary {
			seenPrimary = true
		}

		var prefix interface{}
		if a.PrefixLength > 0 {
			prefix = a.PrefixLength
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO agent_addresses (device_agent_id, interface_name, address, prefix_length, is_primary)
			VALUES ($1, $2, $3::inet, $4, $5)
			ON CONFLICT DO NOTHING`,
			agentID, a.InterfaceName, a.Address, prefix, isPrimary); err != nil {
			return fmt.Errorf("failed to record agent address %s: %w", a.Address, err)
		}
	}

	return tx.Commit()
}
