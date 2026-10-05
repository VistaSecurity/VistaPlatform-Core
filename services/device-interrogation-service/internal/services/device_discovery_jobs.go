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
	"github.com/redis/go-redis/v9"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/security/credentials"
)

// Agent-routed Add device ( slice B).
//
// Add device identifies a device by logging in to it. Slice A does that
// synchronously, from the platform — which cannot reach a device on a segment
// only a deployed device agent can see. For that device the operator names the
// agent, and the identification runs THERE as a `device_discovery` job:
//
//	POST /devices/discoveries ─► device_jobs row (agent_id = the named agent,
//	                             credentials master-key encrypted, 15 min to claim)
//	agent poll (declares di.CapabilityDeviceDiscovery) ─► claim, seal creds for it
//	agent: Registry.Identify ─► IdentificationReport | typed failure code
//	SubmitJobResult ─► the device is created exactly as slice A creates it
//
// EXECUTOR RULE. The executor is fixed when the job is created, by the
// operator's choice, and never raced for:
//
//   - "Reach it from: the platform" is slice A's synchronous probe. Nothing is
//     queued, so the in-cluster PlatformAgentWorker never sees a discovery.
//   - "Reach it from: <agent>" creates the job ALREADY ASSIGNED to that agent.
//     Only that agent can claim it (agentDiscoveryClaimArm), and only once it
//     has declared the capability. valid_job_assignment refuses an unassigned
//     device_discovery row, so there is no row the worker and the agents could
//     both take.
//
// Why not an unassigned job any capable agent (or the worker) may claim, as
// device_interrogation is: whoever wins that race decides the outcome. A device
// reachable from one agent would read "unreachable" whenever the worker or a
// different agent claimed first, and the operator would be sent to debug
// routing that is fine. Knowing which executor attempted is the point of the
// typed outcome (addendum A); a race makes it an accident.

// DeviceDiscoveryClaimWindow is how long a queued discovery waits for its agent
// before it reads "not picked up". An agent polls every 30 seconds by default; fifteen
// minutes is an agent that is down, not one that is slow.
const DeviceDiscoveryClaimWindow = 15 * time.Minute

// deviceDiscoveryCapabilityTTL is how long an agent's declared capability is
// remembered after its last poll. Agents poll every 30 seconds by default, so this only
// lapses for an agent that has stopped polling.
const deviceDiscoveryCapabilityTTL = 10 * time.Minute

// deviceDiscoveryKeepSucceeded is how long a finished discovery stays in the
// list, so the page that queued it can see it land and refresh the devices.
const deviceDiscoveryKeepSucceeded = 10 * time.Minute

func agentCapabilityKey(agentID uuid.UUID) string {
	return "device_agent:capabilities:" + agentID.String()
}

// RecordAgentCapabilities remembers what an agent declared on its poll.
// Best-effort: a Redis failure costs only an "agent unavailable" answer at
// Add device until the next poll succeeds.
func (s *JobQueueService) RecordAgentCapabilities(ctx context.Context, agentID uuid.UUID, caps map[string]bool) {
	if s.redis == nil || !caps[di.CapabilityDeviceDiscovery] {
		return
	}
	if err := s.redis.Set(ctx, agentCapabilityKey(agentID), di.CapabilityDeviceDiscovery, deviceDiscoveryCapabilityTTL).Err(); err != nil {
		log.Printf("[JobQueueService] could not record capabilities of agent %s: %v", agentID, err)
	}
}

// agentDeclaredDiscovery reports whether the agent declared the
// device_discovery capability on a poll within deviceDiscoveryCapabilityTTL.
func agentDeclaredDiscovery(ctx context.Context, rdb *redis.Client, agentID uuid.UUID) (bool, error) {
	if rdb == nil {
		return false, nil
	}
	v, err := rdb.Get(ctx, agentCapabilityKey(agentID)).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return v == di.CapabilityDeviceDiscovery, nil
}

// Typed refusals of an agent-routed Add device. Codes are API vocabulary.
const (
	// CodeAgentNotFound: no such agent in this organization.
	CodeAgentNotFound = "agent_not_found"
	// CodeAgentUnavailable: the agent has not polled recently while declaring
	// it can discover devices — it is stopped, unreachable, or older than this
	// platform.
	CodeAgentUnavailable = "agent_unavailable"
	// CodeNotPickedUp: the agent never claimed the job inside the window.
	CodeNotPickedUp = "not_picked_up"
	// CodeAgentNoResult: the agent claimed the job and never reported back.
	CodeAgentNoResult = "agent_no_result"
	// CodeCreateFailed: the agent identified the device but recording it
	// failed on the platform.
	CodeCreateFailed = "create_failed"
)

// ErrDeviceDiscoveryNotFound is a discovery id the tenant does not own.
var ErrDeviceDiscoveryNotFound = errors.New("device discovery not found")

// ErrDeviceDiscoveryNotRetryable is a discovery still queued, running or done.
var ErrDeviceDiscoveryNotRetryable = errors.New("only a failed discovery, or one no agent picked up, can be retried")

// agentDiscoveryMessages is the tenant-facing copy for a discovery an AGENT
// ran. Where it differs from the platform's copy it is because the platform's
// says "from the platform".
var agentDiscoveryMessages = map[string]string{
	string(di.IdentifyConnectionFailed): "The agent couldn't connect to the management address. Check the address and port, and that this agent can reach it.",
	CodeAgentUnavailable:                "This agent hasn't checked in as able to discover devices in the last few minutes. Check that it is running and up to date.",
	CodeAgentNotFound:                   "That agent isn't registered to this organization.",
	CodeNotPickedUp:                     "The agent didn't pick this up within 15 minutes. Check that it is running and up to date, then retry.",
	CodeAgentNoResult:                   "The agent started but never reported back. Check the agent, then retry.",
	CodeCreateFailed:                    "The device was identified, but it couldn't be recorded. Retry, or add it by hand.",
	"cancelled":                         "This discovery was cancelled.",
}

// AgentDiscoveryMessage is the fixed tenant-facing copy for code on the
// agent-routed path.
func AgentDiscoveryMessage(code string) string {
	if m, ok := agentDiscoveryMessages[code]; ok {
		return m
	}
	if m := DiscoveryMessage(code); m != "" {
		return m
	}
	return discoveryMessages[di.IdentifyFailed]
}

// DeviceDiscoveryRequestError is a refusal at enqueue time, safe to return.
type DeviceDiscoveryRequestError struct {
	Code    string
	Message string
}

func (e *DeviceDiscoveryRequestError) Error() string { return e.Code + ": " + e.Message }

// DeviceDiscovery is one agent-routed Add device as the Devices page shows it:
// a row that is not a device yet. It never carries credentials.
type DeviceDiscovery struct {
	ID uuid.UUID `json:"id"`
	// Status is the row's state: queued, running, succeeded, held_for_review,
	// failed or not_picked_up.
	Status        string     `json:"status"`
	DeviceType    string     `json:"device_type"`
	ManagementURL string     `json:"management_url"`
	AgentID       uuid.UUID  `json:"agent_id"`
	AgentName     *string    `json:"agent_name"`
	ErrorCode     *string    `json:"error_code,omitempty"`
	Message       *string    `json:"message,omitempty"`
	AssetID       *uuid.UUID `json:"asset_id,omitempty"`
	ObservationID *string    `json:"observation_id,omitempty"`
	ProposalID    *string    `json:"proposal_id,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
}

// Discovery statuses.
const (
	DiscoveryQueued        = "queued"
	DiscoveryRunning       = "running"
	DiscoverySucceeded     = "succeeded"
	DiscoveryHeldForReview = "held_for_review"
	DiscoveryFailed        = "failed"
	DiscoveryNotPickedUp   = "not_picked_up"
)

// EnqueueDeviceDiscoveryRequest is the operator's four fields plus the agent.
type EnqueueDeviceDiscoveryRequest struct {
	TenantID              uuid.UUID
	AgentID               uuid.UUID
	DeviceType            string
	ManagementURL         string
	Username              string
	Password              string
	TLSInsecureSkipVerify bool
}

// DeviceDiscoveryJobs owns agent-routed Add device: queueing it, listing it
// for the Devices page, retrying and dismissing it.
type DeviceDiscoveryJobs struct {
	db        *sql.DB
	queue     *JobQueueService
	redis     *redis.Client
	masterKey string
	registry  *di.Registry
	now       func() time.Time
}

// NewDeviceDiscoveryJobs builds the service. db is the RLS-scoped connection;
// every read and write here is tenant-scoped.
func NewDeviceDiscoveryJobs(db, bypassDB *sql.DB, rdb *redis.Client, masterKey string) *DeviceDiscoveryJobs {
	return &DeviceDiscoveryJobs{
		db:        db,
		queue:     NewJobQueueService(db, bypassDB, rdb),
		redis:     rdb,
		masterKey: masterKey,
		registry:  di.NewRegistry(),
		now:       time.Now,
	}
}

// Enqueue validates and queues one discovery on the named agent.
func (s *DeviceDiscoveryJobs) Enqueue(ctx context.Context, req EnqueueDeviceDiscoveryRequest) (*DeviceDiscovery, error) {
	req.ManagementURL = strings.TrimSpace(req.ManagementURL)
	if !s.registry.CanIdentify(req.DeviceType) {
		return nil, &DeviceDiscoveryRequestError{Code: string(di.IdentifyNotSupported), Message: DiscoveryMessage(string(di.IdentifyNotSupported))}
	}
	// The address is stored in the job's parameters and shown on the row, so
	// a URL carrying credentials, a query or a fragment is refused here rather
	// than kept. DisplayAddress strips exactly those; a clean address survives
	// it unchanged.
	if req.ManagementURL == "" || di.DisplayAddress(req.ManagementURL) != req.ManagementURL {
		return nil, &DeviceDiscoveryRequestError{Code: string(di.IdentifyInvalidTarget), Message: DiscoveryMessage(string(di.IdentifyInvalidTarget))}
	}
	if s.masterKey == "" {
		// A disabled cipher would store the password in the clear.
		return nil, errors.New("encryption master key not configured")
	}

	agentName, err := s.tenantAgent(ctx, req.TenantID, req.AgentID)
	if err != nil {
		return nil, err
	}
	declared, err := agentDeclaredDiscovery(ctx, s.redis, req.AgentID)
	if err != nil {
		log.Printf("[DeviceDiscoveryJobs] capability lookup for agent %s failed: %v", req.AgentID, err)
	}
	if !declared {
		return nil, &DeviceDiscoveryRequestError{Code: CodeAgentUnavailable, Message: AgentDiscoveryMessage(CodeAgentUnavailable)}
	}

	skip := EffectiveInsecureSkipVerify(req.DeviceType, req.TLSInsecureSkipVerify)
	cipher, err := credentials.NewCipher("job_credentials", s.masterKey, credentials.Policy{Fields: sensitiveCredentialFields})
	if err != nil {
		return nil, err
	}
	sealedPassword, err := cipher.EncryptValue(req.Password)
	if err != nil {
		return nil, err
	}
	expires := s.now().Add(DeviceDiscoveryClaimWindow)
	agentID := req.AgentID
	job, err := s.queue.CreateJob(ctx, models.CreateDeviceJobRequest{
		TenantID: req.TenantID,
		JobType:  models.JobTypeDeviceDiscovery,
		AgentID:  &agentID,
		// The master-encrypted shape NormalizeJobCredentials opens at hand-off,
		// where the claiming agent's key seals it — the same path an
		// interrogation's stored credentials take.
		Credentials: map[string]interface{}{
			"username":             req.Username,
			"password":             sealedPassword,
			"device_type":          req.DeviceType,
			"management_url":       req.ManagementURL,
			"insecure_skip_verify": skip,
			masterEncryptedFlag:    true,
		},
		Parameters: map[string]interface{}{
			"device_type":          req.DeviceType,
			"management_url":       req.ManagementURL,
			"insecure_skip_verify": skip,
		},
		ExpiresAt: &expires,
	})
	if err != nil {
		return nil, err
	}
	d := &DeviceDiscovery{
		ID: job.ID, Status: DiscoveryQueued, DeviceType: req.DeviceType,
		ManagementURL: req.ManagementURL, AgentID: req.AgentID, AgentName: agentName,
		CreatedAt: job.CreatedAt, ExpiresAt: job.ExpiresAt,
	}
	return d, nil
}

// tenantAgent resolves an agent in the tenant (RLS) and returns its name.
func (s *DeviceDiscoveryJobs) tenantAgent(ctx context.Context, tenantID, agentID uuid.UUID) (*string, error) {
	var name sql.NullString
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT name FROM device_agents WHERE id=$1 AND tenant_id=$2 AND deleted_at IS NULL`,
			agentID, tenantID).Scan(&name)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &DeviceDiscoveryRequestError{Code: CodeAgentNotFound, Message: AgentDiscoveryMessage(CodeAgentNotFound)}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to resolve agent: %w", err)
	}
	if name.Valid {
		return &name.String, nil
	}
	return nil, nil
}

const deviceDiscoveryColumns = `j.id, j.status, j.parameters, j.results, j.agent_id, a.name,
	j.created_at, j.started_at, j.completed_at, j.expires_at`

// List returns the tenant's recent agent-routed discoveries, newest first:
// everything not dismissed and not long since finished. Never credentials —
// the column is not selected.
func (s *DeviceDiscoveryJobs) List(ctx context.Context, tenantID uuid.UUID) ([]DeviceDiscovery, error) {
	out := []DeviceDiscovery{}
	now := s.now()
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT `+deviceDiscoveryColumns+`
			FROM device_jobs j LEFT JOIN device_agents a ON a.id=j.agent_id AND a.tenant_id=j.tenant_id
			WHERE j.tenant_id=$1 AND j.job_type='device_discovery' AND j.deleted_at IS NULL
			  AND j.created_at > $2
			  AND NOT (j.status='completed' AND j.completed_at < $3)
			ORDER BY j.created_at DESC, j.id LIMIT 50`,
			tenantID, now.Add(-7*24*time.Hour), now.Add(-deviceDiscoveryKeepSucceeded))
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			d, err := scanDeviceDiscovery(rows, now)
			if err != nil {
				return err
			}
			out = append(out, *d)
		}
		return rows.Err()
	})
	return out, err
}

// Get returns one discovery the tenant owns.
func (s *DeviceDiscoveryJobs) Get(ctx context.Context, tenantID, id uuid.UUID) (*DeviceDiscovery, error) {
	var d *DeviceDiscovery
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `SELECT `+deviceDiscoveryColumns+`
			FROM device_jobs j LEFT JOIN device_agents a ON a.id=j.agent_id AND a.tenant_id=j.tenant_id
			WHERE j.tenant_id=$1 AND j.id=$2 AND j.job_type='device_discovery' AND j.deleted_at IS NULL`, tenantID, id)
		var err error
		d, err = scanDeviceDiscovery(row, s.now())
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDeviceDiscoveryNotFound
	}
	return d, err
}

// Retry re-queues a failed or unclaimed discovery on the same agent, with the
// credentials it was queued with. The agent's capability is checked again: a
// retry onto an agent that is still down would only fail the same way.
func (s *DeviceDiscoveryJobs) Retry(ctx context.Context, tenantID, id uuid.UUID) (*DeviceDiscovery, error) {
	current, err := s.Get(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if current.Status != DiscoveryFailed && current.Status != DiscoveryNotPickedUp {
		return nil, ErrDeviceDiscoveryNotRetryable
	}
	if current.ErrorCode != nil && *current.ErrorCode == CodeAgentNoResult {
		// The job is still in_progress on the agent's side; it is failed only
		// in how it is shown. Retrying it resets it to pending below.
		log.Printf("[DeviceDiscoveryJobs] retrying discovery %s whose agent never reported back", id)
	}
	declared, capErr := agentDeclaredDiscovery(ctx, s.redis, current.AgentID)
	if capErr != nil {
		log.Printf("[DeviceDiscoveryJobs] capability lookup for agent %s failed: %v", current.AgentID, capErr)
	}
	if !declared {
		return nil, &DeviceDiscoveryRequestError{Code: CodeAgentUnavailable, Message: AgentDiscoveryMessage(CodeAgentUnavailable)}
	}
	expires := s.now().Add(DeviceDiscoveryClaimWindow)
	err = shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE device_jobs
			SET status='pending', results=NULL, error_message=NULL, assigned_at=NULL,
			    started_at=NULL, completed_at=NULL, expires_at=$3, updated_at=now()
			WHERE tenant_id=$1 AND id=$2 AND job_type='device_discovery' AND deleted_at IS NULL
			  AND status IN ('failed','cancelled','pending','in_progress','assigned')`, tenantID, id, expires)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrDeviceDiscoveryNotFound
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, tenantID, id)
}

// Dismiss removes a discovery from the list and drops its stored credentials.
// An agent still running it then files its result against a job that no
// longer exists, which SubmitJobResult refuses.
func (s *DeviceDiscoveryJobs) Dismiss(ctx context.Context, tenantID, id uuid.UUID) error {
	return shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE device_jobs
			SET deleted_at=now(), credentials='{}'::jsonb, updated_at=now()
			WHERE tenant_id=$1 AND id=$2 AND job_type='device_discovery' AND deleted_at IS NULL`, tenantID, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrDeviceDiscoveryNotFound
		}
		return nil
	})
}

// dropDiscoveryCredentials empties a finished discovery's stored credentials
// (the master-key ciphertext Enqueue wrote with credentials.Cipher). Keyed by
// job id on the agent-outbound path, so it runs on the bypass role.
func dropDiscoveryCredentials(ctx context.Context, bypassDB *sql.DB, tenantID, jobID uuid.UUID) error {
	_, err := bypassDB.ExecContext(ctx,
		`UPDATE device_jobs SET credentials='{}'::jsonb, updated_at=now()
		  WHERE id=$1 AND tenant_id=$2 AND job_type='device_discovery'`, jobID, tenantID)
	return err
}

// storedDiscoveryResult is the part of device_jobs.results a discovery reads.
type storedDiscoveryResult struct {
	FailureCode string                 `json:"failure_code"`
	Metadata    map[string]interface{} `json:"metadata"`
}

func scanDeviceDiscovery(row rowScanner, now time.Time) (*DeviceDiscovery, error) {
	var (
		d                  DeviceDiscovery
		status             string
		params, results    []byte
		agentID            uuid.NullUUID
		agentName          sql.NullString
		started, completed sql.NullTime
		expires            sql.NullTime
	)
	if err := row.Scan(&d.ID, &status, &params, &results, &agentID, &agentName,
		&d.CreatedAt, &started, &completed, &expires); err != nil {
		return nil, err
	}
	var p struct {
		DeviceType    string `json:"device_type"`
		ManagementURL string `json:"management_url"`
	}
	_ = json.Unmarshal(params, &p)
	d.DeviceType = p.DeviceType
	d.ManagementURL = di.DisplayAddress(p.ManagementURL)
	d.AgentID = agentID.UUID
	if agentName.Valid {
		d.AgentName = &agentName.String
	}
	if started.Valid {
		d.StartedAt = &started.Time
	}
	if completed.Valid {
		d.CompletedAt = &completed.Time
	}
	if expires.Valid {
		d.ExpiresAt = &expires.Time
	}
	var r storedDiscoveryResult
	if len(results) > 0 {
		_ = json.Unmarshal(results, &r)
	}
	fail := func(code string) {
		d.Status = DiscoveryFailed
		msg := AgentDiscoveryMessage(code)
		d.ErrorCode, d.Message = &code, &msg
	}
	switch models.DeviceJobStatus(status) {
	case models.JobStatusPending:
		if d.ExpiresAt != nil && !d.ExpiresAt.After(now) {
			code := CodeNotPickedUp
			msg := AgentDiscoveryMessage(code)
			d.Status, d.ErrorCode, d.Message = DiscoveryNotPickedUp, &code, &msg
		} else {
			d.Status = DiscoveryQueued
		}
	case models.JobStatusAssigned, models.JobStatusInProgress:
		ref := d.StartedAt
		if ref == nil {
			ref = &d.CreatedAt
		}
		if now.Sub(*ref) > DeviceDiscoveryClaimWindow {
			fail(CodeAgentNoResult)
		} else {
			d.Status = DiscoveryRunning
		}
	case models.JobStatusCompleted:
		d.Status = DiscoverySucceeded
		if s, ok := r.Metadata["asset_id"].(string); ok {
			if id, err := uuid.Parse(s); err == nil {
				d.AssetID = &id
			}
		}
		if s, ok := r.Metadata["observation_id"].(string); ok && s != "" {
			d.Status, d.ObservationID = DiscoveryHeldForReview, &s
		}
		if s, ok := r.Metadata["proposal_id"].(string); ok && s != "" {
			d.Status, d.ProposalID = DiscoveryHeldForReview, &s
		}
	case models.JobStatusCancelled:
		fail("cancelled")
	default:
		code := r.FailureCode
		if code == "" {
			code = string(di.IdentifyFailed)
		}
		fail(code)
	}
	return &d, nil
}

// ---- completion -------------------------------------------------------------

// discoveredDeviceCreator is the slice of DeviceService a completed discovery
// writes through — the same two calls Add device makes.
type discoveredDeviceCreator interface {
	CreateDevice(ctx context.Context, tenantID uuid.UUID, req models.CreateDeviceRequest) (*models.Device, error)
	PinSSHHostKeyIfUnset(ctx context.Context, tenantID, deviceID uuid.UUID, fingerprint, keyType string) (bool, error)
}

// NewDiscoveredDeviceRequest is the device Add device records for an
// identified device. Shared by the synchronous probe (handlers) and the
// agent-routed job (completeDeviceDiscovery), so the two cannot drift on what
// a discovered device looks like.
func NewDiscoveredDeviceRequest(deviceType, managementURL, username, password string, skipVerify bool, info *DiscoveredDeviceInfo, now time.Time) models.CreateDeviceRequest {
	req := models.CreateDeviceRequest{
		DeviceType:    deviceType,
		ManagementURL: &managementURL,
		Username:      &username,
		Password:      &password,
		// Persisted as given. The probe just connected under this setting, so
		// the first interrogation must run under it too — a device probed over
		// its self-signed certificate and saved with verification on fails on
		// the very certificate discovery accepted.
		TLSInsecureSkipVerify: &skipVerify,
		DiscoveryMethod:       "device_interrogation",
		Metadata:              map[string]interface{}{},
		Tags:                  map[string]interface{}{},
	}
	info.ApplyTo(&req, IsSSHManagedDeviceType(deviceType))
	req.Metadata["auto_discovered"] = true
	req.Metadata["discovery_timestamp"] = now.UTC().Format(time.RFC3339)
	return req
}

// DiscoveredInfoFromReport maps an agent's report onto what ApplyTo reads.
func DiscoveredInfoFromReport(r *di.IdentificationReport) *DiscoveredDeviceInfo {
	return &DiscoveredDeviceInfo{
		Vendor: r.Vendor, Model: r.Model, SerialNumber: r.SerialNumber,
		Hostname: r.Hostname, IPAddress: r.IPAddress, FirmwareVersion: r.FirmwareVersion,
		MacAddress: r.MACAddress, TargetHost: r.TargetHost, TargetPort: r.TargetPort,
		SSHHostKeyFingerprint: r.SSHHostKeyFingerprint, SSHHostKeyType: r.SSHHostKeyType,
	}
}

// projectDiscoveryResult rebuilds an agent's device_discovery result from its
// allowlisted parts only. Whatever else the agent sent — assets, facts,
// metadata, free text — is dropped, not stored: a discovery's whole answer is
// the identification or the typed reason it failed.
func projectDiscoveryResult(in *models.JobResult) *models.JobResult {
	out := &models.JobResult{JobID: in.JobID, CompletedAt: in.CompletedAt}
	if in.Success {
		report := in.Identification.Sanitized()
		if report.IdentifiesSomething() {
			out.Success = true
			out.Identification = report
			return out
		}
		out.FailureCode = string(di.IdentifyUnsupportedResponse)
	} else {
		out.FailureCode = in.FailureCode
		if !di.KnownIdentifyFailure(out.FailureCode) {
			out.FailureCode = string(di.IdentifyFailed)
		}
	}
	out.Error = AgentDiscoveryMessage(out.FailureCode)
	return out
}

// completeDeviceDiscovery turns an agent's discovery result into the device,
// exactly as the synchronous Add device does, and returns the result to store
// and the job status it decides.
//
// The stored result is the projection plus where the device went — never the
// credentials, which are read from the job, used, and dropped.
func completeDeviceDiscovery(ctx context.Context, creator discoveredDeviceCreator, job *models.DeviceJob, received *models.JobResult, masterKey string) (*models.JobResult, models.DeviceJobStatus) {
	result := projectDiscoveryResult(received)
	if !result.Success {
		return result, models.JobStatusFailed
	}
	failCreate := func(cause error) (*models.JobResult, models.DeviceJobStatus) {
		log.Printf("[device_discovery] job %s identified a device but could not record it: %v", job.ID, cause)
		return &models.JobResult{JobID: result.JobID, CompletedAt: result.CompletedAt, Identification: result.Identification,
			FailureCode: CodeCreateFailed, Error: AgentDiscoveryMessage(CodeCreateFailed)}, models.JobStatusFailed
	}

	plain, err := NormalizeJobCredentials(job.Credentials, masterKey)
	if err != nil {
		return failCreate(fmt.Errorf("open stored credentials: %w", err))
	}
	str := func(k string) string { v, _ := plain[k].(string); return v }
	skip, _ := plain["insecure_skip_verify"].(bool)
	deviceType := str("device_type")
	req := NewDiscoveredDeviceRequest(deviceType, str("management_url"), str("username"), str("password"),
		EffectiveInsecureSkipVerify(deviceType, skip), DiscoveredInfoFromReport(result.Identification), time.Now())
	if job.AgentID != nil {
		req.Metadata["discovered_by_agent_id"] = job.AgentID.String()
	}

	result.Metadata = map[string]interface{}{"device_type": deviceType}
	device, err := creator.CreateDevice(ctx, job.TenantID, req)
	if err != nil {
		var retained *identity.RetainedObservation
		var contested *DeviceIdentityContestedError
		switch {
		case errors.As(err, &retained):
			result.Metadata["outcome"] = "retained"
			result.Metadata["observation_id"] = retained.Result.ObservationID
			if retained.Result.ProposalID != "" {
				result.Metadata["proposal_id"] = retained.Result.ProposalID
			}
			return result, models.JobStatusCompleted
		case errors.As(err, &contested):
			result.Metadata["outcome"] = "contested"
			if contested.ProposalID != "" {
				result.Metadata["proposal_id"] = contested.ProposalID
			}
			return result, models.JobStatusCompleted
		}
		return failCreate(err)
	}
	result.Metadata["outcome"] = "created"
	result.Metadata["asset_id"] = device.ID.String()
	if fp := result.Identification.SSHHostKeyFingerprint; fp != "" {
		if _, pinErr := creator.PinSSHHostKeyIfUnset(ctx, job.TenantID, device.ID, fp, result.Identification.SSHHostKeyType); pinErr != nil {
			log.Printf("[device_discovery] created %s but could not pin its SSH host key; the first interrogation will enrol it: %v", device.ID, pinErr)
		}
	}
	return result, models.JobStatusCompleted
}
