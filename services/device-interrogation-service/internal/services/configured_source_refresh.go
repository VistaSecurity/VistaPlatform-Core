package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	database "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// SourceRefreshRequest identifies one source-first enrichment attempt. Evidence
// is fingerprinted for retry consistency; source selection always reads the
// tenant's durable observation, never a caller-supplied management address.
type SourceRefreshRequest struct {
	RequestID     uuid.UUID            `json:"request_id"`
	TenantID      uuid.UUID            `json:"tenant_id"`
	ObservationID uuid.UUID            `json:"observation_id"`
	Evidence      identity.Observation `json:"evidence"`
}
type SourceRefreshStatus struct {
	JobID  uuid.UUID `json:"job_id"`
	State  string    `json:"state"`
	Reason string    `json:"reason,omitempty"`
}

var ErrRefreshConflict = errors.New("refresh request evidence changed")
var ErrRefreshNotFound = errors.New("refresh observation or request not found")
var ErrRefreshCredentialsUnavailable = errors.New("configured credentials unavailable")

// DeviceJobPreparer reuses the interactive interrogation credential/profile
// builder. It may open short tenant transactions, so it runs outside a data tx.
type DeviceJobPreparer func(context.Context, uuid.UUID, uuid.UUID) (models.CreateDeviceJobRequest, error)
type ConfiguredSourceRefresh struct {
	db      *sql.DB
	queue   *JobQueueService
	devices *DeviceService
	prepare DeviceJobPreparer
}

func NewConfiguredSourceRefresh(db *sql.DB, queue *JobQueueService, devices *DeviceService, prepare DeviceJobPreparer) *ConfiguredSourceRefresh {
	return &ConfiguredSourceRefresh{db: db, queue: queue, devices: devices, prepare: prepare}
}
func (s *ConfiguredSourceRefresh) Refresh(ctx context.Context, req SourceRefreshRequest) (SourceRefreshStatus, error) {
	out := SourceRefreshStatus{JobID: req.RequestID}
	if req.RequestID == uuid.Nil || req.TenantID == uuid.Nil || req.ObservationID == uuid.Nil || req.Evidence.TenantID != req.TenantID.String() {
		return out, ErrRefreshConflict
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return out, err
	}
	sum := sha256.Sum256(raw)
	fingerprint := hex.EncodeToString(sum[:])
	// The dedicated control pool avoids holding a scarce data connection while
	// credentials are read or a worker finishes. Serializes replicas and retries.
	err = database.WithSessionAdvisoryLocks(ctx, s.db, []database.SessionAdvisoryLock{{Key: "source-refresh:" + req.TenantID.String()}}, func() error {
		var observation identity.Observation
		var linked uuid.NullUUID
		var existing bool
		var attempts int
		var next time.Time
		err := database.WithTenantTx(ctx, s.db, req.TenantID, func(tx *sql.Tx) error {
			var evidence []byte
			if err := tx.QueryRowContext(ctx, `SELECT evidence,asset_id FROM identity_observations WHERE tenant_id=$1 AND id=$2 AND state NOT IN ('dismissed','expired','conflict')`, req.TenantID, req.ObservationID).Scan(&evidence, &linked); errors.Is(err, sql.ErrNoRows) {
				return ErrRefreshNotFound
			} else if err != nil {
				return err
			}
			if err := json.Unmarshal(evidence, &observation); err != nil {
				return err
			}
			var stored string
			err := tx.QueryRowContext(ctx, `SELECT r.fingerprint,r.attempts,greatest(r.next_attempt_at,COALESCE(j.completed_at,r.created_at)+interval '5 minutes') FROM identity_source_refreshes r LEFT JOIN device_jobs j ON j.tenant_id=r.tenant_id AND j.id=r.device_job_id WHERE r.tenant_id=$1 AND r.id=$2`, req.TenantID, req.RequestID).Scan(&stored, &attempts, &next)
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			if stored != fingerprint {
				return ErrRefreshConflict
			}
			existing = true
			var errStatus error
			out, errStatus = s.statusTx(ctx, tx, req.TenantID, req.RequestID)
			return errStatus
		})
		if err != nil {
			return err
		}
		if existing && (out.State == "queued" || out.State == "running" || out.State == "completed" || out.Reason == "executor_did_not_claim_job" || time.Now().Before(next)) {
			return nil
		}
		plan, reason, err := s.plan(ctx, req.TenantID, req.ObservationID, observation, linked)
		if err != nil {
			return err
		}
		out.State = "queued"
		out.Reason = ""
		if reason != "" {
			out.State = "blocked"
			out.Reason = reason
			if reason == "no_configured_source" {
				out.State = "completed"
			}
		}
		var job *models.DeviceJob
		err = database.WithTenantTx(ctx, s.db, req.TenantID, func(tx *sql.Tx) error {
			// Lock current policy before asset or work rows. Credential preparation
			// above does not authorize a later dispatch after a concurrent pause.
			if _, err := lockSourceRefreshPolicy(ctx, tx, req.TenantID); err != nil {
				return err
			}
			// Recheck the observation remains eligible after preparing credentials.
			var eligible uuid.UUID
			err := tx.QueryRowContext(ctx, `SELECT id FROM identity_observations WHERE tenant_id=$1 AND id=$2 AND state NOT IN ('dismissed','expired','conflict') FOR SHARE`, req.TenantID, req.ObservationID).Scan(&eligible)
			if errors.Is(err, sql.ErrNoRows) {
				return ErrRefreshNotFound
			}
			if err != nil {
				return err
			}

			var child *uuid.UUID
			if out.State == "queued" {
				plan.Parameters["identity_refresh_request_id"] = req.RequestID.String()
				candidate := &models.DeviceJob{TenantID: req.TenantID, JobType: plan.JobType, AssetID: plan.AssetID, AgentID: plan.AgentID, IntegrationID: plan.IntegrationID, Parameters: plan.Parameters}
				if err := s.queue.validateRefreshClaimTx(ctx, tx, candidate, false); err != nil {
					// Database/transaction failures remain retryable. Controlled
					// authorization failures retain a blocked logical receipt.
					if !errors.Is(err, errSourceRefreshDenied) && !errors.Is(err, errSourceRefreshPaused) {
						return err
					}
					out.State = "blocked"
					out.Reason = "configured_source_policy_or_executor_changed"
					if errors.Is(err, errSourceRefreshPaused) {
						out.Reason = "enrichment_paused"
					}
				}
			}
			if out.State == "queued" {
				plan.Parameters["identity_refresh_request_id"] = req.RequestID.String()
				var err error
				// Share one configured-source refresh across observations. The
				// request receipt is independent of the executor work receipt.
				sourceParameters := make(map[string]interface{}, len(plan.Parameters))
				for key, value := range plan.Parameters {
					if key != "identity_refresh_request_id" {
						sourceParameters[key] = value
					}
				}
				sourceRaw, err := json.Marshal(struct {
					Asset, Agent, Integration *uuid.UUID
					Type                      models.DeviceJobType
					Parameters                map[string]interface{}
				}{plan.AssetID, plan.AgentID, plan.IntegrationID, plan.JobType, sourceParameters})
				if err != nil {
					return err
				}
				sourceSum := sha256.Sum256(sourceRaw)
				sourceKey := hex.EncodeToString(sourceSum[:])
				plan.Parameters["identity_refresh_source_key"] = sourceKey
				var reusable uuid.UUID
				err = tx.QueryRowContext(ctx, `SELECT id FROM device_jobs WHERE tenant_id=$1 AND parameters?'identity_refresh_source_key' AND parameters->>'identity_refresh_source_key'=$2 AND deleted_at IS NULL
                  AND (status IN ('assigned','in_progress') OR status='pending' AND (expires_at IS NULL OR expires_at>now())
                    OR status='completed' AND completed_at>now()-interval '5 minutes')
                  ORDER BY created_at DESC LIMIT 1`, req.TenantID, sourceKey).Scan(&reusable)
				if err == nil {
					child = &reusable
				} else if !errors.Is(err, sql.ErrNoRows) {
					return err
				} else {
					job, err = s.queue.createJobTx(ctx, tx, uuid.New(), plan)
					if err != nil {
						return err
					}
					child = &job.ID
				}
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO identity_source_refreshes(tenant_id,id,observation_id,fingerprint,state,reason,device_job_id,attempts,next_attempt_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,now()+interval '5 minutes')
    ON CONFLICT(tenant_id,id) DO UPDATE SET state=EXCLUDED.state,reason=EXCLUDED.reason,device_job_id=EXCLUDED.device_job_id,attempts=EXCLUDED.attempts,next_attempt_at=EXCLUDED.next_attempt_at,updated_at=now()`, req.TenantID, req.RequestID, req.ObservationID, fingerprint, out.State, out.Reason, child, attempts+1)
			return err
		})
		if err != nil {
			return err
		}
		if job != nil {
			s.queue.publishJob(job)
		}
		return nil
	})
	return out, err
}
func (s *ConfiguredSourceRefresh) Status(ctx context.Context, tenant, id uuid.UUID) (SourceRefreshStatus, error) {
	var out SourceRefreshStatus
	err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error { var err error; out, err = s.statusTx(ctx, tx, tenant, id); return err })
	return out, err
}
func (s *ConfiguredSourceRefresh) statusTx(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID) (SourceRefreshStatus, error) {
	out := SourceRefreshStatus{JobID: id}
	var child uuid.NullUUID
	var status sql.NullString
	var result []byte
	var expired bool
	var executor string
	err := tx.QueryRowContext(ctx, `SELECT r.state,r.reason,r.device_job_id,j.status,j.results,COALESCE(j.expires_at<now() AND j.status='pending',false),COALESCE(j.parameters->>'identity_refresh_executor','')
 FROM identity_source_refreshes r LEFT JOIN device_jobs j ON j.tenant_id=r.tenant_id AND j.id=r.device_job_id
 WHERE r.tenant_id=$1 AND r.id=$2`, tenant, id).Scan(&out.State, &out.Reason, &child, &status, &result, &expired, &executor)
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrRefreshNotFound
	}
	if err != nil {
		return out, err
	}
	if !child.Valid {
		return out, nil
	}
	switch status.String {
	case "pending":
		out.State = "queued"
		if expired {
			out.State = "blocked"
			out.Reason = "executor_did_not_claim_job"
		}
	case "assigned", "in_progress":
		out.State = "running"
	case "failed", "cancelled":
		out.State = "failed"
		out.Reason = "configured_source_job_failed"
	case "completed":
		var payload struct {
			Metadata struct {
				Materialized bool `json:"identity_refresh_materialized"`
			} `json:"metadata"`
			Processing struct {
				DiscoveryID       string `json:"discovery_job_id"`
				Finished          string `json:"processing_finished_at"`
				Fully             bool   `json:"fully_materialized"`
				Fatal             string `json:"fatal"`
				TargetsFailed     int    `json:"targets_failed"`
				FindingsFailed    int    `json:"findings_failed"`
				DiscoveriesFailed int    `json:"discoveries_failed"`
			} `json:"processing"`
		}
		if len(result) > 0 {
			if err := json.Unmarshal(result, &payload); err != nil {
				return out, err
			}
		}
		out.State = "running"
		out.Reason = "waiting_for_result_ingestion"
		if payload.Processing.Finished != "" {
			// Platform interrogation writes its discovery rows directly. Its
			// empty returned Assets list is intentional, not a failed ingest.
			direct := executor == "platform" && payload.Metadata.Materialized && payload.Processing.TargetsFailed == 0 && payload.Processing.FindingsFailed == 0 && payload.Processing.DiscoveriesFailed == 0
			if (!payload.Processing.Fully && !direct) || payload.Processing.Fatal != "" {
				out.State = "failed"
				out.Reason = "configured_source_ingestion_failed"
			} else {
				var pending bool
				if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sensor_discoveries WHERE tenant_id=$1 AND batch_id=$2 AND processed_at IS NULL)`, tenant, payload.Processing.DiscoveryID).Scan(&pending); err != nil {
					return out, err
				}
				if !pending {
					out.State = "completed"
					out.Reason = "source_results_ingested"
				}
			}
		}
	default:
		out.State = "failed"
		out.Reason = "configured_source_job_unavailable"
	}
	return out, nil
}

// plan follows durable provenance or an already linked managed asset. A weak
// name cannot select an arbitrary tenant integration, credential or executor.
func (s *ConfiguredSourceRefresh) plan(ctx context.Context, tenant, observationID uuid.UUID, obs identity.Observation, linked uuid.NullUUID) (models.CreateDeviceJobRequest, string, error) {
	plan := models.CreateDeviceJobRequest{TenantID: tenant, Parameters: map[string]interface{}{}}
	if strings.HasPrefix(obs.Source.Ref, "cloud:") {
		return s.planCloud(ctx, tenant, observationID, obs, linked)
	}
	var asset, agent, integration uuid.NullUUID
	var prior bool
	err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		if strings.HasPrefix(obs.Source.Ref, "interrogation:") {
			id, err := uuid.Parse(strings.TrimPrefix(obs.Source.Ref, "interrogation:"))
			if err != nil {
				return nil
			}
			err = tx.QueryRowContext(ctx, `SELECT asset_id,agent_id,integration_id FROM device_jobs WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL`, tenant, id).Scan(&asset, &agent, &integration)
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			prior = true
		}
		if !asset.Valid && linked.Valid {
			var managed bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM asset_management WHERE tenant_id=$1 AND asset_id=$2)`, tenant, linked.UUID).Scan(&managed); err != nil {
				return err
			}
			if managed {
				asset = linked
			}
		}
		if asset.Valid && !prior {
			err := tx.QueryRowContext(ctx, `SELECT agent_id,integration_id FROM device_jobs WHERE tenant_id=$1 AND asset_id=$2 AND status='completed' AND deleted_at IS NULL ORDER BY completed_at DESC LIMIT 1`, tenant, asset.UUID).Scan(&agent, &integration)
			if err == nil {
				prior = true
			} else if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return plan, "", err
	}
	if !asset.Valid {
		return plan, "no_configured_source", nil
	}
	device, err := s.devices.GetDevice(ctx, tenant, asset.UUID)
	if errors.Is(err, ErrDeviceNotFound) {
		return plan, "configured_source_unavailable", nil
	}
	if err != nil {
		return plan, "", err
	}
	if reason, err := s.authorizeTargetedRefresh(ctx, tenant, device); err != nil || reason != "" {
		return plan, reason, err
	}
	if !prior {
		return plan, "executor_scope_unknown", nil
	}
	if !agent.Valid && device.Metadata["identity_enrichment_executor"] != "platform" {
		return plan, "executor_scope_unknown", nil
	}
	if agent.Valid {
		var reachable bool
		err = database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM device_agents WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL AND status='active' AND last_heartbeat>now()-interval '5 minutes' AND COALESCE(version,'')<>'' AND COALESCE(profile,'')<>'')`, tenant, agent.UUID).Scan(&reachable)
		})
		if err != nil {
			return plan, "", err
		}
		if !reachable {
			return plan, "executor_unreachable_or_unsuitable", nil
		}
	}
	if s.prepare == nil {
		return plan, "credential_preparation_unavailable", nil
	}
	plan, err = s.prepare(ctx, tenant, device.ID)
	if errors.Is(err, ErrRefreshCredentialsUnavailable) {
		return plan, "configured_credentials_unavailable", nil
	}
	if err != nil {
		return plan, "", err
	}
	if agent.Valid {
		plan.AgentID = &agent.UUID
		plan.Parameters["identity_refresh_executor"] = agent.UUID.String()
	} else {
		plan.Parameters["identity_refresh_executor"] = "platform"
	}
	return plan, "", nil
}

func (s *ConfiguredSourceRefresh) planCloud(ctx context.Context, tenant, observationID uuid.UUID, obs identity.Observation, linked uuid.NullUUID) (models.CreateDeviceJobRequest, string, error) {
	plan := models.CreateDeviceJobRequest{TenantID: tenant, JobType: models.JobTypeCloudDiscovery, Parameters: map[string]interface{}{}}
	var device *models.Device
	if linked.Valid {
		var err error
		device, err = s.devices.GetDevice(ctx, tenant, linked.UUID)
		if err != nil && !errors.Is(err, ErrDeviceNotFound) {
			return plan, "", err
		}
	}
	if device == nil {
		var sealed string
		err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT context_enc FROM identity_observation_cloud_contexts WHERE tenant_id=$1 AND observation_id=$2 ORDER BY observed_at DESC LIMIT 1`, tenant, observationID).Scan(&sealed)
		})
		if errors.Is(err, sql.ErrNoRows) {
			return plan, "cloud_source_not_identified", nil
		}
		if err != nil {
			return plan, "", err
		}
		raw, err := s.devices.cipher.DecryptValue(sealed)
		if err != nil {
			return plan, "configured_credentials_unavailable", nil
		}
		var payload retainedCloudContext
		if err := json.Unmarshal([]byte(raw), &payload); err != nil {
			return plan, "", err
		}
		device = &payload.Device
	}
	if device.CredentialID == nil {
		return plan, "cloud_source_not_identified", nil
	}
	provider := strings.TrimPrefix(obs.Source.Ref, "cloud:")
	resourceType := boundedCloudResourceType(provider, device.DeviceType)
	if resourceType == "" {
		return plan, "cloud_resource_refresh_unsupported", nil
	}
	// Tenant-owned configuration only. A shared integration does not by itself
	// authorize automatic enrichment for every tenant.
	var configured bool
	err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM platform_integrations WHERE tenant_id=$1 AND id=$2 AND integration_type=$3 AND is_active AND deleted_at IS NULL AND config IS NOT NULL AND config<>'{}'::jsonb)`, tenant, *device.CredentialID, provider).Scan(&configured)
	})
	if err != nil {
		return plan, "", err
	}
	if !configured {
		return plan, "configured_credentials_unavailable", nil
	}
	plan.IntegrationID = device.CredentialID
	plan.Parameters["cloud_provider"] = provider
	plan.Parameters["resource_types"] = []string{resourceType}
	plan.Parameters["source_refresh_only"] = true
	if region := cloudRegionForDevice(*device); region != "" {
		plan.Parameters["regions"] = []string{region}
	}
	if group, ok := device.Metadata["resource_group"].(string); ok && group != "" {
		plan.Parameters["resource_groups"] = []string{group}
	}
	return plan, "", nil
}

// Explicit collector vocabulary: never pass an unknown type and accidentally
// interpret it as "all resources". Compute enumeration is deliberately excluded.
func boundedCloudResourceType(provider, deviceType string) string {
	kind := strings.TrimPrefix(deviceType, provider+"_")
	switch provider {
	case "aws":
		switch kind {
		case "alb", "nlb", "elb", "api_gateway", "cloudfront", "kms", "s3", "rds":
			return kind
		}
	case "azure":
		if kind == "keyvault_key" {
			return "key_vault"
		}
		switch kind {
		case "application_gateway", "load_balancer", "key_vault", "storage_account", "sql_database":
			return kind
		}
	case "gcp":
		switch kind {
		case "https_load_balancer":
			return "load_balancer"
		case "kms_crypto_key":
			return "kms"
		}
		switch kind {
		case "load_balancer", "ssl_proxy", "kms", "storage", "cloudsql":
			return kind
		}
	}
	return ""
}
