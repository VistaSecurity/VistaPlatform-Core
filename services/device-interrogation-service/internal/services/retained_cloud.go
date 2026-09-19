package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/relationships"
)

// CloudIdentitySummary counts committed identity outcomes independently of
// crypto findings and enumerated resources. Retained evidence is not an asset.
type CloudIdentitySummary struct {
	AssetsCreated        int `json:"assets_created"`
	AssetsMatched        int `json:"assets_matched"`
	ApprovalPending      int `json:"approval_pending"`
	ObservationsRetained int `json:"observations_retained"`
	Conflicts            int `json:"conflicts"`
	RejectedInputs       int `json:"rejected_inputs"`
}
type cloudRunKey struct{}
type cloudRunEvidence struct {
	mu       sync.Mutex
	summary  CloudIdentitySummary
	failure  error
	retained map[string]identity.IngestResult
}

func recordCloudOutcome(ctx context.Context, resourceID string, res identity.Resolution, pending bool, err error) {
	run, _ := ctx.Value(cloudRunKey{}).(*cloudRunEvidence)
	if run == nil {
		return
	}
	run.mu.Lock()
	defer run.mu.Unlock()
	if err != nil {
		run.summary.RejectedInputs++
		run.failure = errors.Join(run.failure, err)
		return
	}
	if pending {
		run.summary.ApprovalPending++
	}
	switch res.Outcome {
	case identity.OutcomeCreated:
		run.summary.AssetsCreated++
	case identity.OutcomeMatched:
		run.summary.AssetsMatched++
	case identity.OutcomeConflict:
		run.summary.Conflicts++
		if !res.Asset.Zero() {
			run.summary.AssetsCreated++
		}
	}
	if res.Asset.Zero() && res.ObservationID != "" {
		run.summary.ObservationsRetained++
		if run.retained == nil {
			run.retained = make(map[string]identity.IngestResult)
		}
		run.retained[resourceID] = res.IngestResult()
	}
}

type retainedCloudContext struct {
	Device      models.Device
	Observation identity.Observation
	Enumeration *cloudEnumResource
}
type cloudEnumerationContextKey struct{}

func (s *CloudDiscoveryService) retainCloudContext(ctx context.Context, repo *pgidentity.Repository, obs identity.Observation, res identity.Resolution, device *models.Device) error {
	if res.ObservationID == "" {
		return nil
	}
	if !s.devices.cipher.Enabled() {
		return fmt.Errorf("cloud context encryption unavailable")
	}
	enumeration, _ := ctx.Value(cloudEnumerationContextKey{}).(*cloudEnumResource)
	raw, err := json.Marshal(retainedCloudContext{Device: *device, Observation: obs, Enumeration: enumeration})
	if err != nil {
		return err
	}
	sealed, err := s.devices.cipher.EncryptValue(string(raw))
	if err != nil {
		return err
	}
	_, err = repo.Tx().ExecContext(ctx, `INSERT INTO identity_observation_cloud_contexts(tenant_id,observation_id,receipt_key,context_enc,observed_at)
 VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, obs.TenantID, res.ObservationID, identity.ObservationReceiptKey(obs), sealed, obs.ObservedAt)
	return err
}

// ReplayRetainedCloudContext uses one transaction for facts, downstream durable
// discoveries and acknowledgement. It never re-observes identity or sets its
// timestamp to replay time. Lifecycle locks exclude merge/approval changes.
func (s *CloudDiscoveryService) ReplayRetainedCloudContext(ctx context.Context, tenant uuid.UUID) error {
	repo, err := s.devices.Repo()
	if err != nil {
		return err
	}
	for range 50 {
		var observation, asset uuid.UUID
		var receipt, sealed string
		err := repo.RunInTx(ctx, tenant.String(), func(r *pgidentity.Repository) error {
			mode, err := r.AdmissionMode(ctx, tenant.String())
			if err != nil {
				return err
			}
			if mode == "paused" {
				return sql.ErrNoRows
			}
			return r.Tx().QueryRowContext(ctx, `SELECT p.observation_id,p.receipt_key,p.context_enc,o.asset_id
    FROM identity_observation_cloud_contexts p JOIN identity_observations o ON o.tenant_id=p.tenant_id AND o.id=p.observation_id
    JOIN assets a ON a.tenant_id=o.tenant_id AND a.id=o.asset_id
    WHERE p.tenant_id=$1 AND p.materialized_at IS NULL AND p.next_attempt_at<=now()
    AND o.state='linked' AND a.asset_status='monitoring' AND a.deleted_at IS NULL
    ORDER BY p.next_attempt_at,p.observation_id,p.receipt_key LIMIT 1`, tenant).Scan(&observation, &receipt, &sealed, &asset)
		})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		raw, err := s.devices.cipher.DecryptValue(sealed)
		if err != nil {
			return err
		}
		var payload retainedCloudContext
		if err := json.Unmarshal([]byte(raw), &payload); err != nil {
			return err
		}
		var parent uuid.UUID
		if payload.Enumeration != nil && payload.Enumeration.ParentID != "" {
			owners, err := repo.FindByIdentifier(ctx, tenant.String(), identity.KindCloudResourceID, payload.Enumeration.ParentID, "")
			if err != nil {
				return err
			}
			if len(owners) == 1 {
				parent, err = uuid.Parse(owners[0].ID)
				if err != nil {
					return err
				}
			}
		}
		if payload.Enumeration != nil && payload.Enumeration.ParentID != "" && parent == uuid.Nil {
			if err := repo.RunInTx(ctx, tenant.String(), func(r *pgidentity.Repository) error {
				_, err := r.Tx().ExecContext(ctx, `UPDATE identity_observation_cloud_contexts SET next_attempt_at=now()+interval '5 minutes',last_error='cloud parent identity unresolved' WHERE tenant_id=$1 AND observation_id=$2 AND receipt_key=$3`, tenant, observation, receipt)
				return err
			}); err != nil {
				return err
			}
			continue
		}
		locks := []shareddatabase.SessionAdvisoryLock{{Key: pgidentity.AssetLifecycleLockKey(tenant, asset), Shared: true}}
		if parent != uuid.Nil {
			locks = append(locks, shareddatabase.SessionAdvisoryLock{Key: pgidentity.AssetLifecycleLockKey(tenant, parent), Shared: true})
		}
		err = shareddatabase.WithSessionAdvisoryLocks(ctx, s.db, locks, func() error {
			return repo.RunInTx(ctx, tenant.String(), func(r *pgidentity.Repository) error {
				mode, err := r.AdmissionMode(ctx, tenant.String())
				if err != nil {
					return err
				}
				if mode == "paused" {
					return nil
				}
				var current uuid.UUID
				var status, class string
				err = r.Tx().QueryRowContext(ctx, `SELECT a.id,a.asset_status,a.class_key FROM identity_observation_cloud_contexts p
     JOIN identity_observations o ON o.tenant_id=p.tenant_id AND o.id=p.observation_id
     JOIN assets a ON a.tenant_id=o.tenant_id AND a.id=o.asset_id
     WHERE p.tenant_id=$1 AND p.observation_id=$2 AND p.receipt_key=$3 AND p.materialized_at IS NULL
     AND o.state='linked' AND a.deleted_at IS NULL FOR UPDATE OF p,a SKIP LOCKED`, tenant, observation, receipt).Scan(&current, &status, &class)
				if errors.Is(err, sql.ErrNoRows) {
					return nil
				}
				if err != nil {
					return err
				}
				if current != asset || status != "monitoring" {
					return nil
				}
				ref := identity.AssetRef{TenantID: tenant.String(), ID: asset.String()}
				if payload.Enumeration != nil {
					res := payload.Enumeration
					if err := r.UpsertFacts(ctx, ref, facts.ProducerCloudCollector, cloudFactRows(res.Facts, payload.Observation.Source, payload.Observation.ObservedAt)); err != nil {
						return err
					}
					attrs, err := json.Marshal(filterClassAttributes(class, res.Attributes, res.DeviceType))
					if err != nil {
						return err
					}
					if string(attrs) != "null" {
						// Existing values win: a delayed snapshot cannot replace declarations
						// or fresher attributes installed while identity was unresolved.
						if _, err := r.Tx().ExecContext(ctx, `UPDATE assets SET attributes=$3::jsonb||COALESCE(attributes,'{}'::jsonb),updated_at=now() WHERE tenant_id=$1 AND id=$2`, tenant, asset, string(attrs)); err != nil {
							return err
						}
					}
					if parent != uuid.Nil && parent != asset {
						var available bool
						if err := r.Tx().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM assets WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL AND asset_status NOT IN ('archived','denied'))`, tenant, parent).Scan(&available); err != nil {
							return err
						}
						if !available {
							return fmt.Errorf("cloud parent identity changed during replay")
						}
						if available {
							edgeStatus, err := r.EdgeStatusFor(ctx, tenant.String(), payload.Observation.Source.Kind, parent.String(), asset.String())
							if err != nil {
								return err
							}
							if err := r.UpsertRelationship(ctx, tenant.String(), pgidentity.Edge{FromAssetID: parent.String(), ToAssetID: asset.String(), Type: string(relationships.Contains), SourceKind: payload.Observation.Source.Kind, SourceRef: payload.Observation.Source.Ref, Status: edgeStatus, ObservedAt: payload.Observation.ObservedAt}); err != nil {
								return err
							}
						}
					}
				}
				if err := r.ProjectSegmentLocation(ctx, ref, payload.Observation.Network.SegmentID, payload.Observation.Source); err != nil {
					return err
				}
				integration := uuid.Nil
				if payload.Device.CredentialID != nil {
					integration = *payload.Device.CredentialID
				}
				provider := cloudProviderForDevice(payload.Device)
				if _, err := s.writeSensorDiscoveriesTx(ctx, r.Tx(), tenant, observation.String()+":"+receipt, integration, provider, []models.Device{payload.Device}, payload.Observation.ObservedAt, false); err != nil {
					return err
				}
				if _, err := r.Tx().ExecContext(ctx, `INSERT INTO asset_history(tenant_id,asset_id,source,action,changes_json)
     VALUES($1,$2,'measured','updated',jsonb_build_object('kind','cloud_context_materialized','observation_id',$3::text,'receipt_key',$4::text))`, tenant, asset, observation.String(), receipt); err != nil {
					return err
				}
				_, err = r.Tx().ExecContext(ctx, `UPDATE identity_observation_cloud_contexts SET materialized_at=now(),last_error='' WHERE tenant_id=$1 AND observation_id=$2 AND receipt_key=$3`, tenant, observation, receipt)
				return err
			})
		})
		if err != nil {
			_ = repo.RunInTx(ctx, tenant.String(), func(r *pgidentity.Repository) error {
				_, e := r.Tx().ExecContext(ctx, `UPDATE identity_observation_cloud_contexts SET next_attempt_at=now()+interval '5 minutes',last_error='cloud replay failed; retry scheduled' WHERE tenant_id=$1 AND observation_id=$2 AND receipt_key=$3`, tenant, observation, receipt)
				return e
			})
			return err
		}
	}
	return nil
}
func cloudProviderForDevice(device models.Device) string {
	switch strings.ToLower(strings.TrimSpace(derefStr(device.Vendor))) {
	case "aws", "amazon web services":
		return "aws"
	case "azure", "microsoft azure":
		return "azure"
	case "gcp", "google cloud":
		return "gcp"
	}
	return getStringFromMap(device.Metadata, "cloud_provider")
}
func (s *CloudDiscoveryService) RunRetainedCloudContext(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		rows, err := s.bypassDB.QueryContext(ctx, `SELECT DISTINCT tenant_id FROM identity_observation_cloud_contexts WHERE materialized_at IS NULL AND next_attempt_at<=now()`)
		if err == nil {
			var tenants []uuid.UUID
			for rows.Next() {
				var tenant uuid.UUID
				if err = rows.Scan(&tenant); err != nil {
					break
				}
				tenants = append(tenants, tenant)
			}
			if err == nil {
				err = rows.Err()
			}
			_ = rows.Close()
			if err == nil {
				for _, tenant := range tenants {
					if err := s.ReplayRetainedCloudContext(ctx, tenant); err != nil {
						log.Printf("[CloudDiscovery] retained cloud context replay failed for tenant %s: %v", tenant, err)
					}
				}
			}
		}
		if err != nil && ctx.Err() == nil {
			log.Printf("[CloudDiscovery] retained tenant enumeration failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Evidence, not slice position, identifies a row when a cloud batch is retried
// with its resources or listeners in a different order.
func cloudDiscoveryReceiptID(tenant uuid.UUID, batch, protocol, address string, port int, metadata []byte) uuid.UUID {
	prefix := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00", batch, protocol, address, port)
	return uuid.NewSHA1(tenant, append([]byte(prefix), metadata...))
}
