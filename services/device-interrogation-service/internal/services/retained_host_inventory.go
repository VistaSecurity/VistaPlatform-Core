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
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// Snapshot retirement is a multi-transaction operation. Serialize host reports
// per tenant so a replay cannot interleave an older package/endpoint snapshot
// with a newer live report. Lifecycle locking additionally excludes asset merges.
func (h *HostInventoryIngest) withRunLock(ctx context.Context, tenant uuid.UUID, fn func() error) error {
	return shareddatabase.WithSessionAdvisoryLocks(ctx, h.db, []shareddatabase.SessionAdvisoryLock{
		{Key: pgidentity.HostSnapshotLockKey(tenant)},
	}, fn)
}

func (h *HostInventoryIngest) retainHostInventory(ctx context.Context, repo *pgidentity.Repository, obs identity.Observation, res identity.Resolution, agent, job uuid.UUID, payload *di.InterrogateResult) error {
	if res.ObservationID == "" {
		return nil
	}
	envelope, err := json.Marshal(obs)
	if err != nil {
		return err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = repo.Tx().ExecContext(ctx, `INSERT INTO identity_observation_host_inventories
	 (tenant_id,observation_id,receipt_key,job_id,agent_id,observation,payload,observed_at)
	 VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`, obs.TenantID, res.ObservationID, identity.ObservationReceiptKey(obs), job, agent, string(envelope), string(body), obs.ObservedAt)
	return err
}

func (h *HostInventoryIngest) finishRetainedHostInventory(ctx context.Context, tenant uuid.UUID, observation, receipt string) error {
	return shareddatabase.WithTenantTx(ctx, h.db, tenant, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE identity_observation_host_inventories SET materialized_at=now(),last_error='' WHERE tenant_id=$1 AND observation_id=$2 AND receipt_key=$3`, tenant, observation, receipt)
		return err
	})
}

// ReplayRetainedHostInventories restores committed, sanitized snapshots after
// their identity is resolved and approved. It never fabricates an asset ID.
func (h *HostInventoryIngest) ReplayRetainedHostInventories(ctx context.Context, tenant uuid.UUID) error {
	for range 50 {
		var observation, asset, job, agent uuid.UUID
		var receipt string
		var envelope, body []byte
		err := shareddatabase.WithTenantTx(ctx, h.db, tenant, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT p.observation_id,o.asset_id,p.receipt_key,p.job_id,p.agent_id,p.observation,p.payload
				 FROM identity_observation_host_inventories p
				 JOIN identity_observations o ON o.tenant_id=p.tenant_id AND o.id=p.observation_id
				 JOIN assets a ON a.tenant_id=o.tenant_id AND a.id=o.asset_id
				 WHERE p.tenant_id=$1 AND p.materialized_at IS NULL AND p.superseded_at IS NULL
				 AND p.next_attempt_at<=now() AND o.state='linked' AND a.asset_status='monitoring' AND a.deleted_at IS NULL
				 ORDER BY p.observed_at DESC,p.receipt_key LIMIT 1`, tenant).Scan(&observation, &asset, &receipt, &job, &agent, &envelope, &body)
		})
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		var original identity.Observation
		var payload di.InterrogateResult
		if err = json.Unmarshal(envelope, &original); err != nil {
			return err
		}
		if err = json.Unmarshal(body, &payload); err != nil {
			return err
		}
		deferred := false
		err = shareddatabase.WithSessionAdvisoryLocks(ctx, h.db, []shareddatabase.SessionAdvisoryLock{
			{Key: pgidentity.HostSnapshotLockKey(tenant)},
			{Key: pgidentity.AssetLifecycleLockKey(tenant, asset), Shared: true},
		}, func() error {
			eligible, superseded := false, false
			err := shareddatabase.WithTenantTx(ctx, h.db, tenant, func(tx *sql.Tx) error {
				var mode string
				if err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT config->'identity_admission'->>'mode' FROM tenant_admin_settings WHERE tenant_id=$1),'disabled')`, tenant).Scan(&mode); err != nil {
					return err
				}
				if mode != "enforce" {
					deferred = true
					return nil
				}
				if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity_observations o JOIN assets a ON a.tenant_id=o.tenant_id AND a.id=o.asset_id
                     JOIN identity_observation_host_inventories p ON p.tenant_id=o.tenant_id AND p.observation_id=o.id
                     WHERE o.tenant_id=$1 AND o.id=$2 AND o.asset_id=$3 AND p.receipt_key=$4
                     AND p.materialized_at IS NULL AND p.superseded_at IS NULL
                     AND o.state='linked' AND a.asset_status='monitoring' AND a.deleted_at IS NULL)`, tenant, observation, asset, receipt).Scan(&eligible); err != nil {
					return err
				}
				if !eligible {
					deferred = true
					return nil
				}
				return tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity_observation_host_inventories p JOIN identity_observations o ON o.tenant_id=p.tenant_id AND o.id=p.observation_id
					 WHERE p.tenant_id=$1 AND o.asset_id=$2 AND p.materialized_at IS NOT NULL AND p.observed_at>$3 AND p.agent_id=$4)`, tenant, asset, original.ObservedAt, agent).Scan(&superseded)
			})
			if err != nil || deferred {
				return err
			}
			if superseded {
				return shareddatabase.WithTenantTx(ctx, h.db, tenant, func(tx *sql.Tx) error {
					_, err := tx.ExecContext(ctx, `UPDATE identity_observation_host_inventories SET superseded_at=now(),last_error='superseded by a newer completed host inventory' WHERE tenant_id=$1 AND observation_id=$2 AND receipt_key=$3`, tenant, observation, receipt)
					return err
				})
			}
			counts, err := h.materialise(ctx, tenant, agent, job, &payload, &original, asset.String())
			if err != nil {
				return err
			}
			if counts.AssetID != asset.String() {
				return fmt.Errorf("retained inventory identity changed during replay")
			}
			if !counts.FullyMaterialized() {
				return fmt.Errorf("retained inventory materialization incomplete")
			}
			if h.bypassDB != nil {
				steps := &ProcessingLog{HostInventory: &counts}
				if err := steps.persist(ctx, h.bypassDB, job); err != nil {
					log.Printf("[HostInventory] retained job %s summary unavailable: %v", job, err)
				}
			}
			return nil
		})
		if err != nil {
			storeErr := shareddatabase.WithTenantTx(ctx, h.db, tenant, func(tx *sql.Tx) error {
				_, saveErr := tx.ExecContext(ctx, `UPDATE identity_observation_host_inventories SET next_attempt_at=now()+interval '5 minutes',last_error='materialization failed; retry scheduled' WHERE tenant_id=$1 AND observation_id=$2 AND receipt_key=$3`, tenant, observation, receipt)
				return saveErr
			})
			return errors.Join(err, storeErr)
		}
		if deferred {
			return nil
		}
	}
	return nil
}

func (h *HostInventoryIngest) RunRetainedHostInventories(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		rows, err := h.bypassDB.QueryContext(ctx, `SELECT DISTINCT tenant_id FROM identity_observation_host_inventories WHERE materialized_at IS NULL AND superseded_at IS NULL`)
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
					if err := h.ReplayRetainedHostInventories(ctx, tenant); err != nil {
						log.Printf("[HostInventory] retained replay failed for tenant %s: %v", tenant, err)
					}
				}
			}
		}
		if err != nil && ctx.Err() == nil {
			log.Printf("[HostInventory] retained tenant enumeration failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
