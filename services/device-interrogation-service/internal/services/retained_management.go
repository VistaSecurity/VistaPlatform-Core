package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/security/credentials"
)

// retainManagement commits encrypted configuration with its identity evidence.
// Encryption covers all fields because metadata and URLs may contain secrets too.
func (s *DeviceService) retainManagement(ctx context.Context, repo *pgidentity.Repository, obs identity.Observation, res identity.Resolution, fields deviceFieldUpdate) error {
	if res.ObservationID == "" {
		return nil
	}
	if !s.cipher.Enabled() {
		return fmt.Errorf("management context encryption unavailable")
	}
	body, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	sealed, err := s.cipher.EncryptValue(string(body))
	if err != nil {
		return err
	}
	_, err = repo.Tx().ExecContext(ctx, `INSERT INTO identity_observation_management(tenant_id,observation_id,context_enc)
	 VALUES($1,$2,$3) ON CONFLICT(tenant_id,observation_id) DO UPDATE
	 SET context_enc=EXCLUDED.context_enc,updated_at=now()
	 WHERE identity_observation_management.materialized_at IS NULL`, obs.TenantID, res.ObservationID, sealed)
	return err
}

// ReplayRetainedManagement installs configuration only after identity resolution
// and monitoring approval. Existing management is preserved for operator review.
func (s *DeviceService) ReplayRetainedManagement(ctx context.Context, tenant uuid.UUID) error {
	repo, err := s.Repo()
	if err != nil {
		return err
	}
	for range 50 {
		done := false
		err := repo.RunInTx(ctx, tenant.String(), func(bound *pgidentity.Repository) error {
			mode, err := bound.AdmissionMode(ctx, tenant.String())
			if err != nil {
				return err
			}
			if mode == "paused" {
				done = true
				return nil
			}
			var observation, asset uuid.UUID
			var sealed string
			err = bound.Tx().QueryRowContext(ctx, `SELECT p.observation_id,o.asset_id,p.context_enc
			 FROM identity_observation_management p
			 JOIN identity_observations o ON o.tenant_id=p.tenant_id AND o.id=p.observation_id
			 JOIN assets a ON a.tenant_id=o.tenant_id AND a.id=o.asset_id
			 WHERE p.tenant_id=$1 AND p.materialized_at IS NULL AND o.state='linked'
			 AND a.asset_status='monitoring' AND a.deleted_at IS NULL
			 AND NOT EXISTS(SELECT 1 FROM asset_management m WHERE m.tenant_id=a.tenant_id AND m.asset_id=a.id)
			 ORDER BY p.observation_id LIMIT 1 FOR UPDATE OF p,a SKIP LOCKED`, tenant).Scan(&observation, &asset, &sealed)
			if err == sql.ErrNoRows {
				done = true
				return nil
			}
			if err != nil {
				return err
			}
			var alreadyManaged bool
			if err := bound.Tx().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM asset_management WHERE tenant_id=$1 AND asset_id=$2)`, tenant, asset).Scan(&alreadyManaged); err != nil {
				return err
			}
			if alreadyManaged {
				return nil
			}
			if !s.cipher.Enabled() || !strings.HasPrefix(sealed, credentials.Prefix) {
				return fmt.Errorf("invalid encrypted management context")
			}
			plain, err := s.cipher.DecryptValue(sealed)
			if err != nil {
				return err
			}
			var fields deviceFieldUpdate
			if err := json.Unmarshal([]byte(plain), &fields); err != nil {
				return err
			}
			// Identity, observed addresses, names, tags and facts stay under the
			// shared identity pipeline; replay configures management only.
			if err := upsertManagement(ctx, bound.Tx(), tenant, asset, managementUpsert{
				ManagementURL: fields.ManagementURL, TLSInsecureSkipVerify: fields.TLSInsecureSkipVerify,
				ManagementProtocol: nonEmptyPtr(managementProtocol(derefStr(fields.ManagementURL), fields.DeviceType)),
				ConnectionStatus:   nonEmptyPtr("unknown"),
			}); err != nil {
				return err
			}
			if err := s.upsertDeviceCredentials(ctx, bound.Tx(), tenant, asset, fields); err != nil {
				return err
			}
			if err := mergeAssetMetadata(ctx, bound.Tx(), tenant, asset, map[string]interface{}{deviceTypeKey: fields.DeviceType, deviceDiscoveryMethodKey: fields.DiscoveryMethod}); err != nil {
				return err
			}
			if _, err := bound.Tx().ExecContext(ctx, `INSERT INTO asset_history(tenant_id,asset_id,source,action,changes_json)
			 SELECT tenant_id,asset_id,source_kind,'updated',jsonb_build_object('kind','management_context_materialized','observation_id',id)
			 FROM identity_observations WHERE tenant_id=$1 AND id=$2`, tenant, observation); err != nil {
				return err
			}
			_, err = bound.Tx().ExecContext(ctx, `UPDATE identity_observation_management SET materialized_at=now() WHERE tenant_id=$1 AND observation_id=$2`, tenant, observation)
			return err
		})
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return nil
}

// RunRetainedManagement uses the bypass pool only to enumerate tenant IDs; every
// configuration read and write above runs in a tenant-scoped transaction.
func (s *DeviceService) RunRetainedManagement(ctx context.Context, bypass *sql.DB) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		rows, err := bypass.QueryContext(ctx, `SELECT DISTINCT tenant_id FROM identity_observation_management WHERE materialized_at IS NULL`)
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
					if err := s.ReplayRetainedManagement(ctx, tenant); err != nil {
						log.Printf("[DeviceService] retained management replay failed for tenant %s: %v", tenant, err)
					}
				}
			}
		}
		if err != nil && ctx.Err() == nil {
			log.Printf("[DeviceService] retained management tenant enumeration failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
