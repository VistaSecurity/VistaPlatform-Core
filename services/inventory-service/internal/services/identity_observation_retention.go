package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/events"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// SweepIdentityEvidence is bounded and restart-safe. A receipt is marked done
// only after idempotent materialization succeeds. The lease prevents duplicate
// work across replicas; an interrupted attempt becomes eligible again.
func (s *AssetService) SweepIdentityEvidence(ctx context.Context, tenant uuid.UUID) (int, error) {
	repo := pgidentity.New(s.db.DB.DB)
	if err := repo.ExpireObservations(ctx, tenant.String(), time.Now().UTC()); err != nil {
		return 0, err
	}
	var mode string
	err := repo.RunInTx(ctx, tenant.String(), func(bound *pgidentity.Repository) error {
		var err error
		mode, err = bound.AdmissionMode(ctx, tenant.String())
		return err
	})
	if err != nil {
		return 0, err
	}
	if mode == "paused" {
		return 0, nil
	}
	processed := 0
	for i := 0; i < 50; i++ {
		var observationID, assetID uuid.UUID
		var receipt string
		var payload []byte
		var observedAt time.Time
		err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sqlx.Tx) error {
			if err := tx.QueryRowContext(ctx, `SELECT p.observation_id,p.receipt_key,p.payload,o.asset_id,r.observed_at
			 FROM identity_observation_payloads p JOIN identity_observations o ON o.tenant_id=p.tenant_id AND o.id=p.observation_id
			 JOIN identity_observation_receipts r ON r.tenant_id=p.tenant_id AND r.observation_id=p.observation_id AND r.receipt_key=p.receipt_key
			 JOIN assets a ON a.tenant_id=o.tenant_id AND a.id=o.asset_id
			 WHERE p.tenant_id=$1 AND p.materialized_at IS NULL AND p.next_attempt_at<=now()
			 AND o.state='linked' AND a.deleted_at IS NULL AND a.asset_status='monitoring'
			 ORDER BY p.next_attempt_at,p.observation_id,p.receipt_key LIMIT 1 FOR UPDATE OF p SKIP LOCKED`, tenant).Scan(&observationID, &receipt, &payload, &assetID, &observedAt); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `UPDATE identity_observation_payloads SET attempt_count=attempt_count+1,next_attempt_at=now()+interval '5 minutes' WHERE tenant_id=$1 AND observation_id=$2 AND receipt_key=$3`, tenant, observationID, receipt)
			return err
		})
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return processed, err
		}
		var finding IngestFinding
		materializeErr := json.Unmarshal(payload, &finding)
		var risk []*events.AssetRiskChangedPayload
		var crypto []*events.CryptoConfigurationAddedPayload
		var certs []*events.CertificateExpiringPayload
		completed := false
		if materializeErr == nil {
			if finding.RawData == nil {
				finding.RawData = make(map[string]interface{})
			}
			// Receipt time is authoritative even when an older payload omitted
			// its observation clock. Replaying evidence is not a new sighting.
			finding.RawData["observed_at"] = observedAt.Format(time.RFC3339Nano)
			for attempt := 0; attempt < 3; attempt++ {
				var redirected uuid.UUID
				materializeErr = withAssetLifecycleReadLock(ctx, s.db.DB.DB, tenant, assetID, func() error {
					var current uuid.UUID
					var monitoring bool
					if err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sqlx.Tx) error {
						return tx.QueryRowContext(ctx, `SELECT a.id,a.asset_status='monitoring' AND a.deleted_at IS NULL
						 FROM identity_observations o JOIN assets a ON a.tenant_id=o.tenant_id AND a.id=o.asset_id
						 WHERE o.tenant_id=$1 AND o.id=$2 AND o.state='linked'`, tenant, observationID).Scan(&current, &monitoring)
					}); err != nil {
						if errors.Is(err, sql.ErrNoRows) {
							return nil // Keep the receipt pending until it is linked again.
						}
						return err
					}
					if current != assetID {
						redirected = current
						return nil // Acquire the survivor's lock before writing.
					}
					if !monitoring {
						return nil // Approval changed after claim; retain for later.
					}
					if isHostObservation(finding) {
						if err := s.materializeRetainedHostObservation(ctx, tenant, assetID, finding); err != nil {
							return err
						}
					} else if err := s.processDiscoveryCryptoData(tenant, assetID, finding, &risk, &crypto, &certs); err != nil {
						return err
					}
					// A merge cannot move the observation until all children and
					// this receipt acknowledgement have committed.
					if err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sqlx.Tx) error {
						_, err := tx.ExecContext(ctx, `UPDATE identity_observation_payloads SET materialized_at=now(),last_error='' WHERE tenant_id=$1 AND observation_id=$2 AND receipt_key=$3`, tenant, observationID, receipt)
						return err
					}); err != nil {
						return err
					}
					completed = true
					return nil
				})
				if materializeErr != nil || redirected == uuid.Nil {
					break
				}
				assetID = redirected
			}
		}
		if materializeErr != nil {
			// Store an operational reason without copying raw payloads or
			// credentials into a user-readable error field.
			err = database.WithTenantTx(ctx, s.db, tenant, func(tx *sqlx.Tx) error {
				_, err := tx.ExecContext(ctx, `UPDATE identity_observation_payloads SET last_error='materialization failed; retry scheduled',next_attempt_at=now()+interval '5 minutes' WHERE tenant_id=$1 AND observation_id=$2 AND receipt_key=$3`, tenant, observationID, receipt)
				return err
			})
			return processed, errors.Join(fmt.Errorf("materialize retained observation %s: %w", observationID, materializeErr), err)
		}
		if !completed {
			continue
		}
		processed++
		if s.eventPublisher != nil {
			for _, p := range risk {
				_ = s.eventPublisher.PublishAssetRiskChanged(ctx, tenant, p, "retained_observation")
			}
			for _, p := range crypto {
				_ = s.eventPublisher.PublishCryptoConfigurationAdded(ctx, tenant, p, "retained_observation")
			}
			for _, p := range certs {
				_ = s.eventPublisher.PublishCertificateExpiring(ctx, tenant, p, "retained_observation")
			}
		}
	}
	return processed, nil
}
