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
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// SweepIdentityEvidence is the identity evidence worker's per-tenant pass. It
// expires observations, replays the crypto evidence that became due
// (replayDueDeferredCrypto, deferred_crypto.go), and materializes retained
// passive host-observation payloads.
//
// The payload half is bounded and restart-safe. A receipt is marked done only
// after idempotent materialization succeeds. The lease prevents duplicate work
// across replicas; an interrupted attempt becomes eligible again.
//
// identity_observation_payloads holds only `host_observation` payloads now: a
// discovery finding's crypto is held in deferred_crypto_findings and replayed
// by the one replay every approval path uses ( F8). The claim below
// selects host observations only, so a stray crypto payload an older pod wrote
// during a rolling upgrade is moved by adopt_legacy_crypto_deferrals() above,
// not materialized by a second replay.
//
// It materialises only observations whose link ATTACHED their evidence
// (platform ADR-0003 D2). A `supporting` row — evidence for an established
// asset the engine linked but wrote nothing from — is `linked` like a match,
// and identity_observations.resolution_outcome is what tells them apart: its
// payload stays unmaterialised, not marked done, until an operator's Link or
// Confirm records a decision of its own and the row becomes eligible here.
// NULL (a row resolved before the column existed) keeps the old behaviour.
func (s *AssetService) SweepIdentityEvidence(ctx context.Context, tenant uuid.UUID) (int, error) {
	repo := pgidentity.New(s.db.DB.DB)
	if err := repo.ExpireObservations(ctx, tenant.String(), time.Now().UTC()); err != nil {
		return 0, err
	}
	// Crypto an older pod parked in the stores deferred_crypto_findings
	// replaced, during the rolling upgrade that introduced it, is moved in
	// before the replay below (the schema's POST-MIGRATIONS moved everything
	// before that). One index probe once nothing is left.
	if err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sqlx.Tx) error {
		_, err := tx.ExecContext(ctx, `SELECT public.adopt_legacy_crypto_deferrals($1)`, tenant)
		return err
	}); err != nil {
		return 0, fmt.Errorf("adopt legacy crypto deferrals: %w", err)
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
	// Before the paused check: crypto held for an approved asset replays
	// whatever the admission mode; the replay itself holds back
	// observation-gated rows while admission is paused.
	replayed, replayErr := s.replayDueDeferredCrypto(ctx, tenant)
	if mode == "paused" {
		return replayed, replayErr
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
			 AND p.payload->>'kind'=$2
			 AND o.state='linked' AND o.resolution_outcome IS DISTINCT FROM 'supporting'
			 AND a.deleted_at IS NULL AND a.asset_status='monitoring'
			 ORDER BY p.next_attempt_at,p.observation_id,p.receipt_key LIMIT 1 FOR UPDATE OF p SKIP LOCKED`, tenant, KindHostObservation).Scan(&observationID, &receipt, &payload, &assetID, &observedAt); err != nil {
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
						 WHERE o.tenant_id=$1 AND o.id=$2 AND o.state='linked'
						 AND o.resolution_outcome IS DISTINCT FROM 'supporting'`, tenant, observationID).Scan(&current, &monitoring)
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
					if err := s.materializeRetainedHostObservation(ctx, tenant, assetID, finding); err != nil {
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
	}
	return processed + replayed, replayErr
}
