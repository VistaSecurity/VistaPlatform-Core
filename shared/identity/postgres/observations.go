package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// AdmissionMode is read in the resolution transaction. An enabled policy on an
// unbound repository is refused: evidence and asset writes must be atomic.
func (r *Repository) AdmissionMode(ctx context.Context, tenantID string) (string, error) {
	mode := "disabled"
	err := r.withTx(ctx, tenantID, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `SELECT COALESCE(config->'identity_admission'->>'mode','disabled')
		 FROM tenant_admin_settings WHERE tenant_id=$1`, tenantID).Scan(&mode)
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	})
	if err == nil && mode != "disabled" && r.tx == nil {
		return "", fmt.Errorf("identity admission requires a bound transaction")
	}
	return mode, err
}

func (r *Repository) FinishObservation(ctx context.Context, obs identity.Observation, observationID string, res identity.Resolution, decision identity.AdmissionDecision, establish bool) error {
	if res.AdmissionReason != "" {
		return r.withTx(ctx, obs.TenantID, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE identity_observations SET admission_reasons=ARRAY[$3::text],enrichment_state='blocked',enrichment_reason=$3,updated_at=now() WHERE tenant_id=$1 AND id=$2`, obs.TenantID, observationID, res.AdmissionReason)
			return err
		})
	}
	if res.Outcome == identity.OutcomeConflict {
		return r.withTx(ctx, obs.TenantID, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE identity_observations SET state='conflict',proposal_id=NULLIF($3,'')::uuid,
			 updated_at=now() WHERE tenant_id=$1 AND id=$2`, obs.TenantID, observationID, res.Proposal.ID)
			return err
		})
	}
	if res.Asset.Zero() {
		return nil
	}
	if establish && decision.Established {
		status := identity.IdentityEstablished
		if obs.Admission.OperatorConfirmed && obs.Source.Kind == identity.SourceDeclared {
			status = identity.IdentityOperatorConfirmed
		}
		return r.LinkObservation(ctx, obs.TenantID, observationID, res.Asset.ID, status)
	}
	return r.withTx(ctx, obs.TenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE identity_observations SET asset_id=$3,state='linked',updated_at=now()
		 WHERE tenant_id=$1 AND id=$2`, obs.TenantID, observationID, res.Asset.ID)
		return err
	})
}

// CheckAdmissionAllowance serializes prospective creates within the tenant;
// unresolved evidence and matches never enter this check or consume allowances.
func (r *Repository) CheckAdmissionAllowance(ctx context.Context, tenantID string) (bool, error) {
	if r.tx == nil {
		return false, fmt.Errorf("admission allowance requires a bound transaction")
	}
	if err := r.checkTenant(tenantID); err != nil {
		return false, err
	}
	if _, err := r.tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,72041))`, tenantID); err != nil {
		return false, err
	}
	tenant, err := uuid.Parse(tenantID)
	if err != nil {
		return false, err
	}
	limit, err := entitlements.GetQuantityInTx(ctx, r.tx, tenant, "max_assets")
	if err != nil {
		return false, err
	}
	if limit == nil {
		return true, nil
	}
	var count int
	if err := r.tx.QueryRowContext(ctx, `SELECT count(*) FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL`, tenantID).Scan(&count); err != nil {
		return false, err
	}
	return count < *limit, nil
}

// StoreObservation records normalized evidence and one delivery receipt in the
// caller's transaction. It never creates, bills, approves, or touches an asset.
func (r *Repository) StoreObservation(ctx context.Context, obs identity.Observation, decision identity.AdmissionDecision) (string, error) {
	if obs.ObservedAt.IsZero() {
		return "", fmt.Errorf("identity observation requires its original observation time")
	}
	if obs.Source.Ref == "" || !obs.Source.Kind.Valid() {
		return "", fmt.Errorf("identity observation requires source provenance")
	}
	normalized := obs
	// Observation browsing requires assets.read, not secret access. Only retain
	// scalar identity/classification context here; adapter attributes may also
	// contain credential material intended for restricted management records.
	normalized.Attributes = make(map[string]any)
	for _, key := range []string{"vendor", "manufacturer", "model", "operating_system", "os_version", "architecture", "firmware_version"} {
		if value, ok := obs.Attributes[key].(string); ok {
			normalized.Attributes[key] = value
		}
	}
	normalized.Identifiers = nil
	for _, raw := range obs.Identifiers {
		id, err := raw.Normalized()
		if err != nil {
			return "", err
		}
		normalized.Identifiers = append(normalized.Identifiers, id)
	}
	evidence, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	var id string
	err = r.withTx(ctx, obs.TenantID, func(tx *sql.Tx) error {
		// Lock the summary before inserting a receipt so concurrent replay can
		// neither increment twice nor erase a dismissal/link made by a reviewer.
		err := tx.QueryRowContext(ctx, `
			INSERT INTO identity_observations
			 (tenant_id,fingerprint,source_kind,source_ref,collector_version,network_scope,
			  evidence,admission_reasons,first_seen_at,last_seen_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)
			ON CONFLICT (tenant_id,fingerprint) DO UPDATE
			 SET fingerprint=EXCLUDED.fingerprint
			RETURNING id`, obs.TenantID, identity.ObservationFingerprint(normalized),
			obs.Source.Kind, obs.Source.Ref, obs.Admission.CollectorVersion, obs.Network.SegmentID,
			string(evidence), pq.Array(decision.Reasons), obs.ObservedAt).Scan(&id)
		if err != nil {
			return fmt.Errorf("store identity observation: %w", err)
		}
		var receipt string
		err = tx.QueryRowContext(ctx, `INSERT INTO identity_observation_receipts
			(tenant_id,observation_id,receipt_key,observed_at,evidence) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT DO NOTHING RETURNING receipt_key`, obs.TenantID, id,
			identity.ObservationReceiptKey(normalized), obs.ObservedAt, string(evidence)).Scan(&receipt)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return fmt.Errorf("store identity receipt: %w", err)
		}
		_, err = tx.ExecContext(ctx, `UPDATE identity_observations o SET
			first_seen_at=LEAST(first_seen_at,$3), last_seen_at=GREATEST(last_seen_at,$3),
			evidence=CASE WHEN $3 >= last_seen_at THEN $4::jsonb ELSE evidence END,
			collector_version=CASE WHEN $3 >= last_seen_at THEN $5 ELSE collector_version END,
			admission_reasons=CASE WHEN $3 >= last_seen_at THEN $6::text[] ELSE admission_reasons END,
			occurrence_count=(SELECT count(*) FROM identity_observation_receipts r
			 WHERE r.tenant_id=o.tenant_id AND r.observation_id=o.id),
			state=CASE WHEN state='expired' AND $3 > last_seen_at THEN 'unresolved' ELSE state END,
			updated_at=now() WHERE tenant_id=$1 AND id=$2`, obs.TenantID, id,
			obs.ObservedAt, string(evidence), obs.Admission.CollectorVersion, pq.Array(decision.Reasons))
		return err
	})
	return id, err
}

// LinkObservation changes identity quality only after resolution has succeeded.
// Approval and existing declared values are deliberately untouched.
func (r *Repository) LinkObservation(ctx context.Context, tenantID, observationID, assetID string, status identity.IdentityStatus) error {
	if status != identity.IdentityEstablished && status != identity.IdentityOperatorConfirmed {
		return fmt.Errorf("invalid established identity status %q", status)
	}
	return r.withTx(ctx, tenantID, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE identity_observations SET
			asset_id=$3, state='linked', updated_at=now()
			WHERE tenant_id=$1 AND id=$2 AND (asset_id IS NULL OR asset_id=$3)`, tenantID, observationID, assetID)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("observation missing or linked to another asset")
		}
		_, err = tx.ExecContext(ctx, `WITH prior AS (
			 SELECT identity_status FROM assets WHERE tenant_id=$1 AND id=$2 FOR UPDATE
			), changed AS (
			 UPDATE assets a SET identity_status=$3,updated_at=now() FROM prior p
			 WHERE a.tenant_id=$1 AND a.id=$2 AND (p.identity_status='legacy'
			 OR (p.identity_status='operator_confirmed' AND $3='established'))
			 RETURNING a.id,p.identity_status AS previous
			) INSERT INTO asset_history(tenant_id,asset_id,source,action,changes_json)
			 SELECT $1,id,CASE WHEN $3='operator_confirmed' THEN 'declared' ELSE 'measured' END,'updated',
			 jsonb_build_object('kind','identity_status','from',previous,'to',$3::text,'observation_id',$4::text)
			 FROM changed`, tenantID, assetID, status, observationID)
		return err
	})
}

// ExpireObservations uses observation time, not administrative update time.
// Open conflict evidence and linked records cannot be removed by this sweep.
func (r *Repository) ExpireObservations(ctx context.Context, tenantID string, now time.Time) error {
	return r.withTx(ctx, tenantID, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE identity_observations SET state='expired',updated_at=now()
			WHERE tenant_id=$1 AND state='unresolved' AND asset_id IS NULL AND proposal_id IS NULL
			AND last_seen_at < $2`, tenantID, now.Add(-30*24*time.Hour)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM identity_observations WHERE tenant_id=$1
			AND state IN ('expired','dismissed') AND asset_id IS NULL AND proposal_id IS NULL
			AND last_seen_at < $2`, tenantID, now.Add(-90*24*time.Hour))
		return err
	})
}
