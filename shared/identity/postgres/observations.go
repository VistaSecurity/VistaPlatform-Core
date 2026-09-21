package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
		// APPEND, never replace. The reasons array already carries the
		// admission decision StoreObservation wrote — `unverified_relayed_advertisement`
		// is the sentence the UI uses to explain why the evidence could not
		// establish anything — and a resolution reason is a SECOND fact about
		// the same evidence, not a correction of the first. Replacing was
		// tolerable while `asset_allowance_exhausted` was the only value; the
		// provisional refusals of D2 would otherwise overwrite the
		// explanation with a segment complaint and leave the tenant reading a
		// reason that does not answer their question.
		return r.withTx(ctx, obs.TenantID, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE identity_observations SET
				admission_reasons=CASE WHEN $3 = ANY(admission_reasons) THEN admission_reasons
				                       ELSE array_append(admission_reasons,$3::text) END,
				enrichment_state='blocked',enrichment_reason=$3,updated_at=now()
				WHERE tenant_id=$1 AND id=$2`, obs.TenantID, observationID, res.AdmissionReason)
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
	// D2/D3. Both new outcomes attach the observation to an asset
	// WITHOUT resolving it: a provisional asset is a guess, so the evidence
	// stays `unresolved` and enrichment keeps working on it until something
	// direct corroborates it. Supporting evidence for an ESTABLISHED asset is
	// resolved, because there is nothing left to find out.
	switch res.Outcome {
	case identity.OutcomeProvisional:
		return r.withTx(ctx, obs.TenantID, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE identity_observations SET asset_id=$3,state='unresolved',
			 updated_at=now() WHERE tenant_id=$1 AND id=$2`, obs.TenantID, observationID, res.Asset.ID)
			return err
		})
	case identity.OutcomeSupporting:
		return r.withTx(ctx, obs.TenantID, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE identity_observations SET asset_id=$3,
			 state=CASE WHEN (SELECT identity_status FROM assets WHERE tenant_id=$1 AND id=$3)='provisional'
			            THEN 'unresolved' ELSE 'linked' END,
			 updated_at=now() WHERE tenant_id=$1 AND id=$2`, obs.TenantID, observationID, res.Asset.ID)
			return err
		})
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
	return checkAdmissionAllowance(ctx, r.tx, tenantID)
}

// checkAdmissionAllowance is the allowance test itself, on a caller's
// transaction, so [Repository.LinkObservation] can apply it at PROMOTION
// without going back through the Repository's own binding check.
//
// PROVISIONAL assets are excluded from the count ( D1). A provisional
// asset is the platform's guess that something exists, made from evidence
// nobody verified; charging a customer's `max_assets` for it would let a
// chatty mDNS reflector exhaust a paid limit with hearsay, and would then
// block the creation of assets that ARE real. The allowance is checked when a
// provisional asset is promoted instead — the moment the platform asserts the
// thing is real.
func checkAdmissionAllowance(ctx context.Context, tx *sql.Tx, tenantID string) (bool, error) {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,72041))`, tenantID); err != nil {
		return false, err
	}
	tenant, err := uuid.Parse(tenantID)
	if err != nil {
		return false, err
	}
	limit, err := entitlements.GetQuantityInTx(ctx, tx, tenant, "max_assets")
	if err != nil {
		return false, err
	}
	if limit == nil {
		return true, nil
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM assets
		 WHERE tenant_id=$1 AND deleted_at IS NULL AND identity_status <> 'provisional'`, tenantID).Scan(&count); err != nil {
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
		// D1: promoting a PROVISIONAL asset is the moment the platform
		// asserts the thing is real, so it is the moment the tenant's
		// `max_assets` allowance applies. When it is exhausted the evidence
		// still lands — the observation above is already linked — and the
		// asset simply stays provisional, with the reason recorded where the
		// tenant can read it. Losing the evidence instead would make an
		// exhausted allowance look like a discovery that never happened.
		var previous string
		err = tx.QueryRowContext(ctx, `SELECT identity_status FROM assets
			WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, assetID).Scan(&previous)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %s", identity.ErrAssetNotFound, assetID)
		}
		if err != nil {
			return err
		}
		if previous == string(identity.IdentityProvisional) {
			allowed, err := checkAdmissionAllowance(ctx, tx, tenantID)
			if err != nil {
				return err
			}
			if !allowed {
				_, err := tx.ExecContext(ctx, `UPDATE identity_observations SET
					admission_reasons=CASE WHEN $3 = ANY(admission_reasons) THEN admission_reasons
					                       ELSE array_append(admission_reasons,$3) END,
					updated_at=now() WHERE tenant_id=$1 AND id=$2`,
					tenantID, observationID, identity.ReasonAssetAllowanceExhausted)
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `WITH prior AS (
			 SELECT identity_status FROM assets WHERE tenant_id=$1 AND id=$2 FOR UPDATE
			), changed AS (
			 UPDATE assets a SET identity_status=$3,updated_at=now() FROM prior p
			 WHERE a.tenant_id=$1 AND a.id=$2 AND (p.identity_status IN ('legacy','provisional')
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
