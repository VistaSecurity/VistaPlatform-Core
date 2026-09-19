package postgres

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// PreserveObservationDismissal runs under the summary lock acquired by
// StoreObservation. It precedes any matcher or asset mutation. Reopening needs
// a stronger identity proof than the immutable human dismissal baseline.
func (r *Repository) PreserveObservationDismissal(ctx context.Context, obs identity.Observation, id string, decision identity.AdmissionDecision) (bool, error) {
	dismissed := false
	err := r.withTx(ctx, obs.TenantID, func(tx *sql.Tx) error {
		var state string
		var baseline, receipt []byte
		if err := tx.QueryRowContext(ctx, `SELECT o.state,(SELECT d.details->'dismissed_evidence' FROM identity_observation_decisions d WHERE d.tenant_id=o.tenant_id AND d.observation_id=o.id AND d.action='dismissed' ORDER BY d.decided_at DESC,d.id DESC LIMIT 1),(SELECT r.evidence FROM identity_observation_receipts r WHERE r.tenant_id=o.tenant_id AND r.observation_id=o.id AND r.receipt_key=$3) FROM identity_observations o WHERE o.tenant_id=$1 AND o.id=$2 FOR UPDATE OF o`, obs.TenantID, id, identity.ObservationReceiptKey(obs)).Scan(&state, &baseline, &receipt); err != nil {
			return err
		}
		if state != "dismissed" {
			return nil
		}
		dismissed = true
		// A historical dismissal with no baseline remains a human decision; do not
		// manufacture past evidence from the latest summary overwritten by a replay.
		if len(baseline) == 0 || !decision.Established {
			return nil
		}
		var prior identity.Observation
		if err := json.Unmarshal(baseline, &prior); err != nil {
			return err
		}
		if admissionEvidenceStrength(decision) <= admissionEvidenceStrength(identity.AssessAdmission(prior)) {
			return nil
		}
		// A producer cannot turn a delivery retry into fresh corroboration by
		// changing its trust flags. Only the evidence durably stored under this
		// receipt may justify reopening; receipt conflicts keep the first proof.
		var recorded identity.Observation
		if len(receipt) == 0 {
			return nil
		}
		if err := json.Unmarshal(receipt, &recorded); err != nil {
			return err
		}
		if admissionEvidenceStrength(identity.AssessAdmission(recorded)) <= admissionEvidenceStrength(identity.AssessAdmission(prior)) {
			return nil
		}

		_, err := tx.ExecContext(ctx, `UPDATE identity_observations SET state='unresolved',enrichment_state='waiting',enrichment_reason='',updated_at=now() WHERE tenant_id=$1 AND id=$2 AND state='dismissed'`, obs.TenantID, id)
		if err == nil {
			dismissed = false
		}
		return err
	})
	return dismissed, err
}

func admissionEvidenceStrength(decision identity.AdmissionDecision) int {
	if !decision.Established {
		return 0
	}
	for _, reason := range decision.Reasons {
		switch reason {
		case "operator_confirmation", "declared_service":
			return 3
		case "authoritative_identifier":
			return 2
		}
	}
	return 1
}
