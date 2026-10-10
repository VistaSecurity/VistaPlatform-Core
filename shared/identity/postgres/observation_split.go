package postgres

// When identical evidence resolves to a different asset.
//
// An `identity_observations` row is keyed by (tenant, fingerprint): every
// sighting of byte-identical evidence — same identifiers, same scope, same
// source — lands on ONE row as another receipt. That was safe while identical
// evidence always resolved to the same asset. It stopped being safe once a
// segment's DHCP posture can change under it: on a static segment
// "address X is-at MAC M" is a floating-address observation that lands on X's
// holder; once the segment is marked dynamic the address no longer votes, and
// the same frame is a match on M's node. The row is linked to the holder, the
// resolution names the node, and [Repository.LinkObservation]'s guard
// ("linked to another asset") used to fail the whole ingest.
//
// What "linked" means to the consumers decides the answer. The row's asset_id
// is where everything retained WITH the row is materialized: the
// device-interrogation workers write every unmaterialized management context,
// host inventory, cloud context and peer context onto `o.asset_id`, and
// inventory-service does the same for payloads — each child keyed by the
// observation and, for most, the receipt it arrived with. Merge preview and
// execution move rows by asset_id; the probe dispatch guard reads it for the
// sensitive-asset policy; an operator's confirmation (`confirmed_by`) is a
// decision about exactly this link.
//
// So the rules are:
//
//   - A NEW sighting (a receipt this transaction inserted) of evidence the row
//     already holds OTHER receipts for is SPLIT onto a row of its own, linked
//     to the new asset. The earlier receipts, and everything retained with
//     them, stay with the asset they were resolved to; relinking the whole row
//     would materialize that context — a management context holds encrypted
//     credentials — onto a device it was never about. The new row takes over
//     the fingerprint, so the next identical sighting lands on it; the old row
//     keeps its id, its receipts, its decisions and its confirmation, under a
//     retired fingerprint (`<fingerprint>#split:<row id>`).
//   - Otherwise — the row IS this sighting (its only receipt), or this is a
//     RE-READ of stored evidence (a transport retry, or the enrichment passes
//     re-resolving the row) — the row moves as a whole: a re-evaluation is a
//     judgement about the evidence, not a new piece of it.
//   - Except a row an operator confirmed, which is never moved by the engine:
//     it splits when it has other receipts (the confirmation stays with them),
//     and otherwise keeps its link and the new asset's history says so.
//
// Every move and split is written to asset_history on BOTH assets, so neither
// timeline gains or loses evidence silently, and no receipt is ever dropped.

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// History `kind` values for the three outcomes.
const (
	historyKindObservationSplit    = "observation_split"
	historyKindObservationRelinked = "observation_relinked"
	historyKindObservationKept     = "observation_kept_operator_link"
)

// splitFingerprintSuffix retires a split row's fingerprint so the unique
// (tenant, fingerprint) slot passes to the row that now receives identical
// sightings. The row id makes it unique however often one evidence splits.
const splitFingerprintSuffix = "#split:"

// noteFreshReceipt remembers that StoreObservation inserted this receipt in
// this transaction. Only a BOUND Repository remembers: an unbound one opens a
// transaction per call, and a marker outliving its transaction would make a
// later replay of the same receipt look new. (Admission refuses to run on an
// unbound Repository anyway — see AdmissionMode.)
func (r *Repository) noteFreshReceipt(observationID, receiptKey string) {
	if r.tx == nil {
		return
	}
	if r.freshReceipts == nil {
		r.freshReceipts = map[string]string{}
	}
	r.freshReceipts[observationID] = receiptKey
}

// settleObservationRow decides which evidence row a resolution to `asset`
// writes to, and makes it writable: see the file comment for the rules.
//
// It returns the row id to link and whether to link it at all (false only for
// an operator-confirmed row the engine must not move). A row that is unlinked,
// or already linked to `asset`, is returned untouched.
func (r *Repository) settleObservationRow(ctx context.Context, obs identity.Observation, observationID string, asset identity.AssetRef) (string, bool, error) {
	rowID, link := observationID, true
	err := r.withTx(ctx, obs.TenantID, func(tx *sql.Tx) error {
		var current, fingerprint string
		var confirmed bool
		if err := tx.QueryRowContext(ctx, `SELECT coalesce(asset_id::text,''), fingerprint, confirmed_by IS NOT NULL
			  FROM identity_observations WHERE tenant_id=$1 AND id=$2 FOR UPDATE`,
			obs.TenantID, observationID).Scan(&current, &fingerprint, &confirmed); err != nil {
			return fmt.Errorf("identity/postgres: read observation %s before linking: %w", observationID, err)
		}
		if current == "" || current == asset.ID {
			return nil
		}
		previous := identity.AssetRef{TenantID: obs.TenantID, ID: current}

		receipt := identity.ObservationReceiptKey(obs)
		var others int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM identity_observation_receipts
			 WHERE tenant_id=$1 AND observation_id=$2 AND receipt_key<>$3`,
			obs.TenantID, observationID, receipt).Scan(&others); err != nil {
			return fmt.Errorf("identity/postgres: count receipts of %s: %w", observationID, err)
		}
		fresh := r.freshReceipts[observationID] == receipt

		switch {
		case others > 0 && (fresh || confirmed):
			newID, err := splitObservation(ctx, tx, obs.TenantID, observationID, fingerprint, receipt)
			if err != nil {
				return err
			}
			rowID = newID
			return r.recordObservationMove(ctx, obs, historyKindObservationSplit, previous, asset, observationID, newID)
		case confirmed:
			// The row is this sighting alone and an operator linked it: a
			// retried delivery that now resolves elsewhere does not overturn
			// a person's decision. The evidence stays where they put it.
			link = false
			return r.RecordHistory(ctx, identity.HistoryEntry{
				TenantID: obs.TenantID, AssetID: asset.ID, Action: identity.ActionUpdated,
				Source: obs.Source, At: obs.ObservedAt,
				Changes: map[string]any{
					"kind":              historyKindObservationKept,
					"observation_id":    observationID,
					"linked_asset_id":   previous.ID,
					"resolved_asset_id": asset.ID,
				},
			})
		default:
			// The whole row moves. asset_id is cleared here and set by the
			// caller's branch, so LinkObservation's guard — which protects
			// the operator and corroboration paths from overwriting a link —
			// sees an unlinked row, and its promotion logic runs as normal.
			if _, err := tx.ExecContext(ctx, `UPDATE identity_observations SET asset_id=NULL,updated_at=now()
				 WHERE tenant_id=$1 AND id=$2`, obs.TenantID, observationID); err != nil {
				return fmt.Errorf("identity/postgres: relink observation %s: %w", observationID, err)
			}
			return r.recordObservationMove(ctx, obs, historyKindObservationRelinked, previous, asset, observationID, observationID)
		}
	})
	if err != nil {
		return "", false, err
	}
	return rowID, link, nil
}

// splitObservation moves one receipt, and the context retained with it, from
// `oldID` to a new row that takes over the fingerprint. The new row is left
// unlinked; the caller's branch links it. It returns the new row's id.
func splitObservation(ctx context.Context, tx *sql.Tx, tenantID, oldID, fingerprint, receipt string) (string, error) {
	if _, err := tx.ExecContext(ctx, `UPDATE identity_observations
		   SET fingerprint = fingerprint || $3 || id::text, updated_at = now()
		 WHERE tenant_id=$1 AND id=$2`, tenantID, oldID, splitFingerprintSuffix); err != nil {
		return "", fmt.Errorf("identity/postgres: retire the fingerprint of %s: %w", oldID, err)
	}
	var newID string
	// The new row is this sighting: its evidence and time come from the
	// receipt (receipts written before receipts carried evidence hold '{}',
	// and fall back to the row's). Provenance and admission reasons are the
	// row's — the fingerprint guarantees the same source and scope.
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO identity_observations
		 (tenant_id,fingerprint,source_kind,source_ref,collector_version,network_scope,evidence,
		  admission_reasons,first_seen_at,last_seen_at,enrichment_state,enrichment_reason)
		SELECT o.tenant_id,$3,o.source_kind,o.source_ref,o.collector_version,o.network_scope,
		       CASE WHEN rc.evidence='{}'::jsonb THEN o.evidence ELSE rc.evidence END,
		       o.admission_reasons,rc.observed_at,rc.observed_at,o.enrichment_state,o.enrichment_reason
		  FROM identity_observations o
		  JOIN identity_observation_receipts rc
		    ON rc.tenant_id=o.tenant_id AND rc.observation_id=o.id AND rc.receipt_key=$4
		 WHERE o.tenant_id=$1 AND o.id=$2
		RETURNING id`, tenantID, oldID, fingerprint, receipt).Scan(&newID); err != nil {
		return "", fmt.Errorf("identity/postgres: split a sighting off %s: %w", oldID, err)
	}
	// The receipt, and every child row retained under it, follow the
	// sighting. Rows keyed by the observation alone (management context, peer
	// context) belong to the receipts that stay, and stay with them.
	for _, table := range []string{
		"identity_observation_receipts",
		"identity_observation_payloads",
		"identity_observation_host_inventories",
		"identity_observation_cloud_contexts",
	} {
		if _, err := tx.ExecContext(ctx, `UPDATE `+table+` SET observation_id=$3
			 WHERE tenant_id=$1 AND observation_id=$2 AND receipt_key=$4`, tenantID, oldID, newID, receipt); err != nil {
			return "", fmt.Errorf("identity/postgres: move %s of the split sighting: %w", table, err)
		}
	}
	// A discovery finding held for the sighting until its observation is
	// linked (inventory-service's deferred_crypto_findings, F8) follows
	// it as well. There the receipt key is the row's dedup_key.
	if _, err := tx.ExecContext(ctx, `UPDATE deferred_crypto_findings SET observation_id=$3
		 WHERE tenant_id=$1 AND observation_id=$2 AND dedup_key=$4`, tenantID, oldID, newID, receipt); err != nil {
		return "", fmt.Errorf("identity/postgres: move the held crypto finding of the split sighting: %w", err)
	}
	// The old row's summary was advanced by this sighting in StoreObservation;
	// it is recomputed from the receipts it still holds.
	if _, err := tx.ExecContext(ctx, `
		UPDATE identity_observations o
		   SET first_seen_at=s.first_seen, last_seen_at=s.last_seen, occurrence_count=s.n,
		       evidence=COALESCE((SELECT CASE WHEN rc.evidence='{}'::jsonb THEN o.evidence ELSE rc.evidence END
		                            FROM identity_observation_receipts rc
		                           WHERE rc.tenant_id=o.tenant_id AND rc.observation_id=o.id
		                           ORDER BY rc.observed_at DESC, rc.receipt_key LIMIT 1), o.evidence),
		       updated_at=now()
		  FROM (SELECT min(observed_at) AS first_seen, max(observed_at) AS last_seen, count(*) AS n
		          FROM identity_observation_receipts WHERE tenant_id=$1 AND observation_id=$2) s
		 WHERE o.tenant_id=$1 AND o.id=$2`, tenantID, oldID); err != nil {
		return "", fmt.Errorf("identity/postgres: recompute %s after the split: %w", oldID, err)
	}
	return newID, nil
}

// recordObservationMove writes the move on both assets' timelines.
func (r *Repository) recordObservationMove(ctx context.Context, obs identity.Observation, kind string, from, to identity.AssetRef, oldRow, newRow string) error {
	changes := map[string]any{
		"kind":           kind,
		"observation_id": newRow,
		"from_asset_id":  from.ID,
		"to_asset_id":    to.ID,
	}
	if oldRow != newRow {
		changes["split_from_observation_id"] = oldRow
	}
	for _, ref := range []identity.AssetRef{from, to} {
		entry := make(map[string]any, len(changes))
		for k, v := range changes {
			entry[k] = v
		}
		if err := r.RecordHistory(ctx, identity.HistoryEntry{
			TenantID: obs.TenantID, AssetID: ref.ID, Action: identity.ActionUpdated,
			Source: obs.Source, At: obs.ObservedAt, Changes: entry,
		}); err != nil {
			return err
		}
	}
	return nil
}
