package postgres

import (
	"context"
	"encoding/json"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// ConfirmedObservationLinks finds previous explicit decisions in this source
// and network scope. Overlap supplies candidates, never automatic ownership.
//
// The row the sighting landed on (observationID) is matched by id alone. A
// source with an Origin groups every run of one device under that row, and
// its source_ref names the run the stored evidence came from, so a delivery
// from an OLDER run (a replayed retained context, a slow agent-path job)
// carries a ref the row no longer has; keying the exact-row branch on the ref
// would miss the operator's own confirmation of exactly this evidence. The
// overlap branch still keys on the ref: that is a search for OTHER rows the
// operator decided under this source.
func (r *Repository) ConfirmedObservationLinks(ctx context.Context, obs identity.Observation, observationID string) ([]identity.ConfirmedObservationLink, error) {
	if err := r.checkTenant(obs.TenantID); err != nil {
		return nil, err
	}
	ids := make([]identity.Identifier, 0, len(obs.Identifiers))
	for _, raw := range obs.Identifiers {
		id, err := raw.Normalized()
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	encoded, err := json.Marshal(ids)
	if err != nil {
		return nil, err
	}
	rows, err := r.tx.QueryContext(ctx, `SELECT o.asset_id,o.evidence,o.id=$5::uuid,
	 (a.deleted_at IS NOT NULL OR a.asset_status IN ('archived','denied'))
	 FROM identity_observations o JOIN assets a ON a.tenant_id=o.tenant_id AND a.id=o.asset_id
	 WHERE o.tenant_id=$1 AND o.confirmed_by IS NOT NULL
	 AND (o.id=$5::uuid OR (o.source_kind=$2 AND o.source_ref=$3 AND o.network_scope=$4 AND EXISTS (
	 SELECT 1 FROM jsonb_array_elements(o.evidence->'identifiers') held
	 CROSS JOIN jsonb_array_elements($6::jsonb) incoming
	 WHERE held->>'kind'=incoming->>'kind' AND held->>'value'=incoming->>'value'
	 AND COALESCE(held->>'scope','')=COALESCE(incoming->>'scope',''))))
	 ORDER BY o.asset_id,o.id`, obs.TenantID, obs.Source.Kind, obs.Source.Ref, obs.Network.SegmentID, observationID, string(encoded))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var links []identity.ConfirmedObservationLink
	for rows.Next() {
		link := identity.ConfirmedObservationLink{Asset: identity.AssetRef{TenantID: obs.TenantID}}
		var raw []byte
		if err := rows.Scan(&link.Asset.ID, &raw, &link.Exact, &link.Unavailable); err != nil {
			return nil, err
		}
		var previous identity.Observation
		if err := json.Unmarshal(raw, &previous); err != nil {
			return nil, err
		}
		link.Identifiers = previous.Identifiers
		links = append(links, link)
	}
	return links, rows.Err()
}
