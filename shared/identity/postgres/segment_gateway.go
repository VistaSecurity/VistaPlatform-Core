package postgres

// A network segment records its gateway (owner decision D1).
//
// The link is four columns on `network_segments` — gateway_asset_id,
// gateway_address, gateway_source_ref, gateway_observed_at — written ONLY by
// [Repository.ReconcileGatewayLinks], from one interrogation's complete list of
// the device's own addresses on the networks it serves (`net.vlans`).
//
// # The link follows the address, not the claim
//
// A device claiming an address does not make it the network's gateway: a
// claim against an established holder opens a merge proposal and the device
// does not get the address (shared/identity/claimed.go). So the reconcile
// never trusts the list it is given. A segment is linked only where the device
// HOLDS one of the listed addresses, scoped to that segment, in
// asset_identifiers at the moment the reconcile runs — which is exactly what
// the claim settled. A contested address is therefore never linked, and an
// address the device later loses (re-homed, merged away) stops linking it on
// the next run.
//
// # The list is complete
//
// The run reports every network the device serves. A segment linked to this
// device that the list no longer reaches is cleared — and only a link to THIS
// device: another device's claim on a network is never touched by this one's
// run. A run that reported no `net.vlans` fact at all does not call this; an
// absent fact is not evidence that the device serves nothing.
//
// # Two devices, one network
//
// An HA pair or a VRRP group can both report serving one network, each from
// its own address. The most recent observation wins the columns; the other
// claim is kept in metadata.gateway_candidates, keyed by asset id, so it is not
// lost. That is enough for v1 (spec §3.3). A candidate is never promoted by a
// clear: the other device's next run re-asserts its own claim.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"
)

// GatewayCandidatesKey is the network_segments.metadata key that keeps the
// claims of devices that are not the current gateway, keyed by asset id.
const GatewayCandidatesKey = "gateway_candidates"

// MaxGatewaySourceRefLen is network_segments.gateway_source_ref's width.
const MaxGatewaySourceRefLen = 200

// ErrGatewayAssetUnknown is a reconcile for an asset that is not a live asset
// of the tenant. Nothing is written.
var ErrGatewayAssetUnknown = errors.New("identity/postgres: the gateway is not a live asset of the tenant")

// GatewaySegment is one segment a reconcile linked, or kept as a candidate.
type GatewaySegment struct {
	SegmentID string `json:"segment_id"`
	Address   string `json:"address"`
}

// GatewayLinkResult is what one reconcile did.
type GatewayLinkResult struct {
	// Linked are the segments this device is now the gateway of.
	Linked []GatewaySegment `json:"linked"`
	// Candidates are segments where the device holds an address but a more
	// recent observation names another gateway; the claim is kept in
	// metadata.gateway_candidates.
	Candidates []GatewaySegment `json:"candidates"`
	// Cleared are the segments whose link to this device was removed: the
	// device no longer holds a listed address there.
	Cleared []string `json:"cleared"`
}

// gatewayCandidate is one entry of metadata.gateway_candidates.
type gatewayCandidate struct {
	Address    string `json:"address"`
	SourceRef  string `json:"source_ref,omitempty"`
	ObservedAt string `json:"observed_at,omitempty"`
}

// gatewayRow is one locked segment.
type gatewayRow struct {
	id         string
	gateway    sql.NullString
	address    sql.NullString
	sourceRef  sql.NullString
	observedAt sql.NullTime
	candidates map[string]gatewayCandidate
}

// NormalizeGatewayAddresses parses, unmaps and de-duplicates addresses, in
// order, dropping what is not an address. It is the form asset_identifiers
// stores an ip_address in.
func NormalizeGatewayAddresses(addresses []string) []string {
	seen := make(map[string]bool, len(addresses))
	out := make([]string, 0, len(addresses))
	for _, raw := range addresses {
		a, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		v := a.Unmap().WithZone("").String()
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// ReconcileGatewayLinks makes the segment → gateway links for assetID match
// one interrogation's complete list of the device's own addresses on the
// networks it serves (see the file comment for the rules). Idempotent: the
// same list over the same identifiers writes nothing new.
func (r *Repository) ReconcileGatewayLinks(ctx context.Context, tenantID, assetID, sourceRef string, observedAt time.Time, addresses []string) (GatewayLinkResult, error) {
	out := GatewayLinkResult{Linked: []GatewaySegment{}, Candidates: []GatewaySegment{}, Cleared: []string{}}
	if len(sourceRef) > MaxGatewaySourceRefLen {
		return out, fmt.Errorf("identity/postgres: gateway source ref is %d characters, more than %d", len(sourceRef), MaxGatewaySourceRefLen)
	}
	if observedAt.IsZero() {
		observedAt = time.Now()
	}
	observedAt = observedAt.UTC()
	addrs := NormalizeGatewayAddresses(addresses)
	err := r.withTx(ctx, tenantID, func(tx *sql.Tx) error {
		var live bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (SELECT 1 FROM public.assets
			                WHERE tenant_id = $1::uuid AND id::text = $2 AND deleted_at IS NULL)`,
			tenantID, assetID).Scan(&live); err != nil {
			return fmt.Errorf("gateway links: reading the asset: %w", err)
		}
		if !live {
			return ErrGatewayAssetUnknown
		}

		// The segments where the device HOLDS a listed address, scoped to
		// that segment. The first listed address wins a segment the device
		// holds two of.
		held := map[string]string{}
		var heldOrder []string
		if len(addrs) > 0 {
			rows, err := tx.QueryContext(ctx, `
				SELECT DISTINCT ON (ns.id) ns.id::text, ai.value, c.ord
				  FROM unnest($3::text[]) WITH ORDINALITY AS c(addr, ord)
				  JOIN public.asset_identifiers ai
				    ON ai.tenant_id = $1::uuid AND ai.asset_id::text = $2
				   AND ai.kind = 'ip_address' AND ai.value = c.addr
				  JOIN public.network_segments ns
				    ON ns.tenant_id = $1::uuid AND ns.id::text = ai.scope
				 ORDER BY ns.id, c.ord`, tenantID, assetID, pq.Array(addrs))
			if err != nil {
				return fmt.Errorf("gateway links: reading held addresses: %w", err)
			}
			type heldRow struct {
				segment, address string
				ord              int64
			}
			var hs []heldRow
			for rows.Next() {
				var h heldRow
				if err := rows.Scan(&h.segment, &h.address, &h.ord); err != nil {
					_ = rows.Close()
					return err
				}
				hs = append(hs, h)
			}
			if err := rows.Err(); err != nil {
				_ = rows.Close()
				return err
			}
			_ = rows.Close()
			// Report in the run's own order.
			sort.SliceStable(hs, func(i, j int) bool { return hs[i].ord < hs[j].ord })
			for _, h := range hs {
				held[h.segment] = h.address
				heldOrder = append(heldOrder, h.segment)
			}
		}

		// Every segment this run can change, locked in one order so two
		// gateways reconciling at once cannot deadlock.
		rows, err := tx.QueryContext(ctx, `
			SELECT id::text, gateway_asset_id::text, host(gateway_address), gateway_source_ref,
			       gateway_observed_at, coalesce(metadata -> $4::text, '{}'::jsonb)::text
			  FROM public.network_segments
			 WHERE tenant_id = $1::uuid
			   AND (id::text = ANY($3::text[])
			        OR gateway_asset_id::text = $2
			        OR coalesce(metadata -> $4::text, '{}'::jsonb) ? $2)
			 ORDER BY id
			   FOR UPDATE`, tenantID, assetID, pq.Array(heldOrder), GatewayCandidatesKey)
		if err != nil {
			return fmt.Errorf("gateway links: locking segments: %w", err)
		}
		locked := map[string]*gatewayRow{}
		var lockedOrder []string
		for rows.Next() {
			g := &gatewayRow{}
			var cands string
			if err := rows.Scan(&g.id, &g.gateway, &g.address, &g.sourceRef, &g.observedAt, &cands); err != nil {
				_ = rows.Close()
				return err
			}
			g.candidates = decodeGatewayCandidates(cands)
			locked[g.id] = g
			lockedOrder = append(lockedOrder, g.id)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		_ = rows.Close()

		self := gatewayCandidate{SourceRef: sourceRef, ObservedAt: observedAt.Format(time.RFC3339Nano)}
		for _, id := range heldOrder {
			g, ok := locked[id]
			if !ok {
				continue // deleted between the two reads
			}
			address := held[id]
			current := g.gateway.String
			switch {
			case current == "" || current == assetID:
				delete(g.candidates, assetID)
				if err := writeGatewayLink(ctx, tx, tenantID, g, &assetID, address, sourceRef, observedAt); err != nil {
					return err
				}
				out.Linked = append(out.Linked, GatewaySegment{SegmentID: id, Address: address})
			case g.observedAt.Valid && g.observedAt.Time.After(observedAt):
				// Another device's claim is the more recent observation: it
				// stays, and this one is kept beside it.
				c := self
				c.Address = address
				g.candidates[assetID] = c
				if err := writeGatewayCandidates(ctx, tx, tenantID, g); err != nil {
					return err
				}
				out.Candidates = append(out.Candidates, GatewaySegment{SegmentID: id, Address: address})
			default:
				prev := gatewayCandidate{Address: g.address.String, SourceRef: g.sourceRef.String}
				if g.observedAt.Valid {
					prev.ObservedAt = g.observedAt.Time.UTC().Format(time.RFC3339Nano)
				}
				g.candidates[current] = prev
				delete(g.candidates, assetID)
				if err := writeGatewayLink(ctx, tx, tenantID, g, &assetID, address, sourceRef, observedAt); err != nil {
					return err
				}
				out.Linked = append(out.Linked, GatewaySegment{SegmentID: id, Address: address})
			}
		}

		// What this run no longer reaches: this device's link is cleared and
		// its candidacy withdrawn. Another device's link is not touched.
		for _, id := range lockedOrder {
			if _, ok := held[id]; ok {
				continue
			}
			g := locked[id]
			_, wasCandidate := g.candidates[assetID]
			delete(g.candidates, assetID)
			if g.gateway.String == assetID {
				if err := writeGatewayLink(ctx, tx, tenantID, g, nil, "", "", time.Time{}); err != nil {
					return err
				}
				out.Cleared = append(out.Cleared, id)
				continue
			}
			if wasCandidate {
				if err := writeGatewayCandidates(ctx, tx, tenantID, g); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return GatewayLinkResult{Linked: []GatewaySegment{}, Candidates: []GatewaySegment{}, Cleared: []string{}}, err
	}
	return out, nil
}

// writeGatewayLink sets the four columns (asset nil clears them) and the
// candidates, writing nothing when neither changes. A refreshed observation
// time on an otherwise identical link is a change: it is what "most recent
// wins" compares.
func writeGatewayLink(ctx context.Context, tx *sql.Tx, tenantID string, g *gatewayRow, asset *string, address, sourceRef string, observedAt time.Time) error {
	var a, addr, ref, at any
	if asset != nil {
		a, addr, ref, at = *asset, address, sourceRef, observedAt
	}
	cands, err := encodeGatewayCandidates(g.candidates)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE public.network_segments
		   SET gateway_asset_id    = $3::uuid,
		       gateway_address     = $4::inet,
		       gateway_source_ref  = $5,
		       gateway_observed_at = $6::timestamptz,
		       metadata = CASE WHEN $7::jsonb = '{}'::jsonb
		                       THEN coalesce(metadata, '{}'::jsonb) - $8::text
		                       ELSE jsonb_set(coalesce(metadata, '{}'::jsonb), ARRAY[$8::text], $7::jsonb) END,
		       updated_at = now()
		 WHERE tenant_id = $1::uuid AND id::text = $2
		   AND (gateway_asset_id, gateway_address, gateway_source_ref, gateway_observed_at,
		        coalesce(metadata -> $8::text, '{}'::jsonb))
		       IS DISTINCT FROM ($3::uuid, $4::inet, $5::varchar, $6::timestamptz, $7::jsonb)`,
		tenantID, g.id, a, addr, ref, at, cands, GatewayCandidatesKey); err != nil {
		return fmt.Errorf("gateway links: writing segment %s: %w", g.id, err)
	}
	return nil
}

// writeGatewayCandidates writes the candidates alone.
func writeGatewayCandidates(ctx context.Context, tx *sql.Tx, tenantID string, g *gatewayRow) error {
	cands, err := encodeGatewayCandidates(g.candidates)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE public.network_segments
		   SET metadata = CASE WHEN $3::jsonb = '{}'::jsonb
		                       THEN coalesce(metadata, '{}'::jsonb) - $4::text
		                       ELSE jsonb_set(coalesce(metadata, '{}'::jsonb), ARRAY[$4::text], $3::jsonb) END,
		       updated_at = now()
		 WHERE tenant_id = $1::uuid AND id::text = $2
		   AND coalesce(metadata -> $4::text, '{}'::jsonb) IS DISTINCT FROM $3::jsonb`,
		tenantID, g.id, cands, GatewayCandidatesKey); err != nil {
		return fmt.Errorf("gateway links: writing candidates of segment %s: %w", g.id, err)
	}
	return nil
}

func decodeGatewayCandidates(raw string) map[string]gatewayCandidate {
	out := map[string]gatewayCandidate{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil || out == nil {
		// A malformed value is replaced, never trusted.
		return map[string]gatewayCandidate{}
	}
	return out
}

func encodeGatewayCandidates(c map[string]gatewayCandidate) (string, error) {
	if len(c) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(c)
	return string(b), err
}

// RepointGatewayCandidates moves a merged-away asset's gateway candidacies to
// the survivor, inside the merge's transaction and AFTER the merge re-pointed
// network_segments.gateway_asset_id (a declared asset reference the merge
// moves like every other). A survivor that is the segment's gateway, or
// already a candidate there, keeps its own entry; the merged-away entry goes.
func RepointGatewayCandidates(ctx context.Context, q interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, tenantID, from, to string) error {
	_, err := q.ExecContext(ctx, `
		UPDATE public.network_segments ns
		   SET metadata = CASE WHEN n.next = '{}'::jsonb
		                       THEN ns.metadata - $4::text
		                       ELSE jsonb_set(ns.metadata, ARRAY[$4::text], n.next) END,
		       updated_at = now()
		  FROM (SELECT s.id,
		               ((s.metadata -> $4::text) - $2::text
		                 || CASE WHEN (s.metadata -> $4::text) ? $2::text
		                          AND s.gateway_asset_id IS DISTINCT FROM $3::uuid
		                          AND NOT ((s.metadata -> $4::text) ? $3::text)
		                         THEN jsonb_build_object($3::text, (s.metadata -> $4::text) -> $2::text)
		                         ELSE '{}'::jsonb END)
		               - CASE WHEN s.gateway_asset_id = $3::uuid THEN $3::text ELSE '' END AS next
		          FROM public.network_segments s
		         WHERE s.tenant_id = $1::uuid
		           AND jsonb_typeof(s.metadata -> $4::text) = 'object'
		           AND ((s.metadata -> $4::text) ? $2::text
		                OR (s.gateway_asset_id = $3::uuid AND (s.metadata -> $4::text) ? $3::text))) n
		 WHERE ns.id = n.id AND ns.tenant_id = $1::uuid`,
		tenantID, from, to, GatewayCandidatesKey)
	if err != nil {
		return fmt.Errorf("gateway candidates: re-pointing %s to %s: %w", from, to, err)
	}
	return nil
}
