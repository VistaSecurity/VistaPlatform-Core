package postgres

// A prefix records its gateway (owner decision D1; DCIM row 1.6).
//
// The link is four columns on `prefixes` — gateway_asset_id, gateway_ip_id,
// gateway_source_ref, gateway_observed_at — written ONLY by
// [Repository.ReconcileGatewayLinks], from one interrogation's complete list of
// the device's own addresses on the networks it serves (`net.vlans`).
// `gateway_ip_id` is the `ip_addresses` row the device holds on that network:
// the address is the identity engine's, filed on one of the device's
// interfaces (row 1.4).
//
// # The link follows the address, not the claim
//
// A device claiming an address does not make it the network's gateway: a
// claim against an established holder opens a merge proposal and the device
// does not get the address (shared/identity/claimed.go). So the reconcile
// never trusts the list it is given. A prefix is linked only where the device
// HOLDS one of the listed addresses, scoped to that prefix, at the moment the
// reconcile runs — which is exactly what the claim settled. A contested
// address is therefore never linked, and an address the device later loses
// (re-homed, merged away) stops linking it on the next run.
//
// # The list is complete
//
// The run reports every network the device serves. A prefix linked to this
// device that the list no longer reaches is cleared — and only a link to THIS
// device: another device's claim on a network is never touched by this one's
// run. A run that reported no `net.vlans` fact at all does not call this; an
// absent fact is not evidence that the device serves nothing.
//
// # Two devices, one network
//
// An HA pair or a VRRP group can both report serving one network, each from
// its own address. The most recent observation wins the columns; the other
// device is reported as a candidate and not stored. A shared gateway is
// modelled as what it is — an FHRP group whose VIP is an `ip_addresses` row
// with `assigned_kind = 'fhrp_group'` — which the reads show beside the
// gateway (services/inventory-service prefix_gateway.go). A candidate is never
// promoted by a clear: the other device's next run re-asserts its own claim.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"
)

// MaxGatewaySourceRefLen bounds prefixes.gateway_source_ref.
const MaxGatewaySourceRefLen = 200

// ErrGatewayAssetUnknown is a reconcile for an asset that is not a live asset
// of the tenant. Nothing is written.
var ErrGatewayAssetUnknown = errors.New("identity/postgres: the gateway is not a live asset of the tenant")

// GatewayPrefix is one prefix a reconcile linked, or found claimed by a more
// recent observation of another device.
type GatewayPrefix struct {
	PrefixID string `json:"prefix_id"`
	Address  string `json:"address"`
}

// GatewayLinkResult is what one reconcile did.
type GatewayLinkResult struct {
	// Linked are the prefixes this device is now the gateway of.
	Linked []GatewayPrefix `json:"linked"`
	// Candidates are prefixes where the device holds an address but a more
	// recent observation names another gateway.
	Candidates []GatewayPrefix `json:"candidates"`
	// Cleared are the prefixes whose link to this device was removed: the
	// device no longer holds a listed address there.
	Cleared []string `json:"cleared"`
}

// gatewayRow is one locked prefix.
type gatewayRow struct {
	id         string
	gateway    sql.NullString
	observedAt sql.NullTime
}

// heldAddress is a listed address the device holds in one prefix.
type heldAddress struct {
	address, ipID string
}

// NormalizeGatewayAddresses parses, unmaps and de-duplicates addresses, in
// order, dropping what is not an address. It is the form the identity engine
// stores an address in.
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

// ReconcileGatewayLinks makes the prefix → gateway links for assetID match one
// interrogation's complete list of the device's own addresses on the networks
// it serves (see the file comment for the rules). Idempotent: the same list
// over the same addresses writes nothing new.
func (r *Repository) ReconcileGatewayLinks(ctx context.Context, tenantID, assetID, sourceRef string, observedAt time.Time, addresses []string) (GatewayLinkResult, error) {
	empty := GatewayLinkResult{Linked: []GatewayPrefix{}, Candidates: []GatewayPrefix{}, Cleared: []string{}}
	out := empty
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

		// The prefixes where the device HOLDS a listed address, scoped to that
		// prefix. The first listed address wins a prefix the device holds two
		// of.
		held := map[string]heldAddress{}
		var heldOrder []string
		if len(addrs) > 0 {
			rows, err := tx.QueryContext(ctx, `
				SELECT DISTINCT ON (p.id) p.id::text, ai.value, ai.id::text, c.ord
				  FROM unnest($3::text[]) WITH ORDINALITY AS c(addr, ord)
				  JOIN (`+AddressIdentifiersSQL+`) ai
				    ON ai.tenant_id = $1::uuid AND ai.asset_id::text = $2
				   AND ai.value = c.addr
				  JOIN public.prefixes p
				    ON p.tenant_id = $1::uuid AND p.id::text = ai.scope
				   AND p.status NOT IN ('rejected', 'archived')
				 ORDER BY p.id, c.ord`, tenantID, assetID, pq.Array(addrs))
			if err != nil {
				return fmt.Errorf("gateway links: reading held addresses: %w", err)
			}
			type heldRow struct {
				prefix, address, ipID string
				ord                   int64
			}
			var hs []heldRow
			for rows.Next() {
				var h heldRow
				if err := rows.Scan(&h.prefix, &h.address, &h.ipID, &h.ord); err != nil {
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
				held[h.prefix] = heldAddress{address: h.address, ipID: h.ipID}
				heldOrder = append(heldOrder, h.prefix)
			}
		}

		// Every prefix this run can change, locked in one order so two
		// gateways reconciling at once cannot deadlock.
		rows, err := tx.QueryContext(ctx, `
			SELECT id::text, gateway_asset_id::text, gateway_observed_at
			  FROM public.prefixes
			 WHERE tenant_id = $1::uuid
			   AND (id::text = ANY($3::text[]) OR gateway_asset_id::text = $2)
			 ORDER BY id
			   FOR UPDATE`, tenantID, assetID, pq.Array(heldOrder))
		if err != nil {
			return fmt.Errorf("gateway links: locking prefixes: %w", err)
		}
		locked := map[string]*gatewayRow{}
		var lockedOrder []string
		for rows.Next() {
			g := &gatewayRow{}
			if err := rows.Scan(&g.id, &g.gateway, &g.observedAt); err != nil {
				_ = rows.Close()
				return err
			}
			locked[g.id] = g
			lockedOrder = append(lockedOrder, g.id)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		_ = rows.Close()

		for _, id := range heldOrder {
			g, ok := locked[id]
			if !ok {
				continue // deleted between the two reads
			}
			h := held[id]
			current := g.gateway.String
			if current != "" && current != assetID && g.observedAt.Valid && g.observedAt.Time.After(observedAt) {
				// Another device's claim is the more recent observation: it
				// stays.
				out.Candidates = append(out.Candidates, GatewayPrefix{PrefixID: id, Address: h.address})
				continue
			}
			if err := writeGatewayLink(ctx, tx, tenantID, id, &assetID, h.ipID, sourceRef, observedAt); err != nil {
				return err
			}
			out.Linked = append(out.Linked, GatewayPrefix{PrefixID: id, Address: h.address})
		}

		// What this run no longer reaches: this device's link is cleared.
		// Another device's link is not touched.
		for _, id := range lockedOrder {
			if _, ok := held[id]; ok {
				continue
			}
			if locked[id].gateway.String == assetID {
				if err := writeGatewayLink(ctx, tx, tenantID, id, nil, "", "", time.Time{}); err != nil {
					return err
				}
				out.Cleared = append(out.Cleared, id)
			}
		}
		return nil
	})
	if err != nil {
		return empty, err
	}
	return out, nil
}

// writeGatewayLink sets the four columns (asset nil clears them), writing
// nothing when none changes. A refreshed observation time on an otherwise
// identical link is a change: it is what "most recent wins" compares.
func writeGatewayLink(ctx context.Context, tx *sql.Tx, tenantID, prefixID string, asset *string, ipID, sourceRef string, observedAt time.Time) error {
	var a, ip, ref, at any
	if asset != nil {
		a, ip, ref, at = *asset, ipID, sourceRef, observedAt
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE public.prefixes
		   SET gateway_asset_id    = $3::uuid,
		       gateway_ip_id       = $4::uuid,
		       gateway_source_ref  = $5,
		       gateway_observed_at = $6::timestamptz,
		       updated_at = now()
		 WHERE tenant_id = $1::uuid AND id::text = $2
		   AND (gateway_asset_id, gateway_ip_id, gateway_source_ref, gateway_observed_at)
		       IS DISTINCT FROM ($3::uuid, $4::uuid, $5::text, $6::timestamptz)`,
		tenantID, prefixID, a, ip, ref, at); err != nil {
		return fmt.Errorf("gateway links: writing prefix %s: %w", prefixID, err)
	}
	return nil
}
