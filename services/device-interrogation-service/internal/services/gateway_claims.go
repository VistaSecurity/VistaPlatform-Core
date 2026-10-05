package services

// A gateway owns its networks (slice A: ingest).
//
// An interrogated router, firewall or controller reports every network it
// serves in its `net.vlans` fact, and each entry with a prefix also carries the
// device's OWN address on that network (`gateway`). ensureVLANSegments has
// always turned the prefixes into segments; nothing read the addresses, so the
// router stayed known only on the networks a sensor had heard it on, and a
// stray record created from one of its addresses kept that address for good.
//
// Two things happen here, both for the asset the interrogation was dispatched
// to and both read from the fact rather than from any vendor's fields, so every
// producer that reports a gateway benefits:
//
//  1. Each gateway address goes to inventory-service as a CLAIMED address
//     (identity.IdentifierProvenance.Claimed) in a first-hand sighting bound to
//     the device by the identifiers it already holds. The engine attaches it
//     pinned, scoped to the segment it falls in, re-homes it from a
//     provisional or address-only holder, and opens a merge proposal against
//     any stronger holder rather than taking it (shared/identity/claimed.go).
//     One sighting per address, so one contested address does not hold up the
//     others.
//  2. The device's HOME segment is set: the segment of the address it was
//     interrogated at (its management address), not whichever of its
//     addresses a finding last arrived on. Claimed-address sightings never
//     place the device (identity.Sighting.ClaimsAddresses); this does.
//  3. (Slice B) The run's complete address list goes to inventory-service's
//     gateway-links route, which makes the device the gateway of every
//     segment where it now HOLDS one of them and of no other
//     (linkGatewaySegments; the rules are in shared/identity/postgres
//     segment_gateway.go).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/identity/sightingclient"
	sharednetwork "github.com/vistasecurity/vistaplatform/shared/network"
)

// reasonHomeSegment is the history reason on the entry that moves a device to
// its home segment.
const reasonHomeSegment = "home_segment_is_management_address"

// maxGatewayClaimsPerPost bounds one post of claimed-address sightings, well
// under inventory-service's MaxSightingsPerCall.
const maxGatewayClaimsPerPost = 100

// vlanGatewayAddresses returns the device's own address on each network a
// net.vlans fact reports, in the fact's order and without duplicates.
//
// An entry contributes only when it has BOTH a segmentable prefix (the same
// test ensureVLANSegments applies, so every address lands inside a segment
// that exists) and a gateway address inside that prefix that is neither the
// network nor, for IPv4, the broadcast address. An entry without a prefix — a
// Cisco VLAN database row — is skipped silently: it names a VLAN, not an
// address.
func vlanGatewayAddresses(value any) []string {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var entries []map[string]any
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		subnet, _ := e["subnet"].(string)
		gateway, _ := e["gateway"].(string)
		prefix, err := netip.ParsePrefix(strings.TrimSpace(subnet))
		if err != nil {
			continue
		}
		prefix, ok := sharednetwork.UnmapPrefix(prefix)
		if !ok || !segmentablePrefix(prefix) {
			continue
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(gateway))
		if err != nil {
			continue
		}
		addr = addr.Unmap().WithZone("")
		if !prefix.Contains(addr) || addr == prefix.Addr() || isIPv4Broadcast(prefix, addr) {
			continue
		}
		if v := addr.String(); !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// isIPv4Broadcast reports whether addr is the last address of an IPv4 prefix
// shorter than /31 (where the last address is a host).
func isIPv4Broadcast(p netip.Prefix, addr netip.Addr) bool {
	if !addr.Is4() || p.Bits() >= 31 {
		return false
	}
	b := p.Masked().Addr().As4()
	host := 32 - p.Bits()
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	n |= (1 << host) - 1
	return addr == netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

// selfGatewayAddresses collects the gateway addresses of every net.vlans fact
// the interrogation reported about the device ITSELF. A net.vlans fact bound
// to a subject (a device the controller manages) is that device's, not the
// interrogated one's, and is not claimed here: the claim has to come from a
// session to the device whose address it is.
func selfGatewayAddresses(fs []di.FactObservation) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range fs {
		if f.Key != facts.KeyNetVlans || !f.Subject.IsZero() {
			continue
		}
		for _, a := range vlanGatewayAddresses(f.Value) {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}

// gatewayClaimSighting is the first-hand sighting of one claimed address: the
// device's own address on a network it serves, read over the session the
// platform opened to it, bound to the device by the identifiers the platform
// already holds for it (inferred, as selfIdentitySighting binds the serial).
func gatewayClaimSighting(tenantID uuid.UUID, source identity.Source, at time.Time, address string, known []identity.SightedIdentifier) identity.Sighting {
	ids := []identity.SightedIdentifier{{
		Kind:  identity.KindIPAddress,
		Value: address,
		// The device's own configuration: self-reported, and a claim the
		// engine settles against any other holder.
		Provenance: identity.IdentifierProvenance{SelfReported: true, Claimed: true},
	}}
	return identity.Sighting{
		TenantID:    tenantID.String(),
		Source:      source,
		Channel:     identity.ChannelAuthenticatedSession,
		ObservedAt:  at,
		Confidence:  1,
		Ownership:   identity.OwnershipInternal,
		Identifiers: append(ids, known...),
	}
}

// reportsOwnNetworks reports whether the interrogation carried a net.vlans fact
// about the device ITSELF. Only then is the run a statement about which
// networks the device serves: a run that carried no such fact (a partial
// collection, a vendor that does not report networks) says nothing, and must
// not unlink the device from networks an earlier run linked.
func reportsOwnNetworks(fs []di.FactObservation) bool {
	for _, f := range fs {
		if f.Key == facts.KeyNetVlans && f.Subject.IsZero() {
			return true
		}
	}
	return false
}

// persistGatewayClaims claims each gateway address the device reported, sets
// its home segment, and then links it as the gateway of the networks where it
// now holds its address. Called from persist, after ensureVLANSegments, so
// every address resolves into the segment the same run created.
func (s *ObservationSink) persistGatewayClaims(ctx context.Context, tenantID, assetID uuid.UUID, source identity.Source, at time.Time, fs []di.FactObservation) error {
	if s.db == nil || !reportsOwnNetworks(fs) {
		return nil
	}
	addresses := selfGatewayAddresses(fs)
	var errs []error
	claimed := true
	if len(addresses) > 0 {
		if err := s.claimGatewayAddresses(ctx, tenantID, assetID, source, at, addresses); err != nil {
			errs = append(errs, err)
			claimed = false
		}
		if err := s.assertHomeSegment(ctx, tenantID, assetID, source); err != nil {
			errs = append(errs, err)
		}
	}
	// Claims that did not settle leave the links as the last settled run
	// wrote them: an unreachable route is not "the device serves nothing".
	if claimed {
		if err := s.linkGatewaySegments(ctx, tenantID, assetID, source, at, addresses); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// errNoGatewayLinker is a deployment fault, as errNoSightingPoster is: the
// installed poster cannot reach the gateway-links route.
var errNoGatewayLinker = errors.New("identity: the inventory-service client cannot reconcile gateway links")

// linkGatewaySegments hands inventory-service the run's COMPLETE list of the
// device's gateway addresses ( slice B, spec §3.3). inventory-service
// owns the segment → gateway link: it links the device to every segment where
// it now HOLDS one of these addresses — so a claim that opened a merge
// proposal instead links nothing — and unlinks it from every segment where it
// no longer does (shared/identity/postgres ReconcileGatewayLinks). An empty
// list from a run that did report its networks unlinks the device everywhere.
func (s *ObservationSink) linkGatewaySegments(ctx context.Context, tenantID, assetID uuid.UUID, source identity.Source, at time.Time, addresses []string) error {
	poster, err := sightingPoster(s.db)
	if err != nil {
		return err
	}
	linker, ok := poster.(sightingclient.GatewayLinker)
	if !ok {
		return errNoGatewayLinker
	}
	res, err := linker.ReconcileGatewayLinks(ctx, tenantID.String(), sightingclient.GatewayLinksRequest{
		AssetID: assetID.String(), SourceRef: source.Ref, ObservedAt: at, Addresses: addresses,
	})
	if err != nil {
		return fmt.Errorf("gateway links: %w", err)
	}
	if len(res.Cleared) > 0 || len(res.Candidates) > 0 {
		log.Printf("[ObservationSink] gateway links of asset %s: %d linked, %d kept as candidate, %d cleared",
			assetID, len(res.Linked), len(res.Candidates), len(res.Cleared))
	}
	return nil
}

// claimGatewayAddresses posts one claimed-address sighting per address.
func (s *ObservationSink) claimGatewayAddresses(ctx context.Context, tenantID, assetID uuid.UUID, source identity.Source, at time.Time, addresses []string) error {
	known, err := knownAssetIdentifiers(ctx, s.db, tenantID, assetID)
	if err != nil {
		return fmt.Errorf("gateway addresses: reading the device's identifiers: %w", err)
	}
	if len(known) == 0 {
		// Nothing binds a sighting to the device the session was opened to;
		// the address alone would be a new device to the engine. The same
		// floor the serial observes (persistIdentity).
		log.Printf("[ObservationSink] %d gateway address(es) of asset %s not sent: the asset holds no identifier to bind them to", len(addresses), assetID)
		return nil
	}
	poster, err := sightingPoster(s.db)
	if err != nil {
		return err
	}
	items := make([]sightingclient.Item, 0, len(addresses))
	for _, a := range addresses {
		items = append(items, sightingclient.Item{Sighting: gatewayClaimSighting(tenantID, source, at, a, known)})
	}
	for start := 0; start < len(items); start += maxGatewayClaimsPerPost {
		end := min(start+maxGatewayClaimsPerPost, len(items))
		results, err := poster.PostItems(ctx, tenantID.String(), items[start:end])
		if err != nil {
			return fmt.Errorf("gateway addresses: posting claims: %w", err)
		}
		for i, r := range results {
			address := addresses[start+i]
			switch {
			case r.Rejected():
				log.Printf("[ObservationSink] gateway address %s of asset %s refused: %s", address, assetID, strings.Join(r.Reasons, ", "))
			case r.AssetID != assetID.String():
				// Contested: another asset holds the address with stronger
				// identifiers, and Approvals has the merge proposal. Not this
				// device's to take.
				log.Printf("[ObservationSink] gateway address %s of asset %s resolved %s (asset %q, proposal %q); not attached",
					address, assetID, r.Outcome, r.AssetID, r.ProposalID)
			}
		}
	}
	return nil
}

// assertHomeSegment sets the device's network_segment_id to the segment of the
// address it was interrogated at ( §3.4).
//
// A device that routes several networks holds an address in each, so "its
// segment" read off whichever address a finding or a sighting arrived on is
// a different answer every run. The management address is the one the
// operator registered the device at and the platform reaches it on. When it
// is a name rather than an address, or falls in no segment (an upstream WAN
// address), the device's segment is left as it is: there is no home to
// assert, and guessing one of the routed segments is the bug this replaces.
//
// The location then follows the home segment only (ProjectSegmentLocation,
// which never overwrites a location somebody stated).
func (s *ObservationSink) assertHomeSegment(ctx context.Context, tenantID, assetID uuid.UUID, source identity.Source) error {
	var managementURL sql.NullString
	if err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT management_url FROM public.asset_management
			WHERE tenant_id = $1 AND asset_id = $2`, tenantID, assetID).Scan(&managementURL)
	}); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("home segment: reading the management address: %w", err)
	}
	addr, err := netip.ParseAddr(managementHost(managementURL.String))
	if err != nil {
		return nil
	}
	repo := s.store()
	scope, _, err := repo.ScopeForAddress(ctx, tenantID.String(), addr.Unmap().WithZone(""), "")
	if err != nil {
		return fmt.Errorf("home segment: scoping the management address: %w", err)
	}
	home, err := uuid.Parse(scope)
	if err != nil {
		// The tenant default: the management address is in no segment.
		return nil
	}
	ref := identity.AssetRef{TenantID: tenantID.String(), ID: assetID.String()}
	err = repo.RunInTx(ctx, tenantID.String(), func(bound *pgidentity.Repository) error {
		var previous sql.NullString
		err := bound.Tx().QueryRowContext(ctx, `
			SELECT network_segment_id::text FROM public.assets
			WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
			FOR UPDATE`, tenantID, assetID).Scan(&previous)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if previous.String != home.String() {
			if _, err := bound.Tx().ExecContext(ctx, `
				UPDATE public.assets SET network_segment_id = $3, updated_at = now()
				WHERE tenant_id = $1 AND id = $2`, tenantID, assetID, home); err != nil {
				return err
			}
			if err := bound.RecordHistory(ctx, identity.HistoryEntry{
				TenantID: ref.TenantID, AssetID: ref.ID, Action: identity.ActionUpdated, Source: source,
				Changes: map[string]any{
					"network_segment_id": map[string]string{"from": previous.String, "to": home.String()},
					"reason":             reasonHomeSegment,
				},
			}); err != nil {
				return err
			}
		}
		// The location follows the home segment only, and never replaces one
		// somebody stated.
		return bound.ProjectSegmentLocation(ctx, ref, home.String(), source)
	})
	if err != nil {
		return fmt.Errorf("home segment: %w", err)
	}
	return nil
}
