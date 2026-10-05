package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// ScopeForAddress implements [identity.Repository].
//
// It is THE answer to "where was I standing?", and it lives here rather than in
// each service that builds observations so inventory-service and
// device-interrogation-service cannot disagree about which segment an address
// is in. One more spelling of this lookup is one more dedupe key.
//
// The rules, in order:
//
//   - the most specific ACTIVE `cidr` segment containing the address wins (a
//     /28 carved out of a /24 is the more precise answer);
//   - failing that, an `ip_range` segment whose bounds contain it;
//   - failing that, [identity.ScopeTenantDefault] — the tenant-wide default
//     space. NEVER an empty scope. "This tenant has no segments" is a fact
//     about their topology, not an absence of one, and treating it as an
//     absence is what made one host, observed three times, into three assets.
//
// `domain` and `cloud_vpc` segments are not consulted: neither can be decided
// from an address alone. A hostname-only observation is the caller's to scope
// (inventory-service still asks its segment service for a domain match), and
// when nothing matches the default scope is the answer there too.
//
// `dynamic` comes from the segment's `metadata->>'dynamic'`. There is no column
// for it yet (ADR-0002 D3's follow-up "decide the dynamic-segment flag
// semantics" is still open), so this reads the one place an operator can set it
// today and defaults to FALSE — the safe direction for a segment nobody said
// anything about, because a segment wrongly marked dynamic silently stops
// ip_address deciding anything in it.
//
// One exception, and it is a statement rather than a silence: a segment LEARNED
// from a device that reported the network but not its DHCP posture carries
// `metadata->>'dhcp' = 'unknown'` (device-interrogation's net.vlans intake). For
// identity that counts as dynamic. The device told us a network exists and that
// it did not measure whether leases are handed out on it; letting a bare
// address vote there is how two devices that held the same lease become one
// asset — in every later run and every other intake, not only the run that
// learned the segment. The STORED value stays `unknown`: this is how the
// identity layer reads an unknown, not a claim that DHCP was observed.
//
// The containment test runs in Go rather than as `$1::inet <<= value::inet`
// because `value` is free text: one malformed row would abort the whole query
// with a cast error, and the lookup would fail for every address in the tenant.
//
// The matching itself is [identity.SegmentSnapshot.ScopeForAddress] over
// [Repository.SegmentSnapshot] — one implementation shared with the in-memory
// store and with identity.Intake, so the per-address lookup and the intake
// cannot disagree about which segment an address is in.
func (r *Repository) ScopeForAddress(ctx context.Context, tenantID string, addr netip.Addr, cloudNetworkRef string) (string, bool, error) {
	if !addr.IsValid() {
		// Not an address, so inside no segment. The default scope is still the
		// truthful answer — and it needs no read.
		return identity.ScopeTenantDefault, false, nil
	}
	snap, err := r.SegmentSnapshot(ctx, tenantID)
	if err != nil {
		return "", false, err
	}
	scope, dynamic := snap.ScopeForAddress(addr, cloudNetworkRef)
	return scope, dynamic, nil
}

// SegmentSnapshot implements [identity.Repository]: every active `cidr`,
// `ip_range` and `domain` segment of the tenant, in creation order, in one
// read.
//
// `dynamic` is the STORED effective posture (`metadata->>'dynamic'`, which
// segment_posture.go's one-statement rule keeps equal to the highest-ranked
// source's statement), OR'd with `metadata->>'dhcp' = 'unknown'` — see
// [Repository.ScopeForAddress] for why an unmeasured learned segment reads as
// dynamic. It is never read from `dynamic_by_source`: precedence is decided
// once, at write time, and a reader that re-derived it would be a second copy
// of the rule. A domain segment's posture is irrelevant and reported false.
func (r *Repository) SegmentSnapshot(ctx context.Context, tenantID string) (identity.SegmentSnapshot, error) {
	snap := identity.SegmentSnapshot{TenantID: tenantID}
	err := r.withTx(ctx, tenantID, func(tx *sql.Tx) error {
		rs, err := tx.QueryContext(ctx, `
			SELECT id::text, segment_type, value,
			       segment_type <> 'domain' AND (
			           coalesce((metadata->>'dynamic')::boolean, false)
			           OR coalesce(metadata->>'dhcp', '') = 'unknown'),
			       coalesce(cloud_network_ref, '')
			FROM public.network_segments
			WHERE tenant_id = $1 AND is_active = true
			  AND segment_type IN ('cidr', 'ip_range', 'domain')
			ORDER BY created_at, id`, tenantID)
		if err != nil {
			return fmt.Errorf("identity/postgres: read network segments: %w", err)
		}
		defer func() { _ = rs.Close() }()
		for rs.Next() {
			var s identity.NetworkSegment
			if err := rs.Scan(&s.ID, &s.Type, &s.Value, &s.Dynamic, &s.CloudNetworkRef); err != nil {
				return fmt.Errorf("identity/postgres: scan network segment: %w", err)
			}
			s.CloudNetworkRef = strings.TrimSpace(s.CloudNetworkRef)
			snap.Segments = append(snap.Segments, s)
		}
		return rs.Err()
	})
	if err != nil {
		return identity.SegmentSnapshot{}, err
	}
	return snap, nil
}
