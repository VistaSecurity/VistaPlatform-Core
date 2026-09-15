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
// today and defaults to FALSE — the safe direction, because a segment wrongly
// marked dynamic silently stops ip_address deciding anything in it.
//
// The containment test runs in Go rather than as `$1::inet <<= value::inet`
// because `value` is free text: one malformed row would abort the whole query
// with a cast error, and the lookup would fail for every address in the tenant.
func (r *Repository) ScopeForAddress(ctx context.Context, tenantID string, addr netip.Addr, cloudNetworkRef string) (string, bool, error) {
	if !addr.IsValid() {
		// Not an address, so inside no segment. The default scope is still the
		// truthful answer.
		return identity.ScopeTenantDefault, false, nil
	}
	a := addr.Unmap().WithZone("")
	wantNetwork := strings.TrimSpace(cloudNetworkRef)

	var rows []segmentRow
	err := r.withTx(ctx, tenantID, func(tx *sql.Tx) error {
		rs, err := tx.QueryContext(ctx, `
			SELECT id::text, segment_type, value,
			       coalesce((metadata->>'dynamic')::boolean, false),
			       coalesce(cloud_network_ref, '')
			FROM public.network_segments
			WHERE tenant_id = $1 AND is_active = true
			  AND segment_type IN ('cidr', 'ip_range')`, tenantID)
		if err != nil {
			return fmt.Errorf("identity/postgres: read network segments: %w", err)
		}
		defer func() { _ = rs.Close() }()
		for rs.Next() {
			var x segmentRow
			if err := rs.Scan(&x.id, &x.segmentType, &x.value, &x.dynamic, &x.networkRef); err != nil {
				return fmt.Errorf("identity/postgres: scan network segment: %w", err)
			}
			rows = append(rows, x)
		}
		return rs.Err()
	})
	if err != nil {
		return "", false, err
	}

	// The CIDR matches are collected per prefix length rather than reduced to a
	// single "best" as they arrive, because the ambiguity that matters is
	// BETWEEN equally specific segments: 10.0.1.0/24 in vpc-a and 10.0.1.0/24
	// in vpc-b. Keeping only the first would hide exactly the case this
	// function was changed to answer.
	best := -1 // prefix bits of the best CIDR match; -1 = none yet
	var bestMatches []segmentRow
	var rangeMatches []segmentRow

	for _, x := range rows {
		// A segment belonging to ANOTHER cloud network is not a candidate for
		// an observation that says which network it was on. An unscoped
		// segment stays a candidate: an operator may legitimately have drawn
		// one over the same space.
		if wantNetwork != "" && x.networkRef != "" && x.networkRef != wantNetwork {
			continue
		}
		switch x.segmentType {
		case "cidr":
			p, perr := netip.ParsePrefix(strings.TrimSpace(x.value))
			if perr != nil {
				// A segment nobody can parse matches nothing. Skipping it is
				// right and skipping it QUIETLY is not the same as it not
				// existing — the segment UI validates on write, so a bad row
				// here is old data, not a live decision.
				continue
			}
			p = p.Masked()
			if p.Addr().BitLen() != a.BitLen() || !p.Contains(a) {
				continue
			}
			switch {
			case p.Bits() > best:
				best, bestMatches = p.Bits(), []segmentRow{x}
			case p.Bits() == best:
				bestMatches = append(bestMatches, x)
			}
		case "ip_range":
			lo, hi, ok := parseRange(x.value)
			if !ok || lo.BitLen() != a.BitLen() {
				continue
			}
			if a.Compare(lo) >= 0 && a.Compare(hi) <= 0 {
				rangeMatches = append(rangeMatches, x)
			}
		}
	}

	if chosen, ok := pickSegment(bestMatches, wantNetwork); ok {
		return chosen.id, chosen.dynamic, nil
	}
	if chosen, ok := pickSegment(rangeMatches, wantNetwork); ok {
		return chosen.id, chosen.dynamic, nil
	}
	return identity.ScopeTenantDefault, false, nil
}

// pickSegment chooses among equally-good matches, or refuses to.
//
// With a network ref, a segment in THAT network beats an unscoped one: the
// caller told us where it was standing and a segment drawn for that network is
// the more precise answer to the same question.
//
// Without one, matches that disagree about which cloud network they belong to
// are a question the caller did not answer. Returning "no segment" — and so the
// tenant-wide default — is the honest outcome: the address will be recorded and
// will simply not decide an identity, which is exactly right for an address
// that names two places. Picking the first row would make an asset's identity
// depend on query order.
func pickSegment(matches []segmentRow, wantNetwork string) (segmentRow, bool) {
	switch len(matches) {
	case 0:
		return segmentRow{}, false
	case 1:
		return matches[0], true
	}
	if wantNetwork != "" {
		for _, m := range matches {
			if m.networkRef == wantNetwork {
				return m, true
			}
		}
		// Every match is unscoped; they are all the same answer.
		return matches[0], true
	}
	for _, m := range matches {
		if m.networkRef != matches[0].networkRef {
			return segmentRow{}, false
		}
	}
	return matches[0], true
}

// segmentRow is one `network_segments` row, as much of it as scoping needs.
type segmentRow struct {
	id          string
	segmentType string
	value       string
	dynamic     bool
	networkRef  string
}

// parseRange splits "10.0.0.1-10.0.0.254" into its bounds. A range whose ends
// are reversed is accepted and swapped: an operator typing them the other way
// round meant the same range.
func parseRange(v string) (netip.Addr, netip.Addr, bool) {
	parts := strings.SplitN(strings.TrimSpace(v), "-", 2)
	if len(parts) != 2 {
		return netip.Addr{}, netip.Addr{}, false
	}
	lo, err := netip.ParseAddr(strings.TrimSpace(parts[0]))
	if err != nil {
		return netip.Addr{}, netip.Addr{}, false
	}
	hi, err := netip.ParseAddr(strings.TrimSpace(parts[1]))
	if err != nil {
		return netip.Addr{}, netip.Addr{}, false
	}
	lo, hi = lo.Unmap().WithZone(""), hi.Unmap().WithZone("")
	if lo.BitLen() != hi.BitLen() {
		return netip.Addr{}, netip.Addr{}, false
	}
	if lo.Compare(hi) > 0 {
		lo, hi = hi, lo
	}
	return lo, hi, true
}
