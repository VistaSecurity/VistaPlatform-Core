package identity

import (
	"net/netip"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/network"
)

// Segment types a [SegmentSnapshot] carries. `cloud_vpc` segments are not in
// the snapshot at all: they carry no address or name predicate, so nothing can
// be scoped by one.
const (
	SegmentTypeCIDR    = "cidr"
	SegmentTypeIPRange = "ip_range"
	SegmentTypeDomain  = "domain"
)

// NetworkSegment is one active tenant network segment, as much of it as scoping
// an identifier needs.
type NetworkSegment struct {
	// ID is the scope an identifier placed in this segment carries: the
	// segment's uuid in the SQL store.
	ID string `json:"id"`
	// Type is one of the SegmentType* constants.
	Type string `json:"type"`
	// Value is the segment's literal: a CIDR, a "start-end" range, or a domain
	// pattern (shared/network.MatchesDomainPattern).
	Value string `json:"value"`
	// CloudNetworkRef is the cloud network (VPC / VNet) the segment belongs
	// to, empty for an operator-drawn LAN segment. See
	// [Repository.ScopeForAddress] for why a CIDR alone is not unique.
	CloudNetworkRef string `json:"cloud_network_ref,omitempty"`
	// Dynamic is the segment's STORED, EFFECTIVE DHCP posture: the value the
	// precedence rule (operator > measured > inferred,
	// shared/identity/postgres/segment_posture.go) already wrote, plus the one
	// reading identity adds — a segment learned with `dhcp: unknown` counts as
	// dynamic. It is meaningful for cidr and ip_range segments only; a domain
	// segment hands out no addresses and is never dynamic.
	//
	// Nothing a collector saw on THIS run reaches it. A controller that reports
	// DHCP on a network records that as a measured posture, and the next
	// snapshot reads the effective value — so an operator who marked the
	// segment static is not overruled by the next run's overlay ( item 7).
	Dynamic bool `json:"dynamic,omitempty"`
}

// SegmentSnapshot is one tenant's active segments, read once.
//
// It exists so an intake that scopes several identifiers — a host with three
// addresses and two names — asks the store ONE question per sighting instead
// of one per identifier, and so every identifier in that sighting is scoped
// against the same topology even if an operator edits a segment mid-call.
//
// The scoping rules live here, as pure functions of the snapshot, and BOTH
// repository implementations answer [Repository.ScopeForAddress] through
// [SegmentSnapshot.ScopeForAddress]. That is the point: the per-address
// lookup and [Intake] cannot disagree about which segment an address is in,
// because they are one function.
type SegmentSnapshot struct {
	TenantID string `json:"tenant_id"`
	// Segments are in the store's stable order (creation order). The order
	// matters only for the domain rule, where the first matching pattern wins,
	// exactly as shared/network.MatchSegment has always ranked them.
	Segments []NetworkSegment `json:"segments,omitempty"`
}

// ScopeForAddress is [Repository.ScopeForAddress] over the snapshot: the most
// specific `cidr` segment containing the address, else an `ip_range` segment
// containing it, else [ScopeTenantDefault]. It never returns an empty scope.
//
// cloudNetworkRef narrows the candidates to segments in that network or in
// none; equally specific matches in two DIFFERENT networks with no ref to
// choose between them answer [ScopeTenantDefault] (see pickSegment).
//
// The tenant default is never dynamic: it is not a DHCP range, it is
// "everywhere else".
func (s SegmentSnapshot) ScopeForAddress(addr netip.Addr, cloudNetworkRef string) (scope string, dynamic bool) {
	if !addr.IsValid() {
		return ScopeTenantDefault, false
	}
	a := addr.Unmap().WithZone("")
	want := strings.TrimSpace(cloudNetworkRef)

	// The CIDR matches are collected per prefix length rather than reduced to
	// a single "best" as they arrive, because the ambiguity that matters is
	// BETWEEN equally specific segments: 10.0.1.0/24 in vpc-a and 10.0.1.0/24
	// in vpc-b. Keeping only the first would hide exactly that case.
	best := -1
	var bestMatches, rangeMatches []NetworkSegment
	for _, seg := range s.Segments {
		// A segment belonging to ANOTHER cloud network is not a candidate for
		// an observation that says which network it was on. An unscoped
		// segment stays a candidate.
		if want != "" && seg.CloudNetworkRef != "" && seg.CloudNetworkRef != want {
			continue
		}
		switch seg.Type {
		case SegmentTypeCIDR:
			p, err := netip.ParsePrefix(strings.TrimSpace(seg.Value))
			if err != nil {
				// A segment nobody can parse matches nothing. The segment UI
				// validates on write, so a bad row here is old data.
				continue
			}
			p = p.Masked()
			if p.Addr().BitLen() != a.BitLen() || !p.Contains(a) {
				continue
			}
			switch {
			case p.Bits() > best:
				best, bestMatches = p.Bits(), []NetworkSegment{seg}
			case p.Bits() == best:
				bestMatches = append(bestMatches, seg)
			}
		case SegmentTypeIPRange:
			lo, hi, ok := parseSegmentRange(seg.Value)
			if !ok || lo.BitLen() != a.BitLen() {
				continue
			}
			if a.Compare(lo) >= 0 && a.Compare(hi) <= 0 {
				rangeMatches = append(rangeMatches, seg)
			}
		}
	}
	if chosen, ok := pickSegment(bestMatches, want); ok {
		return chosen.ID, chosen.Dynamic
	}
	if chosen, ok := pickSegment(rangeMatches, want); ok {
		return chosen.ID, chosen.Dynamic
	}
	return ScopeTenantDefault, false
}

// ScopeForName is THE domain rule: the first `domain` segment whose pattern
// matches the name (shared/network.MatchSegment, the rule
// inventory-service's segment service and device-interrogation's
// scopeResolver both applied through two local copies of the query), and false
// when none does.
//
// The name is folded the way identifiers are stored — lower case, no trailing
// dot — before it is matched, so `Printer.Corp.Example.` and
// `printer.corp.example` land in the same segment.
func (s SegmentSnapshot) ScopeForName(name string) (string, bool) {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if n == "" {
		return "", false
	}
	var candidates []network.Segment
	for _, seg := range s.Segments {
		if seg.Type == SegmentTypeDomain {
			candidates = append(candidates, network.Segment{ID: seg.ID, Type: seg.Type, Value: seg.Value})
		}
	}
	match, ok := network.MatchSegment(candidates, "", n)
	if !ok {
		return "", false
	}
	return match.ID, true
}

// IsDynamic reports whether the segment with this id hands addresses out
// dynamically, by its stored effective posture. The tenant default, a domain
// segment and an id the snapshot does not hold all answer false.
func (s SegmentSnapshot) IsDynamic(scope string) bool {
	if scope == "" || scope == ScopeTenantDefault {
		return false
	}
	for _, seg := range s.Segments {
		if seg.ID == scope {
			return seg.Dynamic && seg.Type != SegmentTypeDomain
		}
	}
	return false
}

// pickSegment chooses among equally good matches, or refuses to.
//
// With a network ref, a segment in THAT network beats an unscoped one: the
// caller told us where it was standing. Without one, matches that disagree
// about which cloud network they belong to are a question the caller did not
// answer, and the honest outcome is no segment — the tenant default, where the
// address is recorded and decides nothing. Picking the first row would make an
// asset's identity depend on query order.
func pickSegment(matches []NetworkSegment, wantNetwork string) (NetworkSegment, bool) {
	switch len(matches) {
	case 0:
		return NetworkSegment{}, false
	case 1:
		return matches[0], true
	}
	if wantNetwork != "" {
		for _, m := range matches {
			if m.CloudNetworkRef == wantNetwork {
				return m, true
			}
		}
		// Every match is unscoped; they are all the same answer.
		return matches[0], true
	}
	for _, m := range matches {
		if m.CloudNetworkRef != matches[0].CloudNetworkRef {
			return NetworkSegment{}, false
		}
	}
	return matches[0], true
}

// parseSegmentRange splits "10.0.0.1-10.0.0.254" into its bounds. Reversed
// ends are accepted and swapped: an operator typing them the other way round
// meant the same range.
func parseSegmentRange(v string) (netip.Addr, netip.Addr, bool) {
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
