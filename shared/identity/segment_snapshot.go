package identity

import (
	"net/netip"
	"strings"
)

// SegmentTypeCIDR is the only scope type a [SegmentSnapshot] carries: an IPAM
// prefix (DCIM row 1.6 retired the operator-drawn segments, and with them the
// `ip_range` and `domain` scope types; ADR-0010 D3).
const SegmentTypeCIDR = "cidr"

// NetworkSegment is one scope an identifier can be placed in: a tenant's IPAM
// prefix in the global VRF, as much of it as scoping an identifier needs. The
// name predates the prefix model; the scope it carries is the prefix id.
type NetworkSegment struct {
	// ID is the scope an identifier placed in this prefix carries: the
	// prefix's uuid in the SQL store.
	ID string `json:"id"`
	// Type is [SegmentTypeCIDR].
	Type string `json:"type"`
	// Value is the prefix's CIDR.
	Value string `json:"value"`
	// CloudNetworkRef is the cloud network (VPC / VNet) the prefix belongs
	// to, empty for an on-premises prefix. See [Repository.ScopeForAddress]
	// for why a CIDR alone is not unique.
	CloudNetworkRef string `json:"cloud_network_ref,omitempty"`
	// Dynamic is the prefix's STORED DHCP posture (`prefixes.dhcp_managed`).
	// Nothing a collector saw on THIS run reaches it: a controller that
	// reports DHCP on a network records that on the prefix, and the next
	// snapshot reads it ( item 7).
	Dynamic bool `json:"dynamic,omitempty"`
}

// SegmentSnapshot is one tenant's scoping prefixes, read once.
//
// It exists so an intake that scopes several identifiers — a host with three
// addresses and two names — asks the store ONE question per sighting instead
// of one per identifier, and so every identifier in that sighting is scoped
// against the same topology even if an operator edits a prefix mid-call.
//
// The scoping rules live here, as pure functions of the snapshot, and BOTH
// repository implementations answer [Repository.ScopeForAddress] through
// [SegmentSnapshot.ScopeForAddress]. That is the point: the per-address
// lookup and [Intake] cannot disagree about which prefix an address is in,
// because they are one function.
type SegmentSnapshot struct {
	TenantID string `json:"tenant_id"`
	// Prefixes are the tenant's IPAM prefixes in the global VRF, each as a
	// `cidr` NetworkSegment whose ID is the prefix id, whose Dynamic is the
	// prefix's DHCP posture (`prefixes.dhcp_managed`) and whose
	// CloudNetworkRef is the prefix's. An address is scoped to the
	// longest-matching prefix (shared/dcim/ipam.LongestMatch's rule).
	Prefixes []NetworkSegment `json:"prefixes,omitempty"`
}

// ScopeForAddress is [Repository.ScopeForAddress] over the snapshot: the most
// specific prefix containing the address, else [ScopeTenantDefault]. It never
// returns an empty scope.
//
// cloudNetworkRef narrows the candidates to prefixes in that network or in
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
	if chosen, ok := longestMatch(s.Prefixes, a, want); ok {
		return chosen.ID, chosen.Dynamic
	}
	return ScopeTenantDefault, false
}

// IsDynamic reports whether the prefix with this id hands addresses out
// dynamically, by its stored posture. The tenant default and an id the
// snapshot does not hold answer false.
func (s SegmentSnapshot) IsDynamic(scope string) bool {
	if scope == "" || scope == ScopeTenantDefault {
		return false
	}
	for _, p := range s.Prefixes {
		if p.ID == scope {
			return p.Dynamic
		}
	}
	return false
}

// longestMatch is the CIDR rule over one list: the most specific `cidr` entry
// containing a, ambiguity between equally specific entries in two cloud
// networks resolved by pickSegment.
func longestMatch(list []NetworkSegment, a netip.Addr, want string) (NetworkSegment, bool) {
	best := -1
	var matches []NetworkSegment
	for _, seg := range list {
		if seg.Type != SegmentTypeCIDR {
			continue
		}
		if want != "" && seg.CloudNetworkRef != "" && seg.CloudNetworkRef != want {
			continue
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(seg.Value))
		if err != nil {
			continue
		}
		p = p.Masked()
		if p.Addr().BitLen() != a.BitLen() || !p.Contains(a) {
			continue
		}
		switch {
		case p.Bits() > best:
			best, matches = p.Bits(), []NetworkSegment{seg}
		case p.Bits() == best:
			matches = append(matches, seg)
		}
	}
	return pickSegment(matches, want)
}

// pickSegment chooses among equally good matches, or refuses to.
//
// With a network ref, a prefix in THAT network beats an unscoped one: the
// caller told us where it was standing. Without one, matches that disagree
// about which cloud network they belong to are a question the caller did not
// answer, and the honest outcome is no prefix — the tenant default, where the
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
