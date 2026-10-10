// Package addrscope is the platform's ONE definition of which addresses are
// private by address class.
//
// Before it there were four, and they disagreed: inventory-service's
// classifier, discovery-processor's fallback, automatic scanning and probe
// consent each wrote their own `IsPrivate() || ...` ladder, so one host could
// be an internal candidate to one component and a third party to the next
// ( F3). Everything that asks "is this address the tenant's by address
// class?" now asks [Classify], and a guard (package addrscopeguard, run by
// `make audit`) fails when a new copy appears anywhere under shared/,
// services/, sensor/ or device-agent/.
//
// The scopes:
//
//   - [Private]: RFC 1918, RFC 4193 (IPv6 ULA, fc00::/7), loopback and
//     link-local unicast. Nobody else's service lives there as seen from inside
//     the tenant's network.
//   - [CGNAT]: RFC 6598 shared address space, 100.64.0.0/10. Overlay networks
//     (Tailscale, ZeroTier) and mobile carriers hand it out.
//   - [Public]: every other valid address, including the documentation ranges,
//     multicast and the unspecified address. "Not globally routable" does not
//     make an address the tenant's.
//   - [Invalid]: not an address.
//
// Two predicates are derived from it, and they differ on purpose ( D1):
//
//   - [IsTenantAddressable] (Private or CGNAT) decides OWNERSHIP
//     classification: an address that matches no declared segment but is in
//     either class is an internal candidate ("unknown"), never "third_party".
//     A CGNAT host is far more often the tenant's own overlay than a carrier's
//     other customer, and routing it to external connections hid it from
//     inventory.
//   - [MayAutoProbe] (Private only) decides AUTOMATIC ACTIVE PROBING. CGNAT is
//     carrier space with other operators' customers on the far side, so it is
//     probed automatically only when the tenant DECLARED a segment over it —
//     a check every caller already makes separately. Classification widening
//     to CGNAT does not widen consent.
//
// Pure Go with no imports beyond the standard library: the standalone sensor
// reaches this package through shared/probeconsent, so it must stay CGO-free
// and free of platform-internal coupling.
package addrscope

import (
	"net"
	"net/netip"
	"strings"
)

// Scope is the address class of one address.
type Scope int

const (
	// Invalid is not an address: empty, unparseable, or a hostname.
	Invalid Scope = iota
	// Private is RFC 1918, RFC 4193 (ULA), loopback or link-local unicast.
	Private
	// CGNAT is RFC 6598 shared address space, 100.64.0.0/10.
	CGNAT
	// Public is every other valid address.
	Public
)

// String is the scope's name, for logs and test failures.
func (s Scope) String() string {
	switch s {
	case Private:
		return "private"
	case CGNAT:
		return "cgnat"
	case Public:
		return "public"
	default:
		return "invalid"
	}
}

// The address-class data. These are the only RFC 1918 / RFC 4193 / RFC 6598
// literals the guard test allows outside test files.
var (
	privateRanges = [...]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),     // RFC 1918
		netip.MustParsePrefix("172.16.0.0/12"),  // RFC 1918
		netip.MustParsePrefix("192.168.0.0/16"), // RFC 1918
		netip.MustParsePrefix("fc00::/7"),       // RFC 4193 unique local
	}
	cgnatRange = netip.MustParsePrefix("100.64.0.0/10") // RFC 6598
)

// PrivateRanges returns the RFC 1918 and RFC 4193 prefixes — the routable
// private ranges, without loopback and link-local. For callers that reason in
// prefixes or intervals rather than single addresses (the dispatch guard). A
// fresh slice each call, so a caller cannot edit the definition.
func PrivateRanges() []netip.Prefix {
	return append([]netip.Prefix(nil), privateRanges[:]...)
}

// CGNATRange returns RFC 6598 shared address space, 100.64.0.0/10.
func CGNATRange() netip.Prefix { return cgnatRange }

// Normalize unmaps an IPv4-mapped IPv6 address and strips any zone, so
// ::ffff:10.0.0.1 and fe80::1%eth0 are judged as 10.0.0.1 and fe80::1.
func Normalize(addr netip.Addr) netip.Addr {
	return addr.Unmap().WithZone("")
}

// Classify returns the address class of addr after [Normalize].
func Classify(addr netip.Addr) Scope {
	if !addr.IsValid() {
		return Invalid
	}
	addr = Normalize(addr)
	switch {
	case IsPrivateRange(addr), addr.IsLoopback(), addr.IsLinkLocalUnicast():
		return Private
	case cgnatRange.Contains(addr):
		return CGNAT
	default:
		return Public
	}
}

// Parse reads a textual address — whitespace trimmed, zone stripped,
// IPv4-mapped unmapped. ok is false for anything that is not a literal
// address.
func Parse(s string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, false
	}
	return Normalize(addr), true
}

// ClassifyString is [Classify] over a textual address; anything that does not
// parse is [Invalid].
func ClassifyString(s string) Scope {
	addr, ok := Parse(s)
	if !ok {
		return Invalid
	}
	return Classify(addr)
}

// ClassifyIP is [Classify] over a net.IP; nil and malformed values are
// [Invalid].
func ClassifyIP(ip net.IP) Scope {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return Invalid
	}
	return Classify(addr)
}

// IsPrivateRange reports whether addr is in RFC 1918 or RFC 4193 space —
// [Private] without loopback and link-local. A prefix or a scheduled scan
// cares about the difference: loopback and link-local are not ranges a tenant
// declares or an unattended sweep visits.
func IsPrivateRange(addr netip.Addr) bool {
	addr = Normalize(addr)
	for _, p := range privateRanges {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// IsTenantAddressable reports whether addr is an internal candidate by address
// class alone: [Private] or [CGNAT]. An address that matches no declared
// segment and passes this is classified "unknown" (review it), never
// "third_party".
func IsTenantAddressable(addr netip.Addr) bool {
	s := Classify(addr)
	return s == Private || s == CGNAT
}

// MayAutoProbe reports whether addr may be probed automatically on address
// class alone: [Private] only. CGNAT needs a declared segment, which callers
// check separately; exclusions are also the caller's, and win over this.
func MayAutoProbe(addr netip.Addr) bool {
	return Classify(addr) == Private
}
