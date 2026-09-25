// Package probeconsent decides whether an address is the tenant's own for the
// purpose of AUTOMATIC active probing — traffic nobody asked for in the moment.
//
// The owner's rule (Q10,: "we need to probe owned assets if the
// customer owns them and they configure them within their own tenant. we never
// want to, by default, run a blanket scan on third parties". Passive capture sees
// every destination a tenant's hosts talk to, vendors and SaaS included, so a
// component that reacts to what it saw passively — the sensor's TLS enricher is
// the one this was written for — has to be able to tell the two apart without
// asking the platform about every destination.
//
// An address is OWNED when it is
//
//   - private by address class: RFC 1918, RFC 4193 (ULA), loopback or
//     link-local unicast — see [OwnedByAddressClass];
//   - inside a prefix the tenant DECLARED as one of its network segments
//     (delivered by the platform in [OwnedNetworks.Prefixes]); or
//   - an endpoint the tenant elevated to a monitored asset (delivered in
//     [OwnedNetworks.Endpoints]) — the one place a public address the tenant
//     does not own is nevertheless "configured within their own tenant".
//
// and it is not inside an EXCLUDED prefix ([OwnedNetworks.Excluded]): a
// segment the tenant marked sensitive or active-probes-disabled, or a range on
// its automatic-scan exclusion list. An exclusion beats everything, including
// the third-party opt-in — "do not probe this" is the more specific statement.
//
// Everything else is a third party. That includes RFC 6598 carrier-grade NAT
// (100.64.0.0/10): it is carrier space with other operators' customers on the
// far side, the same call shared/network.PrefixNetworkType and the dispatch
// guard make for it. A tenant whose own overlay lives there (Tailscale does)
// declares a segment over it, which is exactly the statement of ownership this
// package reads.
//
// Pure Go, no CGO, no database: the standalone sensor imports it (see
// CLAUDE.md on what the sensor may depend on), and so does sensor-manager, which
// builds the wire shape. Both halves therefore read the same definition.
package probeconsent

import (
	"net"
	"net/netip"
	"strconv"
	"strings"

	sharednetwork "github.com/vistasecurity/vistaplatform/shared/network"
)

// OwnedNetworks is the platform's statement, delivered to a sensor on its
// heartbeat, of which public space this tenant has claimed as its own.
//
// Only what the address class cannot already prove is sent. Private space is
// owned by definition and is not listed; a LEARNED segment (one the platform
// read off an interrogated device's VLAN table) is never listed, because a
// firewall reporting its ISP transit network is saying where it is connected,
// not what it owns.
type OwnedNetworks struct {
	// Prefixes are CIDRs from the tenant's declared network segments.
	Prefixes []string `json:"prefixes"`
	// Endpoints are "ip:port" pairs the tenant elevated from an external
	// connection to a monitored asset. An endpoint, not an address: the
	// tenant elevated one service, not every port on a vendor's host.
	Endpoints []string `json:"endpoints"`
	// Excluded are CIDRs the tenant said must not be actively probed: segments
	// marked sensitive or active-probes-disabled, and its automatic-scan
	// exclusions. They win over every other rule here.
	Excluded []string `json:"excluded"`
	// Incomplete is set when the platform could not build the set. Prefixes
	// and Endpoints are then empty on purpose — ownership it could not
	// refresh must not keep granting probes — and Excluded holds only the
	// exclusions it could read, so a sensor ADDS them to the exclusions it
	// already had rather than replacing them.
	Incomplete bool `json:"incomplete,omitempty"`
}

// Scope is OwnedNetworks parsed once, for lookups on a hot path.
//
// The zero Scope owns private space and nothing else, which is also what a
// sensor talking to a platform too old to send OwnedNetworks gets: absent
// consent is not consent.
type Scope struct {
	prefixes  []netip.Prefix
	endpoints map[netip.AddrPort]struct{}
	excluded  []netip.Prefix
}

// Parse builds a Scope. An entry that does not parse is dropped rather than
// failing the whole set — one malformed segment must not take a tenant's
// declared estate back to "private only" — and is counted in rejected so the
// caller can log it.
func Parse(n OwnedNetworks) (scope Scope, rejected int) {
	prefixes, rejected := parsePrefixes(n.Prefixes)
	for _, p := range prefixes {
		// Too broad to be anybody's: not ownership, whoever sent it — the
		// platform filters these too, and a sensor's local list is held to the
		// same rule. Exclusions are NOT capped: a wide exclusion only ever
		// withholds probes.
		if TooBroadToClaim(p) {
			rejected++
			continue
		}
		scope.prefixes = append(scope.prefixes, p)
	}
	var bad int
	scope.excluded, bad = parsePrefixes(n.Excluded)
	rejected += bad
	for _, raw := range n.Endpoints {
		ap, err := netip.ParseAddrPort(strings.TrimSpace(raw))
		if err != nil || ap.Addr().Zone() != "" || ap.Port() == 0 {
			rejected++
			continue
		}
		if scope.endpoints == nil {
			scope.endpoints = make(map[netip.AddrPort]struct{})
		}
		scope.endpoints[netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())] = struct{}{}
	}
	return scope, rejected
}

// Merge applies a delivered set on top of the scope a sensor already holds. A
// complete set replaces it outright. An Incomplete one (the platform could not
// build the set) carries no ownership and only the exclusions the platform
// could read, so the result owns nothing beyond private space and excludes
// everything either side knew: losing an exclusion because a read failed would
// be the unsafe direction.
func Merge(prev Scope, n OwnedNetworks) (Scope, int) {
	next, rejected := Parse(n)
	if !n.Incomplete {
		return next, rejected
	}
	out := Scope{excluded: append(append([]netip.Prefix(nil), prev.excluded...), next.excluded...)}
	return out, rejected
}

// ExcludedStrings is the scope's exclusions in wire form, so a sensor can
// record what is in force after a Merge.
func (s Scope) ExcludedStrings() []string {
	out := make([]string, 0, len(s.excluded))
	for _, p := range s.excluded {
		out = append(out, p.String())
	}
	return out
}

// WithoutOwnership is the scope with every declared prefix and elevated
// endpoint dropped and the exclusions kept: what a sensor falls back to when
// its delivered ownership has gone stale.
func (s Scope) WithoutOwnership() Scope {
	return Scope{excluded: s.excluded}
}

// MayProbe is the whole decision for an AUTOMATIC active probe of ip:port —
// one nobody asked for in the moment: never inside an exclusion; always when
// the destination is the tenant's own; otherwise only when the tenant opted in
// to probing third parties. A destination that is not a literal address is
// never probed: it cannot be placed on either side of any of these lines.
func (s Scope) MayProbe(ip string, port int, thirdPartyOptIn bool) bool {
	addr, ok := parseAddr(ip)
	if !ok || s.excludes(addr) {
		return false
	}
	return s.owns(addr, port) || thirdPartyOptIn
}

// Owns reports whether ip:port is the tenant's own and not excluded. Anything
// that is not a literal address is NOT owned: an unknown destination cannot be
// shown to be the tenant's.
func (s Scope) Owns(ip string, port int) bool {
	addr, ok := parseAddr(ip)
	return ok && !s.excludes(addr) && s.owns(addr, port)
}

func (s Scope) excludes(addr netip.Addr) bool {
	for _, p := range s.excluded {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func (s Scope) owns(addr netip.Addr, port int) bool {
	if OwnedByAddressClass(addr) {
		return true
	}
	for _, p := range s.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	if port > 0 && port <= 65535 {
		if _, ok := s.endpoints[netip.AddrPortFrom(addr, uint16(port))]; ok {
			return true
		}
	}
	return false
}

// Len is how many prefixes, endpoints and exclusions the scope holds, for
// logging.
func (s Scope) Len() (prefixes, endpoints, excluded int) {
	return len(s.prefixes), len(s.endpoints), len(s.excluded)
}

func parseAddr(ip string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// Re-export the shared ownership-claim limits for callers that already use the
// probe-consent vocabulary. The definition itself lives in shared/network so
// manual-scan authorization and automatic enrichment cannot drift.
const (
	MinClaimBitsIPv4 = sharednetwork.MinClaimBitsIPv4
	MinClaimBitsIPv6 = sharednetwork.MinClaimBitsIPv6
)

// TooBroadToClaim delegates to shared/network's single definition, including
// its handling of IPv4-mapped, 6to4, Teredo and NAT64 prefixes.
func TooBroadToClaim(p netip.Prefix) bool {
	return sharednetwork.TooBroadToClaim(p)
}

// WhollyOwnedByAddressClass reports that every address in p is owned by
// address class — so declaring it adds nothing a sensor does not already know.
func WhollyOwnedByAddressClass(p netip.Prefix) bool {
	q, ok := unmapPrefix(p.Masked())
	return ok && OwnedByAddressClass(q.Addr()) && OwnedByAddressClass(lastAddr(q))
}

// lastAddr is the highest address in a prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	p = p.Masked()
	b := p.Addr().AsSlice()
	for i := range b {
		for bit := 0; bit < 8; bit++ {
			if i*8+bit >= p.Bits() {
				b[i] |= 1 << (7 - bit)
			}
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

func parsePrefixes(raw []string) (out []netip.Prefix, rejected int) {
	for _, r := range raw {
		p, err := netip.ParsePrefix(strings.TrimSpace(r))
		if err != nil || p.Addr().Zone() != "" {
			rejected++
			continue
		}
		p, ok := unmapPrefix(p)
		if !ok {
			rejected++
			continue
		}
		out = append(out, p)
	}
	return out, rejected
}

// OwnedByAddressClass is the part of ownership an address proves on its own:
// RFC 1918 and RFC 4193 space ([netip.Addr.IsPrivate]), loopback, and
// link-local unicast. Nobody else's service lives there as seen from inside
// the tenant's network.
//
// Deliberately NOT here: carrier-grade NAT, the documentation ranges, and
// anything else merely "not globally routable". Not being routable does not
// make an address the tenant's.
func OwnedByAddressClass(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()
}

// EndpointString is the wire spelling of an endpoint, shared by the platform
// that writes it and the tests that read it.
func EndpointString(ip string, port int) string {
	if addr, err := netip.ParseAddr(strings.TrimSpace(ip)); err == nil {
		ip = addr.Unmap().String()
	}
	return net.JoinHostPort(ip, strconv.Itoa(port))
}

// unmapPrefix rewrites an IPv4-mapped IPv6 prefix as the IPv4 prefix it
// denotes, because addresses are unmapped before lookup and a mapped prefix
// would otherwise contain nothing. A mapped prefix shorter than /96 reaches
// outside the mapped space and has no IPv4 meaning.
func unmapPrefix(p netip.Prefix) (netip.Prefix, bool) {
	if !p.Addr().Is4In6() {
		return p.Masked(), true
	}
	if p.Bits() < 96 {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96).Masked(), true
}
