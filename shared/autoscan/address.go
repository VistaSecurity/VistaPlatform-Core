package autoscan

import (
	"net/netip"
	"strings"
)

// Reason explains why an address was or was not accepted for an automatic
// scan. It is returned rather than logged so the caller can count refusals by
// cause — "nothing was scanned" and "nothing was ELIGIBLE" are different
// answers, and a sweep that quietly scans zero hosts is the silent-success
// shape this whole feature has to avoid.
type Reason string

const (
	ReasonPrivate     Reason = "private"            // RFC 1918 / ULA
	ReasonSegment     Reason = "registered_segment" // inside a network segment the tenant declared
	ReasonUnparseable Reason = "unparseable"
	ReasonLoopback    Reason = "loopback"
	ReasonLinkLocal   Reason = "link_local"
	ReasonMulticast   Reason = "multicast"
	ReasonUnspecified Reason = "unspecified"
	ReasonZoned       Reason = "zoned"
	ReasonExcluded    Reason = "excluded"
	ReasonPublic      Reason = "public"
	// ReasonCarrierGradeNAT is RFC 6598 shared address space (100.64.0.0/10),
	// refused for the same reason as public but NAMED, because the tenants who
	// hit it are a recognisable population — Tailscale, ZeroTier and mobile
	// carriers hand out that range — and "public" would send them looking at
	// the wrong thing. The fix is the same as for any range that is theirs:
	// register it as a network segment.
	ReasonCarrierGradeNAT Reason = "carrier_grade_nat"
)

// carrierGradeNAT is RFC 6598 shared address space.
var carrierGradeNAT = netip.MustParsePrefix("100.64.0.0/10")

// ParseTarget turns a stored address into a netip.Addr, or reports why it
// cannot be one.
//
// A zone identifier (`fe80::1%eth0`) is refused rather than stripped. netip
// accepts zones and Postgres `inet` does not, so a zoned string here means the
// value came from somewhere other than the inet column — and a scanner that
// silently dropped the zone would be probing a different interface's idea of
// that address.
func ParseTarget(address string) (netip.Addr, Reason, bool) {
	s := strings.TrimSpace(address)
	if s == "" {
		return netip.Addr{}, ReasonUnparseable, false
	}
	if strings.Contains(s, "%") {
		return netip.Addr{}, ReasonZoned, false
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, ReasonUnparseable, false
	}
	return addr.Unmap(), "", true
}

// Classify decides whether an automatic scan may probe an address.
//
// `segments` are the CIDRs of the network segments the tenant has registered —
// their own declared estate. `excluded` are addresses and ranges the platform
// must never probe on its own initiative (its own cluster, chiefly).
//
// The order is not arbitrary. Exclusions are checked FIRST so that nothing —
// not a tenant's own segment declaration, not RFC 1918 — can put the platform's
// own address back in scope. Everything unroutable (loopback, link-local,
// multicast, unspecified) is refused next, because those are not hosts on the
// tenant's network. Only then is the address accepted, either because it is
// private by address class or because the tenant declared the range as theirs.
//
// The default answer for anything else is NO. A public address reached by an
// unattended daily scan is a third party being port-scanned by us on a
// schedule, which is the one outcome this feature must never produce.
func Classify(addr netip.Addr, segments, excluded []netip.Prefix) (bool, Reason) {
	if !addr.IsValid() {
		return false, ReasonUnparseable
	}
	addr = addr.Unmap()

	for _, p := range excluded {
		if p.Contains(addr) {
			return false, ReasonExcluded
		}
	}

	switch {
	case addr.IsUnspecified():
		return false, ReasonUnspecified
	case addr.IsLoopback():
		return false, ReasonLoopback
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		return false, ReasonLinkLocal
	case addr.IsMulticast():
		return false, ReasonMulticast
	}
	// 255.255.255.255 — netip has no IsBroadcast, and the limited broadcast
	// address is neither multicast nor link-local, so it needs naming.
	if addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return false, ReasonMulticast
	}

	// netip.Addr.IsPrivate is RFC 1918 + RFC 4193 (fd00::/8) and nothing else.
	// In particular it does NOT cover RFC 6598 shared address space
	// (100.64.0.0/10), which is correct for us: that is carrier space, and a
	// tenant behind it reaches other operators' customers through it. A tenant
	// who genuinely runs their estate on it declares it as a network segment,
	// which is the explicit statement of ownership this code requires.
	if addr.IsPrivate() {
		return true, ReasonPrivate
	}

	for _, p := range segments {
		if p.Contains(addr) {
			return true, ReasonSegment
		}
	}

	if carrierGradeNAT.Contains(addr) {
		return false, ReasonCarrierGradeNAT
	}
	return false, ReasonPublic
}

// ParsePrefixes turns segment/exclusion values into prefixes, ignoring anything
// that is not one. Network segments can be a CIDR, a range, a domain or a VPC
// id — only the CIDR form describes addresses, and the others are simply not
// this function's business.
//
// A bare address is accepted as a host prefix (/32, /128) so an exclusion list
// can name one machine without the caller doing the arithmetic.
func ParsePrefixes(values []string) []netip.Prefix {
	var out []netip.Prefix
	for _, raw := range values {
		s := strings.TrimSpace(raw)
		if s == "" || strings.Contains(s, "%") {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		if addr, err := netip.ParseAddr(s); err == nil {
			addr = addr.Unmap()
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return out
}
