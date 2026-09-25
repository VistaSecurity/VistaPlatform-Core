package network

import "net/netip"

// Well-known IPv6 forms that carry an IPv4 address (RFC 4291, 2765, 3056,
// 4380, 6052, 8215).
var (
	nat64WellKnown   = netip.MustParsePrefix("64:ff9b::/96")    // RFC 6052
	nat64LocalUse    = netip.MustParsePrefix("64:ff9b:1::/48")  // RFC 8215: the operator picks the sub-prefix
	ipv4Compatible   = netip.MustParsePrefix("::/96")           // RFC 4291 §2.5.5.1 (deprecated)
	siitTranslated   = netip.MustParsePrefix("::ffff:0:0:0/96") // RFC 2765
	sixToFour        = netip.MustParsePrefix("2002::/16")       // RFC 3056
	teredo           = netip.MustParsePrefix("2001::/32")       // RFC 4380
	unspecifiedOrLo6 = []netip.Addr{netip.IPv6Unspecified(), netip.IPv6Loopback()}
)

// EmbeddedIPv4 returns the IPv4 address an IPv6 address carries, when it is
// one of the forms that lead to an IPv4 destination, and false otherwise. A
// packet sent to such an address can end up at the IPv4 address — through a
// NAT64 or SIIT translator, a 6to4 relay or a Teredo relay, or (for the
// mapped form) the local stack — so anything that judges destinations must
// judge the IPv4 address too: ::ffff:169.254.169.254, 64:ff9b::a9fe:a9fe and
// 2002:a9fe:a9fe:: all lead to the cloud metadata service.
//
//   - IPv4-mapped    ::ffff:a.b.c.d          → a.b.c.d
//   - SIIT           ::ffff:0:a.b.c.d        → a.b.c.d
//   - IPv4-compatible ::a.b.c.d (not :: / ::1) → a.b.c.d
//   - NAT64          64:ff9b::a.b.c.d         → a.b.c.d
//   - 6to4           2002:AABB:CCDD::         → AA.BB.CC.DD
//   - Teredo         2001:0:…                 → the CLIENT address (bits
//     96–127, bit-inverted), the one the relay delivers to. The server
//     address in bits 32–63 is not a destination and is not returned.
//
// Local-use NAT64 (64:ff9b:1::/48, RFC 8215) returns false: the operator
// chooses a sub-prefix of any RFC 6052 length inside it, and where the IPv4
// address sits depends on that length, which the address alone does not say.
// Reading it at one fixed position would be a guess; callers must treat that
// /48 as a whole (dispatchguard reserves it; TooBroadToClaim refuses to count
// it as anybody's).
//
// An IPv4 address (not IPv6) returns false: it embeds nothing. The one shared
// definition for scan authorization (shared/identity/dispatchguard) and probe
// consent (shared/probeconsent).
func EmbeddedIPv4(addr netip.Addr) (netip.Addr, bool) {
	if !addr.IsValid() || addr.Is4() {
		return netip.Addr{}, false
	}
	addr = addr.WithZone("")
	if addr.Is4In6() {
		return addr.Unmap(), true
	}
	b := addr.As16()
	switch {
	case siitTranslated.Contains(addr),
		nat64WellKnown.Contains(addr):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case ipv4Compatible.Contains(addr):
		for _, special := range unspecifiedOrLo6 {
			if addr == special {
				return netip.Addr{}, false
			}
		}
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case nat64LocalUse.Contains(addr):
		return netip.Addr{}, false
	case sixToFour.Contains(addr):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	case teredo.Contains(addr):
		return netip.AddrFrom4([4]byte{b[12] ^ 0xff, b[13] ^ 0xff, b[14] ^ 0xff, b[15] ^ 0xff}), true
	}
	return netip.Addr{}, false
}

// embeddingBlocks are the IPv6 blocks whose addresses carry an IPv4 address,
// with the bit offset where it starts and whether it is bit-inverted.
// offset < 0: the position is not fixed (local-use NAT64, RFC 8215).
var embeddingBlocks = []struct {
	prefix   netip.Prefix
	offset   int
	inverted bool
}{
	{sixToFour, 16, false},      // 2002:AABB:CCDD::
	{teredo, 96, true},          // client address, bits 96–127, bit-inverted
	{nat64WellKnown, 96, false}, // 64:ff9b::a.b.c.d
	{ipv4Compatible, 96, false}, // ::a.b.c.d
	{siitTranslated, 96, false}, // ::ffff:0:a.b.c.d
	{nat64LocalUse, -1, false},  // operator-chosen layout
}

// EmbeddedIPv4Prefix returns the IPv4 prefix an IPv6 prefix carries, when the
// prefix lies wholly inside one IPv4-embedding block (6to4, Teredo, NAT64
// 64:ff9b::/96, IPv4-compatible, SIIT, or IPv4-mapped) and the answer is
// exact. It returns false — fail closed — for anything it cannot determine
// exactly:
//
//   - a prefix that is not wholly inside one block (64:ff9b::/32 and
//     2001::/16 contain whole blocks; they carry more than one IPv4 prefix);
//   - a prefix shorter than the block's embedding offset (2001::/32 is every
//     Teredo server AND every client);
//   - anything in local-use NAT64 64:ff9b:1::/48, whose layout depends on the
//     operator's prefix length (see EmbeddedIPv4).
//
// Examples: 2002::/16 → 0.0.0.0/0; 2002:5db8:d800::/40 → 93.184.216.0/24;
// 64:ff9b::5d00:0/104 → 93.0.0.0/8. Bits past the IPv4 address (a 6to4 /64)
// do not narrow it further: 2002:5db8:d822::/64 → 93.184.216.34/32.
func EmbeddedIPv4Prefix(p netip.Prefix) (netip.Prefix, bool) {
	if !p.IsValid() || !p.Addr().Is6() {
		return netip.Prefix{}, false
	}
	p = netip.PrefixFrom(p.Addr().WithZone(""), p.Bits()).Masked()
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96), true
	}
	for _, e := range embeddingBlocks {
		if !e.prefix.Contains(p.Addr()) {
			continue
		}
		// Every offset is at or past its block's length, so "shorter than
		// the offset" also refuses a prefix that is wider than the block.
		if e.offset < 0 || p.Bits() < e.offset {
			return netip.Prefix{}, false
		}
		bits := p.Bits() - e.offset
		if bits > 32 {
			bits = 32
		}
		b := p.Addr().As16()
		start := e.offset / 8
		v4 := [4]byte{b[start], b[start+1], b[start+2], b[start+3]}
		if e.inverted {
			for i := range v4 {
				v4[i] ^= 0xff
			}
		}
		return netip.PrefixFrom(netip.AddrFrom4(v4), bits).Masked(), true
	}
	return netip.Prefix{}, false
}
