package network

import "net/netip"

// Minimum prefix lengths for a DECLARED network segment to count as a claim of
// ownership. Nobody owns a /7 of the IPv4 internet or a /15 of IPv6, and a
// segment that wide — 0.0.0.0/0 above all — would otherwise put every third
// party inside the tenant's "registered networks": a silent opt-in to
// automatic probing (W5.13a) and a bypass of the explicit-external-target
// confirmation (W5.13b).
//
// This is the ONE definition. The segment API refuses new saves of such
// prefixes; scan authorization (shared/identity/dispatchguard) and probe consent
// (shared/probeconsent) refuse to treat pre-existing ones as ownership.
const (
	MinClaimBitsIPv4 = 8
	MinClaimBitsIPv6 = 16
)

// TooBroadToClaim reports whether a declared prefix is too wide to be a
// statement of ownership: shorter than /8 for IPv4, shorter than /16 for IPv6.
// An IPv4-mapped prefix is judged as the IPv4 prefix it denotes, and one that
// reaches outside the mapped space (shorter than /96) is too broad by
// definition. An invalid prefix is too broad.
//
// A prefix wholly inside space the address class already makes the tenant's —
// RFC 1918 and ULA (fc00::/7, including the fd00::/8 tenants commonly
// register), loopback, link-local — is exempt: claiming it widens nothing, and
// refusing it would only break a legitimate segment.
func TooBroadToClaim(p netip.Prefix) bool {
	if !p.IsValid() {
		return true
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return true
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	p = p.Masked()
	if broad, embedding := embeddedBreadth(p); embedding {
		return broad
	}
	if ownedByAddressClass(p.Addr()) && ownedByAddressClass(lastAddrOf(p)) {
		return false
	}
	if p.Addr().Is4() {
		return p.Bits() < MinClaimBitsIPv4
	}
	return p.Bits() < MinClaimBitsIPv6
}

// ownedByAddressClass: RFC 1918 / RFC 4193, loopback, link-local unicast.
func ownedByAddressClass(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()
}

func lastAddrOf(p netip.Prefix) netip.Addr {
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

// embeddedBreadth judges a prefix that touches an IPv4-embedding block (6to4,
// Teredo, NAT64, IPv4-compatible, SIIT, local-use NAT64) by the IPv4 space it
// carries ( W5.13b review N6): 2002::/16 is every IPv4 address in 6to4
// form, 0.0.0.0/0. When EmbeddedIPv4Prefix cannot say exactly which IPv4
// prefix that is — a prefix containing a whole block (64:ff9b::/32,
// 2001::/16), one shorter than the embedding offset (2001::/32), anything in
// local-use NAT64 — the claim is too broad. It reports embedding=false when
// the prefix touches none of the blocks.
func embeddedBreadth(p netip.Prefix) (tooBroad, embedding bool) {
	if !p.Addr().Is6() {
		return false, false
	}
	touches := false
	for _, e := range embeddingBlocks {
		if p.Overlaps(e.prefix) {
			touches = true
			break
		}
	}
	if !touches {
		return false, false
	}
	v4, ok := EmbeddedIPv4Prefix(p)
	if !ok {
		return true, true
	}
	return v4.Bits() < MinClaimBitsIPv4, true
}
