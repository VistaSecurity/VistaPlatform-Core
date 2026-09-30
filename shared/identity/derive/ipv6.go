package derive

import (
	"net/netip"
	"strings"
)

// The source references a derived identifier carries, so the asset page can
// say what it was derived from ( Phase 2, "derived from <evidence>").
//
// Every one starts with [RefPrefix]; the evidence follows the kind:
//
//	derived:eui64:<ipv6 address>   a MAC recovered from an EUI-64 IPv6 address
//	derived:serial:<serial>        a MAC read out of a MAC-shaped serial number
const RefPrefix = "derived:"

// RefEUI64 is the source reference of a MAC derived from addr by [MACFromEUI64].
// The zone is dropped: `fe80::…%eth0` names an interface on the collector, not
// anything about the device.
func RefEUI64(addr netip.Addr) string {
	return RefPrefix + "eui64:" + addr.WithZone("").String()
}

// RefSerial is the source reference of a MAC derived from serial by
// [MACFromSerial].
func RefSerial(serial string) string {
	return RefPrefix + "serial:" + strings.TrimSpace(serial)
}

// AddressRole is what an address may be used for in identification ( D2).
type AddressRole int

const (
	// RoleIdentifier — an IPv4 address, or an IPv6 address that is stable: an
	// EUI-64 one, or one a person evidently assigned (see [IPv6Role]). It
	// becomes an ip_address identifier as before.
	RoleIdentifier AddressRole = iota
	// RoleLinkLocal — fe80::/10. Unique only on its own link, so it may
	// identify only within the segment the observation was made in, never
	// tenant-wide.
	RoleLinkLocal
	// RoleTemporary — a unicast IPv6 address (ULA or global) whose interface
	// identifier is neither EUI-64 nor low-entropy: the shape of an RFC 8981
	// temporary address. It rotates, so each one attached as an identifier is a
	// value never seen again. Recorded as an attribute instead.
	RoleTemporary
)

// String names the role for logs and test failures.
func (r AddressRole) String() string {
	switch r {
	case RoleLinkLocal:
		return "link-local"
	case RoleTemporary:
		return "temporary"
	default:
		return "identifier"
	}
}

// manualIIDMinZeroNibbles is how many of the 16 hex digits of an interface
// identifier must be zero for it to read as ASSIGNED rather than generated.
//
// A generated IID (RFC 8981 temporary, RFC 7217 stable-privacy, RFC 4941) is 64
// pseudo-random bits, so each nibble is zero with probability 1/16 and the
// count of zero nibbles is Binomial(16, 1/16): mean 1, and P(≥8) ≈ 3·10⁻⁶. An
// address a person or a DHCPv6 pool assigned — ::10, ::53, ::1:2, ::dead:beef,
// ::1000:a — has eight or more by construction. The threshold therefore keeps
// every such address an identifier and misreads a random one about once in
// three hundred thousand, in the safe direction (a temporary address kept as an
// identifier is today's behaviour, not a wrong merge).
const manualIIDMinZeroNibbles = 8

// IPv6Role decides what an address may be used for in identification
// ( D2). IPv4 and IPv4-mapped addresses are always [RoleIdentifier], and so
// is anything that is not a unicast address this rule has an opinion about
// (loopback, multicast, unspecified — the identifier path already refuses the
// ones that are not identities).
//
// The hard question is a unicast address that is not EUI-64. An RFC 8981
// temporary address, an RFC 7217 stable-privacy address and a static address a
// person chose all have an IID that is "not EUI-64", and the IID alone cannot
// tell the first two apart. What it CAN tell is whether a person chose it: a
// hand-assigned IID is low-entropy (see [manualIIDMinZeroNibbles]). So:
//
//   - EUI-64 IID → identifier (and the caller derives the MAC under it);
//   - low-entropy IID → identifier: a server's `2001:db8::10` stays a server
//     identity and is never demoted;
//   - any other IID → [RoleTemporary].
//
// The cost is stated rather than hidden: a stable-privacy (RFC 7217) address is
// also demoted, because it is indistinguishable from a temporary one. It stays
// on the asset as an attribute, and the device is identified by everything
// else the sighting carried — its IPv4 address, its MAC, its names.
func IPv6Role(addr netip.Addr) AddressRole {
	if !addr.IsValid() || !addr.Is6() || addr.Is4In6() {
		return RoleIdentifier
	}
	addr = addr.WithZone("")
	if addr.IsLinkLocalUnicast() {
		return RoleLinkLocal
	}
	if !addr.IsGlobalUnicast() || addr.IsLoopback() || addr.IsMulticast() {
		// IsGlobalUnicast is true for ULA (fc00::/7) as well as GUA: both are
		// unicast addresses a host may generate temporary IIDs in.
		return RoleIdentifier
	}
	if IsEUI64(addr) || lowEntropyIID(addr) {
		return RoleIdentifier
	}
	return RoleTemporary
}

// lowEntropyIID reports whether the address's interface identifier (the low 64
// bits) has at least [manualIIDMinZeroNibbles] zero hex digits.
func lowEntropyIID(addr netip.Addr) bool {
	b := addr.As16()
	zero := 0
	for _, v := range b[8:] {
		if v>>4 == 0 {
			zero++
		}
		if v&0x0f == 0 {
			zero++
		}
	}
	return zero >= manualIIDMinZeroNibbles
}
