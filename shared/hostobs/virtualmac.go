package hostobs

import "strings"

// Virtual-router MACs: the addresses a first-hop-redundancy protocol puts on
// the wire for a FLOATING address, which move between routers with it.
//
// A MAC is treated everywhere in this platform as a stable identifier of one
// physical thing (ADR-0002 D3 ranks `mac_address` above every name and address
// kind, and the unique index of DATA_MODEL §2 lets it belong to one asset).
// These ranges break that premise by design: the MAC belongs to the ROLE
// ("active router for VRRP group 7"), not to whichever chassis currently holds
// it, and it moves at failover. Keying a node on one would make the standby
// router "become" the active one at every failover — the same rotating-key
// failure a locally-administered MAC produces, so it is handled the same way:
// not an identifier, kept as an attribute.
//
// The table is by protocol, with the source each prefix is taken from:
//
//   - VRRP, IPv4 — RFC 5798 §7.3: "The virtual router MAC address associated
//     with a virtual router is an IEEE 802 MAC Address in the following format:
//     IPv4 case: 00-00-5E-00-01-{VRID}". Also what keepalived puts on its
//     `use_vmac` interface, and what OpenBSD/FreeBSD CARP uses (carp(4):
//     "00:00:5e:00:01:<vhid>").
//   - VRRP, IPv6 — RFC 5798 §7.3: "IPv6 case: 00-00-5E-00-02-{VRID}".
//   - HSRP version 1 — RFC 2281 §5.1: "the virtual MAC address is
//     00-00-0C-07-AC-{group}", from Cisco's OUI 00-00-0C.
//   - HSRP version 2 — Cisco IOS "Configuring HSRP", HSRP Version 2 Design:
//     the virtual MAC range is 0000.0C9F.F000 through 0000.0C9F.FFFF (the low
//     twelve bits carry the group number).
//   - GLBP — Cisco IOS "Configuring GLBP": virtual forwarder MACs are
//     0007.b400.XXYY, where XX is the group and YY the forwarder number.
//
// What is deliberately NOT here: MetalLB L2, kube-vip and Windows NLB unicast
// mode announce the floating address from the NODE's real NIC, so nothing about
// the MAC says it is floating — that case is caught downstream, by the
// identification engine's floating-address rule, where the MAC resolving to one
// asset and the address to another IS the signal.
var virtualMACPrefixes = []struct {
	prefix   string // of a NormalizeMAC-rendered address
	protocol string
}{
	{"00:00:5e:00:01:", "vrrp"},  // RFC 5798 §7.3 (IPv4); CARP; keepalived
	{"00:00:5e:00:02:", "vrrp6"}, // RFC 5798 §7.3 (IPv6)
	{"00:00:0c:07:ac:", "hsrp"},  // RFC 2281 §5.1
	{"00:00:0c:9f:f", "hsrp2"},   // Cisco HSRPv2: 0000.0c9f.f000–0000.0c9f.ffff
	{"00:07:b4:", "glbp"},        // Cisco GLBP: 0007.b400.xxyy
}

// VirtualMACProtocol reports whether a MAC is a first-hop-redundancy virtual
// router address, and which protocol's. The MAC may be in any spelling
// [NormalizeMAC] accepts. An unrecognised or unusable address answers ("",
// false).
//
// Exported because the CONSUMER must apply it, not only the producer: an older
// sensor binary sends observations that predate [HostObservation.MACVirtual],
// and the rule has to hold for those too.
func VirtualMACProtocol(mac string) (string, bool) {
	m := NormalizeMAC(mac)
	if m == "" {
		return "", false
	}
	for _, v := range virtualMACPrefixes {
		if strings.HasPrefix(m, v.prefix) {
			return v.protocol, true
		}
	}
	return "", false
}
