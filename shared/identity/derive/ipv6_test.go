package derive

import (
	"net/netip"
	"testing"
)

// TestIPv6Role pins D2's three-way split and, above all, that a
// statically configured server address is NOT demoted to "temporary".
// Mutation: drop lowEntropyIID from IPv6Role → the "static server" rows fail;
// drop the IsLinkLocalUnicast branch → the link-local rows fail.
func TestIPv6Role(t *testing.T) {
	tests := []struct {
		addr string
		want AddressRole
	}{
		// The spec's vector.
		{"fe80::1", RoleLinkLocal},
		{"fd00::a2b2:c3ff:fed4:e5f6", RoleIdentifier}, // EUI-64
		{"fd00::1234:5678:9abc:def0", RoleTemporary},  // random IID
		// Link-local, whatever the IID and whatever the zone.
		{"fe80::a2b2:c3ff:fed4:e5f6", RoleLinkLocal},
		{"fe80::1234:5678:9abc:def0%eth0", RoleLinkLocal},
		{"febf::1", RoleLinkLocal}, // top of fe80::/10
		// Global unicast (documentation prefix, RFC 3849).
		{"2001:db8::a2b2:c3ff:fed4:e5f6", RoleIdentifier},
		{"2001:db8:1:2:8d3c:4a1f:b27e:9c05", RoleTemporary},
		// Statically configured servers keep their identity.
		{"2001:db8::10", RoleIdentifier},
		{"2001:db8::53", RoleIdentifier},
		{"2001:db8::1:2", RoleIdentifier},
		{"2001:db8::dead:beef", RoleIdentifier},
		{"2001:db8::1:2:3:4", RoleIdentifier},
		{"fd00:1:2:3::1000:a", RoleIdentifier},
		// IPv4 and the addresses the rule has no opinion about.
		{"192.0.2.10", RoleIdentifier},
		{"::ffff:192.0.2.10", RoleIdentifier},
		{"::1", RoleIdentifier},
		{"ff02::fb", RoleIdentifier},
	}
	for _, tc := range tests {
		t.Run(tc.addr, func(t *testing.T) {
			addr, err := netip.ParseAddr(tc.addr)
			if err != nil {
				t.Fatalf("bad vector: %v", err)
			}
			if got := IPv6Role(addr); got != tc.want {
				t.Fatalf("IPv6Role(%s) = %s, want %s", tc.addr, got, tc.want)
			}
		})
	}
	if got := IPv6Role(netip.Addr{}); got != RoleIdentifier {
		t.Fatalf("invalid Addr = %s, want identifier (no opinion)", got)
	}
}

// TestIPv6Role_RandomIIDsAreTemporary checks the entropy threshold from the
// other side: IIDs drawn the way RFC 8981 draws them are overwhelmingly
// classified temporary. A deterministic generator keeps the test stable.
func TestIPv6Role_RandomIIDsAreTemporary(t *testing.T) {
	var state uint64 = 0x9e3779b97f4a7c15
	next := func() uint64 { // splitmix64
		state += 0x9e3779b97f4a7c15
		z := state
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		return z ^ (z >> 31)
	}
	kept := 0
	const n = 20000
	for i := 0; i < n; i++ {
		var b [16]byte
		b[0], b[1] = 0x20, 0x01
		b[2], b[3] = 0x0d, 0xb8
		iid := next()
		for j := 0; j < 8; j++ {
			b[8+j] = byte(iid >> (8 * j))
		}
		addr := netip.AddrFrom16(b)
		if IsEUI64(addr) {
			continue
		}
		if IPv6Role(addr) != RoleTemporary {
			kept++
		}
	}
	if kept > 1 {
		t.Fatalf("%d of %d random IIDs were kept as identifiers; the threshold should keep ~0", kept, n)
	}
}

func TestDerivedRefs(t *testing.T) {
	if got := RefEUI64(netip.MustParseAddr("fe80::a2b2:c3ff:fed4:e5f6%eth0")); got != "derived:eui64:fe80::a2b2:c3ff:fed4:e5f6" {
		t.Fatalf("RefEUI64 = %q", got)
	}
	if got := RefSerial(" A0B2C3D4E5F6 "); got != "derived:serial:A0B2C3D4E5F6" {
		t.Fatalf("RefSerial = %q", got)
	}
}
