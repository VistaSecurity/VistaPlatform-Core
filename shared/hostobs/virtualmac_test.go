package hostobs

import "testing"

// The virtual-router MAC table, one row per protocol, each pinned against the
// range its source document gives. Deleting a row from the table turns its
// case here red; adding a real vendor OUI to the table turns the negative cases
// red.
func TestVirtualMACProtocol(t *testing.T) {
	cases := []struct {
		mac   string
		proto string
	}{
		// RFC 5798 §7.3 — VRRP IPv4, VRID 1 and VRID 255; also CARP/keepalived.
		{"00:00:5e:00:01:01", "vrrp"},
		{"00:00:5e:00:01:ff", "vrrp"},
		{"00-00-5E-00-01-07", "vrrp"}, // any spelling NormalizeMAC accepts
		{"0000.5e00.0107", "vrrp"},
		// RFC 5798 §7.3 — VRRP IPv6.
		{"00:00:5e:00:02:01", "vrrp6"},
		// RFC 2281 §5.1 — HSRP v1, group 0 and group 255.
		{"00:00:0c:07:ac:00", "hsrp"},
		{"00:00:0c:07:ac:ff", "hsrp"},
		// Cisco HSRP v2 — 0000.0c9f.f000 through 0000.0c9f.ffff.
		{"00:00:0c:9f:f0:00", "hsrp2"},
		{"00:00:0c:9f:f7:d1", "hsrp2"},
		{"00:00:0c:9f:ff:ff", "hsrp2"},
		// Cisco GLBP — 0007.b400.xxyy.
		{"00:07:b4:00:01:01", "glbp"},
		{"00:07:b4:00:ff:04", "glbp"},

		// Not virtual: a real Cisco chassis MAC from the same OUI as HSRP, the
		// IANA OUI outside the VRRP block, HSRPv2's neighbour just below the
		// range, and two ordinary vendor addresses.
		{"00:00:0c:12:34:56", ""},
		{"00:00:5e:00:03:01", ""},
		{"00:00:5e:12:34:56", ""},
		{"00:00:0c:9f:ef:ff", ""},
		{"e8:ff:1e:d9:95:07", ""},
		{"28:cf:da:11:22:33", ""},
		// Unusable input is not virtual either.
		{"", ""},
		{"ff:ff:ff:ff:ff:ff", ""},
		{"not-a-mac", ""},
	}
	for _, tc := range cases {
		got, ok := VirtualMACProtocol(tc.mac)
		if ok != (tc.proto != "") || got != tc.proto {
			t.Errorf("VirtualMACProtocol(%q) = (%q, %v), want (%q, %v)", tc.mac, got, ok, tc.proto, tc.proto != "")
		}
	}
}

// Finalize flags a virtual MAC the way it flags a locally-administered one, and
// records the protocol as an attribute — so a consumer that drops the MAC as an
// identifier still has the explanation on the row.
func TestVirtualMACIsFlaggedAndKeptAsAnAttribute(t *testing.T) {
	o := &HostObservation{MAC: "00:00:5e:00:01:2a", Source: SourceARP}
	o.Finalize()
	if !o.MACVirtual {
		t.Error("a VRRP virtual router MAC was not flagged MACVirtual")
	}
	if o.MACLocallyAdministered {
		t.Error("a VRRP MAC is universally administered (the U/L bit is clear); it must not be reported as local")
	}
	if got := o.Attributes["virtual_mac_protocol"]; got != "vrrp" {
		t.Errorf("attributes[virtual_mac_protocol] = %v, want vrrp", got)
	}

	u := &HostObservation{MAC: "e8:ff:1e:d9:95:07", Source: SourceARP}
	u.Finalize()
	if u.MACVirtual {
		t.Error("a real NIC's MAC was flagged virtual")
	}
	if _, ok := u.Attributes["virtual_mac_protocol"]; ok {
		t.Error("a real NIC's observation carries a virtual_mac_protocol attribute")
	}
}
