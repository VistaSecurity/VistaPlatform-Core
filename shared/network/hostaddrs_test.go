package network

import (
	"net"
	"testing"
)

func TestControlPlaneHostPortDefaultsPortByScheme(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want string
	}{
		{"https defaults to 443", "https://sensors.example.com", "sensors.example.com:443"},
		{"http defaults to 80", "http://platform.local", "platform.local:80"},
		{"explicit port wins", "https://sensors.example.com:8444", "sensors.example.com:8444"},
		{"ipv6 host is bracketed", "https://[2001:db8::1]", "[2001:db8::1]:443"},
		{"empty url yields nothing", "", ""},
		{"garbage without a host yields nothing", "not-a-url", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := controlPlaneHostPort(tc.url); got != tc.want {
				t.Fatalf("controlPlaneHostPort(%q) = %q, want %q", tc.url, got, tc.want)
			}
		})
	}
}

// HostAddresses must never surface loopback or link-local: neither identifies
// the host to anything outside it, and including them would make every agent
// appear to cover 127.0.0.0/8 and fe80::/10.
func TestHostAddressesExcludesLoopbackAndLinkLocal(t *testing.T) {
	for _, a := range HostAddresses("") {
		if a.Address == "127.0.0.1" || a.Address == "::1" {
			t.Fatalf("loopback %s was reported on %s", a.Address, a.InterfaceName)
		}
		if len(a.Address) >= 5 && a.Address[:5] == "fe80:" {
			t.Fatalf("link-local %s was reported on %s", a.Address, a.InterfaceName)
		}
		if a.InterfaceName == "" {
			t.Fatalf("address %s reported with no interface name", a.Address)
		}
	}
}

// Exactly the address matching primaryIP is flagged, so the platform's
// one-primary-per-agent database constraint can never be violated by a report.
func TestHostAddressesMarksAtMostOnePrimary(t *testing.T) {
	all := HostAddresses("")
	if len(all) == 0 {
		t.Skip("no non-loopback addresses in this environment")
	}

	target := all[0].Address
	var primaries int
	for _, a := range HostAddresses(target) {
		if a.IsPrimary {
			primaries++
			if a.Address != target {
				t.Fatalf("flagged %s as primary, wanted %s", a.Address, target)
			}
		}
	}
	if primaries != 1 {
		t.Fatalf("got %d primaries, want exactly 1", primaries)
	}
}

// Nothing is primary when the agent could not determine its source address.
func TestHostAddressesMarksNonePrimaryWhenUnknown(t *testing.T) {
	for _, a := range HostAddresses("") {
		if a.IsPrimary {
			t.Fatalf("%s flagged primary with no primary IP supplied", a.Address)
		}
	}
}

// usableInterfaceMAC excludes a locally-administered (randomised/virtual-NIC)
// MAC and a first-hop-redundancy virtual-router MAC, the same rule
// shared/hostobs applies to a passively observed one — a rotating or floating
// address is not a stable identifier of this chassis.
func TestUsableInterfaceMAC(t *testing.T) {
	cases := []struct {
		name string
		mac  net.HardwareAddr
		want string
	}{
		{"ordinary NIC", net.HardwareAddr{0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e}, "00:1a:2b:3c:4d:5e"},
		{"locally administered (U/L bit set)", net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, ""},
		{"VRRP virtual router MAC", net.HardwareAddr{0x00, 0x00, 0x5e, 0x00, 0x01, 0x07}, ""},
		{"HSRP virtual router MAC", net.HardwareAddr{0x00, 0x00, 0x0c, 0x07, 0xac, 0x0a}, ""},
		{"empty", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			iface := net.Interface{Name: "eth-test", HardwareAddr: tc.mac}
			if got := usableInterfaceMAC(iface); got != tc.want {
				t.Fatalf("usableInterfaceMAC(%v) = %q, want %q", tc.mac, got, tc.want)
			}
		})
	}
}

// HostAddresses attaches the interface's MAC to every address bound to it,
// when the interface has a real (non-loopback) one — verified against the
// live environment's own interfaces rather than a mock, matching the file's
// other HostAddresses tests.
func TestHostAddressesCarriesMACWhenPresent(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skip("cannot enumerate interfaces in this environment")
	}
	hasRealMAC := false
	for _, iface := range ifaces {
		if usableInterfaceMAC(iface) != "" {
			hasRealMAC = true
			break
		}
	}
	if !hasRealMAC {
		t.Skip("no non-virtual, non-randomised interface MAC in this environment")
	}

	sawMAC := false
	for _, a := range HostAddresses("") {
		if a.MAC != "" {
			sawMAC = true
			if len(a.MAC) != 17 { // "aa:bb:cc:dd:ee:ff"
				t.Fatalf("MAC %q is not a normalised 6-octet address", a.MAC)
			}
		}
	}
	if !sawMAC {
		t.Fatalf("expected at least one reported address to carry a MAC")
	}
}
