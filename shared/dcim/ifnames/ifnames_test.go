package ifnames

import "testing"

func TestIfnames_Canonical(t *testing.T) {
	cases := []struct {
		vendor, raw, want string
		kind              Kind
	}{
		// Cisco IOS / IOS-XE / NX-OS / IOS-XR
		{"cisco", "Gi1/0/1", "GigabitEthernet1/0/1", KindPhysical},
		{"cisco", "gi1/0/24", "GigabitEthernet1/0/24", KindPhysical},
		{"cisco", "GigabitEthernet1/0/24", "GigabitEthernet1/0/24", KindPhysical},
		{"cisco", "GigabitEthernet 1/0/24", "GigabitEthernet1/0/24", KindPhysical},
		{"cisco", "Gig0/1", "GigabitEthernet0/1", KindPhysical},
		{"cisco", "Fa0/1", "FastEthernet0/1", KindPhysical},
		{"cisco", "Te1/1/1", "TenGigabitEthernet1/1/1", KindPhysical},
		{"cisco", "TenGigabitEthernet1/1/1", "TenGigabitEthernet1/1/1", KindPhysical},
		{"cisco", "TenGigE0/0/0/0", "TenGigE0/0/0/0", KindPhysical},
		{"cisco", "Tw1/0/1", "TwoGigabitEthernet1/0/1", KindPhysical},
		{"cisco", "Twe1/0/1", "TwentyFiveGigE1/0/1", KindPhysical},
		{"cisco", "Fo1/0/1", "FortyGigabitEthernet1/0/1", KindPhysical},
		{"cisco", "Hu1/0/49", "HundredGigE1/0/49", KindPhysical},
		{"cisco", "HundredGigE0/0/0/1", "HundredGigE0/0/0/1", KindPhysical},
		{"cisco", "Eth1/1", "Ethernet1/1", KindPhysical},
		{"cisco", "Ethernet1/49", "Ethernet1/49", KindPhysical},
		{"cisco", "Po1", "Port-channel1", KindLAG},
		{"cisco", "port-channel10", "Port-channel10", KindLAG},
		{"cisco", "Port-channel1", "Port-channel1", KindLAG},
		{"cisco", "Po1.100", "Port-channel1.100", KindVirtual},
		{"cisco", "BE1", "Bundle-Ether1", KindLAG},
		{"cisco", "Vl10", "Vlan10", KindVLAN},
		{"cisco", "vlan100", "Vlan100", KindVLAN},
		{"cisco", "Lo0", "Loopback0", KindLoopback},
		{"cisco", "Loopback0", "Loopback0", KindLoopback},
		{"cisco", "mgmt0", "mgmt0", KindManagement},
		{"cisco", "Mgmt0", "mgmt0", KindManagement},
		{"cisco", "MgmtEth0/RP0/CPU0/0", "MgmtEth0/RP0/CPU0/0", KindUnknown},
		{"cisco", "Tu0", "Tunnel0", KindTunnel},
		{"cisco", "Gi0/0.100", "GigabitEthernet0/0.100", KindVirtual},
		{"ios-xe", "Gi1/0/2", "GigabitEthernet1/0/2", KindPhysical},
		{"Cisco Systems", "Te1/0/1", "TenGigabitEthernet1/0/1", KindPhysical},
		{"nxos", "Eth101/1/1", "Ethernet101/1/1", KindPhysical},
		// Juniper
		{"juniper", "ge-0/0/0", "ge-0/0/0", KindPhysical},
		{"juniper", "GE-0/0/1", "ge-0/0/1", KindPhysical},
		{"juniper", "xe-0/1/0", "xe-0/1/0", KindPhysical},
		{"juniper", "et-0/0/48", "et-0/0/48", KindPhysical},
		{"juniper", "et-0/0/48:1", "et-0/0/48:1", KindPhysical},
		{"juniper", "ge-0/0/0.0", "ge-0/0/0.0", KindVirtual},
		{"juniper", "ae0", "ae0", KindLAG},
		{"juniper", "ae0.0", "ae0.0", KindVirtual},
		{"juniper", "irb", "irb", KindVLAN},
		{"juniper", "irb.100", "irb.100", KindVLAN},
		{"juniper", "vlan.10", "vlan.10", KindVLAN},
		{"juniper", "lo0", "lo0", KindLoopback},
		{"junos", "lo0.0", "lo0.0", KindLoopback},
		{"juniper", "fxp0", "fxp0", KindManagement},
		{"juniper", "em0", "em0", KindManagement},
		{"juniper", "st0.1", "st0.1", KindTunnel},
		// Arista
		{"arista", "Ethernet1", "Ethernet1", KindPhysical},
		{"arista", "Et1", "Ethernet1", KindPhysical},
		{"arista", "et49/1", "Ethernet49/1", KindPhysical},
		{"arista", "Port-Channel1", "Port-Channel1", KindLAG},
		{"arista", "Po1", "Port-Channel1", KindLAG},
		{"arista", "port-channel20", "Port-Channel20", KindLAG},
		{"arista", "Vlan10", "Vlan10", KindVLAN},
		{"arista", "Ma1", "Management1", KindManagement},
		{"arista", "Management1", "Management1", KindManagement},
		{"arista", "Lo0", "Loopback0", KindLoopback},
		{"eos", "Vx1", "Vxlan1", KindVirtual},
		// Fortinet
		{"fortinet", "port1", "port1", KindPhysical},
		{"fortinet", "PORT2", "port2", KindPhysical},
		{"fortinet", "internal", "internal", KindPhysical},
		{"fortinet", "wan1", "wan1", KindPhysical},
		{"fortinet", "dmz", "dmz", KindPhysical},
		{"fortinet", "mgmt", "mgmt", KindManagement},
		{"fortinet", "fortilink", "fortilink", KindLAG},
		{"fortinet", "ssl.root", "ssl.root", KindTunnel},
		{"fortigate", "Office_VLAN", "Office_VLAN", KindUnknown},
		// Linux
		{"linux", "eth0", "eth0", KindPhysical},
		{"linux", "ens192", "ens192", KindPhysical},
		{"linux", "enp0s3", "enp0s3", KindPhysical},
		{"linux", "eno1", "eno1", KindPhysical},
		{"linux", "bond0", "bond0", KindLAG},
		{"linux", "br0", "br0", KindBridge},
		{"linux", "docker0", "docker0", KindBridge},
		{"linux", "lo", "lo", KindLoopback},
		{"linux", "wlan0", "wlan0", KindWireless},
		{"linux", "wg0", "wg0", KindTunnel},
		{"linux", "veth1a2b3c", "veth1a2b3c", KindVirtual},
		{"linux", "eth0.100", "eth0.100", KindVirtual},
		{"ubuntu", "  ens160 ", "ens160", KindPhysical},
		// Windows
		{"windows", "Ethernet 2", "Ethernet 2", KindPhysical},
		{"windows", "Ethernet  2", "Ethernet 2", KindPhysical},
		{"windows", "Wi-Fi", "Wi-Fi", KindWireless},
		{"windows", "vEthernet (Default Switch)", "vEthernet (Default Switch)", KindVirtual},
		{"windows", "Loopback Pseudo-Interface 1", "Loopback Pseudo-Interface 1", KindLoopback},
		// UniFi
		{"unifi", "Port 24", "Port 24", KindPhysical},
		{"unifi", "port24", "Port 24", KindPhysical},
		{"ubiquiti", "Port 1", "Port 1", KindPhysical},
		{"unifi", "SFP+ 2", "SFP+ 2", KindPhysical},
		{"unifi", "eth0", "eth0", KindPhysical},
		{"unifi", "br0", "br0", KindBridge},
		// No vendor: the name speaks for itself, conservatively.
		{"", "Gi1/0/24", "GigabitEthernet1/0/24", KindPhysical},
		{"", "gi1/0/24", "GigabitEthernet1/0/24", KindPhysical},
		{"", "Po1", "Port-channel1", KindLAG},
		{"", "Port-Channel1", "Port-Channel1", KindLAG},
		{"", "Ethernet1", "Ethernet1", KindPhysical},
		{"", "ge-0/0/0", "ge-0/0/0", KindPhysical},
		{"", "ae1", "ae1", KindLAG},
		{"", "eth0", "eth0", KindPhysical},
		{"", "lo0", "lo0", KindLoopback},
		{"", "em1", "em1", KindPhysical},
		{"", "Ethernet 2", "Ethernet 2", KindPhysical},
		{"", "something-odd", "something-odd", KindUnknown},
		{"", "   ", "", KindUnknown},
	}
	if len(cases) < 60 {
		t.Fatalf("the brief asks for at least 60 cases; have %d", len(cases))
	}
	for _, c := range cases {
		name, kind := Canonical(c.vendor, c.raw)
		if name != c.want || kind != string(c.kind) {
			t.Errorf("Canonical(%q, %q) = (%q, %q), want (%q, %q)", c.vendor, c.raw, name, kind, c.want, c.kind)
		}
	}
}

func TestIfnames_Short(t *testing.T) {
	cases := []struct{ vendor, name, want string }{
		{"cisco", "GigabitEthernet1/0/24", "Gi1/0/24"},
		{"cisco", "TenGigabitEthernet1/1/1", "Te1/1/1"},
		{"cisco", "Port-channel1", "Po1"},
		{"cisco", "Vlan10", "Vl10"},
		{"cisco", "Loopback0", "Lo0"},
		{"arista", "Ethernet1", "Et1"},
		{"arista", "Port-Channel1", "Po1"},
		{"juniper", "ge-0/0/0", "ge-0/0/0"},
		{"linux", "eth0", "eth0"},
		{"", "GigabitEthernet1/0/1", "Gi1/0/1"},
	}
	for _, c := range cases {
		if got := Short(c.vendor, c.name); got != c.want {
			t.Errorf("Short(%q, %q) = %q, want %q", c.vendor, c.name, got, c.want)
		}
	}
}

// Canonical is idempotent: a canonical name canonicalises to itself, so intake
// can run every name through it without a second pass drifting the identity.
func TestIfnames_CanonicalIsIdempotent(t *testing.T) {
	for _, v := range []string{"cisco", "arista", "juniper", "fortinet", "linux", "windows", "unifi", ""} {
		for _, raw := range []string{"Gi1/0/1", "Po1", "Et1", "ge-0/0/0.0", "port1", "eth0", "Ethernet 2", "Port 24", "Vl10", "Ma1"} {
			once, _ := Canonical(v, raw)
			twice, _ := Canonical(v, once)
			if once != twice {
				t.Errorf("vendor %q: %q -> %q -> %q", v, raw, once, twice)
			}
		}
	}
}
