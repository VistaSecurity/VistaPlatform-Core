package services

import "testing"

// TestVlanSegmentSpecs pins which net.vlans entries become network segments,
// what DHCP posture each carries, and what network type its prefix earns.
//
// The fixtures are the shapes the collectors actually emit (see
// shared/deviceinterrogation fortinetVLANs, f5VLANs and the UniFi network
// projection), because the bug this guards was a gate that only one vendor's
// shape could pass: FortiGate and F5 already reported subnet and gateway and
// every one of those entries was dropped for lacking `dhcp_enabled`.
func TestVlanSegmentSpecs(t *testing.T) {
	cases := []struct {
		name  string
		entry map[string]any
		want  *vlanSegmentSpec // nil = no segment
	}{
		{
			name:  "unifi network with DHCP on is a dynamic segment",
			entry: map[string]any{"name": "Default", "subnet": "192.168.1.0/24", "gateway": "192.168.1.1", "dhcp_enabled": true},
			want:  &vlanSegmentSpec{CIDR: "192.168.1.0/24", Name: "Default", DHCP: dhcpEnabled, NetworkType: "private"},
		},
		{
			name:  "unifi network with DHCP off is a static segment",
			entry: map[string]any{"name": "IoT", "subnet": "192.168.20.0/24", "dhcp_enabled": false},
			want:  &vlanSegmentSpec{CIDR: "192.168.20.0/24", Name: "IoT", DHCP: dhcpDisabled, NetworkType: "private"},
		},
		{
			name:  "fortinet subinterface: subnet and gateway, no DHCP posture",
			entry: map[string]any{"id": 100, "name": "port1.100", "subnet": "10.20.30.0/24", "gateway": "10.20.30.1"},
			want:  &vlanSegmentSpec{CIDR: "10.20.30.0/24", Name: "port1.100", DHCP: dhcpUnknown, NetworkType: "private"},
		},
		{
			name:  "f5 self-IP: prefix masked from the device's own address",
			entry: map[string]any{"id": 4094, "name": "internal", "subnet": "172.16.5.10/23", "gateway": "172.16.5.10"},
			want:  &vlanSegmentSpec{CIDR: "172.16.4.0/23", Name: "internal", DHCP: dhcpUnknown, NetworkType: "private"},
		},
		{
			// Carrier space — a firewall's ISP-facing VLAN. Learning it as
			// private would be a declaration of ownership the tenant never
			// made, and a private segment authorises unattended scans.
			name:  "RFC 6598 carrier-grade NAT space is public",
			entry: map[string]any{"subnet": "100.64.8.0/22"},
			want:  &vlanSegmentSpec{CIDR: "100.64.8.0/22", Name: "100.64.8.0/22", DHCP: dhcpUnknown, NetworkType: "public"},
		},
		{
			name:  "an IPv4-mapped IPv6 prefix is stored as the IPv4 prefix it denotes",
			entry: map[string]any{"name": "mapped", "subnet": "::ffff:10.9.8.0/120"},
			want:  &vlanSegmentSpec{CIDR: "10.9.8.0/24", Name: "mapped", DHCP: dhcpUnknown, NetworkType: "private"},
		},
		{name: "an IPv4-mapped host route", entry: map[string]any{"subnet": "::ffff:10.9.8.7/128"}},
		{name: "an IPv4-mapped prefix reaching outside mapped space", entry: map[string]any{"subnet": "::ffff:0.0.0.0/95"}},
		{
			name:  "RFC 4193 ULA is private",
			entry: map[string]any{"name": "v6 lan", "subnet": "fd12:3456:789a:1::/64"},
			want:  &vlanSegmentSpec{CIDR: "fd12:3456:789a:1::/64", Name: "v6 lan", DHCP: dhcpUnknown, NetworkType: "private"},
		},
		{
			name:  "a tenant-owned public prefix learned from its firewall is public",
			entry: map[string]any{"name": "dmz", "subnet": "198.51.100.0/24", "gateway": "198.51.100.1"},
			want:  &vlanSegmentSpec{CIDR: "198.51.100.0/24", Name: "dmz", DHCP: dhcpUnknown, NetworkType: "public"},
		},
		{
			name:  "a prefix wider than the private block it starts in is public",
			entry: map[string]any{"subnet": "10.0.0.0/7"},
			want:  &vlanSegmentSpec{CIDR: "10.0.0.0/7", Name: "10.0.0.0/7", DHCP: dhcpUnknown, NetworkType: "public"},
		},
		{
			name:  "a non-boolean dhcp_enabled is not an answer",
			entry: map[string]any{"subnet": "192.168.9.0/24", "dhcp_enabled": "yes"},
			want:  &vlanSegmentSpec{CIDR: "192.168.9.0/24", Name: "192.168.9.0/24", DHCP: dhcpUnknown, NetworkType: "private"},
		},
		{name: "cisco VLAN database entry: id and name only", entry: map[string]any{"id": 30, "name": "voice"}},
		{name: "IPv4 host route", entry: map[string]any{"subnet": "192.0.2.7/32"}},
		{name: "IPv6 host route", entry: map[string]any{"subnet": "2001:db8::7/128"}},
		{name: "IPv4 default route", entry: map[string]any{"subnet": "0.0.0.0/0"}},
		{name: "IPv6 default route", entry: map[string]any{"subnet": "::/0"}},
		{name: "loopback", entry: map[string]any{"subnet": "127.0.0.0/8"}},
		{name: "IPv4 link-local", entry: map[string]any{"subnet": "169.254.0.0/16"}},
		{name: "IPv6 link-local", entry: map[string]any{"subnet": "fe80::/64"}},
		{name: "multicast", entry: map[string]any{"subnet": "239.1.0.0/16"}},
		{name: "unparseable subnet", entry: map[string]any{"name": "junk", "subnet": "not-a-prefix", "dhcp_enabled": true}},
		{name: "subnet is not a string", entry: map[string]any{"subnet": 24}},
		{name: "empty subnet", entry: map[string]any{"subnet": "  "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := vlanSegmentSpecs([]map[string]any{tc.entry})
			if tc.want == nil {
				if len(got) != 0 {
					t.Fatalf("specs = %+v, want none", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("specs = %+v, want exactly %+v", got, *tc.want)
			}
			if got[0] != *tc.want {
				t.Fatalf("spec = %+v, want %+v", got[0], *tc.want)
			}
		})
	}
}

// TestVlanSegmentSpecs_LeaseScope pins the identity-safety half of the DHCP
// posture: only a network the device positively said serves no DHCP lets a
// bare address vote. Unknown is treated like dynamic for that one purpose, so
// a reused lease can never join two devices on a network nobody measured.
func TestVlanSegmentSpecs_LeaseScope(t *testing.T) {
	for posture, want := range map[dhcpPosture]bool{dhcpEnabled: true, dhcpUnknown: true, dhcpDisabled: false} {
		if got := (vlanSegmentSpec{DHCP: posture}).leaseScope(); got != want {
			t.Errorf("leaseScope(%s) = %v, want %v", posture, got, want)
		}
	}
}

// TestVlanSegmentMetadata pins what a learned segment records about itself:
// an unknown posture is written as unknown and never as `dynamic`, which
// ScopeForAddress and every other reader take as a measured answer.
func TestVlanSegmentMetadata(t *testing.T) {
	unknown := vlanSegmentMetadata(vlanSegmentSpec{DHCP: dhcpUnknown}, "fortinet", "asset-1")
	if _, has := unknown["dynamic"]; has {
		t.Fatalf("unknown posture wrote dynamic: %v", unknown)
	}
	if unknown["dhcp"] != "unknown" || unknown["source"] != segmentSourceInterrogation ||
		unknown["source_device_type"] != "fortinet" || unknown["source_asset_id"] != "asset-1" {
		t.Fatalf("unknown metadata = %v", unknown)
	}
	if on := vlanSegmentMetadata(vlanSegmentSpec{DHCP: dhcpEnabled}, "unifi", "a"); on["dynamic"] != true || on["dhcp"] != "enabled" {
		t.Fatalf("enabled metadata = %v", on)
	}
	if off := vlanSegmentMetadata(vlanSegmentSpec{DHCP: dhcpDisabled}, "unifi", "a"); off["dynamic"] != false || off["dhcp"] != "disabled" {
		t.Fatalf("disabled metadata = %v", off)
	}
	if bare := vlanSegmentMetadata(vlanSegmentSpec{DHCP: dhcpUnknown}, "", "a"); bare["source_device_type"] != nil {
		t.Fatalf("an asset with no device type must not record an empty one: %v", bare)
	}
}
