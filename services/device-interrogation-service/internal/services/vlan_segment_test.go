package services

import "testing"

func TestVlanSegmentSpecs_DHCPEnabledIsDynamic(t *testing.T) {
	specs := vlanSegmentSpecs([]map[string]any{
		{"name": "Default", "subnet": "192.168.1.0/24", "dhcp_enabled": true},
		{"name": "IoT", "subnet": "192.168.20.0/24", "dhcp_enabled": false},
		{"name": "NoDHCPKey", "subnet": "10.0.0.0/24"},
		{"id": 30},
	})
	if len(specs) != 2 {
		t.Fatalf("specs = %+v, want Default (dynamic) and IoT (static)", specs)
	}
	if specs[0].CIDR != "192.168.1.0/24" || !specs[0].Dynamic || specs[0].Name != "Default" {
		t.Errorf("DHCP LAN = %+v, want 192.168.1.0/24 dynamic Default", specs[0])
	}
	if specs[1].CIDR != "192.168.20.0/24" || specs[1].Dynamic {
		t.Errorf("static VLAN = %+v, want 192.168.20.0/24 not dynamic", specs[1])
	}
}
