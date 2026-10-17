package identity

import (
	"strings"
	"testing"
)

func TestNormalizeObservedNeighbors(t *testing.T) {
	in := []ObservedNeighbor{
		{Protocol: "LLDP", LocalInterface: " Gi1/0/1 ", RemoteChassisID: "00b0.e1a2.0001", RemotePortID: " Gi1/0/24 ", RemoteMgmtAddress: "fe80::1%eth0"},
		{Protocol: "cdp", LocalInterface: "Gi1/0/2", RemoteSystemName: "core\x00-sw", RemoteMgmtAddress: "::ffff:198.51.100.1"},
		{Protocol: "lldp", LocalInterface: "Gi1/0/1", RemoteChassisID: "00:B0:E1:A2:00:01", RemotePortID: "Gi1/0/24"}, // duplicate of the first
		{Protocol: "arp", LocalInterface: "Gi1/0/3", RemoteSystemName: "x"},                                           // not a neighbour protocol
		{Protocol: "lldp", LocalInterface: "", RemoteSystemName: "x"},                                                 // no local port
		{Protocol: "lldp", LocalInterface: "Gi1/0/4", RemotePortID: "1"},                                              // nothing to find the far end by
		{Protocol: "lldp", LocalInterface: "Gi1/0/5", RemoteChassisID: "sw-by-name", RemoteSystemName: strings.Repeat("n", 300)},
	}
	out, dropped := NormalizeObservedNeighbors(in)
	if len(out) != 3 || len(dropped) != 3 {
		t.Fatalf("kept %d dropped %d (%v), want 3 and 3: %+v", len(out), len(dropped), dropped, out)
	}
	first := out[0]
	if first.Protocol != "lldp" || first.LocalInterface != "GigabitEthernet1/0/1" || first.RemoteChassisID != "00:b0:e1:a2:00:01" ||
		first.RemotePortID != "Gi1/0/24" || first.RemoteMgmtAddress != "fe80::1" {
		t.Errorf("first = %+v", first)
	}
	if out[1].RemoteSystemName != "core-sw" || out[1].RemoteMgmtAddress != "198.51.100.1" {
		t.Errorf("control character or mapped address kept: %+v", out[1])
	}
	if out[2].RemoteChassisID != "sw-by-name" || len(out[2].RemoteSystemName) != maxNeighborField {
		t.Errorf("non-MAC chassis id or bound wrong: %+v", out[2])
	}
}
