package hostinventory

import "testing"

// DCIM row 1.5a: the interface posture the platform turns into interfaces —
// MTU, the OS's kind for a software link, a VLAN's parent and id, a bond
// member's LAG (Linux `ip -d -j addr`); MTU, speed and VlanID (Windows).

func TestParseIPJSON_BondAndVLANSubInterface(t *testing.T) {
	out, err := ParseIPJSON([]byte(`[
	  {"ifname":"eth0","master":"bond0","mtu":9000,"operstate":"UP","link_type":"ether","address":"b4:96:91:1a:2b:3c",
	   "linkinfo":{"info_slave_kind":"bond"},"addr_info":[]},
	  {"ifname":"bond0","mtu":9000,"operstate":"UP","link_type":"ether","address":"b4:96:91:1a:2b:3c",
	   "ifalias":"secret-alias","linkinfo":{"info_kind":"bond","info_data":{"mode":"active-backup"}},"addr_info":[]},
	  {"ifname":"bond0.100","link":"bond0","mtu":9000,"operstate":"UP","link_type":"ether","address":"b4:96:91:1a:2b:3c",
	   "linkinfo":{"info_kind":"vlan","info_data":{"protocol":"802.1Q","id":100}},"addr_info":[]},
	  {"ifname":"veth1","master":"docker0","mtu":1500,"operstate":"UP","link_type":"ether","address":"6e:4f:2a:9c:11:02","addr_info":[]},
	  {"ifname":"docker0","mtu":1500,"operstate":"DOWN","link_type":"ether","address":"02:42:7b:0c:11:9a",
	   "linkinfo":{"info_kind":"bridge"},"addr_info":[]}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Interface{}
	for _, i := range out {
		by[i.Name] = i
	}
	if e := by["eth0"]; e.LAG != "bond0" || e.MTU != 9000 || e.Kind != "" {
		t.Errorf("eth0 = %+v, want a 9000-MTU member of bond0", e)
	}
	if b := by["bond0"]; b.Kind != "bond" || b.LAG != "" {
		t.Errorf("bond0 = %+v, want kind bond", b)
	}
	if v := by["bond0.100"]; v.Kind != "vlan" || v.Parent != "bond0" || v.VLAN != 100 {
		t.Errorf("bond0.100 = %+v, want vlan 100 on bond0", v)
	}
	// A bridge port's master is a bridge, not an aggregate.
	if v := by["veth1"]; v.LAG != "" {
		t.Errorf("veth1 LAG = %q, want none (docker0 is a bridge)", v.LAG)
	}
}

func TestParseWindowsAdapters_MTUSpeedVLAN(t *testing.T) {
	out, err := ParseWindowsAdapters([]byte(`[
	  {"Name":"Ethernet","MAC":"B4-96-91-1A-2B-4C","Status":"Up","Mtu":1500,"Speed":1000000000,"VlanID":0,"Addresses":[]},
	  {"Name":"Ethernet 2","MAC":"B4-96-91-1A-2B-4D","Status":"Disconnected","Mtu":1500,"Speed":0,"VlanID":0,"Addresses":[]},
	  {"Name":"Ethernet 3","MAC":"B4-96-91-1A-2B-4E","Status":"Up","Mtu":9014,"Speed":10000000000,"VlanID":30,"Addresses":[]}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 {
		t.Fatalf("adapters = %+v", out)
	}
	if e := out[0]; e.MTU != 1500 || e.SpeedMbps != 1000 || e.VLAN != 0 {
		t.Errorf("Ethernet = %+v, want mtu 1500, 1000 Mbit/s", e)
	}
	if e := out[1]; e.SpeedMbps != 0 {
		t.Errorf("a disconnected adapter's 0 speed is unknown, got %d", e.SpeedMbps)
	}
	if e := out[2]; e.MTU != 9014 || e.SpeedMbps != 10000 || e.VLAN != 30 {
		t.Errorf("Ethernet 3 = %+v, want mtu 9014, 10000 Mbit/s, VLAN 30", e)
	}
}

func TestProjectInterfaces_CarriesThePosture(t *testing.T) {
	got := projectInterfaces([]Interface{{Name: "bond0.100", MTU: 9000, SpeedMbps: 1000, Kind: "vlan", Parent: "bond0", VLAN: 100, LAG: ""}})
	e := got[0]
	if e["mtu"] != 9000 || e["speed"] != int64(1000) || e["kind"] != "vlan" || e["parent"] != "bond0" || e["vlan"] != 100 {
		t.Errorf("projection = %+v", e)
	}
	if _, ok := e["lag"]; ok {
		t.Error("an empty LAG was projected")
	}
}
