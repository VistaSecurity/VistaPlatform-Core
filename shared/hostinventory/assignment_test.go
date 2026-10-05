package hostinventory

import (
	"context"
	"reflect"
	"testing"
)

//: the host's own account of how each address is assigned. A STATIC
// answer pins the address to its asset inside a segment flagged DHCP, so every
// parser here errs towards unknown: only a positive statement from the OS is
// static or dynamic.

// TestParseIPJSON_AddressAssignment: no lifetime and no flag is static; the
// `dynamic` flag is a lease (DHCP or SLAAC); a finite lifetime without the flag
// (an address added with valid_lft by hand) is a statement neither way.
//
// Mutation checks: classify every no-flag address static (drop the forever
// test in linuxAssignment) → .9 is static and this fails; drop the Dynamic arm
// → .77 is not dynamic and this fails.
func TestParseIPJSON_AddressAssignment(t *testing.T) {
	ifaces, err := ParseIPJSON([]byte(fixture(t, "linux", "ip-j-addr-assignment.json")))
	if err != nil {
		t.Fatal(err)
	}
	eth0 := ifaces[1]
	if want := []string{"198.51.100.1/24", "2001:db8:aa::1/64"}; !reflect.DeepEqual(eth0.StaticAddresses, want) {
		t.Errorf("static = %v, want %v", eth0.StaticAddresses, want)
	}
	if want := []string{"198.51.100.77/24", "2001:db8:aa::5/64"}; !reflect.DeepEqual(eth0.DynamicAddresses, want) {
		t.Errorf("dynamic = %v, want %v", eth0.DynamicAddresses, want)
	}
	// The original fixture predates lifetimes in the output: every address
	// in it is unknown, not static.
	old, err := ParseIPJSON([]byte(fixture(t, "linux", "ip-j-addr.json")))
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range old {
		if len(i.StaticAddresses)+len(i.DynamicAddresses) != 0 {
			t.Errorf("%s: output with no lifetimes claimed an assignment: static %v dynamic %v", i.Name, i.StaticAddresses, i.DynamicAddresses)
		}
	}
}

// TestParseWindowsAdapters_AddressAssignment: Manual/Manual is static, a DHCP
// or router-advertisement origin is a lease, WellKnown and an absent origin are
// unknown.
func TestParseWindowsAdapters_AddressAssignment(t *testing.T) {
	raw := `[{"Name":"Ethernet","MAC":"B4-96-91-1A-2B-3C","Status":"Up","Virtual":false,
	  "Addresses":["198.51.100.1/24","198.51.100.77/24","fe80::1/64","2001:db8:aa::5/64","198.51.100.9/24"],
	  "Origins":[
	    {"Address":"198.51.100.1/24","Prefix":"Manual","Suffix":"Manual"},
	    {"Address":"198.51.100.77/24","Prefix":"Dhcp","Suffix":"Dhcp"},
	    {"Address":"fe80::1/64","Prefix":"WellKnown","Suffix":"Link"},
	    {"Address":"2001:db8:aa::5/64","Prefix":"RouterAdvertisement","Suffix":"Random"}]}]`
	ifaces, err := ParseWindowsAdapters([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"198.51.100.1/24"}; !reflect.DeepEqual(ifaces[0].StaticAddresses, want) {
		t.Errorf("static = %v, want %v", ifaces[0].StaticAddresses, want)
	}
	if want := []string{"198.51.100.77/24", "2001:db8:aa::5/64"}; !reflect.DeepEqual(ifaces[0].DynamicAddresses, want) {
		t.Errorf("dynamic = %v, want %v", ifaces[0].DynamicAddresses, want)
	}
}

// TestDarwinAssignments: ipconfig's ConfigMethod decides IPv4 when it answers,
// the DHCP packet's yiaddr when it does not, and a missing command leaves
// everything unknown. IPv6 autoconf/temporary flags from ifconfig are leases.
func TestDarwinAssignments(t *testing.T) {
	ifc := ParseIfconfig([]byte(`en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether b4:96:91:1a:2b:3c
	inet6 2001:db8:aa::5 prefixlen 64 autoconf secured
	inet6 2001:db8:aa::1 prefixlen 64
	inet 198.51.100.1 netmask 0xffffff00 broadcast 198.51.100.255
	status: active
en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether b4:96:91:1a:2b:3d
	inet 198.51.100.77 netmask 0xffffff00 broadcast 198.51.100.255
	status: active
en2: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether b4:96:91:1a:2b:3e
	inet 198.51.100.88 netmask 0xffffff00 broadcast 198.51.100.255
	status: active
`))
	r := newFakeLocal().
		cmd([]string{"ipconfig", "getsummary", "en0"}, "<dictionary> {\n  IPv4 : <array> {\n    0 : <dictionary> {\n      ConfigMethod : Manual\n    }\n  }\n  IPv6 : <array> {\n    0 : <dictionary> {\n      ConfigMethod : Automatic\n    }\n  }\n}\n").
		cmdExit([]string{"ipconfig", "getsummary", "en1"}, 1, "").
		cmd([]string{"ipconfig", "getpacket", "en1"}, "op = BOOTREPLY\nciaddr = 0.0.0.0\nyiaddr = 198.51.100.77\nsiaddr = 198.51.100.1\n")
	darwinIPv4Assignments(context.Background(), r, ifc)

	if want := []string{"198.51.100.1/24"}; !reflect.DeepEqual(ifc[0].StaticAddresses, want) {
		t.Errorf("en0 static = %v, want %v", ifc[0].StaticAddresses, want)
	}
	if want := []string{"2001:db8:aa::5/64"}; !reflect.DeepEqual(ifc[0].DynamicAddresses, want) {
		t.Errorf("en0 dynamic = %v, want %v", ifc[0].DynamicAddresses, want)
	}
	if want := []string{"198.51.100.77/24"}; !reflect.DeepEqual(ifc[1].DynamicAddresses, want) || len(ifc[1].StaticAddresses) != 0 {
		t.Errorf("en1 = static %v dynamic %v, want the getpacket lease only", ifc[1].StaticAddresses, ifc[1].DynamicAddresses)
	}
	if len(ifc[2].StaticAddresses)+len(ifc[2].DynamicAddresses) != 0 {
		t.Errorf("en2: no ipconfig answer, yet static %v dynamic %v", ifc[2].StaticAddresses, ifc[2].DynamicAddresses)
	}
}

// TestProjectInterfaces_CarriesAssignment: the fact carries both lists, so the
// ingest sees what the collector read.
func TestProjectInterfaces_CarriesAssignment(t *testing.T) {
	got := projectInterfaces([]Interface{{Name: "eth0", Addresses: []string{"198.51.100.1/24", "198.51.100.77/24"},
		StaticAddresses: []string{"198.51.100.1/24"}, DynamicAddresses: []string{"198.51.100.77/24"}}})
	if !reflect.DeepEqual(got[0]["static_addresses"], []string{"198.51.100.1/24"}) ||
		!reflect.DeepEqual(got[0]["dynamic_addresses"], []string{"198.51.100.77/24"}) {
		t.Errorf("projected = %+v", got[0])
	}
}
