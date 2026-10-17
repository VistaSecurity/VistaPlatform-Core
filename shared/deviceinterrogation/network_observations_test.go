package deviceinterrogation

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// assertNetworkCarriesNo fails when any value in needles appears anywhere in
// the network observation.
func assertNetworkCarriesNo(t *testing.T, n any, needles ...string) {
	t.Helper()
	blob, err := json.Marshal(n)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, s := range needles {
		if strings.Contains(string(blob), s) {
			t.Errorf("the network observation carries %q: %s", s, blob)
		}
	}
}

// Every type a network projection decodes a vendor response into, and the
// carrier itself. Their json tags are the allowlist (the typed-struct form of
// the projection rule), so they are held to the same review as the named
// allowlists in TestProjectionAllowlists_NameNoSecretFields.
//
// Mutation: add a field tagged json:"psksecret" to fortinetCmdbInterface — red.
func TestNetworkProjectionStructs_NameNoSecretFields(t *testing.T) {
	types := []any{
		NetworkObservation{}, ObservedInterface{}, ObservedAddress{}, ObservedPrefix{}, ObservedVLAN{}, ObservedARPEntry{},
		ObservedInventoryItem{}, ObservedModule{}, ObservedVirtualChassis{}, ObservedVirtualChassisMember{},
		fortinetCmdbInterface{}, fortinetMonitorInterface{}, fortinetARP{},
		f5NetInterface{}, f5NetTrunk{}, f5NetVLANExpanded{}, f5NetVLANMember{}, f5RouteDomain{}, f5ARP{}, f5SelfIP{},
		panNetIfnet{}, panNetHW{},
	}
	var walk func(reflect.Type, string)
	seen := map[reflect.Type]bool{}
	walk = func(rt reflect.Type, path string) {
		for rt.Kind() == reflect.Pointer || rt.Kind() == reflect.Slice {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct || seen[rt] {
			return
		}
		seen[rt] = true
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			for _, tag := range []string{f.Tag.Get("json"), f.Tag.Get("xml")} {
				name := strings.Split(tag, ",")[0]
				for _, part := range strings.Split(name, ">") {
					if part != "" && part != "-" && redact.IsSecretName(part) {
						t.Errorf("%s.%s binds %q, a secret-shaped field name", path, f.Name, part)
					}
				}
			}
			walk(f.Type, path+"."+f.Name)
		}
	}
	for _, v := range types {
		rt := reflect.TypeOf(v)
		walk(rt, rt.Name())
	}
}

// Every type key a projection can emit is a key of the interface-type
// registry (shared/dcim): an unknown key would be silently replaced by
// `other` at intake.
func TestMediaInterfaceType_EmitsRegistryKeys(t *testing.T) {
	cases := []struct {
		media string
		speed int64
		want  string
	}{
		{"10/100/1000BaseTX", 1000, "1000base-t"},
		{"10/100/1000BaseTX", 0, "1000base-t"},
		{"10/100/1000BaseTX", 100, "100base-tx"},
		{"SFP-10GBase-SR", 10000, "10gbase-x-sfpp"},
		{"1000BaseSX SFP", 1000, "1000base-sx"},
		{"1000BaseLX SFP", 1000, "1000base-lx"},
		{"1000BaseT SFP", 1000, "1000base-x-sfp"}, // a copper module in an SFP cage: the cage is the form factor
		{"SFP-25GBase-SR SFP28", 25000, "25gbase-x-sfp28"},
		{"QSFP-40G-SR4", 40000, "40gbase-x-qsfpp"},
		{"QSFP28 100GBase-SR4", 100000, "100gbase-x-qsfp28"},
		{"1000T-FD", 1000, "1000base-t"},
		{"10000SR-FD", 10000, "10gbase-x-sfpp"},
		{"10000T-FD", 10000, "10gbase-t"},
		{"100TX-FD", 100, "100base-tx"},
		{"1000SX-FD", 1000, "1000base-sx"},
		{"auto", 0, ""},
		{"none", 0, ""},
		{"Not Present", 0, ""},
		{"", 1000, ""},
		{"N/A", 1000, ""},
	}
	for _, c := range cases {
		got := mediaInterfaceType(c.media, c.speed)
		if got != c.want {
			t.Errorf("mediaInterfaceType(%q, %d) = %q, want %q", c.media, c.speed, got, c.want)
		}
		if got != "" {
			if _, ok := dcim.ParseInterfaceType(got); !ok {
				t.Errorf("mediaInterfaceType(%q) = %q, which the interface-type registry does not hold", c.media, got)
			}
		}
	}
}

func TestExpandVLANList(t *testing.T) {
	cases := []struct {
		in   string
		want []int
		all  bool
	}{
		{"10,20,30", []int{10, 20, 30}, false},
		{"10-12,30", []int{10, 11, 12, 30}, false},
		{"1-4094", nil, true},
		{"1-4095", nil, true},
		{"none", nil, false},
		{"", nil, false},
		{"0,5000,7", []int{7}, false},
		{"20,10,10", []int{10, 20}, false},
	}
	for _, c := range cases {
		got, all := expandVLANList(c.in)
		if all != c.all || !slices.Equal(got, c.want) {
			t.Errorf("expandVLANList(%q) = %v, %v; want %v, %v", c.in, got, all, c.want, c.all)
		}
	}
}

func TestConnectedPrefixes(t *testing.T) {
	got := connectedPrefixes([]netIface{
		{Name: "Vlan10", Addresses: []netAddr{{Address: "10.0.10.1/24"}}},
		{Name: "Gi0/0.20", Mode: "access", UntaggedVLAN: 20, Addresses: []netAddr{{Address: "10.0.20.1/24", VRF: "red"}}},
		{Name: "Loopback0", Addresses: []netAddr{{Address: "10.255.0.1/32"}}},
		{Name: "Gi0/1", Addresses: []netAddr{{Address: "192.0.2.1"}}},
		{Name: "Gi0/2", Mode: "tagged", UntaggedVLAN: 1, Addresses: []netAddr{{Address: "198.51.100.1/30"}}},
		{Name: "Vlan11", Addresses: []netAddr{{Address: "10.0.10.2/24"}}},
	})
	want := []netPrefix{
		{Prefix: "10.0.10.0/24", VLAN: 10},
		{Prefix: "10.0.20.0/24", VRF: "red", VLAN: 20},
		{Prefix: "198.51.100.0/30"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("connectedPrefixes = %+v, want %+v (a host route, a bare address and a duplicate are not prefixes; a trunk's address is on no one VLAN)", got, want)
	}
}

func TestF5SplitRouteDomain(t *testing.T) {
	for in, want := range map[string]struct {
		addr string
		rd   int
	}{
		"10.1.20.5%2/24":   {"10.1.20.5/24", 2},
		"10.1.20.5/24":     {"10.1.20.5/24", 0},
		"10.1.20.5%7":      {"10.1.20.5", 7},
		"2001:db8::5%3/64": {"2001:db8::5/64", 3},
	} {
		addr, rd := f5SplitRouteDomain(in)
		if addr != want.addr || rd != want.rd {
			t.Errorf("f5SplitRouteDomain(%q) = %q, %d; want %q, %d", in, addr, rd, want.addr, want.rd)
		}
	}
	if got := f5VRF(0, map[int]string{0: "0"}); got != "" {
		t.Errorf("route domain 0 is the global table, got VRF %q", got)
	}
	if got := f5VRF(2, map[int]string{2: "tenant-a"}); got != "tenant-a" {
		t.Errorf("route domain 2 = %q, want its name", got)
	}
	if got := f5VRF(4, nil); got != "rd4" {
		t.Errorf("unnamed route domain 4 = %q, want rd4", got)
	}
}

func TestVRFNamesForTheDefaultInstanceAreGlobal(t *testing.T) {
	for in, want := range map[string]string{"vr:default": "", "lr:default": "", "vr:corp": "corp", "N/A": "", "": ""} {
		if got := panVRF(in); got != want {
			t.Errorf("panVRF(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"root": "", "ROOT": "", "": "", "guest": "guest"} {
		if got := fortinetVRF(in); got != want {
			t.Errorf("fortinetVRF(%q) = %q, want %q", in, got, want)
		}
	}
}

// Sanitize walks the network observation: a device-chosen name carrying a
// pasted private key is masked, and the posture beside it survives.
func TestSanitize_MasksTheNetworkObservationsFreeText(t *testing.T) {
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
	result := &InterrogateResult{Network: &NetworkObservation{
		Interfaces: []ObservedInterface{{Name: "port1", Parent: pem, Addresses: []ObservedAddress{{Address: "192.0.2.1/24", VRF: pem}}}},
		VLANs:      []ObservedVLAN{{VID: 10, Name: pem}},
		ARP:        []ObservedARPEntry{{Address: "192.0.2.9", MAC: "00:00:5e:00:53:09", Interface: pem}},
	}}
	Sanitize(result)
	assertNetworkCarriesNo(t, result.Network, "PRIVATE KEY", "MIIEowIBAAKCAQEA")
	if result.Network.Interfaces[0].Name != "port1" || result.Network.Interfaces[0].Addresses[0].Address != "192.0.2.1/24" ||
		result.Network.VLANs[0].VID != 10 || result.Network.ARP[0].MAC != "00:00:5e:00:53:09" {
		t.Errorf("Sanitize ate the posture: %+v", result.Network)
	}
}

// setNetwork bounds every table and says so.
func TestSetNetwork_BoundsTheARPTableAndWarns(t *testing.T) {
	n := &vendorNetwork{}
	for i := 0; i < maxARPEntries+5; i++ {
		n.ARP = append(n.ARP, netARP{Address: "192.0.2.1", MAC: "00:00:5e:00:53:01"})
	}
	r := &InterrogateResult{collector: "cisco"}
	r.setNetwork(n, "show ip arp")
	if len(r.Network.ARP) != maxARPEntries {
		t.Errorf("ARP table kept %d entries, want the bound %d", len(r.Network.ARP), maxARPEntries)
	}
	if len(r.Warnings) != 1 || r.Warnings[0].Reason != WarningTruncated {
		t.Errorf("no truncation warning: %+v", r.Warnings)
	}
	empty := &InterrogateResult{}
	empty.setNetwork(&vendorNetwork{}, "x")
	if empty.Network != nil {
		t.Error("an empty observation was stored")
	}
}

// --- Cisco ---------------------------------------------------------------------

const ciscoUnitInterfaces = `GigabitEthernet0/0 is up, line protocol is up
  Hardware is iGbE, address is 5254.0012.0001 (bia 5254.0012.0001)
  Description: wan PSK-LOOKALIKE-crypto isakmp key 0 MUST-NOT-BE-COLLECTED
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
  Full-duplex, 1000Mb/s, media type is RJ45
GigabitEthernet0/0.30 is up, line protocol is up
  Hardware is iGbE, address is 5254.0012.0001 (bia 5254.0012.0001)
  Internet address is 10.9.30.1/24
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
  Encapsulation 802.1Q Virtual LAN, Vlan ID  30.
`

const ciscoUnitARP = `Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.9.30.1               -   5254.0012.0001  ARPA   GigabitEthernet0/0.30
Internet  10.9.30.40             12   0050.56aa.0040  ARPA   GigabitEthernet0/0.30
Internet  10.9.30.41             12   Incomplete      ARPA
`

// A router-on-a-stick sub-interface is its parent plus its untagged VLAN, the
// connected prefix sits on that VLAN, the device's own ARP entry is not
// evidence about another host, and the Description line is never read.
func TestCiscoNetwork_SubInterfaceAndARP(t *testing.T) {
	n := ciscoNetwork(ciscoNetworkInputs{
		interfaces: ciscoUnitInterfaces,
		merged:     ciscoParseInterfaces(ciscoUnitInterfaces),
		arp:        ciscoParseARP(ciscoUnitARP),
	})
	assertNetworkCarriesNo(t, n, "MUST-NOT-BE-COLLECTED", "isakmp")
	if len(n.Interfaces) != 2 {
		t.Fatalf("interfaces = %+v", n.Interfaces)
	}
	phys, sub := n.Interfaces[0], n.Interfaces[1]
	if phys.Name != "GigabitEthernet0/0" || phys.Type != "1000base-t" || phys.SpeedKbps != 1_000_000 || phys.MTU != 1500 {
		t.Errorf("physical port: %+v", phys)
	}
	if sub.Parent != "GigabitEthernet0/0" || sub.UntaggedVLAN != 30 || sub.Mode != "access" || sub.SpeedKbps != 0 {
		t.Errorf("sub-interface: %+v", sub)
	}
	if len(n.Prefixes) != 1 || n.Prefixes[0] != (netPrefix{Prefix: "10.9.30.0/24", VLAN: 30}) {
		t.Errorf("prefixes = %+v", n.Prefixes)
	}
	if len(n.ARP) != 1 || n.ARP[0].Address != "10.9.30.40" || n.ARP[0].MAC != "00:50:56:aa:00:40" {
		t.Errorf("ARP = %+v, want only the neighbour (own entry and incomplete dropped)", n.ARP)
	}
}

// `show interfaces status` is read by column position; the Name column (a
// free-text port description) is never sliced out.
func TestCiscoParseInterfacesStatus_NeverReadsTheNameColumn(t *testing.T) {
	out := "Port         Name               Status       Vlan       Duplex  Speed Type\n" +
		"Gi1/0/1      trunk 10 secretXYZ connected    10         a-full a-1000 10/100/1000BaseTX\n" +
		"Gi1/0/2                         connected    trunk      a-full a-1000 10/100/1000BaseTX\n" +
		"Te1/1/1                         notconnect   1            full    10G SFP-10GBase-SR\n"
	got := ciscoParseInterfacesStatus(out)
	if got["GigabitEthernet1/0/1"].vlan != "10" || got["GigabitEthernet1/0/2"].vlan != "trunk" || got["TenGigabitEthernet1/1/1"].media != "SFP-10GBase-SR" {
		t.Errorf("status rows = %+v", got)
	}
	blob, _ := json.Marshal(got)
	if strings.Contains(string(blob), "secretXYZ") {
		t.Error("the Name column was read")
	}
}

func TestCiscoParseInterfacesTrunk_NativeAndWrappedAllowedList(t *testing.T) {
	out := `
Port        Mode             Encapsulation  Status        Native vlan
Po1         on               802.1q         trunking      99
Gi1/0/9     on               802.1q         trunking      1

Port        Vlans allowed on trunk
Po1         10,20-22,
            99
Gi1/0/9     1-4094

Port        Vlans allowed and active in management domain
Po1         10
`
	got := ciscoParseInterfacesTrunk(out)
	po := got["Port-channel1"]
	if po == nil || po.native != 99 || !slices.Equal(po.allowed, []int{10, 20, 21, 22, 99}) || po.all {
		t.Errorf("Po1 = %+v", po)
	}
	if gi := got["GigabitEthernet1/0/9"]; gi == nil || !gi.all || gi.native != 1 {
		t.Errorf("Gi1/0/9 = %+v, want tagged-all with native 1", gi)
	}
}

// setNetwork canonicalises every name once, with the vendor family, so the
// names an ARP entry, a parent or a LAG refer to are spelled as the interface
// they name: the ARP rule parks an unknown entry against the learning
// interface BY NAME.
func TestSetNetwork_CanonicalisesEveryCrossReference(t *testing.T) {
	r := &InterrogateResult{}
	r.setNetwork(&vendorNetwork{
		Interfaces: []netIface{{Name: "ethernet1/2"}, {Name: "ethernet1/2.100", Parent: "ethernet1/2", LAG: "ae1"}},
		ARP:        []netARP{{Address: "192.0.2.9", MAC: "00:00:5e:00:53:09", Interface: "ethernet1/2.100"}, {Address: "192.0.2.10", MAC: "00:00:5e:00:53:0a", VRF: "red"}},
	}, "x")
	n := r.Network
	if n.Interfaces[0].Name != "Ethernet1/2" || n.Interfaces[1].Name != "Ethernet1/2.100" ||
		n.Interfaces[1].Parent != "Ethernet1/2" || n.Interfaces[1].LAG != "ae1" {
		t.Errorf("interfaces = %+v", n.Interfaces)
	}
	if len(n.ARP) != 1 || n.ARP[0].Interface != "Ethernet1/2.100" {
		t.Errorf("ARP = %+v, want the global-table entry, its interface spelled as the interface is", n.ARP)
	}
}

// The management address is the record's address, else the management URL's
// host — never a loopback or link-local one, which is how a test or a tunnel
// reached the device.
func TestSetNetworkManagementAddress(t *testing.T) {
	for _, c := range []struct {
		device DeviceInfo
		want   string
	}{
		{DeviceInfo{IPAddress: "198.51.100.7"}, "198.51.100.7"},
		{DeviceInfo{ManagementURL: "https://198.51.100.8:8443/"}, "198.51.100.8"},
		{DeviceInfo{IPAddress: "fw.example.test", ManagementURL: "https://[2001:db8::8]/"}, "2001:db8::8"},
		{DeviceInfo{IPAddress: "127.0.0.1", ManagementURL: "https://127.0.0.1:1234"}, ""},
		{DeviceInfo{ManagementURL: "https://fe80::1/"}, ""},
		{DeviceInfo{ManagementURL: "https://fw.example.test/"}, ""},
	} {
		r := &InterrogateResult{Network: &NetworkObservation{}}
		r.setNetworkManagementAddress(c.device)
		if r.Network.ManagementAddress != c.want {
			t.Errorf("%+v: management address %q, want %q", c.device, r.Network.ManagementAddress, c.want)
		}
	}
	// A collector that measured no network has nothing to stamp.
	empty := &InterrogateResult{}
	empty.setNetworkManagementAddress(DeviceInfo{IPAddress: "198.51.100.7"})
	if empty.Network != nil {
		t.Error("a management address created a network observation")
	}
}
