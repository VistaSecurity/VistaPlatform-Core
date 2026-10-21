package deviceinterrogation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// DCIM gap 1, part 2: the Fortinet, Palo Alto, F5 and Cisco NX-OS collectors
// name each interface's virtual device context and list the device's
// contexts, projected from recorded (synthesised) responses in testdata/vdc —
// name and identifier only, never the vendor's context object.
//
// Mutations (each red, then restored green): drop `ifc.Context = vdom` in
// fortinetNetwork; drop the `<vsys>` binding (the Vsys field's tag) in
// panNetwork; drop the route domain's `vlans` binding in f5Network (servers'
// self-IP fallback then wins for every VLAN, internal moves to "0"); drop the
// `(b)` trim in ciscoParseVDCMembership; ask `show vdc membership` of every
// OS (the IOS polarity goes red); drop the `contexts[c]` guard in setNetwork.

const vdcPlantedSecret = "PlantedVdcSecret-4410"

func readVDCFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "vdc", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// projectNetwork runs a vendor projection through the wire conversion and
// the sanitiser, as production does.
func projectNetwork(t *testing.T, n *vendorNetwork) *NetworkObservation {
	t.Helper()
	r := &InterrogateResult{}
	r.setNetwork(n, "test")
	if r.Network == nil {
		t.Fatal("no network observation")
	}
	sanitizeNetwork(r.Network)
	blob, err := json.Marshal(r.Network)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), vdcPlantedSecret) {
		t.Fatalf("the planted secret reached the network observation: %s", blob)
	}
	return r.Network
}

type wantContext struct {
	name string
	id   int // -1: none
}

func contextsOf(n *NetworkObservation) []wantContext {
	var out []wantContext
	for _, c := range n.VirtualDeviceContexts {
		w := wantContext{name: c.Name, id: -1}
		if c.Identifier != nil {
			w.id = *c.Identifier
		}
		out = append(out, w)
	}
	return out
}

func interfaceContexts(n *NetworkObservation) map[string]string {
	out := map[string]string{}
	for _, ifc := range n.Interfaces {
		out[ifc.Name] = ifc.VirtualDeviceContext
	}
	return out
}

func checkContexts(t *testing.T, n *NetworkObservation, want []wantContext, wantIfc map[string]string) {
	t.Helper()
	if got := contextsOf(n); !reflect.DeepEqual(got, want) {
		t.Errorf("contexts %+v, want %+v", got, want)
	}
	got := interfaceContexts(n)
	for name, ctx := range wantIfc {
		v, ok := got[name]
		if !ok {
			t.Errorf("interface %q missing; have %v", name, got)
			continue
		}
		if v != ctx {
			t.Errorf("interface %q in context %q, want %q", name, v, ctx)
		}
	}
}

func TestVDCProjection_FortinetVDOMs(t *testing.T) {
	var resp struct {
		Results []map[string]interface{} `json:"results"`
	}
	if err := json.Unmarshal(readVDCFixture(t, "fortinet_cmdb_system_interface.json"), &resp); err != nil {
		t.Fatal(err)
	}
	n := projectNetwork(t, fortinetNetwork(resp.Results, nil, nil))
	// root is a context like any other VDOM; a VDOM has no number.
	checkContexts(t, n, []wantContext{{"root", -1}, {"branch-a", -1}}, map[string]string{
		"port1": "root", "port2": "root", "port3": "branch-a", "vlan-a-users": "branch-a", "ha": "",
	})
	// The VDOM → VRF mapping is kept: root is the global table, any other
	// VDOM the VRF of its addresses.
	for _, ifc := range n.Interfaces {
		for _, a := range ifc.Addresses {
			want := ""
			if ifc.VirtualDeviceContext == "branch-a" {
				want = "branch-a"
			}
			if a.VRF != want {
				t.Errorf("%s address %s in VRF %q, want %q", ifc.Name, a.Address, a.VRF, want)
			}
		}
	}
}

func TestVDCProjection_PaloAltoVsys(t *testing.T) {
	vn, err := panNetwork(string(readVDCFixture(t, "paloalto_show_interface_all.xml")), panSystemInfo{}, "")
	if err != nil {
		t.Fatal(err)
	}
	n := projectNetwork(t, vn)
	checkContexts(t, n, []wantContext{{"vsys1", 1}, {"vsys2", 2}}, map[string]string{
		"Ethernet1/1": "vsys1", "Ethernet1/2": "vsys2", "Ethernet1/2.20": "vsys2", "Ethernet1/4": "",
	})
}

// The operator's vsys display names ride on the contexts' description, and
// nothing else of the vsys entry does: not the import lists, not the planted
// setting. A vsys with no display-name (vsys1) and one no interface names
// (vsys3) add nothing.
//
// Mutation: drop the `panApplyVsysNames` call in collect (paloalto.go) or the
// `display-name` tag on panVsysEntry; return the whole entry instead of its
// display name and the planted-secret check goes red.
func TestVDCProjection_PaloAltoVsysDisplayNames(t *testing.T) {
	vn, err := panNetwork(string(readVDCFixture(t, "paloalto_show_interface_all.xml")), panSystemInfo{}, "")
	if err != nil {
		t.Fatal(err)
	}
	names, err := panVsysDisplayNames(string(readVDCFixture(t, "paloalto_config_vsys.xml")))
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"vsys2": "Tenant B Edge", "vsys3": "Unused lab"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("display names = %v, want %v", names, want)
	}
	panApplyVsysNames(vn, names)
	n := projectNetwork(t, vn)
	got := map[string]string{}
	for _, c := range n.VirtualDeviceContexts {
		got[c.Name] = c.Description
	}
	if want := map[string]string{"vsys1": "", "vsys2": "Tenant B Edge"}; !reflect.DeepEqual(got, want) {
		t.Errorf("context descriptions = %v, want %v", got, want)
	}
	// Names and identifiers are what they were.
	checkContexts(t, n, []wantContext{{"vsys1", 1}, {"vsys2", 2}}, map[string]string{
		"Ethernet1/1": "vsys1", "Ethernet1/2": "vsys2", "Ethernet1/2.20": "vsys2", "Ethernet1/4": "",
	})
}

// A display name is bounded and redacted like any other device-chosen text.
func TestVDCProjection_VsysDisplayNameIsBoundedAndRedacted(t *testing.T) {
	vn := &vendorNetwork{Producer: panCollector, Contexts: []netContext{
		{Name: "vsys1", ID: 1, HasID: true, Description: strings.Repeat("é", 300)},
	}}
	n := projectNetwork(t, vn)
	if got := []rune(n.VirtualDeviceContexts[0].Description); len(got) != maxNetDescriptionLen {
		t.Errorf("description has %d characters, want %d", len(got), maxNetDescriptionLen)
	}
}

func TestVDCProjection_F5RouteDomains(t *testing.T) {
	var domains f5Collection[f5RouteDomain]
	if err := json.Unmarshal(readVDCFixture(t, "f5_net_route_domain.json"), &domains); err != nil {
		t.Fatal(err)
	}
	vlans := []f5NetVLANExpanded{
		{Name: "external", FullPath: "/Common/external", Tag: 101},
		{Name: "internal", FullPath: "/Common/internal", Tag: 201},
		{Name: "servers", FullPath: "/Common/servers", Tag: 301},
		{Name: "unaddressed", FullPath: "/Common/unaddressed", Tag: 401},
	}
	selfIPs := []f5SelfIP{
		{Name: "self-ext", Address: "198.51.100.30/24", VLAN: "/Common/external"},
		// A self IP's %N disagreeing with the route domain's VLAN list: the
		// list is the configuration, %N the fallback.
		{Name: "self-int", Address: "10.80.1.5%0/24", VLAN: "/Common/internal"},
		// servers is in no route domain's list: its self IP's %7 says.
		{Name: "self-srv", Address: "10.80.2.5%7/24", VLAN: "/Common/servers"},
	}
	ifaces := []f5NetInterface{{Name: "1.1", MACAddress: "00:00:5e:00:53:21", Enabled: true, MediaActive: "1000T-FD"}}
	n := projectNetwork(t, f5Network(ifaces, nil, vlans, selfIPs, domains.Items, nil))
	checkContexts(t, n, []wantContext{{"0", 0}, {"tenant-a", 2}, {"spare", 7}}, map[string]string{
		"external": "0", "internal": "tenant-a", "servers": "spare", "unaddressed": "", "1.1": "",
	})
}

// With no route-domain list (the collection failed), a self IP's %N names the
// context by its id — BIG-IP's own default name.
func TestVDCProjection_F5WithoutRouteDomainList(t *testing.T) {
	vlans := []f5NetVLANExpanded{{Name: "internal", Tag: 201}}
	selfIPs := []f5SelfIP{{Name: "self-int", Address: "10.80.1.5%3/24", VLAN: "/Common/internal"}}
	n := projectNetwork(t, f5Network(nil, nil, vlans, selfIPs, nil, nil))
	checkContexts(t, n, []wantContext{{"3", 3}}, map[string]string{"internal": "3"})
}

func TestVDCProjection_CiscoNXOSMembership(t *testing.T) {
	vdcs := ciscoParseVDCMembership(string(readVDCFixture(t, "cisco_nxos_show_vdc_membership.txt")))
	if len(vdcs) != 2 || vdcs[0].id != 1 || vdcs[0].name != "core-a" || vdcs[1].id != 2 || vdcs[1].name != "agg-b" {
		t.Fatalf("vdcs %+v", vdcs)
	}
	if want := []string{"Ethernet3/1", "Ethernet3/2", "Ethernet3/3", "Ethernet3/4"}; !reflect.DeepEqual(vdcs[0].ports, want) {
		t.Errorf("core-a ports %v, want %v", vdcs[0].ports, want)
	}
	if want := []string{"Ethernet4/1", "Ethernet4/2", "Ethernet4/3"}; !reflect.DeepEqual(vdcs[1].ports, want) {
		t.Errorf("agg-b ports %v, want %v", vdcs[1].ports, want)
	}
	merged := []map[string]interface{}{
		{"name": "Ethernet3/1", "state": "up"}, {"name": "Ethernet4/2", "state": "up"},
		{"name": "Ethernet4/3", "state": "down"}, {"name": "Ethernet3/8", "state": "down"}, {"name": "mgmt0", "state": "up"},
	}
	n := projectNetwork(t, ciscoNetwork(ciscoNetworkInputs{merged: merged, osName: "NX-OS",
		vdcMembership: string(readVDCFixture(t, "cisco_nxos_show_vdc_membership.txt"))}))
	checkContexts(t, n, []wantContext{{"core-a", 1}, {"agg-b", 2}}, map[string]string{
		"Ethernet3/1": "core-a", "Ethernet4/2": "agg-b", "Ethernet4/3": "agg-b", "Ethernet3/8": "", "mgmt0": "",
	})
}

// `show vdc membership` is asked of NX-OS and of no other Cisco OS, and its
// answer reaches the observation.
func TestVDCProjection_CiscoAsksNXOSOnly(t *testing.T) {
	membership := string(readVDCFixture(t, "cisco_nxos_show_vdc_membership.txt"))
	for _, osName := range []string{"", "IOS", "IOS-XE", "IOS-XR", "ASA", "NX-OS"} {
		asked := false
		run := func(_ context.Context, command string) (string, bool, error) {
			switch command {
			case "show vdc membership":
				asked = true
				return membership, true, nil
			case "show ip interface brief":
				return "Interface              IP-Address      OK? Method Status                Protocol\n" +
					"Ethernet3/1            unassigned      YES unset  up                    up\n", true, nil
			}
			return "", false, os.ErrNotExist
		}
		r := &InterrogateResult{}
		ciscoCollectOps(context.Background(), r, run, map[string]interface{}{"os_name": osName})
		if asked != (osName == "NX-OS") {
			t.Errorf("%q: asked show vdc membership = %v", osName, asked)
		}
		if osName == "NX-OS" && (r.Network == nil || len(r.Network.VirtualDeviceContexts) != 2) {
			t.Errorf("NX-OS: contexts not in the observation: %+v", r.Network)
		}
	}
}

// The wire conversion names on an interface only a context the observation
// lists, bounds names and drops an identifier outside the column's range.
func TestVDCProjection_SetNetworkBounds(t *testing.T) {
	long := strings.Repeat("x", maxNetNameLen+10)
	vn := &vendorNetwork{
		Interfaces: []netIface{{Name: "eth0", Context: "a"}, {Name: "eth1", Context: "unlisted"}, {Name: "eth2", Context: long}},
		Contexts:   []netContext{{Name: "a", ID: 40000, HasID: true}, {Name: long, ID: 3, HasID: true}, {Name: "a", ID: 1, HasID: true}},
	}
	n := projectNetwork(t, vn)
	checkContexts(t, n, []wantContext{{"a", -1}, {long[:maxNetNameLen], 3}}, map[string]string{
		"eth0": "a", "eth1": "", "eth2": long[:maxNetNameLen],
	})
}

// addContext records a name once, and a later statement of the same name
// supplies an identifier the first lacked.
func TestVDCProjection_AddContext(t *testing.T) {
	var n vendorNetwork
	n.addContext(" r ", 0, false)
	n.addContext("r", 4, true)
	n.addContext("r", 5, true)
	n.addContext("", 1, true)
	if want := []netContext{{Name: "r", ID: 4, HasID: true}}; !reflect.DeepEqual(n.Contexts, want) {
		t.Errorf("contexts %+v, want %+v", n.Contexts, want)
	}
}

// The collector reads the vsys display names and files them as the contexts'
// description; a firewall that refuses the config read still reports its
// contexts, without descriptions, and says so in a warning.
//
// Mutation: delete the `panApplyVsysNames(network, names)` line in
// panClient.interrogate → the description assertion goes red.
func TestVDCProjection_PaloAltoCollectorFilesDisplayNames(t *testing.T) {
	serve := func(refuseConfig bool) *InterrogateResult {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			q := r.URL.Query()
			switch {
			case q.Get("type") == "keygen" || r.Method == http.MethodPost:
				_, _ = w.Write([]byte(`<response status="success"><result><key>FAKEAPIKEY==</key></result></response>`))
			case q.Get("type") == "op" && strings.Contains(q.Get("cmd"), "<interface>"):
				_, _ = w.Write(readVDCFixture(t, "paloalto_show_interface_all.xml"))
			case q.Get("type") == "config" && q.Get("xpath") == panVsysXPath:
				if refuseConfig {
					_, _ = w.Write([]byte(`<response status="error" code="16"><msg>Unauthorized</msg></response>`))
					return
				}
				_, _ = w.Write(readVDCFixture(t, "paloalto_config_vsys.xml"))
			default:
				_, _ = w.Write([]byte(panEmptyResultResponse))
			}
		}))
		defer srv.Close()
		c := newPanClient(srv.URL, "admin", "admin", true)
		res, err := c.interrogate(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	descriptions := func(res *InterrogateResult) map[string]string {
		if res.Network == nil {
			t.Fatal("no network observation")
		}
		out := map[string]string{}
		for _, c := range res.Network.VirtualDeviceContexts {
			out[c.Name] = c.Description
		}
		return out
	}
	if got, want := descriptions(serve(false)), map[string]string{"vsys1": "", "vsys2": "Tenant B Edge"}; !reflect.DeepEqual(got, want) {
		t.Errorf("descriptions = %v, want %v", got, want)
	}
	refused := serve(true)
	if got, want := descriptions(refused), map[string]string{"vsys1": "", "vsys2": ""}; !reflect.DeepEqual(got, want) {
		t.Errorf("with the config read refused, descriptions = %v, want %v", got, want)
	}
	warned := false
	for _, w := range refused.Warnings {
		if w.Endpoint == panVsysXPath {
			warned = true
		}
	}
	if !warned {
		t.Errorf("no warning for the refused display-name read: %+v", refused.Warnings)
	}
}
