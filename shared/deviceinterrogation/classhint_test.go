package deviceinterrogation

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
)

// PARITY. Every class and vendor hint this package produced BEFORE workstream
// 2.10a moved the rules into standards/classification-rules.yaml must still
// come out of the engine, unchanged.
//
// The table below is a verbatim transcription of the maps and constants that
// used to live in classhint.go, cisco_ops.go, unifi_ops.go and paloalto_ops.go.
// It is deliberately a SECOND copy of the data — a parity test that read the
// rules would be asserting that the rules equal themselves — and it is allowed
// to be the one hand-maintained copy in the codebase because its whole job is
// to notice when the generated one moves.
//
// Mutation-checked: delete any one rule from the YAML, run `make generate`, and
// the failure names the exact hint that disappeared.
//
// Adding a NEW rule does not fail this test, which is correct: the table is a
// floor, not a ceiling. Curation is the point of the move.
func TestClassHintParity_EveryPre210aHintSurvivedTheMoveToRules(t *testing.T) {
	t.Run("collector platforms", func(t *testing.T) {
		cases := map[string]struct {
			got  func() string
			want string
		}{
			"palo alto (panClassHint)":         {panClassHint, "firewall"},
			"fortinet (fortinetClassHint)":     {fortinetClassHint, "firewall"},
			"f5 (f5ClassHint)":                 {f5ClassHint, "load_balancer"},
			"unifi (unifiControllerClassHint)": {unifiControllerClassHint, "wireless_controller"},
		}
		for name, tc := range cases {
			if got := tc.got(); got != tc.want {
				t.Errorf("%s = %q, want %q — the rule behind it is gone or changed", name, got, tc.want)
			}
		}
	})

	// The UniFi controller's device `type` vocabulary, exactly as
	// unifiTypeClassHints held it.
	t.Run("unifi device types", func(t *testing.T) {
		cases := map[string]string{
			"uap": "access_point",
			"usw": "switch",
			"ugw": "router",
			"udm": "router",
			"uxg": "router",
			"uck": "wireless_controller",
		}
		for deviceType, want := range cases {
			if got := unifiClassHint(deviceType); got != want {
				t.Errorf("unifiClassHint(%q) = %q, want %q", deviceType, got, want)
			}
		}
	})

	// The Cisco product-id prefixes, exactly as ciscoPIDClassHints held them.
	// Order matters here as much as content: AIR-CT must still beat AIR-.
	t.Run("cisco product-id prefixes", func(t *testing.T) {
		cases := map[string]string{
			"WS-C":    "switch",
			"C9200":   "switch",
			"C9300":   "switch",
			"C9400":   "switch",
			"C9500":   "switch",
			"C9600":   "switch",
			"IE-":     "switch",
			"N9K-":    "switch",
			"N7K-":    "switch",
			"N5K-":    "switch",
			"N3K-":    "switch",
			"N2K-":    "switch",
			"ISR":     "router",
			"ASR":     "router",
			"CISCO29": "router",
			"CISCO39": "router",
			"C8200":   "router",
			"C8300":   "router",
			"C8500":   "router",
			"C1111":   "router",
			"C1121":   "router",
			"ASA":     "firewall",
			"FPR":     "firewall",
			"C9800":   "wireless_controller",
			"AIR-CT":  "wireless_controller",
			"AIR-":    "access_point",
		}
		for pid, want := range cases {
			if got := ciscoClassHintForPID(pid); got != want {
				t.Errorf("ciscoClassHintForPID(%q) = %q, want %q", pid, got, want)
			}
		}
	})

	// The configured device_type fallback, exactly as ciscoDeviceTypeClassHints
	// held it.
	t.Run("cisco device types", func(t *testing.T) {
		cases := map[string]string{
			"cisco_router": "router",
			"cisco_switch": "switch",
			"cisco_asa":    "firewall",
		}
		for deviceType, want := range cases {
			if got := ciscoDeviceTypeClassHint(deviceType); got != want {
				t.Errorf("ciscoDeviceTypeClassHint(%q) = %q, want %q", deviceType, got, want)
			}
		}
	})

	// The SNMP private-enterprise numbers, as snmpEnterpriseHints held them —
	// INCLUDING the empty classes, which are the deliberate half.
	//
	// Two kinds of change since the map, both reviewed and both intentional; the
	// point of this test is that nothing changes SILENTLY, not that nothing
	// changes.
	//
	// VENDOR SPELLINGS now follow standards/oui-vendors.csv, because the rules
	// and the OUI table have to name a manufacturer identically or the engine's
	// vendor arbitration cancels them against each other: `Dell` from the OUI
	// rule against `Dell Inc.` from here meant a Dell server seen by both MAC
	// and SNMP came back with NO vendor and no class at all.
	//
	// FORTINET (12356) and HUAWEI (2011) lost their classes. Both enterprise
	// arcs cover the whole company — FortiSwitch, FortiAP and FortiAnalyzer
	// answer under 12356; Huawei's servers and storage arrays answer under 2011
	// — so the class was asserted for devices it was wrong about. The FortiGate
	// conclusion lives in the `platform` rule, where the evidence for it is.
	t.Run("snmp enterprise numbers", func(t *testing.T) {
		cases := map[int]snmpVendorHint{
			9:     {Vendor: "Cisco Systems", Class: "network_device"},
			11:    {Vendor: "Hewlett Packard"},
			43:    {Vendor: "3Com"},
			171:   {Vendor: "D-Link", Class: "network_device"},
			207:   {Vendor: "Allied Telesis", Class: "network_device"},
			318:   {Vendor: "American Power Conversion"},
			674:   {Vendor: "Dell"},
			789:   {Vendor: "NetApp", Class: "storage_device"},
			890:   {Vendor: "Zyxel", Class: "network_device"},
			1916:  {Vendor: "Extreme Networks", Class: "network_device"},
			1991:  {Vendor: "Brocade", Class: "network_device"},
			2011:  {Vendor: "Huawei Technologies"},
			2636:  {Vendor: "Juniper Networks", Class: "network_device"},
			3375:  {Vendor: "F5 Networks", Class: "load_balancer"},
			4526:  {Vendor: "NETGEAR", Class: "network_device"},
			5951:  {Vendor: "Citrix", Class: "load_balancer"},
			6876:  {Vendor: "VMware"},
			12356: {Vendor: "Fortinet"},
			14988: {Vendor: "MikroTik", Class: "network_device"},
			20916: {Vendor: "Hikvision", Class: "iot_device"},
			25461: {Vendor: "Palo Alto Networks", Class: "firewall"},
			25506: {Vendor: "H3C", Class: "network_device"},
			30065: {Vendor: "Arista Networks", Class: "network_device"},
			41112: {Vendor: "Ubiquiti Networks", Class: "network_device"},
		}
		for enterprise, want := range cases {
			oid := "1.3.6.1.4.1." + itoa(enterprise) + ".1.1"
			if got := snmpObjectIDHint(oid); got != want {
				t.Errorf("snmpObjectIDHint(%q) = %+v, want %+v", oid, got, want)
			}
		}
	})
}

// PARITY, for the one hint 2.10a did NOT move: the CDP capability fallback in
// ciscoPeerClassHint, which stayed a Go switch statement until 2.10b turned it
// into three `cdp_capabilities` rules.
//
// The table transcribes that switch — `contains "switch"` → switch, else
// `contains "router"` → router, else nothing — applied to the capability
// strings IOS actually prints, with ONE deliberate exception recorded below. A
// refactor that quietly re-decided what a neighbour is would be the
// wrong-fact-that-looks-right the rule table exists to avoid, so the answers are
// pinned rather than re-derived.
//
// Mutation-checked: delete the `router,switch` rule from the YAML, run
// `make generate`, and the both-bits case fails by name.
func TestCiscoPeerClassHint_MatchesThePreRulesBehaviour(t *testing.T) {
	cases := []struct {
		name         string
		platform     string
		capabilities string
		want         string
	}{
		// A recognised product id still wins outright — it is a 0.85 model rule
		// against a 0.65 capability rule, well over the conflict epsilon.
		{"pid beats capabilities", "cisco WS-C3750X-48P", "Switch IGMP", "switch"},
		{"pid alone", "cisco C9300-48P", "", "switch"},
		{"wireless controller pid", "cisco AIR-CT5520-K9", "", "wireless_controller"},

		// The fallback, which is what moved.
		{"switch only", "cisco unknown-box", "Switch IGMP", "switch"},
		{"router only", "cisco unknown-box", "Router", "router"},
		// The ONE answer the move deliberately changed. The Go switch returned
		// `switch` here, which is right for a Catalyst doing inter-VLAN routing
		// and wrong for an ISR with a switch module — both advertise exactly
		// these two bits. `network_device` is their common ancestor and is
		// certainly right for both, which is the rule of thumb the table is
		// governed by, and it is what the `lldp_capability` rule for the same
		// device seen over the other protocol already answered.
		{"both bits are a network device, not a guess at which", "cisco unknown-box", "Router Switch IGMP", "network_device"},
		// …and a recognised PID still refines it back to the leaf: an 0.85
		// `model` rule against a 0.70 capability rule whose class is its
		// ancestor.
		{"a known PID refines the both-bits answer", "cisco WS-C3750X-48P", "Router Switch IGMP", "switch"},
		{"host is not a class", "cisco unknown-box", "Host", ""},
		{"phone has no class in the taxonomy", "cisco unknown-box", "Host Phone", ""},
		{"nothing at all", "", "", ""},
		{"unrecognised word contributes nothing", "cisco unknown-box", "Gizmo", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ciscoPeerClassHint(tc.platform, tc.capabilities); got != tc.want {
				t.Errorf("ciscoPeerClassHint(%q, %q) = %q, want %q",
					tc.platform, tc.capabilities, got, tc.want)
			}
		})
	}
}

// The two producers of a CDP capability list — a live capture reading the
// bitmask, and an SSH session reading IOS's rendering of it — have to end up in
// ONE vocabulary, or the same device classifies differently depending on how we
// happened to see it.
func TestCiscoCDPCapabilityNames_SpeaksTheDecodersVocabulary(t *testing.T) {
	got := ciscoCDPCapabilityNames("Router Switch IGMP Trans-Bridge Host Phone Gizmo")
	want := []string{"router", "switch", "igmp_capable", "transparent_bridge", "host", "voip_phone"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	// An unmapped word is DROPPED, not lower-cased and passed on. A capability
	// name nothing can ever match reads as evidence and is not.
	if names := ciscoCDPCapabilityNames("Gizmo Widget"); len(names) != 0 {
		t.Errorf("unmapped words produced %v, want none", names)
	}
}

// Every class this package can propose is a key in the generated class
// registry. A hint nothing recognises is worse than no hint: it reaches
// Approvals as a proposal for a class that does not exist, and the reviewer
// cannot act on it.
//
// The engine's own tests check this across ALL rules; this one checks it across
// the hints these collectors actually emit, which is the narrower claim the
// interrogators depend on.
func TestClassHints_AreRegisteredAssetClasses(t *testing.T) {
	hints := map[string]string{
		"palo alto":        panClassHint(),
		"unifi controller": unifiControllerClassHint(),
		"fortinet":         fortinetClassHint(),
		"f5":               f5ClassHint(),
	}
	for _, deviceType := range []string{"uap", "usw", "ugw", "udm", "uxg", "uck"} {
		hints["unifi type "+deviceType] = unifiClassHint(deviceType)
	}
	for _, pid := range []string{"WS-C3750X", "C9300-48P", "ISR4331/K9", "ASA5525", "C9800-40", "AIR-CT5520", "AIR-AP3802I"} {
		hints["cisco pid "+pid] = ciscoClassHintForPID(pid)
	}
	for _, deviceType := range []string{"cisco_router", "cisco_switch", "cisco_asa"} {
		hints["cisco device type "+deviceType] = ciscoDeviceTypeClassHint(deviceType)
	}
	for _, enterprise := range []int{9, 789, 3375, 25461, 41112} {
		hints["snmp enterprise "+itoa(enterprise)] = snmpObjectIDHint("1.3.6.1.4.1." + itoa(enterprise) + ".1").Class
	}

	if len(hints) < 10 {
		t.Fatalf("only %d class hints were collected; the test has stopped walking the mappings", len(hints))
	}
	for source, class := range hints {
		if class == "" {
			t.Errorf("%s produced no class at all — its rule is missing", source)
			continue
		}
		if _, ok := assetclass.Get(class); !ok {
			t.Errorf("%s proposes class %q, which is not in standards/asset-classes.yaml", source, class)
		}
	}
}

// A vendor with no unambiguous class must produce no class, not a guess. Dell
// and HP sell servers, switches and printers under one enterprise number, and
// this is the assertion that stops a well-meaning "fill in the gaps" pass over
// the YAML from turning four honest blanks into four fabricated facts.
func TestSNMPEnterpriseHints_LeaveAmbiguousVendorsUnclassified(t *testing.T) {
	for _, enterprise := range []int{
		11 /* HP */, 674 /* Dell */, 6876 /* VMware */, 318, /* APC */
		// Fortinet and Huawei joined them in review. Enterprise 12356 covers
		// FortiSwitch, FortiAP and FortiAnalyzer as well as FortiGate, and 2011
		// covers Huawei's servers and storage arrays as well as its switches —
		// so the class each used to assert was wrong for a large share of the
		// devices that answer under it.
		12356 /* Fortinet */, 2011, /* Huawei */
	} {
		hint := snmpObjectIDHint("1.3.6.1.4.1." + itoa(enterprise) + ".1.1")
		if hint.Vendor == "" {
			t.Errorf("enterprise %d is no longer in the rule table; the test is stale", enterprise)
		}
		if hint.Class != "" {
			t.Errorf("enterprise %d (%s) was given class %q, but its products span several classes", enterprise, hint.Vendor, hint.Class)
		}
	}
}

func TestUnifiClassHint(t *testing.T) {
	cases := map[string]string{
		"uap":     "access_point",
		"USW":     "switch",
		" ugw ":   "router",
		"udm":     "router",
		"uck":     "wireless_controller",
		"uph":     "", // UniFi phone: no rule, so no hint
		"":        "",
		"unknown": "",
	}
	for deviceType, want := range cases {
		if got := unifiClassHint(deviceType); got != want {
			t.Errorf("unifiClassHint(%q) = %q, want %q", deviceType, got, want)
		}
	}
}

// A sysObjectID outside the private-enterprise arc, or from an enterprise no
// rule covers, yields nothing rather than a guess.
func TestSNMPObjectIDHint_UnknownAndOutOfArcYieldNothing(t *testing.T) {
	for _, oid := range []string{
		"",
		"1.3.6.1.2.1.1.1",         // standard MIB-II, not a manufacturer arc
		"1.3.6.1.4.1.99999.1",     // an enterprise no rule covers
		"1.3.6.1.4.1.8072.3.2.10", // Net-SNMP: the AGENT, deliberately unlisted
		"1.3.6.1.4.1.2021.250.10", // UCD-SNMP, same reason
	} {
		if got := snmpObjectIDHint(oid); got != (snmpVendorHint{}) {
			t.Errorf("snmpObjectIDHint(%q) = %+v, want an empty hint", oid, got)
		}
	}
}
