package dcim

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// lowerKebab is the key shape every registry shares (NetBox keys carry dots:
// "ieee802.11ac", "2.5gbase-t", and a few outlet keys are upper-case: "CS6360C").
var lowerKebab = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.]*(-[A-Za-z0-9.]+)*$`)

type entry struct {
	Key   string `yaml:"key"`
	Label string `yaml:"label"`
	Group string `yaml:"group"`
	Speed int64  `yaml:"speed_kbps"`
	Freq  int    `yaml:"frequency_mhz"`
	Width int    `yaml:"width_mhz"`
}

func readYAML(t *testing.T, name string, out any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "standards", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, out); err != nil {
		t.Fatal(err)
	}
}

type interfaceYAML struct {
	InterfaceTypes  map[string][]entry `yaml:"interface_types"`
	ConsolePorts    []entry            `yaml:"console_port_types"`
	PortTypes       []entry            `yaml:"port_types"`
	PowerPorts      []entry            `yaml:"power_port_types"`
	PowerOutlets    []entry            `yaml:"power_outlet_types"`
	Duplex          []entry            `yaml:"duplex"`
	InterfaceModes  []entry            `yaml:"interface_modes"`
	PoEModes        []entry            `yaml:"poe_modes"`
	PoETypes        []entry            `yaml:"poe_types"`
	WirelessChannel []entry            `yaml:"wireless_channels"`
}

type cableYAML struct {
	CableTypes  []entry             `yaml:"cable_types"`
	LengthUnits []entry             `yaml:"length_units"`
	Status      []entry             `yaml:"cable_status"`
	Compatible  map[string][]string `yaml:"compatible_terminations"`
}

func keys(es []entry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Key
	}
	return out
}

// groupedKeys flattens the grouped interface types in file order. A Go map
// loses the YAML order, so read the node tree instead.
func orderedInterfaceKeys(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "standards", "interface-types.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	var out []string
	root := doc.Content[0]
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value != "interface_types" {
			continue
		}
		groups := root.Content[i+1]
		for g := 1; g < len(groups.Content); g += 2 {
			var es []entry
			if err := groups.Content[g].Decode(&es); err != nil {
				t.Fatal(err)
			}
			out = append(out, keys(es)...)
		}
	}
	return out
}

func asStrings[T ~string](in []T) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}

func checkShape(t *testing.T, name string, ks []string) {
	t.Helper()
	if len(ks) == 0 {
		t.Fatalf("%s: empty", name)
	}
	seen := map[string]bool{}
	for _, k := range ks {
		if !lowerKebab.MatchString(k) {
			t.Errorf("%s: key %q is not lower-kebab", name, k)
		}
		if seen[k] {
			t.Errorf("%s: duplicate key %q", name, k)
		}
		seen[k] = true
	}
}

func TestRegistriesMatchYAMLAndAreWellFormed(t *testing.T) {
	var ifc interfaceYAML
	var cab cableYAML
	readYAML(t, "interface-types.yaml", &ifc)
	readYAML(t, "cable-types.yaml", &cab)

	cases := []struct {
		name string
		got  []string
		want []string
	}{
		{"interface types", asStrings(AllInterfaceTypes()), orderedInterfaceKeys(t)},
		{"console port types", asStrings(AllConsolePortTypes()), keys(ifc.ConsolePorts)},
		{"port types", asStrings(AllPortTypes()), keys(ifc.PortTypes)},
		{"power port types", asStrings(AllPowerPortTypes()), keys(ifc.PowerPorts)},
		{"power outlet types", asStrings(AllPowerOutletTypes()), keys(ifc.PowerOutlets)},
		{"duplex", asStrings(AllInterfaceDuplexes()), keys(ifc.Duplex)},
		{"interface modes", asStrings(AllInterfaceModes()), keys(ifc.InterfaceModes)},
		{"poe modes", asStrings(AllPoEModes()), keys(ifc.PoEModes)},
		{"poe types", asStrings(AllPoETypes()), keys(ifc.PoETypes)},
		{"cable types", asStrings(AllCableTypes()), keys(cab.CableTypes)},
		{"length units", asStrings(AllCableLengthUnits()), keys(cab.LengthUnits)},
		{"cable status", asStrings(AllCableStatuses()), keys(cab.Status)},
	}
	for _, c := range cases {
		checkShape(t, c.name, c.got)
		if !reflect.DeepEqual(c.got, c.want) {
			t.Errorf("%s: Go registry differs from the YAML\n got %v\nwant %v", c.name, c.got, c.want)
		}
	}

	var chans []string
	for _, c := range AllWirelessChannels() {
		chans = append(chans, c.Key)
	}
	checkShape(t, "wireless channels", chans)
	if !reflect.DeepEqual(chans, keys(ifc.WirelessChannel)) {
		t.Error("wireless channels: Go registry differs from the YAML")
	}
}

func TestLabelsGroupsAndSpeedsMatchYAML(t *testing.T) {
	var ifc interfaceYAML
	var cab cableYAML
	readYAML(t, "interface-types.yaml", &ifc)
	readYAML(t, "cable-types.yaml", &cab)

	n := 0
	for g, es := range ifc.InterfaceTypes {
		for _, e := range es {
			n++
			ty, ok := ParseInterfaceType(e.Key)
			if !ok {
				t.Fatalf("ParseInterfaceType(%q) failed", e.Key)
			}
			if InterfaceTypeLabel(ty) != e.Label {
				t.Errorf("%s label %q != %q", e.Key, InterfaceTypeLabel(ty), e.Label)
			}
			if InterfaceTypeGroup(ty) != g {
				t.Errorf("%s group %q != %q", e.Key, InterfaceTypeGroup(ty), g)
			}
			sp, has := InterfaceTypeSpeedKbps(ty)
			if has != (e.Speed != 0) || sp != e.Speed {
				t.Errorf("%s speed (%d,%v) != %d", e.Key, sp, has, e.Speed)
			}
		}
	}
	if n != len(AllInterfaceTypes()) {
		t.Errorf("%d YAML interface types, %d in Go", n, len(AllInterfaceTypes()))
	}
	for _, e := range cab.CableTypes {
		ty, ok := ParseCableType(e.Key)
		if !ok || CableTypeLabel(ty) != e.Label || CableTypeGroup(ty) != e.Group {
			t.Errorf("cable type %s does not round-trip", e.Key)
		}
	}
	if _, ok := ParseInterfaceType("not-a-type"); ok {
		t.Error("ParseInterfaceType accepted an unknown key")
	}
	if InterfaceTypeLabel("not-a-type") != "" {
		t.Error("unknown type has a label")
	}
	for _, e := range ifc.WirelessChannel {
		c, ok := ParseWirelessChannel(e.Key)
		if !ok || c.FrequencyMHz != e.Freq || c.WidthMHz != e.Width || c.Label != e.Label {
			t.Errorf("wireless channel %s does not round-trip", e.Key)
		}
	}
}

// spot checks against NetBox 4.x so a bad transcription of a well-known key shows up.
func TestKnownNetBoxKeys(t *testing.T) {
	want := map[InterfaceType]string{
		InterfaceType1000baseT:       "1000BASE-T (1GE)",
		InterfaceType10gbaseXSfpp:    "SFP+ (10GE)",
		InterfaceType25gbaseXSfp28:   "SFP28 (25GE)",
		InterfaceType100gbaseXQsfp28: "QSFP28 (100GE)",
		InterfaceTypeLag:             "Link Aggregation Group (LAG)",
		InterfaceTypeVirtual:         "Virtual",
	}
	for ty, label := range want {
		if InterfaceTypeLabel(ty) != label {
			t.Errorf("%s label = %q, want %q", ty, InterfaceTypeLabel(ty), label)
		}
	}
	if g := InterfaceTypeGroup(InterfaceType10gbaseXSfpp); g != "ethernet_modular" {
		t.Errorf("SFP+ group = %q", g)
	}
	if sp, ok := InterfaceTypeSpeedKbps(InterfaceType10gbaseXSfpp); !ok || sp != 10_000_000 {
		t.Errorf("SFP+ speed = %d,%v", sp, ok)
	}
	if CableTypeGroup(CableTypeCat6a) != "copper" || CableTypeGroup(CableTypeSmfOs2) != "fibre" || CableTypeGroup(CableTypePower) != "power" || CableTypeGroup(CableTypeCoaxial) != "copper" {
		t.Error("cable type groups wrong")
	}
}

// netboxMatrix is NetBox's COMPATIBLE_TERMINATION_TYPES, restated independently of the
// YAML so the generator and the file cannot drift together unnoticed.
var netboxMatrix = map[ObjectKind][]ObjectKind{
	ObjectKindInterface:          {ObjectKindInterface, ObjectKindFrontPort, ObjectKindRearPort, ObjectKindCircuitTermination},
	ObjectKindConsolePort:        {ObjectKindConsoleServerPort, ObjectKindFrontPort, ObjectKindRearPort},
	ObjectKindConsoleServerPort:  {ObjectKindConsolePort, ObjectKindFrontPort, ObjectKindRearPort},
	ObjectKindFrontPort:          {ObjectKindInterface, ObjectKindConsolePort, ObjectKindConsoleServerPort, ObjectKindFrontPort, ObjectKindRearPort, ObjectKindCircuitTermination},
	ObjectKindRearPort:           {ObjectKindInterface, ObjectKindConsolePort, ObjectKindConsoleServerPort, ObjectKindFrontPort, ObjectKindRearPort, ObjectKindCircuitTermination},
	ObjectKindPowerPort:          {ObjectKindPowerOutlet, ObjectKindPowerFeed},
	ObjectKindPowerOutlet:        {ObjectKindPowerPort},
	ObjectKindPowerFeed:          {ObjectKindPowerPort},
	ObjectKindCircuitTermination: {ObjectKindInterface, ObjectKindFrontPort, ObjectKindRearPort, ObjectKindCircuitTermination},
}

func TestCableCompatibleIsExactlyNetBoxsMatrix(t *testing.T) {
	for _, a := range AllObjectKinds {
		allowed := map[ObjectKind]bool{}
		for _, b := range netboxMatrix[a] {
			allowed[b] = true
		}
		for _, b := range AllObjectKinds {
			if got := CableCompatible(a, b); got != allowed[b] {
				t.Errorf("CableCompatible(%s, %s) = %v, want %v", a, b, got, allowed[b])
			}
		}
	}
}

// NetBox's matrix is symmetric (a power feed lists only power ports, and power ports
// list the feed back). The test asserts symmetry for every pair, and the one-sided
// shape the brief names: a feed cables to a power port and nothing else.
func TestCableCompatibleIsSymmetric(t *testing.T) {
	for _, a := range AllObjectKinds {
		for _, b := range AllObjectKinds {
			if CableCompatible(a, b) != CableCompatible(b, a) {
				t.Errorf("CableCompatible(%s,%s) != CableCompatible(%s,%s)", a, b, b, a)
			}
		}
	}
	if got := CableCompatibleKinds(ObjectKindPowerFeed); !reflect.DeepEqual(got, []ObjectKind{ObjectKindPowerPort}) {
		t.Errorf("power_feed cables to %v, want only power_port", got)
	}
	if CableCompatible(ObjectKindPowerFeed, ObjectKindPowerOutlet) || CableCompatible(ObjectKindPowerOutlet, ObjectKindPowerFeed) {
		t.Error("a power feed must not cable to an outlet")
	}
	if CableCompatible(ObjectKindAsset, ObjectKindAsset) || CableCompatible("nope", ObjectKindInterface) {
		t.Error("non-termination kinds must not be cable-compatible")
	}
}

func TestCableCompatibleMatchesYAML(t *testing.T) {
	var cab cableYAML
	readYAML(t, "cable-types.yaml", &cab)
	kinds := make([]string, 0, len(cab.Compatible))
	for k := range cab.Compatible {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, a := range kinds {
		got := asStrings(CableCompatibleKinds(ObjectKind(a)))
		want := append([]string(nil), cab.Compatible[a]...)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: Go %v, YAML %v", a, got, want)
		}
	}
}

// netboxSnapshot is standards/netbox-choices.v4.3.5.json: the key and label maps
// extracted mechanically from NetBox v4.3.5's choices.py, constants.py and
// wireless/choices.py. It is the ground truth the registries are held to.
type netboxSnapshot struct {
	Version string `json:"netbox_version"`
	Choices map[string][]struct {
		Name    *string    `json:"name"`
		Choices [][]string `json:"choices"`
	} `json:"choices"`
	Compatible map[string][]string `json:"compatible_termination_types"`
}

func (n netboxSnapshot) labels(class string) map[string]string {
	out := map[string]string{}
	for _, g := range n.Choices[class] {
		for _, c := range g.Choices {
			out[c[0]] = c[1]
		}
	}
	return out
}

func TestRegistriesAreExactlyNetBoxs(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "standards", "netbox-choices.v4.3.5.json"))
	if err != nil {
		t.Fatal(err)
	}
	var nb netboxSnapshot
	if err := json.Unmarshal(b, &nb); err != nil {
		t.Fatal(err)
	}
	if nb.Version != "4.3.5" {
		t.Fatalf("snapshot is NetBox %s", nb.Version)
	}

	ours := map[string]map[string]string{}
	add := func(class string, keys []string, label func(string) string) {
		m := map[string]string{}
		for _, k := range keys {
			m[k] = label(k)
		}
		ours[class] = m
	}
	add("InterfaceType", asStrings(AllInterfaceTypes()), func(k string) string { return InterfaceTypeLabel(InterfaceType(k)) })
	add("ConsolePortType", asStrings(AllConsolePortTypes()), func(k string) string { return ConsolePortTypeLabel(ConsolePortType(k)) })
	add("PortType", asStrings(AllPortTypes()), func(k string) string { return PortTypeLabel(PortType(k)) })
	add("PowerPortType", asStrings(AllPowerPortTypes()), func(k string) string { return PowerPortTypeLabel(PowerPortType(k)) })
	add("PowerOutletType", asStrings(AllPowerOutletTypes()), func(k string) string { return PowerOutletTypeLabel(PowerOutletType(k)) })
	add("InterfaceDuplex", asStrings(AllInterfaceDuplexes()), func(k string) string { return InterfaceDuplexLabel(InterfaceDuplex(k)) })
	add("InterfaceMode", asStrings(AllInterfaceModes()), func(k string) string { return InterfaceModeLabel(InterfaceMode(k)) })
	add("InterfacePoEMode", asStrings(AllPoEModes()), func(k string) string { return PoEModeLabel(PoEMode(k)) })
	add("InterfacePoEType", asStrings(AllPoETypes()), func(k string) string { return PoETypeLabel(PoEType(k)) })
	add("CableType", asStrings(AllCableTypes()), func(k string) string { return CableTypeLabel(CableType(k)) })
	add("CableLengthUnit", asStrings(AllCableLengthUnits()), func(k string) string { return CableLengthUnitLabel(CableLengthUnit(k)) })
	add("LinkStatus", asStrings(AllCableStatuses()), func(k string) string { return CableStatusLabel(CableStatus(k)) })
	wc := map[string]string{}
	for _, c := range AllWirelessChannels() {
		wc[c.Key] = c.Label
	}
	ours["WirelessChannel"] = wc

	for class, mine := range ours {
		theirs := nb.labels(class)
		if len(theirs) == 0 {
			t.Fatalf("%s: not in the NetBox snapshot", class)
		}
		for k, l := range theirs {
			got, ok := mine[k]
			if !ok {
				t.Errorf("%s: NetBox key %q is missing from our registry", class, k)
			} else if got != l {
				t.Errorf("%s: %q label %q, NetBox has %q", class, k, got, l)
			}
		}
		for k := range mine {
			if _, ok := theirs[k]; !ok {
				t.Errorf("%s: key %q is not a NetBox %s", class, k, nb.Version)
			}
		}
		if len(mine) != len(theirs) {
			t.Errorf("%s: %d keys, NetBox has %d", class, len(mine), len(theirs))
		}
	}

	// The termination matrix, NetBox model names mapped to our kind keys.
	for a, list := range nb.Compatible {
		want := append([]string(nil), list...)
		sort.Strings(want)
		var got []string
		for _, k := range AllObjectKinds {
			if strings.ReplaceAll(string(k), "_", "") == a {
				for _, c := range CableCompatibleKinds(k) {
					got = append(got, strings.ReplaceAll(string(c), "_", ""))
				}
			}
		}
		sort.Strings(got)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("matrix %s: ours %v, NetBox %v", a, got, want)
		}
	}
	if len(nb.Compatible) != len(compatibleTerminations) {
		t.Errorf("matrix has %d kinds, NetBox %d", len(compatibleTerminations), len(nb.Compatible))
	}
}
