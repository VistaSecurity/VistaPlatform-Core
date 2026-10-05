package agentconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

type portListCase struct {
	Input     string   `json:"input"`
	Ports     []int    `json:"ports"`
	Canonical string   `json:"canonical"`
	Problems  []string `json:"problems"`
}

func portListCases(t *testing.T) []portListCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/port_lists.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []portListCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("no port-list cases: a table that loads nothing passes everything")
	}
	return doc.Cases
}

// The rule itself, against the cases the console's check reads too.
func TestParsePortListCases(t *testing.T) {
	for _, tc := range portListCases(t) {
		t.Run(fmt.Sprintf("%q", tc.Input), func(t *testing.T) {
			ports, problems := ParsePortList(tc.Input)
			if !reflect.DeepEqual(ports, tc.Ports) {
				t.Errorf("ports = %v, want %v", ports, tc.Ports)
			}
			if len(problems) != len(tc.Problems) || (len(problems) > 0 && !reflect.DeepEqual(problems, tc.Problems)) {
				t.Errorf("problems = %q, want %q", problems, tc.Problems)
			}
			if len(problems) == 0 {
				if got := FormatPortList(ports); got != tc.Canonical {
					t.Errorf("canonical = %q, want %q", got, tc.Canonical)
				}
			}
		})
	}
}

// The ceiling is on distinct ports: 64 is accepted, 65 is refused, and
// repeating one port does not count against it.
func TestParsePortListCeiling(t *testing.T) {
	list := func(n int) string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = fmt.Sprint(10000 + i)
		}
		return strings.Join(parts, ",")
	}
	if _, bad := ParsePortList(list(MaxPortListEntries)); len(bad) != 0 {
		t.Errorf("%d ports refused: %v", MaxPortListEntries, bad)
	}
	_, bad := ParsePortList(list(MaxPortListEntries + 1))
	if len(bad) != 1 || bad[0] != "65 ports listed; at most 64 are allowed" {
		t.Errorf("%d ports: problems = %q", MaxPortListEntries+1, bad)
	}
	repeated := list(MaxPortListEntries) + "," + list(MaxPortListEntries)
	if _, bad := ParsePortList(repeated); len(bad) != 0 {
		t.Errorf("duplicates counted against the ceiling: %v", bad)
	}
}

func TestFormatPortListIsCanonical(t *testing.T) {
	if got := FormatPortList([]int{10443, 9443, 9443, 0, 70000}); got != "9443,10443" {
		t.Errorf("FormatPortList = %q, want 9443,10443 — sorted, deduplicated, invalid entries left out", got)
	}
	if got := FormatPortList(nil); got != "" {
		t.Errorf("FormatPortList(nil) = %q, want the empty list", got)
	}
}

// The registry entry is what every hop reads: a sensor setting, applied on
// restart (the capture filter is fixed when the handle opens), defaulting to
// no extra ports, carrying the built-in table the console names ports from.
func TestExtraTLSPortsRegistryEntry(t *testing.T) {
	f, ok := Registry[KeyExtraTLSPorts]
	if !ok {
		t.Fatal("extra_tls_ports is not registered")
	}
	if !AppliesTo(KeyExtraTLSPorts, RuntimeSensor) || AppliesTo(KeyExtraTLSPorts, RuntimeAgent) {
		t.Errorf("runtimes = %v, want sensor only", f.Runtimes)
	}
	if f.Kind != KindPortList {
		t.Errorf("kind = %s, want port_list", f.Kind)
	}
	if f.Apply != ApplyOnRestart {
		t.Errorf("apply = %s; the console would show Applied for a port the capture filter does not admit yet", f.Apply)
	}
	if f.Default.S == nil || *f.Default.S != "" {
		t.Errorf("default = %v, want the empty list", f.Default)
	}
	if f.Confirm != "" {
		t.Error("a confirmation would keep the sensor's own file value from being adopted at bootstrap")
	}
	if f.BuiltInPorts[443] != "HTTPS" || f.BuiltInPorts[22] != "SSH" {
		t.Errorf("built-in ports not carried: %v", f.BuiltInPorts)
	}
	if !strings.Contains(f.Description, "capture load") {
		t.Error("the description must say that more ports cost capture load")
	}
}

// The platform refuses junk and names it, one problem per bad entry.
func TestValidatePortList(t *testing.T) {
	for _, tc := range []struct {
		name string
		v    Value
		want []string
	}{
		{"canonical", Text("9443,10443"), nil},
		{"spaced and duplicated", Text("10443, 9443, 9443"), nil},
		{"empty list", Text(""), nil},
		{"a built-in port is accepted", Text("443"), nil},
		{"junk", Text("9443,abc,70000"), []string{
			`extra_tls_ports: "abc" is not a port number`,
			"extra_tls_ports: 70000 is outside the port range 1-65535",
		}},
		{"a range", Text("9000-9010"), []string{`extra_tls_ports: "9000-9010" is a range; list each port on its own`}},
		{"a number, not a list", Int(9443), []string{`extra_tls_ports: expected a list of port numbers, got "9443"`}},
		{"a bool", Bool(true), []string{`extra_tls_ports: expected a list of port numbers, got "true"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(RuntimeSensor, Values{KeyExtraTLSPorts: tc.v})
			if tc.want == nil {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			ve, ok := err.(*ValidationError)
			if !ok {
				t.Fatalf("err = %v, want a ValidationError", err)
			}
			if !reflect.DeepEqual(ve.Problems, tc.want) {
				t.Errorf("problems = %q, want %q", ve.Problems, tc.want)
			}
		})
	}
	if err := Validate(RuntimeAgent, Values{KeyExtraTLSPorts: Text("9443")}); err == nil {
		t.Error("an agent accepted a sensor-only setting")
	}
}

// Normalize stores one spelling per set of ports, so the revision — and with
// it "applied" — does not depend on how somebody typed the list.
func TestNormalizeCanonicalisesPortLists(t *testing.T) {
	out, notes := Normalize(RuntimeSensor, Values{KeyExtraTLSPorts: Text(" 10443, 9443,9443 ")})
	if got := out[KeyExtraTLSPorts]; got.S == nil || *got.S != "9443,10443" {
		t.Errorf("normalized = %v, want 9443,10443", got)
	}
	if len(notes) != 1 || notes[0] != "extra_tls_ports: removed 1 duplicate port(s)" {
		t.Errorf("notes = %q, want one note for the duplicate", notes)
	}
	if Revision(RuntimeSensor, out) != Revision(RuntimeSensor, Values{KeyExtraTLSPorts: Text("9443,10443")}) {
		t.Error("two spellings of one port set hash to different revisions")
	}
	if _, notes := Normalize(RuntimeSensor, Values{KeyExtraTLSPorts: Text("9443,10443")}); len(notes) != 0 {
		t.Errorf("a canonical list produced notes: %q", notes)
	}
}

// A port list must cross the wire as a string: an older sensor decodes the
// whole heartbeat answer through Value, which refuses an array (ports.go).
func TestPortListTravelsAsAString(t *testing.T) {
	b, err := json.Marshal(Values{KeyExtraTLSPorts: Text("9443,10443")})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"extra_tls_ports":"9443,10443"}` {
		t.Errorf("wire form = %s", b)
	}
	var back Values
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !back[KeyExtraTLSPorts].Equal(Text("9443,10443")) {
		t.Errorf("round trip = %v", back)
	}
}

func TestPortListChangeReadsNoneForTheEmptyList(t *testing.T) {
	ch := Change{Key: KeyExtraTLSPorts, From: Text(""), To: Text("9443")}
	if got := ch.String(); got != "extra_tls_ports: none → 9443" {
		t.Errorf("change = %q", got)
	}
}

// A sensor whose own file lists extra ports is bootstrapped to them, like any
// other non-default local setting.
func TestBootstrapAdoptsTheSensorsOwnPortList(t *testing.T) {
	got := BootstrapValues(RuntimeSensor, nil, nil, Values{KeyExtraTLSPorts: Text("9443")})
	if v := got[KeyExtraTLSPorts]; v.S == nil || *v.S != "9443" {
		t.Errorf("bootstrap = %v, want the file's 9443 adopted", got)
	}
	if got := BootstrapValues(RuntimeSensor, nil, nil, Values{KeyExtraTLSPorts: Text("")}); len(got) != 0 {
		t.Errorf("bootstrap = %v, want nothing for a sensor running the default", got)
	}
}
