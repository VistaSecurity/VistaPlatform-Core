package devicetypelib

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, name string) DeviceType {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	dts, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	if len(dts) != 1 {
		t.Fatalf("%s: %d types, want 1", name, len(dts))
	}
	return dts[0]
}

// Three real library files (testdata/PROVENANCE.md) parse into the templates
// they declare, every kind accounted for.
//
// Mutation: drop any one component kind from normalise (e.g. the power-outlet
// loop, or the port-mappings join) → its count below goes to zero.
func TestParse_RealLibraryFiles(t *testing.T) {
	c := load(t, "cisco-c9300-48p.yaml")
	if c.Manufacturer != "Cisco" || c.Model != "Catalyst 9300-48P" || c.Slug != "cisco-c9300-48p" || c.PartNumber != "C9300-48P" {
		t.Fatalf("identity: %+v", c)
	}
	if c.UHeight != 1 || !c.IsFullDepth || c.Airflow != "front-to-rear" || c.Weight == nil || *c.Weight != 7.59 || c.WeightUnit != "kg" {
		t.Fatalf("physical: u=%v full=%v airflow=%q weight=%v %q", c.UHeight, c.IsFullDepth, c.Airflow, c.Weight, c.WeightUnit)
	}
	if len(c.Interfaces) != 51 || len(c.ConsolePorts) != 2 || len(c.ModuleBays) != 6 {
		t.Fatalf("templates: %d interfaces, %d console, %d module bays (want 51, 2, 6); warnings %v",
			len(c.Interfaces), len(c.ConsolePorts), len(c.ModuleBays), c.Warnings)
	}
	first := c.Interfaces[0]
	if first.Name != "GigabitEthernet1/0/1" || first.Type != "1000base-t" || first.PoEMode != "pse" || first.PoEType != "type2-ieee802.3at" || !first.Enabled {
		t.Fatalf("first interface: %+v", first)
	}
	last := c.Interfaces[50]
	if last.Name != "GigabitEthernet0/0" || !last.MgmtOnly {
		t.Fatalf("management interface: %+v", last)
	}
	if front, rear := c.ImagePaths(); front != "elevation-images/Cisco/cisco-c9300-48p.front.png" || rear == "" {
		t.Fatalf("image paths: %q %q", front, rear)
	}
	if len(c.Warnings) != 0 {
		t.Fatalf("a clean library file produced warnings: %v", c.Warnings)
	}

	p := load(t, "apc-ap7900b.yaml")
	if len(p.PowerPorts) != 1 || len(p.PowerOutlets) != 8 || len(p.ConsolePorts) != 1 || len(p.Interfaces) != 1 {
		t.Fatalf("PDU templates: %d power ports, %d outlets, %d console, %d interfaces", len(p.PowerPorts), len(p.PowerOutlets), len(p.ConsolePorts), len(p.Interfaces))
	}
	if o := p.PowerOutlets[0]; o.PowerPort != "Power Port 1" || o.FeedLeg != "A" || o.Type != "nema-5-15r" {
		t.Fatalf("outlet: %+v", o)
	}
	if p.IsFullDepth || p.Airflow != "passive" {
		t.Fatalf("PDU physical: full=%v airflow=%q", p.IsFullDepth, p.Airflow)
	}

	pp := load(t, "panduit-cpa24bly.yaml")
	if len(pp.FrontPorts) != 24 || len(pp.RearPorts) != 24 {
		t.Fatalf("patch panel: %d front, %d rear", len(pp.FrontPorts), len(pp.RearPorts))
	}
	for _, f := range pp.FrontPorts {
		if f.RearPort != f.Name || f.RearPortPosition != 1 || f.Type != "8p8c" {
			t.Fatalf("front port %+v is not mapped to its rear port", f)
		}
	}
}

// Untrusted input: unknown keys are ignored, bad values are dropped with a
// warning, required fields and limits are enforced, and nothing is fetched.
func TestParse_UntrustedInput(t *testing.T) {
	dts, err := Parse([]byte(`
manufacturer: Acme
model: Widget 1
exec: rm -rf /
u_height: 2
airflow: sideways
interfaces:
  - name: eth0
    type: 400gbase-x-quantum
  - name: eth0
    type: 1000base-t
  - name: ` + strings.Repeat("x", 65) + `
    type: 1000base-t
front-ports:
  - name: F1
    type: not-a-port
---
manufacturer: Acme
model: Widget 2
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(dts) != 2 {
		t.Fatalf("%d types, want 2", len(dts))
	}
	w := dts[0]
	if w.Slug != "widget-1" || w.UHeight != 2 || w.Airflow != "" {
		t.Fatalf("normalised: %+v", w)
	}
	if len(w.Interfaces) != 1 || w.Interfaces[0].Type != "other" || len(w.FrontPorts) != 0 {
		t.Fatalf("templates: %+v", w)
	}
	if len(w.Warnings) != 5 {
		t.Fatalf("warnings %v, want 5 (airflow, unknown type, duplicate, long name, front port)", w.Warnings)
	}
	for _, bad := range []string{"model: X\n", "manufacturer: A\nmodel: X\nu_height: 1.3\n", "manufacturer: A\nmodel: [unclosed\n"} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if _, err := Parse(make([]byte, MaxDocumentBytes+1)); err != ErrTooLarge {
		t.Fatalf("oversized input: %v", err)
	}
}
