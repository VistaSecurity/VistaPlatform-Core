package sensordispatch

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

var autoNow = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func fleetSensor(name string, online bool, prefixes ...string) FleetSensor {
	beat := autoNow.Add(-20 * time.Second)
	if !online {
		beat = autoNow.Add(-2 * time.Hour)
	}
	s := FleetSensor{ID: uuid.New(), Name: name, Status: "active", LastHeartbeat: &beat, ReportingInterval: 30, SelfAddresses: map[netip.Addr]bool{}, ScanPlan: true}
	for _, p := range prefixes {
		s.Prefixes = append(s.Prefixes, netip.MustParsePrefix(p))
	}
	return s
}

func literal(target string) AutoTarget {
	if p, err := netip.ParsePrefix(target); err == nil {
		lo := p.Masked().Addr()
		hi := lo
		for a := lo; p.Contains(a); a = a.Next() {
			hi = a
		}
		return AutoTarget{Target: target, Lo: lo, Hi: hi}
	}
	a := netip.MustParseAddr(target)
	return AutoTarget{Target: target, Lo: a, Hi: a}
}

func TestChooseAutoExecutor(t *testing.T) {
	edge := fleetSensor("edge-a", true, "10.50.0.0/24")
	other := fleetSensor("edge-b", true, "10.60.0.0/24")
	offline := fleetSensor("edge-c", false, "10.70.0.0/24")
	gapped := fleetSensor("edge-d", true, "10.80.0.0/24")
	gapped.AirGapped = true
	platform := fleetSensor("platform", true, "10.0.0.0/8")
	platform.System = true
	fleet := []FleetSensor{edge, other, offline, gapped, platform}

	for _, tc := range []struct {
		name     string
		targets  []AutoTarget
		observed map[netip.Addr]uuid.UUID
		fleet    []FleetSensor
		want     *FleetSensor
		reason   string
	}{
		{name: "one sensor covers every target", targets: []AutoTarget{literal("10.50.0.0/25"), literal("10.50.0.200")}, fleet: fleet, want: &edge, reason: "sensor edge-a is online"},
		{name: "targets split across two sensors", targets: []AutoTarget{literal("10.50.0.1"), literal("10.60.0.1")}, fleet: fleet, reason: "served by different sensors"},
		{name: "a target no sensor serves", targets: []AutoTarget{literal("10.50.0.1"), literal("10.99.0.1")}, fleet: fleet, reason: `"10.99.0.1"`},
		{name: "a CIDR wider than the sensor's network", targets: []AutoTarget{literal("10.50.0.0/23")}, fleet: fleet, reason: `"10.50.0.0/23"`},
		{name: "offline sensor is never chosen", targets: []AutoTarget{literal("10.70.0.5")}, fleet: fleet, reason: "edge-c serves every target but is offline"},
		{name: "air-gapped sensor is never chosen", targets: []AutoTarget{literal("10.80.0.5")}, fleet: fleet, reason: `"10.80.0.5"`},
		{name: "the platform's own sensor is never chosen", targets: []AutoTarget{literal("10.1.2.3")}, fleet: []FleetSensor{platform}, reason: "no tenant sensor can run scans"},
		{name: "an external target keeps the job on the platform", targets: []AutoTarget{literal("10.50.0.1"), {Target: "93.184.216.34", Lo: netip.MustParseAddr("93.184.216.34"), Hi: netip.MustParseAddr("93.184.216.34"), External: true}}, fleet: fleet, reason: "outside your registered networks"},
		{name: "the observing sensor serves an address outside its networks", targets: []AutoTarget{literal("10.99.0.7")}, observed: map[netip.Addr]uuid.UUID{netip.MustParseAddr("10.99.0.7"): other.ID}, fleet: fleet, want: &other, reason: "last observed by it"},
		{name: "a hostname is served when every pinned address is", targets: []AutoTarget{{Target: "app.example.com", Addresses: []netip.Addr{netip.MustParseAddr("10.50.0.8"), netip.MustParseAddr("10.50.0.9")}}}, fleet: fleet, want: &edge},
		{name: "a hostname with one uncovered address is not", targets: []AutoTarget{{Target: "app.example.com", Addresses: []netip.Addr{netip.MustParseAddr("10.50.0.8"), netip.MustParseAddr("10.99.0.9")}}}, fleet: fleet, reason: `"app.example.com"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ChooseAutoExecutor(tc.targets, tc.observed, tc.fleet, autoNow)
			switch {
			case tc.want == nil && got.Sensor != nil:
				t.Fatalf("chose %s, want the platform (%s)", got.Sensor.Name, got.Reason)
			case tc.want != nil && (got.Sensor == nil || got.Sensor.ID != tc.want.ID):
				t.Fatalf("got %+v, want sensor %s", got, tc.want.Name)
			}
			if got.Reason == "" || !strings.Contains(got.Reason, tc.reason) {
				t.Fatalf("reason %q lacks %q", got.Reason, tc.reason)
			}
		})
	}
}

// Never scan yourself: the sensor whose own host a target is does not get it.
func TestChooseAutoExecutor_NeverScansItself(t *testing.T) {
	edge := fleetSensor("edge-a", true, "10.50.0.0/24")
	edge.SelfAddresses[netip.MustParseAddr("10.50.0.2")] = true
	got := ChooseAutoExecutor([]AutoTarget{literal("10.50.0.2")}, nil, []FleetSensor{edge}, autoNow)
	if got.Sensor != nil {
		t.Fatalf("a sensor was handed its own address: %+v", got)
	}
}

// Two sensors that both serve every target resolve the same way every time.
func TestChooseAutoExecutor_Deterministic(t *testing.T) {
	a := fleetSensor("alpha", true, "10.50.0.0/24")
	b := fleetSensor("bravo", true, "10.50.0.0/16")
	for i := 0; i < 5; i++ {
		got := ChooseAutoExecutor([]AutoTarget{literal("10.50.0.9")}, nil, []FleetSensor{b, a}, autoNow)
		if got.Sensor == nil || got.Sensor.Name != "alpha" {
			t.Fatalf("got %+v, want alpha", got)
		}
	}
}

func TestCoveragePrefixes(t *testing.T) {
	if got := CoveragePrefixes([]string{"10.1.2.3/24", "bogus"}, "10.9.9.9"); len(got) != 1 || got[0].String() != "10.1.2.0/24" {
		t.Fatalf("bound = %v", got)
	}
	if got := CoveragePrefixes(nil, "10.9.9.9"); len(got) != 1 || got[0].String() != "10.9.9.0/24" {
		t.Fatalf("primary = %v", got)
	}
	if got := CoveragePrefixes(nil, "fd00::5"); len(got) != 1 || got[0].String() != "fd00::/64" {
		t.Fatalf("primary v6 = %v", got)
	}
	if got := CoveragePrefixes(nil, ""); len(got) != 0 {
		t.Fatalf("nothing = %v", got)
	}
}

// WP2b: Auto exists only for scan-plan jobs, so a sensor whose software
// cannot run a plan is never chosen — online and serving every target or not —
// and the reason says so; a capable sensor serving the same targets is.
func TestChooseAutoExecutor_NeedsTheScanPlanCapability(t *testing.T) {
	old := fleetSensor("edge-old", true, "10.50.0.0/24")
	old.ScanPlan = false
	got := ChooseAutoExecutor([]AutoTarget{literal("10.50.0.9")}, nil, []FleetSensor{old}, autoNow)
	if got.Sensor != nil {
		t.Fatalf("a sensor that cannot run a scan plan was chosen: %+v", got)
	}
	if !strings.Contains(got.Reason, "edge-old") || !strings.Contains(got.Reason, "does not support scan depth") {
		t.Fatalf("reason %q does not say the sensor's software cannot run it", got.Reason)
	}
	// Last observed by it counts no more than its networks do.
	got = ChooseAutoExecutor([]AutoTarget{literal("10.99.0.9")}, map[netip.Addr]uuid.UUID{netip.MustParseAddr("10.99.0.9"): old.ID}, []FleetSensor{old}, autoNow)
	if got.Sensor != nil {
		t.Fatalf("an observing sensor that cannot run a scan plan was chosen: %+v", got)
	}

	capable := fleetSensor("edge-new", true, "10.50.0.0/24")
	got = ChooseAutoExecutor([]AutoTarget{literal("10.50.0.9")}, nil, []FleetSensor{old, capable}, autoNow)
	if got.Sensor == nil || got.Sensor.ID != capable.ID {
		t.Fatalf("got %+v, want the capable sensor edge-new", got)
	}
}
