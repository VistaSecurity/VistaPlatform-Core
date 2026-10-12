package jobs

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/autoscan"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/identityenrichment"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/sensorrouting"
	sharedautoscan "github.com/vistasecurity/vistaplatform/shared/autoscan"
)

func seg(cidr, kind string) autoscan.Segment { return autoscan.Segment{Value: cidr, NetworkType: kind} }

func collectorOn(name string, ifaces ...string) identityenrichment.Collector {
	var ps []netip.Prefix
	for _, i := range ifaces {
		ps = append(ps, netip.MustParsePrefix(i))
	}
	return identityenrichment.NewCollector(uuid.New(), name, ps...)
}

func TestDecidePlatformTargets(t *testing.T) {
	siteSensor := collectorOn("site", "192.0.2.10/24")
	otherSensor := collectorOn("other", "203.0.113.5/24")

	cases := []struct {
		name         string
		reach        autoScanReachability
		strict       bool
		target       string
		wantPlatform bool
		wantSensor   string
		wantSkipped  bool
	}{
		{"eligible sensor in the segment runs it", autoScanReachability{
			Segments: []autoscan.Segment{seg("192.0.2.0/24", "private")}, Collectors: []identityenrichment.Collector{siteSensor, otherSensor}, HasLiveSensors: true},
			true, "192.0.2.50", false, "site", false},
		{"cloud segment, no sensor: skipped", autoScanReachability{
			Segments: []autoscan.Segment{seg("198.51.100.0/24", "cloud")}, Collectors: []identityenrichment.Collector{siteSensor}, HasLiveSensors: true},
			true, "198.51.100.7", false, "", true},
		{"cloud segment, tenant has no sensors at all: still skipped", autoScanReachability{
			Segments: []autoscan.Segment{seg("198.51.100.0/24", "cloud")}},
			true, "198.51.100.7", false, "", true},
		{"cloud segment is skipped even with the prefer-sensor switch off", autoScanReachability{
			Segments: []autoscan.Segment{seg("198.51.100.0/24", "cloud")}, HasLiveSensors: true},
			false, "198.51.100.7", false, "", true},
		{"private segment, other live sensors none reaching: skipped", autoScanReachability{
			Segments: []autoscan.Segment{seg("198.51.100.0/24", "private")}, Collectors: []identityenrichment.Collector{siteSensor}, HasLiveSensors: true},
			true, "198.51.100.7", false, "", true},
		{"private segment, tenant has no sensors at all: platform", autoScanReachability{
			Segments: []autoscan.Segment{seg("198.51.100.0/24", "private")}},
			true, "198.51.100.7", true, "", false},
		{"vpn segment, other live sensors none reaching: skipped", autoScanReachability{
			Segments: []autoscan.Segment{seg("198.51.100.0/24", "vpn")}, HasLiveSensors: true},
			true, "198.51.100.7", false, "", true},
		{"vpn segment, no sensors at all: platform", autoScanReachability{
			Segments: []autoscan.Segment{seg("198.51.100.0/24", "vpn")}},
			true, "198.51.100.7", true, "", false},
		{"no registered segment, tenant has sensors: skipped", autoScanReachability{HasLiveSensors: true},
			true, "198.51.100.7", false, "", true},
		{"no registered segment, no sensors: platform", autoScanReachability{},
			true, "198.51.100.7", true, "", false},
		{"switch off: private host stays on the platform despite sensors", autoScanReachability{
			Segments: []autoscan.Segment{seg("198.51.100.0/24", "private")}, HasLiveSensors: true},
			false, "198.51.100.7", true, "", false},
		{"the sensor's own address is never handed to itself", autoScanReachability{
			Segments: []autoscan.Segment{seg("192.0.2.0/24", "private")}, Collectors: []identityenrichment.Collector{siteSensor}, HasLiveSensors: true},
			true, "192.0.2.10", false, "", true},
		{"most specific segment wins (cloud /28 inside a private /24)", autoScanReachability{
			Segments: []autoscan.Segment{seg("198.51.100.0/24", "private"), seg("198.51.100.0/28", "cloud")}},
			true, "198.51.100.7", false, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := decidePlatformTargets([]string{c.target}, c.reach, c.strict)
			gotPlatform := len(d.Platform) == 1
			gotSkipped := len(d.Unreachable) == 1
			gotSensor := ""
			if len(d.ViaCollector) == 1 {
				gotSensor = d.ViaCollector[0].Collector.Name
			}
			if gotPlatform != c.wantPlatform || gotSkipped != c.wantSkipped || gotSensor != c.wantSensor {
				t.Fatalf("decision = %+v, want platform=%v sensor=%q skipped=%v", d, c.wantPlatform, c.wantSensor, c.wantSkipped)
			}
		})
	}
}

type fakeReach struct {
	r   autoScanReachability
	err error
}

func (f fakeReach) Reachability(context.Context, uuid.UUID, time.Time) (autoScanReachability, error) {
	return f.r, f.err
}

// Through the sweep: the cloud address is neither dispatched nor stamped, and
// the tenant sees why in the sweep's refusals; the reachable host still runs.
func TestSweepTenant_DoesNotProbeUnreachableTargetsFromThePlatform(t *testing.T) {
	targets := targetsAt("198.51.100.7", "192.0.2.50")
	store := &fakeStore{policy: sharedautoscan.DefaultPolicy(), targets: targets}
	d := &fakeDispatcher{}
	site := collectorOn("site", "192.0.2.10/24")
	j := routedJob(store, d, &fakeRouter{plan: sensorrouting.Plan{Platform: []string{"198.51.100.7", "192.0.2.50"}}})
	j.SetReach(fakeReach{r: autoScanReachability{
		Segments:       []autoscan.Segment{seg("198.51.100.0/24", "cloud"), seg("192.0.2.0/24", "private")},
		Collectors:     []identityenrichment.Collector{site},
		HasLiveSensors: true,
	}})
	j.SweepTenant(context.Background(), uuid.New(), false)

	if len(d.jobs) != 1 || d.jobs[0].ExecutionMode != "sensors" || len(d.jobs[0].Targets) != 1 || d.jobs[0].Targets[0] != "192.0.2.50" {
		t.Fatalf("dispatched %+v, want one sensor job over 192.0.2.50 only", d.jobs)
	}
	if len(store.recorded) != 1 || len(store.recorded[0].assetIDs) != 1 || store.recorded[0].assetIDs[0] != targets[1].AssetID {
		t.Errorf("stamps = %+v, want only the reachable asset", store.recorded)
	}
	got := store.stateSet[len(store.stateSet)-1].LastSweepRefusals[sharedautoscan.ReasonNoEligibleCollector]
	if got != 1 {
		t.Errorf("refusals = %+v, want %s=1", store.stateSet[len(store.stateSet)-1].LastSweepRefusals, sharedautoscan.ReasonNoEligibleCollector)
	}
}

func TestSweepTenant_ReachFailureKeepsThePlatformFallback(t *testing.T) {
	store := &fakeStore{policy: sharedautoscan.DefaultPolicy(), targets: targetsAt("198.51.100.7")}
	d := &fakeDispatcher{}
	j := routedJob(store, d, &fakeRouter{plan: sensorrouting.Plan{Platform: []string{"198.51.100.7"}}})
	j.SetReach(fakeReach{err: errors.New("db down")})
	j.SweepTenant(context.Background(), uuid.New(), false)
	if len(d.jobs) != 1 || d.jobs[0].ExecutionMode != "async" {
		t.Fatalf("dispatched %+v, want the platform fallback on a reach read error", d.jobs)
	}
}

func TestNoEligibleCollectorReasonMatchesIdentityEnrichment(t *testing.T) {
	if string(sharedautoscan.ReasonNoEligibleCollector) != identityenrichment.ReasonNoEligibleCollector {
		t.Fatalf("reason strings diverged: %q vs %q", sharedautoscan.ReasonNoEligibleCollector, identityenrichment.ReasonNoEligibleCollector)
	}
}
