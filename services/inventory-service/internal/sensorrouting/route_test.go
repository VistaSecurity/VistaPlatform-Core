package sensorrouting

// The routing rule, one polarity at a time: observing sensor beats segment
// beats platform; an OFFLINE observer skips the target rather than handing it
// to the platform; the platform's own sensor never gets a job; unknown
// observers fall through to the segment rule.

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

var now = time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)

func live(name string, prefixes ...string) Sensor {
	beat := now.Add(-20 * time.Second)
	return Sensor{ID: uuid.New(), Name: name, Status: "active", LastHeartbeat: &beat, ReportingInterval: 30, Prefixes: PrefixesFor(prefixes, "")}
}

func offline(name string, prefixes ...string) Sensor {
	s := live(name, prefixes...)
	beat := now.Add(-time.Hour)
	s.LastHeartbeat = &beat
	return s
}

func targetsOf(p Plan, id uuid.UUID) []string {
	for _, g := range p.Groups {
		if g.Sensor.ID == id {
			return g.Targets
		}
	}
	return nil
}

func TestRoute_ObservingSensorWins(t *testing.T) {
	xps := live("xps16-sensor", "198.51.100.0/24")
	branch := live("branch-sensor", "10.20.0.0/16")
	// 10.20.0.5 sits in branch's segment but xps16 is the one that SAW it.
	plan := Route([]string{"10.20.0.5"}, map[string]uuid.UUID{"10.20.0.5": xps.ID}, []Sensor{xps, branch}, now)

	if got := targetsOf(plan, xps.ID); len(got) != 1 || got[0] != "10.20.0.5" {
		t.Fatalf("xps16 targets = %v, want [10.20.0.5]", got)
	}
	if len(plan.Platform) != 0 || len(plan.Skipped) != 0 || len(targetsOf(plan, branch.ID)) != 0 {
		t.Errorf("plan = %+v, want only the observing sensor", plan)
	}
	if plan.Groups[0].Reasons["10.20.0.5"] != ReasonObserved {
		t.Errorf("reason = %q", plan.Groups[0].Reasons["10.20.0.5"])
	}
}

// TestRoute_NeverScanSelf_ObservedBranch pins asset-inventory decision 9's
// guard: a sensor is never assigned its OWN host as a scan target, even when
// it is the sensor that last observed that address (which it always is, for
// its own address, once it starts self-reporting).
//
// Mutation check: delete the `!observer.IsSelf(target)` clause in Route and
// this goes red (xps16 would be assigned its own address, reason
// "observing_sensor").
func TestRoute_NeverScanSelf_ObservedBranch(t *testing.T) {
	xps := live("xps16-sensor", "198.51.100.0/24")
	xps.SelfAddresses = map[string]bool{"198.51.100.99": true}
	branch := live("branch-sensor", "10.20.0.0/16")

	// xps16 "observed" its own address (it always does — it is on its own
	// segment) AND a genuinely different host.
	observed := map[string]uuid.UUID{
		"198.51.100.99": xps.ID,
		"10.20.0.5":     xps.ID,
	}
	plan := Route([]string{"198.51.100.99", "10.20.0.5"}, observed, []Sensor{xps, branch}, now)

	got := targetsOf(plan, xps.ID)
	if len(got) != 1 || got[0] != "10.20.0.5" {
		t.Fatalf("xps16 targets = %v, want only the OTHER host (10.20.0.5)", got)
	}
	// Its own address has no other observer and is inside no OTHER sensor's
	// segment, so it falls through to the platform sensor rather than being
	// silently dropped.
	if len(plan.Platform) != 1 || plan.Platform[0] != "198.51.100.99" {
		t.Errorf("plan.Platform = %v, want [198.51.100.99] (self address falls through to platform)", plan.Platform)
	}
}

// TestRoute_NeverScanSelf_SegmentBranch covers the segment-coverage path
// separately: a sensor's own address sits inside a segment it is itself
// bound to (the common case — it IS on that segment), and nobody has
// "observed" it yet (first self-report, before any discovery row exists).
//
// Mutation check: delete the `s.IsSelf(target)` skip inside the segment loop
// and this goes red (xps16 would be assigned its own address via
// ReasonSegment).
func TestRoute_NeverScanSelf_SegmentBranch(t *testing.T) {
	xps := live("xps16-sensor", "198.51.100.0/24")
	xps.SelfAddresses = map[string]bool{"198.51.100.99": true}

	plan := Route([]string{"198.51.100.99", "198.51.100.42"}, nil, []Sensor{xps}, now)

	got := targetsOf(plan, xps.ID)
	if len(got) != 1 || got[0] != "198.51.100.42" {
		t.Fatalf("xps16 targets = %v, want only 198.51.100.42", got)
	}
	if len(plan.Platform) != 1 || plan.Platform[0] != "198.51.100.99" {
		t.Errorf("plan.Platform = %v, want [198.51.100.99]", plan.Platform)
	}
}

// TestRoute_NeverScanSelf_AnotherSensorCanStillScanIt confirms the guard is
// per-sensor, not a global exclusion: a DIFFERENT sensor covering the same
// segment is a legitimate executor for scanning sensor A's own host.
func TestRoute_NeverScanSelf_AnotherSensorCanStillScanIt(t *testing.T) {
	xps := live("xps16-sensor", "198.51.100.0/24")
	xps.SelfAddresses = map[string]bool{"198.51.100.99": true}
	other := live("other-sensor", "198.51.100.0/24")

	plan := Route([]string{"198.51.100.99"}, nil, []Sensor{xps, other}, now)

	// Two segment candidates cover it; the tie-break (sorted by name) picks
	// "other-sensor" before "xps16-sensor" — but the point under test is that
	// SOME sensor gets it, not xps16, and definitely not nobody.
	if len(plan.Platform) != 0 {
		t.Errorf("plan.Platform = %v, want empty — another sensor should have taken it", plan.Platform)
	}
	if got := targetsOf(plan, xps.ID); len(got) != 0 {
		t.Errorf("xps16 targets = %v, want none — it must never scan itself", got)
	}
	if got := targetsOf(plan, other.ID); len(got) != 1 {
		t.Errorf("other-sensor targets = %v, want [198.51.100.99]", got)
	}
}

func TestRoute_SegmentSensorWhenNobodyObserved(t *testing.T) {
	xps := live("xps16-sensor", "198.51.100.0/24")
	plan := Route([]string{"198.51.100.42", "198.51.100.43"}, nil, []Sensor{xps}, now)
	if got := targetsOf(plan, xps.ID); strings.Join(got, ",") != "198.51.100.42,198.51.100.43" {
		t.Fatalf("segment routing gave %v", got)
	}
	if plan.Groups[0].Reasons["198.51.100.42"] != ReasonSegment {
		t.Errorf("reason = %q", plan.Groups[0].Reasons["198.51.100.42"])
	}
}

func TestRoute_PlatformFallback(t *testing.T) {
	xps := live("xps16-sensor", "198.51.100.0/24")
	plan := Route([]string{"10.0.0.7", "db.internal"}, nil, []Sensor{xps}, now)
	if strings.Join(plan.Platform, ",") != "10.0.0.7,db.internal" {
		t.Fatalf("platform = %v", plan.Platform)
	}
	if len(plan.Groups) != 0 || len(plan.Skipped) != 0 {
		t.Errorf("plan = %+v", plan)
	}
}

// The target observed ONLY by the platform's own sensor is a platform target.
// (The store already excludes system sensors from observedBy; this pins the
// planner's own guard should a caller pass one anyway.)
func TestRoute_PlatformSensorNeverGetsAJob(t *testing.T) {
	platform := live("Platform Discovery Sensor")
	platform.System = true
	plan := Route([]string{"10.0.0.7"}, map[string]uuid.UUID{"10.0.0.7": platform.ID}, []Sensor{platform}, now)
	if len(plan.Groups) != 0 || len(plan.Platform) != 1 {
		t.Fatalf("plan = %+v, want the platform", plan)
	}
}

// The guard the spec names: an offline observing sensor SKIPS the target. It
// is not handed to the platform (a scan from the wrong place), and it is not
// handed to a segment sensor (the observer is the better evidence and will be
// back). Flip Dispatchable to true for a stale sensor and this goes red.
func TestRoute_OfflineObserverSkipsRatherThanSubstitutes(t *testing.T) {
	xps := offline("xps16-sensor", "198.51.100.0/24")
	branch := live("branch-sensor", "198.51.100.0/24") // covers the same segment
	plan := Route([]string{"198.51.100.42"}, map[string]uuid.UUID{"198.51.100.42": xps.ID}, []Sensor{xps, branch}, now)

	if len(plan.Groups) != 0 || len(plan.Platform) != 0 {
		t.Fatalf("an offline observer's target was routed elsewhere: %+v", plan)
	}
	if len(plan.Skipped) != 1 || plan.Skipped[0].Reason != ReasonObserverOffline || plan.Skipped[0].Sensor.ID != xps.ID {
		t.Fatalf("skipped = %+v", plan.Skipped)
	}
	msg := plan.Skipped[0].Message()
	for _, want := range []string{"xps16-sensor", "offline", "198.51.100.42", "not scanned"} {
		if !strings.Contains(msg, want) {
			t.Errorf("skip message %q lacks %q", msg, want)
		}
	}
}

func TestRoute_OfflineSegmentSensorIsNotACandidate(t *testing.T) {
	xps := offline("xps16-sensor", "198.51.100.0/24")
	plan := Route([]string{"198.51.100.42"}, nil, []Sensor{xps}, now)
	if len(plan.Platform) != 1 || len(plan.Groups) != 0 {
		t.Fatalf("plan = %+v, want the platform (no live sensor covers it)", plan)
	}
}

func TestRoute_AirGappedAndSystemSensorsNeverCoverASegment(t *testing.T) {
	gapped := live("vault-sensor", "198.51.100.0/24")
	gapped.AirGapped = true
	system := live("Platform Discovery Sensor", "198.51.100.0/24")
	system.System = true
	plan := Route([]string{"198.51.100.42"}, nil, []Sensor{gapped, system}, now)
	if len(plan.Platform) != 1 || len(plan.Groups) != 0 {
		t.Fatalf("plan = %+v", plan)
	}
}

// An observer id that is no longer in the fleet (deleted sensor) falls through
// to the segment rule rather than being skipped forever.
func TestRoute_UnknownObserverFallsThrough(t *testing.T) {
	xps := live("xps16-sensor", "198.51.100.0/24")
	plan := Route([]string{"198.51.100.42"}, map[string]uuid.UUID{"198.51.100.42": uuid.New()}, []Sensor{xps}, now)
	if got := targetsOf(plan, xps.ID); len(got) != 1 {
		t.Fatalf("plan = %+v, want the segment sensor", plan)
	}
}

func TestRoute_GroupsBySensorInFirstAppearanceOrderAndDedupes(t *testing.T) {
	a := live("alpha", "10.1.0.0/16")
	b := live("beta", "10.2.0.0/16")
	plan := Route([]string{"10.2.0.1", "10.1.0.1", "10.2.0.2", "10.2.0.1", " ", "10.9.9.9"}, nil, []Sensor{a, b}, now)
	if len(plan.Groups) != 2 || plan.Groups[0].Sensor.ID != b.ID || plan.Groups[1].Sensor.ID != a.ID {
		t.Fatalf("groups = %+v, want beta first (its target came first)", plan.Groups)
	}
	if strings.Join(plan.Groups[0].Targets, ",") != "10.2.0.1,10.2.0.2" {
		t.Errorf("beta targets = %v (duplicate not collapsed?)", plan.Groups[0].Targets)
	}
	if strings.Join(plan.Platform, ",") != "10.9.9.9" {
		t.Errorf("platform = %v", plan.Platform)
	}
}

// Two live sensors covering one segment resolve the same way every time.
func TestRoute_SegmentTieIsDeterministic(t *testing.T) {
	a := live("alpha", "10.1.0.0/16")
	b := live("beta", "10.1.0.0/16")
	for i := 0; i < 5; i++ {
		plan := Route([]string{"10.1.0.1"}, nil, []Sensor{b, a}, now)
		if len(plan.Groups) != 1 || plan.Groups[0].Sensor.Name != "alpha" {
			t.Fatalf("iteration %d: %+v", i, plan.Groups)
		}
	}
}

func TestPrefixesFor(t *testing.T) {
	got := PrefixesFor([]string{"198.51.100.173/24", "garbage", "fd00::1/64"}, "10.0.0.1")
	if len(got) != 2 || got[0] != netip.MustParsePrefix("198.51.100.0/24") || got[1] != netip.MustParsePrefix("fd00::/64") {
		t.Errorf("bound prefixes = %v", got)
	}
	// No bound prefixes: the primary address widened to a LAN guess.
	if got := PrefixesFor(nil, "198.51.100.173"); len(got) != 1 || got[0] != netip.MustParsePrefix("198.51.100.0/24") {
		t.Errorf("v4 fallback = %v", got)
	}
	if got := PrefixesFor(nil, "2001:db8::10"); len(got) != 1 || got[0] != netip.MustParsePrefix("2001:db8::/64") {
		t.Errorf("v6 fallback = %v", got)
	}
	if got := PrefixesFor(nil, ""); len(got) != 0 {
		t.Errorf("no address = %v", got)
	}
}

func TestPickDispatchable(t *testing.T) {
	xps := live("xps16-sensor")
	stale := offline("branch-sensor")
	system := live("Platform Discovery Sensor")
	system.System = true
	gapped := live("vault-sensor")
	gapped.AirGapped = true
	fleet := []Sensor{xps, stale, system, gapped}

	if got, err := PickDispatchable(fleet, xps.ID, now); err != nil || got.ID != xps.ID {
		t.Fatalf("live sensor: %v / %+v", err, got)
	}
	cases := []struct {
		name string
		id   uuid.UUID
		want error
	}{
		{"offline", stale.ID, ErrSensorOffline},
		{"platform's own", system.ID, ErrSensorNotDispatchable},
		{"air-gapped", gapped.ID, ErrSensorNotDispatchable},
		{"unknown", uuid.New(), ErrSensorNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := PickDispatchable(fleet, tc.id, now); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}
