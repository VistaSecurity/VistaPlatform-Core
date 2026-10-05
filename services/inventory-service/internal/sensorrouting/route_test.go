package sensorrouting

// The routing rule, one polarity at a time: observing sensor beats segment
// beats platform; an OFFLINE observer hands the target to a different live
// segment sensor, and skips it when there is none — never to the platform; the
// platform's own sensor never gets a job; unknown observers fall through to
// the segment rule.

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

// TestRoute_OfflineObserver pins what happens to a host whose observing
// sensor is registered but not live: a DIFFERENT live tenant sensor covering
// the host's network takes it (same_segment); with none, it is skipped. In no
// case is it handed to the platform — a host a tenant sensor saw may only be
// reachable from inside, and the platform would scan it from the wrong place.
//
// Mutation checks (both polarities):
//   - drop the segment fall-through in Route's offline-observer branch and
//     "another live sensor covers it" (and the tie case) go red;
//   - append the offline-observer target to plan.Platform instead of
//     plan.Skipped and every "skipped" row goes red.
func TestRoute_OfflineObserver(t *testing.T) {
	const target = "198.51.100.42"
	type want struct {
		sensor string // the sensor's name the target is assigned to; "" for none
		reason Reason
		skip   bool // skipped, naming the offline observer
		plat   bool // handed to the platform
	}
	selfHost := func(s Sensor, addr string) Sensor {
		s.SelfAddresses = map[string]bool{addr: true}
		return s
	}
	airGapped := func(s Sensor) Sensor { s.AirGapped = true; return s }
	system := func(s Sensor) Sensor { s.System = true; return s }

	cases := []struct {
		name     string
		target   string
		observer Sensor
		others   []Sensor
		want     want
	}{
		{
			name:     "observer live: it wins over a live segment sensor, unchanged",
			observer: live("xps16-sensor", "203.0.113.0/24"),
			others:   []Sensor{live("branch-sensor", "198.51.100.0/24")},
			want:     want{sensor: "xps16-sensor", reason: ReasonObserved},
		},
		{
			name:     "observer offline, another live sensor covers it: routed there",
			observer: offline("xps16-sensor", "198.51.100.0/24"),
			others:   []Sensor{live("branch-sensor", "198.51.100.0/24")},
			want:     want{sensor: "branch-sensor", reason: ReasonSegment},
		},
		{
			name:     "observer offline, the covering sensor is offline too: skipped",
			observer: offline("xps16-sensor", "198.51.100.0/24"),
			others:   []Sensor{offline("branch-sensor", "198.51.100.0/24")},
			want:     want{skip: true},
		},
		{
			name:     "observer offline, nobody covers it: skipped, never the platform",
			observer: offline("xps16-sensor", "203.0.113.0/24"),
			others:   []Sensor{live("branch-sensor", "10.20.0.0/16")},
			want:     want{skip: true},
		},
		{
			name:     "observer offline and alone: skipped, never the platform",
			observer: offline("xps16-sensor"),
			want:     want{skip: true},
		},
		{
			name:     "observer offline, only it covers its target: the offline observer is not chosen",
			observer: offline("xps16-sensor", "198.51.100.0/24"),
			others:   []Sensor{live("branch-sensor", "10.20.0.0/16")},
			want:     want{skip: true},
		},
		{
			name:     "observer offline, the only covering live sensor is the target's own host: skipped",
			observer: offline("xps16-sensor", "198.51.100.0/24"),
			others:   []Sensor{selfHost(live("branch-sensor", "198.51.100.0/24"), target)},
			want:     want{skip: true},
		},
		{
			name:     "observer offline, own-host sensor skipped in favour of a later live one",
			observer: offline("xps16-sensor", "198.51.100.0/24"),
			others: []Sensor{
				selfHost(live("alpha-sensor", "198.51.100.0/24"), target),
				live("branch-sensor", "198.51.100.0/24"),
			},
			want: want{sensor: "branch-sensor", reason: ReasonSegment},
		},
		{
			name:     "observer offline, air-gapped and system sensors cover it: never chosen, skipped",
			observer: offline("xps16-sensor", "198.51.100.0/24"),
			others: []Sensor{
				airGapped(live("vault-sensor", "198.51.100.0/24")),
				system(live("Platform Discovery Sensor", "198.51.100.0/24")),
			},
			want: want{skip: true},
		},
		{
			name:     "hostname target with an offline observer: skipped as before (no segment for a name)",
			target:   "db.internal",
			observer: offline("xps16-sensor", "198.51.100.0/24"),
			others:   []Sensor{live("branch-sensor", "198.51.100.0/24")},
			want:     want{skip: true},
		},
		{
			name:     "observer offline and the target is its OWN host: falls through exactly as before",
			observer: selfHost(offline("xps16-sensor", "198.51.100.0/24"), target),
			others:   []Sensor{live("branch-sensor", "10.20.0.0/16")},
			want:     want{plat: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tgt := tc.target
			if tgt == "" {
				tgt = target
			}
			fleet := append([]Sensor{tc.observer}, tc.others...)
			plan := Route([]string{tgt}, map[string]uuid.UUID{tgt: tc.observer.ID}, fleet, now)

			if got := len(plan.Platform) == 1 && plan.Platform[0] == tgt; got != tc.want.plat || len(plan.Platform) > 1 {
				t.Fatalf("platform = %v, want handed to the platform: %v", plan.Platform, tc.want.plat)
			}
			skipped := len(plan.Skipped) == 1 && plan.Skipped[0].Target == tgt
			if skipped != tc.want.skip || len(plan.Skipped) > 1 {
				t.Fatalf("skipped = %+v, want skipped: %v", plan.Skipped, tc.want.skip)
			}
			if skipped {
				sk := plan.Skipped[0]
				if sk.Reason != ReasonObserverOffline || sk.Sensor.ID != tc.observer.ID {
					t.Errorf("skip = %+v, want observing_sensor_offline naming the observer", sk)
				}
				msg := sk.Message()
				for _, w := range []string{tc.observer.Name, "offline", tgt, "not scanned"} {
					if !strings.Contains(msg, w) {
						t.Errorf("skip message %q lacks %q", msg, w)
					}
				}
			}
			if tc.want.sensor == "" {
				if len(plan.Groups) != 0 {
					t.Fatalf("groups = %+v, want no sensor job", plan.Groups)
				}
				return
			}
			if len(plan.Groups) != 1 || plan.Groups[0].Sensor.Name != tc.want.sensor ||
				len(plan.Groups[0].Targets) != 1 || plan.Groups[0].Targets[0] != tgt {
				t.Fatalf("groups = %+v, want %s alone with %s", plan.Groups, tc.want.sensor, tgt)
			}
			// Whatever was chosen is a live, non-system, non-air-gapped
			// tenant sensor that is not the target's own host — and, when
			// chosen by segment, one whose networks contain the target.
			chosen := plan.Groups[0].Sensor
			if !chosen.Dispatchable(now) || chosen.System || chosen.AirGapped || chosen.IsSelf(tgt) {
				t.Errorf("chosen sensor %+v is not a live, non-system, non-air-gapped, non-self tenant sensor", chosen)
			}
			if tc.want.reason == ReasonSegment && !chosen.Covers(netip.MustParseAddr(tgt)) {
				t.Errorf("chosen segment sensor %+v does not cover %s", chosen, tgt)
			}
			if got := plan.Groups[0].Reasons[tgt]; got != tc.want.reason {
				t.Errorf("reason = %q, want %q", got, tc.want.reason)
			}
		})
	}
}

// An offline observer's target, two live sensors covering it: the choice is
// the stable name order, whatever order the fleet arrives in. The PrefixesFor
// widening makes this fall-through reachable on a guess, so the tie must at
// least resolve the same way every pass.
func TestRoute_OfflineObserverSegmentTieIsDeterministic(t *testing.T) {
	xps := offline("xps16-sensor", "10.1.0.0/16")
	a := live("alpha", "10.1.0.0/16")
	b := live("beta", "10.1.0.0/16")
	for i, fleet := range [][]Sensor{{xps, b, a}, {a, xps, b}, {b, a, xps}} {
		plan := Route([]string{"10.1.0.1"}, map[string]uuid.UUID{"10.1.0.1": xps.ID}, fleet, now)
		if len(plan.Groups) != 1 || plan.Groups[0].Sensor.Name != "alpha" || plan.Groups[0].Reasons["10.1.0.1"] != ReasonSegment {
			t.Fatalf("fleet order %d: groups = %+v, want alpha by same_segment", i, plan.Groups)
		}
		if len(plan.Skipped) != 0 || len(plan.Platform) != 0 {
			t.Fatalf("fleet order %d: plan = %+v", i, plan)
		}
	}
}

// Routing only ever partitions the targets it was given: a mixed batch under
// the new fall-through comes back with every target in exactly one of Groups,
// Platform or Skipped, and nothing added. The consent and dispatch guards
// downstream judge exactly the targets the caller selected.
func TestRoute_PartitionsTheTargetsItWasGiven(t *testing.T) {
	gone := offline("xps16-sensor", "198.51.100.0/24")
	branch := live("branch-sensor", "198.51.100.0/24")
	edge := live("edge-sensor", "203.0.113.0/24")
	targets := []string{"198.51.100.42", "203.0.113.9", "10.9.9.9", "192.0.2.1", "db.internal"}
	observed := map[string]uuid.UUID{
		"198.51.100.42": gone.ID, // offline observer, live segment sensor → branch
		"203.0.113.9":   edge.ID, // live observer → edge
		"192.0.2.1":     gone.ID, // offline observer, nobody covers → skipped
		// 10.9.9.9 and db.internal: nobody observed, nobody covers → platform
	}
	plan := Route(targets, observed, []Sensor{gone, branch, edge}, now)

	count := map[string]int{}
	for _, g := range plan.Groups {
		for _, tg := range g.Targets {
			count[tg]++
		}
	}
	for _, tg := range plan.Platform {
		count[tg]++
	}
	for _, sk := range plan.Skipped {
		count[sk.Target]++
	}
	if len(count) != len(targets) {
		t.Fatalf("plan covers %v, want exactly %v", count, targets)
	}
	for _, tg := range targets {
		if count[tg] != 1 {
			t.Errorf("%s appears %d times in the plan", tg, count[tg])
		}
	}
	if got := targetsOf(plan, branch.ID); strings.Join(got, ",") != "198.51.100.42" {
		t.Errorf("branch-sensor = %v", got)
	}
	if strings.Join(plan.Platform, ",") != "10.9.9.9,db.internal" {
		t.Errorf("platform = %v", plan.Platform)
	}
	if len(plan.Skipped) != 1 || plan.Skipped[0].Target != "192.0.2.1" {
		t.Errorf("skipped = %+v", plan.Skipped)
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
