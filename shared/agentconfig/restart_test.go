package agentconfig

import (
	"testing"
	"time"
)

func TestShouldRestart(t *testing.T) {
	for _, tc := range []struct {
		name       string
		uptime     time.Duration
		requestAge time.Duration
		want       bool
	}{
		{"nobody asked", time.Hour, 0, false},
		{"running since before the request", 10 * time.Minute, 5 * time.Minute, true},
		{"started after the request", 5 * time.Minute, 10 * time.Minute, false},
		{"started at the instant of the request", 5 * time.Minute, 5 * time.Minute, false},
		{"just started, old request", time.Second, time.Hour, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShouldRestart(tc.uptime, tc.requestAge); got != tc.want {
				t.Errorf("ShouldRestart(uptime=%v, age=%v) = %v, want %v",
					tc.uptime, tc.requestAge, got, tc.want)
			}
		})
	}
}

// The reason this compares durations rather than timestamps.
//
// Comparing the platform's request time against the device's start time loops
// forever when the clocks disagree: a device an hour behind restarts, comes
// back with a start time still "before" the request, and restarts again —
// every heartbeat, on every skewed host in the fleet. Durations cannot express
// that bug, and this test is what stops somebody reintroducing it.
func TestSkewedClocksCannotCauseARestartLoop(t *testing.T) {
	const skew = time.Hour // the device's clock is an hour behind

	platformNow := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	req := RestartRequest{At: platformNow.Add(-2 * time.Minute)}

	// The device has been up for 5 minutes, i.e. since before the request.
	if !ShouldRestart(5*time.Minute, req.Age(platformNow)) {
		t.Fatal("a device running since before the request must restart")
	}

	// It restarts. Its clock is still an hour off — and that must not matter.
	for i := 1; i <= 5; i++ {
		later := platformNow.Add(time.Duration(i) * time.Minute)
		uptime := time.Duration(i) * time.Minute // running since the restart
		if ShouldRestart(uptime, req.Age(later)) {
			t.Fatalf("restarted again %d minute(s) later with a %v clock skew — this is the loop", i, skew)
		}
	}
}

// Ten clicks are one restart, not ten: only the latest request is stored, and
// the device compares against its age.
func TestRepeatedRequestsCollapse(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	req := RestartRequest{At: now.Add(-time.Second)}
	if !ShouldRestart(time.Hour, req.Age(now)) {
		t.Fatal("the latest request must be honoured")
	}
	if ShouldRestart(time.Millisecond, req.Age(now)) {
		t.Error("a device that has just started honoured an older request")
	}
}

func TestAge(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)

	if got := (RestartRequest{}).Age(now); got != 0 {
		t.Errorf("age of no request = %v, want 0", got)
	}
	if got := (RestartRequest{At: now.Add(-90 * time.Second)}).Age(now); got != 90*time.Second {
		t.Errorf("age = %v, want 90s", got)
	}
	// A request that reads as being in the FUTURE — the platform's own clock
	// stepped back — must be 0, not a tiny positive age. A tiny positive age
	// satisfies ShouldRestart for every running process, which is the
	// fleet-wide loop this design exists to prevent, relocated to the
	// platform's clock.
	future := RestartRequest{At: now.Add(time.Minute)}
	if got := future.Age(now); got != 0 {
		t.Errorf("age of a future-dated request = %v, want 0", got)
	}
	if ShouldRestart(30*24*time.Hour, future.Age(now)) {
		t.Error("a future-dated request restarted a long-running device — the platform-side loop")
	}
}

// The wire field is what the device actually decides on, so its rounding is
// load-bearing. Truncating a just-made request to 0 makes it indistinguishable
// from no request at all — which is exactly what happened, and what let an
// integration test pass on a payload that said nobody had asked.
func TestWireSecondsRoundsUpSoAJustMadeRequestIsNotZero(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)

	if got := (RestartRequest{At: now.Add(-5 * time.Millisecond)}).WireSeconds(now); got != 1 {
		t.Errorf("a 5ms-old request goes on the wire as %d seconds, want 1 — 0 reads as 'nobody asked'", got)
	}
	if got := (RestartRequest{At: now.Add(-1500 * time.Millisecond)}).WireSeconds(now); got != 2 {
		t.Errorf("a 1.5s-old request = %d, want 2", got)
	}
	if got := (RestartRequest{At: now.Add(-2 * time.Second)}).WireSeconds(now); got != 2 {
		t.Errorf("an exactly-2s request = %d, want 2", got)
	}
	if got := (RestartRequest{}).WireSeconds(now); got != 0 {
		t.Errorf("no request = %d, want 0", got)
	}
	if got := (RestartRequest{At: now.Add(time.Hour)}).WireSeconds(now); got != 0 {
		t.Errorf("a future-dated request = %d, want 0", got)
	}
}
