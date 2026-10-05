package discovery

// The per-unit pipeline's own budgets (scan_unit.go). Moved here with the
// pipeline from cluster-sensor-service ( WP2b), unchanged.

import (
	"testing"
	"time"
)

func TestUnitWorkers_StaysInsideThePaceBudget(t *testing.T) {
	for _, pace := range []Pace{PacePolite, PaceNormal, PaceFast} {
		p, _ := pace.Profile()
		if n := UnitWorkers(p); n < 1 || n*p.PerHostConcurrency > p.GlobalConcurrency {
			t.Errorf("%s: %d workers × %d per host exceeds the pace's %d", pace, n, p.PerHostConcurrency, p.GlobalConcurrency)
		}
	}
}

func TestUnitDeadline_ScalesWithPortsAndIsCapped(t *testing.T) {
	e, err := NewUnitEngine(PaceNormal, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	quick := e.Deadline(UnitInput{TCP: QuickPorts()})
	thorough := e.Deadline(UnitInput{TCP: ThoroughPorts(), UDP: CuratedUDPPorts()})
	if quick >= thorough {
		t.Errorf("quick %s, thorough %s: the deadline does not grow with the ports", quick, thorough)
	}
	// A Thorough host at the normal pace, every port filtered, waits out
	// 512 batches × 1.5s ≈ 12.8 min of connect timeouts: the deadline must
	// leave room for that.
	if thorough < 13*time.Minute {
		t.Errorf("thorough deadline %s is shorter than its worst-case port scan", thorough)
	}
	// Polite: 4,096 batches × (2s + 100ms) ≈ 2.4h of connect timeouts.
	polite, _ := NewUnitEngine(PacePolite, nil, nil)
	if d := polite.Deadline(UnitInput{TCP: ThoroughPorts(), UDP: CuratedUDPPorts()}); d < 143*time.Minute || d > MaxUnitDeadline {
		t.Errorf("polite thorough deadline = %s, want between its worst case and the %s cap", d, MaxUnitDeadline)
	}
	slow, _ := NewUnitEngine(PacePolite, nil, nil)
	slow.pace.PerHostConcurrency, slow.pace.ConnectTimeout = 1, 30*time.Second
	if d := slow.Deadline(UnitInput{TCP: ThoroughPorts()}); d != MaxUnitDeadline {
		t.Errorf("deadline = %s, want the %s cap", d, MaxUnitDeadline)
	}
}

// An OT opt-in identification cannot probe is refused when the engine is
// built, before any packet — not discovered host by host.
func TestNewUnitEngine_RefusesAnUnknownOTOptIn(t *testing.T) {
	if _, err := NewUnitEngine(PaceNormal, []string{"DNP3"}, nil); err == nil {
		t.Fatal("an engine was built for an OT protocol nothing can probe")
	}
	if _, err := NewUnitEngine(PaceNormal, []string{"Modbus"}, nil); err != nil {
		t.Fatalf("a valid opt-in was refused: %v", err)
	}
}

func TestPlanTargetHostname(t *testing.T) {
	for in, want := range map[string]string{"10.0.0.1": "", "10.0.0.0/24": "", "10.0.0.1-10.0.0.9": "", "fd00::1": "", "app.example.com": "app.example.com"} {
		if got := PlanTargetHostname(in); got != want {
			t.Errorf("PlanTargetHostname(%q) = %q, want %q", in, got, want)
		}
	}
}
