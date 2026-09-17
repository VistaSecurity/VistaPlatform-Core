package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/hostinventory"

	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig/desiredstate"
)

// Turning host inventory on and off from the control plane has to START and
// STOP the loop, not set a flag the loop consults. An agent told to stop
// describing its host must stop reading the package database, not read it and
// throw the result away.
func TestHostInventorySupervisorStartsAndStops(t *testing.T) {
	var mu sync.Mutex
	running := 0
	sup := newHostInventorySupervisor(time.Hour, func(iv *interval, stop <-chan struct{}) {
		mu.Lock()
		running++
		mu.Unlock()
		<-stop
		mu.Lock()
		running--
		mu.Unlock()
	})

	if err := sup.setEnabled(true); err != nil {
		t.Fatalf("setEnabled(true): %v", err)
	}
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return running == 1 }, "the loop to start")

	// Idempotent: the platform re-sends full desired state every beat.
	if err := sup.setEnabled(true); err != nil {
		t.Fatalf("setEnabled(true) again: %v", err)
	}
	mu.Lock()
	again := running
	mu.Unlock()
	if again != 1 {
		t.Errorf("%d loops running after a repeated enable, want 1", again)
	}

	if err := sup.setEnabled(false); err != nil {
		t.Fatalf("setEnabled(false): %v", err)
	}
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return running == 0 }, "the loop to stop")
}

// The floor is enforced on the agent too, not only at the platform. An older
// platform, or a hand-made request, must not make a host walk its package
// database every minute.
func TestHostInventorySupervisorRefusesAnIntervalBelowTheFloor(t *testing.T) {
	sup := newHostInventorySupervisor(time.Hour, func(*interval, <-chan struct{}) {})
	if err := sup.setInterval(5 * time.Minute); err == nil {
		t.Error("five minutes was accepted; the one-hour floor is a bound on how often a customer's host does this work")
	}
	if err := sup.setInterval(6 * time.Hour); err != nil {
		t.Errorf("six hours was refused: %v", err)
	}
}

// A running loop picks up a new cadence WITHOUT RESTARTING — and the assertion
// has to be that the loop reacts, not that the value landed in a field.
//
// The first version of this test stubbed the loop as `func(iv, stop){<-stop}`
// and asserted `sup.iv.get() == 3h`. It passed while the real host-inventory
// loop ignored the pushed interval entirely, because it pinned the plumbing
// into the interval object rather than any effect of it. That is the
// "check that cannot fail" shape: with intervals allowed up to 30 days, the
// bug it missed meant shortening 30 days to an hour could take 30 days.
func TestIntervalChangeWakesARunningLoop(t *testing.T) {
	cycles := make(chan struct{}, 8)
	sup := newHostInventorySupervisor(time.Hour, func(iv *interval, stop <-chan struct{}) {
		// Same shape as the real loop: wait a cycle, then work.
		for waitCycle(iv, stop, nil) {
			select {
			case cycles <- struct{}{}:
			default:
			}
		}
	})
	if err := sup.setEnabled(true); err != nil {
		t.Fatalf("setEnabled: %v", err)
	}
	defer func() { _ = sup.setEnabled(false) }()

	// Nothing should fire on the original hour-long cadence.
	select {
	case <-cycles:
		t.Fatal("the loop fired before its interval elapsed")
	case <-time.After(30 * time.Millisecond):
	}

	if err := sup.setInterval(2 * time.Hour); err != nil {
		t.Fatalf("setInterval: %v", err)
	}
	// Lengthening must not fire it either.
	select {
	case <-cycles:
		t.Fatal("lengthening the interval fired the loop")
	case <-time.After(30 * time.Millisecond):
	}

	// Shortening below the elapsed time must wake it promptly. setInterval
	// refuses anything under the floor, so go through the interval the
	// supervisor handed the loop — the platform-side floor is tested
	// separately.
	sup.mu.Lock()
	iv := sup.iv
	sup.mu.Unlock()
	iv.set(5 * time.Millisecond)

	select {
	case <-cycles:
	case <-time.After(3 * time.Second):
		t.Fatal("the loop never woke; it is still serving the wait it started with")
	}
}

// The REAL host-inventory loop must honour a pushed cadence. Driving the actual
// runLocalHostInventoryLoop is the only way to see that: it is the loop that
// ignored the interval, while a stub in its place looked fine.
func TestRealHostInventoryLoopHonoursAPushedInterval(t *testing.T) {
	// The floor is a per-call parameter, so this test lowers it for its own
	// loop and nothing else: a real one-hour floor cannot be observed in a unit
	// test, and testing a stub instead is what hid the original bug.
	collected := make(chan struct{}, 8)
	sub := &countingSubmitter{ch: collected}

	iv := newInterval(30 * time.Minute)
	stop := make(chan struct{})
	defer close(stop)

	go runLocalHostInventoryLoopWith(sub, "agent-1", iv, stop, func(context.Context, string) (*hostinventory.Report, *di.InterrogateResult, error) {
		return &hostinventory.Report{Platform: "test"}, &di.InterrogateResult{}, nil
	}, time.Millisecond)

	// The immediate first collection on start.
	select {
	case <-collected:
	case <-time.After(3 * time.Second):
		t.Fatal("no collection on start")
	}

	// Nothing more on a 30-minute cadence.
	select {
	case <-collected:
		t.Fatal("collected again before the interval elapsed")
	case <-time.After(50 * time.Millisecond):
	}

	// Shorten it. The loop is inside a 30-minute wait; if it does not wake, the
	// setting an operator just changed takes effect half an hour later — and at
	// the registry's maximum, thirty days later.
	iv.set(5 * time.Millisecond)
	select {
	case <-collected:
	case <-time.After(3 * time.Second):
		t.Fatal("the real loop ignored the pushed interval — it is using a private timer")
	}
}

func TestConfiguredHostInventoryCollectorPassesConnectionPrivacyOptIn(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
	}{
		{name: "disabled by default", enabled: false},
		{name: "explicitly enabled", enabled: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent := &DeviceAgent{config: &config.Config{HostInventoryConnectionsEnabled: tt.enabled}}
			called := false
			collector := agent.configuredHostInventoryCollector(func(_ context.Context, agentID string, enabled bool) (*hostinventory.Report, *di.InterrogateResult, error) {
				called = true
				if agentID != "agent-1" {
					t.Errorf("agentID = %q, want agent-1", agentID)
				}
				if enabled != tt.enabled {
					t.Errorf("collectConnections = %t, want %t", enabled, tt.enabled)
				}
				return &hostinventory.Report{Platform: "test"}, &di.InterrogateResult{}, nil
			})

			if _, _, err := collector(context.Background(), "agent-1"); err != nil {
				t.Fatalf("collector: %v", err)
			}
			if !called {
				t.Fatal("configured collector did not call the production connection-aware collector")
			}
		})
	}
}

// countingSubmitter reports a collection without touching the host.
type countingSubmitter struct{ ch chan struct{} }

func (c *countingSubmitter) SubmitHostInventory(*hostinventory.Report, *di.InterrogateResult) error {
	select {
	case c.ch <- struct{}{}:
	default:
	}
	return nil
}

// everyInterval re-reads the duration each cycle: that is what makes a pushed
// interval take effect without a restart.
func TestEveryIntervalRereadsTheDuration(t *testing.T) {
	iv := newInterval(time.Hour)
	stop := make(chan struct{})
	ticks := make(chan struct{}, 4)

	go everyInterval(iv, stop, func() {
		select {
		case ticks <- struct{}{}:
		default:
		}
	})

	// The immediate first run.
	select {
	case <-ticks:
	case <-time.After(2 * time.Second):
		close(stop)
		t.Fatal("no immediate first run")
	}

	// Shorten it; the next wait must use the new value.
	iv.set(5 * time.Millisecond)
	select {
	case <-ticks:
	case <-time.After(2 * time.Second):
		close(stop)
		t.Fatal("a shortened interval did not take effect; the loop is still using its startup value")
	}
	close(stop)
}

// Every setting the registry says an agent has must have a handler, or the
// platform offers knobs this binary silently cannot honour.
func TestEveryAgentSettingHasAHandler(t *testing.T) {
	applier := desiredstate.New()
	sup := newHostInventorySupervisor(time.Hour, func(*interval, <-chan struct{}) {})
	registerManagedSettings(applier, sup, newInterval(time.Minute), newInterval(time.Minute), func(bool) {})

	values := agentconfig.Values{}
	for _, f := range agentconfig.FieldsFor(agentconfig.RuntimeAgent) {
		values[f.Key] = f.Default
	}
	applier.Apply("rev-1", values)

	_, failures, _ := applier.Report()
	for k, why := range failures {
		t.Errorf("%s was not applied: %s", k, why)
	}
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// Shortening an interval must interrupt the wait it is shortening. A loop 20
// minutes into a 24-hour wait that does not notice a change to six hours makes
// "the control plane is authoritative" mean "eventually, maybe tomorrow".
func TestShorteningAnIntervalInterruptsTheCurrentWait(t *testing.T) {
	iv := newInterval(time.Hour)
	stop := make(chan struct{})
	defer close(stop)
	ticks := make(chan struct{}, 4)

	go everyInterval(iv, stop, func() {
		select {
		case ticks <- struct{}{}:
		default:
		}
	})

	<-ticks // the immediate first run

	iv.set(10 * time.Millisecond)
	select {
	case <-ticks:
	case <-time.After(3 * time.Second):
		t.Fatal("the loop was still serving its original hour-long wait")
	}
}

// An interval shortened below the time already elapsed fires NOW rather than
// waiting the new interval afresh — otherwise repeated changes could postpone a
// collection indefinitely.
func TestElapsedTimeCountsTowardsAShortenedInterval(t *testing.T) {
	iv := newInterval(time.Hour)
	stop := make(chan struct{})
	defer close(stop)
	ticks := make(chan struct{}, 4)

	go everyInterval(iv, stop, func() {
		select {
		case ticks <- struct{}{}:
		default:
		}
	})
	<-ticks

	time.Sleep(60 * time.Millisecond)
	start := time.Now()
	iv.set(20 * time.Millisecond) // already exceeded by the sleep above

	select {
	case <-ticks:
		if waited := time.Since(start); waited > 15*time.Millisecond {
			t.Errorf("waited a further %v; the elapsed time should have satisfied the new interval immediately", waited)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the loop never fired")
	}
}
