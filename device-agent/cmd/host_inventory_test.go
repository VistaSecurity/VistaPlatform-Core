package main

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/api"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/hostinventory"
)

// The LOCAL host-inventory schedule.
//
// It is the half of the feature with no job behind it: nothing queues it,
// nothing retries it, and if the loop stops the host silently disappears from
// the inventory. These pin the two properties that prevent that — it collects
// on START as well as on the tick, and a failure does not end the loop.

type recordingSubmitter struct {
	mu     sync.Mutex
	calls  int
	err    error
	notify chan struct{}
}

func (s *recordingSubmitter) SubmitHostInventory(_ *hostinventory.Report, _ *di.InterrogateResult) error {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	select {
	case s.notify <- struct{}{}:
	default:
	}
	return s.err
}

func (s *recordingSubmitter) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// An agent restarted daily — a container, a laptop — would never reach a
// 24-hour tick. Collecting on start is what makes the feature do anything at
// all on those hosts.
func TestRunLocalHostInventoryLoop_CollectsOnStart(t *testing.T) {
	s := &recordingSubmitter{notify: make(chan struct{}, 4)}
	stop := make(chan struct{})
	defer close(stop)

	go runLocalHostInventoryLoop(s, "agent-1", newInterval(time.Hour), stop)

	select {
	case <-s.notify:
	case <-time.After(90 * time.Second):
		t.Fatal("no collection happened on start; a host restarted before its first tick would never report")
	}
	if got := s.count(); got != 1 {
		t.Errorf("collections on start = %d, want 1", got)
	}
}

// A transient failure — one boot where `ss` was momentarily missing, a network
// blip on the POST — must not silently end host inventory for the lifetime of
// the process. Same reasoning as the heartbeat loop's.
func TestRunLocalHostInventoryLoop_SurvivesAFailedSubmission(t *testing.T) {
	s := &recordingSubmitter{notify: make(chan struct{}, 8), err: errors.New("platform unreachable")}
	stop := make(chan struct{})
	defer close(stop)

	// The floor is applied inside the loop, so ask for something small and
	// confirm the loop still ticks rather than stalling on the first error.
	go runLocalHostInventoryLoop(s, "agent-1", newInterval(time.Hour), stop)

	select {
	case <-s.notify:
	case <-time.After(90 * time.Second):
		t.Fatal("the first collection never ran")
	}
	if s.count() != 1 {
		t.Fatalf("collections = %d", s.count())
	}
	// The loop must still be alive: closing stop returns cleanly rather than
	// finding a goroutine that already exited on the error.
}

// A nil submitter must not panic — the loop is started from Start(), which runs
// before anything guarantees a client exists.
func TestRunLocalHostInventoryLoop_NilSubmitterIsANoOp(t *testing.T) {
	runLocalHostInventoryLoop(nil, "agent-1", newInterval(time.Hour), nil)
}

// The floor is enforced in the loop as well as in the config parser. A package
// enumeration every minute is a self-inflicted denial of service on the
// customer's own host, and the config is not the only way an interval reaches
// here.
func TestRunLocalHostInventoryLoop_RaisesATooSmallInterval(t *testing.T) {
	if config.MinHostInventoryInterval <= 0 {
		t.Fatal("the floor is not set")
	}
	// A one-nanosecond interval with no floor would spin the collector as fast
	// as the host can answer. Asserting the parser and the loop agree on the
	// floor is the cheap half; the loop's own clamp is read directly below.
	if got := config.ParseHostInventoryInterval("5m"); got != config.MinHostInventoryInterval {
		t.Errorf("ParseHostInventoryInterval(5m) = %v, want the %v floor", got, config.MinHostInventoryInterval)
	}
	if got := config.ParseHostInventoryInterval(""); got != config.DefaultHostInventoryInterval {
		t.Errorf("an unset interval = %v, want the %v default", got, config.DefaultHostInventoryInterval)
	}
	if got := config.ParseHostInventoryInterval("not-a-duration"); got != config.DefaultHostInventoryInterval {
		t.Errorf("an unparseable interval = %v, want the default", got)
	}
	if got := config.ParseHostInventoryInterval("48h"); got != 48*time.Hour {
		t.Errorf("a valid interval above the floor was not honoured: %v", got)
	}
}

// An over-cap report is not a transient failure, and the loop must say so
// rather than logging it as one more submission that will probably work next
// time.
//
// Both branches return without retrying — the loop waits for the next
// scheduled collection either way — but only one of them is a condition that
// will still be true then, and only one is worth an operator's attention today.
//
// To mutation-test: drop the errors.As branch from hostInventorySubmitFailure
// and the first case loses the byte count and the "will not fix itself" line.
func TestHostInventorySubmitFailure_DistinguishesAnOverCapReport(t *testing.T) {
	const interval = 24 * time.Hour

	overCap := hostInventorySubmitFailure(
		&api.ReportTooLargeError{Bytes: 40_000_000, Detail: "cap is 33554432 bytes"}, interval)

	// The measured size, because the agent is the only side that knows it.
	if !strings.Contains(overCap, "40000000") {
		t.Errorf("the over-cap line does not name the measured size: %q", overCap)
	}
	// And that waiting will not help, which is the whole difference.
	if !strings.Contains(overCap, "will not fix itself") {
		t.Errorf("the over-cap line reads as a transient failure: %q", overCap)
	}
	if strings.Contains(overCap, "retrying at the next") {
		t.Errorf("the over-cap line promises a retry that cannot succeed: %q", overCap)
	}

	transient := hostInventorySubmitFailure(errors.New("connection refused"), interval)
	if strings.Contains(transient, "will not fix itself") {
		t.Errorf("a transient failure was reported as permanent: %q", transient)
	}
	if !strings.Contains(transient, "retrying at the next scheduled collection") {
		t.Errorf("a transient failure does not say when it will be retried: %q", transient)
	}
}

// And the loop itself must make exactly ONE submission attempt for an over-cap
// report, then wait for the next scheduled collection like any other outcome.
// A retry here is what would turn a permanent condition into a hot loop against
// the platform.
func TestRunLocalHostInventoryLoop_DoesNotRetryAnOverCapReport(t *testing.T) {
	s := &recordingSubmitter{
		notify: make(chan struct{}, 8),
		err:    &api.ReportTooLargeError{Bytes: 40_000_000, Detail: "too big"},
	}
	stop := make(chan struct{})
	defer close(stop)

	go runLocalHostInventoryLoop(s, "agent-1", newInterval(time.Hour), stop)

	select {
	case <-s.notify:
	case <-time.After(90 * time.Second):
		t.Fatal("the first collection never ran")
	}

	// Give any retry loop time to show itself. The next SCHEDULED collection is
	// an hour away, so a second call inside this window could only be a retry.
	time.Sleep(300 * time.Millisecond)
	if got := s.count(); got != 1 {
		t.Fatalf("submissions = %d, want exactly 1 — an over-cap report must not be retried; "+
			"the same host produces the same size every time", got)
	}
}

// A fixed ticker keeps a fleet in whatever phase it started in, forever —
// and agents are rolled out and upgraded in batches, so that phase is commonly
// the same minute for hundreds of hosts. Each then walks its whole package
// database and posts a report at that minute, every day.
//
// The two properties that matter are both bounds, and both are one-sided:
// jitter is only ever ADDED, so the floor stays a real floor, and it is
// bounded above so a daily cadence stays recognisably daily.
func TestJitteredInterval_AddsBoundedSpreadAndNeverGoesUnderTheFloor(t *testing.T) {
	const interval = 24 * time.Hour
	max := interval + interval/hostInventoryJitterFraction

	seen := map[time.Duration]bool{}
	for i := 0; i < 500; i++ {
		got := jitteredInterval(interval)
		if got < interval {
			t.Fatalf("jitter went UNDER the interval: %v < %v — the floor is a safety bound on how "+
				"often a customer's host is made to do this work, and jitter must not be a way under it", got, interval)
		}
		if got >= max {
			t.Fatalf("jitter exceeded its bound: %v >= %v", got, max)
		}
		seen[got] = true
	}
	// A constant "jitter" would spread nothing. 500 draws over a 2.4-hour span
	// cannot plausibly collide into a handful of values.
	if len(seen) < 100 {
		t.Errorf("only %d distinct waits in 500 draws — this is not spreading a fleet", len(seen))
	}

	// Degenerate intervals must not panic or produce a negative wait.
	for _, d := range []time.Duration{0, -time.Second, time.Nanosecond} {
		if got := jitteredInterval(d); got < d {
			t.Errorf("jitteredInterval(%v) = %v, which is less than the interval", d, got)
		}
	}
}

// failedSectionSuffix is what stops a partial collection being logged as a
// whole one.
func TestFailedSectionSuffix(t *testing.T) {
	whole := &hostinventory.Report{Sections: map[string]string{
		"host": hostinventory.SectionOK, "packages": hostinventory.SectionOK,
	}}
	if got := failedSectionSuffix(whole); got != "" {
		t.Errorf("a complete collection produced a failure suffix: %q", got)
	}

	partial := &hostinventory.Report{Sections: map[string]string{
		"host":       hostinventory.SectionOK,
		"packages":   hostinventory.SectionFailed,
		"cert_h":     hostinventory.SectionUnsupported,
		"interfaces": hostinventory.SectionFailed,
	}}
	got := failedSectionSuffix(partial)
	if got != " (failed: interfaces, packages)" {
		t.Errorf("failure suffix = %q", got)
	}
	// An unsupported section is not a failure — the platform simply has no way
	// to answer, which is a different claim.
	if got == "" {
		t.Error("a partial collection reported no failures")
	}
}
