package main

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
)

type fakeHeartbeatSender struct {
	mu    sync.Mutex
	beats int
	err   error
}

func (f *fakeHeartbeatSender) SendHeartbeat() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.beats++
	return f.err
}

func (f *fakeHeartbeatSender) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.beats
}

func waitForBeats(t *testing.T, s *fakeHeartbeatSender, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.count() >= want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("agent sent %d heartbeat(s) in 2s, want >= %d", s.count(), want)
}

// TestHeartbeatLoop_BeatsOnInterval is the regression test for's first
// defect. OutboundClient.SendHeartbeat existed but had ZERO callers anywhere in
// the repo, so device_agents.last_heartbeat never moved after registration: the
// agent was invisible in the platform's liveness view, and — because the
// discovery_agent_offline detector skips rows whose last_heartbeat is NULL — a
// genuinely dead tenant agent raised no alert at all.
func TestHeartbeatLoop_BeatsOnInterval(t *testing.T) {
	sender := &fakeHeartbeatSender{}
	stop := make(chan struct{})
	go runHeartbeatLoop(sender, 5*time.Millisecond, stop)
	defer close(stop)

	waitForBeats(t, sender, 3)
}

// TestHeartbeatLoop_BeatsImmediately — an agent must appear alive as soon as it
// starts, not one interval later.
func TestHeartbeatLoop_BeatsImmediately(t *testing.T) {
	sender := &fakeHeartbeatSender{}
	stop := make(chan struct{})
	go runHeartbeatLoop(sender, time.Hour, stop)
	defer close(stop)

	waitForBeats(t, sender, 1)
}

// TestHeartbeatLoop_SurvivesFailures — a transient network blip must not end
// liveness reporting for the life of the process, which is exactly how an agent
// would drift into a false "offline" state and stay there.
func TestHeartbeatLoop_SurvivesFailures(t *testing.T) {
	sender := &fakeHeartbeatSender{err: errors.New("connection refused")}
	stop := make(chan struct{})
	go runHeartbeatLoop(sender, 5*time.Millisecond, stop)
	defer close(stop)

	waitForBeats(t, sender, 3)
}

// TestHeartbeatLoop_StopHalts — clean shutdown.
func TestHeartbeatLoop_StopHalts(t *testing.T) {
	sender := &fakeHeartbeatSender{}
	stop := make(chan struct{})
	go runHeartbeatLoop(sender, 5*time.Millisecond, stop)

	waitForBeats(t, sender, 2)
	close(stop)
	time.Sleep(30 * time.Millisecond)
	settled := sender.count()
	time.Sleep(50 * time.Millisecond)
	if got := sender.count(); got != settled {
		t.Fatalf("agent sent %d more heartbeat(s) after stop, want 0", got-settled)
	}
}

// TestHeartbeatLoop_NilSenderIsSafe — an unregistered agent has no client;
// starting the loop must not panic.
func TestHeartbeatLoop_NilSenderIsSafe(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		runHeartbeatLoop(nil, time.Millisecond, nil)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runHeartbeatLoop(nil) did not return")
	}
}

// TestHeartbeatInterval_StaysInsideOfflineDwell — the platform's
// discovery_agent_offline detector opens an alert after 15 minutes of silence.
// A default heartbeat interval anywhere near that would make a healthy agent
// flap, so the default must leave room for several consecutive failures.
func TestHeartbeatInterval_StaysInsideOfflineDwell(t *testing.T) {
	const offlineDwell = 15 * time.Minute
	if config.DefaultHeartbeatInterval*3 >= offlineDwell {
		t.Fatalf("default heartbeat interval %v leaves no room for missed beats inside the %v offline dwell",
			config.DefaultHeartbeatInterval, offlineDwell)
	}
}
