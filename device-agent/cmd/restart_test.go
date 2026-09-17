package main

import (
	"sync"
	"testing"
	"time"
)

// The decision the whole design rests on. Getting it wrong means an agent that
// restarts on every heartbeat, forever, across a whole fleet.
func TestRestartOnlyWhenThisProcessPredatesTheRequest(t *testing.T) {
	t.Run("a request younger than this process is ignored", func(t *testing.T) {
		stopped := false
		// Started 10 seconds ago; the request was made 1 hour ago, so this
		// process began AFTER it and is already what was asked for.
		r := newRestartCoordinator(time.Now().Add(-10*time.Second), func() { stopped = true })
		r.onRequest(time.Hour)
		if stopped {
			t.Error("restarted on a request this process already satisfies — this is the restart loop")
		}
	})

	t.Run("no request at all is ignored", func(t *testing.T) {
		stopped := false
		r := newRestartCoordinator(time.Now().Add(-time.Hour), func() { stopped = true })
		r.onRequest(0)
		if stopped {
			t.Error("restarted with no request")
		}
	})

	t.Run("a process older than the request restarts", func(t *testing.T) {
		stopped := false
		r := newRestartCoordinator(time.Now().Add(-time.Hour), func() { stopped = true })
		r.onRequest(time.Minute)
		if !stopped {
			t.Error("a process running since before the request was ignored")
		}
	})
}

// The platform keeps sending the request until the process is gone, so several
// heartbeats can carry it before the exit completes. Stopping twice would log
// twice and race the shutdown.
func TestRestartHappensOnce(t *testing.T) {
	var mu sync.Mutex
	stops := 0
	r := newRestartCoordinator(time.Now().Add(-time.Hour), func() {
		mu.Lock()
		stops++
		mu.Unlock()
	})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.onRequest(time.Minute)
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if stops != 1 {
		t.Errorf("stopped %d times, want exactly 1", stops)
	}
}

// After restarting, the replacement process must not honour the same request.
// This is the property that lets the design skip acknowledgements entirely —
// and, because it is expressed in durations, it holds however wrong the host's
// clock is.
func TestARestartedAgentDoesNotRestartAgain(t *testing.T) {
	stoppedOld := false
	old := newRestartCoordinator(time.Now().Add(-time.Hour), func() { stoppedOld = true })
	old.onRequest(30 * time.Minute)
	if !stoppedOld {
		t.Fatal("the process running at the time of the request must restart")
	}

	// The replacement has just started. The request keeps arriving and ageing;
	// the replacement's uptime grows at the same rate and stays behind it.
	fresh := newRestartCoordinator(time.Now(), func() {
		t.Error("the restarted process honoured the same request again — an unbounded restart loop")
	})
	for i := 1; i <= 5; i++ {
		fresh.onRequest(30*time.Minute + time.Duration(i)*time.Minute)
	}
}
