package main

// Honouring a restart requested from the control plane.
//
// The platform sends how long ago an operator asked. The agent restarts when it
// has been running for longer than that — idempotent by construction, because
// after restarting its uptime is smaller than the request's age. There is no
// acknowledgement to lose and no queue to drain.
//
// Durations on both sides, never two clocks: an agent whose clock disagrees
// with the platform's would otherwise restart on every heartbeat for ever. See
// agentconfig.ShouldRestart.
//
// "Restart" here means EXIT. Something else starts the agent again: systemd, a
// Windows service, a container runtime. On a host where somebody launched it by
// hand, this stops it, and the console says so before asking.

import (
	"log"
	"os"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
)

// restartCoordinator decides whether a restart request applies to this process.
type restartCoordinator struct {
	startedAt time.Time
	// stop is what actually ends the process. Injected so the decision can be
	// tested without killing the test binary — which is not a hypothetical
	// risk, it is the only way to test this at all.
	stop func()

	once sync.Once
}

func newRestartCoordinator(startedAt time.Time, stop func()) *restartCoordinator {
	return &restartCoordinator{startedAt: startedAt, stop: stop}
}

// onRequest is called on every heartbeat with how long ago the platform says an
// operator asked for a restart.
func (r *restartCoordinator) onRequest(requestAge time.Duration) {
	if !agentconfig.ShouldRestart(time.Since(r.startedAt), requestAge) {
		return
	}
	// Once, even if several heartbeats overlap: the platform keeps sending the
	// request until this process is gone, and a second call while the first is
	// shutting down would log twice and race the exit.
	r.once.Do(func() {
		log.Printf("🔁 Restart requested from the console %s ago — exiting so the service manager can start a new process",
			requestAge.Round(time.Second))
		r.stop()
	})
}

// exitForRestart ends the process with a status a service manager treats as a
// restartable stop.
//
// Zero rather than non-zero. systemd's default Restart=on-failure would NOT
// restart on a zero exit, so the deployment guide specifies Restart=always —
// and with that, zero is the honest code: this is a clean, requested shutdown,
// not a crash, and reporting a failure would put a false error in the host's
// journal every time an operator clicks a button.
func exitForRestart() {
	os.Exit(0)
}
