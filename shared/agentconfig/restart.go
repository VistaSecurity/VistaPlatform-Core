package agentconfig

import "time"

// Restart, as desired state rather than as a command — and compared in
// DURATIONS rather than timestamps.
//
// An operator needs to be able to restart a device from the console: a setting
// marked ApplyOnRestart sits at awaiting_restart until something restarts the
// process, and telling somebody to go and do it by hand is the friction this
// whole feature exists to remove.
//
// The obvious design is a command queue — enqueue "restart", deliver it, track
// an acknowledgement, expire it if undelivered. This is not that. The platform
// records WHEN an operator asked, and tells each device how long ago that was.
// A device restarts when it has been running for longer than the request is
// old.
//
// # Why durations, and not the two timestamps
//
// The first version of this compared the platform's request timestamp against
// the device's own process start time. That is a comparison between two
// different clocks, and it loops forever when they disagree:
//
//	device clock 1h behind the platform's
//	request recorded at  12:00 (platform)
//	process started at   11:05 (device)   -> 12:00 > 11:05, restart
//	new process started  11:06 (device)   -> 12:00 > 11:06, restart again
//	... every heartbeat, on every skewed host in the fleet.
//
// Comparing an age against an uptime removes the offset entirely: each side
// measures an interval on its own clock, and clocks that disagree about the
// time still agree about how long a second is. After a restart the uptime is
// near zero and the request's age is larger, so the device stops — whatever
// either clock reads.
//
// What it is NOT: a way to restart a device that nothing supervises. The agent
// and sensor exit; a service manager starts them again. On a host where one was
// launched by hand, "restart" means "stop", and the console says so before
// asking.
type RestartRequest struct {
	// At is when an operator last asked, on the PLATFORM's clock. Zero means
	// never. It is display material — "requested 5 minutes ago" — and never the
	// basis of the decision.
	At time.Time `json:"restart_requested_at,omitempty"`
}

// Age is how long ago the request was made, measured entirely on the platform's
// clock. Zero when nobody has asked.
func (r RestartRequest) Age(now time.Time) time.Duration {
	if r.At.IsZero() {
		return 0
	}
	age := now.Sub(r.At)
	if age <= 0 {
		// The request reads as being in the FUTURE on our own clock — the
		// platform's clock stepped backwards between recording and reading it.
		//
		// Zero, meaning "do not restart yet", not "just made". A tiny positive
		// age would satisfy ShouldRestart for every running process, which is
		// the fleet-wide restart loop this design exists to prevent, merely
		// relocated from the device's clock to the platform's. The request is
		// not lost: once the clock passes the recorded time the age becomes
		// positive again and the restart happens then.
		return 0
	}
	return age
}

// WireSeconds is the age as it goes on the wire, rounded UP to a whole second.
//
// Rounded up, not truncated, because a request is milliseconds old on the very
// heartbeat that follows it and truncation would send 0 — which a device reads
// as "nobody asked". That is not merely a delay: it made the field indistin-
// guishable from an absent request, and an integration test pass on a payload
// that said nothing had been requested.
//
// Whole seconds because that is ample: the comparison is against a process
// uptime, and no decision here turns on sub-second precision.
func (r RestartRequest) WireSeconds(now time.Time) int64 {
	age := r.Age(now)
	if age <= 0 {
		return 0
	}
	secs := int64(age / time.Second)
	if age%time.Second != 0 {
		secs++
	}
	return secs
}

// ShouldRestart reports whether a device that has been running for uptime must
// restart to honour a request made requestAge ago.
//
// Both arguments are intervals, each measured on the clock of the side that
// produced it. A device is older than the request exactly when it was already
// running when the request was made — which is the question — and no absolute
// time is compared.
//
// Strictly greater, so a device whose uptime exactly equals the request's age
// does not restart: at equality the process started at the instant of the
// request, and it is already running the state that was asked for.
func ShouldRestart(uptime, requestAge time.Duration) bool {
	if requestAge <= 0 {
		return false
	}
	return uptime > requestAge
}
