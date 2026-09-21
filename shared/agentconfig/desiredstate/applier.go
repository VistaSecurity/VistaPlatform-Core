// Package desiredstate applies the configuration the control plane hands a
// device, and reports back what actually took effect.
//
// Used by BOTH shipped binaries — the discovery agent and the sensor. It lives
// in shared/ rather than in one of them because the alternative was a second
// copy: the convergence rules (report evidence not echoes, retry a failure,
// never re-apply a clean revision, refuse a value of the wrong type) are the
// same rules on both, and the sensor and agent halves of this product have
// drifted apart before by being written twice.
//
// The control plane is authoritative (feature): a device's config file
// supplies what it needs to REGISTER — the platform URL and the registration
// key — and everything after that is desired state fetched on every heartbeat.
// A local edit to a managed setting is therefore overwritten at the next beat,
// which is the point: one place to look, and drift heals itself.
//
// Constraints, because both importers are cross-compiled binaries that ship to
// customer hosts: pure Go, no CGO, no database, no platform runtime. The
// setting names come from shared/agentconfig so a binary and the platform
// cannot disagree about what a setting is called or what type it holds.
package desiredstate

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
)

// Setter applies one setting to the running device. It returns an error the
// platform will display verbatim against that setting, so the message is
// written for an operator, not for a log.
//
// A setter that has RECORDED a value it cannot bring into force until the
// process restarts returns [ErrNeedsRestart]. That is a third outcome, not a
// failure: the sensor's capture filter is fixed when the interface handle
// opens, so switching a decoder on mid-run would leave it running and
// receiving nothing. Reporting it as applied would claim a change that is not
// in force; reporting it as failed would send an operator looking for a problem
// that does not exist.
type Setter func(agentconfig.Value) error

// ErrNeedsRestart is returned by a setter that recorded the value but cannot
// apply it until the process restarts. Wrap it with %w to add detail.
var ErrNeedsRestart = errors.New("takes effect on restart")

// Applier holds the agent's view of its desired state.
//
// It records the revision it has SUCCESSFULLY applied, never the one it was
// handed. Reporting the handed revision would tell the platform the agent had
// converged the instant it was told to — the report has to be evidence, not an
// echo.
type Applier struct {
	mu sync.Mutex

	setters map[agentconfig.Key]Setter

	applied        string
	local          agentconfig.Values
	current        agentconfig.Values
	failures       map[agentconfig.Key]string
	pendingRestart []agentconfig.Key
}

func New() *Applier {
	return &Applier{
		setters:  make(map[agentconfig.Key]Setter),
		local:    make(agentconfig.Values),
		current:  make(agentconfig.Values),
		failures: make(map[agentconfig.Key]string),
	}
}

// SetLocal records what this agent is running from its OWN configuration file,
// before the platform has said anything.
//
// Reported on every beat, and load-bearing on the FIRST one: a platform that
// has never been told anything about this device would otherwise resolve its
// settings to built-in defaults and hand them back — switching off, one minute
// after startup, whatever the file had turned on. The platform adopts these as
// the device's starting position instead, so the first answer describes what
// the agent is already doing.
func (a *Applier) SetLocal(v agentconfig.Values) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.local = v.Clone()
}

// Handle registers the function that applies one setting.
//
// A setting with no handler is not silently ignored: Apply records it as a
// failure naming the setting, so a platform that offers a knob this build does
// not implement says so instead of showing it as applied. That is the same
// honesty the version display owes — an agent is allowed to be older than the
// console, but not to pretend otherwise.
func (a *Applier) Handle(k agentconfig.Key, s Setter) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.setters[k] = s
}

// Apply takes the values the platform sent and makes them true, as far as it
// can.
//
// Every setting is attempted even when an earlier one fails: a fleet-wide
// change that trips over one unsupported setting must still deliver the rest,
// and the operator gets a per-setting reason for what did not land.
func (a *Applier) Apply(revision string, values agentconfig.Values) {
	if revision == "" {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if revision == a.applied && len(a.failures) == 0 {
		// Already converged, including the pending-restart case: what changes
		// that is a restart, not another apply. Re-applying every minute would
		// restart timers for no reason and turn a steady state into churn.
		//
		// Note the scope: this skips only when NOTHING is failing. With any
		// setting in failure, every setter runs again — including one that is
		// pending restart, which is why such a setter has to be an idempotent
		// recorder rather than something that toggles state.
		return
	}

	failures := make(map[agentconfig.Key]string)
	var pendingRestart []agentconfig.Key
	applied := make(agentconfig.Values, len(values))

	for _, k := range values.Keys() {
		v := values[k]
		setter, ok := a.setters[k]
		if !ok {
			failures[k] = fmt.Sprintf("this agent (%s) does not support %s", currentAgentVersion(), k)
			continue
		}
		err := setter(v)
		switch {
		case errors.Is(err, ErrNeedsRestart):
			// Recorded, not in force. Counts as applied for the revision — the
			// device HAS adopted the desired state as far as it can — and is
			// reported separately so the platform can say "awaiting restart"
			// rather than "applied" or "failed".
			pendingRestart = append(pendingRestart, k)
			applied[k] = v
		case err != nil:
			failures[k] = err.Error()
		default:
			applied[k] = v
		}
	}

	a.current = applied
	a.failures = failures
	a.pendingRestart = pendingRestart
	a.applied = revision

	switch {
	case len(failures) == 0:
		log.Printf("⚙️  Applied configuration revision %s (%d settings)", short(revision), len(applied))
	default:
		log.Printf("⚙️  Applied configuration revision %s with %d failure(s): %v", short(revision), len(failures), failures)
	}
}

// Report is what rides the next heartbeat.
//
// The revision is the one that was applied. When a setting failed, the revision
// is still reported — the platform pairs it with the failures and renders
// "failed", which is more useful than silence and lets the operator see WHICH
// setting is the problem rather than watching a device sit at "pending" forever.
func (a *Applier) Report() (revision string, failures map[string]string, pendingRestart []string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.failures) > 0 {
		failures = make(map[string]string, len(a.failures))
		for k, v := range a.failures {
			failures[string(k)] = v
		}
	}
	for _, k := range a.pendingRestart {
		pendingRestart = append(pendingRestart, string(k))
	}
	return a.applied, failures, pendingRestart
}

// Running is what this agent is actually running: its own file configuration,
// overlaid with everything the platform has successfully applied.
//
// The overlay matters in the failure case. A setting the platform pushed and
// the device could NOT apply is absent from `current`, so the file value shows
// through — which is the truth, and is what a device is supposed to report.
// Echoing the pushed value instead would be the same lie as reporting a
// revision that was handed over rather than adopted.
//
// Pending values have not taken effect: retain their startup values until
// the capture is rebuilt or the process restarts.
func (a *Applier) Running() agentconfig.Values {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.local.Clone()
	pending := make(map[agentconfig.Key]bool, len(a.pendingRestart))
	for _, k := range a.pendingRestart {
		pending[k] = true
	}
	for k, v := range a.current {
		if !pending[k] {
			out[k] = v
		}
	}
	return out
}

// Current returns the settings in force, for logging and tests.
func (a *Applier) Current() agentconfig.Values {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.current.Clone()
}

// agentVersion is stamped by the binary at startup so an unsupported-setting
// message can name the version an operator has to upgrade FROM. "agent" here
// means either binary — the sensor stamps it too.
//
// Guarded: it is written once before Start in practice, but it is read from the
// heartbeat goroutine, and "safe as currently called" is not a property that
// survives somebody adding a second caller.
var (
	versionMu    sync.RWMutex
	agentVersion = "unknown"
)

// SetAgentVersion records the running version for failure messages.
func SetAgentVersion(v string) {
	if v == "" {
		return
	}
	versionMu.Lock()
	defer versionMu.Unlock()
	agentVersion = v
}

func currentAgentVersion() string {
	versionMu.RLock()
	defer versionMu.RUnlock()
	return agentVersion
}

func short(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}

// BoolSetter adapts a func(bool) into a Setter, refusing a value of the wrong
// type rather than coercing it. A coerced value is a setting the operator did
// not choose.
func BoolSetter(f func(bool) error) Setter {
	return func(v agentconfig.Value) error {
		if v.B == nil {
			return fmt.Errorf("expected true or false, got %q", v.String())
		}
		return f(*v.B)
	}
}

// DurationSetter adapts a func(time.Duration) for a setting stored in seconds.
//
// The registry's own bounds are enforced HERE, on the agent, not only at the
// platform that sent the value. The platform validates before storing, but an
// older platform, a partially-rolled-back one, or a hand-made request would
// otherwise be able to push a one-second poll interval onto every host in a
// fleet. A device is entitled to refuse an instruction that would harm the host
// it runs on, and to say why.
func DurationSetter(key agentconfig.Key, f func(time.Duration) error) Setter {
	return func(v agentconfig.Value) error {
		if v.I == nil {
			return fmt.Errorf("expected a whole number of seconds, got %q", v.String())
		}
		if *v.I <= 0 {
			return fmt.Errorf("%d seconds is not a usable interval", *v.I)
		}
		if field, ok := agentconfig.Registry[key]; ok {
			switch {
			case field.Floor > 0 && *v.I < field.Floor:
				// A floor is raised, not refused — the same rule the platform
				// applies, so both ends agree on what a too-small value means.
				return f(time.Duration(field.Floor) * time.Second)
			case field.Floor == 0 && field.Min > 0 && *v.I < field.Min:
				return fmt.Errorf("%ds is below the %ds minimum for %s", *v.I, field.Min, key)
			case field.Max > 0 && *v.I > field.Max:
				return fmt.Errorf("%ds is above the %ds maximum for %s", *v.I, field.Max, key)
			}
		}
		return f(time.Duration(*v.I) * time.Second)
	}
}

// TextSetter adapts a func(string).
func TextSetter(f func(string) error) Setter {
	return func(v agentconfig.Value) error {
		if v.S == nil {
			return fmt.Errorf("expected a string, got %q", v.String())
		}
		return f(*v.S)
	}
}
