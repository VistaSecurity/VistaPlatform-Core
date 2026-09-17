package main

// Runtime plumbing for control-plane-managed settings.
//
// The settings the platform can change are the ones with a live effect here:
// whether the local host inventory runs and how often, how often the agent
// polls and beats, and how much it logs. Each is behind a small supervisor so a
// change takes effect on the next beat rather than at the next restart — an
// operator who has to restart an agent to change an interval has not really
// been given control of it.

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig/desiredstate"
)

// setVerboseLogging switches the agent's log verbosity at runtime.
//
// The same two states the -verbose flag and the `verbose:` config key already
// select, so a pushed log level and a local flag mean exactly one thing rather
// than two overlapping ones.
func setVerboseLogging(on bool) {
	if on {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
		log.Println("Verbose logging enabled by the control plane")
		return
	}
	log.SetFlags(log.LstdFlags)
	log.Println("Verbose logging disabled by the control plane")
}

// interval is a duration that loops re-read on every tick.
//
// The loops used to hold a time.Ticker built from the value at startup, which
// made the interval unchangeable for the life of the process. Reading it per
// tick is what makes "the control plane is authoritative" true for these
// settings rather than aspirational.
type interval struct {
	mu      sync.Mutex
	d       time.Duration
	changed chan struct{}
}

func newInterval(d time.Duration) *interval {
	return &interval{d: d, changed: make(chan struct{}, 1)}
}

func (i *interval) get() time.Duration {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.d
}

// set changes the cadence and WAKES a loop that is already waiting.
//
// Re-reading the value at the top of each cycle is not enough on its own: a
// loop that is 20 minutes into a 24-hour wait would not notice a change to six
// hours until the original day had passed. Shortening an interval is the common
// case — somebody wants results sooner — so it has to interrupt the wait it is
// shortening, or "the control plane is authoritative" quietly means "eventually,
// maybe tomorrow".
func (i *interval) set(d time.Duration) {
	i.mu.Lock()
	unchanged := i.d == d
	i.d = d
	i.mu.Unlock()
	if unchanged {
		return
	}
	select {
	case i.changed <- struct{}{}:
	default:
		// A wake is already pending; one is enough.
	}
}

// waitCycle waits one cycle of iv, returning false if stop closed first.
//
// It is the ONE place a managed cadence is waited on. Every loop that honours a
// pushed interval must go through it — a loop with its own timer silently opts
// out of remote management, which is how the host-inventory loop came to ignore
// the very setting this feature exists to change. `shape` lets a caller adjust
// the computed duration (host inventory adds jitter); it is applied to the
// interval, never to the elapsed time, so it cannot push a wait under the
// floor.
//
// On a change the ELAPSED time counts: an interval shortened to less than the
// time already waited fires now rather than waiting the new interval over
// again. Re-waiting would let repeated changes postpone a collection forever.
func waitCycle(iv *interval, stop <-chan struct{}, shape func(time.Duration) time.Duration) bool {
	started := time.Now()
	for {
		d := iv.get()
		if d <= 0 {
			d = time.Minute
		}
		if shape != nil {
			d = shape(d)
		}
		remaining := d - time.Since(started)
		if remaining <= 0 {
			break
		}
		timer := time.NewTimer(remaining)
		select {
		case <-stop:
			timer.Stop()
			return false
		case <-iv.changed:
			// Recompute against the new value, keeping the elapsed time.
			timer.Stop()
			continue
		case <-timer.C:
		}
		break
	}
	select {
	case <-stop:
		return false
	default:
	}
	return true
}

// everyInterval runs fn immediately, then once per cycle of iv.
func everyInterval(iv *interval, stop <-chan struct{}, fn func()) {
	fn()
	for waitCycle(iv, stop, nil) {
		fn()
	}
}

// hostInventorySupervisor starts and stops the local host-inventory loop as the
// platform turns it on and off.
//
// Stopping is a real stop, not a flag the loop checks: an agent told to stop
// describing its host must stop reading the package database, not read it and
// discard the result.
type hostInventorySupervisor struct {
	mu       sync.Mutex
	run      func(iv *interval, stop <-chan struct{})
	iv       *interval
	stop     chan struct{}
	enabled  bool
	interval time.Duration
}

func newHostInventorySupervisor(interval time.Duration, run func(iv *interval, stop <-chan struct{})) *hostInventorySupervisor {
	if interval <= 0 {
		interval = config.DefaultHostInventoryInterval
	}
	return &hostInventorySupervisor{run: run, interval: interval}
}

// setEnabled starts or stops the loop. Turning on an already-running loop, or
// off an already-stopped one, does nothing — the platform re-sends the full
// desired state on every beat, so idempotence here is what keeps a steady state
// steady.
func (s *hostInventorySupervisor) setEnabled(on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if on == s.enabled {
		return nil
	}
	s.enabled = on
	if !on {
		if s.stop != nil {
			close(s.stop)
			s.stop = nil
		}
		log.Printf("🖥️  Host inventory turned off by the control plane")
		return nil
	}
	if s.run == nil {
		return fmt.Errorf("this agent cannot collect host inventory")
	}
	s.iv = newInterval(s.interval)
	s.stop = make(chan struct{})
	log.Printf("🖥️  Host inventory turned on by the control plane, every %v", s.interval)
	go s.run(s.iv, s.stop)
	return nil
}

// isEnabled reports whether the loop is running. Read under the same lock the
// heartbeat goroutine writes it with.
func (s *hostInventorySupervisor) isEnabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enabled
}

// setInterval changes the cadence, taking effect on the next tick of a running
// loop.
func (s *hostInventorySupervisor) setInterval(d time.Duration) error {
	if d < config.MinHostInventoryInterval {
		// The platform raises this before storing, so reaching here means an
		// older platform or a hand-made request. Refusing is better than
		// walking the package database twelve times an hour.
		return fmt.Errorf("%v is below the one-hour minimum", d)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.interval = d
	if s.iv != nil {
		s.iv.set(d)
	}
	return nil
}

// localValues is what this agent's own configuration file says it is running,
// spelled in the registry's keys.
//
// Reported to the platform so a device enrolled before the control plane
// existed establishes its real starting position on its first beat, rather than
// being handed built-in defaults nobody chose. The keys are the SAME strings
// the file uses (see agentconfig.Key), so there is one name per setting rather
// than a translation table that can drift.
//
// A zero duration is omitted rather than reported as 0: the agent is saying
// what it is running, and "0 seconds" is not something it is running.
func localValues(cfg *config.Config) agentconfig.Values {
	if cfg == nil {
		return nil
	}
	v := agentconfig.Values{
		agentconfig.KeyHostInventoryEnabled: agentconfig.Bool(cfg.HostInventoryEnabled),
	}
	for key, d := range map[agentconfig.Key]time.Duration{
		agentconfig.KeyHostInventoryInterval: cfg.HostInventoryInterval,
		agentconfig.KeyPollInterval:          cfg.PollInterval,
		agentconfig.KeyHeartbeatInterval:     cfg.HeartbeatInterval,
	} {
		if d > 0 {
			v[key] = agentconfig.Int(int64(d / time.Second))
		}
	}
	// Only when the file actually says something. The -verbose flag defaults
	// ON for an interactive install, so treating "no setting" as a level would
	// report a verbosity the operator never chose — and, being different from
	// the registry default, it would then be recorded as this device's own.
	if cfg.Verbose != nil {
		level := "info"
		if *cfg.Verbose {
			level = "debug"
		}
		v[agentconfig.KeyLogLevel] = agentconfig.Text(level)
	}
	return v
}

// registerManagedSettings wires every setting this build can apply.
//
// A setting NOT registered here is reported back as unsupported rather than
// silently ignored, so a console offering a knob this binary does not implement
// says so instead of showing it as applied.
func registerManagedSettings(
	applier *desiredstate.Applier,
	hostInventory *hostInventorySupervisor,
	poll, heartbeat *interval,
	setVerbose func(bool),
) {
	applier.Handle(agentconfig.KeyHostInventoryEnabled, desiredstate.BoolSetter(hostInventory.setEnabled))
	applier.Handle(agentconfig.KeyHostInventoryInterval, desiredstate.DurationSetter(agentconfig.KeyHostInventoryInterval, hostInventory.setInterval))

	applier.Handle(agentconfig.KeyPollInterval, desiredstate.DurationSetter(agentconfig.KeyPollInterval, func(d time.Duration) error {
		poll.set(d)
		return nil
	}))
	applier.Handle(agentconfig.KeyHeartbeatInterval, desiredstate.DurationSetter(agentconfig.KeyHeartbeatInterval, func(d time.Duration) error {
		heartbeat.set(d)
		return nil
	}))

	applier.Handle(agentconfig.KeyLogLevel, desiredstate.TextSetter(func(level string) error {
		// The agent has verbose/not-verbose rather than four levels, so the
		// four map onto the two. Mapping is stated here rather than pretended
		// away: an operator who selects "warn" gets quiet logging, and the
		// platform is not told the agent has four levels it does not have.
		switch level {
		case "debug":
			setVerbose(true)
			return nil
		case "info", "warn", "error":
			setVerbose(false)
			return nil
		}
		return fmt.Errorf("unknown log level %q", level)
	}))
}
