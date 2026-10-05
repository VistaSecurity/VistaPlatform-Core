package discovery

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Pace names a scan speed profile.
type Pace string

const (
	// PacePolite is for fragile or monitored networks: few connections at
	// once, a long timeout, and a pause between batches.
	PacePolite Pace = "polite"
	// PaceNormal is the default.
	PaceNormal Pace = "normal"
	// PaceFast is for a well-provisioned LAN whose owner wants an answer
	// quickly. Its short timeout can report a slow-to-answer port (a lost SYN
	// on a lossy path) as filtered.
	PaceFast Pace = "fast"
)

// PaceProfile is the concrete concurrency and timing a scan runs with.
//
// The wall-clock cost of a host whose ports are all filtered (nothing answers,
// every connect waits out ConnectTimeout) is about
//
//	ceil(ports / PerHostConcurrency) × (ConnectTimeout + BatchDelay)
//
// so a Thorough (65 535-port) scan of one silent host takes roughly 2.4 h
// polite, 13 min normal and 2 min fast. Ports that answer (open or refused)
// cost a round trip, not a timeout.
type PaceProfile struct {
	// GlobalConcurrency bounds connections in flight across every host of
	// one scan call. It is further capped, process-wide, by the file-
	// descriptor budget (see Limits).
	GlobalConcurrency int
	// PerHostConcurrency bounds connections in flight to any one address.
	PerHostConcurrency int
	// ConnectTimeout is how long one connect may wait before the port is
	// classified filtered.
	ConnectTimeout time.Duration
	// BatchDelay is a pause after every PerHostConcurrency ports handed out
	// for a host; 0 disables it.
	BatchDelay time.Duration
}

var paceProfiles = map[Pace]PaceProfile{
	PacePolite: {GlobalConcurrency: 128, PerHostConcurrency: 16, ConnectTimeout: 2 * time.Second, BatchDelay: 100 * time.Millisecond},
	PaceNormal: {GlobalConcurrency: 512, PerHostConcurrency: 128, ConnectTimeout: 1500 * time.Millisecond},
	PaceFast:   {GlobalConcurrency: 2048, PerHostConcurrency: 512, ConnectTimeout: time.Second},
}

// ParsePace maps a pace name ("polite", "normal", "fast"; case-insensitive)
// to a Pace. The empty string is PaceNormal.
func ParsePace(name string) (Pace, error) {
	n := Pace(strings.ToLower(strings.TrimSpace(name)))
	if n == "" {
		return PaceNormal, nil
	}
	if _, ok := paceProfiles[n]; !ok {
		return "", fmt.Errorf("unknown scan pace %q (want polite, normal or fast)", name)
	}
	return n, nil
}

// Profile returns the profile for a named pace.
func (p Pace) Profile() (PaceProfile, error) {
	prof, ok := paceProfiles[p]
	if !ok {
		return PaceProfile{}, fmt.Errorf("unknown scan pace %q (want polite, normal or fast)", string(p))
	}
	return prof, nil
}

func (p PaceProfile) validate() error {
	switch {
	case p.GlobalConcurrency < 1:
		return fmt.Errorf("global concurrency %d must be at least 1", p.GlobalConcurrency)
	case p.PerHostConcurrency < 1:
		return fmt.Errorf("per-host concurrency %d must be at least 1", p.PerHostConcurrency)
	case p.PerHostConcurrency > p.GlobalConcurrency:
		return fmt.Errorf("per-host concurrency %d exceeds global concurrency %d", p.PerHostConcurrency, p.GlobalConcurrency)
	case p.ConnectTimeout <= 0 || p.ConnectTimeout > 30*time.Second:
		return fmt.Errorf("connect timeout %s must be in (0, 30s]", p.ConnectTimeout)
	case p.BatchDelay < 0 || p.BatchDelay > 10*time.Second:
		return fmt.Errorf("batch delay %s must be in [0, 10s]", p.BatchDelay)
	}
	return nil
}

// File-descriptor budget.
//
// Every in-flight connect holds a socket, i.e. a file descriptor. A Thorough
// scan at the fast pace wants thousands at once, and the process also needs
// descriptors for everything else it does (database pool, NATS, logs, the
// HTTP server). Running out does not fail loudly: dials start returning
// EMFILE, which a naive scanner records as "filtered" — a silent false
// negative — while the rest of the process starts failing too.
//
// So connections are admitted through one PROCESS-WIDE gate sized from the
// descriptor limit, shared by every Scanner and every concurrent scan:
//
//	slots = clamp((RLIMIT_NOFILE soft limit − 256) / 2, 8, 16384)
//
// i.e. keep 256 descriptors for the rest of the process and give the scanner
// at most half of what remains. (Go raises the soft limit to the hard limit
// at start-up on Unix, so this reads the effective limit.) The 16384 ceiling
// applies even to an unlimited descriptor limit, because the next limits —
// the ephemeral port range and conntrack — are of that order. Where there is
// no descriptor rlimit (Windows) the gate is a fixed 1024.
const (
	fdReserve        = 256
	minConnSlots     = 8
	maxConnSlots     = 16384
	nonUnixConnSlots = 1024
)

// connSlotsForFDLimit turns a descriptor limit into a connection budget.
// ok=false means the platform has no such limit.
func connSlotsForFDLimit(limit uint64, ok bool) int {
	if !ok {
		return nonUnixConnSlots
	}
	if limit <= fdReserve+2*minConnSlots {
		return minConnSlots
	}
	slots := (limit - fdReserve) / 2
	if slots > maxConnSlots {
		return maxConnSlots
	}
	return int(slots)
}

// connGate is a counting semaphore over connection slots.
type connGate struct {
	slots chan struct{}
}

func newConnGate(n int) *connGate {
	return &connGate{slots: make(chan struct{}, n)}
}

func (g *connGate) capacity() int { return cap(g.slots) }

var processConnGate = sync.OnceValue(func() *connGate {
	return newConnGate(connSlotsForFDLimit(processFDLimit()))
})

// Limits reports the bounds a Scanner will actually run with.
type Limits struct {
	PaceProfile
	// ConnectionSlots is the process-wide connection budget derived from the
	// file-descriptor limit; it is shared with every other Scanner.
	ConnectionSlots int
	// EffectiveConcurrency is min(GlobalConcurrency, ConnectionSlots): the
	// most connections one scan can have in flight.
	EffectiveConcurrency int
}
