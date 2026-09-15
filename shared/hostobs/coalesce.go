package hostobs

import (
	"sync"
	"time"
)

// DefaultCoalesceWindow is how long observations about one subject are
// accumulated before the merged result is emitted. A minute is long enough to
// gather the ARP, the DHCP exchange and the mDNS announcement that a host
// produces when it joins a segment, and short enough that a newly arrived
// device shows up in the inventory while somebody is still looking at it.
const DefaultCoalesceWindow = 60 * time.Second

// DefaultCoalesceCapacity bounds how many subjects are tracked at once. A
// /16 of chatty hosts, a scan, or a forged-MAC flood must not turn the
// coalescer into the sensor's memory leak.
const DefaultCoalesceCapacity = 4096

// Coalescer merges observations about the same subject inside a time window.
//
// Without it the sensor emits a row per ARP frame — thousands a minute on a
// busy segment, all saying the same thing. With it, one host produces one
// observation per window carrying everything every decoder learned about it:
// the MAC from ARP, the hostname from DHCP, the service types from mDNS, the
// vendor from the OUI table.
//
// Safe for concurrent use.
type Coalescer struct {
	window   time.Duration
	capacity int

	// now reads the clock an entry's age is measured against. Injectable for
	// tests only; production is always time.Now.
	now func() time.Time

	mu      sync.Mutex
	pending map[string]*entry
	// dropped counts subjects refused because the map was full. Surfaced on
	// the heartbeat: a coalescer silently discarding half the segment is
	// exactly the "reports success while doing nothing" failure CLAUDE.md
	// warns about.
	dropped int64
}

type entry struct {
	obs *HostObservation
	// opened is when THIS PROCESS started accumulating the subject, read from
	// the same clock [Coalescer.Expired] is given. It is deliberately NOT
	// obs.ObservedAt, which is a CAPTURE timestamp.
	//
	// Mixing the two was a real bug: `Expired` is called with time.Now() on a
	// ticker, and comparing a wall-clock tick against a capture timestamp makes
	// the window's length depend on the difference between two clocks. An NTP
	// step BACKWARDS froze expiry until the wall clock caught up — every
	// subject sat in the map, `host_observations_pending` climbed, and nothing
	// anywhere said why. A capture timestamp running ahead of the host clock
	// (a mirror port whose tap stamps its own time) has the same effect.
	//
	// Reading both ends from time.Now() also means Go's monotonic reading is
	// present on both, so Sub uses the monotonic clock and a step of either
	// direction cannot affect the window at all.
	opened time.Time
}

// NewCoalescer returns a Coalescer with the given window and capacity.
// Non-positive values fall back to the defaults.
func NewCoalescer(window time.Duration, capacity int) *Coalescer {
	if window <= 0 {
		window = DefaultCoalesceWindow
	}
	if capacity <= 0 {
		capacity = DefaultCoalesceCapacity
	}
	return &Coalescer{
		window:   window,
		capacity: capacity,
		pending:  make(map[string]*entry, capacity/4+1),
		now:      time.Now,
	}
}

// Add folds an observation into the pending set. It reports false when the
// observation identified nothing or the coalescer was full; the caller counts
// those.
func (c *Coalescer) Add(obs *HostObservation) bool {
	if obs == nil || !obs.Identifies() {
		return false
	}
	key := obs.Key()

	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.pending[key]; ok {
		Merge(e.obs, obs)
		return true
	}
	if len(c.pending) >= c.capacity {
		c.dropped++
		return false
	}
	c.pending[key] = &entry{obs: obs, opened: c.now()}
	return true
}

// Expired drains and returns every subject whose window has closed as of now.
// The caller emits them.
//
// `now` must come from the same clock the coalescer opens entries with —
// time.Now() — NOT from a capture timestamp. See [entry.opened]: the two are
// different clocks, and comparing across them made the window's length a
// function of the drift between them.
func (c *Coalescer) Expired(now time.Time) []*HostObservation {
	c.mu.Lock()
	defer c.mu.Unlock()

	var out []*HostObservation
	for k, e := range c.pending {
		if now.Sub(e.opened) < c.window {
			continue
		}
		e.obs.Finalize()
		out = append(out, e.obs)
		delete(c.pending, k)
	}
	return out
}

// Drain returns everything pending, regardless of window. Used at shutdown and
// at the end of a pcap file, where there is no later flush to wait for.
func (c *Coalescer) Drain() []*HostObservation {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make([]*HostObservation, 0, len(c.pending))
	for k, e := range c.pending {
		e.obs.Finalize()
		out = append(out, e.obs)
		delete(c.pending, k)
	}
	return out
}

// Pending reports how many subjects are currently accumulating.
func (c *Coalescer) Pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending)
}

// Dropped reports how many subjects were refused because the coalescer was at
// capacity.
func (c *Coalescer) Dropped() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dropped
}

// Merge folds src into dst in place.
//
// The rule is the discovery envelope's rule: EMPTY NEVER WINS. A later
// observation may add a name, an address or a vendor, and may never blank one
// — an ARP frame arriving after a DHCP exchange knows no hostname, and an
// unconditional last-writer-wins merge would erase the one the DHCP told us.
// That exact mistake is why TLS-over-TCP rows reached external_connections
// with a certificate chain and a NULL protocol version.
//
// The one thing that does move is ObservedAt, which advances to the latest
// frame: the subject was seen then, and an inventory's "last seen" must be the
// last time, not the first.
func Merge(dst, src *HostObservation) {
	if dst == nil || src == nil {
		return
	}
	if src.ObservedAt.After(dst.ObservedAt) {
		dst.ObservedAt = src.ObservedAt
	}
	if dst.MAC == "" && src.MAC != "" {
		dst.MAC = src.MAC
		dst.MACLocallyAdministered = src.MACLocallyAdministered
	}
	if dst.Vendor == "" {
		dst.Vendor = src.Vendor
	}
	if dst.Model == "" {
		dst.Model = src.Model
	}
	for _, a := range src.Addresses {
		dst.addAddr(a)
	}
	for _, h := range src.Hostnames {
		dst.addHostname(h)
	}
	for _, fq := range src.FQDNs {
		dst.addFQDN(fq)
	}
	for _, s := range src.Services {
		dst.addService(s)
	}
	for _, s := range src.Sources {
		if !containsString(dst.Sources, s) {
			dst.Sources = append(dst.Sources, s)
		}
	}
	if src.Source != "" && !containsString(dst.Sources, src.Source) {
		dst.Sources = append(dst.Sources, src.Source)
	}
	for k, v := range src.Attributes {
		if v == nil {
			continue
		}
		if _, exists := dst.Attributes[k]; exists {
			// First observation of an attribute wins. A later DHCP REQUEST
			// does not overwrite the OFFER's message type with its own; both
			// are true of different frames, and the attribute map has room
			// for one answer.
			continue
		}
		dst.setAttr(k, v)
	}
}

func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
