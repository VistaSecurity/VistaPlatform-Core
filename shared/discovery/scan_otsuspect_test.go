package discovery

import (
	"context"
	"net/netip"
	"sort"
	"testing"
	"time"
)

// peakConcurrencySkippingFirst returns the maximum number of connections to
// addr (for ports matched by include) that were simultaneously in flight,
// ignoring the first skip such connects in start order. A connect is in flight
// from its dialAt until its closedAt.
//
// Skipping the first skip connects by start order drops the initial burst that
// was already in flight when the host became OT-suspect — the connections the
// spec explicitly lets finish — and measures the steady state that follows.
// Crucially it does NOT depend on wall-clock timing: with the throttle removed
// the host runs at full concurrency for its whole scan, so the connects after
// the burst are still at full concurrency and the peak stays high.
func (d *fakeDialer) peakConcurrencySkippingFirst(addr netip.Addr, include func(uint16) bool, skip int) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	type span struct{ start, end time.Time }
	var spans []span
	far := time.Now().Add(time.Hour)
	for _, ap := range d.dials {
		if ap.Addr() != addr || !include(ap.Port()) {
			continue
		}
		start := d.dialAt[ap]
		end, ok := d.closedAt[ap]
		if !ok || !end.After(start) {
			end = far
		}
		spans = append(spans, span{start, end})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start.Before(spans[j].start) })
	if skip >= len(spans) {
		return 0
	}
	spans = spans[skip:]
	type ev struct {
		t     time.Time
		delta int
	}
	var evs []ev
	for _, s := range spans {
		evs = append(evs, ev{s.start, +1}, ev{s.end, -1})
	}
	sort.Slice(evs, func(i, j int) bool {
		if evs[i].t.Equal(evs[j].t) {
			return evs[i].delta < evs[j].delta // close before open at a tie
		}
		return evs[i].t.Before(evs[j].t)
	})
	cur, peak := 0, 0
	for _, e := range evs {
		cur += e.delta
		if cur > peak {
			peak = cur
		}
	}
	return peak
}

// TestScan_OTSuspectThrottlesRegularPortsAfterTrigger drives a host whose one
// open OT port makes it OT-suspect, then proves its regular-port concurrency
// drops to the configured value for every connect started after the trigger —
// while a non-OT host scanned in the same call keeps full concurrency.
func TestScan_OTSuspectThrottlesRegularPortsAfterTrigger(t *testing.T) {
	const suspectConc = 2
	otHost := mustAddr(t, "10.9.0.1")
	plainHost := mustAddr(t, "10.9.0.2")

	// Regular ports answer open quickly (so workers keep cycling through the
	// feed, giving the throttle something to limit). OT ports answer open only
	// on the OT host — on the plain host they are refused, so it never becomes
	// suspect. latency makes connections overlap so concurrency is measurable.
	d := newFakeDialer(func(ap netip.AddrPort) fakeBehavior {
		if OTPorts().Contains(int(ap.Port())) && ap.Addr() != otHost {
			return behRefused
		}
		return behOpen
	})
	// The OT port answers instantly, every regular port after a delay: the
	// trigger therefore lands while the first regular burst is still in flight
	// (not yet cycled), so skipping that burst leaves only throttled connects.
	d.latencyFn = func(ap netip.AddrPort) time.Duration {
		if OTPorts().Contains(int(ap.Port())) {
			return 0
		}
		return 20 * time.Millisecond
	}

	s := newTestScanner(t, d, WithAssumeUp(), WithOTSuspectConcurrency(suspectConc), WithOTSpacing(time.Millisecond))
	// One OT port + many regular ports, so plenty are dialled after the trigger.
	ports := OTPorts().Union(portRange(t, 1, 400))
	res, err := s.Scan(context.Background(), []netip.Addr{otHost, plainHost}, ports)
	if err != nil {
		t.Fatal(err)
	}
	if d.writes != 0 {
		t.Errorf("engine wrote %d times; the scan must never send a payload", d.writes)
	}

	var otScan, plainScan HostScan
	for _, h := range res.Hosts {
		switch h.Addr {
		case otHost:
			otScan = h
		case plainHost:
			plainScan = h
		}
		checkInvariant(t, h)
	}

	if !otScan.OTSuspect || otScan.OTSuspectPort == 0 {
		t.Fatalf("OT host: OTSuspect=%v OTSuspectPort=%d, want suspect with a trigger port", otScan.OTSuspect, otScan.OTSuspectPort)
	}
	if !OTPorts().Contains(otScan.OTSuspectPort) {
		t.Errorf("OT host: trigger port %d is not an OT port", otScan.OTSuspectPort)
	}
	if plainScan.OTSuspect {
		t.Errorf("plain host wrongly marked OT-suspect (trigger port %d)", plainScan.OTSuspectPort)
	}

	// Drop the initial per-host burst that was in flight when the host turned
	// OT-suspect (those connects are allowed to finish), then confirm every
	// connect that followed was throttled to the configured ceiling.
	regular := func(p uint16) bool { return !OTPorts().Contains(int(p)) }
	if peak := d.peakConcurrencySkippingFirst(otHost, regular, testPace.PerHostConcurrency); peak > suspectConc {
		t.Errorf("OT-suspect host: peak regular concurrency after the trigger burst = %d, want <= %d", peak, suspectConc)
	}

	// Polarity: the plain host, with no OT port open, was scanned with real
	// parallelism — otherwise the test above cannot tell a throttle from a
	// scan that was never concurrent in the first place.
	if peak := d.peakConcurrencySkippingFirst(plainHost, regular, 0); peak <= suspectConc {
		t.Errorf("plain host: peak regular concurrency = %d, want > %d (throttle must not apply)", peak, suspectConc)
	}
}

// TestScan_OTSuspectDoesNotAddConnections pins the one-way guarantee: an
// OT-suspect concurrency at or above the pace's per-host limit is a no-op, not
// a way to raise concurrency.
func TestScan_OTSuspectConcurrencyNeverExceedsPerHost(t *testing.T) {
	d := newFakeDialer(allBehave(behOpen))
	d.latency = time.Millisecond
	// suspectConc far above the test pace's PerHostConcurrency (64).
	s := newTestScanner(t, d, WithAssumeUp(), WithOTSuspectConcurrency(maxOTSuspectConcurrency), WithOTSpacing(0))
	host := mustAddr(t, "10.9.1.1")
	ports := OTPorts().Union(portRange(t, 1, 300))
	if _, err := s.Scan(context.Background(), []netip.Addr{host}, ports); err != nil {
		t.Fatal(err)
	}
	regular := func(p uint16) bool { return !OTPorts().Contains(int(p)) }
	if peak := d.peakConcurrencySkippingFirst(host, regular, 0); peak > testPace.PerHostConcurrency {
		t.Errorf("peak regular concurrency = %d, want <= per-host limit %d", peak, testPace.PerHostConcurrency)
	}
}

func TestWithOTSuspectConcurrency_Validation(t *testing.T) {
	for _, n := range []int{0, -1, maxOTSuspectConcurrency + 1} {
		if _, err := NewScanner(WithOTSuspectConcurrency(n)); err == nil {
			t.Errorf("WithOTSuspectConcurrency(%d) accepted, want error", n)
		}
	}
	if _, err := NewScanner(WithOTSuspectConcurrency(1)); err != nil {
		t.Errorf("WithOTSuspectConcurrency(1): %v", err)
	}
}
