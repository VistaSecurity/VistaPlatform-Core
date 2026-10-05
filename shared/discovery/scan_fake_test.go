package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// fakeBehavior is what the fake network does with one connect.
type fakeBehavior int

const (
	behOpen        fakeBehavior = iota // accept
	behRefused                         // RST: ECONNREFUSED
	behReset                           // ECONNRESET during connect
	behFiltered                        // silence: block until the dial context ends
	behUnreachable                     // EHOSTUNREACH
	behEMFILE                          // local: out of descriptors
)

// fakeDialer is a network that exists only in memory. It records every
// address dialled and measures concurrency: a connect is "in flight" from
// DialContext entry until it fails or, if accepted, until the engine closes
// the connection — which is exactly what a fragile device experiences.
type fakeDialer struct {
	behave  func(ap netip.AddrPort) fakeBehavior
	latency time.Duration // before an open/refused answer

	// latencyFn, when set, overrides latency per address:port, so a test can
	// make one port answer faster than the rest (e.g. an OT trigger landing
	// before the regular-port burst has cycled).
	latencyFn func(ap netip.AddrPort) time.Duration

	mu          sync.Mutex
	dials       []netip.AddrPort
	dialAt      map[netip.AddrPort]time.Time
	closedAt    map[netip.AddrPort]time.Time
	host        map[netip.Addr]int
	peakHost    map[netip.Addr]int
	ot          map[netip.Addr]int
	peakOT      map[netip.Addr]int
	global      int
	peakGlobal  int
	unclosed    int
	writes      int
	badAddrs    []string
	cancelled   atomic.Bool // set by a test just before it cancels
	afterCancel atomic.Int64
	debug       []string
}

func newFakeDialer(behave func(ap netip.AddrPort) fakeBehavior) *fakeDialer {
	return &fakeDialer{
		behave:   behave,
		dialAt:   map[netip.AddrPort]time.Time{},
		closedAt: map[netip.AddrPort]time.Time{},
		host:     map[netip.Addr]int{},
		peakHost: map[netip.Addr]int{},
		ot:       map[netip.Addr]int{},
		peakOT:   map[netip.Addr]int{},
	}
}

func allBehave(b fakeBehavior) func(netip.AddrPort) fakeBehavior {
	return func(netip.AddrPort) fakeBehavior { return b }
}

func (d *fakeDialer) enter(ap netip.AddrPort) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dials = append(d.dials, ap)
	d.dialAt[ap] = time.Now()
	a := ap.Addr()
	d.global++
	d.peakGlobal = max(d.peakGlobal, d.global)
	d.host[a]++
	d.peakHost[a] = max(d.peakHost[a], d.host[a])
	if OTPorts().Contains(int(ap.Port())) {
		d.ot[a]++
		d.peakOT[a] = max(d.peakOT[a], d.ot[a])
	}
}

func (d *fakeDialer) leave(ap netip.AddrPort) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closedAt[ap] = time.Now()
	a := ap.Addr()
	d.global--
	d.host[a]--
	if OTPorts().Contains(int(ap.Port())) {
		d.ot[a]--
	}
}

func (d *fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(address)
	if network != "tcp" || err != nil {
		d.mu.Lock()
		d.badAddrs = append(d.badAddrs, network+" "+address)
		d.mu.Unlock()
		return nil, errors.New("fake: not a literal tcp address")
	}
	if d.cancelled.Load() {
		d.afterCancel.Add(1)
		d.mu.Lock()
		d.debug = append(d.debug, fmt.Sprintf("%s ctxErr=%v global=%d peak=%d", address, ctx.Err() != nil, d.global, d.peakGlobal))
		d.mu.Unlock()
	}
	d.enter(ap)
	b := d.behave(ap)
	lat := d.latency
	if d.latencyFn != nil {
		lat = d.latencyFn(ap)
	}
	if b != behFiltered && lat > 0 {
		select {
		case <-time.After(lat):
		case <-ctx.Done():
			d.leave(ap)
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: ctx.Err()}
		}
	}
	switch b {
	case behOpen:
		d.mu.Lock()
		d.unclosed++
		d.mu.Unlock()
		return &fakeConn{d: d, ap: ap}, nil
	case behRefused:
		d.leave(ap)
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	case behReset:
		d.leave(ap)
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNRESET)}
	case behUnreachable:
		d.leave(ap)
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)}
	case behEMFILE:
		d.leave(ap)
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("socket", syscall.EMFILE)}
	default: // filtered
		<-ctx.Done()
		d.leave(ap)
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: ctx.Err()}
	}
}

func (d *fakeDialer) dialled() []netip.AddrPort {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]netip.AddrPort(nil), d.dials...)
}

func (d *fakeDialer) dialCount(match func(netip.AddrPort) bool) int {
	n := 0
	for _, ap := range d.dialled() {
		if match(ap) {
			n++
		}
	}
	return n
}

type fakeConn struct {
	d      *fakeDialer
	ap     netip.AddrPort
	closed atomic.Bool
}

func (c *fakeConn) Read([]byte) (int, error) { return 0, errors.New("fake: engine must not read") }
func (c *fakeConn) Write([]byte) (int, error) {
	c.d.mu.Lock()
	c.d.writes++
	c.d.mu.Unlock()
	return 0, errors.New("fake: engine must not write")
}
func (c *fakeConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.d.mu.Lock()
		c.d.unclosed--
		c.d.mu.Unlock()
		c.d.leave(c.ap)
	}
	return nil
}
func (c *fakeConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *fakeConn) RemoteAddr() net.Addr             { return net.TCPAddrFromAddrPort(c.ap) }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

// testPace is quick enough for unit tests and keeps filtered ports cheap.
var testPace = PaceProfile{GlobalConcurrency: 256, PerHostConcurrency: 64, ConnectTimeout: 50 * time.Millisecond}

func newTestScanner(t testing.TB, d Dialer, opts ...Option) *Scanner {
	t.Helper()
	base := []Option{WithDialer(d), WithPaceProfile(testPace), WithOTSpacing(time.Millisecond)}
	s, err := NewScanner(append(base, opts...)...)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	return s
}

// withConnSlotsForFDLimit gives a Scanner a private connection gate sized as
// the process gate would be for the given descriptor limit.
func withConnSlotsForFDLimit(limit uint64) Option {
	return func(s *Scanner) error {
		s.gate = newConnGate(connSlotsForFDLimit(limit, true))
		return nil
	}
}

func mustAddr(t testing.TB, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func portRange(t testing.TB, lo, hi int) PortSet {
	t.Helper()
	var b portBits
	b.setRange(lo, hi)
	return b.portSet()
}

// waitGoroutines fails the test if the goroutine count does not return to
// the baseline: the engine must not leave anything running after it returns.
func waitGoroutines(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		n := runtime.NumGoroutine()
		if n <= baseline {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			buf = buf[:runtime.Stack(buf, true)]
			t.Fatalf("goroutines leaked: %d running, baseline %d\n%s", n, baseline, buf)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func checkInvariant(t *testing.T, h HostScan) {
	t.Helper()
	sum := h.OpenCount + h.Closed + h.Filtered + h.LocalErrors + h.NotProbed
	if sum != h.PortsRequested {
		t.Errorf("%s: open %d + closed %d + filtered %d + local %d + not probed %d = %d, want requested %d",
			h.Addr, h.OpenCount, h.Closed, h.Filtered, h.LocalErrors, h.NotProbed, sum, h.PortsRequested)
	}
}
