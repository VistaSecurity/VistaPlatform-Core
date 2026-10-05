package discovery

import (
	"context"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Real-socket tests. Loopback ONLY, on ephemeral ports this test bound itself
// (never a fixed well-known port, which a parallel suite or a local service
// could hold).

// loopbackListeners binds n listeners on host:0. Each accepted connection is
// read until EOF, and any byte received is counted: the engine must close
// without ever sending one.
type loopbackListeners struct {
	ports    []int
	accepted atomic.Int64
	bytes    atomic.Int64
	slowEOF  atomic.Int64
	wg       sync.WaitGroup
	lns      []net.Listener
}

func startLoopbackListeners(t testing.TB, host string, n int) *loopbackListeners {
	t.Helper()
	l := &loopbackListeners{}
	for range n {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
		if err != nil {
			l.close()
			t.Skipf("cannot listen on %s: %v", host, err)
		}
		l.lns = append(l.lns, ln)
		l.ports = append(l.ports, ln.Addr().(*net.TCPAddr).Port)
		l.wg.Go(func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				l.accepted.Add(1)
				l.wg.Go(func() {
					defer func() { _ = c.Close() }()
					_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
					nb, err := io.Copy(io.Discard, c)
					l.bytes.Add(nb)
					if err != nil { // deadline: the scanner did not close promptly
						l.slowEOF.Add(1)
					}
				})
			}
		})
	}
	t.Cleanup(l.close)
	return l
}

func (l *loopbackListeners) close() {
	for _, ln := range l.lns {
		_ = ln.Close()
	}
	l.wg.Wait()
}

// freedPorts returns n ports that were just bound on host and released, so a
// connect to them is refused.
func freedPorts(t testing.TB, host string, n int) []int {
	t.Helper()
	var lns []net.Listener
	var out []int
	for range n {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
		if err != nil {
			for _, l := range lns {
				_ = l.Close()
			}
			t.Skipf("cannot listen on %s: %v", host, err)
		}
		lns = append(lns, ln)
		out = append(out, ln.Addr().(*net.TCPAddr).Port)
	}
	for _, ln := range lns {
		_ = ln.Close()
	}
	return out
}

func TestScanTCP_LoopbackRealSockets(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			ls := startLoopbackListeners(t, host, 5)
			closed := freedPorts(t, host, 5)
			ports, err := NewPortSet(append(slices.Clone(ls.ports), closed...)...)
			if err != nil {
				t.Fatal(err)
			}
			s, err := NewScanner()
			if err != nil {
				t.Fatal(err)
			}
			h, err := s.ScanTCP(context.Background(), netip.MustParseAddr(host), ports)
			if err != nil {
				t.Fatal(err)
			}
			want := slices.Sorted(slices.Values(ls.ports))
			if !slices.Equal(h.Open, want) {
				t.Errorf("open = %v, want %v", h.Open, want)
			}
			if h.Closed != len(closed) || h.Filtered != 0 || h.LocalErrors != 0 {
				t.Errorf("closed=%d filtered=%d local=%d, want %d/0/0", h.Closed, h.Filtered, h.LocalErrors, len(closed))
			}
			checkInvariant(t, h)
			ls.close()
			if ls.accepted.Load() != int64(len(ls.ports)) {
				t.Errorf("listeners accepted %d connections, want %d (one per open port)", ls.accepted.Load(), len(ls.ports))
			}
			if ls.bytes.Load() != 0 || ls.slowEOF.Load() != 0 {
				t.Errorf("listeners received %d bytes and %d connections left open; the engine must close at once and send nothing",
					ls.bytes.Load(), ls.slowEOF.Load())
			}
		})
	}
}

func TestLiveness_LoopbackRealSockets(t *testing.T) {
	ls := startLoopbackListeners(t, "127.0.0.1", 1)
	closed := freedPorts(t, "127.0.0.1", 1)
	addr := netip.MustParseAddr("127.0.0.1")
	for _, c := range []struct {
		name, evidencePrefix string
		port                 int
	}{
		{"accepting port", "tcp-open:", ls.ports[0]},
		{"refusing port", "tcp-refused:", closed[0]},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, err := NewScanner(WithLivenessPorts(mustPorts(strconv.Itoa(c.port))))
			if err != nil {
				t.Fatal(err)
			}
			res, err := s.Liveness(context.Background(), []netip.Addr{addr})
			if err != nil {
				t.Fatal(err)
			}
			if res[0].State != LivenessUp || res[0].Evidence != c.evidencePrefix+strconv.Itoa(c.port) {
				t.Errorf("state=%v evidence=%q, want up %s%d", res[0].State, res[0].Evidence, c.evidencePrefix, c.port)
			}
		})
	}
}
