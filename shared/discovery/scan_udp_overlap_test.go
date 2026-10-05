package discovery

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"sync"
	"testing"
	"time"
)

// This suite's own loopback address. Its OT test binds the well-known OT UDP
// ports, so per shared/testdb's TestTestFixturesBindTheirOwnLoopbackAddress
// the whole file stays off 127.0.0.1: two suites on one 127.0.0.1:44818 would
// collide under `make test-parallel`. 127.0.0.5 is used by no other suite.
const overlapSuiteAddr = "127.0.0.5"

// blackHole is a loopback UDP socket that answers nothing and counts the
// datagrams that arrive. Loopback only.
type blackHole struct {
	addr string
	mu   sync.Mutex
	n    int
}

func startBlackHole(t *testing.T) *blackHole {
	t.Helper()
	pc, err := net.ListenPacket("udp", net.JoinHostPort(overlapSuiteAddr, "0"))
	if err != nil {
		t.Skipf("cannot listen udp on loopback: %v", err)
	}
	b := &blackHole{addr: pc.LocalAddr().String()}
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			b.mu.Lock()
			b.n++
			b.mu.Unlock()
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	return b
}

// received waits for want datagrams to arrive (they are read by another
// goroutine, shortly after the scan returns) and reports how many did.
func (b *blackHole) received(want int) int {
	deadline := time.Now().Add(2 * time.Second)
	for {
		b.mu.Lock()
		n := b.n
		b.mu.Unlock()
		if n >= want || time.Now().After(deadline) {
			return n
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// sendClockDialer dials every address to target and records the instant each
// datagram is handed to the socket — the scanner's own send, read off the
// monotonic clock in the sending goroutine. Timing the arrivals instead would
// measure the receiving goroutine's scheduling as well.
type sendClockDialer struct {
	target string
	mu     sync.Mutex
	at     []time.Time
}

func (d *sendClockDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	var dl net.Dialer
	conn, err := dl.DialContext(ctx, network, d.target)
	if err != nil {
		return nil, err
	}
	return &sendClockConn{Conn: conn, d: d}, nil
}

func (d *sendClockDialer) sends() []time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := append([]time.Time(nil), d.at...)
	sort.Slice(out, func(i, j int) bool { return out[i].Before(out[j]) })
	return out
}

type sendClockConn struct {
	net.Conn
	d *sendClockDialer
}

func (c *sendClockConn) Write(b []byte) (int, error) {
	c.d.mu.Lock()
	c.d.at = append(c.d.at, time.Now())
	c.d.mu.Unlock()
	return c.Conn.Write(b)
}

// Eight silent custom UDP ports: probed one after another they cost eight
// reply timeouts; with the waits overlapped they cost about one, plus the
// packet-rate spacing — and the spacing still holds for every datagram.
func TestScanUDP_OverlapsReplyWaitsWithinThePacketRate(t *testing.T) {
	hole := startBlackHole(t)
	const rate = 20 // datagrams per second per host: 50ms apart
	const timeout = 400 * time.Millisecond
	dialer := &sendClockDialer{target: hole.addr}
	s, err := NewScanner(WithDialer(dialer), WithPaceProfile(testPace), WithUDPPacketRate(rate))
	if err != nil {
		t.Fatal(err)
	}
	ports := []int{40001, 40002, 40003, 40004, 40005, 40006, 40007, 40008}
	start := time.Now()
	obs, err := s.ScanUDP(context.Background(), netip.MustParseAddr(overlapSuiteAddr), ports, IdentifyOptions{ProbeTimeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)

	if len(obs) != len(ports) {
		t.Fatalf("observations = %d, want %d", len(obs), len(ports))
	}
	for i, o := range obs {
		if o.Port != ports[i] || o.State != "open_or_filtered" {
			t.Errorf("observation %d = %+v, want port %d open_or_filtered, in the order given", i, o, ports[i])
		}
	}
	serial := time.Duration(len(ports)) * timeout
	if elapsed >= serial/2 {
		t.Errorf("8 silent ports took %s; probed one at a time they take %s — the reply waits were not overlapped", elapsed, serial)
	}
	if n := hole.received(len(ports)); n != len(ports) {
		t.Fatalf("datagrams received = %d, want one per port", n)
	}
	sends := dialer.sends()
	if len(sends) != len(ports) {
		t.Fatalf("datagrams sent = %d, want one per port", len(sends))
	}
	// No slack: the scanner starts each interval only after the previous
	// datagram is written, and a timer never fires early, so a loaded machine
	// can only widen these gaps. A shorter one is the scanner breaking the rate.
	interval := time.Second / rate
	for i := 1; i < len(sends); i++ {
		if gap := sends[i].Sub(sends[i-1]); gap < interval {
			t.Errorf("datagrams %d and %d were sent %s apart; the host's rate allows one per %s", i-1, i, gap, interval)
		}
	}
}

// OT/ICS UDP ports under the opt-in are never overlapped: an OT device gets
// one probe at a time. Two silent OT ports therefore take two reply timeouts,
// never one. The OT probers dial the standard ports themselves, so this suite
// binds them on its own loopback address (overlapSuiteAddr).
func TestScanUDP_OTPortsAreNotOverlapped(t *testing.T) {
	for _, port := range []string{"47808", "44818"} {
		pc, err := net.ListenPacket("udp", net.JoinHostPort(overlapSuiteAddr, port))
		if err != nil {
			t.Skipf("cannot bind %s:%s: %v", overlapSuiteAddr, port, err)
		}
		t.Cleanup(func() { _ = pc.Close() })
		go func() {
			buf := make([]byte, 2048)
			for {
				if _, _, err := pc.ReadFrom(buf); err != nil {
					return
				}
			}
		}()
	}
	const timeout = 400 * time.Millisecond
	s, err := NewScanner(WithPaceProfile(testPace), WithUDPPacketRate(1000))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	obs, err := s.ScanUDP(context.Background(), netip.MustParseAddr(overlapSuiteAddr), []int{47808, 44818},
		IdentifyOptions{ProbeTimeout: timeout, OTProbes: []string{"BACnet", "EtherNet_IP"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 2 {
		t.Fatalf("observations = %+v", obs)
	}
	if elapsed := time.Since(start); elapsed < 2*timeout-50*time.Millisecond {
		t.Errorf("two silent OT ports took %s, less than two reply timeouts (%s): they were probed at the same time", elapsed, 2*timeout)
	}
}
