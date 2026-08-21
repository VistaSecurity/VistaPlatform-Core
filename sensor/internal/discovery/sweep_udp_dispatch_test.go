package discovery

import (
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// These tests pin the DISPATCH DECISION in SweepHost, not the probers.
// Exercising probeBACnet in isolation would have passed before B-60 was fixed
// too: the prober always worked, it was simply never called on this path. What
// was broken is that SweepHost reached UDP-registered probers only through the
// ports a TCP connect scan reported open, so a BACnet/IP controller — UDP 47808
// only — was never asked anything while the sweep returned no findings and no
// errors.
//
// Everything below therefore drives SweepHost from the outside with NO TCP
// listener anywhere, and asserts on what came back.

// The planner refuses to invent a port, so the fixture must bind the real
// well-known BACnet/IP port.
const sweepBACnetPort = 47808

// sweepFixtureHost is 127.0.0.2, not 127.0.0.1, on purpose.
//
// services/cluster-sensor-service's UDP-dispatch suite binds 127.0.0.1:47808 for
// the same reason this one needs the port, and `make test-parallel`,
// `make test-race` and `make test-coverage` all run that package concurrently
// with this one. Two suites racing for one loopback socket is a flake by
// construction — and worse, the other suite's probes would reach a listener
// bound here and corrupt its assertions. A distinct loopback address gives each
// suite its own socket and its own datagrams.
const sweepFixtureHost = "127.0.0.2"

// TestSweepHostDispatchesUDPProberWithNoOpenTCPPort is the regression test for
// B-60 on the sensor's sweep path. Nothing listens on TCP; a BACnet device
// answers on UDP 47808. Before the fix this returned zero findings.
func TestSweepHostDispatchesUDPProberWithNoOpenTCPPort(t *testing.T) {
	var datagrams int64
	bindSweepUDP(t, sweepBACnetPort, &datagrams, sweepBACnetIAmReply())

	prober := NewActiveProber(2 * time.Second)
	findings := prober.SweepHost(sweepFixtureHost, []int{sweepBACnetPort}, models.DiscoveryOptions{})

	if got := atomic.LoadInt64(&datagrams); got == 0 {
		t.Fatal("no Who-Is datagram reached the device: the UDP prober was never dispatched (B-60)")
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 — a BACnet device answered and must be recorded", len(findings))
	}

	f := findings[0]
	if f.Protocol != "BACnet" {
		t.Errorf("Protocol = %q, want BACnet", f.Protocol)
	}
	if f.Port != sweepBACnetPort {
		t.Errorf("Port = %d, want %d", f.Port, sweepBACnetPort)
	}
	if f.Target != sweepFixtureHost {
		t.Errorf("Target = %q, want %q", f.Target, sweepFixtureHost)
	}
	if got := f.RawMetadata["bacnet_device_instance"]; got != 1234 {
		t.Errorf("RawMetadata[bacnet_device_instance] = %v, want 1234", got)
	}
	if got := f.RawMetadata["bacnet_probe_transport"]; got != "udp" {
		t.Errorf("RawMetadata[bacnet_probe_transport] = %v, want udp", got)
	}
	if got := f.RawMetadata["bacnet_probe_outcome"]; got != string(shareddisc.ProbeAnswered) {
		t.Errorf("RawMetadata[bacnet_probe_outcome] = %v, want %q", got, shareddisc.ProbeAnswered)
	}
}

// TestSweepHostUnansweredUDPProbeCreatesNoFinding pins the other half: UDP has
// no handshake, so silence is not evidence. A probe nobody answers must not
// manufacture a finding — a sensor finding is mirrored into sensor_discoveries
// and materialises inventory, so a fabricated one becomes a fabricated asset.
func TestSweepHostUnansweredUDPProbeCreatesNoFinding(t *testing.T) {
	var datagrams int64
	bindSweepUDP(t, sweepBACnetPort, &datagrams, nil) // listens, never replies

	prober := NewActiveProber(200 * time.Millisecond)
	findings := prober.SweepHost(sweepFixtureHost, []int{sweepBACnetPort}, models.DiscoveryOptions{})

	if got := atomic.LoadInt64(&datagrams); got == 0 {
		t.Fatal("the probe was never dispatched — this test cannot distinguish silence from a missing probe")
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0 — an unanswered UDP probe is inconclusive, not a device: %+v", len(findings), findings)
	}
}

// TestSweepTCPPortsSkipsUDPRegisteredProtocols pins the gate that was wrong.
// BACnet reached the prober only from the open-TCP-port loop, which is a
// transport it does not speak. Leaving it there once UDP dispatch exists would
// also double every datagram, so the exclusion is load-bearing in both
// directions: a TCP listener on 47808 must draw no Who-Is from this path.
func TestSweepTCPPortsSkipsUDPRegisteredProtocols(t *testing.T) {
	var datagrams int64
	bindSweepUDP(t, sweepBACnetPort, &datagrams, sweepBACnetIAmReply())
	bindSweepTCP(t, sweepBACnetPort)

	prober := NewActiveProber(200 * time.Millisecond)
	findings := prober.sweepTCPPorts(sweepFixtureHost, []int{sweepBACnetPort})

	if got := atomic.LoadInt64(&datagrams); got != 0 {
		t.Errorf("the TCP loop sent %d UDP datagram(s) — a UDP prober must not be dispatched from an open-TCP-port result", got)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %d, want 0 — an open TCP socket on 47808 is not an I-Am", len(findings))
	}
}

// TestUDPProtocolsForPortsDerivesFromTheSweptPorts pins the scope rule on the
// sweep's protocol derivation. A sweep carries no protocol list, so the ports
// are the whole authorisation: a port nobody swept must contribute no protocol
// and no datagram.
func TestUDPProtocolsForPortsDerivesFromTheSweptPorts(t *testing.T) {
	tests := []struct {
		name  string
		ports []int
		want  []string
	}{
		{name: "BACnet's own port", ports: []int{47808}, want: []string{"BACnet"}},
		{name: "EtherNet/IP's own port", ports: []int{44818}, want: []string{"EtherNet_IP"}},
		{name: "IT ports imply no OT datagrams", ports: []int{443, 8443, 22, 445}},
		{name: "TCP-registered OT ports are not planned here", ports: []int{502, 4840}},
		{name: "unknown port contributes nothing", ports: []int{31337}},
		{name: "duplicates collapse to one datagram stream", ports: []int{47808, 47808}, want: []string{"BACnet"}},
		{
			name:  "mixed sweep dispatches only the OT ports that were asked for",
			ports: []int{443, 47808, 502, 44818},
			want:  []string{"BACnet", "EtherNet_IP"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := udpProtocolsForPorts(tt.ports)
			if len(got) != len(tt.want) {
				t.Fatalf("udpProtocolsForPorts(%v) = %v, want %v", tt.ports, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestUnknownPortFallbackIsNotUDPRegistered pins the invariant that lets
// udpProtocolsForPorts be read at a glance.
//
// That derivation uses WellKnownProtocolsForPort, which does NOT fall back,
// rather than ProtocolsForPort, which answers "TLS" for any port the curated map
// has never heard of. Swapping the two is currently indistinguishable — the
// fallback is TLS and TLS has no UDP prober — which means a reviewer cannot tell
// from the tests above that the choice matters, and a future contributor could
// "simplify" it back. The choice matters the moment the fallback names anything
// UDP-registered: an unknown port would then draw OT discovery datagrams that
// nobody asked for.
//
// So pin the assumption directly. If this fails, the `ok` check in
// udpProtocolsForPorts has become load-bearing and must not be removed.
func TestUnknownPortFallbackIsNotUDPRegistered(t *testing.T) {
	const unknownPort = 31337
	if _, wellKnown := shareddisc.WellKnownProtocolsForPort(unknownPort); wellKnown {
		t.Fatalf("port %d is now in the curated map — pick another unknown port", unknownPort)
	}
	for _, protocol := range shareddisc.ProtocolsForPort(unknownPort) {
		if shareddisc.IsUDPProtocol(protocol) {
			t.Errorf("ProtocolsForPort(%d) now falls back to %q, which is UDP-registered: an unknown port would draw OT datagrams if the derivation ever used the falling-back lookup",
				unknownPort, protocol)
		}
	}
}

// TestSweepUDPProbeTimeoutIsBounded pins that a sweep does not inherit the job's
// per-probe timeout for UDP. An absent UDP device cannot fail fast, so at the
// sensor's 30s job timeout every silent host would cost minutes and a /24 sweep
// would run for an hour. The targeted prober keeps the full timeout.
func TestSweepUDPProbeTimeoutIsBounded(t *testing.T) {
	prober := NewActiveProber(30 * time.Second)
	if got := prober.sweepUDPProber.Timeout(); got != sweepMaxUDPProbeTimeout {
		t.Errorf("sweep UDP timeout = %v, want it capped at %v", got, sweepMaxUDPProbeTimeout)
	}
	if got := prober.prober.Timeout(); got != 30*time.Second {
		t.Errorf("targeted prober timeout = %v, want the job's full 30s", got)
	}

	// A shorter job timeout is honoured rather than raised to the cap.
	short := NewActiveProber(200 * time.Millisecond)
	if got := short.sweepUDPProber.Timeout(); got != 200*time.Millisecond {
		t.Errorf("sweep UDP timeout = %v, want the job's shorter 200ms", got)
	}
}

// bindSweepUDP binds a loopback UDP socket on the given port, counting datagrams
// and optionally replying with a canned response. Failure to bind is fatal on
// purpose: skipping would leave the dispatch untested and green.
func bindSweepUDP(t *testing.T, port int, counter *int64, reply []byte) {
	t.Helper()
	pc, err := net.ListenPacket("udp", net.JoinHostPort(sweepFixtureHost, strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("bind %s UDP %d: %v (on Linux the whole 127.0.0.0/8 is local; on macOS run `sudo ifconfig lo0 alias %s up`)",
			sweepFixtureHost, port, err, sweepFixtureHost)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			_, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			atomic.AddInt64(counter, 1)
			if reply == nil {
				continue
			}
			if _, err := pc.WriteTo(reply, from); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = pc.Close(); wg.Wait() })
}

// bindSweepTCP binds a loopback TCP listener so ScanOpenPorts reports the port
// open — the condition the old gate required and the new one must ignore.
func bindSweepTCP(t *testing.T, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(sweepFixtureHost, strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("bind %s TCP %d: %v", sweepFixtureHost, port, err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
}

// sweepBACnetIAmReply is a well-formed BACnet/IP I-Am for device instance 1234
// (object type 8 = device), per ASHRAE 135 §B.4 — the reply a real controller
// sends to a Who-Is.
func sweepBACnetIAmReply() []byte {
	msg := []byte{
		0x81, 0x0A, 0x00, 0x00, // BVLC: BACnet/IP, Original-Unicast-NPDU, length patched below
		0x01, 0x00, // NPDU version, control
		0x10, 0x00, // APDU: Unconfirmed Request, service choice I-Am
		0xC4, 0x02, 0x00, 0x04, 0xD2, // Object identifier: (8 << 22) | 1234
		0x22, 0x01, 0xE0, // Max APDU length accepted
		0x91, 0x00, // Segmentation supported
		0x21, 0x63, // Vendor identifier
	}
	msg[2] = byte(len(msg) >> 8)
	msg[3] = byte(len(msg))
	return msg
}
