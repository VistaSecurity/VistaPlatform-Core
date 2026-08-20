package services

import (
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// These tests pin the DISPATCH DECISION, not the probers. Exercising probeBACnet
// in isolation would have passed before B-60 was fixed too: the prober always
// worked, it was simply never called. What was broken is that a UDP-registered
// prober was only reachable from the per-open-port loop of a TCP scan, so a
// BACnet/IP controller — UDP 47808 only — was never asked anything while the job
// reported `completed` with zero findings and zero errors.
//
// Everything below therefore drives the scan from the outside, with NO TCP
// listener anywhere, and asserts on what came back.

const (
	// The planner refuses to invent a port, so the fixtures must bind the real
	// well-known ports. Both are unprivileged and unused by anything in CI.
	bacnetPort     = 47808
	ethernetIPPort = 44818
)

// TestScanTargetDispatchesUDPProberWithNoOpenTCPPort is the regression test for
// B-60. Nothing listens on TCP; a BACnet device answers on UDP 47808. Before the
// fix this returned zero findings and zero errors.
func TestScanTargetDispatchesUDPProberWithNoOpenTCPPort(t *testing.T) {
	var datagrams int64
	bindUDP(t, bacnetPort, &datagrams, bacnetIAmReply())

	ps := NewPortScanner()

	findings, err := ps.ScanTarget("127.0.0.1", []int32{bacnetPort}, []string{"BACnet"}, nil, nil)
	if err != nil {
		t.Fatalf("ScanTarget: %v", err)
	}

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
	if f.Port != bacnetPort {
		t.Errorf("Port = %d, want %d", f.Port, bacnetPort)
	}
	if f.ExecutedVia != "udp-probe" {
		t.Errorf("ExecutedVia = %q, want udp-probe", f.ExecutedVia)
	}
	if got := f.Data["bacnet_device_instance"]; got != 1234 {
		t.Errorf("Data[bacnet_device_instance] = %v, want 1234", got)
	}
	if got := f.Data["bacnet_probe_outcome"]; got != string(shareddisc.ProbeAnswered) {
		t.Errorf("Data[bacnet_probe_outcome] = %v, want %q", got, shareddisc.ProbeAnswered)
	}
	if _, inconclusive := f.Data["bacnet_probe_inconclusive"]; inconclusive {
		t.Error("an answered probe must not be flagged inconclusive")
	}
}

// TestScanTargetUnansweredUDPProbeCreatesNoFinding pins the other half: UDP has
// no handshake, so silence is not evidence. A probe nobody answers must not
// manufacture a finding — every stored finding is mirrored into
// sensor_discoveries and materialises inventory, so a fabricated one becomes a
// fabricated asset.
func TestScanTargetUnansweredUDPProbeCreatesNoFinding(t *testing.T) {
	var datagrams int64
	bindUDP(t, bacnetPort, &datagrams, nil) // listens, never replies

	ps := NewPortScanner()
	ps.otProber = shareddisc.NewProber(200 * time.Millisecond)

	findings, err := ps.ScanTarget("127.0.0.1", []int32{bacnetPort}, []string{"BACnet"}, nil, nil)
	if err != nil {
		t.Fatalf("ScanTarget: %v", err)
	}

	if got := atomic.LoadInt64(&datagrams); got == 0 {
		t.Fatal("the probe was never dispatched — this test cannot distinguish silence from a missing probe")
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0 — an unanswered UDP probe is inconclusive, not a device: %+v", len(findings), findings)
	}
}

// TestUnansweredUDPProbeAnnotatesRatherThanClaimsAbsence pins the three-way
// distinction where there IS somewhere to record it: an open-port finding
// already exists for the port, so the inconclusive outcome is written onto it
// rather than being reported as a confirmed absence or lost entirely.
func TestUnansweredUDPProbeAnnotatesRatherThanClaimsAbsence(t *testing.T) {
	var datagrams int64
	bindUDP(t, bacnetPort, &datagrams, nil)

	ps := NewPortScanner()
	ps.otProber = shareddisc.NewProber(200 * time.Millisecond)

	// Stand in for a TCP scan that did find a listener on the same port.
	existing := []models.DiscoveryFinding{{
		ExecutedVia: "nmap",
		Protocol:    "tcp",
		Port:        bacnetPort,
		ResolvedIP:  "127.0.0.1",
		Data:        map[string]interface{}{},
	}}

	findings := ps.dispatchUDPProbes(existing, "127.0.0.1", []int32{bacnetPort}, []string{"BACnet"}, nil)

	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 — the outcome belongs on the existing finding, not a new one", len(findings))
	}
	data := findings[0].Data
	if got := data["bacnet_probe_outcome"]; got != string(shareddisc.ProbeNoAnswer) {
		t.Errorf("Data[bacnet_probe_outcome] = %v, want %q", got, shareddisc.ProbeNoAnswer)
	}
	if inconclusive, _ := data["bacnet_probe_inconclusive"].(bool); !inconclusive {
		t.Error("silence must be recorded as inconclusive — it is not proof the device is absent")
	}
	if got := data["bacnet_probe_attempts"]; got != 2 {
		t.Errorf("Data[bacnet_probe_attempts] = %v, want 2 (one datagram is weak evidence)", got)
	}
	if got := data["bacnet_probe_transport"]; got != "udp" {
		t.Errorf("Data[bacnet_probe_transport] = %v, want udp", got)
	}
	// The finding must NOT have been re-labelled as a confirmed BACnet device.
	if findings[0].Protocol != "tcp" {
		t.Errorf("Protocol = %q, want tcp — an unanswered probe identifies nothing", findings[0].Protocol)
	}
}

// TestSharedOTSMBEligibleExcludesUDPRegisteredProtocols pins that the TCP
// open-port loop no longer claims to handle UDP protocols. This is the gate that
// was wrong: BACnet and EtherNet/IP were listed here, so their only dispatch
// path required an open TCP port they do not have.
func TestSharedOTSMBEligibleExcludesUDPRegisteredProtocols(t *testing.T) {
	for _, proto := range []string{"BACnet", "EtherNet_IP", "ethernet-ip", "BACNET"} {
		if sharedOTSMBEligible(proto) {
			t.Errorf("sharedOTSMBEligible(%q) = true — a UDP prober must not be gated on an open TCP port", proto)
		}
	}
	for _, proto := range []string{"Modbus", "OPC_UA", "SMB"} {
		if !sharedOTSMBEligible(proto) {
			t.Errorf("sharedOTSMBEligible(%q) = false — these genuinely ride on TCP and must stay on the TCP path", proto)
		}
	}
}

// TestEtherNetIPHasNoTCPPath answers the "largely unaffected" half of the
// finding directly, rather than assuming it. EtherNet/IP explicit messaging does
// listen on TCP 44818 — but our List Identity prober is registered UDP and dials
// UDP, so it has no TCP path at all. An open TCP 44818 merely happened to make
// the old gate fire; it never carried the probe. A device reachable only on UDP
// 44818 was as invisible as a BACnet controller.
func TestEtherNetIPHasNoTCPPath(t *testing.T) {
	if !shareddisc.IsUDPProtocol("EtherNet_IP") {
		t.Fatal("EtherNet_IP is not UDP-registered — this test's premise has changed")
	}

	var tcpConns int64
	bindTCP(t, ethernetIPPort, &tcpConns)

	ps := NewPortScanner()
	ps.otProber = shareddisc.NewProber(200 * time.Millisecond)

	findings := ps.dispatchUDPProbes(nil, "127.0.0.1", []int32{ethernetIPPort}, []string{"EtherNet_IP"}, nil)

	if got := atomic.LoadInt64(&tcpConns); got != 0 {
		t.Errorf("the EtherNet/IP prober opened %d TCP connection(s) — it is registered as a UDP prober and must not", got)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %d, want 0 — an open TCP listener is not a List Identity answer", len(findings))
	}
}

// TestDispatchableOTProtocolsKeepsTheAuditColumnHonest pins the other half of
// "record only what was genuinely attempted": discovery_jobs.ot_probe_protocols
// documents itself as "these probes were dispatched", so a protocol that would
// never become a discovery target must not appear in it.
func TestDispatchableOTProtocolsKeepsTheAuditColumnHonest(t *testing.T) {
	if got := dispatchableOTProtocols([]string{"BACnet", "Modbus"}); len(got) != 2 {
		t.Errorf("dispatchableOTProtocols(BACnet, Modbus) = %v, want both — each has a standard port", got)
	}
	// A protocol with no standard port produces no target row, so recording it
	// as probed would be the "reported as probed, never probed" lie again.
	if got := dispatchableOTProtocols([]string{"BACnet", "Nonexistent"}); len(got) != 1 || got[0] != "BACnet" {
		t.Errorf("dispatchableOTProtocols(BACnet, Nonexistent) = %v, want [BACnet]", got)
	}
	if got := dispatchableOTProtocols([]string{"Nonexistent"}); got != nil {
		t.Errorf("dispatchableOTProtocols(Nonexistent) = %v, want nil", got)
	}
	if got := dispatchableOTProtocols(nil); got != nil {
		t.Errorf("dispatchableOTProtocols(nil) = %v, want nil", got)
	}
}

// bindUDP binds a loopback UDP socket on the given port, counting datagrams and
// optionally replying with a canned response. Failure to bind is fatal on
// purpose: skipping would leave the dispatch untested and green.
func bindUDP(t *testing.T, port int, counter *int64, reply []byte) {
	t.Helper()
	pc, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("bind loopback UDP %d (must be free on the test host): %v", port, err)
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

// bindTCP binds a loopback TCP listener on the given port, counting accepted
// connections.
func bindTCP(t *testing.T, port int, counter *int64) {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("bind loopback TCP %d (must be free on the test host): %v", port, err)
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
			atomic.AddInt64(counter, 1)
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
}

// bacnetIAmReply is a well-formed BACnet/IP I-Am for device instance 1234
// (object type 8 = device), per ASHRAE 135 §B.4.
func bacnetIAmReply() []byte {
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
