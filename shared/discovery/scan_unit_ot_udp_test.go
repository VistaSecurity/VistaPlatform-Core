package discovery

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// otUDPSuiteAddr is this suite's own loopback address: BACnet's well-known
// UDP port has to be bound literally (the OT UDP probers dial addr:47808
// themselves), and shared/testdb's TestTestFixturesBindTheirOwnLoopbackAddress
// keeps every such suite off 127.0.0.1.
const otUDPSuiteAddr = "127.0.0.31"

// serveBACnet answers every datagram on otUDPSuiteAddr:47808 with an I-Am
// (bacnetIAm, device instance 1234) and
// counts them. A bind failure is fatal: a skip would leave the opt-in path
// untested and green.
func serveBACnet(t *testing.T) *atomic.Int32 {
	t.Helper()
	pc, err := net.ListenPacket("udp", net.JoinHostPort(otUDPSuiteAddr, "47808"))
	if err != nil {
		t.Fatalf("bind %s:47808/udp: %v", otUDPSuiteAddr, err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	var n atomic.Int32
	go func() {
		buf := make([]byte, 1500)
		for {
			_, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			n.Add(1)
			_, _ = pc.WriteTo(bacnetIAm(), from)
		}
	}()
	return &n
}

// TestUnitEngine_OTOptInProbesBACnetOverUDP is the engine half of the OT-only
// request's move onto the shared engine ( WP5): a unit with UDP 47808 and
// the BACnet opt-in sends one Who-Is and records the device, with no TCP port
// asked for or sent to; the same unit without the opt-in sends nothing to the
// controller and records it connect-only. (BACnet/IP is UDP-only, so a TCP
// scan would never find it — the B-60 regression the legacy dispatch fixed.)
func TestUnitEngine_OTOptInProbesBACnetOverUDP(t *testing.T) {
	datagrams := serveBACnet(t)
	addr := netip.MustParseAddr(otUDPSuiteAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	without, err := NewUnitEngine(PaceNormal, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := without.Run(ctx, UnitInput{Addr: addr, UDP: []int{47808}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.UDP) != 1 || out.UDP[0].Identified || out.UDP[0].Notes != "ot-opt-in-not-given" {
		t.Fatalf("without the opt-in: %+v, want one connect-only observation", out.UDP)
	}
	if n := datagrams.Load(); n != 0 {
		t.Fatalf("the controller received %d datagram(s) without the BACnet opt-in", n)
	}

	with, err := NewUnitEngine(PaceNormal, []string{"BACnet"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err = with.Run(ctx, UnitInput{Addr: addr, UDP: []int{47808}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.TCP) != 0 || len(out.Host.Open) != 0 {
		t.Fatalf("a UDP-only unit scanned TCP: open=%v obs=%+v", out.Host.Open, out.TCP)
	}
	if len(out.UDP) != 1 || !out.UDP[0].Identified || out.UDP[0].Protocol != "BACnet" || out.UDP[0].Result == nil {
		t.Fatalf("with the opt-in: %+v, want the BACnet device identified", out.UDP)
	}
	if got := out.UDP[0].Result.Metadata["bacnet_device_instance"]; got != 1234 {
		t.Fatalf("bacnet_device_instance = %v, want 1234", got)
	}
	if n := datagrams.Load(); n != 1 {
		t.Fatalf("the controller received %d datagram(s), want exactly one Who-Is", n)
	}
}
