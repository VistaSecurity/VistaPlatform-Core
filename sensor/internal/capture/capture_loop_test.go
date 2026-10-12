package capture

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
)

func TestResolveCaptureDevice(t *testing.T) {
	// Linux-style list: most devices have no description, so a bare
	// strings.Contains(x, "") used to match the first one for ANY name.
	linux := []pcap.Interface{
		{Name: "any"},
		{Name: "lo"},
		{Name: "eth0"},
		{Name: "eth1"},
	}
	windows := []pcap.Interface{
		{Name: `\Device\NPF_{A}`, Description: "Intel(R) Ethernet Connection"},
		{Name: `\Device\NPF_{B}`, Description: "Realtek PCIe GbE"},
	}
	tests := []struct {
		name    string
		iface   string
		devs    []pcap.Interface
		want    string
		wantErr string
	}{
		{"exact name not shadowed by earlier description-less device", "eth1", linux, "eth1", ""},
		{"exact name later in list", "eth0", linux, "eth0", ""},
		{"exact name beats an earlier description match", "eth0", append([]pcap.Interface{{Name: "br0", Description: "eth0 bridge"}}, linux...), "eth0", ""},
		{"description fallback", "Realtek", windows, `\Device\NPF_{B}`, ""},
		{"description fallback is case-insensitive", "realtek pcie gbe", windows, `\Device\NPF_{B}`, ""},
		{"unknown name with description-less devices errors", "wlan9", linux, "", "Available interfaces"},
		{"unknown name lists devices", "wlan9", windows, "", "Intel(R) Ethernet Connection"},
		{"empty name never matches", "", linux, "", "not found"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveCaptureDevice(tc.iface, tc.devs)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// A closed packet channel must be reported and end the loop, not spin.
func TestPumpPackets_ClosedChannelReportsErrorAndReturns(t *testing.T) {
	pc := NewPacketCapture(&config.Config{SensorID: "s"})
	defer pc.cancel()

	ch := make(chan gopacket.Packet)
	close(ch)
	done := make(chan struct{})
	go func() { pc.pumpPackets(ch, "eth9"); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pumpPackets did not return after its channel closed (busy-spin)")
	}
	select {
	case err := <-pc.GetErrors():
		if !strings.Contains(err.Error(), "eth9") {
			t.Fatalf("error should name the interface: %v", err)
		}
	default:
		t.Fatal("no error reported for a closed packet source")
	}
	if got := pc.FailedInterfaces(); len(got) != 1 || got[0] != "eth9" {
		t.Fatalf("FailedInterfaces = %v, want [eth9]", got)
	}
}

// Shutdown closes the handle, which closes the channel; that is not an error.
func TestPumpPackets_ClosedChannelDuringShutdownIsSilent(t *testing.T) {
	pc := NewPacketCapture(&config.Config{SensorID: "s"})
	pc.cancel()
	ch := make(chan gopacket.Packet)
	close(ch)
	pc.pumpPackets(ch, "eth9")
	select {
	case err := <-pc.GetErrors():
		t.Fatalf("unexpected error during shutdown: %v", err)
	default:
	}
}

func feedKerberosSegment(t *testing.T, pc *PacketCapture, ts time.Time) {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.IP{10, 0, 0, 1}, DstIP: net.IP{10, 0, 0, 2}}
	tcp := &layers.TCP{SrcPort: 50000, DstPort: 88, Seq: 1, ACK: true}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ip, tcp, gopacket.Payload([]byte{0, 0, 0, 1})); err != nil {
		t.Fatal(err)
	}
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	dec := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	pc.assemblerMu.Lock()
	pc.krbTCPAssembler.AssembleWithTimestamp(pkt.NetworkLayer().NetworkFlow(), dec, ts)
	pc.assemblerMu.Unlock()
}

// An idle flow with no FIN/RST must be evicted by the periodic flush.
func TestFlushStale_EvictsIdleTCPFlows(t *testing.T) {
	cfg := &config.Config{SensorID: "s"}
	cfg.Capture.EnableKerberos = true
	pc := NewPacketCapture(cfg)
	defer pc.cancel()

	feedKerberosSegment(t, pc, time.Now().Add(-5*time.Minute))
	count := func() int {
		pc.kerberosTCPFactory.mu.Lock()
		defer pc.kerberosTCPFactory.mu.Unlock()
		return len(pc.kerberosTCPFactory.sessions)
	}
	if count() != 1 {
		t.Fatalf("setup: sessions = %d, want 1", count())
	}
	pc.flushStale(assemblerMaxIdle)
	if n := count(); n != 0 {
		t.Fatalf("idle flow still present after flushStale: sessions = %d", n)
	}

	// A fresh flow survives.
	feedKerberosSegment(t, pc, time.Now())
	pc.flushStale(assemblerMaxIdle)
	if n := count(); n != 1 {
		t.Fatalf("active flow evicted: sessions = %d, want 1", n)
	}
}

func TestKerberosTCPFactory_FlushOldSessions(t *testing.T) {
	f := NewKerberosTCPStreamFactory(nil, "s")
	f.sessions[tlsFlowKey{}] = &kerberosTCPState{lastSeen: time.Now().Add(-time.Hour)}
	f.FlushOldSessions(time.Minute)
	if len(f.sessions) != 0 {
		t.Fatal("stale Kerberos TCP session was not flushed")
	}
}
