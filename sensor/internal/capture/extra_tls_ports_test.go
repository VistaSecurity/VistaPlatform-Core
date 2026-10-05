package capture

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// clientHelloRecord returns a TLS record carrying a minimal ClientHello with
// SNI and ALPN, so a decoded flow is distinguishable from an empty one.
func clientHelloRecord() []byte {
	msg := []byte{0x03, 0x03}
	msg = append(msg, make([]byte, 32)...)
	msg = append(msg, 0x00)                               // session id len
	msg = append(msg, 0x00, 0x04, 0x13, 0x01, 0xc0, 0x2f) // two suites
	msg = append(msg, 0x01, 0x00)                         // null compression
	ext := buildTestExtensions()
	msg = append(msg, byte(len(ext)>>8), byte(len(ext)))
	msg = append(msg, ext...)

	hs := []byte{0x01, byte(len(msg) >> 16), byte(len(msg) >> 8), byte(len(msg))}
	hs = append(hs, msg...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

// buildTCPData frames payload as one client->server TCP segment, decoded the
// way the capture handle would decode it.
func buildTCPData(t *testing.T, srcIP, dstIP string, srcPort, dstPort int, payload []byte) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.ParseIP(srcIP), DstIP: net.ParseIP(dstIP),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort),
		Seq: 1000, ACK: true, PSH: true, Window: 65535,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("checksum setup: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	p.Metadata().Timestamp = time.Now()
	return p
}

// discoveriesFor drives the REAL analyzePacket with a TLS ClientHello to
// dstPort and returns what the capture path emitted. FlushAll stands in for
// the connection closing: the assembler only hands bytes to a stream and ends
// it then, and the TLS stream emits on ReassemblyComplete.
func discoveriesFor(t *testing.T, extra []int, dstPort int) []*models.CryptoDiscovery {
	t.Helper()
	cfg := &config.Config{SensorID: "test-sensor"}
	cfg.Capture.DedupTTLMinutes = 1
	cfg.Capture.ExtraPortsToMonitor = extra
	pc := NewPacketCapture(cfg)
	defer pc.cancel()

	pc.analyzePacket(buildTCPData(t, "192.0.2.10", "192.0.2.20", 50123, dstPort, clientHelloRecord()), "eth0")

	pc.assemblerMu.Lock()
	pc.assembler.FlushAll()
	pc.sshAssembler.FlushAll()
	pc.assemblerMu.Unlock()

	var out []*models.CryptoDiscovery
	for {
		select {
		case d := <-pc.discoveries:
			out = append(out, d)
		default:
			return out
		}
	}
}

// The wiring test for H5: a port in extraPortsToMonitor is captured by
// the BPF filter AND decoded. Before the fix the packet was dropped in
// analyzePacket because getProtocolFromPort("9443") is "".
func TestExtraPortsToMonitorAreDecodedAsTLS(t *testing.T) {
	got := discoveriesFor(t, []int{9443}, 9443)
	if len(got) != 1 {
		t.Fatalf("got %d discoveries for a ClientHello to listed port 9443, want 1", len(got))
	}
	d := got[0]
	if d.Protocol != "TLS" || d.Port != 9443 || d.DestIP != "192.0.2.20" {
		t.Errorf("discovery = protocol %q port %d dest %q, want TLS 9443 192.0.2.20", d.Protocol, d.Port, d.DestIP)
	}
}

// Negative polarity: the same bytes to a port nobody listed stay dropped, so
// the positive test cannot pass by classifying everything as TLS.
func TestUnlistedPortIsStillIgnored(t *testing.T) {
	for _, extra := range [][]int{nil, {8444}, {9443}} {
		dst := 9443
		if len(extra) == 1 && extra[0] == 9443 {
			dst = 10443
		}
		if got := discoveriesFor(t, extra, dst); len(got) != 0 {
			t.Errorf("extra=%v dst=%d: got %d discoveries, want 0", extra, dst, len(got))
		}
	}
}

// Extras never change a built-in meaning: 443 is TLS with or without being
// listed, and listing 22 does not turn SSH into TLS (a ClientHello to 22 goes
// to the SSH assembler, which finds no banner and emits nothing).
func TestExtraPortsNeverOverrideBuiltins(t *testing.T) {
	if got := discoveriesFor(t, []int{443}, 443); len(got) != 1 {
		t.Errorf("443 listed as extra: got %d discoveries, want 1 (unchanged built-in TLS)", len(got))
	}
	if got := discoveriesFor(t, []int{22}, 22); len(got) != 0 {
		t.Errorf("22 listed as extra: got %d discoveries, want 0 (22 stays SSH)", len(got))
	}

	starttls := []int{25, 143, 110, 5432, 3306, 21, 5222, 389}
	for _, p := range []int{22, 445, 88, 502, 102, 20000, 4840, 44818, 5094, 500, 4500} {
		set := newExtraTLSPorts([]int{p})
		if got := set.protocol(p, starttls); got != "" {
			t.Errorf("port %d: extras classified a built-in port as %q", p, got)
		}
	}
	for _, p := range starttls {
		set := newExtraTLSPorts([]int{p})
		if got := set.protocol(p, starttls); got != "" {
			t.Errorf("STARTTLS port %d: extras classified it as %q", p, got)
		}
		if got := classifyForTest(p, false, starttls, set); got != "" {
			t.Errorf("STARTTLS port %d with STARTTLS disabled: classified as %q, want plaintext ignored", p, got)
		}
	}
	if got := newExtraTLSPorts([]int{9443}).protocol(9443, starttls); got != "TLS" {
		t.Errorf("9443 = %q, want TLS", got)
	}
}

// classifyForTest mirrors the order both call sites use (built-in table, then
// extras) so the STARTTLS-disabled case is pinned without a capture instance.
func classifyForTest(port int, enableSTARTTLS bool, starttls []int, e extraTLSPorts) string {
	if p := getProtocolFromPort(port, enableSTARTTLS, starttls); p != "" {
		return p
	}
	return e.protocol(port, starttls)
}

func TestExtraPortsInvalidValuesAreIgnored(t *testing.T) {
	set := newExtraTLSPorts([]int{0, -1, 70000, 9443, 65535})
	if len(set) != 2 {
		t.Errorf("set = %v, want only 9443 and 65535", set)
	}
	for _, bad := range []int{0, -1, 70000} {
		if set.protocol(bad, nil) != "" {
			t.Errorf("invalid port %d classified", bad)
		}
	}

	// An out-of-range term would fail the whole BPF compile, taking every
	// other port down with it.
	cfg := &config.Config{}
	cfg.Capture.ExtraPortsToMonitor = []int{0, -5, 70000, 9443}
	filter := buildBPFFilter(cfg)
	for _, bad := range []string{"tcp port 0", "tcp port -5", "tcp port 70000"} {
		if strings.Contains(filter+" ", bad+" ") {
			t.Errorf("filter carries invalid term %q: %s", bad, filter)
		}
	}
	if !strings.Contains(filter, "tcp port 9443") {
		t.Errorf("filter lost the valid extra port: %s", filter)
	}
}

// R2: no extras -> the filter is exactly what it was before this change.
func TestBPFFilterUnchangedWithoutExtras(t *testing.T) {
	cfg := &config.Config{}
	want := "tcp port 443 or tcp port 22 or tcp port 993 or tcp port 995 or tcp port 465 or tcp port 587 or tcp port 636 or tcp port 5671 or tcp port 8443 or tcp port 853 or udp port 443 or udp port 500 or udp port 4500 or tcp port 3389"
	if got := buildBPFFilter(cfg); got != want {
		t.Errorf("filter changed for a config without extras:\n got %s\nwant %s", got, want)
	}
}
