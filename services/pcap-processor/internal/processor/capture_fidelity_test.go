package processor

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// Capture-level tests: synthetic capture files run through processPcapFile, so
// they cover the wiring from the packet decoder into the TLS reassembler and
// the QUIC detector, not just those pieces in isolation.

var (
	clientMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x09}
	serverMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	clientIP  = net.IPv4(192, 168, 1, 71).To4()
	serverIP  = net.IPv4(203, 0, 113, 10).To4()
)

type captureWriter struct {
	t   *testing.T
	w   *pcapgo.Writer
	f   *os.File
	ts  time.Time
	cut int // snapshot length; frames longer than this are recorded truncated
}

func newCapture(t *testing.T, path string, snaplen int) *captureWriter {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create capture: %v", err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(uint32(snaplen), layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write header: %v", err)
	}
	return &captureWriter{t: t, w: w, f: f, ts: time.Unix(1790000000, 0), cut: snaplen}
}

func (c *captureWriter) frame(ls ...gopacket.SerializableLayer) {
	c.t.Helper()
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...); err != nil {
		c.t.Fatalf("serialize: %v", err)
	}
	data := buf.Bytes()
	captured := data
	if len(captured) > c.cut {
		captured = captured[:c.cut]
	}
	c.ts = c.ts.Add(time.Millisecond)
	ci := gopacket.CaptureInfo{Timestamp: c.ts, CaptureLength: len(captured), Length: len(data)}
	if err := c.w.WritePacket(ci, captured); err != nil {
		c.t.Fatalf("write packet: %v", err)
	}
}

func (c *captureWriter) tcp(fromClient bool, seq uint32, payload []byte) {
	c.t.Helper()
	srcMAC, dstMAC, src, dst := clientMAC, serverMAC, clientIP, serverIP
	sport, dport := layers.TCPPort(51514), layers.TCPPort(443)
	if !fromClient {
		srcMAC, dstMAC, src, dst = serverMAC, clientMAC, serverIP, clientIP
		sport, dport = dport, sport
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: src, DstIP: dst}
	tcp := &layers.TCP{SrcPort: sport, DstPort: dport, Seq: seq, ACK: true, PSH: true, Window: 65535}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	c.frame(&layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}, ip, tcp, gopacket.Payload(payload))
}

func (c *captureWriter) udp(fromClient bool, payload []byte) {
	c.t.Helper()
	srcMAC, dstMAC, src, dst := clientMAC, serverMAC, clientIP, serverIP
	sport, dport := layers.UDPPort(52545), layers.UDPPort(443)
	if !fromClient {
		srcMAC, dstMAC, src, dst = serverMAC, clientMAC, serverIP, clientIP
		sport, dport = dport, sport
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: src, DstIP: dst}
	udp := &layers.UDP{SrcPort: sport, DstPort: dport}
	_ = udp.SetNetworkLayerForChecksum(ip)
	c.frame(&layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}, ip, udp, gopacket.Payload(payload))
}

// arp writes a gratuitous ARP announcement from mac/ip.
func (c *captureWriter) arp(mac net.HardwareAddr, ip net.IP) {
	c.t.Helper()
	c.frame(
		&layers.Ethernet{SrcMAC: mac, DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, EthernetType: layers.EthernetTypeARP},
		&layers.ARP{
			AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
			HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
			SourceHwAddress: mac, SourceProtAddress: ip,
			DstHwAddress: make([]byte, 6), DstProtAddress: ip,
		},
	)
}

func (c *captureWriter) close() {
	if err := c.f.Close(); err != nil {
		c.t.Fatalf("close capture: %v", err)
	}
}

// clientHelloRecord is a TLS record holding a ClientHello for sni, padded past
// one TCP segment the way a post-quantum key share pads a real browser's.
func clientHelloRecord(sni string) []byte {
	u16 := func(v int) []byte { return binary.BigEndian.AppendUint16(nil, uint16(v)) }

	name := append([]byte{0x00}, append(u16(len(sni)), sni...)...)
	sniExt := append(u16(0x0000), u16(len(name)+2)...)
	sniExt = append(sniExt, u16(len(name))...)
	sniExt = append(sniExt, name...)
	padExt := append(append(u16(0x0015), u16(1500)...), make([]byte, 1500)...)
	exts := append(sniExt, padExt...)

	body := append(u16(0x0303), make([]byte, 32)...) // version, random
	body = append(body, 0x00)                        // session id
	body = append(body, u16(2)...)
	body = append(body, u16(0xC02F)...)
	body = append(body, 0x01, 0x00) // compression: null
	body = append(body, u16(len(exts))...)
	body = append(body, exts...)

	hs := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append(append([]byte{0x16, 0x03, 0x01}, u16(len(hs))...), hs...)
}

// quicInitial is the start of a QUIC v1 long-header Initial packet; only the
// header is read.
func quicInitial() []byte {
	p := []byte{0xC3, 0x00, 0x00, 0x00, 0x01, 0x08}
	return append(p, make([]byte, 1200)...)
}

func runCapture(t *testing.T, build func(c *captureWriter), snaplen int) *PcapResult {
	t.Helper()
	path := filepath.Join(t.TempDir(), "capture.pcap")
	c := newCapture(t, path, snaplen)
	build(c)
	c.close()
	result, err := testProcessor(t).processPcapFile(context.Background(), path, "sensor-under-test")
	if err != nil {
		t.Fatalf("processPcapFile: %v", err)
	}
	return result
}

func discoveriesOf(r *PcapResult, protocol string) []CryptoDiscovery {
	var out []CryptoDiscovery
	for _, d := range r.Discoveries {
		if d.Protocol == protocol {
			out = append(out, d)
		}
	}
	return out
}

// TestRetransmittedClientHelloStillYieldsTLS: the first segment of a
// two-segment ClientHello appears twice in the capture, as a retransmission
// does. The processor must hand the reassembler the TCP sequence number, or
// the duplicate is spliced into the stream and the handshake is lost.
func TestRetransmittedClientHelloStillYieldsTLS(t *testing.T) {
	rec := clientHelloRecord("retransmit.example.com")
	const isn = 4_000_000_000
	result := runCapture(t, func(c *captureWriter) {
		c.tcp(true, isn, rec[:1200])
		c.tcp(true, isn, rec[:1200])
		c.tcp(true, isn+1200, rec[1200:])
	}, 65535)

	tls := discoveriesOf(result, "TLS")
	if len(tls) != 1 || tls[0].SNI != "retransmit.example.com" {
		t.Fatalf("expected one TLS discovery for retransmit.example.com, got %+v", tls)
	}
	if result.TruncatedPackets != 0 {
		t.Errorf("truncated packets = %d, want 0 for a full-length capture", result.TruncatedPackets)
	}
}

// TestSnapshotTruncationIsReported is the shape of the capture that prompted it: a 128-byte
// snapshot length. The ClientHello cannot be read, and the result must say why.
func TestSnapshotTruncationIsReported(t *testing.T) {
	rec := clientHelloRecord("snaplen.example.com")
	const isn = 1000
	result := runCapture(t, func(c *captureWriter) {
		c.tcp(true, isn, rec[:1200])
		c.tcp(true, isn+1200, rec[1200:])
		c.udp(true, quicInitial())
	}, 128)

	if result.SnapshotLength != 128 {
		t.Errorf("snapshot length = %d, want 128", result.SnapshotLength)
	}
	if result.TruncatedPackets != 3 {
		t.Errorf("truncated packets = %d, want 3", result.TruncatedPackets)
	}
	if tls := discoveriesOf(result, "TLS"); len(tls) != 0 {
		t.Errorf("a ClientHello the capture cut short produced %d TLS discovery(ies)", len(tls))
	}
	// The QUIC version sits in the first bytes of the datagram, so it survives.
	if quic := discoveriesOf(result, "QUIC"); len(quic) != 1 {
		t.Errorf("expected the QUIC Initial to survive truncation, got %d", len(quic))
	}
}

// TestQUICConversationIsOneClientToServerDiscovery: both ends send Initial
// packets. Only the client's — the first in the conversation — is recorded,
// with the version spelled the way the live sensor spells it.
func TestQUICConversationIsOneClientToServerDiscovery(t *testing.T) {
	result := runCapture(t, func(c *captureWriter) {
		c.udp(true, quicInitial())
		c.udp(false, quicInitial())
		c.udp(true, quicInitial())
	}, 65535)

	quic := discoveriesOf(result, "QUIC")
	if len(quic) != 1 {
		t.Fatalf("expected 1 QUIC discovery for one conversation, got %d: %+v", len(quic), quic)
	}
	d := quic[0]
	if d.SourceIP != clientIP.String() || d.DestIP != serverIP.String() || d.DestPort != 443 {
		t.Errorf("discovery is %s:%d -> %s:%d, want the client's Initial to the server on 443",
			d.SourceIP, d.SourcePort, d.DestIP, d.DestPort)
	}
	if d.ProtocolVersion != "QUIC v1" {
		t.Errorf("protocol version = %q, want %q (the sensor's spelling)", d.ProtocolVersion, "QUIC v1")
	}
}

func TestQUICVersionNegotiationIsNotAnInitial(t *testing.T) {
	vn := []byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x08}
	vn = append(vn, make([]byte, 40)...)
	result := runCapture(t, func(c *captureWriter) { c.udp(false, vn) }, 65535)
	if quic := discoveriesOf(result, "QUIC"); len(quic) != 0 {
		t.Errorf("a Version Negotiation packet produced %d QUIC discovery(ies)", len(quic))
	}
}

func TestProtocolCountsCountDiscoveries(t *testing.T) {
	r := &PcapResult{Discoveries: []CryptoDiscovery{{Protocol: "QUIC"}, {Protocol: "QUIC"}, {Protocol: "HOST"}}}
	got := r.protocolCounts()
	if got["QUIC"] != 2 || got["HOST"] != 1 || len(got) != 2 {
		t.Errorf("protocol counts = %v, want QUIC:2 HOST:1", got)
	}
}

// TestEveryObservedHostIsKept: three hosts announce themselves over ARP and
// three host discoveries come out. The sink once keyed host observations on a
// field they never set, so a capture of a whole segment produced one host,
// chosen at random.
func TestEveryObservedHostIsKept(t *testing.T) {
	hosts := []struct {
		mac net.HardwareAddr
		ip  net.IP
	}{
		{net.HardwareAddr{0x02, 0x00, 0x5e, 0x00, 0x00, 0x01}, net.IPv4(192, 168, 1, 1).To4()},
		{net.HardwareAddr{0x02, 0x00, 0x5e, 0x00, 0x00, 0x02}, net.IPv4(192, 168, 1, 249).To4()},
		{net.HardwareAddr{0x02, 0x00, 0x5e, 0x00, 0x00, 0x03}, net.IPv4(192, 168, 1, 205).To4()},
	}
	result := runCapture(t, func(c *captureWriter) {
		for _, h := range hosts {
			c.arp(h.mac, h.ip)
		}
	}, 65535)

	got := map[string]bool{}
	for _, d := range discoveriesOf(result, "HOST") {
		got[d.DestIP] = true
	}
	for _, h := range hosts {
		if !got[h.ip.String()] {
			t.Errorf("host %s (%s) missing from %d host discovery(ies)", h.ip, h.mac, len(got))
		}
	}
}
