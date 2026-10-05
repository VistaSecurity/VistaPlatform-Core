package capture

import (
	"encoding/binary"
	"net"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// buildUDPData frames payload as one UDP datagram, decoded the way the
// capture handle would decode it.
func buildUDPData(t *testing.T, srcPort, dstPort int, payload []byte) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.ParseIP("192.0.2.10"), DstIP: net.ParseIP("192.0.2.20"),
	}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("checksum setup: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	p.Metadata().Timestamp = time.Now()
	return p
}

// drainDiscoveries returns everything analyzePacket queued so far.
func drainDiscoveries(pc *PacketCapture) []*models.CryptoDiscovery {
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

// udpDiscoveries drives the REAL analyzePacket with the given datagrams on one
// capture instance and returns what the capture path emitted.
func udpDiscoveries(t *testing.T, mutate func(*config.Config), pkts ...gopacket.Packet) []*models.CryptoDiscovery {
	t.Helper()
	cfg := &config.Config{SensorID: "test-sensor"}
	cfg.Capture.DedupTTLMinutes = 1
	if mutate != nil {
		mutate(cfg)
	}
	pc := NewPacketCapture(cfg)
	defer pc.cancel()
	for _, p := range pkts {
		pc.analyzePacket(p, "eth0")
	}
	return drainDiscoveries(pc)
}

func wgHandshakeInitiation() []byte {
	data := make([]byte, wgHandshakeInitiationSize)
	data[0] = wgTypeHandshakeInitiation
	binary.LittleEndian.PutUint32(data[4:8], 42)
	return data
}

func wgTransportData() []byte {
	data := make([]byte, wgTransportDataMinSize)
	data[0] = wgTypeTransportData
	return data
}

func openVPNHardResetClient() []byte {
	data := make([]byte, 32)
	data[0] = openvpnHardResetClientV2 << 3
	copy(data[1:9], []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE})
	return data
}

// The wiring test for the UDP classification: a datagram to 51820 / 1194 has
// no entry in the TCP-oriented getProtocolFromPort, and analyzePacket used to
// return on that empty protocol before the UDP branch ever ran, so the
// WireGuard and OpenVPN decoders were captured by the BPF filter and then
// never reached.
func TestUDPVPNPacketsReachTheirDecoders(t *testing.T) {
	cases := []struct {
		name    string
		port    int
		payload []byte
		enable  func(*config.Config)
		version string
	}{
		{"WireGuard", 51820, wgHandshakeInitiation(), func(c *config.Config) { c.Capture.EnableWireGuard = true }, "WireGuard"},
		{"OpenVPN", 1194, openVPNHardResetClient(), func(c *config.Config) { c.Capture.EnableOpenVPN = true }, "OpenVPN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := udpDiscoveries(t, tc.enable, buildUDPData(t, 40000, tc.port, tc.payload))
			if len(got) != 1 {
				t.Fatalf("got %d discoveries for a %s datagram to UDP %d with the flag on, want 1", len(got), tc.name, tc.port)
			}
			d := got[0]
			if d.Protocol != "VPN" || d.Version != tc.version || d.Port != tc.port || d.DestIP != "192.0.2.20" || d.SourceIP != "192.0.2.10" {
				t.Errorf("discovery = %s/%s port %d %s->%s, want VPN/%s port %d 192.0.2.10->192.0.2.20",
					d.Protocol, d.Version, d.Port, d.SourceIP, d.DestIP, tc.version, tc.port)
			}

			// Negative polarity: the flag still gates the decoder. The BPF
			// filter is what normally keeps these datagrams out, but the
			// flag must hold even for a packet that arrives anyway.
			if off := udpDiscoveries(t, nil, buildUDPData(t, 40000, tc.port, tc.payload)); len(off) != 0 {
				t.Errorf("flag off: got %d discoveries, want 0", len(off))
			}
		})
	}
}

// Each decoder only fires on its own port: the same bytes to a port nobody
// owns stay dropped, so the positive test cannot pass by decoding every UDP
// datagram.
func TestUDPUnrelatedPortsYieldNothing(t *testing.T) {
	all := func(c *config.Config) {
		c.Capture.EnableWireGuard = true
		c.Capture.EnableOpenVPN = true
		c.Capture.EnableDNP3 = true
		c.Capture.EnableHARTIP = true
		c.Capture.EnableKerberos = true
	}
	for _, port := range []int{51821, 1195, 9999, 53} {
		for name, payload := range map[string][]byte{"wireguard": wgHandshakeInitiation(), "openvpn": openVPNHardResetClient()} {
			if got := udpDiscoveries(t, all, buildUDPData(t, 40000, port, payload)); len(got) != 0 {
				t.Errorf("%s payload to UDP %d: got %d discoveries, want 0", name, port, len(got))
			}
		}
	}
	// A reply (service port as the SOURCE, client ephemeral port as the
	// destination) stays dropped: the decoders record the destination as the
	// service, so decoding it would report the client's ephemeral port as a
	// VPN server.
	if got := udpDiscoveries(t, all, buildUDPData(t, 51820, 40000, wgHandshakeInitiation())); len(got) != 0 {
		t.Errorf("WireGuard reply from 51820 to an ephemeral port: got %d discoveries, want 0", len(got))
	}
	if got := udpDiscoveries(t, all, buildUDPData(t, 1194, 40000, openVPNHardResetClient())); len(got) != 0 {
		t.Errorf("OpenVPN reply from 1194 to an ephemeral port: got %d discoveries, want 0", len(got))
	}
	// A WireGuard decoder given a non-WireGuard payload on its own port.
	if got := udpDiscoveries(t, all, buildUDPData(t, 40000, 51820, []byte("not wireguard at all"))); len(got) != 0 {
		t.Errorf("junk to 51820: got %d discoveries, want 0", len(got))
	}
}

// TCP to the same port numbers follows the TCP path, which has no entry for
// either of them: the UDP classification must not leak into TCP.
func TestTCPToVPNPortsStaysDropped(t *testing.T) {
	cfg := &config.Config{SensorID: "test-sensor"}
	cfg.Capture.DedupTTLMinutes = 1
	cfg.Capture.EnableWireGuard = true
	cfg.Capture.EnableOpenVPN = true
	pc := NewPacketCapture(cfg)
	defer pc.cancel()
	// A real ClientHello, so a leak into the TLS assembler would be visible
	// as a discovery rather than hidden by undecodable bytes.
	for _, port := range []int{51820, 1194} {
		pc.analyzePacket(buildTCPData(t, "192.0.2.10", "192.0.2.20", 50123, port, clientHelloRecord()), "eth0")
	}
	pc.assemblerMu.Lock()
	pc.assembler.FlushAll()
	pc.sshAssembler.FlushAll()
	pc.assemblerMu.Unlock()
	if got := drainDiscoveries(pc); len(got) != 0 {
		t.Errorf("TCP ClientHellos to the UDP-only VPN ports produced %d discoveries, want 0", len(got))
	}
}

// A tunnel sends a transport-data datagram per packet. The decoders emit for
// each one, and the sensor holds at most 1000 discoveries before evicting the
// oldest, so without a per-endpoint dedup a busy tunnel would push real TLS
// findings out of the buffer.
func TestUDPVPNDiscoveriesAreDeduplicatedPerEndpoint(t *testing.T) {
	on := func(c *config.Config) {
		c.Capture.EnableWireGuard = true
		c.Capture.EnableOpenVPN = true
	}
	var pkts []gopacket.Packet
	pkts = append(pkts, buildUDPData(t, 40000, 51820, wgHandshakeInitiation()))
	for i := 0; i < 50; i++ {
		pkts = append(pkts, buildUDPData(t, 40000, 51820, wgTransportData()))
	}
	got := udpDiscoveries(t, on, pkts...)
	if len(got) != 1 || got[0].RawMetadata["wireguard_message_type"] != "Handshake Initiation" {
		t.Fatalf("51 WireGuard datagrams to one endpoint: got %d discoveries, want exactly the first (handshake)", len(got))
	}

	pkts = pkts[:0]
	for i := 0; i < 20; i++ {
		pkts = append(pkts, buildUDPData(t, 40000, 1194, openVPNHardResetClient()))
	}
	if got := udpDiscoveries(t, on, pkts...); len(got) != 1 {
		t.Errorf("20 OpenVPN datagrams to one endpoint: got %d discoveries, want 1", len(got))
	}

	// Different endpoints are not collapsed together.
	if got := udpDiscoveries(t, on,
		buildUDPData(t, 40000, 51820, wgHandshakeInitiation()),
		buildUDPData(t, 40000, 1194, openVPNHardResetClient()),
	); len(got) != 2 {
		t.Errorf("one WireGuard + one OpenVPN datagram: got %d discoveries, want 2", len(got))
	}
}

// The UDP protocols that already worked (because their port also sits in the
// TCP-oriented table) must keep working and keep their flag behaviour.
func TestExistingUDPProtocolsStillDecode(t *testing.T) {
	quic := []byte{0xC0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	ike := make([]byte, 28)
	binary.BigEndian.PutUint64(ike[0:8], 0x1111111111111111)
	ike[16], ike[17], ike[18] = 1, 0x10, ikeExchangeIdentityProtection
	binary.BigEndian.PutUint32(ike[24:28], 28)
	natT := append([]byte{0, 0, 0, 0}, ike...)
	krb := buildMinimalASREQ([]int{18, 17, 23})
	dnp3 := buildDNP3Frame(0x0001, 0x0002, []byte{0xC0, 0xC1, 0x01, 0x32, 0x01, 0x00, 0x00, 0x01})
	hart := buildHARTIPMessage(hartIPMsgPublishNotify, 0x10, 0, 555, 8)

	dnp3On := func(c *config.Config) { c.Capture.EnableDNP3 = true }
	hartOn := func(c *config.Config) { c.Capture.EnableHARTIP = true }
	cases := []struct {
		name     string
		port     int
		payload  []byte
		mutate   func(*config.Config)
		protocol string
		want     int
	}{
		{"QUIC 443", 443, quic, nil, "QUIC", 1},
		{"IKE 500", 500, ike, nil, "IPSec", 1},
		{"IKE NAT-T 4500", 4500, natT, nil, "IPSec", 1},
		{"Kerberos 88", 88, krb, func(c *config.Config) { c.Capture.EnableKerberos = true }, "Kerberos", 1},
		{"DNP3 20000 flag on", 20000, dnp3, dnp3On, "DNP3", 1},
		{"DNP3 20000 flag off", 20000, dnp3, nil, "", 0},
		{"HART-IP 5094 flag on", 5094, hart, hartOn, "HART_IP", 1},
		{"HART-IP 5094 flag off", 5094, hart, nil, "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := udpDiscoveries(t, tc.mutate, buildUDPData(t, 40000, tc.port, tc.payload))
			if len(got) != tc.want {
				t.Fatalf("got %d discoveries, want %d", len(got), tc.want)
			}
			if tc.want == 1 && got[0].Protocol != tc.protocol {
				t.Errorf("protocol = %q, want %q", got[0].Protocol, tc.protocol)
			}
		})
	}
}

// Every UDP port the BPF filter admits must have a decoder to hand it to, or
// the packets are captured and silently dropped, which is how WireGuard and
// OpenVPN went dead. The filter is built with every feature on; host
// observation is left off because its ports belong to the hostobs package.
func TestEveryBPFUDPPortHasAUDPDecoder(t *testing.T) {
	cfg := &config.Config{}
	cfg.Capture.EnableWireGuard = true
	cfg.Capture.EnableOpenVPN = true
	cfg.Capture.EnableKerberos = true
	cfg.Capture.EnableDNP3 = true
	cfg.Capture.EnableHARTIP = true
	filter := buildBPFFilter(cfg)

	terms := regexp.MustCompile(`udp port (\d+)`).FindAllStringSubmatch(filter, -1)
	if len(terms) < 8 {
		t.Fatalf("filter %q yielded only %d udp terms; the extraction is broken", filter, len(terms))
	}
	for _, m := range terms {
		port, _ := strconv.Atoi(m[1])
		if getUDPProtocolFromPort(port) == "" {
			t.Errorf("BPF admits udp port %d but getUDPProtocolFromPort has no decoder for it", port)
		}
	}
}
