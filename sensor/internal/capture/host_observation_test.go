package capture

import (
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
)

// buildEthernet frames a payload the way the wire would, so classification is
// exercised against a real gopacket decode rather than a hand-made struct.
func buildEthernet(t *testing.T, src, dst net.HardwareAddr, ethType layers.EthernetType, payload []byte) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: src, DstMAC: dst, EthernetType: ethType}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{},
		eth, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	p.Metadata().Timestamp = time.Unix(1789000000, 0).UTC()
	return p
}

func buildUDP(t *testing.T, srcMAC net.HardwareAddr, srcIP, dstIP string, srcPort, dstPort int, payload []byte) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.ParseIP(srcIP), DstIP: net.ParseIP(dstIP),
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
	p.Metadata().Timestamp = time.Unix(1789000000, 0).UTC()
	return p
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// Packet fixtures, byte-identical to the ones in shared/hostobs/fixtures_test.go
// (see there for how each was assembled from its RFC). Using the SAME bytes on
// both capture paths is the point: if the two runtimes ever disagree about what
// a frame means, one of the two test files starts failing.
//
// TestFixturesDecode below is what keeps that claim honest — a mistyped copy
// would otherwise still satisfy a classification-only assertion.
const (
	// Gratuitous ARP reply from an Apple device claiming 192.168.10.50.
	arpHex = "000108000604000228cfda112233c0a80a32000000000000c0a80a32"
	// LLDP from a Cisco access switch.
	lldpHex = "020704001a2f1122330416054769676162697445746865726e6574312f302f323406020078080e55706c696e6b20746f20636f72650a186163636573732d73772d332e636f72702e6578616d706c650c23436973636f20494f5320536f6674776172652c2043333735304520536f6674776172650e0400140014100c0501c0a80a020200000018000000"
	// mDNS response announcing hp-printer.local with an _ipp._tcp service.
	mdnsHex = "1234840000000004000000000a68702d7072696e746572056c6f63616c0000018001000000780004c0a80a4d0b4850204c617365724a6574045f697070045f746370056c6f63616c00002180010000007800180000000002770a68702d7072696e746572056c6f63616c00045f697070045f746370056c6f63616c00000c000100000078001d0b4850204c617365724a6574045f697070045f746370056c6f63616c000a68702d7072696e746572056c6f63616c00001080010000007800060574793d4850"
)

func TestClassifyHostObs(t *testing.T) {
	apple := net.HardwareAddr{0x28, 0xcf, 0xda, 0x11, 0x22, 0x33}
	cisco := net.HardwareAddr{0x00, 0x1a, 0x2f, 0x11, 0x22, 0x33}
	bcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	t.Run("ARP", func(t *testing.T) {
		p := buildEthernet(t, apple, bcast, layers.EthernetTypeARP, mustHex(t, arpHex))
		f, ok := classifyHostObs(p, "eth0")
		if !ok || f.kind != hostobs.KindARP {
			t.Fatalf("classify = (%v, %v), want ARP", f.kind, ok)
		}
	})

	t.Run("LLDP", func(t *testing.T) {
		p := buildEthernet(t, cisco, net.HardwareAddr{0x01, 0x80, 0xc2, 0, 0, 0x0e},
			layers.EthernetTypeLinkLayerDiscovery, mustHex(t, lldpHex))
		f, ok := classifyHostObs(p, "eth0")
		if !ok || f.kind != hostobs.KindLLDP {
			t.Fatalf("classify = (%v, %v), want LLDP", f.kind, ok)
		}
		if f.srcMAC != "00:1a:2f:11:22:33" {
			t.Errorf("srcMAC = %q", f.srcMAC)
		}
	})

	t.Run("mDNS over UDP", func(t *testing.T) {
		p := buildUDP(t, apple, "192.168.10.77", "224.0.0.251", 5353, 5353, mustHex(t, mdnsHex))
		f, ok := classifyHostObs(p, "eth0")
		if !ok || f.kind != hostobs.KindMDNS {
			t.Fatalf("classify = (%v, %v), want mDNS", f.kind, ok)
		}
		if f.srcAddr.String() != "192.168.10.77" {
			t.Errorf("srcAddr = %v", f.srcAddr)
		}
	})

	t.Run("TLS traffic is not a candidate", func(t *testing.T) {
		// The crypto paths must be untouched: a TCP 443 packet has to fall
		// straight through classification.
		eth := &layers.Ethernet{SrcMAC: apple, DstMAC: cisco, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
			SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2")}
		tcp := &layers.TCP{SrcPort: 40000, DstPort: 443}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf,
			gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
			eth, ip, tcp, gopacket.Payload([]byte{0x16, 0x03, 0x01})); err != nil {
			t.Fatal(err)
		}
		p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
		if _, ok := classifyHostObs(p, "eth0"); ok {
			t.Error("a TLS packet was classified as a host observation candidate")
		}
	})

	t.Run("payload is copied, not aliased", func(t *testing.T) {
		// libpcap reuses its buffer. A decoder handed the original slice would
		// see whatever arrived next.
		raw := mustHex(t, arpHex)
		p := buildEthernet(t, apple, bcast, layers.EthernetTypeARP, raw)
		f, ok := classifyHostObs(p, "eth0")
		if !ok {
			t.Fatal("not classified")
		}
		before := f.payload[8]
		// Scribble over the packet's own backing array.
		for i := range p.Data() {
			p.Data()[i] = 0xaa
		}
		if f.payload[8] != before {
			t.Error("the handed-off payload aliases the capture buffer")
		}
	})
}

func TestHostObsPipelineEmitsDiscovery(t *testing.T) {
	out := make(chan *models.CryptoDiscovery, 8)
	p := newHostObsPipeline("sensor-1", out, time.Millisecond, hostobs.Config{})

	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx)

	apple := net.HardwareAddr{0x28, 0xcf, 0xda, 0x11, 0x22, 0x33}
	bcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	p.Offer(buildEthernet(t, apple, bcast, layers.EthernetTypeARP, mustHex(t, arpHex)), "eth0")

	// Cancelling drains whatever the window still holds, so the test does not
	// have to wait out a real coalescing window.
	cancel()
	p.Stop()

	select {
	case d := <-out:
		if d.Protocol != "HOST" {
			t.Errorf("Protocol = %q, want HOST", d.Protocol)
		}
		if d.DiscoveryMethod != "passive_host_observation" {
			t.Errorf("DiscoveryMethod = %q", d.DiscoveryMethod)
		}
		if d.DiscoveryType != "host_observation" {
			t.Errorf("DiscoveryType = %q", d.DiscoveryType)
		}
		if d.Port != 0 {
			t.Errorf("Port = %d; sensor_discoveries.port is NOT NULL and a host is not an endpoint, so 0 is the documented value", d.Port)
		}
		if d.DestIP != "192.168.10.50" {
			t.Errorf("DestIP = %q", d.DestIP)
		}
		// The envelope rule: fields that do not apply stay EMPTY rather than
		// carrying a plausible-looking zero.
		if d.Version != "" || d.CipherSuite != "" || d.KeySize != 0 {
			t.Errorf("crypto fields populated on a host observation: version=%q cipher=%q keysize=%d",
				d.Version, d.CipherSuite, d.KeySize)
		}
		if d.RawMetadata["discovery_type"] != "host_observation" {
			t.Errorf("raw_metadata.discovery_type = %v", d.RawMetadata["discovery_type"])
		}
		obs, ok := d.RawMetadata["host_observation"].(*hostobs.HostObservation)
		if !ok {
			t.Fatalf("raw_metadata.host_observation = %T, want *hostobs.HostObservation", d.RawMetadata["host_observation"])
		}
		if obs.MAC != "28:cf:da:11:22:33" || obs.Vendor != "Apple" {
			t.Errorf("observation = %+v", obs)
		}
	default:
		t.Fatal("no discovery emitted")
	}

	m := p.Metrics()
	if m["host_observations_emitted"].(int64) != 1 {
		t.Errorf("emitted = %v, want 1", m["host_observations_emitted"])
	}
	if m["host_observations_decoded"].(int64) != 1 {
		t.Errorf("decoded = %v, want 1", m["host_observations_decoded"])
	}
}

func TestHostObsQueueDropsAreCounted(t *testing.T) {
	// The pipeline is NOT started, so nothing drains the hand-off channel. The
	// point is that a saturated queue sheds frames and says so, rather than
	// blocking a capture worker.
	p := newHostObsPipeline("sensor-1", make(chan *models.CryptoDiscovery, 1), time.Minute, hostobs.Config{})

	apple := net.HardwareAddr{0x28, 0xcf, 0xda, 0x11, 0x22, 0x33}
	bcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	pkt := buildEthernet(t, apple, bcast, layers.EthernetTypeARP, mustHex(t, arpHex))

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < hostObsQueueDepth+16; i++ {
			p.Offer(pkt, "eth0")
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Offer blocked on a full queue; it must always shed")
	}

	if got := p.Metrics()["host_observations_queue_dropped"].(int64); got < 16 {
		t.Errorf("queue_dropped = %d, want at least 16", got)
	}
}

func TestBPFFilterCarriesHostObservationTerms(t *testing.T) {
	// The wiring check, not the content check — shared/hostobs owns which terms
	// are needed and has its own test for that. What this pins is that the
	// sensor actually ASKS for them, and only when the feature is on. Enabling
	// the decoders without widening the filter gives a pipeline that runs,
	// reports success and never sees a frame.
	on := &config.Config{}
	on.Capture.HostObservation = true
	filter := buildBPFFilter(on)
	for _, term := range hostobs.BPFTerms(hostobs.Config{}) {
		if !strings.Contains(filter, term) {
			t.Errorf("capture filter is missing %q: %s", term, filter)
		}
	}
	// The crypto terms must survive alongside them.
	if !strings.Contains(filter, "tcp port 443") {
		t.Errorf("host observation displaced the crypto filter: %s", filter)
	}

	off := &config.Config{}
	off.Capture.HostObservation = false
	quiet := buildBPFFilter(off)
	if strings.Contains(quiet, "ether proto 0x88cc") {
		t.Errorf("host-observation terms present with the feature off, widening capture for nothing: %s", quiet)
	}
	if !strings.Contains(quiet, "tcp port 443") {
		t.Errorf("crypto filter broken with the feature off: %s", quiet)
	}
}

func TestHostObsConfidenceGrading(t *testing.T) {
	// A DNS answer is a third party's claim about a host that may not even be
	// on this segment; an LLDP advertisement is the device stating its own
	// identity. Grading them the same would put hearsay and measurement into
	// the same column with the same weight.
	lldp := &hostobs.HostObservation{Source: hostobs.SourceLLDP, MAC: "00:1a:2f:11:22:33"}
	lldp.Finalize()
	dns := &hostobs.HostObservation{Source: hostobs.SourceDNS, Hostnames: []string{"app"}}
	dns.Finalize()

	if hostObsConfidence(lldp) <= hostObsConfidence(dns) {
		t.Errorf("LLDP confidence %v is not above DNS %v",
			hostObsConfidence(lldp), hostObsConfidence(dns))
	}
	// numeric(3,2) in the column: anything at or above 10 would be rejected by
	// Postgres, which surfaces as a whole batch failing to insert.
	if c := hostObsConfidence(lldp); c <= 0 || c >= 10 {
		t.Errorf("confidence %v is outside numeric(3,2)", c)
	}
}

// TestFixturesDecode proves the hex above is what its comment says it is.
//
// Every other test in this file asserts CLASSIFICATION — which decoder a frame
// belongs to — and a mistyped blob would pass all of them, because
// classification reads the Ethernet header and never looks at the payload. This
// is the assertion that fails when a copied fixture drifts from the shared one.
func TestFixturesDecode(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind hostobs.Kind
		hex  string
		mac  string
	}{
		{"arp", hostobs.KindARP, arpHex, "28:cf:da:11:22:33"},
		{"lldp", hostobs.KindLLDP, lldpHex, "00:1a:2f:11:22:33"},
		{"mdns", hostobs.KindMDNS, mdnsHex, "00:1e:8f:aa:bb:cc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs, err := hostobs.Decode(tc.kind, hostobs.Frame{
				Payload: mustHex(t, tc.hex),
				SrcMAC:  tc.mac,
				// The frame's own source address, which is what lets the mDNS
				// decoder attribute the announcement to the sender at all: a
				// response whose records do not name the address it came from
				// was relayed, and its MAC belongs to the reflector.
				SrcAddr: netip.MustParseAddr("192.168.10.77"),
				At:      time.Unix(1789000000, 0).UTC(),
			})
			if err != nil {
				t.Fatalf("fixture does not decode as %v: %v", tc.kind, err)
			}
			if obs.MAC != tc.mac {
				t.Errorf("MAC = %q, want %q", obs.MAC, tc.mac)
			}
		})
	}
}

// TestDNSDecoderIsOptInOnTheSensor is the sensor-side half of the opt-in.
// shared/hostobs owns the decision and has its own test for it; what this pins
// is that the sensor asks the shared package rather than deciding for itself,
// in BOTH places it has to — the capture filter and the classifier gate.
//
// The two are separate because they fail differently. A filter that asks for
// UDP 53 when nobody turned DNS on hauls every query on the segment into the
// worker pool for nothing; a classifier that decodes UDP 53 anyway records
// resolutions nobody consented to, whatever the filter said.
func TestDNSDecoderIsOptInOnTheSensor(t *testing.T) {
	base := &config.Config{}
	base.Capture.HostObservation = true

	t.Run("filter", func(t *testing.T) {
		// Term by term: "udp port 53" is a substring of "udp port 5353", so a
		// Contains check on the joined filter would match the mDNS term and
		// could never fail.
		off := buildBPFFilter(base)
		for _, term := range strings.Split(off, " or ") {
			if term == "udp port 53" {
				t.Errorf("the default filter asks for UDP 53: %s", off)
			}
		}
		if !strings.Contains(off, "udp port 5353") {
			t.Errorf("mDNS was switched off with DNS; only DNS is opt-in: %s", off)
		}

		on := *base
		on.Capture.HostObservationDNS = true
		got := buildBPFFilter(&on)
		found := false
		for _, term := range strings.Split(got, " or ") {
			if term == "udp port 53" {
				found = true
			}
		}
		if !found {
			t.Errorf("HostObservationDNS did not reach the capture filter: %s", got)
		}
	})

	t.Run("classifier", func(t *testing.T) {
		out := make(chan *models.CryptoDiscovery, 4)
		p := newHostObsPipeline("sensor-1", out, time.Minute, hostObsConfig(base))
		p.Offer(buildUDP(t, net.HardwareAddr{0x00, 0x1e, 0x8f, 0xaa, 0xbb, 0xcc},
			"10.0.0.53", "10.0.0.9", 53, 40000, mustHex(t, dnsAnswerHex)), "eth0")
		if got := p.Metrics()["host_observations_offered"].(int64); got != 0 {
			t.Errorf("a DNS response was offered to the decoders with DNS off (offered=%d)", got)
		}

		onCfg := *base
		onCfg.Capture.HostObservationDNS = true
		p = newHostObsPipeline("sensor-1", out, time.Minute, hostObsConfig(&onCfg))
		p.Offer(buildUDP(t, net.HardwareAddr{0x00, 0x1e, 0x8f, 0xaa, 0xbb, 0xcc},
			"10.0.0.53", "10.0.0.9", 53, 40000, mustHex(t, dnsAnswerHex)), "eth0")
		if got := p.Metrics()["host_observations_offered"].(int64); got != 1 {
			t.Errorf("opting in did not reach the classifier (offered=%d)", got)
		}
	})
}

// A unicast DNS response: one question, one A answer for "app.corp.example".
// Built field by field from RFC 1035, not by this package's encoder.
const dnsAnswerHex = "1234818000010001000000000361707004636f7270076578616d706c65000001" +
	"00010361707004636f7270076578616d706c6500000100010000007800040a010203"

// A real 802.3 CDP frame, whole: destination 01:00:0c:cc:cc:cc, a LENGTH field
// (not an EtherType), the 802.2 LLC/SNAP header, then the CDP body with the
// device ID, port ID and platform TLVs. Assembled from the Cisco specification,
// not by this package's encoder.
const cdpBodyHex = "02b40000000100196361622d73772d312e636f72702e6578616d706c65000300164769676162697445746865726e6574302f3200060019636973636f2057532d43323936302d323454542d4c"

func cdp8023Frame(t *testing.T, src net.HardwareAddr) []byte {
	t.Helper()
	llc := append([]byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00}, mustHex(t, cdpBodyHex)...)
	frame := []byte{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc}
	frame = append(frame, src...)
	frame = append(frame, byte(len(llc)>>8), byte(len(llc)))
	return append(frame, llc...)
}

// TestCDPClassifiesThroughARealGopacketDecode is the one path in this feature
// that no other test covers, and it is the one most likely to break silently.
//
// CDP is not an EtherType protocol. On the wire its ethertype field is a
// LENGTH, and gopacket does not hand that length back: it moves the value into
// Ethernet.Length and OVERWRITES Ethernet.EthernetType with the sentinel
// EthernetTypeLLC. So the number ClassifyEther is given for a CDP frame is
// never the number the wire carried — the dispatch works because that sentinel
// also happens to be below the 1500 boundary.
//
// Every other CDP test in this repo builds the classifier input by hand and so
// cannot see that. If the sentinel ever moved above 1500, or gopacket started
// stripping the LLC/SNAP header into its own layer, CDP would stop being
// decoded and NOTHING would report it: no error, no malformed count, just a
// segment whose switches quietly never appear. That is exactly the "runs,
// reports success, sees nothing" failure this package was built to avoid.
func TestCDPClassifiesThroughARealGopacketDecode(t *testing.T) {
	cisco := net.HardwareAddr{0x00, 0x0f, 0x23, 0xaa, 0xbb, 0xcc}
	p := gopacket.NewPacket(cdp8023Frame(t, cisco), layers.LayerTypeEthernet, gopacket.Default)
	p.Metadata().Timestamp = time.Unix(1789000000, 0).UTC()

	f, ok := classifyHostObs(p, "eth0")
	if !ok || f.kind != hostobs.KindCDP {
		t.Fatalf("classify = (%v, %v), want CDP — a live CDP frame is not reaching the decoder", f.kind, ok)
	}
	if f.srcMAC != "00:0f:23:aa:bb:cc" {
		t.Errorf("srcMAC = %q", f.srcMAC)
	}

	// And all the way through the decoder, so the payload handed over is the
	// CDP body and not the LLC/SNAP header.
	obs, err := hostobs.Decode(f.kind, hostobs.Frame{Payload: f.payload, SrcMAC: f.srcMAC, At: f.at})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(obs.FQDNs) == 0 || obs.FQDNs[0] != "cab-sw-1.corp.example" {
		t.Errorf("device ID lost between gopacket and the decoder: %#v", obs.FQDNs)
	}
	if obs.Model != "WS-C2960-24TT-L" {
		t.Errorf("Model = %q", obs.Model)
	}
}
