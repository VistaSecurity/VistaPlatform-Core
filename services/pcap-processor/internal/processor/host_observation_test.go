package processor

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/vistasecurity/vistaplatform/shared/hostobs"
)

// Packet fixtures, byte-identical to the ones in shared/hostobs/fixtures_test.go
// and in the sensor's own test (see the shared file for how each was assembled
// from its RFC). Using the SAME bytes on both capture paths is the point: if the
// two runtimes ever disagree about what a frame means, one of the two test files
// starts failing.
//
// TestFixturesDecode below keeps that claim honest — a mistyped copy would
// otherwise still satisfy a classification-only assertion.
const (
	// Gratuitous ARP from an Apple device claiming 192.168.10.50.
	pcapARPHex = "000108000604000228cfda112233c0a80a32000000000000c0a80a32"
	// LLDP from a Cisco access switch.
	pcapLLDPHex = "020704001a2f1122330416054769676162697445746865726e6574312f302f323406020078080e55706c696e6b20746f20636f72650a186163636573732d73772d332e636f72702e6578616d706c650c23436973636f20494f5320536f6674776172652c2043333735304520536f6674776172650e0400140014100c0501c0a80a020200000018000000"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad fixture hex: %v", err)
	}
	return b
}

func ethPacket(t *testing.T, src net.HardwareAddr, ethType layers.EthernetType, payload []byte, at time.Time) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       src,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: ethType,
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, eth, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	p.Metadata().Timestamp = at
	return p
}

func TestHostObsCollectorEmitsOneRowPerHost(t *testing.T) {
	at := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	apple := net.HardwareAddr{0x28, 0xcf, 0xda, 0x11, 0x22, 0x33}
	cisco := net.HardwareAddr{0x00, 0x1a, 0x2f, 0x11, 0x22, 0x33}

	c := newHostObsCollector()
	// The same host ARPs repeatedly, as hosts do. One row must come out, not
	// twenty — that is what the coalescer is for.
	for i := 0; i < 20; i++ {
		c.Offer(ethPacket(t, apple, layers.EthernetTypeARP, mustHex(t, pcapARPHex), at.Add(time.Duration(i)*time.Second)))
	}
	c.Offer(ethPacket(t, cisco, layers.EthernetTypeLinkLayerDiscovery, mustHex(t, pcapLLDPHex), at))

	got := c.Discoveries()
	if len(got) != 2 {
		t.Fatalf("got %d discoveries, want 2 (one per host): %+v", len(got), got)
	}

	byMAC := map[string]CryptoDiscovery{}
	for _, d := range got {
		if d.Protocol != "HOST" {
			t.Errorf("Protocol = %q, want HOST", d.Protocol)
		}
		if d.DiscoveryType != "host_observation" {
			t.Errorf("DiscoveryType = %q", d.DiscoveryType)
		}
		if d.DiscoveryMethod != "pcap_upload" {
			t.Errorf("DiscoveryMethod = %q", d.DiscoveryMethod)
		}
		if d.DestPort != 0 {
			t.Errorf("DestPort = %d; a host is not an endpoint and the column is NOT NULL, so 0 is the documented value", d.DestPort)
		}
		if d.HostObservation == nil {
			t.Fatal("HostObservation is nil on a host-observation discovery")
		}
		byMAC[d.HostObservation.MAC] = d
	}

	arp, ok := byMAC["28:cf:da:11:22:33"]
	if !ok {
		t.Fatalf("no observation for the ARP sender: %v", byMAC)
	}
	if arp.DestIP != "192.168.10.50" {
		t.Errorf("ARP DestIP = %q", arp.DestIP)
	}
	if arp.HostObservation.Vendor != "Apple" {
		t.Errorf("ARP vendor = %q, want Apple from the OUI table", arp.HostObservation.Vendor)
	}
	// The merged observation carries the LATEST frame's time: a capture file's
	// "last seen" is the last time the host appeared in it.
	if !arp.Timestamp.Equal(at.Add(19 * time.Second)) {
		t.Errorf("ARP timestamp = %v, want the last frame's %v", arp.Timestamp, at.Add(19*time.Second))
	}

	lldp, ok := byMAC["00:1a:2f:11:22:33"]
	if !ok {
		t.Fatalf("no observation for the LLDP advertiser: %v", byMAC)
	}
	// The advertiser is the subject, identified by its own chassis MAC and
	// name. No adjacency is claimed: the sensor-side reasoning applies here
	// too, and a file additionally has no capture interface to name.
	if len(lldp.HostObservation.FQDNs) == 0 {
		t.Errorf("LLDP advertiser has no name: %#v", lldp.HostObservation)
	}
	if _, present := lldp.HostObservation.Facts["net.neighbors"]; present {
		t.Errorf("pcap LLDP decode wrote net.neighbors: %v", lldp.HostObservation.Facts)
	}
	if _, present := lldp.HostObservation.Attributes["capture_interface"]; present {
		t.Errorf("a file named a capture interface: %v", lldp.HostObservation.Attributes)
	}
}

func TestHostObsMetadataCarriesTheObservation(t *testing.T) {
	obs := &hostobs.HostObservation{
		Source:    hostobs.SourceLLDP,
		MAC:       "00:1a:2f:11:22:33",
		Hostnames: []string{"access-sw-3"},
		FQDNs:     []string{"access-sw-3.corp.example"},
	}
	obs.Finalize()

	meta := buildDiscoveryMetadata(CryptoDiscovery{
		Protocol:        "HOST",
		DiscoveryType:   "host_observation",
		HostObservation: obs,
	})

	if meta["discovery_type"] != "host_observation" {
		t.Errorf("discovery_type = %v", meta["discovery_type"])
	}
	// The FQDN, not the short name: it is the one a CMDB can join on.
	if meta["hostname"] != "access-sw-3.corp.example" {
		t.Errorf("hostname = %v, want the fully-qualified name", meta["hostname"])
	}

	// The payload has to survive the JSON round trip the column forces, with
	// the key names the wire contract promises the consumer.
	blob, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatal(err)
	}
	ho, ok := back["host_observation"].(map[string]any)
	if !ok {
		t.Fatalf("host_observation did not survive as an object: %s", blob)
	}
	for _, k := range []string{"mac", "source", "vendor", "facts"} {
		if _, ok := ho[k]; !ok {
			t.Errorf("host_observation is missing %q: %s", k, blob)
		}
	}
	if ho["vendor"] != "Cisco Systems" {
		t.Errorf("vendor = %v, want the OUI-derived Cisco Systems", ho["vendor"])
	}
}

func TestCryptoDiscoveriesCarryNoHostObservation(t *testing.T) {
	// The two shapes must stay disjoint: a TLS row with a host_observation key
	// would make the consumer's kind check ambiguous.
	meta := buildDiscoveryMetadata(CryptoDiscovery{
		Protocol:      "TLS",
		DiscoveryType: "tls_session",
		SNI:           "api.example.com",
	})
	if _, ok := meta["host_observation"]; ok {
		t.Errorf("a TLS discovery carried a host_observation key: %v", meta)
	}
}

func TestClassifyHostObsMatchesTheSharedDecision(t *testing.T) {
	// This runtime's plumbing must reach the same verdict as the sensor's for
	// the same frame. Both call shared/hostobs to decide; this pins that the
	// pcap side actually asks rather than deciding for itself.
	apple := net.HardwareAddr{0x28, 0xcf, 0xda, 0x11, 0x22, 0x33}

	kind, payload, mac, _ := classifyHostObs(
		ethPacket(t, apple, layers.EthernetTypeARP, mustHex(t, pcapARPHex), time.Now()))
	if kind != hostobs.KindARP {
		t.Errorf("kind = %v, want ARP", kind)
	}
	if mac != "28:cf:da:11:22:33" {
		t.Errorf("srcMAC = %q", mac)
	}
	if len(payload) == 0 {
		t.Error("empty payload for a classified frame")
	}

	// A TLS packet must fall straight through — the crypto path owns it.
	eth := &layers.Ethernet{SrcMAC: apple, DstMAC: apple, EthernetType: layers.EthernetTypeIPv4}
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
	if kind, _, _, _ := classifyHostObs(p); kind != hostobs.KindNone {
		t.Errorf("a TLS packet classified as %v", kind)
	}
}

// TestFixturesDecode proves the hex above is what its comment says it is.
//
// The collector tests assert on the decoded RESULT, so a mistyped blob would
// mostly surface there — but as a confusing failure about a missing MAC rather
// than as "the fixture is wrong". This says which.
func TestFixturesDecode(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind hostobs.Kind
		hex  string
		mac  string
	}{
		{"arp", hostobs.KindARP, pcapARPHex, "28:cf:da:11:22:33"},
		{"lldp", hostobs.KindLLDP, pcapLLDPHex, "00:1a:2f:11:22:33"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs, err := hostobs.Decode(tc.kind, hostobs.Frame{
				Payload: mustHex(t, tc.hex),
				SrcMAC:  tc.mac,
				At:      time.Now(),
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

// TestPcapDNSIsNotDecoded pins that a capture FILE gets the same default as a
// live sensor.
//
// A file has no BPF filter to shed UDP 53 with, so the classifier gate is the
// only thing standing between an uploaded capture and a record of every name
// that network resolved. The reason is the same as the sensor's: the decoder
// reads answers only and never the question section, but an answer names what
// was asked, and an uploader handing over a capture of their segment did not
// ask for that to be extracted.
//
// mDNS in the same file is still decoded — it is a device advertising itself,
// not a lookup — which is what makes this test about DNS rather than about the
// collector being switched off.
func TestPcapDNSIsNotDecoded(t *testing.T) {
	c := newHostObsCollector()
	at := time.Now()
	resolver := net.HardwareAddr{0x00, 0x1e, 0x8f, 0xaa, 0xbb, 0xcc}

	c.Offer(udpPacket(t, resolver, "10.0.0.53", "10.0.0.9", 53, 40000,
		mustHex(t, pcapDNSAnswerHex), at))

	if c.decoded != 0 {
		t.Errorf("a DNS answer in the capture was decoded (%d)", c.decoded)
	}
	if got := len(c.Discoveries()); got != 0 {
		t.Errorf("a DNS answer produced %d discoveries", got)
	}

	// The same collector still decodes what it should.
	c = newHostObsCollector()
	c.Offer(ethPacket(t, net.HardwareAddr{0x28, 0xcf, 0xda, 0x11, 0x22, 0x33},
		layers.EthernetTypeARP, mustHex(t, pcapARPHex), at))
	if c.decoded != 1 {
		t.Errorf("ARP decoded %d times; only DNS is off", c.decoded)
	}
}

// A unicast DNS response: one question, one A answer for "app.corp.example".
// Assembled field by field from RFC 1035.
const pcapDNSAnswerHex = "1234818000010001000000000361707004636f7270076578616d706c65000001" +
	"00010361707004636f7270076578616d706c6500000100010000007800040a010203"

// udpPacket frames a UDP payload the way the wire would, so the file path is
// exercised against a real gopacket decode.
func udpPacket(t *testing.T, srcMAC net.HardwareAddr, srcIP, dstIP string, srcPort, dstPort int, payload []byte, at time.Time) gopacket.Packet {
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
	p.Metadata().Timestamp = at
	return p
}

// A real 802.3 CDP frame, whole: destination 01:00:0c:cc:cc:cc, a LENGTH field
// (not an EtherType), the 802.2 LLC/SNAP header, then the CDP body with the
// device ID, port ID and platform TLVs. Assembled from the Cisco specification,
// not by this package's encoder.
const pcapCDPBodyHex = "02b40000000100196361622d73772d312e636f72702e6578616d706c65000300164769676162697445746865726e6574302f3200060019636973636f2057532d43323936302d323454542d4c"

func pcapCDP8023Frame(t *testing.T, src net.HardwareAddr) []byte {
	t.Helper()
	llc := append([]byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00}, mustHex(t, pcapCDPBodyHex)...)
	frame := []byte{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc}
	frame = append(frame, src...)
	frame = append(frame, byte(len(llc)>>8), byte(len(llc)))
	return append(frame, llc...)
}

// TestPcapCDPClassifiesThroughARealGopacketDecode is the one path in this feature
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
func TestPcapCDPClassifiesThroughARealGopacketDecode(t *testing.T) {
	cisco := net.HardwareAddr{0x00, 0x0f, 0x23, 0xaa, 0xbb, 0xcc}
	p := gopacket.NewPacket(pcapCDP8023Frame(t, cisco), layers.LayerTypeEthernet, gopacket.Default)
	p.Metadata().Timestamp = time.Now()

	kind, payload, srcMAC, _ := classifyHostObs(p)
	if kind != hostobs.KindCDP {
		t.Fatalf("classify = %v, want CDP — a CDP frame in a capture file is not reaching the decoder", kind)
	}
	if srcMAC != "00:0f:23:aa:bb:cc" {
		t.Errorf("srcMAC = %q", srcMAC)
	}

	// And all the way through the decoder, so the payload handed over is the
	// CDP body and not the LLC/SNAP header.
	obs, err := hostobs.Decode(kind, hostobs.Frame{Payload: payload, SrcMAC: srcMAC})
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

// A replayed capture grades a host exactly as the live sensor does.
//
// This row and a live sensor's row for the same host land in the same
// `sensor_discoveries` table, are read by the same auto-approval rules, and
// become the same asset. Before the ladder moved into shared/hostobs this
// function wrote a flat 0.85 for every discovery it produced, so an LLDP
// advertisement the sensor graded 0.95 arrived here as 0.85 and a DNS answer
// graded 0.60 arrived as 0.85 as well — a rule reading `confidence >= 0.9`
// fired on one runtime and not the other, and one reading `confidence >= 0.8`
// fired on a DNS answer it was never meant to.
//
// The drift was invisible for exactly one reason: nothing asserted a NUMBER.
// So this asserts numbers, and it asserts them against hostobs.Confidence
// rather than against literals, which is what makes it fail when the two
// runtimes are given different ladders rather than when the ladder changes.
//
// Mutation check: put `0.85` back in place of `pipelineConfidence(d)` in
// processor.go — or make this function return a constant — and this fails.
func TestPipelineConfidenceGradesHostObservationsOnTheSharedLadder(t *testing.T) {
	for _, tc := range []struct {
		source string
		want   float64
	}{
		{hostobs.SourceLLDP, 0.95},
		{hostobs.SourceCDP, 0.95},
		{hostobs.SourceDHCP, 0.95},
		{hostobs.SourceARP, 0.85},
		{hostobs.SourceNBNS, 0.85},
		{hostobs.SourceMDNS, 0.80},
		{hostobs.SourceDNS, 0.60},
	} {
		t.Run(tc.source, func(t *testing.T) {
			obs := &hostobs.HostObservation{Source: tc.source, MAC: "28:cf:da:11:22:33"}
			obs.Finalize()
			d := CryptoDiscovery{HostObservation: obs}

			got := pipelineConfidence(d)
			// Against the shared ladder first: that is the invariant, and it
			// keeps holding if the ladder is ever re-graded.
			if want := hostobs.Confidence(obs); got != want {
				t.Errorf("confidence = %v, want the shared ladder's %v — the two capture runtimes must grade one host identically", got, want)
			}
			// And against the value, because the ladder itself drifting
			// silently is the other half of the same failure.
			if got != tc.want {
				t.Errorf("confidence = %v, want %v", got, tc.want)
			}
		})
	}

	// The strongest contributing source wins, so a host seen over ARP and then
	// over DHCP is graded on the DHCP exchange — which the flat value could
	// never express.
	multi := &hostobs.HostObservation{
		Source: hostobs.SourceARP, Sources: []string{hostobs.SourceARP, hostobs.SourceDHCP},
		MAC: "28:cf:da:11:22:34",
	}
	if got := pipelineConfidence(CryptoDiscovery{HostObservation: multi}); got != 0.95 {
		t.Errorf("ARP+DHCP graded %v, want 0.95 — the best contributing source wins", got)
	}

	// A CRYPTO discovery keeps the existing 0.85. It is not graded by anything
	// here — the PCAP path measures what it measures — and changing it would be
	// a separate decision about a separate pipeline.
	if got := pipelineConfidence(CryptoDiscovery{Protocol: "TLS"}); got != 0.85 {
		t.Errorf("a crypto discovery graded %v, want the unchanged 0.85", got)
	}
}
