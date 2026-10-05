package capture

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// Passive TLS posture comes from BOTH directions of a connection.
//
// The ClientHello (client -> server) carries SNI, JA3/JA4 and the client's
// offer; only the ServerHello (server -> client) carries what was NEGOTIATED —
// the protocol version and cipher suite — and, for TLS <= 1.2, the server's
// certificate chain. For third parties passive capture is the only source of
// posture (they are never actively probed), so a sensor that only ever sees
// the ClientHello can score nothing.
//
// These tests drive the REAL capture path — analyzePacket, the tcpassembly
// assembler, the TLS stream factory — with a client -> server and a
// server -> client half of one connection, as a sensor on the client host
// captures them. They pin three things that each independently broke it:
//   - analyzePacket classified a TCP packet by DESTINATION port only, so every
//     server -> client segment (destination = the client's ephemeral port)
//     was discarded before it reached the assembler;
//   - tcpassembly creates one stream per DIRECTION, and the factory gave each
//     its own session state, so a ServerHello could never join the
//     ClientHello it answered (and the endpoint dedup let only one half out);
//   - only the first handshake message in a record was parsed, so a server
//     flight coalesced into one record (ServerHello + Certificate + ...) lost
//     its certificate.

const (
	bidiClientIP   = "192.0.2.10"
	bidiServerIP   = "203.0.113.5"
	bidiClientPort = 50123
)

// tcpSegment frames one TCP segment with explicit sequence numbers and flags.
func tcpSegment(t *testing.T, srcIP, dstIP string, srcPort, dstPort int, seq, ack uint32, syn bool, payload []byte) gopacket.Packet {
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
		Seq: seq, Ack: ack, SYN: syn, ACK: ack != 0, PSH: len(payload) > 0, Window: 65535,
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

// tlsRecord wraps body in a TLS record header of the given content type.
func tlsRecord(contentType byte, body []byte) []byte {
	rec := []byte{contentType, 0x03, 0x03, byte(len(body) >> 8), byte(len(body))}
	return append(rec, body...)
}

// testCertDER returns a freshly minted self-signed ECDSA P-256 leaf.
func testCertDER(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// certificateMsg builds a TLS <= 1.2 Certificate handshake body for one cert.
func certificateMsg(der []byte) []byte {
	entry := []byte{byte(len(der) >> 16), byte(len(der) >> 8), byte(len(der))}
	entry = append(entry, der...)
	body := []byte{byte(len(entry) >> 16), byte(len(entry) >> 8), byte(len(entry))}
	return append(body, entry...)
}

// captureConnection feeds a client->server flight and a server->client flight
// of one connection (after a SYN / SYN-ACK, as a live capture sees it) through
// the real analyzePacket, then closes the assembler and returns every TLS
// discovery the capture path produced. serverSegments may split the server
// flight across several TCP segments.
func captureConnection(t *testing.T, serverPort int, clientFlight []byte, serverSegments ...[]byte) []*models.CryptoDiscovery {
	t.Helper()
	cfg := &config.Config{SensorID: "test-sensor"}
	cfg.Capture.DedupTTLMinutes = 1
	pc := NewPacketCapture(cfg)
	defer pc.cancel()

	const clientISN, serverISN = uint32(1000), uint32(9000)
	pc.analyzePacket(tcpSegment(t, bidiClientIP, bidiServerIP, bidiClientPort, serverPort, clientISN, 0, true, nil), "eth0")
	pc.analyzePacket(tcpSegment(t, bidiServerIP, bidiClientIP, serverPort, bidiClientPort, serverISN, clientISN+1, true, nil), "eth0")
	pc.analyzePacket(tcpSegment(t, bidiClientIP, bidiServerIP, bidiClientPort, serverPort, clientISN+1, serverISN+1, false, clientFlight), "eth0")
	seq := serverISN + 1
	for _, seg := range serverSegments {
		pc.analyzePacket(tcpSegment(t, bidiServerIP, bidiClientIP, serverPort, bidiClientPort, seq, clientISN+1+uint32(len(clientFlight)), false, seg), "eth0")
		seq += uint32(len(seg))
	}

	pc.assemblerMu.Lock()
	pc.assembler.FlushAll()
	pc.assemblerMu.Unlock()

	var out []*models.CryptoDiscovery
	for _, d := range drainDiscoveries(pc) {
		if d.Protocol == "TLS" {
			out = append(out, d)
		}
	}
	return out
}

func handshakeTypesOf(d *models.CryptoDiscovery) map[string]bool {
	seen := map[string]bool{}
	if types, ok := d.RawMetadata["handshake_types"].([]string); ok {
		for _, ht := range types {
			seen[ht] = true
		}
	}
	return seen
}

// assertOneJoinedDiscovery checks the connection produced exactly ONE
// discovery, oriented client -> server, carrying both hellos.
func assertOneJoinedDiscovery(t *testing.T, got []*models.CryptoDiscovery, port int) *models.CryptoDiscovery {
	t.Helper()
	if len(got) != 1 {
		for i, d := range got {
			t.Logf("discovery %d: %s -> %s:%d version=%q cipher=%q types=%v", i, d.SourceIP, d.DestIP, d.Port, d.Version, d.CipherSuite, d.RawMetadata["handshake_types"])
		}
		t.Fatalf("got %d TLS discoveries for one connection, want exactly 1 (both directions joined)", len(got))
	}
	d := got[0]
	if d.SourceIP != bidiClientIP || d.DestIP != bidiServerIP || d.Port != port {
		t.Errorf("orientation = %s -> %s:%d, want %s -> %s:%d", d.SourceIP, d.DestIP, d.Port, bidiClientIP, bidiServerIP, port)
	}
	types := handshakeTypesOf(d)
	if !types["ClientHello"] || !types["ServerHello"] {
		t.Errorf("handshake_types = %v, want both ClientHello and ServerHello", d.RawMetadata["handshake_types"])
	}
	if d.RawMetadata["sni"] != "example.com" {
		t.Errorf("sni = %v, want example.com (client half lost)", d.RawMetadata["sni"])
	}
	return d
}

// TLS 1.3: the ServerHello is the last plaintext the server sends; the
// version comes from supported_versions, the suite from the hello itself.
func TestPassiveTLS13NegotiatedValuesFromServerHello(t *testing.T) {
	serverFlight := tlsRecord(0x16, handshakeRecord(0x02, buildServerHello(0x0303, 0x1301, 0x0304)))
	serverFlight = append(serverFlight, tlsRecord(0x14, []byte{0x01})...)     // compat ChangeCipherSpec
	serverFlight = append(serverFlight, tlsRecord(0x17, make([]byte, 64))...) // encrypted EncryptedExtensions..Finished
	// Bytes after the handshake that happen to LOOK like a handshake record
	// (here: a TLS 1.0 RC4 ServerHello) are ciphertext and must not overwrite
	// what was negotiated.
	serverFlight = append(serverFlight, tlsRecord(0x16, handshakeRecord(0x02, buildServerHello(0x0301, 0x0005, 0)))...)

	got := captureConnection(t, 443, clientHelloRecord(), serverFlight)
	d := assertOneJoinedDiscovery(t, got, 443)
	if d.Version != "TLS 1.3" {
		t.Errorf("Version = %q, want TLS 1.3", d.Version)
	}
	if d.CipherSuite != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("CipherSuite = %q, want TLS_AES_128_GCM_SHA256", d.CipherSuite)
	}
}

// TLS 1.2: version and suite from the ServerHello, and the certificate chain
// in clear. The server flight is ONE record holding three handshake messages
// and is split across two TCP segments, as real servers send it.
func TestPassiveTLS12NegotiatedValuesAndCertificateFromServerFlight(t *testing.T) {
	var flight []byte
	flight = append(flight, handshakeRecord(0x02, buildServerHello(0x0303, 0xC02F, 0))...)
	flight = append(flight, handshakeRecord(0x0B, certificateMsg(testCertDER(t, "example.com")))...)
	flight = append(flight, handshakeRecord(0x0E, nil)...) // ServerHelloDone
	record := tlsRecord(0x16, flight)
	half := len(record) / 2

	got := captureConnection(t, 443, clientHelloRecord(), record[:half], record[half:])
	d := assertOneJoinedDiscovery(t, got, 443)
	if d.Version != "TLS 1.2" {
		t.Errorf("Version = %q, want TLS 1.2", d.Version)
	}
	if d.CipherSuite != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
		t.Errorf("CipherSuite = %q, want TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", d.CipherSuite)
	}
	certs, _ := d.RawMetadata["certificates"].([]interface{})
	if len(certs) != 1 {
		t.Fatalf("certificates = %v, want the server's one-cert chain", d.RawMetadata["certificates"])
	}
	leaf, _ := certs[0].(map[string]interface{})
	if leaf["subject_dn"] != "CN=example.com" {
		t.Errorf("leaf subject_dn = %v, want CN=example.com", leaf["subject_dn"])
	}
	if !handshakeTypesOf(d)["Certificate"] {
		t.Errorf("handshake_types = %v, want Certificate", d.RawMetadata["handshake_types"])
	}
}

// A server reply on its own (the client half never captured) is still a
// legitimate observation of the server's negotiated parameters, oriented with
// the server as destination.
func TestPassiveServerHelloAloneIsOrientedToTheServer(t *testing.T) {
	cfg := &config.Config{SensorID: "test-sensor"}
	cfg.Capture.DedupTTLMinutes = 1
	pc := NewPacketCapture(cfg)
	defer pc.cancel()

	flight := tlsRecord(0x16, handshakeRecord(0x02, buildServerHello(0x0303, 0x1302, 0x0304)))
	pc.analyzePacket(tcpSegment(t, bidiServerIP, bidiClientIP, 8443, bidiClientPort, 5000, 0, true, nil), "eth0")
	pc.analyzePacket(tcpSegment(t, bidiServerIP, bidiClientIP, 8443, bidiClientPort, 5001, 1, false, flight), "eth0")
	pc.assemblerMu.Lock()
	pc.assembler.FlushAll()
	pc.assemblerMu.Unlock()

	got := drainDiscoveries(pc)
	if len(got) != 1 {
		t.Fatalf("got %d discoveries, want 1", len(got))
	}
	d := got[0]
	if d.DestIP != bidiServerIP || d.Port != 8443 || d.SourceIP != bidiClientIP {
		t.Errorf("orientation = %s -> %s:%d, want %s -> %s:8443", d.SourceIP, d.DestIP, d.Port, bidiClientIP, bidiServerIP)
	}
	if d.Version != "TLS 1.3" || d.CipherSuite != "TLS_AES_256_GCM_SHA384" {
		t.Errorf("negotiated = %q / %q, want TLS 1.3 / TLS_AES_256_GCM_SHA384", d.Version, d.CipherSuite)
	}
}

// IEC 62351-3 compliance is a verdict on NEGOTIATED parameters. A ClientHello
// with no ServerHello has none, and "unknown" must not be reported as
// "noncompliant".
func TestIEC62351NotAssertedWithoutNegotiatedParameters(t *testing.T) {
	cfg := &config.Config{SensorID: "test-sensor"}
	cfg.Capture.DedupTTLMinutes = 1
	pc := NewPacketCapture(cfg)
	defer pc.cancel()

	pc.analyzePacket(tcpSegment(t, bidiClientIP, bidiServerIP, bidiClientPort, 443, 1000, 0, true, nil), "eth0")
	pc.analyzePacket(tcpSegment(t, bidiClientIP, bidiServerIP, bidiClientPort, 443, 1001, 1, false, clientHelloRecord()), "eth0")
	pc.assemblerMu.Lock()
	pc.assembler.FlushAll()
	pc.assemblerMu.Unlock()

	got := drainDiscoveries(pc)
	if len(got) != 1 {
		t.Fatalf("got %d discoveries, want 1 ClientHello-only discovery", len(got))
	}
	for _, k := range []string{"iec62351_applicable", "iec62351_overall", "iec62351_noncompliance"} {
		if v, ok := got[0].RawMetadata[k]; ok {
			t.Errorf("ClientHello-only discovery carries %s=%v; no negotiated parameters were observed", k, v)
		}
	}

	// Polarity check: once the negotiated values ARE known the classifier
	// still runs (and still reports a real failure).
	cbc := tlsRecord(0x16, handshakeRecord(0x02, buildServerHello(0x0301, 0xC013, 0))) // TLS 1.0, ECDHE-RSA-AES128-CBC-SHA
	d := captureConnection(t, 443, clientHelloRecord(), cbc)
	if len(d) != 1 {
		t.Fatalf("got %d discoveries, want 1", len(d))
	}
	if d[0].RawMetadata["iec62351_applicable"] != true || d[0].RawMetadata["iec62351_overall"] != false {
		t.Errorf("negotiated TLS 1.0 CBC on 443 must still be classified noncompliant: %v", d[0].RawMetadata)
	}
}
