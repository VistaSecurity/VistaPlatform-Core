package capture

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/vistasecurity/vistaplatform/sensor/internal/cache"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// quicClientHello wraps a ClientHello carrying the given SNI and ALPN in a
// TLS handshake header, the way it travels in a CRYPTO frame.
func quicClientHello(sni string, alpn ...string) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)                               // session id
	body = append(body, 0x00, 0x04, 0x13, 0x01, 0x13, 0x02) // two TLS 1.3 suites
	body = append(body, 0x01, 0x00)                         // null compression

	var exts []byte
	addExt := func(typ uint16, payload []byte) {
		exts = binary.BigEndian.AppendUint16(exts, typ)
		exts = binary.BigEndian.AppendUint16(exts, uint16(len(payload)))
		exts = append(exts, payload...)
	}
	if sni != "" {
		addExt(0x0000, buildSNIExtension(sni))
	}
	if len(alpn) > 0 {
		addExt(0x0010, buildALPNExtension(alpn...))
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	msg := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(msg, body...)
}

// encryptedQUICInitial builds a client Initial the decoder can decrypt: the
// inverse of decryptQUICInitial (RFC 9001 section 5), with a 4-byte packet
// number so the header-protection sample sits where the decoder reads it.
func encryptedQUICInitial(t *testing.T, version uint32, dcid []byte, pn uint32, sni string, alpn ...string) []byte {
	t.Helper()
	key, iv, hp, err := deriveQUICInitialSecret(dcid, quicSaltForVersion(version))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	hello := quicClientHello(sni, alpn...)
	plain := []byte{0x06, 0x00}
	plain = binary.BigEndian.AppendUint16(plain, 0x4000|uint16(len(hello)))
	plain = append(plain, hello...)
	plain = append(plain, make([]byte, 32)...) // PADDING

	hdr := []byte{0xC3}
	hdr = binary.BigEndian.AppendUint32(hdr, version)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0x00, 0x00) // empty SCID, empty token
	hdr = binary.BigEndian.AppendUint16(hdr, 0x4000|uint16(4+len(plain)+16))
	pnBytes := binary.BigEndian.AppendUint32(nil, pn)

	nonce := append([]byte(nil), iv...)
	for i := 0; i < 4; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	ct := gcm.Seal(nil, nonce, plain, append(append([]byte(nil), hdr...), pnBytes...))

	mask, err := computeHPMask(hp, ct[:16])
	if err != nil {
		t.Fatalf("mask: %v", err)
	}
	hdr[0] ^= mask[0] & 0x0f
	for i := range pnBytes {
		pnBytes[i] ^= mask[1+i]
	}
	pkt := append(hdr, pnBytes...)
	return append(pkt, ct...)
}

// versionOnlyInitial is a bare long-header Initial: it identifies QUIC and its
// version but cannot be decrypted, so the decoder falls back to version-only.
func versionOnlyInitial(version uint32) []byte {
	return append(binary.BigEndian.AppendUint32([]byte{0xC0}, version), 0x00, 0x00, 0x00)
}

// quicDatagram frames payload as a client-to-server QUIC datagram on UDP 443
// between the given hosts.
func quicDatagram(t *testing.T, srcIP, dstIP string, srcPort int, payload []byte) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.ParseIP(srcIP), DstIP: net.ParseIP(dstIP),
	}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: 443}
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

func quicDecryptOn(c *config.Config) { c.Capture.EnableQUICDecrypt = true }

// The wiring test for: a QUIC connection opens with a burst of Initial
// packets, and each one used to reach the discovery channel. Drive the REAL
// analyzePacket so that deleting the cache check in the QUIC case fails this.
func TestQUICInitialBurstYieldsOneDiscovery(t *testing.T) {
	t.Run("version-only", func(t *testing.T) {
		var pkts []gopacket.Packet
		for i := 0; i < 16; i++ {
			pkts = append(pkts, quicDatagram(t, "192.0.2.10", "192.0.2.20", 40000, versionOnlyInitial(1)))
		}
		got := udpDiscoveries(t, nil, pkts...)
		if len(got) != 1 {
			t.Fatalf("16 identical QUIC Initials: got %d discoveries, want 1", len(got))
		}
		if got[0].Protocol != "QUIC" || got[0].DestIP != "192.0.2.20" || got[0].Port != 443 {
			t.Errorf("discovery = %s %s:%d, want QUIC 192.0.2.20:443", got[0].Protocol, got[0].DestIP, got[0].Port)
		}
	})

	t.Run("decrypted", func(t *testing.T) {
		var pkts []gopacket.Packet
		for i := 0; i < 16; i++ {
			pkts = append(pkts, quicDatagram(t, "192.0.2.10", "192.0.2.20", 40000,
				encryptedQUICInitial(t, 1, []byte{1, 2, 3, 4, 5, 6, 7, 8}, uint32(i), "example.com", "h3")))
		}
		got := udpDiscoveries(t, quicDecryptOn, pkts...)
		if len(got) != 1 {
			t.Fatalf("16 decryptable QUIC Initials: got %d discoveries, want 1", len(got))
		}
		if got[0].RawMetadata["sni_server_name"] != "example.com" {
			t.Errorf("sni_server_name = %v, want example.com (the decode must survive the dedup)", got[0].RawMetadata["sni_server_name"])
		}
	})

	// Junk to UDP/443 that is not a QUIC Initial decodes to nothing and must
	// not use up the cache entry for a real flow that follows it.
	t.Run("junk does not consume the cache", func(t *testing.T) {
		got := udpDiscoveries(t, nil,
			quicDatagram(t, "192.0.2.10", "192.0.2.20", 40000, []byte("not quic at all, just bytes")),
			quicDatagram(t, "192.0.2.10", "192.0.2.20", 40000, versionOnlyInitial(1)),
		)
		if len(got) != 1 {
			t.Fatalf("junk then a real Initial: got %d discoveries, want 1", len(got))
		}
	})
}

// Only identical observations collapse. A different server, client, QUIC
// version or SNI/ALPN is a different finding and keeps its own discovery.
func TestQUICDedupKeepsDistinctObservations(t *testing.T) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	cases := []struct {
		name string
		pkts func(t *testing.T) []gopacket.Packet
		want int
	}{
		{"different servers", func(t *testing.T) []gopacket.Packet {
			return []gopacket.Packet{
				quicDatagram(t, "192.0.2.10", "192.0.2.20", 40000, versionOnlyInitial(1)),
				quicDatagram(t, "192.0.2.10", "192.0.2.21", 40000, versionOnlyInitial(1)),
			}
		}, 2},
		{"different clients, same server", func(t *testing.T) []gopacket.Packet {
			return []gopacket.Packet{
				quicDatagram(t, "192.0.2.10", "192.0.2.20", 40000, versionOnlyInitial(1)),
				quicDatagram(t, "192.0.2.11", "192.0.2.20", 40000, versionOnlyInitial(1)),
			}
		}, 2},
		{"same client and server, new ephemeral port", func(t *testing.T) []gopacket.Packet {
			return []gopacket.Packet{
				quicDatagram(t, "192.0.2.10", "192.0.2.20", 40000, versionOnlyInitial(1)),
				quicDatagram(t, "192.0.2.10", "192.0.2.20", 40001, versionOnlyInitial(1)),
			}
		}, 1},
		{"same flow, different QUIC version", func(t *testing.T) []gopacket.Packet {
			return []gopacket.Packet{
				quicDatagram(t, "192.0.2.10", "192.0.2.20", 40000, versionOnlyInitial(1)),
				quicDatagram(t, "192.0.2.10", "192.0.2.20", 40000, versionOnlyInitial(0x6b3343cf)),
			}
		}, 2},
		{"same server, different SNI", func(t *testing.T) []gopacket.Packet {
			return []gopacket.Packet{
				quicDatagram(t, "192.0.2.10", "192.0.2.20", 40000, encryptedQUICInitial(t, 1, dcid, 0, "a.example.com", "h3")),
				quicDatagram(t, "192.0.2.10", "192.0.2.20", 40001, encryptedQUICInitial(t, 1, dcid, 0, "b.example.com", "h3")),
				quicDatagram(t, "192.0.2.10", "192.0.2.20", 40002, encryptedQUICInitial(t, 1, dcid, 1, "a.example.com", "h3")),
			}
		}, 2},
		{"same server and SNI, different ALPN", func(t *testing.T) []gopacket.Packet {
			return []gopacket.Packet{
				quicDatagram(t, "192.0.2.10", "192.0.2.20", 40000, encryptedQUICInitial(t, 1, dcid, 0, "a.example.com", "h3")),
				quicDatagram(t, "192.0.2.10", "192.0.2.20", 40001, encryptedQUICInitial(t, 1, dcid, 0, "a.example.com", "doq")),
			}
		}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := udpDiscoveries(t, quicDecryptOn, tc.pkts(t)...); len(got) != tc.want {
				t.Fatalf("got %d discoveries, want %d", len(got), tc.want)
			}
		})
	}
}

// A long-lived flow is re-reported once the dedup window has passed, on the
// same cadence the TLS and VPN paths use (they share the ConnectionCache).
func TestQUICDedupReReportsAfterTTL(t *testing.T) {
	cfg := &config.Config{SensorID: "test-sensor"}
	cfg.Capture.DedupTTLMinutes = 1
	pc := NewPacketCapture(cfg)
	defer pc.cancel()
	pc.SetCache(cache.NewConnectionCache(50*time.Millisecond, 1000))

	send := func(n int) []*models.CryptoDiscovery {
		for i := 0; i < n; i++ {
			pc.analyzePacket(quicDatagram(t, "192.0.2.10", "192.0.2.20", 40000, versionOnlyInitial(1)), "eth0")
		}
		return drainDiscoveries(pc)
	}

	if got := send(10); len(got) != 1 {
		t.Fatalf("first burst: got %d discoveries, want 1", len(got))
	}
	if got := send(10); len(got) != 0 {
		t.Fatalf("second burst inside the window: got %d discoveries, want 0", len(got))
	}
	time.Sleep(80 * time.Millisecond)
	if got := send(10); len(got) != 1 {
		t.Fatalf("burst after the window expired: got %d discoveries, want 1", len(got))
	}
}

// The QUIC key shares the cache with TLS and the VPN decoders without ever
// colliding with their entries for the same server and port.
func TestQUICDedupKeyDoesNotCollideWithTLS(t *testing.T) {
	cfg := &config.Config{SensorID: "test-sensor"}
	cfg.Capture.DedupTTLMinutes = 1
	pc := NewPacketCapture(cfg)
	defer pc.cancel()
	if shouldReport, _ := pc.cache.ShouldReport("192.0.2.20", 443, "TLS"); !shouldReport {
		t.Fatal("seeding the TLS entry should report")
	}
	pc.analyzePacket(quicDatagram(t, "192.0.2.10", "192.0.2.20", 40000, versionOnlyInitial(1)), "eth0")
	if got := drainDiscoveries(pc); len(got) != 1 {
		t.Fatalf("a recent TLS report to the same server:443 suppressed the QUIC discovery: got %d, want 1", len(got))
	}
}
