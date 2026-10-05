package capture

import (
	"encoding/binary"
	"testing"
)

// The key-exchange group is the one part of a passively captured handshake's
// posture the cipher suite does not name, and without its size the platform
// cannot finish a strength assessment: every ECDHE connection to a third party
// stayed unrated. The server sends it in clear — in the TLS 1.3 ServerHello
// key_share, and in the TLS <= 1.2 ServerKeyExchange.
//
// These drive the REAL capture path (analyzePacket -> tcpassembly -> factory)
// and assert the emitted metadata carries the same keys the active probes
// write (shared/discovery TLSKeyExchange.ApplyTo).

// withKeyShare appends a key_share extension selecting group to a ServerHello
// body built by buildServerHello.
func withKeyShare(serverHello []byte, group uint16, share []byte) []byte {
	// version(2) random(32) sid_len(1)=0 suite(2) comp(1), then ext_len(2).
	const extLenAt = 38
	ext := binary.BigEndian.AppendUint16(nil, 0x0033)
	ext = binary.BigEndian.AppendUint16(ext, uint16(4+len(share)))
	ext = binary.BigEndian.AppendUint16(ext, group)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(share)))
	ext = append(ext, share...)
	out := append([]byte(nil), serverHello...)
	out = append(out, ext...)
	binary.BigEndian.PutUint16(out[extLenAt:], uint16(len(out)-extLenAt-2))
	return out
}

func TestPassiveTLS13RecordsKeyShareGroupAndSize(t *testing.T) {
	hello := withKeyShare(buildServerHello(0x0303, 0x1301, 0x0304), 0x001d, make([]byte, 32)) // x25519
	flight := tlsRecord(0x16, handshakeRecord(0x02, hello))
	flight = append(flight, tlsRecord(0x14, []byte{0x01})...)
	flight = append(flight, tlsRecord(0x17, make([]byte, 64))...)

	d := assertOneJoinedDiscovery(t, captureConnection(t, 443, clientHelloRecord(), flight), 443)
	if got := d.RawMetadata["key_exchange_algorithm"]; got != "X25519" {
		t.Errorf("key_exchange_algorithm = %v, want X25519", got)
	}
	if got := d.RawMetadata["key_exchange_group_raw"]; got != uint16(0x001d) {
		t.Errorf("key_exchange_group_raw = %v (%T), want 29", got, got)
	}
	if got := d.RawMetadata["key_exchange_key_size"]; got != 256 {
		t.Errorf("key_exchange_key_size = %v, want 256", got)
	}
	// One capture says what was negotiated, not what else the server accepts.
	for _, k := range []string{"tls_supports_classical_kex", "tls_supports_pqc_hybrid_kex"} {
		if v, ok := d.RawMetadata[k]; ok {
			t.Errorf("%s = %v from a passive capture, want absent", k, v)
		}
	}
}

func TestPassiveTLS12RecordsServerKeyExchangeCurveAndSize(t *testing.T) {
	// ECDHE ServerKeyExchange: named_curve(3) secp384r1(24), a 97-byte point,
	// then the signature (not read).
	ske := []byte{0x03, 0x00, 0x18, 97}
	ske = append(ske, make([]byte, 97+8)...)
	var flight []byte
	flight = append(flight, handshakeRecord(0x02, buildServerHello(0x0303, 0xC02F, 0))...)
	flight = append(flight, handshakeRecord(0x0B, certificateMsg(testCertDER(t, "example.com")))...)
	flight = append(flight, handshakeRecord(0x0C, ske)...)
	flight = append(flight, handshakeRecord(0x0E, nil)...)

	d := assertOneJoinedDiscovery(t, captureConnection(t, 443, clientHelloRecord(), tlsRecord(0x16, flight)), 443)
	if got := d.RawMetadata["key_exchange_algorithm"]; got != "DH-ECP-384" {
		t.Errorf("key_exchange_algorithm = %v, want DH-ECP-384", got)
	}
	if got := d.RawMetadata["key_exchange_group_raw"]; got != uint16(24) {
		t.Errorf("key_exchange_group_raw = %v, want 24", got)
	}
	if got := d.RawMetadata["key_exchange_key_size"]; got != 384 {
		t.Errorf("key_exchange_key_size = %v, want 384", got)
	}
}

// A DHE exchange names no group: the size is the length of the prime the
// server sent. The suite label stays, and no group id is invented.
func TestPassiveTLS12RecordsDHEPrimeLength(t *testing.T) {
	p := make([]byte, 256)
	p[0] = 0xff // a 2048-bit prime
	ske := binary.BigEndian.AppendUint16(nil, uint16(len(p)+1))
	ske = append(ske, 0x00) // a leading zero octet must not count
	ske = append(ske, p...)
	ske = append(ske, 0x00, 0x01, 0x02) // dh_g
	var flight []byte
	flight = append(flight, handshakeRecord(0x02, buildServerHello(0x0303, 0x0033, 0))...) // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
	flight = append(flight, handshakeRecord(0x0C, ske)...)
	flight = append(flight, handshakeRecord(0x0E, nil)...)

	d := assertOneJoinedDiscovery(t, captureConnection(t, 443, clientHelloRecord(), tlsRecord(0x16, flight)), 443)
	if d.CipherSuite != "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" {
		t.Fatalf("CipherSuite = %q", d.CipherSuite)
	}
	if got := d.RawMetadata["key_exchange_key_size"]; got != 2048 {
		t.Errorf("key_exchange_key_size = %v, want 2048", got)
	}
	if got := d.RawMetadata["key_exchange_algorithm"]; got != "DHE_RSA" {
		t.Errorf("key_exchange_algorithm = %v, want the suite label DHE_RSA", got)
	}
	if v, ok := d.RawMetadata["key_exchange_group_raw"]; ok {
		t.Errorf("key_exchange_group_raw = %v for a custom prime, want absent", v)
	}
}

// Unknown stays unknown: a handshake that shows no group (no key_share, no
// ServerKeyExchange) or a group whose size is not known must not be given one.
func TestPassiveTLSNoGroupEvidenceRecordsNoSize(t *testing.T) {
	t.Run("no key_share", func(t *testing.T) {
		flight := tlsRecord(0x16, handshakeRecord(0x02, buildServerHello(0x0303, 0x1301, 0x0304)))
		flight = append(flight, tlsRecord(0x14, []byte{0x01})...)
		d := assertOneJoinedDiscovery(t, captureConnection(t, 443, clientHelloRecord(), flight), 443)
		for _, k := range []string{"key_exchange_key_size", "key_exchange_group_raw", "key_exchange_algorithm"} {
			if v, ok := d.RawMetadata[k]; ok {
				t.Errorf("%s = %v with no key_share, want absent", k, v)
			}
		}
	})
	t.Run("unrecognised group", func(t *testing.T) {
		hello := withKeyShare(buildServerHello(0x0303, 0x1301, 0x0304), 0x6a6a, make([]byte, 1)) // GREASE
		flight := tlsRecord(0x16, handshakeRecord(0x02, hello))
		flight = append(flight, tlsRecord(0x14, []byte{0x01})...)
		d := assertOneJoinedDiscovery(t, captureConnection(t, 443, clientHelloRecord(), flight), 443)
		if got := d.RawMetadata["key_exchange_group_raw"]; got != uint16(0x6a6a) {
			t.Errorf("key_exchange_group_raw = %v, want the wire id", got)
		}
		for _, k := range []string{"key_exchange_key_size", "key_exchange_algorithm"} {
			if v, ok := d.RawMetadata[k]; ok {
				t.Errorf("%s = %v for an unrecognised group, want absent", k, v)
			}
		}
	})
	t.Run("PSK ServerKeyExchange is not read as curve parameters", func(t *testing.T) {
		var flight []byte
		flight = append(flight, handshakeRecord(0x02, buildServerHello(0x0303, 0xC035, 0))...) // TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA
		flight = append(flight, handshakeRecord(0x0C, []byte{0x03, 0x00, 0x17, 0x00})...)
		flight = append(flight, handshakeRecord(0x0E, nil)...)
		d := assertOneJoinedDiscovery(t, captureConnection(t, 443, clientHelloRecord(), tlsRecord(0x16, flight)), 443)
		if v, ok := d.RawMetadata["key_exchange_key_size"]; ok {
			t.Errorf("key_exchange_key_size = %v from a PSK identity hint, want absent", v)
		}
	})
}
