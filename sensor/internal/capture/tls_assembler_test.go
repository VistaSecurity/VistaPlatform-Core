package capture

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// DISC-1 regression tests.
//
// The passive assembler must record the NEGOTIATED TLS version, which only the
// ServerHello can tell us:
//   - TLS <= 1.2 negotiates via the ServerHello legacy server_version field.
//   - TLS 1.3 pins legacy server_version to 0x0303 and carries the real version
//     in the supported_versions extension.
//
// The ClientHello's supported_versions extension is the client's best OFFER and
// must never stand in for the negotiated version — doing so inventoried every
// TLS 1.2 connection from a modern client as TLS 1.3, hiding legacy exposure.

// handshakeRecord wraps a handshake message body in its 4-byte header.
func handshakeRecord(handshakeType byte, body []byte) []byte {
	rec := make([]byte, 0, 4+len(body))
	rec = append(rec, handshakeType,
		byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	return append(rec, body...)
}

// buildClientHello assembles a minimal ClientHello body. legacyVersion is the
// client_version field; supportedVersions (when non-empty) is emitted as a
// supported_versions (0x002b) extension.
func buildClientHello(legacyVersion uint16, supportedVersions []uint16) []byte {
	msg := make([]byte, 0, 128)
	msg = binary.BigEndian.AppendUint16(msg, legacyVersion)
	msg = append(msg, make([]byte, 32)...) // random
	msg = append(msg, 0)                   // session_id_len = 0

	// cipher_suites: one TLS 1.3 suite (0x1301) and one TLS 1.2 suite (0xC02F)
	suites := []byte{0x13, 0x01, 0xC0, 0x2F}
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(suites)))
	msg = append(msg, suites...)

	msg = append(msg, 1, 0) // compression_methods_len = 1, method = null

	var exts []byte
	if len(supportedVersions) > 0 {
		body := []byte{byte(len(supportedVersions) * 2)}
		for _, v := range supportedVersions {
			body = binary.BigEndian.AppendUint16(body, v)
		}
		exts = binary.BigEndian.AppendUint16(exts, 0x002b)
		exts = binary.BigEndian.AppendUint16(exts, uint16(len(body)))
		exts = append(exts, body...)
	}
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(exts)))
	msg = append(msg, exts...)
	return msg
}

// buildServerHello assembles a minimal ServerHello body. legacyVersion is the
// server_version field; when negotiatedVersion is non-zero a supported_versions
// (0x002b) extension carrying it is appended, as a TLS 1.3 server would.
func buildServerHello(legacyVersion uint16, suite uint16, negotiatedVersion uint16) []byte {
	msg := make([]byte, 0, 128)
	msg = binary.BigEndian.AppendUint16(msg, legacyVersion)
	msg = append(msg, make([]byte, 32)...) // random
	msg = append(msg, 0)                   // session_id_len = 0
	msg = binary.BigEndian.AppendUint16(msg, suite)
	msg = append(msg, 0) // compression method = null

	var exts []byte
	if negotiatedVersion != 0 {
		exts = binary.BigEndian.AppendUint16(exts, 0x002b)
		exts = binary.BigEndian.AppendUint16(exts, 2)
		exts = binary.BigEndian.AppendUint16(exts, negotiatedVersion)
	}
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(exts)))
	msg = append(msg, exts...)
	return msg
}

func newTestTLSStream() *TLSStream {
	return &TLSStream{
		state: &tlsSessionState{
			sessionID:      "test-session",
			handshakeTypes: make(map[uint8]bool),
			lastSeen:       time.Now(),
		},
	}
}

func TestTLSAssemblerNegotiatedVersion(t *testing.T) {
	const (
		tls10 = uint16(0x0301)
		tls12 = uint16(0x0303)
		tls13 = uint16(0x0304)
	)

	tests := []struct {
		name              string
		clientHello       []byte
		serverHello       []byte
		wantVersion       string
		wantClientOffered string
	}{
		{
			// The headline bug: a modern client offers 1.3, the server only
			// speaks 1.2 and answers with legacy server_version 0x0303 and no
			// supported_versions extension.
			name:              "modern client, TLS 1.2-only server",
			clientHello:       buildClientHello(tls12, []uint16{tls13, tls12}),
			serverHello:       buildServerHello(tls12, 0xC02F, 0),
			wantVersion:       "TLS 1.2",
			wantClientOffered: "TLS 1.3",
		},
		{
			// TLS 1.3: legacy field says 1.2, supported_versions says 1.3.
			name:              "TLS 1.3 negotiated via supported_versions",
			clientHello:       buildClientHello(tls12, []uint16{tls13, tls12}),
			serverHello:       buildServerHello(tls12, 0x1301, tls13),
			wantVersion:       "TLS 1.3",
			wantClientOffered: "TLS 1.3",
		},
		{
			// Legacy handshake with no supported_versions anywhere: previously
			// produced an EMPTY version.
			name:              "legacy TLS 1.0 handshake",
			clientHello:       buildClientHello(tls10, nil),
			serverHello:       buildServerHello(tls10, 0xC013, 0),
			wantVersion:       "TLS 1.0",
			wantClientOffered: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestTLSStream()
			s.processHandshakeRecord(handshakeRecord(0x01, tt.clientHello))

			// After the ClientHello alone, nothing has been negotiated yet.
			if s.state.version != "" {
				t.Fatalf("version set from ClientHello alone: %q (the client's offer is not the negotiated version)", s.state.version)
			}

			s.processHandshakeRecord(handshakeRecord(0x02, tt.serverHello))

			if s.state.version != tt.wantVersion {
				t.Errorf("negotiated version = %q, want %q", s.state.version, tt.wantVersion)
			}
			if s.state.clientMaxOfferedVersion != tt.wantClientOffered {
				t.Errorf("clientMaxOfferedVersion = %q, want %q", s.state.clientMaxOfferedVersion, tt.wantClientOffered)
			}
		})
	}
}

// TestTLSAssemblerEmitsClientOfferedVersionSeparately pins that the client's
// advertised maximum reaches the platform under its own key and can never be
// confused with the negotiated version.
func TestTLSAssemblerEmitsClientOfferedVersionSeparately(t *testing.T) {
	s := newTestTLSStream()
	s.processHandshakeRecord(handshakeRecord(0x01, buildClientHello(0x0303, []uint16{0x0304, 0x0303})))
	s.processHandshakeRecord(handshakeRecord(0x02, buildServerHello(0x0303, 0xC02F, 0)))

	disc := emitAndCollect(t, s.state)

	if disc.Version != "TLS 1.2" {
		t.Errorf("discovery Version = %q, want %q", disc.Version, "TLS 1.2")
	}
	if got := disc.RawMetadata["client_max_offered_version"]; got != "TLS 1.3" {
		t.Errorf("client_max_offered_version = %v, want %q", got, "TLS 1.3")
	}
}

// TestTLSAssemblerEmitsCertQualityFlags pins DISC-5: quality flags computed
// during passive chain validation must reach the emitted metadata at the top
// level, where every downstream consumer reads them.
func TestTLSAssemblerEmitsCertQualityFlags(t *testing.T) {
	state := &tlsSessionState{
		sessionID:      "quality-flags",
		serverIP:       "192.0.2.10",
		serverPort:     443,
		protocol:       "TLS",
		version:        "TLS 1.2",
		cipherSuite:    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		handshakeTypes: map[uint8]bool{0x02: true},
		certificates:   []models.CertificateInfo{{SubjectDN: "CN=example.com"}},
		certValStatus:  "valid",
		certQualityFlags: map[string]interface{}{
			"cert_has_sct":          true,
			"cert_is_ev":            true,
			"cert_weak_signature":   "SHA-1",
			"cert_incomplete_chain": true,
		},
		lastSeen: time.Now(),
	}

	disc := emitAndCollect(t, state)

	for key, want := range map[string]interface{}{
		"cert_has_sct":          true,
		"cert_is_ev":            true,
		"cert_weak_signature":   "SHA-1",
		"cert_incomplete_chain": true,
	} {
		if got := disc.RawMetadata[key]; got != want {
			t.Errorf("metadata[%q] = %v, want %v (quality flags must be TOP-LEVEL)", key, got, want)
		}
	}
	if _, nested := disc.RawMetadata["cert_quality_flags"]; nested {
		t.Error("quality flags must not be nested under cert_quality_flags")
	}
}

// emitAndCollect emits a discovery for the state through a factory wired to a
// buffered channel and returns it.
func emitAndCollect(t *testing.T, state *tlsSessionState) *models.CryptoDiscovery {
	t.Helper()
	ch := make(chan *models.CryptoDiscovery, 1)
	f := &TLSStreamFactory{
		sessions:    make(map[tlsFlowKey]*tlsSessionState),
		discoveries: ch,
		sensorID:    "test-sensor",
	}
	if state.serverIP == "" {
		state.serverIP = "192.0.2.1"
	}
	f.emitDiscovery(state, true)

	select {
	case disc := <-ch:
		return disc
	default:
		t.Fatal("no discovery emitted")
		return nil
	}
}
