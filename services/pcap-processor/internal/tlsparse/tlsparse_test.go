package tlsparse

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Synthetic handshake byte builders
// ---------------------------------------------------------------------------

func u16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

func u24(v int) []byte {
	return []byte{byte(v >> 16), byte(v >> 8), byte(v)}
}

// tlsRecord wraps a fragment in a TLS record header.
func tlsRecord(contentType byte, version uint16, fragment []byte) []byte {
	out := []byte{contentType}
	out = append(out, u16(version)...)
	out = append(out, u16(uint16(len(fragment)))...)
	return append(out, fragment...)
}

// handshakeMsg wraps a body in a handshake type+length header.
func handshakeMsg(msgType byte, body []byte) []byte {
	out := []byte{msgType}
	out = append(out, u24(len(body))...)
	return append(out, body...)
}

func extension(extType uint16, body []byte) []byte {
	out := u16(extType)
	out = append(out, u16(uint16(len(body)))...)
	return append(out, body...)
}

func sniExtension(host string) []byte {
	entry := []byte{0x00} // host_name
	entry = append(entry, u16(uint16(len(host)))...)
	entry = append(entry, []byte(host)...)
	body := u16(uint16(len(entry)))
	body = append(body, entry...)
	return extension(0x0000, body)
}

// clientSupportedVersions builds the ClientHello form: 1-byte list length then
// 2-byte versions.
func clientSupportedVersions(versions ...uint16) []byte {
	list := []byte{}
	for _, v := range versions {
		list = append(list, u16(v)...)
	}
	body := append([]byte{byte(len(list))}, list...)
	return extension(0x002b, body)
}

// serverSupportedVersions builds the ServerHello form: a single 2-byte version.
func serverSupportedVersions(v uint16) []byte {
	return extension(0x002b, u16(v))
}

func clientHelloBody(legacyVersion uint16, suites []uint16, exts ...[]byte) []byte {
	body := u16(legacyVersion)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id_length

	cs := []byte{}
	for _, s := range suites {
		cs = append(cs, u16(s)...)
	}
	body = append(body, u16(uint16(len(cs)))...)
	body = append(body, cs...)

	body = append(body, 0x01, 0x00) // compression_methods: 1 x null

	extBytes := []byte{}
	for _, e := range exts {
		extBytes = append(extBytes, e...)
	}
	body = append(body, u16(uint16(len(extBytes)))...)
	body = append(body, extBytes...)
	return body
}

func serverHelloBody(legacyVersion uint16, suite uint16, exts ...[]byte) []byte {
	body := u16(legacyVersion)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id_length
	body = append(body, u16(suite)...)
	body = append(body, 0x00) // compression_method: null

	extBytes := []byte{}
	for _, e := range exts {
		extBytes = append(extBytes, e...)
	}
	body = append(body, u16(uint16(len(extBytes)))...)
	body = append(body, extBytes...)
	return body
}

func certificateBody(ders ...[]byte) []byte {
	entries := []byte{}
	for _, der := range ders {
		entries = append(entries, u24(len(der))...)
		entries = append(entries, der...)
	}
	return append(u24(len(entries)), entries...)
}

// selfSignedDER produces a real, parseable certificate so the DER path is
// exercised end to end rather than against a hand-rolled stub.
func selfSignedDER(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: commonName, Organization: []string{"Vista Test"}},
		NotBefore:    time.Now().Add(-time.Hour).UTC().Truncate(time.Second),
		NotAfter:     time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second),
		DNSNames:     []string{commonName},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

func flow() (client, server FlowKey) {
	client = FlowKey{SrcIP: "10.0.0.9", SrcPort: 51514, DstIP: "10.0.0.1", DstPort: 443}
	server = FlowKey{SrcIP: "10.0.0.1", SrcPort: 443, DstIP: "10.0.0.9", DstPort: 51514}
	return
}

func collect(t *testing.T) (*Tracker, *[]*Session) {
	t.Helper()
	var out []*Session
	tr := NewTracker(func(s *Session) { out = append(out, s) })
	return tr, &out
}

// ---------------------------------------------------------------------------
// Finding 1 — negotiated version
// ---------------------------------------------------------------------------

// TestServerHelloNegotiatedVersion pins the fix for the "every TLS 1.3
// connection reports TLS 1.2" defect: the negotiated version is the
// supported_versions extension when the server sent it, and the legacy
// server_version only as a fallback.
func TestServerHelloNegotiatedVersion(t *testing.T) {
	tests := []struct {
		name   string
		body   []byte
		expect string
	}{
		{
			// TLS 1.3 pins legacy_version to 0x0303 and carries 0x0304 in
			// supported_versions. Reading only the legacy field yields the
			// wrong answer for every modern connection.
			name:   "tls13 supported_versions wins over legacy 0x0303",
			body:   serverHelloBody(0x0303, 0x1301, serverSupportedVersions(0x0304)),
			expect: "TLS 1.3",
		},
		{
			name:   "plain tls12 falls back to legacy server_version",
			body:   serverHelloBody(0x0303, 0xC02F),
			expect: "TLS 1.2",
		},
		{
			name:   "tls10 falls back to legacy server_version",
			body:   serverHelloBody(0x0301, 0x002F),
			expect: "TLS 1.0",
		},
		{
			name:   "tls11 falls back to legacy server_version",
			body:   serverHelloBody(0x0302, 0x0035),
			expect: "TLS 1.1",
		},
		{
			name:   "ssl30 falls back to legacy server_version",
			body:   serverHelloBody(0x0300, 0x000A),
			expect: "SSL 3.0",
		},
		{
			// A supported_versions extension is present but names a version we
			// do not recognise: keep the legacy value rather than blanking it.
			name:   "unknown supported_versions leaves legacy in place",
			body:   serverHelloBody(0x0303, 0xC02F, serverSupportedVersions(0x7f1c)),
			expect: "TLS 1.2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sh := ParseServerHello(tc.body)
			if sh == nil {
				t.Fatal("ParseServerHello returned nil")
			}
			if sh.Version != tc.expect {
				t.Errorf("negotiated version = %q, want %q", sh.Version, tc.expect)
			}
		})
	}
}

// TestClientOfferIsNeverNegotiated pins the second half of finding 1: a TLS
// 1.3-capable client talking to a TLS 1.2-only server must be inventoried as
// TLS 1.2, with the client's offer kept as separate metadata.
func TestClientOfferIsNeverNegotiated(t *testing.T) {
	c, s := flow()
	tr, got := collect(t)
	ts := time.Now()

	ch := clientHelloBody(0x0303, []uint16{0x1301, 0xC02F},
		clientSupportedVersions(0x0304, 0x0303),
		sniExtension("api.example.com"))
	tr.Feed(c, tlsRecord(0x16, 0x0301, handshakeMsg(0x01, ch)), ts)

	sh := serverHelloBody(0x0303, 0xC02F) // TLS 1.2-only server
	tr.Feed(s, tlsRecord(0x16, 0x0303, handshakeMsg(0x02, sh)), ts)
	tr.Flush()

	if len(*got) != 1 {
		t.Fatalf("expected 1 session, got %d", len(*got))
	}
	sess := (*got)[0]
	if sess.NegotiatedVersion != "TLS 1.2" {
		t.Errorf("negotiated = %q, want TLS 1.2", sess.NegotiatedVersion)
	}
	if sess.ClientMaxOffered != "TLS 1.3" {
		t.Errorf("client max offered = %q, want TLS 1.3", sess.ClientMaxOffered)
	}
	if sess.SNI != "api.example.com" {
		t.Errorf("SNI = %q", sess.SNI)
	}
}

// TestClientHelloOnlyLeavesVersionUnobserved: when the capture never carried
// the server's flight there is no negotiated version. Empty means "not
// observed" — it must never be back-filled from the client's offer.
func TestClientHelloOnlyLeavesVersionUnobserved(t *testing.T) {
	c, _ := flow()
	tr, got := collect(t)

	ch := clientHelloBody(0x0303, []uint16{0x1301}, clientSupportedVersions(0x0304))
	tr.Feed(c, tlsRecord(0x16, 0x0301, handshakeMsg(0x01, ch)), time.Now())
	tr.Flush()

	if len(*got) != 1 {
		t.Fatalf("expected 1 session, got %d", len(*got))
	}
	if v := (*got)[0].NegotiatedVersion; v != "" {
		t.Errorf("negotiated version = %q, want empty (server flight not captured)", v)
	}
}

// ---------------------------------------------------------------------------
// Finding 3 — IANA cipher suite names
// ---------------------------------------------------------------------------

func TestCipherSuiteNamesAreIANANotHex(t *testing.T) {
	tests := []struct {
		id   uint16
		want string
	}{
		{0x1301, "TLS_AES_128_GCM_SHA256"},
		{0x1302, "TLS_AES_256_GCM_SHA384"},
		{0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		{0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA"},
		// Unknown suites stay identifiable rather than being invented.
		{0xFF01, "0xFF01"},
	}
	for _, tc := range tests {
		if got := CipherName(tc.id); got != tc.want {
			t.Errorf("CipherName(0x%04X) = %q, want %q", tc.id, got, tc.want)
		}
	}

	// GREASE values are deliberate nonsense (RFC 8701) and must never reach
	// the algorithm catalogue.
	for _, g := range []uint16{0x0A0A, 0x1A1A, 0xFAFA} {
		if !IsGREASE(g) {
			t.Errorf("IsGREASE(0x%04X) = false", g)
		}
		if got := CipherName(g); got != "" {
			t.Errorf("CipherName(GREASE 0x%04X) = %q, want empty", g, got)
		}
	}
}

func TestServerHelloEmitsNamedCipher(t *testing.T) {
	sh := ParseServerHello(serverHelloBody(0x0303, 0x1301, serverSupportedVersions(0x0304)))
	if sh.CipherSuite != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("cipher = %q, want TLS_AES_128_GCM_SHA256", sh.CipherSuite)
	}
	if strings.HasPrefix(sh.CipherSuite, "0x") {
		t.Error("cipher suite emitted as a raw hex code; it will not resolve against the algorithms catalogue")
	}
}

func TestClientHelloOfferedCiphersSkipGREASE(t *testing.T) {
	ch := ParseClientHello(clientHelloBody(0x0303, []uint16{0x0A0A, 0x1301, 0xC02F}))
	want := []string{"TLS_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}
	if len(ch.CipherSuites) != len(want) {
		t.Fatalf("offered suites = %v, want %v", ch.CipherSuites, want)
	}
	for i := range want {
		if ch.CipherSuites[i] != want[i] {
			t.Errorf("offered[%d] = %q, want %q", i, ch.CipherSuites[i], want[i])
		}
	}
}

// ---------------------------------------------------------------------------
// Finding 2 — multi-record, multi-segment certificate extraction
// ---------------------------------------------------------------------------

// TestCertificateAcrossTwoSegments pins the reassembly fix: a Certificate
// message that spans two TCP segments (the normal case, since a chain exceeds
// one MSS) must still parse into the canonical certificates array.
func TestCertificateAcrossTwoSegments(t *testing.T) {
	c, s := flow()
	tr, got := collect(t)
	ts := time.Now()

	leaf := selfSignedDER(t, "pcap-leaf.example.com")
	certMsg := handshakeMsg(0x0b, certificateBody(leaf))
	rec := tlsRecord(0x16, 0x0303, certMsg)

	// ClientHello first so the flow starts, then the server flight split
	// mid-record across two segments.
	tr.Feed(c, tlsRecord(0x16, 0x0301, handshakeMsg(0x01,
		clientHelloBody(0x0303, []uint16{0xC02F}, sniExtension("pcap-leaf.example.com")))), ts)

	split := len(rec) / 2
	tr.Feed(s, rec[:split], ts)
	if len(*got) != 0 {
		t.Fatal("session emitted before the Certificate message was complete")
	}
	tr.Feed(s, rec[split:], ts)
	tr.Flush()

	if len(*got) != 1 {
		t.Fatalf("expected 1 session, got %d", len(*got))
	}
	certs := (*got)[0].Certificates
	if len(certs) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(certs))
	}
	got0 := certs[0]
	if !strings.Contains(got0.SubjectDN, "pcap-leaf.example.com") {
		t.Errorf("subject_dn = %q", got0.SubjectDN)
	}
	if got0.IssuerDN != got0.SubjectDN {
		t.Errorf("self-signed cert should have issuer == subject, got %q / %q", got0.IssuerDN, got0.SubjectDN)
	}
	if len(got0.FingerprintSHA256) != 64 {
		t.Errorf("fingerprint_sha256 = %q, want 64 hex chars", got0.FingerprintSHA256)
	}
	if !strings.HasPrefix(got0.CertificatePEM, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("certificate_pem not PEM-encoded: %q", got0.CertificatePEM)
	}
	if got0.KeyAlgorithm != "ECDSA" {
		t.Errorf("key_algorithm = %q, want ECDSA", got0.KeyAlgorithm)
	}
	if got0.NotAfter.IsZero() || got0.NotBefore.IsZero() {
		t.Error("not_before/not_after not populated")
	}
	if got0.ChainOrder != 0 {
		t.Errorf("chain_order = %d, want 0 for the leaf", got0.ChainOrder)
	}
}

// TestMultipleRecordsInOneSegment pins the "only the first TLS record of the
// first segment was ever inspected" half of finding 2: a server flight packing
// ServerHello + Certificate into one segment must yield both.
func TestMultipleRecordsInOneSegment(t *testing.T) {
	c, s := flow()
	tr, got := collect(t)
	ts := time.Now()

	tr.Feed(c, tlsRecord(0x16, 0x0301, handshakeMsg(0x01,
		clientHelloBody(0x0303, []uint16{0xC02F}))), ts)

	leaf := selfSignedDER(t, "multi-record.example.com")
	flight := tlsRecord(0x16, 0x0303, handshakeMsg(0x02, serverHelloBody(0x0303, 0xC02F)))
	flight = append(flight, tlsRecord(0x16, 0x0303, handshakeMsg(0x0b, certificateBody(leaf)))...)
	tr.Feed(s, flight, ts)
	tr.Flush()

	if len(*got) != 1 {
		t.Fatalf("expected 1 session, got %d", len(*got))
	}
	sess := (*got)[0]
	if sess.NegotiatedVersion != "TLS 1.2" {
		t.Errorf("negotiated = %q", sess.NegotiatedVersion)
	}
	if len(sess.Certificates) != 1 {
		t.Fatalf("expected the Certificate message in the same segment to be parsed, got %d certs", len(sess.Certificates))
	}
	if len(sess.HandshakeTypes) != 3 {
		t.Errorf("handshake types = %v, want ClientHello+ServerHello+Certificate", sess.HandshakeTypes)
	}
}

// TestChainOrderPreserved checks a two-cert chain keeps leaf-first ordering.
func TestChainOrderPreserved(t *testing.T) {
	leaf := selfSignedDER(t, "leaf.example.com")
	inter := selfSignedDER(t, "intermediate.example.com")
	certs := ParseCertificateMessage(certificateBody(leaf, inter))
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(certs))
	}
	if certs[0].ChainOrder != 0 || certs[1].ChainOrder != 1 {
		t.Errorf("chain order = %d,%d want 0,1", certs[0].ChainOrder, certs[1].ChainOrder)
	}
	if !strings.Contains(certs[0].SubjectDN, "leaf.example.com") {
		t.Errorf("index 0 should be the leaf, got %q", certs[0].SubjectDN)
	}
}

// TestCertificateMessageSkipsUnparseableEntries: garbage in the chain must not
// discard the entries that do parse.
func TestCertificateMessageSkipsUnparseableEntries(t *testing.T) {
	leaf := selfSignedDER(t, "good.example.com")
	garbage := []byte{0x30, 0x03, 0x01, 0x02, 0x03}
	certs := ParseCertificateMessage(certificateBody(garbage, leaf))
	if len(certs) != 1 {
		t.Fatalf("expected 1 parseable cert, got %d", len(certs))
	}
	if !strings.Contains(certs[0].SubjectDN, "good.example.com") {
		t.Errorf("subject = %q", certs[0].SubjectDN)
	}
}

// ---------------------------------------------------------------------------
// Session identity — the server endpoint is the asset
// ---------------------------------------------------------------------------

// TestServerEndpointIsTheAsset: the ServerHello travels server→client, so
// emitting per-message would have inventoried the CLIENT's ephemeral port as an
// asset. The session must always report the server endpoint as the destination.
func TestServerEndpointIsTheAsset(t *testing.T) {
	c, s := flow()
	tr, got := collect(t)
	ts := time.Now()

	tr.Feed(c, tlsRecord(0x16, 0x0301, handshakeMsg(0x01, clientHelloBody(0x0303, []uint16{0xC02F}))), ts)
	tr.Feed(s, tlsRecord(0x16, 0x0303, handshakeMsg(0x02, serverHelloBody(0x0303, 0xC02F))), ts)
	tr.Flush()

	sess := (*got)[0]
	if sess.ServerIP != "10.0.0.1" || sess.ServerPort != 443 {
		t.Errorf("server endpoint = %s:%d, want 10.0.0.1:443", sess.ServerIP, sess.ServerPort)
	}
	if sess.ClientIP != "10.0.0.9" || sess.ClientPort != 51514 {
		t.Errorf("client endpoint = %s:%d, want 10.0.0.9:51514", sess.ClientIP, sess.ClientPort)
	}
}

// TestServerHelloOnlyStillIdentifiesServer: if only the server side of the flow
// was captured, the ServerHello's SOURCE is the server.
func TestServerHelloOnlyStillIdentifiesServer(t *testing.T) {
	_, s := flow()
	tr, got := collect(t)

	tr.Feed(s, tlsRecord(0x16, 0x0303, handshakeMsg(0x02, serverHelloBody(0x0303, 0xC02F))), time.Now())
	tr.Flush()

	if len(*got) != 1 {
		t.Fatalf("expected 1 session, got %d", len(*got))
	}
	if (*got)[0].ServerIP != "10.0.0.1" || (*got)[0].ServerPort != 443 {
		t.Errorf("server endpoint = %s:%d", (*got)[0].ServerIP, (*got)[0].ServerPort)
	}
}

// TestApplicationDataCompletesSession: once encrypted data flows there is
// nothing more to read, so the session is emitted immediately rather than
// being held to end-of-capture.
func TestApplicationDataCompletesSession(t *testing.T) {
	c, s := flow()
	tr, got := collect(t)
	ts := time.Now()

	tr.Feed(c, tlsRecord(0x16, 0x0301, handshakeMsg(0x01, clientHelloBody(0x0303, []uint16{0xC02F}))), ts)
	tr.Feed(s, tlsRecord(0x16, 0x0303, handshakeMsg(0x02, serverHelloBody(0x0303, 0xC02F))), ts)
	if len(*got) != 0 {
		t.Fatal("session emitted too early")
	}
	tr.Feed(s, tlsRecord(0x17, 0x0303, []byte{0xde, 0xad, 0xbe, 0xef}), ts)
	if len(*got) != 1 {
		t.Fatalf("session should be emitted once application data starts, got %d", len(*got))
	}
}

// ---------------------------------------------------------------------------
// Finding 4 — bounded memory and untrusted SNI
// ---------------------------------------------------------------------------

func TestSanitizeHostname(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"api.example.com", "api.example.com"},
		{"*.wildcard.example.com", "*.wildcard.example.com"},
		{"", ""},
		{strings.Repeat("a", 254), ""},  // over the DNS maximum
		{"bad host.example.com", ""},    // space
		{"evil\x00.example.com", ""},    // NUL
		{"drop\ntable.example.com", ""}, // newline
		{"héllo.example.com", ""},       // non-ASCII
		{"...", ""},                     // no labels
		{strings.Repeat("a", 253), strings.Repeat("a", 253)}, // exactly at the limit
	}
	for _, tc := range tests {
		if got := SanitizeHostname(tc.in); got != tc.want {
			t.Errorf("SanitizeHostname(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestSNIFromCaptureIsSanitized: SNI comes straight off the wire and lands in
// the hostname column, so a hostile capture must not be able to put arbitrary
// bytes there.
func TestSNIFromCaptureIsSanitized(t *testing.T) {
	ch := ParseClientHello(clientHelloBody(0x0303, []uint16{0xC02F},
		sniExtension("evil host\nwith junk")))
	if ch.SNI != "" {
		t.Errorf("SNI = %q, want empty (unsanitary value rejected)", ch.SNI)
	}
}

// TestFlowByteCapAbandonsRunawayFlow pins the per-direction memory cap.
func TestFlowByteCapAbandonsRunawayFlow(t *testing.T) {
	c, _ := flow()
	tr, got := collect(t)
	ts := time.Now()

	// A handshake message header claiming a body that never arrives, followed
	// by a flood of well-framed records: the handshake buffer would grow
	// without bound if the cap were not enforced.
	hdr := append([]byte{0x01}, u24(250000)...)
	tr.Feed(c, tlsRecord(0x16, 0x0303, hdr), ts)
	chunk := make([]byte, 16*1024)
	for i := 0; i < 20; i++ {
		tr.Feed(c, tlsRecord(0x16, 0x0303, chunk), ts)
	}
	tr.Flush()

	if tr.Truncated == 0 {
		t.Fatal("expected the runaway flow to be truncated at the byte cap")
	}
	// Nothing parseable was seen, so nothing should be emitted.
	if len(*got) != 0 {
		t.Errorf("expected no sessions emitted, got %d", len(*got))
	}
}

// TestSessionCapEvicts pins the tracked-flow cap: a scan-heavy capture cannot
// balloon the tracker.
func TestSessionCapEvicts(t *testing.T) {
	tr := NewTracker(func(*Session) {})
	tr.maxSessions = 4
	ts := time.Now()

	// Partial ClientHello records so nothing completes and every flow stays
	// resident.
	partial := tlsRecord(0x16, 0x0301, handshakeMsg(0x01, clientHelloBody(0x0303, []uint16{0xC02F})))
	partial = partial[:len(partial)-4]

	for i := 0; i < 20; i++ {
		key := FlowKey{SrcIP: "10.0.0.9", SrcPort: 40000 + i, DstIP: "10.0.0.1", DstPort: 443}
		tr.Feed(key, partial, ts)
	}
	if len(tr.sessions) > 4 {
		t.Errorf("tracked sessions = %d, want <= 4", len(tr.sessions))
	}
	if tr.Evicted != 16 {
		t.Errorf("evicted = %d, want 16", tr.Evicted)
	}
}

// TestNonTLSTrafficIsNotTracked: unrelated TCP payloads must not allocate a
// flow buffer at all.
func TestNonTLSTrafficIsNotTracked(t *testing.T) {
	c, _ := flow()
	tr, got := collect(t)
	tr.Feed(c, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), time.Now())
	if len(tr.sessions) != 0 {
		t.Errorf("non-TLS payload allocated %d flow(s)", len(tr.sessions))
	}
	tr.Flush()
	if len(*got) != 0 {
		t.Errorf("non-TLS payload produced %d discoveries", len(*got))
	}
}

// TestDesyncedFlowIsAbandoned: a flow whose record framing stops making sense
// (loss, overlap) is dropped rather than mis-parsed into bogus inventory.
func TestDesyncedFlowIsAbandoned(t *testing.T) {
	c, _ := flow()
	tr, got := collect(t)
	ts := time.Now()

	tr.Feed(c, tlsRecord(0x16, 0x0301, handshakeMsg(0x01, clientHelloBody(0x0303, []uint16{0xC02F}))), ts)
	tr.Feed(c, []byte{0x99, 0x99, 0x99, 0x99, 0x99, 0x99}, ts) // not a record header
	if tr.Desynced != 1 {
		t.Errorf("desynced = %d, want 1", tr.Desynced)
	}
	// The ClientHello already parsed, so its session is still emitted.
	if len(*got) != 1 {
		t.Fatalf("expected the already-parsed session to be emitted, got %d", len(*got))
	}
	if len(tr.sessions) != 0 {
		t.Errorf("desynced flow still tracked")
	}
}

// ---------------------------------------------------------------------------
// Record / handshake framing
// ---------------------------------------------------------------------------

func TestDrainRecordsHoldsPartialRecord(t *testing.T) {
	rec := tlsRecord(0x16, 0x0303, []byte{1, 2, 3, 4, 5, 6})
	recs, rest, ok := drainRecords(rec[:8])
	if !ok {
		t.Fatal("drainRecords reported desync on a valid partial record")
	}
	if len(recs) != 0 {
		t.Errorf("emitted %d records from an incomplete one", len(recs))
	}
	if len(rest) != 8 {
		t.Errorf("rest = %d bytes, want 8 retained", len(rest))
	}
}

func TestDrainHandshakeHoldsPartialMessage(t *testing.T) {
	msg := handshakeMsg(0x02, serverHelloBody(0x0303, 0xC02F))
	msgs, rest, ok := drainHandshake(msg[:10])
	if !ok {
		t.Fatal("drainHandshake reported bad framing on a valid partial message")
	}
	if len(msgs) != 0 {
		t.Errorf("emitted %d messages from an incomplete one", len(msgs))
	}
	if len(rest) != 10 {
		t.Errorf("rest = %d bytes, want 10 retained", len(rest))
	}
}

func TestVersionNameUnknownIsEmpty(t *testing.T) {
	if got := VersionName(0x0305); got != "" {
		t.Errorf("VersionName(0x0305) = %q, want empty", got)
	}
	if got := VersionName(0x0304); got != "TLS 1.3" {
		t.Errorf("VersionName(0x0304) = %q", got)
	}
}

// TestTruncatedMessagesDoNotPanic fuzzes prefix truncation over each parser.
func TestTruncatedMessagesDoNotPanic(t *testing.T) {
	bodies := [][]byte{
		clientHelloBody(0x0303, []uint16{0x1301, 0xC02F}, clientSupportedVersions(0x0304), sniExtension("a.example.com")),
		serverHelloBody(0x0303, 0x1301, serverSupportedVersions(0x0304)),
		certificateBody(selfSignedDER(t, "trunc.example.com")),
	}
	for i, body := range bodies {
		for n := 0; n <= len(body); n++ {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("parser %d panicked at prefix length %d: %v", i, n, r)
					}
				}()
				switch i {
				case 0:
					ParseClientHello(body[:n])
				case 1:
					ParseServerHello(body[:n])
				case 2:
					ParseCertificateMessage(body[:n])
				}
			}()
		}
	}
}
