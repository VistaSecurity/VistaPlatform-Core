package capture

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/gopacket/gopacket/tcpassembly"
	"github.com/vistasecurity/vistaplatform/sensor/internal/cache"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

func TestOPCUAPolicyShortName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		uri  string
		want string
	}{
		{"http://opcfoundation.org/UA/SecurityPolicy#None", "None"},
		{"http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256", "Basic256Sha256"},
		{"http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss", "Aes256_Sha256_RsaPss"},
		{"NoFragment", "NoFragment"},
	}
	for _, c := range cases {
		if got := opcuaPolicyShortName(c.uri); got != c.want {
			t.Errorf("opcuaPolicyShortName(%q)=%q, want %q", c.uri, got, c.want)
		}
	}
}

func TestIsOPCUANonePolicy(t *testing.T) {
	t.Parallel()
	if !isOPCUANonePolicy("http://opcfoundation.org/UA/SecurityPolicy#None") {
		t.Error("expected None policy detected")
	}
	if isOPCUANonePolicy("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256") {
		t.Error("Basic256Sha256 wrongly classified as None")
	}
}

func TestIsOPCUADeprecatedPolicy(t *testing.T) {
	t.Parallel()
	if !isOPCUADeprecatedPolicy("http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15") {
		t.Error("Basic128Rsa15 should be deprecated")
	}
	if !isOPCUADeprecatedPolicy("http://opcfoundation.org/UA/SecurityPolicy#Basic256") {
		t.Error("Basic256 should be deprecated")
	}
	if isOPCUADeprecatedPolicy("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256") {
		t.Error("Basic256Sha256 wrongly classified as deprecated")
	}
}

func TestOPCUAParseSecurityPolicyURI(t *testing.T) {
	t.Parallel()
	// Build a synthetic OPN message body.
	uri := "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
	msg := buildOPCUAOPN(uri)
	got := opcuaParseSecurityPolicyURI(msg)
	if got != uri {
		t.Errorf("got %q, want %q", got, uri)
	}

	// Null URI (length = -1) → empty.
	msg2 := make([]byte, opcuaHeaderLen+8)
	copy(msg2[0:4], "OPNF")
	binary.LittleEndian.PutUint32(msg2[4:8], uint32(len(msg2)))
	binary.LittleEndian.PutUint32(msg2[opcuaHeaderLen+4:opcuaHeaderLen+8], 0xFFFFFFFF)
	if got := opcuaParseSecurityPolicyURI(msg2); got != "" {
		t.Errorf("null URI should return empty, got %q", got)
	}
}

func buildOPCUAHello() []byte {
	body := []byte("opc.tcp://test:4840")
	totalLen := opcuaHeaderLen + 24 + len(body)
	msg := make([]byte, totalLen)
	copy(msg[0:4], "HELF")
	binary.LittleEndian.PutUint32(msg[4:8], uint32(totalLen))
	binary.LittleEndian.PutUint32(msg[28:32], uint32(len(body)))
	copy(msg[32:], body)
	return msg
}

func buildOPCUAAck() []byte {
	msg := make([]byte, 28)
	copy(msg[0:4], "ACKF")
	binary.LittleEndian.PutUint32(msg[4:8], 28)
	return msg
}

func buildOPCUAOPN(uri string) []byte {
	uriBytes := []byte(uri)
	totalLen := opcuaHeaderLen + 4 + 4 + len(uriBytes)
	msg := make([]byte, totalLen)
	copy(msg[0:4], "OPNF")
	binary.LittleEndian.PutUint32(msg[4:8], uint32(totalLen))
	binary.LittleEndian.PutUint32(msg[opcuaHeaderLen:opcuaHeaderLen+4], 0x12345678) // ChannelID
	binary.LittleEndian.PutUint32(msg[opcuaHeaderLen+4:opcuaHeaderLen+8], uint32(len(uriBytes)))
	copy(msg[opcuaHeaderLen+8:], uriBytes)
	return msg
}

// buildOPCUAOPNWithCert constructs an OPN message carrying both a
// SecurityPolicy URI and a SenderCertificate ByteString, plus a null
// ReceiverCertificateThumbprint. Used to exercise the cert-extraction path.
func buildOPCUAOPNWithCert(uri string, certDER []byte) []byte {
	uriBytes := []byte(uri)
	bodyLen := 4 + // ChannelID
		4 + len(uriBytes) + // SecurityPolicyURI
		4 + len(certDER) + // SenderCertificate ByteString
		4 // ReceiverCertificateThumbprint length = -1 (null)
	totalLen := opcuaHeaderLen + bodyLen
	msg := make([]byte, totalLen)
	copy(msg[0:4], "OPNF")
	binary.LittleEndian.PutUint32(msg[4:8], uint32(totalLen))
	off := opcuaHeaderLen
	binary.LittleEndian.PutUint32(msg[off:off+4], 0x12345678) // ChannelID
	off += 4
	binary.LittleEndian.PutUint32(msg[off:off+4], uint32(len(uriBytes)))
	off += 4
	copy(msg[off:off+len(uriBytes)], uriBytes)
	off += len(uriBytes)
	binary.LittleEndian.PutUint32(msg[off:off+4], uint32(len(certDER)))
	off += 4
	copy(msg[off:off+len(certDER)], certDER)
	off += len(certDER)
	binary.LittleEndian.PutUint32(msg[off:off+4], 0xFFFFFFFF) // null thumbprint
	return msg
}

// newTestSelfSignedDER returns a freshly-generated self-signed ECDSA P-256
// certificate's DER bytes, suitable for stuffing into an OPC UA OPN body.
func newTestSelfSignedDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "opcua-test-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{"opcua-test-server"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	return der
}

func newTestOPCUAFactory(t *testing.T) (*OPCUAStreamFactory, chan *models.CryptoDiscovery) {
	t.Helper()
	ch := make(chan *models.CryptoDiscovery, 8)
	connCache := cache.NewConnectionCache(60*time.Minute, 1000)
	return NewOPCUAStreamFactory(ch, "test-sensor", connCache), ch
}

func preOPCUAStream(f *OPCUAStreamFactory) (*OPCUAStream, *opcuaSessionState) {
	state := &opcuaSessionState{
		sessionID:  "s1",
		serverIP:   "10.0.0.5",
		serverPort: 4840,
		clientIP:   "10.0.0.10",
	}
	f.mu.Lock()
	f.sessions[tlsFlowKey{}] = state
	f.mu.Unlock()
	return &OPCUAStream{factory: f, key: tlsFlowKey{}, state: state}, state
}

func feedOPCUA(s tcpassembly.Stream, data []byte) {
	s.Reassembled([]tcpassembly.Reassembly{{Bytes: data, Seen: time.Now()}})
}

func TestOPCUAAssembler_HelloAckEmitsBasicFinding(t *testing.T) {
	t.Parallel()
	factory, ch := newTestOPCUAFactory(t)
	stream, _ := preOPCUAStream(factory)

	feedOPCUA(stream, buildOPCUAHello())
	feedOPCUA(stream, buildOPCUAAck())

	select {
	case d := <-ch:
		if d.Protocol != "OPC_UA" {
			t.Errorf("Protocol=%s, want OPC_UA", d.Protocol)
		}
		if d.RawMetadata["opcua_phase"] != "hello-ack" {
			t.Errorf("opcua_phase=%v, want hello-ack", d.RawMetadata["opcua_phase"])
		}
		if d.RawMetadata["opcua_ack_seen"] != true {
			t.Errorf("opcua_ack_seen=%v, want true", d.RawMetadata["opcua_ack_seen"])
		}
	case <-time.After(time.Second):
		t.Fatal("expected basic OPC UA discovery")
	}
}

func TestOPCUAAssembler_OPNExtractsSecurityPolicy(t *testing.T) {
	t.Parallel()
	factory, ch := newTestOPCUAFactory(t)
	stream, _ := preOPCUAStream(factory)

	feedOPCUA(stream, buildOPCUAHello())
	feedOPCUA(stream, buildOPCUAAck())
	// Drain the basic finding from HEL/ACK.
	<-ch
	feedOPCUA(stream, buildOPCUAOPN("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"))

	select {
	case d := <-ch:
		if d.Version != "Basic256Sha256" {
			t.Errorf("Version=%s, want Basic256Sha256", d.Version)
		}
		if d.RawMetadata["security_policy_short"] != "Basic256Sha256" {
			t.Errorf("security_policy_short=%v", d.RawMetadata["security_policy_short"])
		}
		if d.RawMetadata["security"] != "present" {
			t.Errorf("security=%v, want present", d.RawMetadata["security"])
		}
	case <-time.After(time.Second):
		t.Fatal("expected OPN-driven discovery")
	}
}

func TestOPCUAAssembler_OPNNonePolicyClassifiedAsNoCrypto(t *testing.T) {
	t.Parallel()
	factory, ch := newTestOPCUAFactory(t)
	stream, _ := preOPCUAStream(factory)

	feedOPCUA(stream, buildOPCUAOPN("http://opcfoundation.org/UA/SecurityPolicy#None"))

	select {
	case d := <-ch:
		if d.RawMetadata["security"] != "none" {
			t.Errorf("security=%v, want none", d.RawMetadata["security"])
		}
	case <-time.After(time.Second):
		t.Fatal("expected None-policy discovery")
	}
}

func TestOPCUAAssembler_OPNDeprecatedPolicyClassifiedAsWeak(t *testing.T) {
	t.Parallel()
	factory, ch := newTestOPCUAFactory(t)
	stream, _ := preOPCUAStream(factory)

	feedOPCUA(stream, buildOPCUAOPN("http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"))

	select {
	case d := <-ch:
		if d.RawMetadata["security"] != "weak" {
			t.Errorf("security=%v, want weak", d.RawMetadata["security"])
		}
	case <-time.After(time.Second):
		t.Fatal("expected Basic128Rsa15 discovery")
	}
}

func TestOPCUAAssembler_NonOPCUABytesDropBuffer(t *testing.T) {
	t.Parallel()
	factory, ch := newTestOPCUAFactory(t)
	stream, _ := preOPCUAStream(factory)

	feedOPCUA(stream, []byte("GET / HTTP/1.1\r\n\r\n"))
	select {
	case d := <-ch:
		t.Errorf("expected no discovery on HTTP bytes, got %+v", d)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestOPCUAParseOPNBody_ExtractsSenderCertificate(t *testing.T) {
	t.Parallel()
	uri := "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
	certDER := newTestSelfSignedDER(t)
	msg := buildOPCUAOPNWithCert(uri, certDER)

	gotURI, gotCert := opcuaParseOPNBody(msg)
	if gotURI != uri {
		t.Errorf("uri = %q, want %q", gotURI, uri)
	}
	if len(gotCert) != len(certDER) {
		t.Fatalf("cert len = %d, want %d", len(gotCert), len(certDER))
	}
	for i := range certDER {
		if gotCert[i] != certDER[i] {
			t.Fatalf("cert byte %d differs", i)
		}
	}
	// Round-trip through x509 to confirm parseability.
	if _, err := x509.ParseCertificate(gotCert); err != nil {
		t.Errorf("ParseCertificate(extracted DER): %v", err)
	}
}

func TestOPCUAParseOPNBody_NullSenderCertificate(t *testing.T) {
	t.Parallel()
	// Body with valid URI but null SenderCertificate (typical of #None policy).
	uri := "http://opcfoundation.org/UA/SecurityPolicy#None"
	uriBytes := []byte(uri)
	totalLen := opcuaHeaderLen + 4 + 4 + len(uriBytes) + 4
	msg := make([]byte, totalLen)
	copy(msg[0:4], "OPNF")
	binary.LittleEndian.PutUint32(msg[4:8], uint32(totalLen))
	off := opcuaHeaderLen
	binary.LittleEndian.PutUint32(msg[off:off+4], 0x12345678)
	off += 4
	binary.LittleEndian.PutUint32(msg[off:off+4], uint32(len(uriBytes)))
	off += 4
	copy(msg[off:off+len(uriBytes)], uriBytes)
	off += len(uriBytes)
	binary.LittleEndian.PutUint32(msg[off:off+4], 0xFFFFFFFF) // null cert
	gotURI, gotCert := opcuaParseOPNBody(msg)
	if gotURI != uri {
		t.Errorf("uri = %q, want %q", gotURI, uri)
	}
	if gotCert != nil {
		t.Errorf("expected nil cert for null ByteString, got %d bytes", len(gotCert))
	}
}

func TestOPCUAParseOPNBody_TruncatedCertReturnsNil(t *testing.T) {
	t.Parallel()
	// Claim a 100-byte cert but truncate the body — parser must not panic
	// or read past the buffer.
	uri := "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
	uriBytes := []byte(uri)
	totalLen := opcuaHeaderLen + 4 + 4 + len(uriBytes) + 4 + 10 // declare 100, supply 10
	msg := make([]byte, totalLen)
	copy(msg[0:4], "OPNF")
	binary.LittleEndian.PutUint32(msg[4:8], uint32(totalLen))
	off := opcuaHeaderLen
	binary.LittleEndian.PutUint32(msg[off:off+4], 0x12345678)
	off += 4
	binary.LittleEndian.PutUint32(msg[off:off+4], uint32(len(uriBytes)))
	off += 4
	copy(msg[off:off+len(uriBytes)], uriBytes)
	off += len(uriBytes)
	binary.LittleEndian.PutUint32(msg[off:off+4], 100) // claimed cert length
	// only 10 bytes of "cert" actually present in the buffer
	gotURI, gotCert := opcuaParseOPNBody(msg)
	if gotURI != uri {
		t.Errorf("uri = %q, want %q", gotURI, uri)
	}
	if gotCert != nil {
		t.Errorf("expected nil cert when declared length exceeds buffer, got %d bytes", len(gotCert))
	}
}

func TestOPCUAAssembler_OPNWithSenderCertExposesCertificatesMetadata(t *testing.T) {
	t.Parallel()
	factory, ch := newTestOPCUAFactory(t)
	stream, _ := preOPCUAStream(factory)

	uri := "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
	certDER := newTestSelfSignedDER(t)
	feedOPCUA(stream, buildOPCUAOPNWithCert(uri, certDER))

	select {
	case d := <-ch:
		certsRaw, ok := d.RawMetadata["certificates"]
		if !ok {
			t.Fatalf("expected `certificates` in RawMetadata, got: %#v", d.RawMetadata)
		}
		certs, ok := certsRaw.([]interface{})
		if !ok || len(certs) != 1 {
			t.Fatalf("expected 1 certificate, got: %#v", certsRaw)
		}
		first, ok := certs[0].(map[string]interface{})
		if !ok {
			t.Fatalf("certificate not a map: %#v", certs[0])
		}
		if first["subject_dn"] != "CN=opcua-test-server" {
			t.Errorf("subject_dn = %v, want CN=opcua-test-server", first["subject_dn"])
		}
		if first["fingerprint_sha256"] == "" || first["fingerprint_sha256"] == nil {
			t.Errorf("expected non-empty fingerprint_sha256")
		}
		if first["key_algorithm"] != "ECDSA" {
			t.Errorf("key_algorithm = %v, want ECDSA", first["key_algorithm"])
		}
	case <-time.After(time.Second):
		t.Fatal("expected OPN-with-cert discovery")
	}
}

func TestOPCUAAssembler_OPNWithoutCertOmitsCertificatesMetadata(t *testing.T) {
	t.Parallel()
	factory, ch := newTestOPCUAFactory(t)
	stream, _ := preOPCUAStream(factory)

	feedOPCUA(stream, buildOPCUAOPN("http://opcfoundation.org/UA/SecurityPolicy#None"))

	select {
	case d := <-ch:
		if _, ok := d.RawMetadata["certificates"]; ok {
			t.Errorf("certificates should be absent when no SenderCertificate present, got: %#v", d.RawMetadata["certificates"])
		}
	case <-time.After(time.Second):
		t.Fatal("expected #None-policy discovery")
	}
}

func TestOPCUAAssembler_FlushOldSessions(t *testing.T) {
	t.Parallel()
	factory, _ := newTestOPCUAFactory(t)
	old := &opcuaSessionState{lastSeen: time.Now().Add(-2 * time.Hour)}
	factory.mu.Lock()
	factory.sessions[tlsFlowKey{}] = old
	factory.mu.Unlock()
	factory.FlushOldSessions(time.Hour)
	factory.mu.Lock()
	if _, exists := factory.sessions[tlsFlowKey{}]; exists {
		t.Errorf("expected old session to be flushed")
	}
	factory.mu.Unlock()
}
