package capture

import (
	"crypto/x509"
	"encoding/binary"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/tcpassembly"
	"github.com/vistasecurity/vistaplatform/sensor/internal/cache"
	"github.com/vistasecurity/vistaplatform/sensor/internal/discovery"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// OPC UA Binary passive detector for TCP port 4840.
//
// OPC UA is the modern OT secure protocol — x509 certs, configurable
// SecurityPolicies, message signing/encryption modes. The passive parser
// here recognizes the framing:
//
//   Hello (HEL)     — first client → server message; confirms OPC UA service
//   Acknowledge (ACK) — server → client; confirms server speaks OPC UA Binary
//   OpenSecureChannel (OPN) — carries the SecurityPolicy URI
//
// We extract the SecurityPolicy URI (e.g. "...#Basic256Sha256") from the
// OPN body. The sender certificate is also in the OPN body as a ByteString
// — we don't currently parse it through the cert pipeline (that's a
// follow-up; the framing and offsets are correct so layering on the x509
// extraction is straightforward when product wants it).
//
// Reference: OPC 10000-6 §7 (Mappings) for binary message structure;
// OPC 10000-7 §6 for SecurityPolicies.

// OPC UA Binary message types we parse. The 4th byte is "F" (final),
// "C" (intermediate chunk), or "A" (abort) — we only care about the
// 3-letter prefix for classification.
const (
	opcuaHeaderLen = 8 // 4-byte type + 4-byte LE size
)

// opcuaSessionState tracks one TCP flow's accumulated bytes and the
// strongest OPC UA classification reached.
type opcuaSessionState struct {
	sessionID  string
	serverIP   string
	serverPort int
	clientIP   string
	iface      string
	buffer     []byte

	helSeen        bool
	ackSeen        bool
	emittedBasic   bool // emitted the bare OPC UA finding (HEL/ACK level)
	emittedPolicy  bool // emitted with SecurityPolicy URI (OPN level)
	securityPolicy string
	senderCerts    []models.CertificateInfo // extracted from OPN SenderCertificate ByteString

	lastSeen time.Time
}

// OPCUAStreamFactory creates one OPCUAStream per TCP flow on port 4840.
type OPCUAStreamFactory struct {
	mu           sync.Mutex
	sessions     map[tlsFlowKey]*opcuaSessionState
	ifacePending sync.Map
	discoveries  chan<- *models.CryptoDiscovery
	sensorID     string
	cache        *cache.ConnectionCache
}

func NewOPCUAStreamFactory(discoveries chan<- *models.CryptoDiscovery, sensorID string, connCache *cache.ConnectionCache) *OPCUAStreamFactory {
	return &OPCUAStreamFactory{
		sessions:    make(map[tlsFlowKey]*opcuaSessionState),
		discoveries: discoveries,
		sensorID:    sensorID,
		cache:       connCache,
	}
}

func (f *OPCUAStreamFactory) RegisterIfaceForFlow(key tlsFlowKey, iface string) {
	if iface != "" {
		f.ifacePending.Store(key, iface)
	}
}

func (f *OPCUAStreamFactory) New(netFlow, transportFlow gopacket.Flow) tcpassembly.Stream {
	key := tlsFlowKey{net: netFlow, transport: transportFlow}
	dstPort := portFromEndpoint(transportFlow.Dst())
	srcPort := portFromEndpoint(transportFlow.Src())

	serverIP := netFlow.Dst().String()
	serverPort := dstPort
	clientIP := netFlow.Src().String()
	if srcPort == 4840 && dstPort != 4840 {
		serverIP = netFlow.Src().String()
		serverPort = srcPort
		clientIP = netFlow.Dst().String()
	}

	iface := ""
	if v, ok := f.ifacePending.LoadAndDelete(key); ok {
		iface, _ = v.(string)
	}

	f.mu.Lock()
	state, exists := f.sessions[key]
	if !exists {
		state = &opcuaSessionState{
			sessionID:  uuid.New().String(),
			serverIP:   serverIP,
			serverPort: serverPort,
			clientIP:   clientIP,
			iface:      iface,
			lastSeen:   time.Now(),
		}
		f.sessions[key] = state
	} else if iface != "" && state.iface == "" {
		state.iface = iface
	}
	f.mu.Unlock()

	return &OPCUAStream{factory: f, key: key, state: state}
}

func (f *OPCUAStreamFactory) FlushOldSessions(maxAge time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for key, state := range f.sessions {
		if state.lastSeen.Before(cutoff) {
			delete(f.sessions, key)
		}
	}
}

// OPCUAStream consumes reassembled bytes for one TCP flow.
type OPCUAStream struct {
	factory *OPCUAStreamFactory
	key     tlsFlowKey
	state   *opcuaSessionState
}

func (s *OPCUAStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	for _, r := range reassembly {
		s.state.buffer = append(s.state.buffer, r.Bytes...)
		s.state.lastSeen = time.Now()
	}
	if len(s.state.buffer) > 16384 {
		s.state.buffer = s.state.buffer[:16384]
	}
	s.processBuffer()
}

func (s *OPCUAStream) ReassemblyComplete() {
	s.processBuffer()
	s.factory.mu.Lock()
	delete(s.factory.sessions, s.key)
	s.factory.mu.Unlock()
}

// processBuffer walks complete OPC UA Binary messages from the buffer.
// Stops once we've extracted a SecurityPolicy URI — that's the strongest
// classification this passive parser produces.
func (s *OPCUAStream) processBuffer() {
	if s.state.emittedPolicy {
		s.state.buffer = nil
		return
	}

	buf := s.state.buffer
	consumed := 0
	for consumed+opcuaHeaderLen <= len(buf) {
		view := buf[consumed:]
		// Validate: first 3 bytes must be a known message type prefix and
		// the 4th byte must be ASCII 'F'/'C'/'A'. If not, this isn't OPC
		// UA Binary — drop the buffer.
		typ := string(view[0:3])
		flag := view[3]
		if (flag != 'F' && flag != 'C' && flag != 'A') || !isOPCUAType(typ) {
			s.state.buffer = nil
			return
		}
		size := int(binary.LittleEndian.Uint32(view[4:8]))
		if size < opcuaHeaderLen || size > len(view) {
			break // wait for more bytes
		}
		s.handleMessage(typ, view[:size])
		consumed += size
		if s.state.emittedPolicy {
			break
		}
	}
	if consumed > 0 {
		s.state.buffer = buf[consumed:]
	}
}

func isOPCUAType(t string) bool {
	switch t {
	case "HEL", "ACK", "OPN", "MSG", "CLO", "ERR":
		return true
	}
	return false
}

// handleMessage dispatches one OPC UA Binary message. HEL/ACK confirm the
// service is OPC UA; OPN carries the SecurityPolicyURI which is the more
// valuable inventory data.
func (s *OPCUAStream) handleMessage(typ string, msg []byte) {
	switch typ {
	case "HEL":
		s.state.helSeen = true
	case "ACK":
		s.state.ackSeen = true
		// Once we've seen at least one of HEL/ACK, emit a basic OPC UA
		// finding. The SecurityPolicy URI from OPN will upgrade it.
		if !s.state.emittedBasic {
			s.emit("hello-ack", "")
		}
	case "OPN":
		// OPN body layout (after the 8-byte header):
		//   ChannelID(4 LE) SecurityPolicyURI(string)
		//     SenderCert(byteString) ReceiverCertThumbprint(byteString) ...
		// String / ByteString encoding: 4-byte LE length (-1 = null),
		// then UTF-8 / DER bytes.
		uri, certDER := opcuaParseOPNBody(msg)
		if len(certDER) > 0 {
			if cert, err := x509.ParseCertificate(certDER); err == nil {
				s.state.senderCerts = discovery.ExtractCertificatesFromX509([]*x509.Certificate{cert})
			}
		}
		if uri != "" {
			s.state.securityPolicy = uri
			s.emit("open-secure-channel", uri)
		} else if !s.state.emittedBasic {
			s.emit("open-secure-channel", "")
		}
	}
}

// opcuaParseSecurityPolicyURI extracts the SecurityPolicy URI from an OPN
// message. Returns "" when the body is too short or the string length
// indicates null.
func opcuaParseSecurityPolicyURI(msg []byte) string {
	uri, _ := opcuaParseOPNBody(msg)
	return uri
}

// opcuaParseOPNBody extracts the SecurityPolicy URI and the sender's DER
// certificate bytes from an OpenSecureChannel message. Returns ("", nil) on
// malformed or truncated input. The sender certificate is the ByteString
// immediately following the URI; -1 length means null (typical for #None
// policy sessions).
//
// OPN body layout (after the 8-byte header):
//
//	ChannelID(4 LE)
//	SecurityPolicyURI: 4-byte LE length, then UTF-8 bytes (-1 = null)
//	SenderCertificate: 4-byte LE length, then DER bytes (-1 = null)
//	ReceiverCertificateThumbprint: ByteString ...
func opcuaParseOPNBody(msg []byte) (string, []byte) {
	if len(msg) < opcuaHeaderLen+4+4 {
		return "", nil
	}
	uriLenRaw := int32(binary.LittleEndian.Uint32(msg[opcuaHeaderLen+4 : opcuaHeaderLen+8]))
	uriStart := opcuaHeaderLen + 8
	var uri string
	cursor := uriStart
	if uriLenRaw > 0 {
		uriLen := int(uriLenRaw)
		if uriStart+uriLen > len(msg) {
			return "", nil
		}
		uri = string(msg[uriStart : uriStart+uriLen])
		cursor = uriStart + uriLen
	}
	if cursor+4 > len(msg) {
		return uri, nil
	}
	certLenRaw := int32(binary.LittleEndian.Uint32(msg[cursor : cursor+4]))
	cursor += 4
	if certLenRaw <= 0 {
		return uri, nil
	}
	certLen := int(certLenRaw)
	if cursor+certLen > len(msg) {
		return uri, nil
	}
	cert := make([]byte, certLen)
	copy(cert, msg[cursor:cursor+certLen])
	return uri, cert
}

// emit constructs a CryptoDiscovery for the OPC UA session. `phase`
// distinguishes the bare HEL/ACK detection from the SecurityPolicy-URI
// upgrade; `policyURI` is empty for the basic finding.
func (s *OPCUAStream) emit(phase, policyURI string) {
	dedupKey := "OPC_UA"
	if policyURI != "" {
		dedupKey = "OPC_UA-OPN"
	}
	if s.factory.cache != nil && s.state.serverIP != "" {
		shouldReport, _ := s.factory.cache.ShouldReport(s.state.serverIP, s.state.serverPort, dedupKey)
		if !shouldReport {
			if policyURI != "" {
				s.state.emittedPolicy = true
			} else {
				s.state.emittedBasic = true
			}
			return
		}
	}

	metadata := map[string]interface{}{
		"session_id":     s.state.sessionID,
		"reassembled":    true,
		"opcua_phase":    phase,
		"opcua_hel_seen": s.state.helSeen,
		"opcua_ack_seen": s.state.ackSeen,
	}
	if policyURI != "" {
		metadata["security_policy"] = policyURI
		metadata["security_policy_short"] = opcuaPolicyShortName(policyURI)
		// "None" policy is a high-severity finding — it means the OPC UA
		// session has neither signing nor encryption.
		if isOPCUANonePolicy(policyURI) {
			metadata["security"] = "none"
		} else if isOPCUADeprecatedPolicy(policyURI) {
			metadata["security"] = "weak"
		} else {
			metadata["security"] = "present"
		}
	}
	if s.state.iface != "" {
		metadata["interface"] = s.state.iface
	}
	if len(s.state.senderCerts) > 0 {
		certsSlice := make([]interface{}, len(s.state.senderCerts))
		for i, cert := range s.state.senderCerts {
			certsSlice[i] = map[string]interface{}{
				"serial_number":             cert.SerialNumber,
				"subject_dn":                cert.SubjectDN,
				"issuer_dn":                 cert.IssuerDN,
				"not_before":                cert.NotBefore.Format(time.RFC3339),
				"not_after":                 cert.NotAfter.Format(time.RFC3339),
				"key_algorithm":             cert.KeyAlgorithm,
				"signature_alg":             cert.SignatureAlg,
				"is_ca":                     cert.IsCA,
				"certificate_pem":           cert.CertificatePEM,
				"fingerprint_sha256":        cert.FingerprintSHA256,
				"fingerprint_sha1":          cert.FingerprintSHA1,
				"subject_alternative_names": cert.SubjectAlternativeNames,
				"key_usage":                 cert.KeyUsage,
				"extended_key_usage":        cert.ExtendedKeyUsage,
				"key_size":                  cert.KeySize,
				"chain_order":               cert.ChainOrder,
			}
		}
		metadata["certificates"] = certsSlice
	}

	version := "OPC UA Binary"
	if policyURI != "" {
		version = opcuaPolicyShortName(policyURI)
	}

	discovery := &models.CryptoDiscovery{
		ID:              uuid.New().String(),
		SensorID:        s.factory.sensorID,
		Timestamp:       time.Now(),
		SourceIP:        s.state.clientIP,
		DestIP:          s.state.serverIP,
		Port:            s.state.serverPort,
		Protocol:        "OPC_UA",
		Version:         version,
		CipherSuite:     "",
		DiscoveryMethod: "passive",
		Confidence:      0.9,
		RawMetadata:     metadata,
		SessionID:       s.state.sessionID,
		CreatedAt:       time.Now(),
	}
	if policyURI != "" {
		s.state.emittedPolicy = true
	}
	s.state.emittedBasic = true

	select {
	case s.factory.discoveries <- discovery:
	default:
		log.Printf("Warning: OPC UA discovery channel full, dropping session %s", s.state.sessionID)
	}
}

// opcuaPolicyShortName returns the trailing identifier of an OPC UA
// SecurityPolicy URI (e.g. "Basic256Sha256" from
// "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"). Returns
// the input unchanged when there's no '#' fragment.
func opcuaPolicyShortName(uri string) string {
	for i := len(uri) - 1; i >= 0; i-- {
		if uri[i] == '#' {
			return uri[i+1:]
		}
	}
	return uri
}

// isOPCUANonePolicy reports whether the URI is the OPC UA #None policy
// (no signing, no encryption).
func isOPCUANonePolicy(uri string) bool {
	return opcuaPolicyShortName(uri) == "None"
}

// isOPCUADeprecatedPolicy reports whether the URI is one of the OPC
// Foundation-deprecated policies (Basic128Rsa15, Basic256). These use
// SHA-1 and are no longer recommended.
func isOPCUADeprecatedPolicy(uri string) bool {
	switch opcuaPolicyShortName(uri) {
	case "Basic128Rsa15", "Basic256":
		return true
	}
	return false
}

// Compile-time interface checks
var _ tcpassembly.Stream = (*OPCUAStream)(nil)
var _ tcpassembly.StreamFactory = (*OPCUAStreamFactory)(nil)
