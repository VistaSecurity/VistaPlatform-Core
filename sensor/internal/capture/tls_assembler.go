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
	"github.com/vistasecurity/vistaplatform/sensor/internal/crypto"
	"github.com/vistasecurity/vistaplatform/sensor/internal/discovery"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// tlsFlowKey identifies a TCP flow by the server-side endpoint.
// Server role is inferred by port: the side on the lower (or well-known) port is treated as
// the server. This heuristic works for typical deployments but can misidentify roles when
// a server listens on an ephemeral port. In that case source/dest IPs may be swapped in
// the emitted discovery.
type tlsFlowKey struct {
	net, transport gopacket.Flow
}

// tlsSessionState tracks the state of a TLS handshake across multiple packets
type tlsSessionState struct {
	sessionID  string
	serverIP   string
	serverPort int
	clientIP   string
	iface      string
	protocol   string
	buffer     []byte
	// version is the NEGOTIATED protocol version, taken only from the
	// ServerHello (legacy server_version, or supported_versions when the
	// server sends it). It is never populated from the ClientHello — the
	// client's best offer is not what the connection actually used.
	version string
	// clientMaxOfferedVersion is the highest version the client advertised in
	// its ClientHello supported_versions extension. Kept as separate metadata
	// so a modern client talking to a TLS 1.2-only server is not inventoried
	// as TLS 1.3.
	clientMaxOfferedVersion string
	cipherSuite             string
	certificates            []models.CertificateInfo
	sniServerName           string
	certValStatus           string
	certValError            string
	certQualityFlags        map[string]interface{}
	supportedCiphers        []string
	handshakeTypes          map[uint8]bool
	lastSeen                time.Time
	complete                bool

	// JA3/JA4 fingerprinting fields
	ja3Hash        string
	ja4Fingerprint string
	// ALPN protocol negotiation
	alpnProtocols []string // from ClientHello
	selectedALPN  string   // from ServerHello

	// STARTTLS detection
	starttlsDetected bool
	starttlsProtocol string
	starttlsPort     int

	// mTLS detection — track client certificate exchange
	sawCertRequest     bool
	clientCertificates []models.CertificateInfo
}

// TLSStreamFactory creates TLSStream instances for each new TCP flow.
// All reads and writes of the sessions map MUST hold mu. This includes
// New(), FlushOldSessions(), ReassemblyComplete(), and parseCertificate()
// which calls emitDiscovery under the lock.
type TLSStreamFactory struct {
	mu             sync.Mutex
	sessions       map[tlsFlowKey]*tlsSessionState
	discoveries    chan<- *models.CryptoDiscovery
	sensorID       string
	cache          *cache.ConnectionCache // shared dedup cache (same instance as fallback path)
	enableSTARTTLS bool
	starttlsPorts  []int
}

// NewTLSStreamFactory creates a new TLSStreamFactory
func NewTLSStreamFactory(discoveries chan<- *models.CryptoDiscovery, sensorID string, connCache *cache.ConnectionCache, enableSTARTTLS bool, starttlsPorts []int) *TLSStreamFactory {
	return &TLSStreamFactory{
		sessions:       make(map[tlsFlowKey]*tlsSessionState),
		discoveries:    discoveries,
		sensorID:       sensorID,
		cache:          connCache,
		enableSTARTTLS: enableSTARTTLS,
		starttlsPorts:  starttlsPorts,
	}
}

// New creates a new TLSStream for a TCP flow
func (f *TLSStreamFactory) New(netFlow, transportFlow gopacket.Flow) tcpassembly.Stream {
	key := tlsFlowKey{net: netFlow, transport: transportFlow}

	f.mu.Lock()
	state := &tlsSessionState{
		sessionID:      uuid.New().String(),
		serverIP:       netFlow.Dst().String(),
		serverPort:     portFromEndpoint(transportFlow.Dst()),
		clientIP:       netFlow.Src().String(),
		protocol:       getProtocolFromPort(portFromEndpoint(transportFlow.Dst()), f.enableSTARTTLS, f.starttlsPorts),
		handshakeTypes: make(map[uint8]bool),
		lastSeen:       time.Now(),
	}
	if state.protocol == "" {
		// Also check src port (server may be on src side)
		state.protocol = getProtocolFromPort(portFromEndpoint(transportFlow.Src()), f.enableSTARTTLS, f.starttlsPorts)
		if state.protocol != "" {
			state.serverIP = netFlow.Src().String()
			state.serverPort = portFromEndpoint(transportFlow.Src())
			state.clientIP = netFlow.Dst().String()
		}
	}
	f.sessions[key] = state
	f.mu.Unlock()

	return &TLSStream{
		factory: f,
		key:     key,
		state:   state,
	}
}

// FlushOldSessions flushes incomplete sessions older than maxAge, emitting partial discoveries
func (f *TLSStreamFactory) FlushOldSessions(maxAge time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for key, state := range f.sessions {
		if state.lastSeen.Before(cutoff) && !state.complete {
			if len(state.handshakeTypes) > 0 && state.protocol != "" {
				f.emitDiscovery(state, false)
			}
			delete(f.sessions, key)
		}
	}
}

// emitDiscovery creates and sends a CryptoDiscovery for a completed/timed-out session.
// Must be called with f.mu held. skipDedup bypasses ConnectionCache (e.g. mTLS supplemental emit).
func (f *TLSStreamFactory) emitDiscovery(state *tlsSessionState, skipDedup bool) {
	// Dedup check: skip if the same server endpoint was recently reported.
	// f.cache is the shared ConnectionCache used by the fallback path too,
	// so the 60-minute rest period applies consistently across both paths.
	if !skipDedup && f.cache != nil && state.serverIP != "" {
		shouldReport, _ := f.cache.ShouldReport(state.serverIP, state.serverPort, "TLS")
		if !shouldReport {
			return
		}
	}
	metadata := map[string]interface{}{
		"session_id":  state.sessionID,
		"reassembled": true,
	}
	if len(state.handshakeTypes) > 0 {
		types := make([]string, 0)
		names := map[uint8]string{0x01: "ClientHello", 0x02: "ServerHello", 0x0B: "Certificate"}
		for ht := range state.handshakeTypes {
			if name, ok := names[ht]; ok {
				types = append(types, name)
			}
		}
		metadata["handshake_types"] = types
	}
	if len(state.certificates) > 0 {
		certsSlice := make([]interface{}, len(state.certificates))
		for i, cert := range state.certificates {
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
	if state.certValStatus != "" {
		metadata["cert_validation_status"] = state.certValStatus
	}
	if state.certValError != "" {
		metadata["cert_validation_error"] = state.certValError
	}
	// Certificate quality flags go at the TOP LEVEL of the metadata — that is
	// where every downstream consumer reads them (inventory-service
	// applyCertQualityFlags, discovery-processor extractCryptoDetails).
	for k, v := range state.certQualityFlags {
		metadata[k] = v
	}
	// The client's advertised maximum, kept distinct from the negotiated
	// version so it can never be mistaken for what the connection used.
	if state.clientMaxOfferedVersion != "" {
		metadata["client_max_offered_version"] = state.clientMaxOfferedVersion
	}
	if state.sniServerName != "" {
		metadata["sni_server_name"] = state.sniServerName
	}
	if len(state.supportedCiphers) > 0 {
		metadata["supported_ciphers"] = state.supportedCiphers
	}
	if state.cipherSuite != "" {
		if kex := crypto.ParseKeyExchangeAlgorithm(state.cipherSuite); kex != "" {
			metadata["key_exchange_algorithm"] = kex
		}
	}
	if state.iface != "" {
		metadata["interface"] = state.iface
	}
	if state.ja3Hash != "" {
		metadata["ja3_hash"] = state.ja3Hash
	}
	if state.ja4Fingerprint != "" {
		metadata["ja4_fingerprint"] = state.ja4Fingerprint
	}
	if len(state.alpnProtocols) > 0 {
		metadata["alpn_protocols"] = state.alpnProtocols
	}
	if state.selectedALPN != "" {
		metadata["alpn_selected"] = state.selectedALPN
	}
	// BACnet/SC (ASHRAE 135 Annex AB) runs BACnet over WebSocket-over-TLS
	// and identifies itself via ALPN "bacnet.sc". Tag the discovery so the
	// OT lens can show BACnet/SC distinct from classic BACnet/IP.
	emittedProtocol := state.protocol
	if isBACnetSCALPN(state.selectedALPN) || isBACnetSCALPN(firstString(state.alpnProtocols)) {
		emittedProtocol = "BACNET_SC"
		metadata["ot_subprotocol"] = "bacnet.sc"
		metadata["bacnet_sc"] = true
	}
	if state.starttlsDetected {
		metadata["starttls_detected"] = true
		metadata["starttls_protocol"] = state.starttlsProtocol
		metadata["starttls_port"] = state.starttlsPort
	}
	// Tag DNS-over-TLS connections for UI classification
	if state.serverPort == 853 {
		metadata["service_hint"] = "dns-over-tls"
	}
	// IEC 62351-3 classification on energy-relevant ports — applies to
	// TLS-wrapped MMS/ICCP (102), DNP3/TLS (20000), CIM (4712), and HMI/EMS
	// web traffic (443, 8443). Returns nil on unrelated ports.
	if state.serverPort != 0 {
		var keyAlg string
		var keyBits int
		if len(state.certificates) > 0 {
			keyAlg = state.certificates[0].KeyAlgorithm
			keyBits = state.certificates[0].KeySize
		}
		if cls := ClassifyIEC62351(state.serverPort, state.version, state.cipherSuite, keyAlg, keyBits); cls != nil {
			for k, v := range cls.ToMetadata() {
				metadata[k] = v
			}
		}
	}
	// mTLS detection — client certificate was presented
	if len(state.clientCertificates) > 0 {
		metadata["mtls_detected"] = true
		clientCertsSlice := make([]interface{}, len(state.clientCertificates))
		for i, cert := range state.clientCertificates {
			clientCertsSlice[i] = map[string]interface{}{
				"subject_dn":         cert.SubjectDN,
				"issuer_dn":          cert.IssuerDN,
				"not_before":         cert.NotBefore.Format(time.RFC3339),
				"not_after":          cert.NotAfter.Format(time.RFC3339),
				"key_algorithm":      cert.KeyAlgorithm,
				"fingerprint_sha256": cert.FingerprintSHA256,
				"key_size":           cert.KeySize,
			}
		}
		metadata["client_certificates"] = clientCertsSlice
	} else if state.sawCertRequest {
		// Server requested client cert but none was provided
		metadata["mtls_detected"] = false
		metadata["server_requests_client_cert"] = true
	}

	// Determine confidence based on what we observed
	confidence := 0.7
	if len(state.certificates) > 0 {
		confidence = 0.95
	} else if state.cipherSuite != "" {
		confidence = 0.9
	}

	discovery := &models.CryptoDiscovery{
		ID:              uuid.New().String(),
		SensorID:        f.sensorID,
		Timestamp:       time.Now(),
		SourceIP:        state.clientIP,
		DestIP:          state.serverIP,
		Port:            state.serverPort,
		Protocol:        emittedProtocol,
		Version:         state.version,
		CipherSuite:     state.cipherSuite,
		DiscoveryMethod: "passive",
		Confidence:      confidence,
		RawMetadata:     metadata,
		SessionID:       state.sessionID,
		CreatedAt:       time.Now(),
	}

	select {
	case f.discoveries <- discovery:
	default:
		log.Printf("Warning: assembler discovery channel full, dropping session %s", state.sessionID)
	}
}

// TLSStream receives reassembled bytes for a single TCP flow
type TLSStream struct {
	factory *TLSStreamFactory
	key     tlsFlowKey
	state   *tlsSessionState
}

// Reassembled is called by the tcpassembly library with reassembled byte slices
func (s *TLSStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	for _, r := range reassembly {
		s.state.buffer = append(s.state.buffer, r.Bytes...)
		s.state.lastSeen = time.Now()
	}
	s.processTLSBuffer()
}

// ReassemblyComplete is called when the TCP stream is complete (FIN/RST)
func (s *TLSStream) ReassemblyComplete() {
	s.processTLSBuffer()

	s.factory.mu.Lock()
	defer s.factory.mu.Unlock()

	state := s.state
	if !state.complete && len(state.handshakeTypes) > 0 && state.protocol != "" {
		state.complete = true
		s.factory.emitDiscovery(state, false)
	}
	delete(s.factory.sessions, s.key)
}

// processTLSBuffer processes accumulated bytes looking for TLS handshake records
func (s *TLSStream) processTLSBuffer() {
	buf := s.state.buffer
	for len(buf) >= 5 {
		// TLS record header: ContentType(1) + LegacyVersion(2) + Length(2)
		if buf[0] != 0x16 { // Not a handshake record
			// Skip one byte and try again (allow recovery from partial data)
			buf = buf[1:]
			continue
		}

		recordLen := int(binary.BigEndian.Uint16(buf[3:5]))
		if len(buf) < 5+recordLen {
			break // Wait for more data
		}

		record := buf[5 : 5+recordLen]
		s.processHandshakeRecord(record)
		buf = buf[5+recordLen:]
	}
	s.state.buffer = buf
}

// processHandshakeRecord processes a complete TLS handshake record
func (s *TLSStream) processHandshakeRecord(record []byte) {
	if len(record) < 4 {
		return
	}

	handshakeType := record[0]
	msgLen := int(record[1])<<16 | int(record[2])<<8 | int(record[3])
	if len(record) < 4+msgLen {
		return
	}

	s.state.handshakeTypes[handshakeType] = true
	msg := record[4 : 4+msgLen]

	switch handshakeType {
	case 0x01: // ClientHello
		s.parseClientHello(msg)
	case 0x02: // ServerHello
		s.parseServerHello(msg)
	case 0x0B: // Certificate
		s.parseCertificate(msg)
	case 0x0D: // CertificateRequest — server is requesting client authentication (mTLS)
		s.state.sawCertRequest = true
	}
}

// parseClientHello extracts cipher suites, version, JA3/JA4, and ALPN from ClientHello
func (s *TLSStream) parseClientHello(msg []byte) {
	// Use the shared JA3 parser which extracts all needed fields in one pass
	ja3Input, alpnProtocols, sni := ParseClientHelloJA3Fields(msg)

	// Set SNI
	if sni != "" {
		s.state.sniServerName = sni
	}

	// Set ALPN protocols
	if len(alpnProtocols) > 0 {
		s.state.alpnProtocols = alpnProtocols
	}

	// Extract cipher names for the supported_ciphers list
	var ciphers []string
	for _, suite := range ja3Input.CipherSuites {
		if name := tlsCipherName(suite); name != "" {
			ciphers = append(ciphers, name)
		}
	}
	if len(ciphers) > 0 {
		s.state.supportedCiphers = ciphers
	}

	// Compute JA3/JA4 fingerprints
	ja3Hash, _ := ComputeJA3(ja3Input)
	s.state.ja3Hash = ja3Hash
	s.state.ja4Fingerprint = ComputeJA4(ja3Input, alpnProtocols, sni != "")

	// Parse extensions for TLS version (supported_versions)
	// We still need this since ParseClientHelloJA3Fields returns the wire version,
	// not the supported_versions negotiated version
	if len(msg) < 35 {
		return
	}
	offset := 34
	sidLen := int(msg[offset])
	offset++
	offset += sidLen
	if offset+2 > len(msg) {
		return
	}
	csLen := int(msg[offset])<<8 | int(msg[offset+1])
	offset += 2
	offset += csLen
	if offset >= len(msg) {
		return
	}
	compLen := int(msg[offset])
	offset++
	offset += compLen
	if offset+2 > len(msg) {
		return
	}
	extTotalLen := int(msg[offset])<<8 | int(msg[offset+1])
	offset += 2
	extEnd := offset + extTotalLen
	if extEnd > len(msg) {
		extEnd = len(msg)
	}
	tlsVer, sniExt := parseClientHelloExtensions(msg, offset, extEnd)
	if tlsVer != "" {
		// This is the client's best OFFER, not the negotiated version. Record
		// it as its own metadata; s.state.version is set from the ServerHello.
		s.state.clientMaxOfferedVersion = tlsVer
	}
	if sniExt != "" && s.state.sniServerName == "" {
		s.state.sniServerName = sniExt
	}
}

// parseServerHello extracts selected cipher and version from ServerHello
func (s *TLSStream) parseServerHello(msg []byte) {
	// version(2) + random(32) + sid_len(1) + sid(var) + cipher(2) + comp(1)
	if len(msg) < 38 {
		return
	}

	// legacy_version (msg[0:2]) IS the negotiated version for TLS <= 1.2 and
	// for SSL 3.0. TLS 1.3 pins it to 0x0303 and carries the real version in
	// the supported_versions extension, which overrides below. Without this
	// fallback, a TLS 1.2-only server yields no version at all (or, worse,
	// inherits whatever the client offered).
	if name := tlsVersionName(binary.BigEndian.Uint16(msg[0:2])); name != "" {
		s.state.version = name
	}

	offset := 34 // skip version(2) + random(32)
	sidLen := int(msg[offset])
	offset++
	offset += sidLen

	if offset+2 > len(msg) {
		return
	}
	suite := binary.BigEndian.Uint16(msg[offset : offset+2])
	offset += 2
	if name := tlsCipherName(suite); name != "" {
		s.state.cipherSuite = name
	}

	// Skip compression
	offset++

	if offset+2 > len(msg) {
		return
	}
	extTotalLen := int(binary.BigEndian.Uint16(msg[offset : offset+2]))
	offset += 2
	extEnd := offset + extTotalLen
	if extEnd > len(msg) {
		extEnd = len(msg)
	}
	version, selectedALPN := parseServerHelloExtensions(msg, offset, extEnd)
	if version != "" {
		s.state.version = version
	}
	if selectedALPN != "" {
		s.state.selectedALPN = selectedALPN
	}
}

// parseCertificate extracts certificate details from Certificate message
func (s *TLSStream) parseCertificate(msg []byte) {
	// cert_list_length(3) + [cert_len(3) + cert_data(var)]...
	if len(msg) < 3 {
		return
	}
	certListLen := int(msg[0])<<16 | int(msg[1])<<8 | int(msg[2])
	if certListLen <= 0 || 3+certListLen > len(msg) {
		return
	}
	listEnd := 3 + certListLen

	offset := 3
	var chain []*x509.Certificate
	for offset+3 <= listEnd && offset+3 <= len(msg) {
		certLen := int(msg[offset])<<16 | int(msg[offset+1])<<8 | int(msg[offset+2])
		offset += 3
		if certLen <= 0 || offset+certLen > listEnd || offset+certLen > len(msg) {
			break
		}
		der := msg[offset : offset+certLen]
		offset += certLen
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return
	}

	certs := discovery.ExtractCertificatesFromX509(chain)

	// If we saw a CertificateRequest and already have server certs,
	// this Certificate message is from the client (mTLS).
	if s.state.sawCertRequest && len(s.state.certificates) > 0 {
		s.state.clientCertificates = certs
		if s.state.cipherSuite != "" || s.state.version != "" {
			s.factory.mu.Lock()
			if s.state.complete {
				s.factory.emitDiscovery(s.state, true)
			} else {
				s.state.complete = true
				s.factory.emitDiscovery(s.state, false)
				delete(s.factory.sessions, s.key)
			}
			s.factory.mu.Unlock()
		}
		return
	}

	s.state.certificates = certs
	// Local validation only — no OCSP HTTP on the passive capture hot path.
	validation := discovery.ValidateAndClassifyCertChainPassive(chain, s.state.sniServerName)
	s.state.certValStatus = validation.ValidationStatus
	s.state.certValError = validation.ValidationError
	// Keep the quality flags (SCT, known-bad CA, EV, weak signature/key,
	// incomplete chain). Passive capture is the only source of cert data when
	// active probing is disabled, so discarding them here left those
	// discoveries with no flags at all.
	s.state.certQualityFlags = validation.QualityFlags

	if s.state.cipherSuite != "" || s.state.version != "" {
		s.factory.mu.Lock()
		if !s.state.complete {
			s.state.complete = true
			s.factory.emitDiscovery(s.state, false)
			delete(s.factory.sessions, s.key)
		}
		s.factory.mu.Unlock()
	}
}

// parseClientHelloExtensions scans ClientHello extension blocks for negotiated TLS version
// (supported_versions, 0x002b) and server name indication (0x0000).
func parseClientHelloExtensions(msg []byte, extStart, extEnd int) (tlsVersion string, sni string) {
	offset := extStart
	for offset+4 <= extEnd && offset+4 <= len(msg) {
		extType := binary.BigEndian.Uint16(msg[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(msg[offset+2 : offset+4]))
		offset += 4
		if offset+extLen > extEnd || offset+extLen > len(msg) {
			break
		}
		extBody := msg[offset : offset+extLen]
		switch extType {
		case 0x002b:
			if v := parseSupportedVersionsExtensionBody(extBody); v != "" {
				tlsVersion = v
			}
		case 0x0000:
			if h := parseServerNameExtensionBody(extBody); h != "" {
				sni = h
			}
		}
		offset += extLen
	}
	return tlsVersion, sni
}

// parseSupportedVersionsExtensionBody parses the body of the supported_versions extension.
func parseSupportedVersionsExtensionBody(body []byte) string {
	if len(body) < 2 {
		return ""
	}
	if len(body) == 2 {
		return tlsVersionName(binary.BigEndian.Uint16(body))
	}
	listLen := int(body[0])
	if listLen > 0 && listLen%2 == 0 && 1+listLen <= len(body) {
		var best uint16
		for i := 1; i+1 < 1+listLen; i += 2 {
			ver := binary.BigEndian.Uint16(body[i : i+2])
			if tlsVersionName(ver) != "" && ver > best {
				best = ver
			}
		}
		if best != 0 {
			return tlsVersionName(best)
		}
	}
	return ""
}

// parseServerNameExtensionBody returns the first host_name entry from RFC 6066 server_name.
func parseServerNameExtensionBody(body []byte) string {
	if len(body) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(body[0:2]))
	if listLen < 3 || 2+listLen > len(body) {
		return ""
	}
	end := 2 + listLen
	p := 2
	for p+3 <= end {
		nameType := body[p]
		nameLen := int(binary.BigEndian.Uint16(body[p+1 : p+3]))
		p += 3
		if nameLen <= 0 || p+nameLen > end {
			break
		}
		if nameType == 0 {
			return string(body[p : p+nameLen])
		}
		p += nameLen
	}
	return ""
}

// parseServerHelloExtensions scans ServerHello extensions for supported_versions and ALPN.
// Note: In TLS 1.3, the selected ALPN is in EncryptedExtensions (encrypted),
// so selectedALPN will only be populated for TLS <= 1.2 ServerHello.
func parseServerHelloExtensions(msg []byte, start, end int) (tlsVersion string, selectedALPN string) {
	offset := start
	for offset+4 <= end && offset+4 <= len(msg) {
		extType := binary.BigEndian.Uint16(msg[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(msg[offset+2 : offset+4]))
		offset += 4
		if offset+extLen > end || offset+extLen > len(msg) {
			break
		}
		extBody := msg[offset : offset+extLen]
		switch extType {
		case 0x002b: // supported_versions
			if extLen == 2 {
				ver := binary.BigEndian.Uint16(extBody)
				if name := tlsVersionName(ver); name != "" {
					tlsVersion = name
				}
			}
		case 0x0010: // ALPN
			protocols := parseALPNExtensionBody(extBody)
			if len(protocols) > 0 {
				selectedALPN = protocols[0]
			}
		}
		offset += extLen
	}
	return tlsVersion, selectedALPN
}

// portFromEndpoint converts a gopacket Endpoint to an integer port
func portFromEndpoint(ep gopacket.Endpoint) int {
	b := ep.Raw()
	if len(b) == 2 {
		return int(binary.BigEndian.Uint16(b))
	}
	return 0
}

// Compile-time interface checks
var _ tcpassembly.Stream = (*TLSStream)(nil)
var _ tcpassembly.StreamFactory = (*TLSStreamFactory)(nil)
