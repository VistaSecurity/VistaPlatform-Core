package capture

import (
	"encoding/binary"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/tcpassembly"
	"github.com/vistasecurity/vistaplatform/sensor/internal/cache"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

const (
	// maxSTARTTLSPlaintextBuffer is the maximum number of bytes buffered
	// before a STARTTLS upgrade is detected. If exceeded, the stream is discarded.
	maxSTARTTLSPlaintextBuffer = 4096

	// maxConcurrentSTARTTLSStreams limits memory consumption on high-volume
	// STARTTLS ports (e.g., SMTP relays). Once reached, new streams are ignored.
	maxConcurrentSTARTTLSStreams = 1000
)

// STARTTLSStreamFactory creates STARTTLSStream instances for TCP flows on plaintext ports
// that may upgrade to TLS via STARTTLS.
type STARTTLSStreamFactory struct {
	mu          sync.Mutex
	sessions    map[tlsFlowKey]*tlsSessionState
	discoveries chan<- *models.CryptoDiscovery
	sensorID    string
	cache       *cache.ConnectionCache
	ports       []int // configured STARTTLS ports
	activeCount int64 // atomic: current number of active streams
}

// NewSTARTTLSStreamFactory creates a new factory for STARTTLS detection.
func NewSTARTTLSStreamFactory(discoveries chan<- *models.CryptoDiscovery, sensorID string, connCache *cache.ConnectionCache, ports []int) *STARTTLSStreamFactory {
	return &STARTTLSStreamFactory{
		sessions:    make(map[tlsFlowKey]*tlsSessionState),
		discoveries: discoveries,
		sensorID:    sensorID,
		cache:       connCache,
		ports:       ports,
	}
}

// New creates a new STARTTLSStream for a TCP flow.
func (f *STARTTLSStreamFactory) New(netFlow, transportFlow gopacket.Flow) tcpassembly.Stream {
	// Enforce concurrent stream limit
	if atomic.LoadInt64(&f.activeCount) >= maxConcurrentSTARTTLSStreams {
		return &discardStream{}
	}
	atomic.AddInt64(&f.activeCount, 1)

	key := tlsFlowKey{net: netFlow, transport: transportFlow}

	// Determine server side by port
	dstPort := portFromEndpoint(transportFlow.Dst())
	srcPort := portFromEndpoint(transportFlow.Src())

	serverIP := netFlow.Dst().String()
	serverPort := dstPort
	clientIP := netFlow.Src().String()

	// Check if the STARTTLS port is on the source side
	if !portInList(dstPort, f.ports) && portInList(srcPort, f.ports) {
		serverIP = netFlow.Src().String()
		serverPort = srcPort
		clientIP = netFlow.Dst().String()
	}

	proto := protocolForPort(serverPort)
	protoName := "unknown"
	if proto != nil {
		protoName = proto.Name
	}

	f.mu.Lock()
	state := &tlsSessionState{
		sessionID:        uuid.New().String(),
		serverIP:         serverIP,
		serverPort:       serverPort,
		clientIP:         clientIP,
		protocol:         "TLS",
		handshakeTypes:   make(map[uint8]bool),
		lastSeen:         time.Now(),
		starttlsDetected: false,
		starttlsProtocol: protoName,
		starttlsPort:     serverPort,
	}
	f.sessions[key] = state
	f.mu.Unlock()

	return &STARTTLSStream{
		factory:  f,
		key:      key,
		state:    state,
		proto:    proto,
		upgraded: false,
	}
}

// FlushOldSessions removes stale STARTTLS sessions.
func (f *STARTTLSStreamFactory) FlushOldSessions(maxAge time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for key, state := range f.sessions {
		if state.lastSeen.Before(cutoff) && !state.complete {
			delete(f.sessions, key)
		}
	}
}

// emitDiscovery creates and sends a discovery for a STARTTLS session.
// Must be called with f.mu held.
func (f *STARTTLSStreamFactory) emitDiscovery(state *tlsSessionState) {
	if f.cache != nil && state.serverIP != "" {
		shouldReport, _ := f.cache.ShouldReport(state.serverIP, state.serverPort, "TLS")
		if !shouldReport {
			return
		}
	}

	metadata := map[string]interface{}{
		"session_id":        state.sessionID,
		"reassembled":       true,
		"starttls_detected": true,
		"starttls_protocol": state.starttlsProtocol,
		"starttls_port":     state.starttlsPort,
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
	if state.clientMaxOfferedVersion != "" {
		metadata["client_max_offered_version"] = state.clientMaxOfferedVersion
	}
	if state.sniServerName != "" {
		metadata["sni_server_name"] = state.sniServerName
	}
	if len(state.supportedCiphers) > 0 {
		metadata["supported_ciphers"] = state.supportedCiphers
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
	if state.iface != "" {
		metadata["interface"] = state.iface
	}

	confidence := 0.85
	if len(state.certificates) > 0 {
		confidence = 0.95
	} else if state.cipherSuite != "" {
		confidence = 0.9
	}

	disc := &models.CryptoDiscovery{
		ID:              uuid.New().String(),
		SensorID:        f.sensorID,
		Timestamp:       time.Now(),
		SourceIP:        state.clientIP,
		DestIP:          state.serverIP,
		Port:            state.serverPort,
		Protocol:        "TLS",
		Version:         state.version,
		CipherSuite:     state.cipherSuite,
		DiscoveryMethod: "passive",
		Confidence:      confidence,
		RawMetadata:     metadata,
		SessionID:       state.sessionID,
		CreatedAt:       time.Now(),
	}

	select {
	case f.discoveries <- disc:
	default:
		log.Printf("Warning: STARTTLS discovery channel full, dropping session %s", state.sessionID)
	}
}

// STARTTLSStream handles a single TCP flow on a STARTTLS port.
// It buffers plaintext data looking for a STARTTLS upgrade, then switches
// to TLS handshake parsing.
type STARTTLSStream struct {
	factory  *STARTTLSStreamFactory
	key      tlsFlowKey
	state    *tlsSessionState
	proto    *starttlsProtocol
	upgraded bool
	buf      []byte // plaintext buffer before upgrade
}

// Reassembled is called by tcpassembly with reassembled bytes.
func (s *STARTTLSStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	for _, r := range reassembly {
		s.state.lastSeen = time.Now()

		if s.upgraded {
			// Already detected STARTTLS — process as TLS
			s.state.buffer = append(s.state.buffer, r.Bytes...)
			s.processTLSBuffer()
			continue
		}

		// Buffer plaintext data
		s.buf = append(s.buf, r.Bytes...)

		// Check buffer limit
		if len(s.buf) > maxSTARTTLSPlaintextBuffer {
			// Too much plaintext without upgrade — discard
			s.buf = nil
			return
		}

		// Try to detect STARTTLS upgrade
		if s.proto != nil {
			detected, tlsOffset := s.proto.Detect(s.buf)
			if detected {
				s.upgraded = true
				s.state.starttlsDetected = true
				log.Printf("STARTTLS upgrade detected: %s on port %d (%s:%d)",
					s.proto.Name, s.state.starttlsPort, s.state.serverIP, s.state.serverPort)

				// Move remaining data after TLS offset to the TLS buffer
				if tlsOffset < len(s.buf) {
					s.state.buffer = append(s.state.buffer, s.buf[tlsOffset:]...)
					s.processTLSBuffer()
				}
				s.buf = nil
			}
		}
	}
}

// ReassemblyComplete is called when the TCP stream ends.
func (s *STARTTLSStream) ReassemblyComplete() {
	atomic.AddInt64(&s.factory.activeCount, -1)

	if s.upgraded {
		s.processTLSBuffer()
	}

	s.factory.mu.Lock()
	defer s.factory.mu.Unlock()

	state := s.state
	if s.upgraded && !state.complete && len(state.handshakeTypes) > 0 {
		state.complete = true
		s.factory.emitDiscovery(state)
	}
	delete(s.factory.sessions, s.key)
}

// processTLSBuffer processes TLS handshake records from the state buffer.
// Reuses the same TLS record parsing logic as the main TLS assembler.
func (s *STARTTLSStream) processTLSBuffer() {
	buf := s.state.buffer
	for len(buf) >= 5 {
		if buf[0] != 0x16 {
			buf = buf[1:]
			continue
		}
		recordLen := int(binary.BigEndian.Uint16(buf[3:5]))
		if len(buf) < 5+recordLen {
			break
		}
		record := buf[5 : 5+recordLen]
		s.processHandshakeRecord(record)
		buf = buf[5+recordLen:]
	}
	s.state.buffer = buf
}

// processHandshakeRecord processes a TLS handshake record (same logic as TLSStream).
func (s *STARTTLSStream) processHandshakeRecord(record []byte) {
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
	}
}

// parseClientHello extracts JA3/JA4, ALPN, SNI from a ClientHello in a STARTTLS session.
func (s *STARTTLSStream) parseClientHello(msg []byte) {
	ja3Input, alpnProtocols, sni := ParseClientHelloJA3Fields(msg)

	if sni != "" {
		s.state.sniServerName = sni
	}
	if len(alpnProtocols) > 0 {
		s.state.alpnProtocols = alpnProtocols
	}

	var ciphers []string
	for _, suite := range ja3Input.CipherSuites {
		if name := tlsCipherName(suite); name != "" {
			ciphers = append(ciphers, name)
		}
	}
	if len(ciphers) > 0 {
		s.state.supportedCiphers = ciphers
	}

	ja3Hash, _ := ComputeJA3(ja3Input)
	s.state.ja3Hash = ja3Hash
	s.state.ja4Fingerprint = ComputeJA4(ja3Input, alpnProtocols, sni != "")

	// Extract TLS version from supported_versions extension
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
		// Client's best OFFER — not the negotiated version. See tls_assembler.go.
		s.state.clientMaxOfferedVersion = tlsVer
	}
	if sniExt != "" && s.state.sniServerName == "" {
		s.state.sniServerName = sniExt
	}
}

// parseServerHello extracts cipher suite and version from ServerHello.
func (s *STARTTLSStream) parseServerHello(msg []byte) {
	if len(msg) < 38 {
		return
	}
	// legacy_version is the negotiated version for TLS <= 1.2; TLS 1.3 overrides
	// it via supported_versions below. See tls_assembler.go parseServerHello.
	if name := tlsVersionName(binary.BigEndian.Uint16(msg[0:2])); name != "" {
		s.state.version = name
	}
	offset := 34
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
	offset++ // skip compression
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

// discardStream is a no-op stream used when the concurrent stream limit is reached.
type discardStream struct{}

func (d *discardStream) Reassembled([]tcpassembly.Reassembly) {}
func (d *discardStream) ReassemblyComplete()                  {}

// Compile-time interface checks
var _ tcpassembly.Stream = (*STARTTLSStream)(nil)
var _ tcpassembly.StreamFactory = (*STARTTLSStreamFactory)(nil)
var _ tcpassembly.Stream = (*discardStream)(nil)
