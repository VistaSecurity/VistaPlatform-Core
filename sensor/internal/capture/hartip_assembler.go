package capture

import (
	"encoding/binary"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/tcpassembly"
	"github.com/vistasecurity/vistaplatform/sensor/internal/cache"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// HART-IP (HCF Spec 85) passive detector for TCP and UDP port 5094.
//
// HART-IP carries HART field-instrument communications over IP. It's
// dominant in process industries — oil & gas, refineries, water
// treatment, chemical plants — for instrument diagnostics and
// configuration. The classic profile has no native crypto, putting it
// in the same audit posture as Modbus: detection of HART-IP on the
// wire IS the cryptographic finding.
//
// HART-IP message format (HCF Spec 85 §6):
//
//	Version(1)  MessageType(1)  MessageID(1)  Status(1)
//	SequenceNumber(2)  ByteCount(2)  Payload(N)
//
// Version is always 0x01. MessageType values:
//
//	0x00 Request
//	0x01 Response
//	0x02 PublishNotify
//	0x03 PublishRequest
//	0x04 NAK
//
// HART-IP Security exists in the spec but field deployment is rare;
// when we see it the underlying TLS handshake will be picked up by the
// TLS assembler with its own classification.
//
// Reference: HART Communication Foundation Specification 85 (HART-IP).

const (
	hartIPPort         = 5094
	hartIPHeaderLen    = 8 // version(1) + msgType(1) + msgID(1) + status(1) + seqNum(2) + byteCount(2)
	hartIPVersion      = 0x01
	hartIPMaxPayload   = 65535 - hartIPHeaderLen
	hartIPMaxBufferLen = 16384
)

// HART-IP message-type codes we recognize. Anything outside this set on
// byte 1 indicates the bytes are not HART-IP and we should drop the
// buffer (TCP) or skip emission (UDP).
const (
	hartIPMsgRequest        = 0x00
	hartIPMsgResponse       = 0x01
	hartIPMsgPublishNotify  = 0x02
	hartIPMsgPublishRequest = 0x03
	hartIPMsgNAK            = 0x04
)

// hartIPMessageTypeName returns a human-readable label for a recognized
// HART-IP message type, or "" when the code is not one of the valid
// HART-IP values.
func hartIPMessageTypeName(t uint8) string {
	switch t {
	case hartIPMsgRequest:
		return "Request"
	case hartIPMsgResponse:
		return "Response"
	case hartIPMsgPublishNotify:
		return "PublishNotify"
	case hartIPMsgPublishRequest:
		return "PublishRequest"
	case hartIPMsgNAK:
		return "NAK"
	}
	return ""
}

// hartIPHeader is the parsed fixed-size header.
type hartIPHeader struct {
	version     uint8
	messageType uint8
	messageID   uint8
	status      uint8
	sequenceNum uint16
	byteCount   uint16
}

// parseHARTIPHeader validates and decodes the 8-byte HART-IP header.
// Returns (header, true) on success; (zero, false) when the bytes don't
// match a valid HART-IP header (caller should drop the buffer / skip
// emission).
func parseHARTIPHeader(buf []byte) (hartIPHeader, bool) {
	if len(buf) < hartIPHeaderLen {
		return hartIPHeader{}, false
	}
	if buf[0] != hartIPVersion {
		return hartIPHeader{}, false
	}
	if hartIPMessageTypeName(buf[1]) == "" {
		return hartIPHeader{}, false
	}
	byteCount := binary.BigEndian.Uint16(buf[6:8])
	if int(byteCount) > hartIPMaxPayload {
		return hartIPHeader{}, false
	}
	return hartIPHeader{
		version:     buf[0],
		messageType: buf[1],
		messageID:   buf[2],
		status:      buf[3],
		sequenceNum: binary.BigEndian.Uint16(buf[4:6]),
		byteCount:   byteCount,
	}, true
}

// hartIPSessionState tracks one TCP flow's accumulated bytes plus first
// observed metadata. UDP datagrams don't use this; they go through
// parseHARTIPPacket directly.
type hartIPSessionState struct {
	sessionID  string
	serverIP   string
	serverPort int
	clientIP   string
	iface      string
	buffer     []byte
	emitted    bool
	lastSeen   time.Time
}

// HARTIPStreamFactory creates one HARTIPStream per TCP flow on port 5094.
type HARTIPStreamFactory struct {
	mu           sync.Mutex
	sessions     map[tlsFlowKey]*hartIPSessionState
	ifacePending sync.Map
	discoveries  chan<- *models.CryptoDiscovery
	sensorID     string
	cache        *cache.ConnectionCache
}

// NewHARTIPStreamFactory builds the factory.
func NewHARTIPStreamFactory(discoveries chan<- *models.CryptoDiscovery, sensorID string, connCache *cache.ConnectionCache) *HARTIPStreamFactory {
	return &HARTIPStreamFactory{
		sessions:    make(map[tlsFlowKey]*hartIPSessionState),
		discoveries: discoveries,
		sensorID:    sensorID,
		cache:       connCache,
	}
}

// RegisterIfaceForFlow records the capture interface for the next New().
func (f *HARTIPStreamFactory) RegisterIfaceForFlow(key tlsFlowKey, iface string) {
	if iface != "" {
		f.ifacePending.Store(key, iface)
	}
}

// New satisfies tcpassembly.StreamFactory.
func (f *HARTIPStreamFactory) New(netFlow, transportFlow gopacket.Flow) tcpassembly.Stream {
	key := tlsFlowKey{net: netFlow, transport: transportFlow}
	dstPort := portFromEndpoint(transportFlow.Dst())
	srcPort := portFromEndpoint(transportFlow.Src())

	serverIP := netFlow.Dst().String()
	serverPort := dstPort
	clientIP := netFlow.Src().String()
	if srcPort == hartIPPort && dstPort != hartIPPort {
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
		state = &hartIPSessionState{
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

	return &HARTIPStream{factory: f, key: key, state: state}
}

// FlushOldSessions removes stale sessions older than maxAge.
func (f *HARTIPStreamFactory) FlushOldSessions(maxAge time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for key, state := range f.sessions {
		if state.lastSeen.Before(cutoff) {
			delete(f.sessions, key)
		}
	}
}

// HARTIPStream consumes reassembled bytes for one TCP flow.
type HARTIPStream struct {
	factory *HARTIPStreamFactory
	key     tlsFlowKey
	state   *hartIPSessionState
}

func (s *HARTIPStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	for _, r := range reassembly {
		s.state.buffer = append(s.state.buffer, r.Bytes...)
		s.state.lastSeen = time.Now()
	}
	if len(s.state.buffer) > hartIPMaxBufferLen {
		s.state.buffer = s.state.buffer[:hartIPMaxBufferLen]
	}
	s.processBuffer()
}

func (s *HARTIPStream) ReassemblyComplete() {
	s.processBuffer()
	s.factory.mu.Lock()
	delete(s.factory.sessions, s.key)
	s.factory.mu.Unlock()
}

// processBuffer consumes complete HART-IP messages from the buffer.
// Stops after the first valid message triggers an emission; subsequent
// messages in the session refresh lastSeen but don't re-emit (dedup is
// handled by ConnectionCache).
func (s *HARTIPStream) processBuffer() {
	if s.state.emitted {
		s.state.buffer = nil
		return
	}
	buf := s.state.buffer
	if len(buf) < hartIPHeaderLen {
		return
	}
	hdr, ok := parseHARTIPHeader(buf)
	if !ok {
		// Not a HART-IP message — drop the buffer to avoid burning CPU
		// on non-HART-IP traffic that lands on port 5094 (rare but
		// possible with bad firewall rules).
		s.state.buffer = nil
		return
	}
	totalLen := hartIPHeaderLen + int(hdr.byteCount)
	if len(buf) < totalLen {
		return // wait for more bytes
	}
	s.emitDiscovery(hdr, "tcp")
	s.state.buffer = buf[totalLen:]
}

// emitDiscovery reports the HART-IP session. Dedup via ConnectionCache
// so repeated connections to the same server collapse to one finding
// per TTL window.
func (s *HARTIPStream) emitDiscovery(hdr hartIPHeader, transport string) {
	if s.factory.cache != nil && s.state.serverIP != "" {
		shouldReport, _ := s.factory.cache.ShouldReport(s.state.serverIP, s.state.serverPort, "HART-IP-"+transport)
		if !shouldReport {
			s.state.emitted = true
			return
		}
	}
	metadata := buildHARTIPMetadata(s.state.sessionID, hdr, transport, s.state.iface, true)
	discovery := &models.CryptoDiscovery{
		ID:              uuid.New().String(),
		SensorID:        s.factory.sensorID,
		Timestamp:       time.Now(),
		SourceIP:        s.state.clientIP,
		DestIP:          s.state.serverIP,
		Port:            s.state.serverPort,
		Protocol:        "HART_IP",
		Version:         "HART-IP",
		CipherSuite:     "",
		DiscoveryMethod: "passive",
		Confidence:      0.95,
		RawMetadata:     metadata,
		SessionID:       s.state.sessionID,
		CreatedAt:       time.Now(),
	}
	s.state.emitted = true
	select {
	case s.factory.discoveries <- discovery:
	default:
		log.Printf("Warning: HART-IP discovery channel full, dropping session %s", s.state.sessionID)
	}
}

// buildHARTIPMetadata builds the canonical RawMetadata map for both TCP
// and UDP emission paths. `reassembled` is true for TCP, false for UDP.
func buildHARTIPMetadata(sessionID string, hdr hartIPHeader, transport, iface string, reassembled bool) map[string]interface{} {
	metadata := map[string]interface{}{
		"session_id":               sessionID,
		"reassembled":              reassembled,
		"transport":                transport,
		"hartip_message_type":      int(hdr.messageType),
		"hartip_message_type_name": hartIPMessageTypeName(hdr.messageType),
		"hartip_message_id":        int(hdr.messageID),
		"hartip_sequence_number":   int(hdr.sequenceNum),
		"hartip_byte_count":        int(hdr.byteCount),
		// Classic HART-IP is plaintext — absence of crypto is itself the
		// finding for the OT lens / BP-011 evaluation. HART-IP Security
		// exists in the spec but field deployment is rare; when present
		// the underlying TLS is picked up by the TLS assembler.
		"security": "none",
	}
	if iface != "" {
		metadata["interface"] = iface
	}
	return metadata
}

// parseHARTIPPacket inspects a single UDP datagram for HART-IP and
// returns a CryptoDiscovery describing it, or nil when the bytes don't
// match the HART-IP header shape. Mirrors the TCP assembler's emission
// fields so downstream consumers don't need to special-case UDP HART-IP.
//
// The connCache is consulted for dedup using a `HART-IP-udp` key so a
// chatty PublishNotify multicast doesn't flood the discovery channel;
// pass nil to disable dedup (tests).
func parseHARTIPPacket(payload []byte, srcIP, dstIP string, srcPort, dstPort int, sensorID, iface string, connCache *cache.ConnectionCache) *models.CryptoDiscovery {
	hdr, ok := parseHARTIPHeader(payload)
	if !ok {
		return nil
	}

	serverIP := dstIP
	serverPort := dstPort
	clientIP := srcIP
	if srcPort == hartIPPort && dstPort != hartIPPort {
		serverIP = srcIP
		serverPort = srcPort
		clientIP = dstIP
	}

	if connCache != nil && serverIP != "" {
		shouldReport, _ := connCache.ShouldReport(serverIP, serverPort, "HART-IP-udp")
		if !shouldReport {
			return nil
		}
	}

	sessionID := uuid.New().String()
	metadata := buildHARTIPMetadata(sessionID, hdr, "udp", iface, false)
	return &models.CryptoDiscovery{
		ID:              uuid.New().String(),
		SensorID:        sensorID,
		Timestamp:       time.Now(),
		SourceIP:        clientIP,
		DestIP:          serverIP,
		Port:            serverPort,
		Protocol:        "HART_IP",
		Version:         "HART-IP",
		CipherSuite:     "",
		DiscoveryMethod: "passive",
		Confidence:      0.9,
		RawMetadata:     metadata,
		SessionID:       sessionID,
		CreatedAt:       time.Now(),
	}
}

// Compile-time interface checks
var _ tcpassembly.Stream = (*HARTIPStream)(nil)
var _ tcpassembly.StreamFactory = (*HARTIPStreamFactory)(nil)
