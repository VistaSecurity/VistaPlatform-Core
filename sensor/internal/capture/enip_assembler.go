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

// EtherNet/IP CIP passive detector for TCP port 44818.
//
// EtherNet/IP is the Allen-Bradley / Rockwell-ecosystem industrial
// protocol — manufacturing, water/wastewater, automotive. Explicit
// messaging (long-lived engineering / configuration sessions) rides
// TCP 44818 wrapped in a small encapsulation header; implicit cyclic
// I/O messaging runs over UDP 2222 (out of scope here — different
// sensor placement story).
//
// The active prober (ot_probers.go::probeEtherNetIP) already covers
// the List-Identity discovery flow on UDP 44818. This is the symmetric
// passive counterpart so tenants who don't run active probes still see
// their existing EtherNet/IP traffic in the inventory.
//
// Encapsulation header (24 bytes, all integers little-endian):
//
//	Command(2)  Length(2)  SessionHandle(4)  Status(4)
//	SenderContext(8)  Options(4)
//
// Recognized commands:
//
//	0x0063 ListIdentity
//	0x0064 ListServices
//	0x0065 RegisterSession   — first message in any session
//	0x0066 UnRegisterSession
//	0x006F SendRRData        — CIP request/response (one-shot)
//	0x0070 SendUnitData      — CIP messaging on a registered session
//
// Classic CIP is plaintext — we emit `security: "none"`. CIP Security
// (Volume 8 of the CIP spec) wraps the same encapsulation in TLS/DTLS
// and is handled separately.
//
// Reference: ODVA "EtherNet/IP CIP" specification, encapsulation
// protocol §2.

const (
	enipPort           = 44818
	enipHeaderLen      = 24
	enipMaxPayloadSize = 65511 // 65535 - header
)

// EtherNet/IP encapsulation commands we recognize. A valid initial frame
// from either client or server must use one of these. Foreign command
// codes mean this isn't an EtherNet/IP stream and we drop the buffer.
const (
	enipCmdNOP               = 0x0000
	enipCmdListServices      = 0x0004
	enipCmdListIdentityCmd   = 0x0063
	enipCmdListInterfaces    = 0x0064
	enipCmdRegisterSession   = 0x0065
	enipCmdUnRegisterSession = 0x0066
	enipCmdSendRRData        = 0x006F
	enipCmdSendUnitData      = 0x0070
)

// enipCommandName returns a human-readable label for a recognized
// command code, or "" when the code is not one we expect on a valid
// EtherNet/IP stream.
func enipCommandName(cmd uint16) string {
	switch cmd {
	case enipCmdNOP:
		return "NOP"
	case enipCmdListServices:
		return "ListServices"
	case enipCmdListIdentityCmd:
		return "ListIdentity"
	case enipCmdListInterfaces:
		return "ListInterfaces"
	case enipCmdRegisterSession:
		return "RegisterSession"
	case enipCmdUnRegisterSession:
		return "UnRegisterSession"
	case enipCmdSendRRData:
		return "SendRRData"
	case enipCmdSendUnitData:
		return "SendUnitData"
	}
	return ""
}

// enipSessionState tracks one TCP flow's accumulated bytes plus the
// session-handle / command observed in the first valid frame, which
// becomes finding metadata.
type enipSessionState struct {
	sessionID  string
	serverIP   string
	serverPort int
	clientIP   string
	iface      string
	buffer     []byte
	emitted    bool
	lastSeen   time.Time
}

// ENIPStreamFactory creates one ENIPStream per TCP flow on port 44818.
// Reuses tlsFlowKey for the (net, transport) flow tuple — no semantic
// dependency on TLS.
type ENIPStreamFactory struct {
	mu           sync.Mutex
	sessions     map[tlsFlowKey]*enipSessionState
	ifacePending sync.Map
	discoveries  chan<- *models.CryptoDiscovery
	sensorID     string
	cache        *cache.ConnectionCache
}

// NewENIPStreamFactory builds the factory.
func NewENIPStreamFactory(discoveries chan<- *models.CryptoDiscovery, sensorID string, connCache *cache.ConnectionCache) *ENIPStreamFactory {
	return &ENIPStreamFactory{
		sessions:    make(map[tlsFlowKey]*enipSessionState),
		discoveries: discoveries,
		sensorID:    sensorID,
		cache:       connCache,
	}
}

// RegisterIfaceForFlow records the capture interface for the next New().
func (f *ENIPStreamFactory) RegisterIfaceForFlow(key tlsFlowKey, iface string) {
	if iface != "" {
		f.ifacePending.Store(key, iface)
	}
}

// New satisfies tcpassembly.StreamFactory.
func (f *ENIPStreamFactory) New(netFlow, transportFlow gopacket.Flow) tcpassembly.Stream {
	key := tlsFlowKey{net: netFlow, transport: transportFlow}
	dstPort := portFromEndpoint(transportFlow.Dst())
	srcPort := portFromEndpoint(transportFlow.Src())

	serverIP := netFlow.Dst().String()
	serverPort := dstPort
	clientIP := netFlow.Src().String()
	if srcPort == enipPort && dstPort != enipPort {
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
		state = &enipSessionState{
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

	return &ENIPStream{factory: f, key: key, state: state}
}

// FlushOldSessions removes stale sessions older than maxAge.
func (f *ENIPStreamFactory) FlushOldSessions(maxAge time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for key, state := range f.sessions {
		if state.lastSeen.Before(cutoff) {
			delete(f.sessions, key)
		}
	}
}

// ENIPStream consumes reassembled bytes for one TCP flow.
type ENIPStream struct {
	factory *ENIPStreamFactory
	key     tlsFlowKey
	state   *enipSessionState
}

func (s *ENIPStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	for _, r := range reassembly {
		s.state.buffer = append(s.state.buffer, r.Bytes...)
		s.state.lastSeen = time.Now()
	}
	// Cap buffer growth — one encapsulation header + a small CIP payload
	// is all we need to confirm and emit. Pathological streams can't
	// burn unbounded memory.
	if len(s.state.buffer) > 4096 {
		s.state.buffer = s.state.buffer[:4096]
	}
	s.processBuffer()
}

func (s *ENIPStream) ReassemblyComplete() {
	s.processBuffer()
	s.factory.mu.Lock()
	delete(s.factory.sessions, s.key)
	s.factory.mu.Unlock()
}

// processBuffer consumes complete encapsulation frames from the buffer.
// Stops after the first valid frame triggers an emission; subsequent
// frames in the same session refresh lastSeen but don't re-emit (dedup
// is handled by the ConnectionCache).
func (s *ENIPStream) processBuffer() {
	if s.state.emitted {
		s.state.buffer = nil
		return
	}
	buf := s.state.buffer
	if len(buf) < enipHeaderLen {
		return
	}

	cmd, payloadLen, sessionHandle, status, ok := parseENIPHeader(buf)
	if !ok {
		// Not an EtherNet/IP encapsulation header — drop the whole buffer.
		// Avoids burning CPU on non-EtherNet/IP traffic that happened to
		// land on port 44818 (rare but possible with bad firewall rules).
		s.state.buffer = nil
		return
	}
	totalLen := enipHeaderLen + payloadLen
	if len(buf) < totalLen {
		return // wait for more bytes
	}
	s.emitDiscovery(cmd, sessionHandle, status)
	s.state.buffer = buf[totalLen:]
}

// parseENIPHeader validates and parses the 24-byte EtherNet/IP
// encapsulation header. Returns (cmd, payloadLen, sessionHandle, status,
// true) on success; the boolean is false when the bytes don't look like
// an EtherNet/IP header (caller should drop the buffer).
func parseENIPHeader(buf []byte) (cmd uint16, payloadLen int, sessionHandle, status uint32, ok bool) {
	if len(buf) < enipHeaderLen {
		return 0, 0, 0, 0, false
	}
	cmd = binary.LittleEndian.Uint16(buf[0:2])
	if enipCommandName(cmd) == "" {
		return 0, 0, 0, 0, false
	}
	payloadLen = int(binary.LittleEndian.Uint16(buf[2:4]))
	if payloadLen > enipMaxPayloadSize {
		return 0, 0, 0, 0, false
	}
	sessionHandle = binary.LittleEndian.Uint32(buf[4:8])
	status = binary.LittleEndian.Uint32(buf[8:12])
	return cmd, payloadLen, sessionHandle, status, true
}

// emitDiscovery reports the EtherNet/IP session. Dedup via
// ConnectionCache so repeated connections to the same server collapse
// to one finding per TTL window.
func (s *ENIPStream) emitDiscovery(cmd uint16, sessionHandle, status uint32) {
	if s.factory.cache != nil && s.state.serverIP != "" {
		shouldReport, _ := s.factory.cache.ShouldReport(s.state.serverIP, s.state.serverPort, "EtherNet_IP")
		if !shouldReport {
			s.state.emitted = true
			return
		}
	}

	metadata := map[string]interface{}{
		"session_id":        s.state.sessionID,
		"reassembled":       true,
		"transport":         "tcp",
		"enip_command":      int(cmd),
		"enip_command_name": enipCommandName(cmd),
		"session_handle":    int(sessionHandle),
		"enip_status":       int(status),
		// Classic CIP is plaintext — absence of crypto is itself the
		// finding for the OT lens / BP-011 evaluation. CIP Security
		// (TLS/DTLS-wrapped EtherNet/IP, ODVA Volume 8) is handled
		// separately by the TLS assembler.
		"security": "none",
	}
	if s.state.iface != "" {
		metadata["interface"] = s.state.iface
	}

	discovery := &models.CryptoDiscovery{
		ID:              uuid.New().String(),
		SensorID:        s.factory.sensorID,
		Timestamp:       time.Now(),
		SourceIP:        s.state.clientIP,
		DestIP:          s.state.serverIP,
		Port:            s.state.serverPort,
		Protocol:        "EtherNet_IP",
		Version:         "CIP",
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
		log.Printf("Warning: EtherNet/IP discovery channel full, dropping session %s", s.state.sessionID)
	}
}

// Compile-time interface checks
var _ tcpassembly.Stream = (*ENIPStream)(nil)
var _ tcpassembly.StreamFactory = (*ENIPStreamFactory)(nil)
