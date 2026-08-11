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

// SSH message types
const (
	sshMsgKexInit = 20
)

// sshFlowKey identifies a TCP flow
type sshFlowKey struct {
	net, transport gopacket.Flow
}

// sshKexInitData holds parsed SSH_MSG_KEXINIT fields
type sshKexInitData struct {
	kexAlgorithms            []string
	serverHostKeyAlgorithms  []string
	encryptionAlgorithmsC2S  []string
	encryptionAlgorithmsS2C  []string
	macAlgorithmsC2S         []string
	macAlgorithmsS2C         []string
	compressionAlgorithmsC2S []string
	compressionAlgorithmsS2C []string
}

// sshSessionState tracks the state of an SSH handshake
type sshSessionState struct {
	sessionID  string
	serverIP   string
	serverPort int
	clientIP   string
	iface      string
	buffer     []byte
	banner     string
	clientKex  *sshKexInitData
	serverKex  *sshKexInitData
	lastSeen   time.Time
	complete   bool
}

// SSHStreamFactory creates SSHStream instances for each new TCP flow
type SSHStreamFactory struct {
	mu          sync.Mutex
	sessions    map[sshFlowKey]*sshSessionState
	discoveries chan<- *models.CryptoDiscovery
	sensorID    string
	cache       *cache.ConnectionCache // shared dedup cache
}

// NewSSHStreamFactory creates a new SSHStreamFactory
func NewSSHStreamFactory(discoveries chan<- *models.CryptoDiscovery, sensorID string, connCache *cache.ConnectionCache) *SSHStreamFactory {
	return &SSHStreamFactory{
		sessions:    make(map[sshFlowKey]*sshSessionState),
		discoveries: discoveries,
		sensorID:    sensorID,
		cache:       connCache,
	}
}

// New creates a new SSHStream for a TCP flow
func (f *SSHStreamFactory) New(netFlow, transportFlow gopacket.Flow) tcpassembly.Stream {
	key := sshFlowKey{net: netFlow, transport: transportFlow}
	f.mu.Lock()
	state := &sshSessionState{
		sessionID:  uuid.New().String(),
		serverIP:   netFlow.Dst().String(),
		serverPort: portFromEndpoint(transportFlow.Dst()),
		clientIP:   netFlow.Src().String(),
		lastSeen:   time.Now(),
	}
	f.sessions[key] = state
	f.mu.Unlock()
	return &SSHStream{
		factory: f,
		key:     key,
		state:   state,
	}
}

// FlushOldSessions flushes incomplete sessions older than maxAge
func (f *SSHStreamFactory) FlushOldSessions(maxAge time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for key, state := range f.sessions {
		if state.lastSeen.Before(cutoff) && !state.complete {
			if state.clientKex != nil || state.serverKex != nil || state.banner != "" {
				f.emitDiscovery(state)
			}
			delete(f.sessions, key)
		}
	}
}

// emitDiscovery creates and sends a CryptoDiscovery for an SSH session.
// Must be called with f.mu held.
func (f *SSHStreamFactory) emitDiscovery(state *sshSessionState) {
	// Dedup check: skip if the same server endpoint was recently reported.
	if f.cache != nil && state.serverIP != "" {
		shouldReport, _ := f.cache.ShouldReport(state.serverIP, state.serverPort, "SSH")
		if !shouldReport {
			return
		}
	}
	metadata := map[string]interface{}{
		"session_id":  state.sessionID,
		"reassembled": true,
	}
	if state.banner != "" {
		metadata["ssh_banner"] = state.banner
	}
	if state.clientKex != nil {
		if len(state.clientKex.kexAlgorithms) > 0 {
			metadata["ssh_kex_algorithms_client"] = state.clientKex.kexAlgorithms
		}
		if len(state.clientKex.encryptionAlgorithmsC2S) > 0 {
			metadata["ssh_encryption_algs_c2s_client"] = state.clientKex.encryptionAlgorithmsC2S
		}
		if len(state.clientKex.macAlgorithmsC2S) > 0 {
			metadata["ssh_mac_algs_c2s_client"] = state.clientKex.macAlgorithmsC2S
		}
	}
	if state.serverKex != nil {
		if len(state.serverKex.kexAlgorithms) > 0 {
			metadata["ssh_kex_algorithms_server"] = state.serverKex.kexAlgorithms
		}
		if len(state.serverKex.encryptionAlgorithmsC2S) > 0 {
			metadata["ssh_encryption_algs_c2s_server"] = state.serverKex.encryptionAlgorithmsC2S
		}
		if len(state.serverKex.encryptionAlgorithmsS2C) > 0 {
			metadata["ssh_encryption_algs_s2c_server"] = state.serverKex.encryptionAlgorithmsS2C
		}
		if len(state.serverKex.macAlgorithmsC2S) > 0 {
			metadata["ssh_mac_algs_c2s_server"] = state.serverKex.macAlgorithmsC2S
		}
		if len(state.serverKex.compressionAlgorithmsC2S) > 0 {
			metadata["ssh_compression_algs"] = state.serverKex.compressionAlgorithmsC2S
		}
	}
	if state.iface != "" {
		metadata["interface"] = state.iface
	}

	confidence := 0.75
	if state.serverKex != nil {
		confidence = 0.90
	}

	discovery := &models.CryptoDiscovery{
		ID:              uuid.New().String(),
		SensorID:        f.sensorID,
		Timestamp:       time.Now(),
		SourceIP:        state.clientIP,
		DestIP:          state.serverIP,
		Port:            state.serverPort,
		Protocol:        "SSH",
		DiscoveryMethod: "passive",
		Confidence:      confidence,
		RawMetadata:     metadata,
		SessionID:       state.sessionID,
		CreatedAt:       time.Now(),
	}

	select {
	case f.discoveries <- discovery:
	default:
		log.Printf("Warning: SSH assembler discovery channel full, dropping session %s", state.sessionID)
	}
}

// SSHStream receives reassembled bytes for a single SSH TCP flow
type SSHStream struct {
	factory *SSHStreamFactory
	key     sshFlowKey
	state   *sshSessionState
}

// Reassembled receives reassembled byte slices
func (s *SSHStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	for _, r := range reassembly {
		s.state.buffer = append(s.state.buffer, r.Bytes...)
		s.state.lastSeen = time.Now()
	}
	s.processSSHBuffer()
}

// ReassemblyComplete is called when the TCP stream closes
func (s *SSHStream) ReassemblyComplete() {
	s.processSSHBuffer()
	s.factory.mu.Lock()
	defer s.factory.mu.Unlock()
	state := s.state
	if !state.complete && (state.clientKex != nil || state.serverKex != nil || state.banner != "") {
		state.complete = true
		s.factory.emitDiscovery(state)
	}
	delete(s.factory.sessions, s.key)
}

// processSSHBuffer parses the accumulated SSH stream bytes
func (s *SSHStream) processSSHBuffer() {
	buf := s.state.buffer
	offset := 0

	// Check for SSH banner at the start (ASCII "SSH-")
	if offset < len(buf) && len(buf) >= 4 && string(buf[offset:offset+4]) == "SSH-" {
		// Find end of banner line
		end := offset
		for end < len(buf) && buf[end] != '\n' {
			end++
		}
		if end < len(buf) {
			banner := string(buf[offset:end])
			// Trim carriage return
			if len(banner) > 0 && banner[len(banner)-1] == '\r' {
				banner = banner[:len(banner)-1]
			}
			s.state.banner = banner
			offset = end + 1
		} else {
			// Banner not complete yet
			return
		}
	}

	// Parse SSH binary packets
	// Format: packet_length(4) + padding_length(1) + payload(packet_length-padding_length-1) + padding
	for offset+5 <= len(buf) {
		pktLen := int(binary.BigEndian.Uint32(buf[offset : offset+4]))
		if pktLen < 1 || pktLen > 35000 { // sanity check
			// Invalid packet, skip ahead
			offset++
			continue
		}
		total := 4 + pktLen
		if offset+total > len(buf) {
			break // Wait for more data
		}

		paddingLen := int(buf[offset+4])
		payloadLen := pktLen - paddingLen - 1
		if payloadLen < 1 {
			offset += total
			continue
		}

		payloadStart := offset + 5
		payloadEnd := payloadStart + payloadLen
		if payloadEnd > len(buf) {
			break
		}

		payload := buf[payloadStart:payloadEnd]
		msgType := payload[0]

		if msgType == sshMsgKexInit {
			s.parseKexInit(payload[1:]) // skip msg type byte
		}

		offset += total
	}

	s.state.buffer = buf[offset:]
}

// parseKexInit parses SSH_MSG_KEXINIT payload (after the message type byte)
// Format: cookie(16) + name-list fields (each: uint32 length + string data) x 10 + follows(bool) + reserved(uint32)
func (s *SSHStream) parseKexInit(payload []byte) {
	if len(payload) < 17 { // 16 cookie + at least 1 byte
		return
	}
	offset := 16 // skip cookie

	readNameList := func() ([]string, int) {
		if offset+4 > len(payload) {
			return nil, -1
		}
		listLen := int(binary.BigEndian.Uint32(payload[offset : offset+4]))
		offset += 4
		if listLen == 0 {
			return nil, 0
		}
		if offset+listLen > len(payload) {
			return nil, -1
		}
		listStr := string(payload[offset : offset+listLen])
		offset += listLen
		if listStr == "" {
			return nil, 0
		}
		return splitNameList(listStr), 0
	}

	kex := &sshKexInitData{}
	var ok int

	if kex.kexAlgorithms, ok = readNameList(); ok < 0 {
		return
	}
	if kex.serverHostKeyAlgorithms, ok = readNameList(); ok < 0 {
		return
	}
	if kex.encryptionAlgorithmsC2S, ok = readNameList(); ok < 0 {
		return
	}
	if kex.encryptionAlgorithmsS2C, ok = readNameList(); ok < 0 {
		return
	}
	if kex.macAlgorithmsC2S, ok = readNameList(); ok < 0 {
		return
	}
	if kex.macAlgorithmsS2C, ok = readNameList(); ok < 0 {
		return
	}
	if kex.compressionAlgorithmsC2S, ok = readNameList(); ok < 0 {
		return
	}
	if kex.compressionAlgorithmsS2C, ok = readNameList(); ok < 0 {
		return
	}

	// Determine if this is client or server KEXINIT based on which we've seen
	if s.state.clientKex == nil {
		s.state.clientKex = kex
	} else {
		s.state.serverKex = kex
		// Both KEXINIT messages received — emit discovery
		s.factory.mu.Lock()
		if !s.state.complete {
			s.state.complete = true
			s.factory.emitDiscovery(s.state)
			delete(s.factory.sessions, s.key)
		}
		s.factory.mu.Unlock()
	}
}

// splitNameList splits a comma-separated SSH name-list string into individual names
func splitNameList(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				result = append(result, s[start:i])
			}
			start = i + 1
		}
	}
	return result
}

// Compile-time interface checks
var _ tcpassembly.Stream = (*SSHStream)(nil)
var _ tcpassembly.StreamFactory = (*SSHStreamFactory)(nil)
