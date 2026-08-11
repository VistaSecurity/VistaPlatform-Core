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
	"github.com/vistasecurity/vistaplatform/sensor/internal/smbutil"
)

// SMB2 constants
var smb2Magic = []byte{0xFE, 0x53, 0x4D, 0x42} // \xFESMB

const (
	smb2CommandNegotiate = 0x0000

	// SMB2 NEGOTIATE SecurityMode flags
	smbSecurityModeSigningEnabled  = 0x01
	smbSecurityModeSigningRequired = 0x02

	// SMB2 Capabilities — encryption bit
	smbCapabilityEncryption = 0x0040

	// SMB 3.1.1 negotiate context types
	smbNegotiateContextEncryption = 0x0002 // SMB2_ENCRYPTION_CAPABILITIES
	smbNegotiateContextSigning    = 0x0008 // SMB2_SIGNING_CAPABILITIES

	// Encryption cipher IDs
	smbCipherAES128CCM = 0x0001
	smbCipherAES128GCM = 0x0002
	smbCipherAES256CCM = 0x0003
	smbCipherAES256GCM = 0x0004
)

// smbSessionState tracks a single SMB negotiation exchange
type smbSessionState struct {
	sessionID  string
	serverIP   string
	serverPort int
	clientIP   string
	iface      string
	buffer     []byte
	lastSeen   time.Time
	complete   bool
}

// SMBStreamFactory creates SMBStream instances for TCP port 445.
type SMBStreamFactory struct {
	mu           sync.Mutex
	sessions     map[tlsFlowKey]*smbSessionState
	ifacePending sync.Map // tlsFlowKey -> string (capture interface); consumed in New
	discoveries  chan<- *models.CryptoDiscovery
	sensorID     string
	cache        *cache.ConnectionCache
}

// RegisterIfaceForFlow records the capture interface for the next Assembler lookup for this flow key.
func (f *SMBStreamFactory) RegisterIfaceForFlow(key tlsFlowKey, iface string) {
	if iface != "" {
		f.ifacePending.Store(key, iface)
	}
}

// NewSMBStreamFactory creates a factory for SMB protocol parsing.
func NewSMBStreamFactory(discoveries chan<- *models.CryptoDiscovery, sensorID string, connCache *cache.ConnectionCache) *SMBStreamFactory {
	return &SMBStreamFactory{
		sessions:    make(map[tlsFlowKey]*smbSessionState),
		discoveries: discoveries,
		sensorID:    sensorID,
		cache:       connCache,
	}
}

// SMBStream handles a single TCP stream for SMB protocol
type SMBStream struct {
	factory *SMBStreamFactory
	key     tlsFlowKey
	state   *smbSessionState
}

func (f *SMBStreamFactory) New(netFlow, transportFlow gopacket.Flow) tcpassembly.Stream {
	key := tlsFlowKey{net: netFlow, transport: transportFlow}
	dstPort := int(binary.BigEndian.Uint16(transportFlow.Dst().Raw()))
	srcPort := int(binary.BigEndian.Uint16(transportFlow.Src().Raw()))

	serverIP := netFlow.Dst().String()
	serverPort := dstPort
	clientIP := netFlow.Src().String()
	if srcPort == 445 {
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
		state = &smbSessionState{
			sessionID:  uuid.New().String(),
			serverIP:   serverIP,
			serverPort: serverPort,
			clientIP:   clientIP,
			iface:      iface,
			lastSeen:   time.Now(),
		}
		f.sessions[key] = state
	} else {
		if iface != "" && state.iface == "" {
			state.iface = iface
		}
		state.lastSeen = time.Now()
	}
	f.mu.Unlock()

	return &SMBStream{factory: f, key: key, state: state}
}

func (s *SMBStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	for _, r := range reassembly {
		s.state.buffer = append(s.state.buffer, r.Bytes...)
		s.state.lastSeen = time.Now()
	}
	// Limit buffer to prevent unbounded growth — SMB negotiate is small
	if len(s.state.buffer) > 8192 {
		s.state.buffer = s.state.buffer[:8192]
	}
	s.processSMBBuffer()
}

func (s *SMBStream) ReassemblyComplete() {
	if !s.state.complete {
		s.processSMBBuffer()
	}
}

func (s *SMBStream) processSMBBuffer() {
	if s.state.complete || len(s.state.buffer) < 68 { // NetBIOS(4) + SMB2 header(64)
		return
	}

	buf := s.state.buffer

	// NetBIOS Session Service header: Type(1) + Length(3)
	if buf[0] != 0x00 { // Session Message type
		return
	}
	nbLen := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
	if nbLen < 64 || 4+nbLen > len(buf) {
		return
	}

	smb := buf[4 : 4+nbLen]

	// Validate SMB2 magic
	if len(smb) < 64 || smb[0] != smb2Magic[0] || smb[1] != smb2Magic[1] ||
		smb[2] != smb2Magic[2] || smb[3] != smb2Magic[3] {
		return
	}

	// SMB2 header: StructureSize(2) + CreditCharge(2) + Status(4) + Command(2) + ...
	command := binary.LittleEndian.Uint16(smb[12:14])
	flags := binary.LittleEndian.Uint32(smb[16:20])

	// Only parse NEGOTIATE Response (command=0, flags bit 0 = response)
	if command != smb2CommandNegotiate || flags&0x01 == 0 {
		return
	}

	// NEGOTIATE Response body starts after the 64-byte header
	body := smb[64:]
	if len(body) < 65 { // minimum negotiate response body
		return
	}

	s.state.complete = true
	s.parseSMBNegotiateResponse(body)
}

func (s *SMBStream) parseSMBNegotiateResponse(body []byte) {
	// Structure: StructureSize(2) + SecurityMode(2) + DialectRevision(2) + ...
	securityMode := binary.LittleEndian.Uint16(body[2:4])
	dialectRevision := binary.LittleEndian.Uint16(body[4:6])
	capabilities := binary.LittleEndian.Uint32(body[24:28])

	signingEnabled := securityMode&smbSecurityModeSigningEnabled != 0
	signingRequired := securityMode&smbSecurityModeSigningRequired != 0
	encryptionSupported := capabilities&smbCapabilityEncryption != 0

	dialectName := smbutil.DialectName(dialectRevision)

	metadata := map[string]interface{}{
		"smb_dialect":          dialectName,
		"smb_dialect_revision": dialectRevision,
		"signing_enabled":      signingEnabled,
		"signing_required":     signingRequired,
		"encryption_supported": encryptionSupported,
	}
	if s.state.iface != "" {
		metadata["interface"] = s.state.iface
	}

	// For SMB 3.1.1, parse negotiate contexts for encryption ciphers
	if dialectRevision == 0x0311 && len(body) >= 64 {
		// MS-SMB2: NegotiateContextCount at body offset 6, NegotiateContextOffset at60 (from SMB2 header start).
		contextCount := binary.LittleEndian.Uint16(body[6:8])
		contextOffset := binary.LittleEndian.Uint32(body[60:64])
		// contextOffset is from start of SMB2 header (64 bytes before body)
		if contextOffset >= 64 {
			bodyContextOffset := int(contextOffset) - 64
			ciphers := parseSMBNegotiateContexts(body, bodyContextOffset, int(contextCount))
			if len(ciphers) > 0 {
				metadata["encryption_ciphers"] = ciphers
			}
		}
	}

	// Dedup check
	if s.factory.cache != nil {
		shouldReport, _ := s.factory.cache.ShouldReport(s.state.serverIP, s.state.serverPort, "SMB")
		if !shouldReport {
			return
		}
	}

	cipherSuite := ""
	if ciphers, ok := metadata["encryption_ciphers"].([]string); ok && len(ciphers) > 0 {
		cipherSuite = ciphers[0]
	}

	discovery := &models.CryptoDiscovery{
		ID:              uuid.New().String(),
		SensorID:        s.factory.sensorID,
		Timestamp:       time.Now(),
		SourceIP:        s.state.clientIP,
		DestIP:          s.state.serverIP,
		Port:            s.state.serverPort,
		Protocol:        "SMB",
		Version:         dialectName,
		CipherSuite:     cipherSuite,
		DiscoveryMethod: "passive",
		Confidence:      0.90,
		RawMetadata:     metadata,
		SessionID:       s.state.sessionID,
		CreatedAt:       time.Now(),
	}

	select {
	case s.factory.discoveries <- discovery:
	default:
		log.Printf("Warning: SMB discovery channel full, dropping session %s", s.state.sessionID)
	}
}

// parseSMBNegotiateContexts extracts encryption cipher info from SMB 3.1.1
// negotiate context list. Each context is 8-byte aligned:
//
//	ContextType(2) + DataLength(2) + Reserved(4) + Data(variable) + Padding
func parseSMBNegotiateContexts(body []byte, offset int, count int) []string {
	var ciphers []string

	for i := 0; i < count && offset+8 <= len(body); i++ {
		contextType := binary.LittleEndian.Uint16(body[offset : offset+2])
		dataLen := int(binary.LittleEndian.Uint16(body[offset+2 : offset+4]))

		dataStart := offset + 8 // skip type(2)+len(2)+reserved(4)
		if dataStart+dataLen > len(body) {
			break
		}

		if contextType == smbNegotiateContextEncryption && dataLen >= 4 {
			data := body[dataStart : dataStart+dataLen]
			cipherCount := int(binary.LittleEndian.Uint16(data[0:2]))
			for j := 0; j < cipherCount && 2+2*(j+1) <= len(data); j++ {
				cipherID := binary.LittleEndian.Uint16(data[2+2*j : 2+2*(j+1)])
				ciphers = append(ciphers, smbCipherName(cipherID))
			}
		}

		// Advance to next context (8-byte aligned)
		totalLen := 8 + dataLen
		if totalLen%8 != 0 {
			totalLen += 8 - (totalLen % 8)
		}
		offset += totalLen
	}

	return ciphers
}

func smbCipherName(id uint16) string {
	switch id {
	case smbCipherAES128CCM:
		return "AES-128-CCM"
	case smbCipherAES128GCM:
		return "AES-128-GCM"
	case smbCipherAES256CCM:
		return "AES-256-CCM"
	case smbCipherAES256GCM:
		return "AES-256-GCM"
	}
	return "Unknown"
}

// FlushOldSessions removes stale SMB sessions older than maxAge.
func (f *SMBStreamFactory) FlushOldSessions(maxAge time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for key, state := range f.sessions {
		if state.lastSeen.Before(cutoff) {
			delete(f.sessions, key)
		}
	}
}
