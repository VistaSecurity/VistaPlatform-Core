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

// DNP3 (IEEE 1815) passive detector. Dominant SCADA protocol for North
// American electric T&D — RTUs, protective relays, meters, reclosers
// talking to control-center master stations on TCP/UDP port 20000.
//
// Most deployments are still plaintext; some have Secure Authentication
// (SAv2 deprecated, SAv5 current, SAv6 emerging). We classify on three
// axes:
//   - Plaintext DNP3 (no SA objects ever seen): security="none",
//     Version="DNP3-Plaintext" — high-severity finding.
//   - SAv5 with strong MAC (HMAC-SHA-256-16 or AES-128-GMAC-12):
//     security="present", Version="SAv5".
//   - SAv2 or SAv5 with SHA-1-family MAC: security="weak",
//     Version="SAv2" / "SAv5".
//
// Frame format (link layer):
//   Sync(2) Length(1) Control(1) Dst(2 LE) Src(2 LE) CRC(2)
// Data blocks: 16 bytes data + 2 bytes CRC each.
//
// SA objects live in Group 120 (0x78). Variation byte after the group
// byte tells us which SA message it is:
//   0x01 Challenge        — carries MAC algorithm ID
//   0x02 Reply
//   0x03 Aggressive Mode  — also carries MAC algorithm ID
//   0x04 Session Key Status Request
//   0x05 Session Key Data
//   0x06 Authentication Error
//
// We don't validate CRCs — positional stripping is enough for parsing.
// This file deliberately handles only the common SAv5 challenge/aggressive
// patterns; full IEEE 1815 parsing would be much larger and not worth it
// for the discovery use case (we just need to know which crypto profile
// the session is using).
//
// References:
//   - IEEE 1815-2012 (DNP3 + SA Annex A)
//   - OpenDNP3 reference implementation (open source)

// DNP3 link-layer constants.
const (
	dnp3SyncByte0   = 0x05
	dnp3SyncByte1   = 0x64
	dnp3HeaderLen   = 10 // sync(2) + length(1) + ctrl(1) + dst(2) + src(2) + crc(2)
	dnp3MinFrameLen = dnp3HeaderLen
)

// SA Group 120 object variation codes we recognize.
//
// Variations 1–6 are SAv2 / SAv5 (symmetric HMAC / AES-GMAC).
// Variations 7–10 were introduced in IEEE 1815.1 (SAv6) and carry
// asymmetric-PKI key management — public-key updates and per-outstation
// certificate status. Detection of any 7–10 object indicates SAv6.
const (
	dnp3SAGroup                  = 0x78
	dnp3SAVarChallenge           = 0x01
	dnp3SAVarReply               = 0x02
	dnp3SAVarAggressiveMode      = 0x03
	dnp3SAVarSessionKeyStatusReq = 0x04
	dnp3SAVarSessionKeyData      = 0x05
	dnp3SAVarAuthError           = 0x06
	dnp3SAVarPubKeyUpdateReq     = 0x07
	dnp3SAVarPubKeyUpdateStatus  = 0x08
	dnp3SAVarCertStatusReq       = 0x09
	dnp3SAVarCertStatusResp      = 0x0A
)

// MAC algorithm ID → human-readable name + version inference.
// Source: IEEE 1815-2012 Annex A Table 7-1.
type dnp3MACInfo struct {
	Name     string
	Version  string // "SAv2" or "SAv5"
	Strength string // "weak" or "present"
}

func dnp3MACAlgorithm(id uint8) (dnp3MACInfo, bool) {
	switch id {
	case 1:
		return dnp3MACInfo{"HMAC-SHA-1-4", "SAv2", "weak"}, true
	case 2:
		return dnp3MACInfo{"HMAC-SHA-256-8", "SAv5", "present"}, true
	case 3:
		return dnp3MACInfo{"HMAC-SHA-256-16", "SAv5", "present"}, true
	case 4:
		return dnp3MACInfo{"HMAC-SHA-1-10", "SAv2", "weak"}, true
	case 5:
		return dnp3MACInfo{"AES-128-GMAC-12", "SAv5", "present"}, true
	case 6:
		return dnp3MACInfo{"HMAC-SHA-256-10", "SAv5", "present"}, true
	}
	return dnp3MACInfo{}, false
}

// dnp3SessionState tracks one TCP flow's accumulated bytes and the highest-
// confidence DNP3 classification we've reached so far.
type dnp3SessionState struct {
	sessionID  string
	serverIP   string
	serverPort int
	clientIP   string
	iface      string
	buffer     []byte

	// Classification state. Once we've emitted the SA-detected discovery
	// we stop reparsing further frames — they'd just duplicate.
	emittedPlaintext bool
	emittedSA        bool
	saMACID          uint8

	lastSeen time.Time
}

// DNP3StreamFactory creates one DNP3Stream per TCP flow on port 20000.
type DNP3StreamFactory struct {
	mu           sync.Mutex
	sessions     map[tlsFlowKey]*dnp3SessionState
	ifacePending sync.Map
	discoveries  chan<- *models.CryptoDiscovery
	sensorID     string
	cache        *cache.ConnectionCache
}

// NewDNP3StreamFactory builds the factory.
func NewDNP3StreamFactory(discoveries chan<- *models.CryptoDiscovery, sensorID string, connCache *cache.ConnectionCache) *DNP3StreamFactory {
	return &DNP3StreamFactory{
		sessions:    make(map[tlsFlowKey]*dnp3SessionState),
		discoveries: discoveries,
		sensorID:    sensorID,
		cache:       connCache,
	}
}

// RegisterIfaceForFlow records the capture interface for the next New().
func (f *DNP3StreamFactory) RegisterIfaceForFlow(key tlsFlowKey, iface string) {
	if iface != "" {
		f.ifacePending.Store(key, iface)
	}
}

// New satisfies tcpassembly.StreamFactory.
func (f *DNP3StreamFactory) New(netFlow, transportFlow gopacket.Flow) tcpassembly.Stream {
	key := tlsFlowKey{net: netFlow, transport: transportFlow}
	dstPort := portFromEndpoint(transportFlow.Dst())
	srcPort := portFromEndpoint(transportFlow.Src())

	serverIP := netFlow.Dst().String()
	serverPort := dstPort
	clientIP := netFlow.Src().String()
	if srcPort == 20000 && dstPort != 20000 {
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
		state = &dnp3SessionState{
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

	return &DNP3Stream{factory: f, key: key, state: state}
}

// FlushOldSessions removes stale sessions older than maxAge.
func (f *DNP3StreamFactory) FlushOldSessions(maxAge time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for key, state := range f.sessions {
		if state.lastSeen.Before(cutoff) {
			delete(f.sessions, key)
		}
	}
}

// DNP3Stream consumes reassembled bytes for one TCP flow.
type DNP3Stream struct {
	factory *DNP3StreamFactory
	key     tlsFlowKey
	state   *dnp3SessionState
}

func (s *DNP3Stream) Reassembled(reassembly []tcpassembly.Reassembly) {
	for _, r := range reassembly {
		s.state.buffer = append(s.state.buffer, r.Bytes...)
		s.state.lastSeen = time.Now()
	}
	if len(s.state.buffer) > 16384 {
		s.state.buffer = s.state.buffer[:16384]
	}
	s.processBuffer()
}

func (s *DNP3Stream) ReassemblyComplete() {
	s.processBuffer()
	s.factory.mu.Lock()
	delete(s.factory.sessions, s.key)
	s.factory.mu.Unlock()
}

// processBuffer walks complete DNP3 frames out of the accumulated buffer.
// Stops once we've classified as SA-protected — further frames don't
// change the verdict for dedup purposes.
func (s *DNP3Stream) processBuffer() {
	if s.state.emittedSA {
		s.state.buffer = nil
		return
	}

	buf := s.state.buffer
	consumed := 0
	for consumed+dnp3HeaderLen <= len(buf) {
		// Find the next sync marker. If we don't see one near the start,
		// the stream is junk or post-frame trailing bytes — drop and stop.
		view := buf[consumed:]
		if !(view[0] == dnp3SyncByte0 && view[1] == dnp3SyncByte1) {
			// Try to resync within the next 64 bytes; further than that
			// and we're almost certainly looking at non-DNP3 traffic.
			advanced := false
			limit := 64
			if limit > len(view)-1 {
				limit = len(view) - 1
			}
			for i := 1; i < limit; i++ {
				if view[i] == dnp3SyncByte0 && i+1 < len(view) && view[i+1] == dnp3SyncByte1 {
					consumed += i
					advanced = true
					break
				}
			}
			if !advanced {
				s.state.buffer = nil
				return
			}
			continue
		}

		// Length field: number of bytes after the length+control fields,
		// counting source + destination + (16-byte data block + 2-byte CRC) chunks.
		// Per IEEE 1815-2012, length range is 5..255.
		linkLen := int(view[2])
		if linkLen < 5 {
			// Malformed — skip past this sync and keep scanning.
			consumed += 2
			continue
		}
		// Compute total frame size on the wire. After the 10-byte header
		// (which already includes the header CRC), the data portion is
		// (linkLen - 5) bytes split into 16-byte blocks each with a
		// 2-byte CRC trailing. Last block may be short.
		userBytes := linkLen - 5
		blocks := userBytes / 16
		if userBytes%16 != 0 {
			blocks++
		}
		totalLen := dnp3HeaderLen + userBytes + blocks*2
		if totalLen > len(view) {
			break // wait for more bytes
		}

		s.handleFrame(view[:totalLen], userBytes)
		consumed += totalLen
		if s.state.emittedSA {
			break
		}
	}
	if consumed > 0 {
		s.state.buffer = buf[consumed:]
	}
}

// handleFrame parses the application-layer payload (with CRCs stripped
// positionally) and looks for SA Group 120 objects. Falls through to the
// plaintext emission path on the first frame if no SA objects appear.
func (s *DNP3Stream) handleFrame(frame []byte, userBytes int) {
	classification := dnp3ClassifyFrame(frame, userBytes)
	switch classification.kind {
	case dnp3ClassSAv6, dnp3ClassSA:
		s.state.saMACID = classification.macID
		s.emitSA(classification.info)
	case dnp3ClassPlaintext:
		if !s.state.emittedPlaintext {
			s.emitPlaintext()
		}
	}
}

// dnp3ClassKind enumerates the outcomes of scanning a single DNP3 link
// frame for Secure Authentication objects. Higher values win when
// multiple frames are walked in the same buffer/datagram.
type dnp3ClassKind int

const (
	dnp3ClassNone dnp3ClassKind = iota
	dnp3ClassPlaintext
	dnp3ClassSA
	dnp3ClassSAv6
)

// dnp3FrameClassification is what dnp3ClassifyFrame returns: which kind of
// session this frame appears to belong to, and (for SA frames) the inferred
// MAC algorithm info + raw ID. Shared between the TCP assembler and the UDP
// packet parser.
type dnp3FrameClassification struct {
	kind  dnp3ClassKind
	info  dnp3MACInfo
	macID uint8
}

// dnp3ClassifyFrame strips the data-block CRCs from a complete DNP3 link
// frame, scans the application payload for Group 120 (Secure
// Authentication) objects, and returns the resulting classification.
// Returns dnp3ClassNone when the frame is too short to draw any conclusion.
func dnp3ClassifyFrame(frame []byte, userBytes int) dnp3FrameClassification {
	if len(frame) < dnp3HeaderLen {
		return dnp3FrameClassification{kind: dnp3ClassNone}
	}
	app := dnp3StripDataBlockCRCs(frame[dnp3HeaderLen:], userBytes)
	if len(app) < 2 {
		return dnp3FrameClassification{kind: dnp3ClassNone}
	}
	body := app[1:] // drop transport byte
	for i := 0; i < len(body)-2; i++ {
		if body[i] != dnp3SAGroup {
			continue
		}
		variation := body[i+1]
		if variation < dnp3SAVarChallenge || variation > dnp3SAVarCertStatusResp {
			continue
		}
		// Variations 7–10 are IEEE 1815.1 (SAv6) — asymmetric PKI key
		// management. Always SAv6, no symmetric MAC.
		if variation >= dnp3SAVarPubKeyUpdateReq && variation <= dnp3SAVarCertStatusResp {
			return dnp3FrameClassification{
				kind:  dnp3ClassSAv6,
				info:  dnp3MACInfo{Name: "asymmetric-PKI", Version: "SAv6", Strength: "present"},
				macID: 0,
			}
		}
		if variation == dnp3SAVarChallenge || variation == dnp3SAVarAggressiveMode {
			// Object data starts after group + variation + qualifier. The
			// free-format qualifier (0x5B) carries a 2-byte length prefix;
			// other qualifier codes place the object data immediately after.
			objStart := i + 3
			if body[i+2] == 0x5B {
				objStart += 2
			}
			// g120v1 opens with CSQ(4) + USR(2); the MAC algorithm octet is
			// the byte after those. Reading it positionally matters: the CSQ
			// bytes themselves often fall in the valid MAC-ID range (1–6),
			// so scanning for "any plausible ID" misattributes the version.
			macIdx := objStart + 6
			if macIdx < len(body) {
				if info, ok := dnp3MACAlgorithm(body[macIdx]); ok {
					return dnp3FrameClassification{kind: dnp3ClassSA, info: info, macID: body[macIdx]}
				}
			}
		}
		return dnp3FrameClassification{
			kind: dnp3ClassSA,
			info: dnp3MACInfo{Name: "unknown", Version: "SA", Strength: "present"},
		}
	}
	return dnp3FrameClassification{kind: dnp3ClassPlaintext}
}

// dnp3WalkFrames walks one or more DNP3 link frames out of a contiguous
// buffer (typical of a UDP datagram or a fully-assembled TCP segment) and
// returns the highest-priority classification reached: SA beats plaintext,
// plaintext beats none. Caller does not need to deal with frame boundaries
// or CRC stripping.
//
// Unlike the TCP assembler's processBuffer this does not buffer partial
// frames — a UDP datagram either contains complete link frames or it
// doesn't (and even DNP3-over-TCP traffic is overwhelmingly one frame per
// segment). Anything that doesn't parse is treated as "no DNP3 frame here"
// rather than waiting for more bytes.
func dnp3WalkFrames(buf []byte) dnp3FrameClassification {
	best := dnp3FrameClassification{kind: dnp3ClassNone}
	for offset := 0; offset+dnp3HeaderLen <= len(buf); {
		view := buf[offset:]
		if !(view[0] == dnp3SyncByte0 && view[1] == dnp3SyncByte1) {
			// Re-sync within a short window; further than that and we're
			// looking at non-DNP3 bytes (or trailing padding).
			advanced := false
			limit := 64
			if limit > len(view)-1 {
				limit = len(view) - 1
			}
			for i := 1; i < limit; i++ {
				if view[i] == dnp3SyncByte0 && i+1 < len(view) && view[i+1] == dnp3SyncByte1 {
					offset += i
					advanced = true
					break
				}
			}
			if !advanced {
				break
			}
			continue
		}
		linkLen := int(view[2])
		if linkLen < 5 {
			offset += 2
			continue
		}
		userBytes := linkLen - 5
		blocks := userBytes / 16
		if userBytes%16 != 0 {
			blocks++
		}
		totalLen := dnp3HeaderLen + userBytes + blocks*2
		if totalLen > len(view) {
			break
		}
		c := dnp3ClassifyFrame(view[:totalLen], userBytes)
		if c.kind > best.kind {
			best = c
		}
		// SAv6 is the strongest classification — stop walking once we
		// see one. SAv5 doesn't short-circuit so a later SAv6 frame in
		// the same datagram can still upgrade the result.
		if best.kind == dnp3ClassSAv6 {
			break
		}
		offset += totalLen
	}
	return best
}

// parseDNP3Packet inspects a single UDP datagram for DNP3 traffic and
// returns a CryptoDiscovery describing the strongest classification found
// in the datagram, or nil when no DNP3 frame is recognized. Mirrors the
// TCP assembler's emission shape so downstream consumers don't need to
// special-case UDP DNP3.
//
// The connCache is consulted for dedup using a per-(server, port, class)
// key so a chatty outstation polled many times per second doesn't flood
// the discovery channel; pass nil to disable dedup (tests).
func parseDNP3Packet(payload []byte, srcIP, dstIP string, srcPort, dstPort int, sensorID, iface string, connCache *cache.ConnectionCache) *models.CryptoDiscovery {
	if len(payload) < dnp3HeaderLen {
		return nil
	}
	classification := dnp3WalkFrames(payload)
	if classification.kind == dnp3ClassNone {
		return nil
	}

	// Identify the server side. With UDP we don't have a real handshake;
	// pin the server as the side using the well-known port 20000, falling
	// back to the destination otherwise.
	serverIP := dstIP
	serverPort := dstPort
	clientIP := srcIP
	if srcPort == 20000 && dstPort != 20000 {
		serverIP = srcIP
		serverPort = srcPort
		clientIP = dstIP
	}

	sessionID := uuid.New().String()
	var (
		protocol = "DNP3"
		version  string
		metadata = map[string]interface{}{
			"session_id":  sessionID,
			"reassembled": false,
			"transport":   "udp",
		}
	)
	dedupKey := "DNP3-UDP"
	switch classification.kind {
	case dnp3ClassPlaintext:
		version = "DNP3-Plaintext"
		metadata["security"] = "none"
		metadata["plaintext_dnp3"] = true
		metadata["sa_active"] = false
	case dnp3ClassSA, dnp3ClassSAv6:
		info := classification.info
		version = info.Version
		security := info.Strength
		if security == "" {
			security = "present"
		}
		metadata["sa_active"] = true
		metadata["sa_version"] = info.Version
		metadata["mac_algorithm_id"] = int(classification.macID)
		metadata["mac_algorithm_name"] = info.Name
		metadata["security"] = security
		if classification.kind == dnp3ClassSAv6 {
			dedupKey = "DNP3-UDP-SAv6"
		} else {
			dedupKey = "DNP3-UDP-SA"
		}
	}
	if iface != "" {
		metadata["interface"] = iface
	}

	if connCache != nil && serverIP != "" {
		shouldReport, _ := connCache.ShouldReport(serverIP, serverPort, dedupKey)
		if !shouldReport {
			return nil
		}
	}

	return &models.CryptoDiscovery{
		ID:              uuid.New().String(),
		SensorID:        sensorID,
		Timestamp:       time.Now(),
		SourceIP:        clientIP,
		DestIP:          serverIP,
		Port:            serverPort,
		Protocol:        protocol,
		Version:         version,
		CipherSuite:     "",
		DiscoveryMethod: "passive",
		Confidence:      0.9,
		RawMetadata:     metadata,
		SessionID:       sessionID,
		CreatedAt:       time.Now(),
	}
}

// dnp3StripDataBlockCRCs removes the 2-byte CRC trailing each 16-byte
// data block from the application portion of the frame. Returns the
// concatenated payload bytes. Block boundaries are derived from the data
// itself (full 16-byte blocks, then a final short block of whatever
// remains minus its CRC); userBytes only caps the output, so an
// overstated count degrades gracefully instead of dropping the frame.
func dnp3StripDataBlockCRCs(data []byte, userBytes int) []byte {
	out := make([]byte, 0, userBytes)
	consumed := 0
	for consumed+2 < len(data) && len(out) < userBytes {
		blockLen := 16
		if rem := len(data) - consumed - 2; rem < blockLen {
			blockLen = rem
		}
		if want := userBytes - len(out); want < blockLen {
			blockLen = want
		}
		out = append(out, data[consumed:consumed+blockLen]...)
		consumed += blockLen + 2 // skip CRC
	}
	return out
}

func (s *DNP3Stream) emitPlaintext() {
	if s.factory.cache != nil && s.state.serverIP != "" {
		shouldReport, _ := s.factory.cache.ShouldReport(s.state.serverIP, s.state.serverPort, "DNP3")
		if !shouldReport {
			s.state.emittedPlaintext = true
			return
		}
	}
	metadata := map[string]interface{}{
		"session_id":     s.state.sessionID,
		"reassembled":    true,
		"security":       "none",
		"plaintext_dnp3": true,
		"sa_active":      false,
	}
	if s.state.iface != "" {
		metadata["interface"] = s.state.iface
	}
	s.send("DNP3", "DNP3-Plaintext", metadata)
	s.state.emittedPlaintext = true
}

func (s *DNP3Stream) emitSA(info dnp3MACInfo) {
	dedupKey := "DNP3-SA"
	if info.Version == "SAv6" {
		dedupKey = "DNP3-SAv6"
	}
	if s.factory.cache != nil && s.state.serverIP != "" {
		shouldReport, _ := s.factory.cache.ShouldReport(s.state.serverIP, s.state.serverPort, dedupKey)
		if !shouldReport {
			s.state.emittedSA = true
			return
		}
	}
	security := info.Strength
	if security == "" {
		security = "present"
	}
	metadata := map[string]interface{}{
		"session_id":         s.state.sessionID,
		"reassembled":        true,
		"sa_active":          true,
		"sa_version":         info.Version,
		"mac_algorithm_id":   int(s.state.saMACID),
		"mac_algorithm_name": info.Name,
		"security":           security,
	}
	if s.state.iface != "" {
		metadata["interface"] = s.state.iface
	}
	s.send("DNP3", info.Version, metadata)
	s.state.emittedSA = true
}

func (s *DNP3Stream) send(protocol, version string, metadata map[string]interface{}) {
	discovery := &models.CryptoDiscovery{
		ID:              uuid.New().String(),
		SensorID:        s.factory.sensorID,
		Timestamp:       time.Now(),
		SourceIP:        s.state.clientIP,
		DestIP:          s.state.serverIP,
		Port:            s.state.serverPort,
		Protocol:        protocol,
		Version:         version,
		CipherSuite:     "",
		DiscoveryMethod: "passive",
		Confidence:      0.9,
		RawMetadata:     metadata,
		SessionID:       s.state.sessionID,
		CreatedAt:       time.Now(),
	}
	select {
	case s.factory.discoveries <- discovery:
	default:
		log.Printf("Warning: DNP3 discovery channel full, dropping session %s", s.state.sessionID)
	}
}

// frame helpers — kept exported for tests.

// dnp3LinkAddresses returns the link-layer destination and source
// addresses from a complete DNP3 frame header.
func dnp3LinkAddresses(frame []byte) (dst, src uint16, ok bool) {
	if len(frame) < dnp3HeaderLen {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint16(frame[4:6]), binary.LittleEndian.Uint16(frame[6:8]), true
}

// Compile-time interface checks
var _ tcpassembly.Stream = (*DNP3Stream)(nil)
var _ tcpassembly.StreamFactory = (*DNP3StreamFactory)(nil)
