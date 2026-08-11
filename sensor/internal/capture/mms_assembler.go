package capture

import (
	"encoding/hex"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/tcpassembly"
	"github.com/vistasecurity/vistaplatform/sensor/internal/cache"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// MMS / ICCP passive detector.
//
// Both protocols ride TCP port 102 over the ISO transport stack (TPKT →
// COTP → ISO Session/Presentation → MMS or TASE.2). Plaintext sessions
// land here; TLS-wrapped sessions are picked up by the existing TLS
// assembler (port 102 routes to BOTH this assembler and the TLS assembler
// — see packet_capture.go's analyzePacket dispatch). Only one will fire
// per session; the other no-ops because the wire bytes don't match.
//
// We emit `Protocol="MMS"` when we see a TPKT/COTP CR or DT PDU, then
// re-emit as `Protocol="ICCP"` if the first DT payload contains the
// TASE.2 application-context OID. Either way, security="none" because
// these sessions are observed plaintext.
//
// Design note: we deliberately do not parse the full ACSE/ASN.1 layer —
// the OID byte-pattern search in cotp_tpkt.go's findTASE2OID is reliable
// enough for differentiation and avoids dragging an ASN.1 dependency into
// the standalone sensor binary.

// mmsSessionState tracks one TCP flow's accumulated bytes plus per-session
// metadata extracted from the COTP CR PDU.
type mmsSessionState struct {
	sessionID  string
	serverIP   string
	serverPort int
	clientIP   string
	iface      string
	buffer     []byte

	srcTSAPHex string
	dstTSAPHex string
	cotpSeen   bool

	emittedAs string // "" before emit; "MMS" or "ICCP" after
	lastSeen  time.Time
}

// MMSStreamFactory creates one MMSStream per TCP flow on port 102. Reuses
// tlsFlowKey as the map key purely for type sharing — there is no semantic
// dependency on TLS.
type MMSStreamFactory struct {
	mu           sync.Mutex
	sessions     map[tlsFlowKey]*mmsSessionState
	ifacePending sync.Map
	discoveries  chan<- *models.CryptoDiscovery
	sensorID     string
	cache        *cache.ConnectionCache
}

// NewMMSStreamFactory builds the factory. `connCache` is the shared
// dedup cache; one MMS finding per (server, port, "MMS"|"ICCP") pair per
// TTL window.
func NewMMSStreamFactory(discoveries chan<- *models.CryptoDiscovery, sensorID string, connCache *cache.ConnectionCache) *MMSStreamFactory {
	return &MMSStreamFactory{
		sessions:    make(map[tlsFlowKey]*mmsSessionState),
		discoveries: discoveries,
		sensorID:    sensorID,
		cache:       connCache,
	}
}

// RegisterIfaceForFlow records the capture interface for the next New()
// call on this flow key. Same pattern as SMBStreamFactory.
func (f *MMSStreamFactory) RegisterIfaceForFlow(key tlsFlowKey, iface string) {
	if iface != "" {
		f.ifacePending.Store(key, iface)
	}
}

// New satisfies tcpassembly.StreamFactory.
func (f *MMSStreamFactory) New(netFlow, transportFlow gopacket.Flow) tcpassembly.Stream {
	key := tlsFlowKey{net: netFlow, transport: transportFlow}
	dstPort := portFromEndpoint(transportFlow.Dst())
	srcPort := portFromEndpoint(transportFlow.Src())

	serverIP := netFlow.Dst().String()
	serverPort := dstPort
	clientIP := netFlow.Src().String()
	if srcPort == 102 && dstPort != 102 {
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
		state = &mmsSessionState{
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

	return &MMSStream{factory: f, key: key, state: state}
}

// FlushOldSessions removes sessions that haven't received bytes within
// maxAge. Called from the central 30-second ticker.
func (f *MMSStreamFactory) FlushOldSessions(maxAge time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for key, state := range f.sessions {
		if state.lastSeen.Before(cutoff) {
			delete(f.sessions, key)
		}
	}
}

// MMSStream consumes reassembled bytes for one TCP flow.
type MMSStream struct {
	factory *MMSStreamFactory
	key     tlsFlowKey
	state   *mmsSessionState
}

func (s *MMSStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	for _, r := range reassembly {
		s.state.buffer = append(s.state.buffer, r.Bytes...)
		s.state.lastSeen = time.Now()
	}
	// Cap buffer growth — we only need to see CR + the first DT payload
	// to make the MMS-vs-ICCP determination. Anything beyond ~16 KB is
	// almost certainly post-detection traffic that wastes memory.
	if len(s.state.buffer) > 16384 {
		s.state.buffer = s.state.buffer[:16384]
	}
	s.processBuffer()
}

func (s *MMSStream) ReassemblyComplete() {
	s.processBuffer()
	s.factory.mu.Lock()
	delete(s.factory.sessions, s.key)
	s.factory.mu.Unlock()
}

// processBuffer walks complete TPKT PDUs out of the accumulated buffer.
// Stops once we've emitted a terminal classification — ICCP (for MMS
// sessions that turn out to be TASE.2) or S7/S7-Plus (Siemens), which
// share port 102 with MMS but use a vendor-specific application layer.
func (s *MMSStream) processBuffer() {
	if isTerminalMMSClass(s.state.emittedAs) {
		// Final classification reached; drain and stop reparsing.
		s.state.buffer = nil
		return
	}

	buf := s.state.buffer
	consumed := 0
	for consumed+tpktHeaderLen <= len(buf) {
		view := buf[consumed:]
		// Not a TPKT frame — drop the whole buffer. Either we're looking
		// at a TLS session (handled by the TLS assembler) or the stream
		// is malformed; either way no point re-scanning forward.
		if !isTPKTHeader(view) {
			s.state.buffer = nil
			return
		}
		pduLen := tpktLength(view)
		if pduLen < tpktHeaderLen+2 || pduLen > len(view) {
			break // wait for more bytes
		}
		s.state.cotpSeen = true
		s.handleTPKTFrame(view[:pduLen])
		consumed += pduLen
		// One-shot: stop walking once we've reached a terminal
		// classification (ICCP / S7 / S7-Plus).
		if isTerminalMMSClass(s.state.emittedAs) {
			break
		}
	}
	if consumed > 0 {
		s.state.buffer = buf[consumed:]
	}
}

// handleTPKTFrame dispatches one full TPKT PDU. CR PDUs give us the TSAP
// addresses and trigger the initial MMS finding; DT PDUs are inspected
// for the TASE.2 OID to upgrade the classification to ICCP.
func (s *MMSStream) handleTPKTFrame(frame []byte) {
	switch cotpPDUType(frame) {
	case cotpPDUConnectionRequest, cotpPDUConnectionConfirm:
		src, dst := extractTSAPs(frame)
		if len(src) > 0 {
			s.state.srcTSAPHex = hex.EncodeToString(src)
		}
		if len(dst) > 0 {
			s.state.dstTSAPHex = hex.EncodeToString(dst)
		}
		// Only emit the MMS finding once per session — the CC mirrors
		// the CR's TSAPs, no need for a second discovery.
		if s.state.emittedAs == "" {
			s.emit("MMS", "")
		}
	case cotpPDUData:
		// Inspect application-layer payload. Three vendor families share
		// port 102:
		//   - IEC 61850 MMS (default — already emitted on the CR above)
		//   - ICCP / TASE.2 — leading TASE.2 OID in the ACSE bind
		//   - Siemens S7 — payload byte 0 = 0x32 (S7Comm) or 0x72 (S7-Plus)
		// First-match wins; S7 / S7-Plus / ICCP all re-emit over the
		// initial MMS finding because they're the more specific protocol.
		if isTerminalMMSClass(s.state.emittedAs) {
			return
		}
		payload := cotpPayload(frame)
		if v := detectS7Variant(payload); v != "" {
			s.emit("S7", v)
			return
		}
		if findTASE2OID(payload) {
			s.emit("ICCP", "TASE.2")
		}
	}
}

// isTerminalMMSClass reports whether an `emittedAs` value represents a
// final classification (no further reparsing will change it). The bare
// "MMS" finding is intentionally non-terminal because S7 / S7-Plus /
// ICCP detection from the first DT PDU can still upgrade it.
func isTerminalMMSClass(s string) bool {
	switch s {
	case "ICCP", "S7":
		return true
	}
	return false
}

// detectS7Variant inspects a COTP DT PDU's application payload for the
// Siemens S7 protocol-ID byte. Returns "S7Comm" for classic S7
// (S7-300/400/1200/1500 legacy firmware), "S7Plus" for S7-Plus (newer
// 1500 firmware), or "" when neither variant is recognized.
//
// Reference: Wireshark dissector epan/dissectors/packet-s7comm.c —
// S7Comm protocol-ID at byte 0 is 0x32; S7-Plus uses 0x72. Both are
// distinct from MMS (ASN.1 BER, typically starts with 0x60 / 0x61 /
// 0xA0…) and ICCP (BER with the TASE.2 OID).
func detectS7Variant(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	switch payload[0] {
	case 0x32:
		return "S7Comm"
	case 0x72:
		return "S7Plus"
	}
	return ""
}

// emit constructs and dispatches a CryptoDiscovery for the session.
// `protocol` is "MMS" or "ICCP"; `version` is the optional version label
// (empty for MMS, "TASE.2" for ICCP).
func (s *MMSStream) emit(protocol, version string) {
	if s.factory.cache != nil && s.state.serverIP != "" {
		shouldReport, _ := s.factory.cache.ShouldReport(s.state.serverIP, s.state.serverPort, protocol)
		if !shouldReport {
			s.state.emittedAs = protocol
			return
		}
	}

	metadata := map[string]interface{}{
		"session_id":  s.state.sessionID,
		"reassembled": true,
		// All three protocols routed here (MMS, ICCP, S7) are observed
		// plaintext when this assembler fires; the TLS-wrapped path goes
		// through the standard TLS assembler instead and gets IEC 62351-3
		// classification there.
		"security": "none",
	}
	// IEC 61850 / 62351 framing applies to MMS + ICCP/TASE.2 only.
	// S7 is a Siemens proprietary protocol with no IEC-spec lineage.
	if protocol == "MMS" || protocol == "ICCP" {
		metadata["iec61850_protocol"] = protocol
		metadata["iec62351_applicable"] = true
	}
	if s.state.srcTSAPHex != "" {
		metadata["src_tsap"] = s.state.srcTSAPHex
	}
	if s.state.dstTSAPHex != "" {
		metadata["dst_tsap"] = s.state.dstTSAPHex
	}
	if s.state.iface != "" {
		metadata["interface"] = s.state.iface
	}
	if protocol == "ICCP" {
		metadata["standard"] = "TASE.2 / IEC 60870-6"
	}
	if protocol == "S7" {
		metadata["vendor"] = "Siemens"
		metadata["s7_variant"] = version
		metadata["plaintext_s7"] = true
	}

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
	s.state.emittedAs = protocol

	select {
	case s.factory.discoveries <- discovery:
	default:
		log.Printf("Warning: %s discovery channel full, dropping session %s", protocol, s.state.sessionID)
	}
}

// Compile-time interface checks
var _ tcpassembly.Stream = (*MMSStream)(nil)
var _ tcpassembly.StreamFactory = (*MMSStreamFactory)(nil)
