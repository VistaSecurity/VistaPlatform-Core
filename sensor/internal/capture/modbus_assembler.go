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

// Modbus/TCP (TCP port 502, MBAP-wrapped Modbus PDU) is the dominant OT
// protocol in the field — PLCs, drives, sensors, flow meters, RTUs all speak
// it. It has no native authentication or encryption: every Modbus/TCP session
// is a plaintext conversation. For VistaPlatform, *detecting* Modbus on the wire
// IS the finding — the absence of crypto is the cryptographic-discovery
// signal.
//
// MBAP frame:
//
//	Transaction ID  : 2 bytes BE
//	Protocol ID     : 2 bytes BE (always 0x0000 for Modbus/TCP)
//	Length          : 2 bytes BE (number of bytes following — Unit ID + PDU)
//	Unit ID         : 1 byte
//	Function Code   : 1 byte
//	Data            : variable
//
// Modbus/TLS (TCP port 802, RFC 8184) is handled transparently by the
// existing TLS assembler when port 802 is added to the BPF.

const (
	modbusTCPProtocolID = 0x0000
	modbusMBAPHeaderLen = 6 // TxID(2) + ProtoID(2) + Length(2)
	modbusMaxFrameLen   = 260
)

// modbusFunctionName maps standard Modbus function codes to their names.
// Codes ≥ 0x80 are exception responses (normal code | 0x80) and are handled
// at lookup time. Returns "Unknown" for unrecognized codes — the discovery is
// still useful (we know it's a Modbus session), the function name is just
// metadata.
func modbusFunctionName(code uint8) string {
	if code&0x80 != 0 {
		base := modbusFunctionName(code & 0x7F)
		return base + " (Exception)"
	}
	switch code {
	case 1:
		return "ReadCoils"
	case 2:
		return "ReadDiscreteInputs"
	case 3:
		return "ReadHoldingRegisters"
	case 4:
		return "ReadInputRegisters"
	case 5:
		return "WriteSingleCoil"
	case 6:
		return "WriteSingleRegister"
	case 7:
		return "ReadExceptionStatus"
	case 8:
		return "Diagnostics"
	case 11:
		return "GetCommEventCounter"
	case 12:
		return "GetCommEventLog"
	case 15:
		return "WriteMultipleCoils"
	case 16:
		return "WriteMultipleRegisters"
	case 17:
		return "ReportServerID"
	case 20:
		return "ReadFileRecord"
	case 21:
		return "WriteFileRecord"
	case 22:
		return "MaskWriteRegister"
	case 23:
		return "ReadWriteMultipleRegisters"
	case 24:
		return "ReadFIFOQueue"
	case 43:
		return "EncapsulatedInterfaceTransport"
	}
	return "Unknown"
}

// modbusSessionState tracks a single TCP flow's accumulated bytes and whether
// we've already emitted a discovery for this session (since one Modbus session
// produces many frames; we only need to report once per dedup window).
type modbusSessionState struct {
	sessionID  string
	serverIP   string
	serverPort int
	clientIP   string
	iface      string
	buffer     []byte
	emitted    bool
	lastSeen   time.Time
}

// ModbusStreamFactory creates ModbusStream instances for TCP port 502 flows.
// Reuses tlsFlowKey purely for sharing the (net, transport) flow tuple —
// there is no semantic dependency on TLS.
type ModbusStreamFactory struct {
	mu           sync.Mutex
	sessions     map[tlsFlowKey]*modbusSessionState
	ifacePending sync.Map // tlsFlowKey -> string (capture interface)
	discoveries  chan<- *models.CryptoDiscovery
	sensorID     string
	cache        *cache.ConnectionCache
}

// NewModbusStreamFactory creates a Modbus assembler factory.
func NewModbusStreamFactory(discoveries chan<- *models.CryptoDiscovery, sensorID string, connCache *cache.ConnectionCache) *ModbusStreamFactory {
	return &ModbusStreamFactory{
		sessions:    make(map[tlsFlowKey]*modbusSessionState),
		discoveries: discoveries,
		sensorID:    sensorID,
		cache:       connCache,
	}
}

// RegisterIfaceForFlow records the capture interface for the next Assembler
// lookup for this flow key — same pattern as SMBStreamFactory.
func (f *ModbusStreamFactory) RegisterIfaceForFlow(key tlsFlowKey, iface string) {
	if iface != "" {
		f.ifacePending.Store(key, iface)
	}
}

// New satisfies tcpassembly.StreamFactory. Modbus/TCP servers always listen on
// 502 — use that to disambiguate which side is the server.
func (f *ModbusStreamFactory) New(netFlow, transportFlow gopacket.Flow) tcpassembly.Stream {
	key := tlsFlowKey{net: netFlow, transport: transportFlow}
	dstPort := portFromEndpoint(transportFlow.Dst())
	srcPort := portFromEndpoint(transportFlow.Src())

	serverIP := netFlow.Dst().String()
	serverPort := dstPort
	clientIP := netFlow.Src().String()
	if srcPort == 502 && dstPort != 502 {
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
		state = &modbusSessionState{
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

	return &ModbusStream{factory: f, key: key, state: state}
}

// FlushOldSessions removes stale sessions older than maxAge. Called from the
// 30s ticker in PacketCapture.Start to prevent unbounded session-map growth.
func (f *ModbusStreamFactory) FlushOldSessions(maxAge time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for key, state := range f.sessions {
		if state.lastSeen.Before(cutoff) {
			delete(f.sessions, key)
		}
	}
}

// ModbusStream consumes reassembled TCP bytes for a single flow.
type ModbusStream struct {
	factory *ModbusStreamFactory
	key     tlsFlowKey
	state   *modbusSessionState
}

// Reassembled appends new bytes and processes any complete frames.
func (s *ModbusStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	for _, r := range reassembly {
		s.state.buffer = append(s.state.buffer, r.Bytes...)
		s.state.lastSeen = time.Now()
	}
	// Cap buffer growth — Modbus frames are tiny and we only need to see
	// one valid frame to confirm and emit. Extreme cap protects against
	// pathological malformed streams.
	if len(s.state.buffer) > 4096 {
		s.state.buffer = s.state.buffer[:4096]
	}
	s.processBuffer()
}

// ReassemblyComplete is called when the TCP stream closes. Cleans up state.
func (s *ModbusStream) ReassemblyComplete() {
	s.processBuffer()
	s.factory.mu.Lock()
	delete(s.factory.sessions, s.key)
	s.factory.mu.Unlock()
}

// processBuffer consumes complete MBAP frames from the buffer. Stops at the
// first valid frame that triggers a discovery emission to keep work bounded;
// subsequent frames in the same session just refresh lastSeen via Reassembled.
func (s *ModbusStream) processBuffer() {
	if s.state.emitted {
		// We've already classified this flow as Modbus — drain the buffer
		// to keep memory bounded; no need to reparse.
		s.state.buffer = nil
		return
	}

	buf := s.state.buffer
	for len(buf) >= modbusMBAPHeaderLen+1 { // header + at least the function-code byte
		// Protocol ID must be 0x0000 for Modbus/TCP. If it's not, this isn't
		// a Modbus stream — drop the whole buffer to avoid burning CPU on
		// non-Modbus traffic that happened to land on port 502.
		protoID := binary.BigEndian.Uint16(buf[2:4])
		if protoID != modbusTCPProtocolID {
			s.state.buffer = nil
			return
		}

		length := int(binary.BigEndian.Uint16(buf[4:6]))
		// Length covers UnitID + PDU. Sanity-check before waiting for more
		// bytes — a frame longer than the spec maximum is malformed.
		if length < 2 || length > modbusMaxFrameLen-modbusMBAPHeaderLen {
			s.state.buffer = nil
			return
		}
		totalLen := modbusMBAPHeaderLen + length
		if len(buf) < totalLen {
			break // wait for more bytes
		}

		txID := binary.BigEndian.Uint16(buf[0:2])
		unitID := buf[6]
		funcCode := buf[7]

		s.emitDiscovery(txID, unitID, funcCode)
		buf = buf[totalLen:]
		break // one emission per session is enough
	}
	s.state.buffer = buf
}

// emitDiscovery reports the Modbus session. Dedup is via ConnectionCache so
// repeated Modbus sessions to the same server within the TTL window collapse
// to one discovery — same model the TLS / SSH / SMB paths use.
func (s *ModbusStream) emitDiscovery(txID uint16, unitID, funcCode uint8) {
	if s.factory.cache != nil && s.state.serverIP != "" {
		shouldReport, _ := s.factory.cache.ShouldReport(s.state.serverIP, s.state.serverPort, "Modbus")
		if !shouldReport {
			s.state.emitted = true
			return
		}
	}

	metadata := map[string]interface{}{
		"session_id":     s.state.sessionID,
		"reassembled":    true,
		"transaction_id": int(txID),
		"unit_id":        int(unitID),
		"function_code":  int(funcCode),
		"function_name":  modbusFunctionName(funcCode),
		"modbus_variant": "ModbusTCP",
		// Absence of crypto is itself the finding — surface it explicitly so
		// the compliance engine and UI can render it without inferring from
		// CipherSuite=="".
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
		Protocol:        "Modbus",
		Version:         "ModbusTCP",
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
		log.Printf("Warning: Modbus discovery channel full, dropping session %s", s.state.sessionID)
	}
}

// Compile-time interface checks
var _ tcpassembly.Stream = (*ModbusStream)(nil)
var _ tcpassembly.StreamFactory = (*ModbusStreamFactory)(nil)
