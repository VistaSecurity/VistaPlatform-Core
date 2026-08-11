package capture

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/gopacket/gopacket/tcpassembly"
	"github.com/vistasecurity/vistaplatform/sensor/internal/cache"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

func TestModbusFunctionName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		code uint8
		want string
	}{
		{1, "ReadCoils"},
		{2, "ReadDiscreteInputs"},
		{3, "ReadHoldingRegisters"},
		{4, "ReadInputRegisters"},
		{5, "WriteSingleCoil"},
		{6, "WriteSingleRegister"},
		{15, "WriteMultipleCoils"},
		{16, "WriteMultipleRegisters"},
		{23, "ReadWriteMultipleRegisters"},
		{43, "EncapsulatedInterfaceTransport"},
		{99, "Unknown"},
		// Exception responses: original code | 0x80
		{0x83, "ReadHoldingRegisters (Exception)"}, // 0x03 | 0x80
		{0x90, "WriteMultipleRegisters (Exception)"},
	}
	for _, c := range cases {
		if got := modbusFunctionName(c.code); got != c.want {
			t.Errorf("modbusFunctionName(0x%02X)=%q, want %q", c.code, got, c.want)
		}
	}
}

// buildModbusFrame constructs a valid Modbus/TCP request frame for the given
// function code with `dataBytes` of trailing data.
func buildModbusFrame(txID uint16, unitID, funcCode uint8, dataBytes int) []byte {
	pduLen := 1 + dataBytes                             // function code + data
	frame := make([]byte, modbusMBAPHeaderLen+1+pduLen) // header + unitID + PDU
	binary.BigEndian.PutUint16(frame[0:2], txID)
	binary.BigEndian.PutUint16(frame[2:4], modbusTCPProtocolID)
	binary.BigEndian.PutUint16(frame[4:6], uint16(1+pduLen)) // unitID + PDU
	frame[6] = unitID
	frame[7] = funcCode
	// Remaining bytes left zero — content doesn't matter for detection.
	return frame
}

// newTestModbusFactory creates a factory wired to a buffered discoveries
// channel and a fresh ConnectionCache (60s TTL).
func newTestModbusFactory(t *testing.T) (*ModbusStreamFactory, chan *models.CryptoDiscovery) {
	t.Helper()
	ch := make(chan *models.CryptoDiscovery, 4)
	connCache := cache.NewConnectionCache(60*time.Minute, 1000)
	return NewModbusStreamFactory(ch, "test-sensor", connCache), ch
}

// feedReassembly simulates the assembler delivering a single contiguous chunk.
func feedReassembly(s tcpassembly.Stream, data []byte) {
	s.Reassembled([]tcpassembly.Reassembly{{Bytes: data, Seen: time.Now()}})
}

func TestModbusAssembler_ValidReadHoldingRegistersRequest(t *testing.T) {
	t.Parallel()
	factory, ch := newTestModbusFactory(t)

	// directly construct state — bypasses the gopacket Flow construction in
	// New() since the parser doesn't actually use those fields.
	state := &modbusSessionState{
		sessionID:  "s1",
		serverIP:   "10.0.0.5",
		serverPort: 502,
		clientIP:   "10.0.0.10",
		iface:      "eth0",
	}
	factory.mu.Lock()
	factory.sessions[tlsFlowKey{}] = state
	factory.mu.Unlock()
	stream := &ModbusStream{factory: factory, key: tlsFlowKey{}, state: state}

	// Read Holding Registers (function 3) — request data is 4 bytes
	// (start address + quantity)
	frame := buildModbusFrame(0x1234, 1, 3, 4)
	feedReassembly(stream, frame)

	select {
	case d := <-ch:
		if d.Protocol != "Modbus" {
			t.Errorf("Protocol=%s, want Modbus", d.Protocol)
		}
		if d.Version != "ModbusTCP" {
			t.Errorf("Version=%s, want ModbusTCP", d.Version)
		}
		if d.CipherSuite != "" {
			t.Errorf("CipherSuite=%q, want empty (Modbus has no crypto)", d.CipherSuite)
		}
		if d.DestIP != "10.0.0.5" || d.Port != 502 {
			t.Errorf("DestIP=%s Port=%d, want 10.0.0.5:502", d.DestIP, d.Port)
		}
		if d.RawMetadata["function_code"] != 3 {
			t.Errorf("function_code=%v, want 3", d.RawMetadata["function_code"])
		}
		if d.RawMetadata["function_name"] != "ReadHoldingRegisters" {
			t.Errorf("function_name=%v, want ReadHoldingRegisters", d.RawMetadata["function_name"])
		}
		if d.RawMetadata["transaction_id"] != int(0x1234) {
			t.Errorf("transaction_id=%v, want 4660", d.RawMetadata["transaction_id"])
		}
		if d.RawMetadata["unit_id"] != 1 {
			t.Errorf("unit_id=%v, want 1", d.RawMetadata["unit_id"])
		}
		if d.RawMetadata["security"] != "none" {
			t.Errorf("security=%v, want none", d.RawMetadata["security"])
		}
	case <-time.After(time.Second):
		t.Fatal("expected discovery within 1s")
	}
}

func TestModbusAssembler_RejectsInvalidProtocolID(t *testing.T) {
	t.Parallel()
	factory, ch := newTestModbusFactory(t)

	state := &modbusSessionState{serverIP: "10.0.0.5", serverPort: 502, clientIP: "10.0.0.10"}
	factory.mu.Lock()
	factory.sessions[tlsFlowKey{}] = state
	factory.mu.Unlock()
	stream := &ModbusStream{factory: factory, key: tlsFlowKey{}, state: state}

	// Build a frame with the wrong Protocol ID — should be rejected.
	frame := buildModbusFrame(1, 1, 3, 4)
	binary.BigEndian.PutUint16(frame[2:4], 0x1234) // not 0x0000

	feedReassembly(stream, frame)

	select {
	case d := <-ch:
		t.Errorf("expected no discovery for invalid Protocol ID, got %+v", d)
	case <-time.After(50 * time.Millisecond):
		// expected — no discovery
	}
}

func TestModbusAssembler_BufferUntilCompleteFrame(t *testing.T) {
	t.Parallel()
	factory, ch := newTestModbusFactory(t)

	state := &modbusSessionState{serverIP: "10.0.0.5", serverPort: 502, clientIP: "10.0.0.10"}
	factory.mu.Lock()
	factory.sessions[tlsFlowKey{}] = state
	factory.mu.Unlock()
	stream := &ModbusStream{factory: factory, key: tlsFlowKey{}, state: state}

	frame := buildModbusFrame(0x55AA, 2, 16, 8)

	// Deliver in two chunks — split mid-header.
	feedReassembly(stream, frame[:3])
	select {
	case d := <-ch:
		t.Fatalf("did not expect discovery before full frame, got %+v", d)
	case <-time.After(20 * time.Millisecond):
	}
	feedReassembly(stream, frame[3:])

	select {
	case d := <-ch:
		if d.RawMetadata["function_name"] != "WriteMultipleRegisters" {
			t.Errorf("function_name=%v, want WriteMultipleRegisters", d.RawMetadata["function_name"])
		}
	case <-time.After(time.Second):
		t.Fatal("expected discovery once frame completed")
	}
}

func TestModbusAssembler_OneEmissionPerSession(t *testing.T) {
	t.Parallel()
	factory, ch := newTestModbusFactory(t)

	state := &modbusSessionState{serverIP: "10.0.0.5", serverPort: 502, clientIP: "10.0.0.10"}
	factory.mu.Lock()
	factory.sessions[tlsFlowKey{}] = state
	factory.mu.Unlock()
	stream := &ModbusStream{factory: factory, key: tlsFlowKey{}, state: state}

	// Three back-to-back valid frames in one delivery — only the first
	// should produce a discovery.
	concat := make([]byte, 0)
	concat = append(concat, buildModbusFrame(1, 1, 3, 4)...)
	concat = append(concat, buildModbusFrame(2, 1, 3, 4)...)
	concat = append(concat, buildModbusFrame(3, 1, 3, 4)...)
	feedReassembly(stream, concat)

	count := 0
loop:
	for {
		select {
		case <-ch:
			count++
		case <-time.After(50 * time.Millisecond):
			break loop
		}
	}
	if count != 1 {
		t.Errorf("expected 1 discovery per session, got %d", count)
	}
}

func TestModbusAssembler_DedupViaConnectionCache(t *testing.T) {
	t.Parallel()
	factory, ch := newTestModbusFactory(t)

	// First session — expect discovery
	state1 := &modbusSessionState{serverIP: "10.0.0.5", serverPort: 502, clientIP: "10.0.0.10"}
	factory.mu.Lock()
	factory.sessions[tlsFlowKey{}] = state1
	factory.mu.Unlock()
	(&ModbusStream{factory: factory, key: tlsFlowKey{}, state: state1}).
		Reassembled([]tcpassembly.Reassembly{{Bytes: buildModbusFrame(1, 1, 3, 4), Seen: time.Now()}})

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("expected first discovery")
	}

	// Second session, same server — must be deduped (cache hit).
	state2 := &modbusSessionState{serverIP: "10.0.0.5", serverPort: 502, clientIP: "10.0.0.11"}
	// Use a different key so the second session is genuinely new.
	key2 := tlsFlowKey{}
	// Force a different key by storing under a fresh session map entry —
	// safely shadowing the first one by deleting first.
	factory.mu.Lock()
	delete(factory.sessions, tlsFlowKey{})
	factory.sessions[key2] = state2
	factory.mu.Unlock()
	(&ModbusStream{factory: factory, key: key2, state: state2}).
		Reassembled([]tcpassembly.Reassembly{{Bytes: buildModbusFrame(2, 1, 3, 4), Seen: time.Now()}})

	select {
	case d := <-ch:
		t.Errorf("expected dedup to suppress second discovery, got %+v", d)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestModbusAssembler_FlushOldSessions(t *testing.T) {
	t.Parallel()
	factory, _ := newTestModbusFactory(t)

	old := &modbusSessionState{lastSeen: time.Now().Add(-2 * time.Hour)}
	fresh := &modbusSessionState{lastSeen: time.Now()}
	keyOld := tlsFlowKey{}
	keyFresh := tlsFlowKey{}
	// Distinguish keys by storing twice in succession — second store
	// overwrites, so use a manual layout instead.
	factory.mu.Lock()
	factory.sessions[keyOld] = old
	// hack: mutate keyFresh to differ — gopacket flows aren't constructable
	// here without real packets, so instead exercise behavior by adding the
	// fresh entry under a different map by rebuilding.
	factory.mu.Unlock()

	factory.FlushOldSessions(time.Hour)

	factory.mu.Lock()
	if _, exists := factory.sessions[keyOld]; exists {
		t.Error("expected old session to be flushed")
	}
	factory.sessions[keyFresh] = fresh
	factory.mu.Unlock()

	factory.FlushOldSessions(time.Hour)

	factory.mu.Lock()
	if _, exists := factory.sessions[keyFresh]; !exists {
		t.Error("expected fresh session to be retained")
	}
	factory.mu.Unlock()
}
