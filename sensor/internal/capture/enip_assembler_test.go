package capture

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/gopacket/gopacket/tcpassembly"
	"github.com/vistasecurity/vistaplatform/sensor/internal/cache"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// =============================================================================
// Encapsulation header parser
// =============================================================================

func TestENIPCommandName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		cmd  uint16
		want string
	}{
		{enipCmdNOP, "NOP"},
		{enipCmdRegisterSession, "RegisterSession"},
		{enipCmdSendRRData, "SendRRData"},
		{enipCmdSendUnitData, "SendUnitData"},
		{enipCmdListIdentityCmd, "ListIdentity"},
		{0xFFFF, ""},
		{0x0001, ""},
	}
	for _, c := range cases {
		if got := enipCommandName(c.cmd); got != c.want {
			t.Errorf("enipCommandName(%#x)=%q, want %q", c.cmd, got, c.want)
		}
	}
}

// buildENIPHeader constructs a synthetic 24-byte EtherNet/IP encapsulation
// header followed by `payloadLen` zero bytes. All integer fields are
// little-endian as required by the spec.
func buildENIPHeader(cmd uint16, payloadLen int, sessionHandle, status uint32) []byte {
	buf := make([]byte, enipHeaderLen+payloadLen)
	binary.LittleEndian.PutUint16(buf[0:2], cmd)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(payloadLen))
	binary.LittleEndian.PutUint32(buf[4:8], sessionHandle)
	binary.LittleEndian.PutUint32(buf[8:12], status)
	// SenderContext[8] and Options[4] left as zeros.
	return buf
}

func TestParseENIPHeader_ValidRegisterSession(t *testing.T) {
	t.Parallel()
	buf := buildENIPHeader(enipCmdRegisterSession, 4, 0xDEADBEEF, 0)
	cmd, payloadLen, sessionHandle, status, ok := parseENIPHeader(buf)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if cmd != enipCmdRegisterSession {
		t.Errorf("cmd=%#x, want RegisterSession", cmd)
	}
	if payloadLen != 4 {
		t.Errorf("payloadLen=%d, want 4", payloadLen)
	}
	if sessionHandle != 0xDEADBEEF {
		t.Errorf("sessionHandle=%#x, want 0xDEADBEEF", sessionHandle)
	}
	if status != 0 {
		t.Errorf("status=%d, want 0", status)
	}
}

func TestParseENIPHeader_RejectsUnknownCommand(t *testing.T) {
	t.Parallel()
	buf := buildENIPHeader(0xFFFF, 0, 0, 0)
	if _, _, _, _, ok := parseENIPHeader(buf); ok {
		t.Errorf("expected ok=false for unknown command 0xFFFF")
	}
}

func TestParseENIPHeader_RejectsShortBuffer(t *testing.T) {
	t.Parallel()
	if _, _, _, _, ok := parseENIPHeader(nil); ok {
		t.Errorf("expected ok=false for nil buffer")
	}
	if _, _, _, _, ok := parseENIPHeader(make([]byte, 23)); ok {
		t.Errorf("expected ok=false for 23-byte buffer (need 24)")
	}
}

// =============================================================================
// Assembler end-to-end
// =============================================================================

func newTestENIPFactory(t *testing.T) (*ENIPStreamFactory, chan *models.CryptoDiscovery) {
	t.Helper()
	ch := make(chan *models.CryptoDiscovery, 4)
	connCache := cache.NewConnectionCache(60*time.Minute, 1000)
	return NewENIPStreamFactory(ch, "test-sensor", connCache), ch
}

func preENIPStream(f *ENIPStreamFactory) (*ENIPStream, *enipSessionState) {
	state := &enipSessionState{
		sessionID:  "s1",
		serverIP:   "10.0.0.5",
		serverPort: enipPort,
		clientIP:   "10.0.0.10",
		iface:      "eth0",
	}
	f.mu.Lock()
	f.sessions[tlsFlowKey{}] = state
	f.mu.Unlock()
	return &ENIPStream{factory: f, key: tlsFlowKey{}, state: state}, state
}

func feedENIP(s tcpassembly.Stream, data []byte) {
	s.Reassembled([]tcpassembly.Reassembly{{Bytes: data, Seen: time.Now()}})
}

func TestENIPAssembler_RegisterSessionEmitsDiscovery(t *testing.T) {
	t.Parallel()
	factory, ch := newTestENIPFactory(t)
	stream, _ := preENIPStream(factory)

	// RegisterSession typically carries a 4-byte payload (ProtocolVersion +
	// OptionFlags); zero payload also fires in practice.
	feedENIP(stream, buildENIPHeader(enipCmdRegisterSession, 4, 0x12345678, 0))

	select {
	case d := <-ch:
		if d.Protocol != "EtherNet_IP" {
			t.Errorf("Protocol=%s, want EtherNet_IP", d.Protocol)
		}
		if d.Version != "CIP" {
			t.Errorf("Version=%s, want CIP", d.Version)
		}
		if d.RawMetadata["security"] != "none" {
			t.Errorf("security=%v, want none", d.RawMetadata["security"])
		}
		if d.RawMetadata["enip_command_name"] != "RegisterSession" {
			t.Errorf("enip_command_name=%v, want RegisterSession", d.RawMetadata["enip_command_name"])
		}
		if d.RawMetadata["session_handle"] != 0x12345678 {
			t.Errorf("session_handle=%v, want 0x12345678", d.RawMetadata["session_handle"])
		}
		if d.Port != enipPort {
			t.Errorf("Port=%d, want %d", d.Port, enipPort)
		}
	case <-time.After(time.Second):
		t.Fatal("expected EtherNet/IP discovery within 1s")
	}
}

func TestENIPAssembler_SendRRDataEmitsDiscovery(t *testing.T) {
	t.Parallel()
	factory, ch := newTestENIPFactory(t)
	stream, _ := preENIPStream(factory)

	feedENIP(stream, buildENIPHeader(enipCmdSendRRData, 16, 0xAABBCCDD, 0))

	select {
	case d := <-ch:
		if d.RawMetadata["enip_command_name"] != "SendRRData" {
			t.Errorf("enip_command_name=%v, want SendRRData", d.RawMetadata["enip_command_name"])
		}
	case <-time.After(time.Second):
		t.Fatal("expected SendRRData discovery")
	}
}

func TestENIPAssembler_NonENIPBytesDropBuffer(t *testing.T) {
	t.Parallel()
	factory, ch := newTestENIPFactory(t)
	stream, state := preENIPStream(factory)

	// HTTP-like bytes — not an EtherNet/IP encapsulation header. The
	// assembler should drop the buffer and never emit anything.
	junk := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	feedENIP(stream, junk)

	select {
	case d := <-ch:
		t.Errorf("expected no discovery on HTTP bytes, got %+v", d)
	case <-time.After(50 * time.Millisecond):
	}
	if state.buffer != nil {
		t.Errorf("expected buffer to be dropped, got %d bytes", len(state.buffer))
	}
}

func TestENIPAssembler_PartialHeaderBuffersUntilComplete(t *testing.T) {
	t.Parallel()
	factory, ch := newTestENIPFactory(t)
	stream, _ := preENIPStream(factory)

	header := buildENIPHeader(enipCmdRegisterSession, 0, 1, 0)
	feedENIP(stream, header[:10])
	select {
	case d := <-ch:
		t.Fatalf("did not expect discovery on partial header, got %+v", d)
	case <-time.After(20 * time.Millisecond):
	}
	feedENIP(stream, header[10:])
	select {
	case d := <-ch:
		if d.Protocol != "EtherNet_IP" {
			t.Errorf("Protocol=%s, want EtherNet_IP", d.Protocol)
		}
	case <-time.After(time.Second):
		t.Fatal("expected EtherNet/IP discovery once header completed")
	}
}

func TestENIPAssembler_OneEmitPerSession(t *testing.T) {
	t.Parallel()
	factory, ch := newTestENIPFactory(t)
	stream, _ := preENIPStream(factory)

	// Two consecutive frames in the same flow should produce only one
	// discovery — the second is dedup'd via the per-session emitted flag.
	feedENIP(stream, buildENIPHeader(enipCmdRegisterSession, 0, 1, 0))
	<-ch
	feedENIP(stream, buildENIPHeader(enipCmdSendUnitData, 0, 1, 0))
	select {
	case d := <-ch:
		t.Errorf("expected dedup, got second discovery %+v", d)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestENIPAssembler_FlushOldSessions(t *testing.T) {
	t.Parallel()
	factory, _ := newTestENIPFactory(t)
	old := &enipSessionState{lastSeen: time.Now().Add(-2 * time.Hour)}
	factory.mu.Lock()
	factory.sessions[tlsFlowKey{}] = old
	factory.mu.Unlock()
	factory.FlushOldSessions(time.Hour)
	factory.mu.Lock()
	if _, exists := factory.sessions[tlsFlowKey{}]; exists {
		t.Errorf("expected old session to be flushed")
	}
	factory.mu.Unlock()
}
