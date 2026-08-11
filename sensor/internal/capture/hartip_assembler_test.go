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
// Header parsing
// =============================================================================

func TestHARTIPMessageTypeName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		t    uint8
		want string
	}{
		{hartIPMsgRequest, "Request"},
		{hartIPMsgResponse, "Response"},
		{hartIPMsgPublishNotify, "PublishNotify"},
		{hartIPMsgPublishRequest, "PublishRequest"},
		{hartIPMsgNAK, "NAK"},
		{0x05, ""},
		{0xFF, ""},
	}
	for _, c := range cases {
		if got := hartIPMessageTypeName(c.t); got != c.want {
			t.Errorf("hartIPMessageTypeName(%#x)=%q, want %q", c.t, got, c.want)
		}
	}
}

// buildHARTIPMessage constructs a synthetic HART-IP message. payloadLen
// is the number of payload bytes after the 8-byte header.
func buildHARTIPMessage(msgType, msgID, status uint8, seqNum uint16, payloadLen int) []byte {
	buf := make([]byte, hartIPHeaderLen+payloadLen)
	buf[0] = hartIPVersion
	buf[1] = msgType
	buf[2] = msgID
	buf[3] = status
	binary.BigEndian.PutUint16(buf[4:6], seqNum)
	binary.BigEndian.PutUint16(buf[6:8], uint16(payloadLen))
	return buf
}

func TestParseHARTIPHeader_ValidRequest(t *testing.T) {
	t.Parallel()
	buf := buildHARTIPMessage(hartIPMsgRequest, 0x01, 0, 42, 16)
	hdr, ok := parseHARTIPHeader(buf)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if hdr.messageType != hartIPMsgRequest {
		t.Errorf("messageType=%#x, want Request", hdr.messageType)
	}
	if hdr.sequenceNum != 42 {
		t.Errorf("sequenceNum=%d, want 42", hdr.sequenceNum)
	}
	if hdr.byteCount != 16 {
		t.Errorf("byteCount=%d, want 16", hdr.byteCount)
	}
}

func TestParseHARTIPHeader_RejectsWrongVersion(t *testing.T) {
	t.Parallel()
	buf := buildHARTIPMessage(hartIPMsgRequest, 0, 0, 0, 0)
	buf[0] = 0x02 // not version 1
	if _, ok := parseHARTIPHeader(buf); ok {
		t.Errorf("expected ok=false for version 2")
	}
}

func TestParseHARTIPHeader_RejectsUnknownMessageType(t *testing.T) {
	t.Parallel()
	buf := buildHARTIPMessage(0x05, 0, 0, 0, 0)
	if _, ok := parseHARTIPHeader(buf); ok {
		t.Errorf("expected ok=false for message type 0x05")
	}
}

func TestParseHARTIPHeader_RejectsShortBuffer(t *testing.T) {
	t.Parallel()
	if _, ok := parseHARTIPHeader(nil); ok {
		t.Errorf("expected ok=false for nil buffer")
	}
	if _, ok := parseHARTIPHeader(make([]byte, 7)); ok {
		t.Errorf("expected ok=false for 7-byte buffer (need 8)")
	}
}

// =============================================================================
// TCP path
// =============================================================================

func newTestHARTIPFactory(t *testing.T) (*HARTIPStreamFactory, chan *models.CryptoDiscovery) {
	t.Helper()
	ch := make(chan *models.CryptoDiscovery, 4)
	connCache := cache.NewConnectionCache(60*time.Minute, 1000)
	return NewHARTIPStreamFactory(ch, "test-sensor", connCache), ch
}

func preHARTIPStream(f *HARTIPStreamFactory) (*HARTIPStream, *hartIPSessionState) {
	state := &hartIPSessionState{
		sessionID:  "s1",
		serverIP:   "10.0.0.5",
		serverPort: hartIPPort,
		clientIP:   "10.0.0.10",
		iface:      "eth0",
	}
	f.mu.Lock()
	f.sessions[tlsFlowKey{}] = state
	f.mu.Unlock()
	return &HARTIPStream{factory: f, key: tlsFlowKey{}, state: state}, state
}

func feedHARTIP(s tcpassembly.Stream, data []byte) {
	s.Reassembled([]tcpassembly.Reassembly{{Bytes: data, Seen: time.Now()}})
}

func TestHARTIPAssembler_RequestEmitsDiscovery(t *testing.T) {
	t.Parallel()
	factory, ch := newTestHARTIPFactory(t)
	stream, _ := preHARTIPStream(factory)

	feedHARTIP(stream, buildHARTIPMessage(hartIPMsgRequest, 0x03, 0, 100, 4))

	select {
	case d := <-ch:
		if d.Protocol != "HART_IP" {
			t.Errorf("Protocol=%s, want HART_IP", d.Protocol)
		}
		if d.RawMetadata["security"] != "none" {
			t.Errorf("security=%v, want none", d.RawMetadata["security"])
		}
		if d.RawMetadata["hartip_message_type_name"] != "Request" {
			t.Errorf("hartip_message_type_name=%v, want Request", d.RawMetadata["hartip_message_type_name"])
		}
		if d.RawMetadata["transport"] != "tcp" {
			t.Errorf("transport=%v, want tcp", d.RawMetadata["transport"])
		}
		if d.RawMetadata["hartip_sequence_number"] != 100 {
			t.Errorf("hartip_sequence_number=%v, want 100", d.RawMetadata["hartip_sequence_number"])
		}
	case <-time.After(time.Second):
		t.Fatal("expected HART-IP TCP discovery within 1s")
	}
}

func TestHARTIPAssembler_NonHARTIPBytesDropBuffer(t *testing.T) {
	t.Parallel()
	factory, ch := newTestHARTIPFactory(t)
	stream, state := preHARTIPStream(factory)

	feedHARTIP(stream, []byte("GET / HTTP/1.1\r\nHost: ex\r\n\r\n"))

	select {
	case d := <-ch:
		t.Errorf("expected no discovery on HTTP bytes, got %+v", d)
	case <-time.After(50 * time.Millisecond):
	}
	if state.buffer != nil {
		t.Errorf("expected buffer dropped, got %d bytes", len(state.buffer))
	}
}

func TestHARTIPAssembler_PartialHeaderBuffersUntilComplete(t *testing.T) {
	t.Parallel()
	factory, ch := newTestHARTIPFactory(t)
	stream, _ := preHARTIPStream(factory)

	msg := buildHARTIPMessage(hartIPMsgRequest, 1, 0, 1, 0)
	feedHARTIP(stream, msg[:5])
	select {
	case <-ch:
		t.Fatal("expected no discovery before full header")
	case <-time.After(20 * time.Millisecond):
	}
	feedHARTIP(stream, msg[5:])
	select {
	case d := <-ch:
		if d.Protocol != "HART_IP" {
			t.Errorf("Protocol=%s, want HART_IP", d.Protocol)
		}
	case <-time.After(time.Second):
		t.Fatal("expected HART-IP discovery once header completed")
	}
}

// =============================================================================
// UDP path
// =============================================================================

func TestHARTIPUDP_PublishNotify(t *testing.T) {
	t.Parallel()
	msg := buildHARTIPMessage(hartIPMsgPublishNotify, 0x10, 0, 555, 8)

	got := parseHARTIPPacket(msg, "10.0.0.10", "10.0.0.5", 49152, hartIPPort, "sensor", "eth0", nil)
	if got == nil {
		t.Fatal("expected discovery")
	}
	if got.Protocol != "HART_IP" {
		t.Errorf("Protocol=%s, want HART_IP", got.Protocol)
	}
	if got.RawMetadata["transport"] != "udp" {
		t.Errorf("transport=%v, want udp", got.RawMetadata["transport"])
	}
	if got.RawMetadata["hartip_message_type_name"] != "PublishNotify" {
		t.Errorf("hartip_message_type_name=%v", got.RawMetadata["hartip_message_type_name"])
	}
	if got.Port != hartIPPort {
		t.Errorf("Port=%d, want %d", got.Port, hartIPPort)
	}
}

func TestHARTIPUDP_NonHARTIPReturnsNil(t *testing.T) {
	t.Parallel()
	if got := parseHARTIPPacket([]byte("GET /"), "10.0.0.10", "10.0.0.5", 49152, hartIPPort, "sensor", "eth0", nil); got != nil {
		t.Errorf("expected nil for non-HART-IP bytes, got %+v", got)
	}
	if got := parseHARTIPPacket(nil, "10.0.0.10", "10.0.0.5", 49152, hartIPPort, "sensor", "eth0", nil); got != nil {
		t.Errorf("expected nil for nil payload, got %+v", got)
	}
}

func TestHARTIPUDP_DedupRejectsRepeats(t *testing.T) {
	t.Parallel()
	connCache := cache.NewConnectionCache(60*time.Minute, 1000)
	msg := buildHARTIPMessage(hartIPMsgRequest, 1, 0, 1, 0)

	first := parseHARTIPPacket(msg, "10.0.0.10", "10.0.0.5", 49152, hartIPPort, "sensor", "eth0", connCache)
	if first == nil {
		t.Fatal("first datagram should emit a discovery")
	}
	second := parseHARTIPPacket(msg, "10.0.0.10", "10.0.0.5", 49152, hartIPPort, "sensor", "eth0", connCache)
	if second != nil {
		t.Errorf("second datagram should dedup to nil, got %+v", second)
	}
}

func TestHARTIPUDP_ServerSidePinningWhenSrcPortIs5094(t *testing.T) {
	t.Parallel()
	msg := buildHARTIPMessage(hartIPMsgResponse, 1, 0, 1, 0)

	got := parseHARTIPPacket(msg, "10.0.0.5", "10.0.0.10", hartIPPort, 49152, "sensor", "eth0", nil)
	if got == nil {
		t.Fatal("expected discovery")
	}
	if got.DestIP != "10.0.0.5" || got.Port != hartIPPort {
		t.Errorf("server pinning wrong: dest=%s port=%d, want 10.0.0.5/%d", got.DestIP, got.Port, hartIPPort)
	}
	if got.SourceIP != "10.0.0.10" {
		t.Errorf("client IP wrong: src=%s, want 10.0.0.10", got.SourceIP)
	}
}

// =============================================================================
// Misc
// =============================================================================

func TestHARTIPAssembler_FlushOldSessions(t *testing.T) {
	t.Parallel()
	factory, _ := newTestHARTIPFactory(t)
	old := &hartIPSessionState{lastSeen: time.Now().Add(-2 * time.Hour)}
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
