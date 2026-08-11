package capture

import (
	"encoding/binary"
	"testing"
)

func TestParseWireGuardPacket_HandshakeInitiation(t *testing.T) {
	t.Parallel()
	// Type 1 (Handshake Initiation) — exactly 148 bytes
	data := make([]byte, 148)
	data[0] = wgTypeHandshakeInitiation
	data[1], data[2], data[3] = 0, 0, 0
	binary.LittleEndian.PutUint32(data[4:8], 42) // sender index

	d := parseWireGuardPacket(data, "10.0.0.1", "10.0.0.2", 12345, 51820, "sensor-1", "eth0")
	if d == nil {
		t.Fatal("expected discovery, got nil")
	}
	if d.Protocol != "VPN" {
		t.Errorf("expected Protocol=VPN, got %s", d.Protocol)
	}
	if d.Version != "WireGuard" {
		t.Errorf("expected Version=WireGuard, got %s", d.Version)
	}
	if d.Confidence != 0.85 {
		t.Errorf("expected Confidence=0.85, got %f", d.Confidence)
	}
	if d.CipherSuite != "Curve25519_ChaCha20-Poly1305_BLAKE2s" {
		t.Errorf("unexpected CipherSuite: %s", d.CipherSuite)
	}
	if d.RawMetadata["wireguard_message_type"] != "Handshake Initiation" {
		t.Errorf("unexpected message type: %v", d.RawMetadata["wireguard_message_type"])
	}
	if d.RawMetadata["wireguard_sender_index"] != uint32(42) {
		t.Errorf("unexpected sender index: %v", d.RawMetadata["wireguard_sender_index"])
	}
}

func TestParseWireGuardPacket_HandshakeResponse(t *testing.T) {
	t.Parallel()
	data := make([]byte, 92)
	data[0] = wgTypeHandshakeResponse
	binary.LittleEndian.PutUint32(data[4:8], 99)  // sender index
	binary.LittleEndian.PutUint32(data[8:12], 42) // receiver index

	d := parseWireGuardPacket(data, "10.0.0.2", "10.0.0.1", 51820, 12345, "sensor-1", "eth0")
	if d == nil {
		t.Fatal("expected discovery, got nil")
	}
	if d.RawMetadata["wireguard_message_type"] != "Handshake Response" {
		t.Errorf("unexpected message type: %v", d.RawMetadata["wireguard_message_type"])
	}
	if d.RawMetadata["wireguard_receiver_index"] != uint32(42) {
		t.Errorf("unexpected receiver index: %v", d.RawMetadata["wireguard_receiver_index"])
	}
}

func TestParseWireGuardPacket_CookieReply(t *testing.T) {
	t.Parallel()
	data := make([]byte, 64)
	data[0] = wgTypeCookieReply

	d := parseWireGuardPacket(data, "10.0.0.1", "10.0.0.2", 51820, 51820, "sensor-1", "eth0")
	if d == nil {
		t.Fatal("expected discovery, got nil")
	}
	if d.Confidence != 0.75 {
		t.Errorf("expected Confidence=0.75, got %f", d.Confidence)
	}
}

func TestParseWireGuardPacket_TransportData(t *testing.T) {
	t.Parallel()
	data := make([]byte, 64)
	data[0] = wgTypeTransportData

	d := parseWireGuardPacket(data, "10.0.0.1", "10.0.0.2", 51820, 51820, "sensor-1", "eth0")
	if d == nil {
		t.Fatal("expected discovery, got nil")
	}
	if d.Confidence != 0.60 {
		t.Errorf("expected Confidence=0.60, got %f", d.Confidence)
	}
}

func TestParseWireGuardPacket_TooShort(t *testing.T) {
	t.Parallel()
	data := []byte{0x01, 0x00, 0x00}
	d := parseWireGuardPacket(data, "10.0.0.1", "10.0.0.2", 51820, 51820, "sensor-1", "eth0")
	if d != nil {
		t.Error("expected nil for too-short packet")
	}
}

func TestParseWireGuardPacket_NonZeroReserved(t *testing.T) {
	t.Parallel()
	data := make([]byte, 148)
	data[0] = wgTypeHandshakeInitiation
	data[1] = 0xFF // non-zero reserved byte

	d := parseWireGuardPacket(data, "10.0.0.1", "10.0.0.2", 51820, 51820, "sensor-1", "eth0")
	if d != nil {
		t.Error("expected nil for non-zero reserved bytes")
	}
}

func TestParseWireGuardPacket_WrongSizeInitiation(t *testing.T) {
	t.Parallel()
	// Handshake Initiation must be exactly 148 bytes — 100 should be rejected
	data := make([]byte, 100)
	data[0] = wgTypeHandshakeInitiation

	d := parseWireGuardPacket(data, "10.0.0.1", "10.0.0.2", 51820, 51820, "sensor-1", "eth0")
	if d != nil {
		t.Error("expected nil for wrong-size initiation")
	}
}

func TestParseWireGuardPacket_UnknownType(t *testing.T) {
	t.Parallel()
	data := make([]byte, 148)
	data[0] = 99 // unknown type

	d := parseWireGuardPacket(data, "10.0.0.1", "10.0.0.2", 51820, 51820, "sensor-1", "eth0")
	if d != nil {
		t.Error("expected nil for unknown message type")
	}
}

func TestParseWireGuardPacket_TransportDataTooShort(t *testing.T) {
	t.Parallel()
	data := make([]byte, 20) // below wgTransportDataMinSize (32)
	data[0] = wgTypeTransportData

	d := parseWireGuardPacket(data, "10.0.0.1", "10.0.0.2", 51820, 51820, "sensor-1", "eth0")
	if d != nil {
		t.Error("expected nil for too-short transport data")
	}
}
