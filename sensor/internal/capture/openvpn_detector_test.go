package capture

import (
	"testing"
)

func TestParseOpenVPNPacket_HardResetV2(t *testing.T) {
	t.Parallel()
	// Byte 0: opcode=7 (P_CONTROL_HARD_RESET_CLIENT_V2), key_id=0 → 7<<3|0 = 0x38
	data := make([]byte, 32)
	data[0] = 0x38 // opcode 7, key_id 0
	// Session ID (bytes 1-8): non-zero
	data[1] = 0xDE
	data[2] = 0xAD
	data[3] = 0xBE
	data[4] = 0xEF
	data[5] = 0xCA
	data[6] = 0xFE
	data[7] = 0xBA
	data[8] = 0xBE

	d := parseOpenVPNPacket(data, "10.0.0.1", "10.0.0.2", 12345, 1194, "sensor-1", "eth0")
	if d == nil {
		t.Fatal("expected discovery, got nil")
	}
	if d.Protocol != "VPN" {
		t.Errorf("expected Protocol=VPN, got %s", d.Protocol)
	}
	if d.Version != "OpenVPN" {
		t.Errorf("expected Version=OpenVPN, got %s", d.Version)
	}
	if d.Confidence != 0.80 {
		t.Errorf("expected Confidence=0.80, got %f", d.Confidence)
	}
	if d.RawMetadata["openvpn_message"] != "P_CONTROL_HARD_RESET_CLIENT_V2" {
		t.Errorf("unexpected message: %v", d.RawMetadata["openvpn_message"])
	}
	if d.RawMetadata["openvpn_session_id"] != "deadbeefcafebabe" {
		t.Errorf("unexpected session ID: %v", d.RawMetadata["openvpn_session_id"])
	}
}

func TestParseOpenVPNPacket_ControlV1(t *testing.T) {
	t.Parallel()
	// opcode=4 (P_CONTROL_V1), key_id=1 → 4<<3|1 = 0x21
	data := make([]byte, 32)
	data[0] = 0x21
	data[1] = 0x01 // non-zero session ID

	d := parseOpenVPNPacket(data, "10.0.0.1", "10.0.0.2", 12345, 1194, "sensor-1", "eth0")
	if d == nil {
		t.Fatal("expected discovery, got nil")
	}
	if d.Confidence != 0.65 {
		t.Errorf("expected Confidence=0.65 for control packet, got %f", d.Confidence)
	}
}

func TestParseOpenVPNPacket_TooShort(t *testing.T) {
	t.Parallel()
	data := make([]byte, 5) // less than 9
	d := parseOpenVPNPacket(data, "10.0.0.1", "10.0.0.2", 12345, 1194, "sensor-1", "eth0")
	if d != nil {
		t.Error("expected nil for too-short packet")
	}
}

func TestParseOpenVPNPacket_ZeroSessionID(t *testing.T) {
	t.Parallel()
	data := make([]byte, 32)
	data[0] = 0x38 // valid opcode
	// session ID is all zeros
	d := parseOpenVPNPacket(data, "10.0.0.1", "10.0.0.2", 12345, 1194, "sensor-1", "eth0")
	if d != nil {
		t.Error("expected nil for all-zero session ID")
	}
}

func TestParseOpenVPNPacket_InvalidOpcode(t *testing.T) {
	t.Parallel()
	data := make([]byte, 32)
	data[0] = 15 << 3 // opcode 15, not a valid OpenVPN opcode
	data[1] = 0x01
	d := parseOpenVPNPacket(data, "10.0.0.1", "10.0.0.2", 12345, 1194, "sensor-1", "eth0")
	if d != nil {
		t.Error("expected nil for invalid opcode")
	}
}
