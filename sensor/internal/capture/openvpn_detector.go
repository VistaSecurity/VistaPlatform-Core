package capture

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// OpenVPN opcodes (high 5 bits of first byte)
const (
	openvpnHardResetClientV1 = 1
	openvpnControlV1         = 4
	openvpnAckV1             = 5
	openvpnHardResetServerV1 = 2
	openvpnHardResetClientV2 = 7
	openvpnHardResetServerV2 = 8
	openvpnHardResetClientV3 = 10
)

// parseOpenVPNPacket detects OpenVPN protocol traffic by fingerprinting the
// opcode/key_id byte and session_id structure.
//
// OpenVPN packet format:
//
//	Byte 0: opcode (bits 7-3) + key_id (bits 2-0)
//	Bytes 1-8: session_id (8 bytes)
//	Then: HMAC / packet_id / ack array / payload (variable)
//
// Minimum packet size is 9 bytes (opcode + session_id).
func parseOpenVPNPacket(data []byte, srcIP, dstIP string, srcPort, dstPort int, sensorID, iface string) *models.CryptoDiscovery {
	if len(data) < 9 {
		return nil
	}

	opcode := data[0] >> 3
	keyID := data[0] & 0x07

	// Validate opcode is a known OpenVPN type
	var msgName string
	switch opcode {
	case openvpnHardResetClientV1:
		msgName = "P_CONTROL_HARD_RESET_CLIENT_V1"
	case openvpnHardResetServerV1:
		msgName = "P_CONTROL_HARD_RESET_SERVER_V1"
	case openvpnControlV1:
		msgName = "P_CONTROL_V1"
	case openvpnAckV1:
		msgName = "P_ACK_V1"
	case openvpnHardResetClientV2:
		msgName = "P_CONTROL_HARD_RESET_CLIENT_V2"
	case openvpnHardResetServerV2:
		msgName = "P_CONTROL_HARD_RESET_SERVER_V2"
	case openvpnHardResetClientV3:
		msgName = "P_CONTROL_HARD_RESET_CLIENT_V3"
	default:
		return nil
	}

	// Session ID must not be all zeros (indicates invalid/random)
	sessionID := data[1:9]
	allZero := true
	for _, b := range sessionID {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil
	}

	// Hard reset messages are the strongest signal
	confidence := 0.65
	if opcode == openvpnHardResetClientV2 || opcode == openvpnHardResetServerV2 ||
		opcode == openvpnHardResetClientV1 || opcode == openvpnHardResetServerV1 ||
		opcode == openvpnHardResetClientV3 {
		confidence = 0.80
	}

	metadata := map[string]interface{}{
		"openvpn_opcode":     fmt.Sprintf("%d", opcode),
		"openvpn_message":    msgName,
		"openvpn_key_id":     keyID,
		"openvpn_session_id": hex.EncodeToString(sessionID),
		"interface":          iface,
	}

	return &models.CryptoDiscovery{
		ID:              uuid.New().String(),
		SensorID:        sensorID,
		Timestamp:       time.Now(),
		SourceIP:        srcIP,
		DestIP:          dstIP,
		Port:            dstPort,
		Protocol:        "VPN",
		Version:         "OpenVPN",
		DiscoveryMethod: "passive",
		Confidence:      confidence,
		RawMetadata:     metadata,
		CreatedAt:       time.Now(),
	}
}
