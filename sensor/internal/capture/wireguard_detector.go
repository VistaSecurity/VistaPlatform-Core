package capture

import (
	"encoding/binary"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// WireGuard message types
const (
	wgTypeHandshakeInitiation = 1
	wgTypeHandshakeResponse   = 2
	wgTypeCookieReply         = 3
	wgTypeTransportData       = 4

	// Expected sizes for handshake messages
	wgHandshakeInitiationSize = 148
	wgHandshakeResponseSize   = 92
	wgCookieReplySize         = 64
	wgTransportDataMinSize    = 32
)

// parseWireGuardPacket detects WireGuard protocol traffic by fingerprinting
// the fixed message format. WireGuard uses a fixed cryptographic suite
// (Curve25519 + ChaCha20-Poly1305 + BLAKE2s) with no negotiation, so
// detection = full crypto inventory.
//
// Message format: Type(1 byte LE) + Reserved(3 zero bytes) + type-specific fields.
func parseWireGuardPacket(data []byte, srcIP, dstIP string, srcPort, dstPort int, sensorID, iface string) *models.CryptoDiscovery {
	if len(data) < 4 {
		return nil
	}

	msgType := data[0]

	// Reserved bytes must be zero
	if data[1] != 0 || data[2] != 0 || data[3] != 0 {
		return nil
	}

	var msgName string
	var confidence float64

	switch msgType {
	case wgTypeHandshakeInitiation:
		if len(data) != wgHandshakeInitiationSize {
			return nil
		}
		msgName = "Handshake Initiation"
		confidence = 0.85
	case wgTypeHandshakeResponse:
		if len(data) != wgHandshakeResponseSize {
			return nil
		}
		msgName = "Handshake Response"
		confidence = 0.85
	case wgTypeCookieReply:
		if len(data) != wgCookieReplySize {
			return nil
		}
		msgName = "Cookie Reply"
		confidence = 0.75
	case wgTypeTransportData:
		if len(data) < wgTransportDataMinSize {
			return nil
		}
		msgName = "Transport Data"
		confidence = 0.60
	default:
		return nil
	}

	metadata := map[string]interface{}{
		"wireguard_message_type": msgName,
		"interface":              iface,
		// WireGuard has a fixed crypto suite — no negotiation
		"key_exchange_algorithm": "Curve25519",
		"symmetric_encryption":   "ChaCha20-Poly1305",
		"hash_algorithm":         "BLAKE2s",
	}

	// Extract sender index from handshake messages (bytes 4-7, little-endian)
	if msgType == wgTypeHandshakeInitiation || msgType == wgTypeHandshakeResponse {
		senderIndex := binary.LittleEndian.Uint32(data[4:8])
		metadata["wireguard_sender_index"] = senderIndex
	}
	if msgType == wgTypeHandshakeResponse {
		receiverIndex := binary.LittleEndian.Uint32(data[8:12])
		metadata["wireguard_receiver_index"] = receiverIndex
	}

	return &models.CryptoDiscovery{
		ID:              uuid.New().String(),
		SensorID:        sensorID,
		Timestamp:       time.Now(),
		SourceIP:        srcIP,
		DestIP:          dstIP,
		Port:            dstPort,
		Protocol:        "VPN",
		Version:         "WireGuard",
		CipherSuite:     "Curve25519_ChaCha20-Poly1305_BLAKE2s",
		DiscoveryMethod: "passive",
		Confidence:      confidence,
		RawMetadata:     metadata,
		CreatedAt:       time.Now(),
		ServiceHints: &models.ServiceHints{
			ServiceName:          "WireGuard VPN",
			IdentificationMethod: "protocol_fingerprint",
			Confidence:           "high",
		},
	}
}
