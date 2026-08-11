package capture

import (
	"encoding/binary"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// parseQUICInitial attempts to extract TLS ClientHello data from a QUIC Initial packet.
// Returns a CryptoDiscovery if successful, nil otherwise.
// QUIC Initial packets have Long Header format: Flags(1) + Version(4) + DCIL(1) + DCID(var) + SCIL(1) + SCID(var) + Token(var) + Length(var) + PN(var) + Payload
//
// When enableDecrypt is true, the function attempts to derive the Initial secret from the DCID
// (per RFC 9001 §5.2) and decrypt the CRYPTO frames to extract the full TLS ClientHello.
// On decryption failure, it falls back to version-only detection. When enableDecrypt is false,
// only opaque Initial detection (no key derivation) is used.
func parseQUICInitial(data []byte, srcIP, dstIP string, srcPort, dstPort int, sensorID, iface string, enableDecrypt bool) *models.CryptoDiscovery {
	return parseQUICInitialWithDecrypt(data, srcIP, dstIP, srcPort, dstPort, sensorID, iface, enableDecrypt)
}

func parseQUICInitialWithDecrypt(data []byte, srcIP, dstIP string, srcPort, dstPort int, sensorID, iface string, enableDecrypt bool) *models.CryptoDiscovery {
	if len(data) < 7 {
		return nil
	}

	// Check Long Header flag: first byte bit 7 must be 1, bit 6 must be 1 (Long Header),
	// and bits 4-5 must be 00 (Initial packet type)
	firstByte := data[0]
	if firstByte&0xC0 != 0xC0 { // Not a Long Header Initial
		return nil
	}
	if firstByte&0x30 != 0x00 { // Not Initial packet type (type 0)
		return nil
	}

	// Version (bytes 1-4)
	if len(data) < 5 {
		return nil
	}
	version := binary.BigEndian.Uint32(data[1:5])
	// Supported QUIC versions: v1 (0x00000001), v2 (0x6b3343cf), QUIC draft versions (0xff0000xx)
	isQUICv1 := version == 0x00000001
	isQUICv2 := version == 0x6b3343cf
	isQUICDraft := version&0xff000000 == 0xff000000
	if !isQUICv1 && !isQUICv2 && !isQUICDraft {
		return nil
	}

	versionStr := "QUIC v1"
	if isQUICv2 {
		versionStr = "QUIC v2"
	} else if isQUICDraft {
		versionStr = "QUIC draft"
	}

	metadata := map[string]interface{}{
		"quic_version": versionStr,
		"interface":    iface,
		"protocol":     "QUIC",
	}

	// Attempt QUIC Initial decryption to extract full ClientHello
	if enableDecrypt && (isQUICv1 || isQUICv2) {
		chInfo, err := decryptQUICInitial(data)
		if err == nil && chInfo != nil {
			log.Printf("QUIC ClientHello decrypted from %s:%d -> %s:%d (SNI=%s)", srcIP, srcPort, dstIP, dstPort, chInfo.SNI)

			// Compute JA3/JA4 fingerprints
			ja3Hash, _ := ComputeJA3(chInfo.JA3Input)
			ja4 := ComputeJA4QUIC(chInfo.JA3Input, chInfo.ALPNProtocols, chInfo.SNI != "")

			metadata["ja3_hash"] = ja3Hash
			metadata["ja4_fingerprint"] = ja4

			if chInfo.SNI != "" {
				metadata["sni_server_name"] = chInfo.SNI
			}
			if len(chInfo.ALPNProtocols) > 0 {
				metadata["alpn_protocols"] = chInfo.ALPNProtocols
			}

			// Extract cipher names
			var cipherNames []string
			for _, suite := range chInfo.JA3Input.CipherSuites {
				if name := tlsCipherName(suite); name != "" {
					cipherNames = append(cipherNames, name)
				}
			}
			if len(cipherNames) > 0 {
				metadata["supported_ciphers"] = cipherNames
			}

			// Determine TLS version from supported_versions if present
			tlsVer := ""
			for _, ext := range chInfo.JA3Input.Extensions {
				if ext == 0x002b {
					tlsVer = "TLS 1.3" // QUIC always uses TLS 1.3
					break
				}
			}
			if tlsVer == "" {
				tlsVer = tlsVersionName(chInfo.JA3Input.TLSVersion)
			}

			disc := makeQUICDiscovery(srcIP, dstIP, dstPort, sensorID, versionStr, metadata)
			disc.Version = versionStr + " (" + tlsVer + ")"
			disc.Confidence = 0.95
			return disc
		}
		// Decryption failed — fall through to basic detection
		log.Printf("QUIC decryption failed for %s:%d -> %s:%d: %v (falling back to version-only)", srcIP, srcPort, dstIP, dstPort, err)
	}

	log.Printf("QUIC Initial packet detected from %s:%d -> %s:%d", srcIP, srcPort, dstIP, dstPort)
	return makeQUICDiscovery(srcIP, dstIP, dstPort, sensorID, versionStr, metadata)
}

func makeQUICDiscovery(srcIP, dstIP string, dstPort int, sensorID, version string, metadata map[string]interface{}) *models.CryptoDiscovery {
	return &models.CryptoDiscovery{
		ID:              uuid.New().String(),
		SensorID:        sensorID,
		Timestamp:       time.Now(),
		SourceIP:        srcIP,
		DestIP:          dstIP,
		Port:            dstPort,
		Protocol:        "QUIC",
		Version:         version,
		DiscoveryMethod: "passive",
		Confidence:      0.8,
		RawMetadata:     metadata,
		CreatedAt:       time.Now(),
	}
}

// readQUICVarInt reads a QUIC variable-length integer from data at offset.
// Returns the value and the number of bytes consumed.
func readQUICVarInt(data []byte, offset int) (uint64, int) {
	if offset >= len(data) {
		return 0, 1
	}
	prefix := data[offset] >> 6
	switch prefix {
	case 0: // 1 byte
		return uint64(data[offset] & 0x3f), 1
	case 1: // 2 bytes
		if offset+1 >= len(data) {
			return 0, 1
		}
		return uint64(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3fff), 2
	case 2: // 4 bytes
		if offset+3 >= len(data) {
			return 0, 1
		}
		return uint64(binary.BigEndian.Uint32(data[offset:offset+4]) & 0x3fffffff), 4
	default: // 8 bytes
		if offset+7 >= len(data) {
			return 0, 1
		}
		return binary.BigEndian.Uint64(data[offset:offset+8]) & 0x3fffffffffffffff, 8
	}
}
