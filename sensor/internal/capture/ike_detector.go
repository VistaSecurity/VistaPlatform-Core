package capture

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// IKE exchange types
const (
	ikeExchangeIdentityProtection = 2  // IKEv1 Main Mode
	ikeExchangeAggressive         = 4  // IKEv1 Aggressive Mode
	ikeExchangeInformational      = 5  // IKEv1 Informational
	ikeExchangeSAInit             = 34 // IKEv2 IKE_SA_INIT
	ikeExchangeAuth               = 35 // IKEv2 IKE_AUTH
)

// IKEv2 payload types
const (
	ikePayloadSA = 33 // Security Association
	ikePayloadKE = 34 // Key Exchange
	ikePayloadN  = 41 // Notify
)

// IKEv2 transform types
const (
	ikeTransformTypeENCR  = 1 // Encryption Algorithm
	ikeTransformTypePRF   = 2 // Pseudo-Random Function
	ikeTransformTypeINTEG = 3 // Integrity Algorithm
	ikeTransformTypeDH    = 4 // Diffie-Hellman Group
	ikeTransformTypeESN   = 5 // Extended Sequence Numbers
)

// parseIKEHeader attempts to detect and parse an IKE packet header.
// IKE Header format (28 bytes): InitiatorSPI(8) + ResponderSPI(8) + NextPayload(1) +
//
//	MajorVersion(4bits) + MinorVersion(4bits) + ExchangeType(1) + Flags(1) + MessageID(4) + Length(4)
func parseIKEHeader(data []byte, srcIP, dstIP string, srcPort, dstPort int, sensorID, iface string) *models.CryptoDiscovery {
	if len(data) < 28 {
		return nil
	}

	// Version byte: upper 4 bits = major, lower 4 bits = minor
	versionByte := data[17]
	majorVersion := versionByte >> 4

	// IKE major version must be 1 or 2
	if majorVersion != 1 && majorVersion != 2 {
		return nil
	}

	exchangeType := data[18]
	messageID := binary.BigEndian.Uint32(data[20:24])
	totalLen := binary.BigEndian.Uint32(data[24:28])

	// Sanity check: total length should match or exceed 28 (header size)
	if totalLen < 28 || totalLen > uint32(len(data))+10000 {
		return nil
	}

	ikeVersion := "IKEv1"
	if majorVersion == 2 {
		ikeVersion = "IKEv2"
	}

	exchangeName := ikeExchangeName(majorVersion, exchangeType)

	metadata := map[string]interface{}{
		"ike_version":   ikeVersion,
		"exchange_type": exchangeName,
		"message_id":    messageID,
		"interface":     iface,
	}

	cipherSuite := ""
	confidence := 0.85

	// For IKEv2 SA_INIT, parse the SA payload to extract proposed algorithms
	nextPayload := data[16]
	if majorVersion == 2 && exchangeType == ikeExchangeSAInit && len(data) > 28 {
		saData := parseIKEv2Payloads(data[28:], nextPayload)
		for k, v := range saData {
			metadata[k] = v
		}
		// Set cipher suite from preferred encryption algorithm
		if encAlgs, ok := saData["ipsec_encryption_algs"].([]string); ok && len(encAlgs) > 0 {
			cipherSuite = encAlgs[0]
			confidence = 0.90
		}
	}

	return &models.CryptoDiscovery{
		ID:              uuid.New().String(),
		SensorID:        sensorID,
		Timestamp:       time.Now(),
		SourceIP:        srcIP,
		DestIP:          dstIP,
		Port:            dstPort,
		Protocol:        "IPSec",
		Version:         ikeVersion,
		CipherSuite:     cipherSuite,
		DiscoveryMethod: "passive",
		Confidence:      confidence,
		RawMetadata:     metadata,
		CreatedAt:       time.Now(),
	}
}

// parseIKEv2Payloads walks the IKEv2 payload chain and extracts crypto
// algorithms from the SA payload.  Each payload has a 4-byte generic header:
//
//	NextPayload(1) + Critical/Reserved(1) + PayloadLength(2)
//
// PayloadLength includes the 4-byte header itself.
func parseIKEv2Payloads(data []byte, firstPayloadType uint8) map[string]interface{} {
	result := map[string]interface{}{}
	offset := 0
	payloadType := firstPayloadType

	for offset+4 <= len(data) && payloadType != 0 {
		nextPayload := data[offset]
		payloadLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))

		// Sanity: payload length must cover at least the header and not overflow
		if payloadLen < 4 || offset+payloadLen > len(data) {
			break
		}

		if payloadType == ikePayloadSA {
			saResult := parseIKEv2SAPayload(data[offset+4 : offset+payloadLen])
			for k, v := range saResult {
				result[k] = v
			}
		}

		offset += payloadLen
		payloadType = nextPayload
	}

	return result
}

// parseIKEv2SAPayload parses the SA payload body (after the generic header).
// SA payload body = one or more Proposals, each containing Transforms.
//
// Proposal format:
//
//	LastOrMore(1) + Reserved(1) + ProposalLength(2) + ProposalNum(1) +
//	ProtocolID(1) + SPISize(1) + NumTransforms(1) + SPI(variable) + Transforms...
func parseIKEv2SAPayload(data []byte) map[string]interface{} {
	var encrAlgs, prfAlgs, integAlgs, dhGroups []string
	proposalCount := 0
	offset := 0

	for offset+8 <= len(data) {
		proposalLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if proposalLen < 8 || offset+proposalLen > len(data) {
			break
		}

		proposalCount++
		spiSize := int(data[offset+6])
		numTransforms := int(data[offset+7])
		tOffset := offset + 8 + spiSize

		for i := 0; i < numTransforms && tOffset+8 <= offset+proposalLen; i++ {
			tLen := int(binary.BigEndian.Uint16(data[tOffset+2 : tOffset+4]))
			if tLen < 8 || tOffset+tLen > offset+proposalLen {
				break
			}

			transformType := data[tOffset+4]
			transformID := binary.BigEndian.Uint16(data[tOffset+6 : tOffset+8])

			// For ENCR transforms, check for key length attribute (type 14)
			keyLen := 0
			if transformType == ikeTransformTypeENCR && tLen > 8 {
				keyLen = parseTransformKeyLength(data[tOffset+8 : tOffset+tLen])
			}

			name := ikeTransformName(transformType, transformID, keyLen)

			switch transformType {
			case ikeTransformTypeENCR:
				encrAlgs = appendUnique(encrAlgs, name)
			case ikeTransformTypePRF:
				prfAlgs = appendUnique(prfAlgs, name)
			case ikeTransformTypeINTEG:
				integAlgs = appendUnique(integAlgs, name)
			case ikeTransformTypeDH:
				dhGroups = appendUnique(dhGroups, name)
			}

			tOffset += tLen
		}

		// Check "last or more" field: 0 = last proposal, 2 = more follow
		if data[offset] == 0 {
			break
		}
		offset += proposalLen
	}

	result := map[string]interface{}{
		"ipsec_proposals_count": proposalCount,
	}
	if len(encrAlgs) > 0 {
		result["ipsec_encryption_algs"] = encrAlgs
	}
	if len(prfAlgs) > 0 {
		result["ipsec_prf_algs"] = prfAlgs
	}
	if len(integAlgs) > 0 {
		result["ipsec_integrity_algs"] = integAlgs
	}
	if len(dhGroups) > 0 {
		result["ipsec_dh_groups"] = dhGroups
	}
	return result
}

// parseTransformKeyLength extracts key length from a transform's attributes.
// IKEv2 transform attribute format: AF(1bit) + Type(15bits) + Value(2bytes).
// Type 14 = Key Length. AF=1 means TV (Type/Value), AF=0 means TLV.
func parseTransformKeyLength(attrs []byte) int {
	offset := 0
	for offset+4 <= len(attrs) {
		attrType := binary.BigEndian.Uint16(attrs[offset : offset+2])
		isTV := attrType&0x8000 != 0
		typeNum := attrType & 0x7FFF
		if isTV {
			value := int(binary.BigEndian.Uint16(attrs[offset+2 : offset+4]))
			if typeNum == 14 { // Key Length
				return value
			}
			offset += 4
		} else {
			attrLen := int(binary.BigEndian.Uint16(attrs[offset+2 : offset+4]))
			offset += 4 + attrLen
		}
	}
	return 0
}

// ikeTransformName maps IKEv2 transform type+ID to a human-readable name.
func ikeTransformName(transformType uint8, transformID uint16, keyLen int) string {
	switch transformType {
	case ikeTransformTypeENCR:
		return ikeEncrName(transformID, keyLen)
	case ikeTransformTypePRF:
		return ikePRFName(transformID)
	case ikeTransformTypeINTEG:
		return ikeIntegName(transformID)
	case ikeTransformTypeDH:
		return ikeDHName(transformID)
	}
	return "Unknown"
}

func ikeEncrName(id uint16, keyLen int) string {
	suffix := ""
	if keyLen > 0 {
		suffix = fmt.Sprintf("-%d", keyLen)
	}
	switch id {
	case 2:
		return "DES" + suffix
	case 3:
		return "3DES"
	case 11:
		return "NULL"
	case 12:
		return "AES-CBC" + suffix
	case 13:
		return "AES-CTR" + suffix
	case 14:
		return "AES-CCM-8" + suffix
	case 15:
		return "AES-CCM-12" + suffix
	case 16:
		return "AES-CCM-16" + suffix
	case 18:
		return "AES-GCM-8" + suffix
	case 19:
		return "AES-GCM-12" + suffix
	case 20:
		return "AES-GCM-16" + suffix
	case 23:
		return "Camellia-CBC" + suffix
	case 28:
		return "ChaCha20-Poly1305"
	}
	return fmt.Sprintf("ENCR_%d%s", id, suffix)
}

func ikePRFName(id uint16) string {
	switch id {
	case 1:
		return "PRF-HMAC-MD5"
	case 2:
		return "PRF-HMAC-SHA1"
	case 4:
		return "PRF-AES128-XCBC"
	case 5:
		return "PRF-HMAC-SHA2-256"
	case 6:
		return "PRF-HMAC-SHA2-384"
	case 7:
		return "PRF-HMAC-SHA2-512"
	}
	return fmt.Sprintf("PRF_%d", id)
}

func ikeIntegName(id uint16) string {
	switch id {
	case 0:
		return "NONE"
	case 1:
		return "AUTH-HMAC-MD5-96"
	case 2:
		return "AUTH-HMAC-SHA1-96"
	case 5:
		return "AUTH-AES-XCBC-96"
	case 12:
		return "AUTH-HMAC-SHA2-256-128"
	case 13:
		return "AUTH-HMAC-SHA2-384-192"
	case 14:
		return "AUTH-HMAC-SHA2-512-256"
	}
	return fmt.Sprintf("INTEG_%d", id)
}

func ikeDHName(id uint16) string {
	switch id {
	case 1:
		return "MODP-768"
	case 2:
		return "MODP-1024"
	case 5:
		return "MODP-1536"
	case 14:
		return "MODP-2048"
	case 15:
		return "MODP-3072"
	case 16:
		return "MODP-4096"
	case 19:
		return "ECP-256"
	case 20:
		return "ECP-384"
	case 21:
		return "ECP-521"
	case 31:
		return "Curve25519"
	case 32:
		return "Curve448"
	}
	return fmt.Sprintf("DH_%d", id)
}

func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}

func ikeExchangeName(majorVersion, exchangeType uint8) string {
	if majorVersion == 2 {
		switch exchangeType {
		case ikeExchangeSAInit:
			return "IKE_SA_INIT"
		case ikeExchangeAuth:
			return "IKE_AUTH"
		case 36:
			return "CREATE_CHILD_SA"
		case 37:
			return "INFORMATIONAL"
		}
	} else {
		switch exchangeType {
		case ikeExchangeIdentityProtection:
			return "Main Mode"
		case ikeExchangeAggressive:
			return "Aggressive Mode"
		case ikeExchangeInformational:
			return "Informational"
		case 6:
			return "Transaction"
		case 32:
			return "Quick Mode"
		case 33:
			return "New Group Mode"
		}
	}
	return "Unknown"
}
