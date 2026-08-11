package capture

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// Kerberos ASN.1 application tags
const (
	krbTagASREQ  = 0x6A // Application tag 10 (AS-REQ)
	krbTagASREP  = 0x6B // Application tag 11 (AS-REP)
	krbTagTGSREQ = 0x6C // Application tag 12 (TGS-REQ)
	krbTagTGSREP = 0x6D // Application tag 13 (TGS-REP)
)

// parseKerberosPacket detects Kerberos AS-REQ/AS-REP/TGS-REQ/TGS-REP messages
// and extracts the etype (encryption type) list. This is a minimal ASN.1 parser
// that walks just deep enough to reach the etype field.
//
// For UDP, data starts with the Kerberos message directly.
// For TCP, the caller must strip the 4-byte length prefix before calling.
func parseKerberosPacket(data []byte, srcIP, dstIP string, srcPort, dstPort int, sensorID, iface string) *models.CryptoDiscovery {
	if len(data) < 10 {
		return nil
	}

	// Check for Kerberos application tag
	tag := data[0]
	var msgType string
	switch tag {
	case krbTagASREQ:
		msgType = "AS-REQ"
	case krbTagASREP:
		msgType = "AS-REP"
	case krbTagTGSREQ:
		msgType = "TGS-REQ"
	case krbTagTGSREP:
		msgType = "TGS-REP"
	default:
		return nil
	}

	// Parse ASN.1 length
	_, headerLen := parseASN1Length(data[1:])
	if headerLen == 0 {
		return nil
	}

	// Extract etypes from the message body
	body := data[1+headerLen:]
	etypes := extractKerberosEtypes(body, tag)

	metadata := map[string]interface{}{
		"kerberos_message_type": msgType,
		"interface":             iface,
	}

	if len(etypes) > 0 {
		metadata["kerberos_etypes"] = etypes
		names := make([]string, len(etypes))
		for i, e := range etypes {
			names[i] = kerberosEtypeName(e)
		}
		metadata["kerberos_etype_names"] = names
	}

	// Try to extract realm from the message
	realm := extractKerberosRealm(body)
	if realm != "" {
		metadata["kerberos_realm"] = realm
	}

	cipherSuite := ""
	if len(etypes) > 0 {
		cipherSuite = kerberosEtypeName(etypes[0])
	}

	return &models.CryptoDiscovery{
		ID:              uuid.New().String(),
		SensorID:        sensorID,
		Timestamp:       time.Now(),
		SourceIP:        srcIP,
		DestIP:          dstIP,
		Port:            dstPort,
		Protocol:        "Kerberos",
		Version:         "Kerberos 5",
		CipherSuite:     cipherSuite,
		DiscoveryMethod: "passive",
		Confidence:      0.90,
		RawMetadata:     metadata,
		CreatedAt:       time.Now(),
	}
}

// extractKerberosEtypes walks the ASN.1 structure to find the etype field.
// In KDC-REQ (AS-REQ/TGS-REQ), etype is field [8] of KDC-REQ-BODY (field [4]).
// In KDC-REP (AS-REP/TGS-REP), etype is field [0] of EncKDCRepPart (encrypted, not accessible).
// For REP messages we extract the enc-part etype (field [3] → etype [0] of EncryptedData).
func extractKerberosEtypes(data []byte, appTag byte) []int {
	if len(data) < 4 {
		return nil
	}

	// For AS-REQ/TGS-REQ: find req-body (context tag [4]) → etype (context tag [8])
	if appTag == krbTagASREQ || appTag == krbTagTGSREQ {
		return findEtypesInKDCReq(data)
	}

	// For AS-REP/TGS-REP: find enc-part (context tag [6]) → etype (context tag [0])
	if appTag == krbTagASREP || appTag == krbTagTGSREP {
		return findEtypeInKDCRep(data)
	}

	return nil
}

// findEtypesInKDCReq scans for the etype SEQUENCE in KDC-REQ-BODY.
// We look for the etype list by scanning for context tag [8] at the right nesting level.
func findEtypesInKDCReq(data []byte) []int {
	// Unwrap outer SEQUENCE (KDC-REQ)
	inner := unwrapSequence(data)
	if inner == nil {
		return nil
	}

	// Walk KDC-REQ fields, find context [4] (req-body)
	reqBodyWrapped := findContextTag(inner, 4)
	if reqBodyWrapped == nil {
		return nil
	}

	// Unwrap req-body SEQUENCE
	reqBody := unwrapSequence(reqBodyWrapped)
	if reqBody == nil {
		return nil
	}

	// Inside req-body, find context [8] (etype)
	etypeSeq := findContextTag(reqBody, 8)
	if etypeSeq == nil {
		return nil
	}

	// etypeSeq should contain a SEQUENCE OF INTEGER
	return parseASN1IntegerSequence(etypeSeq)
}

// findEtypeInKDCRep extracts the single etype from the enc-part EncryptedData.
func findEtypeInKDCRep(data []byte) []int {
	// Unwrap outer SEQUENCE (KDC-REP)
	inner := unwrapSequence(data)
	if inner == nil {
		return nil
	}
	// Walk to find context [6] (enc-part)
	encPart := findContextTag(inner, 6)
	if encPart == nil {
		return nil
	}
	// Unwrap EncryptedData SEQUENCE
	encInner := unwrapSequence(encPart)
	if encInner == nil {
		return nil
	}
	// Inside EncryptedData, context [0] is etype (INTEGER)
	etypeData := findContextTag(encInner, 0)
	if etypeData == nil {
		return nil
	}
	val := parseASN1Integer(etypeData)
	if val != 0 {
		return []int{val}
	}
	return nil
}

// unwrapSequence skips a SEQUENCE tag and returns the content bytes.
func unwrapSequence(data []byte) []byte {
	if len(data) < 2 || data[0] != 0x30 {
		return nil
	}
	contentLen, headerLen := parseASN1Length(data[1:])
	if headerLen == 0 {
		return nil
	}
	start := 1 + headerLen
	end := start + contentLen
	if end > len(data) {
		end = len(data)
	}
	return data[start:end]
}

// findContextTag scans ASN.1 TLV elements for a context-specific tag [n].
// Returns the value bytes (inside the tag) or nil.
func findContextTag(data []byte, ctxTag int) []byte {
	offset := 0
	targetTag := byte(0xA0 | ctxTag) // context-specific, constructed

	for offset < len(data) {
		if offset+2 > len(data) {
			break
		}
		tag := data[offset]
		valueLen, headerLen := parseASN1Length(data[offset+1:])
		if headerLen == 0 || valueLen < 0 {
			break
		}
		totalLen := 1 + headerLen + valueLen
		if offset+totalLen > len(data) {
			break
		}

		if tag == targetTag {
			return data[offset+1+headerLen : offset+totalLen]
		}

		offset += totalLen
	}
	return nil
}

// parseASN1Length parses a DER length field. Returns (length, bytesConsumed).
// Returns (0, 0) on error.
func parseASN1Length(data []byte) (int, int) {
	if len(data) == 0 {
		return 0, 0
	}
	if data[0] < 0x80 {
		return int(data[0]), 1
	}
	numBytes := int(data[0] & 0x7F)
	if numBytes == 0 || numBytes > 4 || numBytes+1 > len(data) {
		return 0, 0
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = length<<8 | int(data[1+i])
	}
	return length, 1 + numBytes
}

// parseASN1IntegerSequence parses a SEQUENCE OF INTEGER, returning int values.
func parseASN1IntegerSequence(data []byte) []int {
	if len(data) < 2 || data[0] != 0x30 { // SEQUENCE tag
		return nil
	}
	seqLen, headerLen := parseASN1Length(data[1:])
	if headerLen == 0 {
		return nil
	}
	body := data[1+headerLen:]
	if seqLen > len(body) {
		seqLen = len(body)
	}

	var result []int
	offset := 0
	for offset < seqLen {
		if offset+2 > seqLen || body[offset] != 0x02 { // INTEGER tag
			break
		}
		intLen, intHeaderLen := parseASN1Length(body[offset+1:])
		if intHeaderLen == 0 || offset+1+intHeaderLen+intLen > seqLen {
			break
		}
		val := parseASN1IntegerBytes(body[offset+1+intHeaderLen : offset+1+intHeaderLen+intLen])
		result = append(result, val)
		offset += 1 + intHeaderLen + intLen
	}
	return result
}

// parseASN1Integer extracts an INTEGER value from data starting at an INTEGER TLV.
func parseASN1Integer(data []byte) int {
	if len(data) < 2 || data[0] != 0x02 { // INTEGER tag
		return 0
	}
	intLen, headerLen := parseASN1Length(data[1:])
	if headerLen == 0 || 1+headerLen+intLen > len(data) {
		return 0
	}
	return parseASN1IntegerBytes(data[1+headerLen : 1+headerLen+intLen])
}

// parseASN1IntegerBytes converts big-endian signed integer bytes to int.
func parseASN1IntegerBytes(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	// Handle negative (signed) values
	negative := b[0]&0x80 != 0
	val := 0
	for _, by := range b {
		val = val<<8 | int(by)
	}
	if negative && len(b) <= 4 {
		// Sign extend
		val -= 1 << (uint(len(b)) * 8)
	}
	return val
}

// extractKerberosRealm attempts to find the realm string in the message.
// Realm is a GeneralString in context tag [1] or [2] depending on message type.
func extractKerberosRealm(data []byte) string {
	inner := unwrapSequence(data)
	if inner == nil {
		return ""
	}
	// Try context tag [2] (crealm in REQ, crealm in REP)
	for _, tag := range []int{1, 2, 9} {
		realmData := findContextTag(inner, tag)
		if realmData == nil {
			continue
		}
		// Should be a GeneralString (tag 0x1B) or UTF8String (tag 0x0C)
		if len(realmData) >= 2 && (realmData[0] == 0x1B || realmData[0] == 0x0C) {
			strLen, headerLen := parseASN1Length(realmData[1:])
			if headerLen > 0 && 1+headerLen+strLen <= len(realmData) {
				return string(realmData[1+headerLen : 1+headerLen+strLen])
			}
		}
	}
	return ""
}

// kerberosEtypeName maps Kerberos etype numbers to human-readable names.
func kerberosEtypeName(etype int) string {
	switch etype {
	case 1:
		return "DES-CBC-CRC"
	case 3:
		return "DES-CBC-MD5"
	case 5:
		return "DES3-CBC-MD5"
	case 7:
		return "DES3-CBC-SHA1"
	case 16:
		return "DES3-CBC-SHA1-KD"
	case 17:
		return "AES128-CTS-HMAC-SHA1-96"
	case 18:
		return "AES256-CTS-HMAC-SHA1-96"
	case 19:
		return "AES128-CTS-HMAC-SHA256-128"
	case 20:
		return "AES256-CTS-HMAC-SHA384-192"
	case 23:
		return "RC4-HMAC"
	case 24:
		return "RC4-HMAC-EXP"
	case -128:
		return "RC4-HMAC-OLD"
	case -133:
		return "AES256-CTS-HMAC-SHA384-192"
	case -134:
		return "AES128-CTS-HMAC-SHA256-128"
	}
	return fmt.Sprintf("etype-%d", etype)
}
