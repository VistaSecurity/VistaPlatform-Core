package capture

import "encoding/binary"

// TPKT (RFC 1006) and COTP (ISO 8073) framing helpers.
//
// IEC 61850 MMS and ICCP/TASE.2 both ride on the same ISO transport
// stack: TCP → TPKT → COTP → ISO Session → ISO Presentation → ASN.1
// payload. We don't need the upper layers for protocol identification —
// recognizing the TPKT magic + a valid COTP PDU type is enough to confirm
// this is an MMS or ICCP session, and the COTP CR PDU's variable-parameters
// section gives us the source/destination TSAP addresses (useful asset
// identifiers for the OT inventory tab).
//
// ICCP differentiation requires inspecting the ISO Presentation layer's
// ACSE Application-Context-Name OID, encoded as ASN.1 BER. We do that as
// a byte-pattern search on the first DT payload rather than a full ASN.1
// parse — see findTASE2OID below.
//
// References:
//   - RFC 1006 (TPKT)
//   - ISO 8073 / RFC 905 (COTP)
//   - IEC 61850-8-1 (MMS over ISO stack)
//   - IEC 60870-6 (TASE.2 / ICCP)

// tpktHeaderLen is the fixed size of every TPKT PDU header.
const tpktHeaderLen = 4

// COTP PDU type codes we care about. The full set is in ISO 8073; these
// four cover the 99% of MMS/ICCP traffic an OT-boundary sensor will see.
const (
	cotpPDUConnectionRequest = 0xE0
	cotpPDUConnectionConfirm = 0xD0
	cotpPDUData              = 0xF0
	cotpPDUDisconnectRequest = 0x80
)

// COTP CR/CC variable-parameter codes.
const (
	cotpParamSrcTSAP = 0xC1
	cotpParamDstTSAP = 0xC2
)

// isTPKTHeader reports whether buf starts with the TPKT magic
// (version=0x03, reserved=0x00). Cheap pre-check before paying for full
// header parsing — every TPKT PDU on the wire begins with these bytes.
func isTPKTHeader(buf []byte) bool {
	return len(buf) >= tpktHeaderLen && buf[0] == 0x03 && buf[1] == 0x00
}

// tpktLength reads the 16-bit big-endian total length from a TPKT header.
// Returns 0 if buf is too short or the magic doesn't match — the caller
// should treat that as "wait for more bytes" rather than as a parse error.
func tpktLength(buf []byte) int {
	if !isTPKTHeader(buf) {
		return 0
	}
	return int(binary.BigEndian.Uint16(buf[2:4]))
}

// cotpPDUType returns the COTP PDU-type byte from a TPKT-prefixed buffer
// (immediately follows the LI byte at offset tpktHeaderLen+1). Returns 0
// when the buffer is too short — 0 is not a valid COTP PDU type, so the
// caller can use that as the "unknown" sentinel.
func cotpPDUType(buf []byte) byte {
	// COTP layout inside TPKT: LI(1) PDUType(1) ...
	if len(buf) < tpktHeaderLen+2 {
		return 0
	}
	return buf[tpktHeaderLen+1]
}

// cotpPayload returns the application-layer slice that sits inside a TPKT
// PDU after the COTP header. The COTP header is variable-length: LI is
// the byte count of header data after LI itself, so total COTP header =
// 1 + LI bytes. Returns nil on short buffer or invalid LI.
func cotpPayload(buf []byte) []byte {
	if len(buf) < tpktHeaderLen+2 {
		return nil
	}
	li := int(buf[tpktHeaderLen])
	cotpEnd := tpktHeaderLen + 1 + li
	tpktEnd := tpktLength(buf)
	if tpktEnd <= cotpEnd || tpktEnd > len(buf) {
		return nil
	}
	return buf[cotpEnd:tpktEnd]
}

// extractTSAPs walks the variable-parameters section of a COTP CR (or
// CC) PDU and returns the source and destination TSAP byte values when
// present. The TSAP bytes are returned without interpretation — MMS uses
// them as ASCII (e.g. "MMS"), but vendor implementations vary.
//
// CR PDU layout after TPKT:
//
//	LI(1) PDUType(1=0xE0) DSTREF(2) SRCREF(2) Class(1) [params: code(1) len(1) value(N)...]
//
// Returns (nil, nil) when buf doesn't contain a CR or CC PDU.
func extractTSAPs(buf []byte) (src, dst []byte) {
	pduType := cotpPDUType(buf)
	if pduType != cotpPDUConnectionRequest && pduType != cotpPDUConnectionConfirm {
		return nil, nil
	}
	li := int(buf[tpktHeaderLen])
	// Header layout starting at the byte AFTER LI:
	//   PDUType(1) DSTREF(2) SRCREF(2) Class(1) [variable params]
	// So fixed COTP header bytes (after LI) = 6.
	const fixedHdrAfterLI = 6
	if li < fixedHdrAfterLI {
		return nil, nil
	}
	paramsStart := tpktHeaderLen + 1 + fixedHdrAfterLI
	paramsEnd := tpktHeaderLen + 1 + li
	if paramsEnd > len(buf) {
		return nil, nil
	}
	off := paramsStart
	for off+2 <= paramsEnd {
		code := buf[off]
		l := int(buf[off+1])
		off += 2
		if off+l > paramsEnd {
			return src, dst
		}
		val := buf[off : off+l]
		switch code {
		case cotpParamSrcTSAP:
			src = append([]byte(nil), val...)
		case cotpParamDstTSAP:
			dst = append([]byte(nil), val...)
		}
		off += l
	}
	return src, dst
}

// tase2OIDPattern is the BER-encoded form of the TASE.2 application-context
// OID 1.2.840.10006.300.7.1.1.* used by ICCP servers. We match the leading
// nine value bytes — that's enough to disambiguate TASE.2 from MMS without
// committing to a specific TASE.2 service profile sub-OID.
//
// OID encoding: 0x06 = OID tag, 0x09 = length, then the canonical BER bytes.
// 1.2.840.10006.300.7.1.1 → 0x2A 0x86 0x48 0xCE 0x76 0x82 0x2C 0x07 0x01 (and one more)
// We search for the leading recognizable run; vendor variants append
// different sub-OIDs.
var tase2OIDPatternPrefix = []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0xCE, 0x76, 0x82, 0x2C, 0x07, 0x01}

// findTASE2OID returns true if the buffer contains the TASE.2 OID byte
// pattern anywhere within it. Pragmatic shortcut around full ACSE/ASN.1
// parsing per the design doc — the pattern is specific enough that false
// positives in real MMS-only traffic are vanishingly rare.
func findTASE2OID(buf []byte) bool {
	if len(buf) < len(tase2OIDPatternPrefix) {
		return false
	}
	// Bounded scan; OID is small enough that bytes.Index would be fine
	// but inlining keeps this allocation-free on the per-packet hot path.
	last := len(buf) - len(tase2OIDPatternPrefix)
	for i := 0; i <= last; i++ {
		if buf[i] != tase2OIDPatternPrefix[0] {
			continue
		}
		match := true
		for j := 1; j < len(tase2OIDPatternPrefix); j++ {
			if buf[i+j] != tase2OIDPatternPrefix[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
