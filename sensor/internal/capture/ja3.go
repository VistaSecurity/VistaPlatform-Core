package capture

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"
)

// JA3Input holds the parsed ClientHello fields needed for JA3 computation.
type JA3Input struct {
	TLSVersion           uint16
	CipherSuites         []uint16
	Extensions           []uint16
	EllipticCurves       []uint16
	EllipticCurveFormats []uint8
}

// ComputeJA3 computes the JA3 fingerprint from a ClientHello.
// JA3 format: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
// Each list is dash-separated. The result is MD5-hashed.
// GREASE values are filtered out per the JA3 specification.
func ComputeJA3(input JA3Input) (hash string, raw string) {
	// Filter GREASE from all lists
	ciphers := filterGREASE16(input.CipherSuites)
	extensions := filterGREASE16(input.Extensions)
	curves := filterGREASE16(input.EllipticCurves)
	// Point formats don't have GREASE values but we keep the full list

	parts := []string{
		strconv.Itoa(int(input.TLSVersion)),
		joinUint16(ciphers, "-"),
		joinUint16(extensions, "-"),
		joinUint16(curves, "-"),
		joinUint8(input.EllipticCurveFormats, "-"),
	}
	raw = strings.Join(parts, ",")
	sum := md5.Sum([]byte(raw))
	hash = hex.EncodeToString(sum[:])
	return hash, raw
}

// isGREASE returns true if the value is a GREASE value per RFC 8701.
// GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa
func isGREASE(val uint16) bool {
	// GREASE values have the pattern 0x?a?a where both nibbles match
	return val&0x0f0f == 0x0a0a && val>>8 == val&0xff
}

// filterGREASE16 removes GREASE values from a uint16 slice.
func filterGREASE16(vals []uint16) []uint16 {
	result := make([]uint16, 0, len(vals))
	for _, v := range vals {
		if !isGREASE(v) {
			result = append(result, v)
		}
	}
	return result
}

func joinUint16(vals []uint16, sep string) string {
	strs := make([]string, len(vals))
	for i, v := range vals {
		strs[i] = strconv.Itoa(int(v))
	}
	return strings.Join(strs, sep)
}

func joinUint8(vals []uint8, sep string) string {
	strs := make([]string, len(vals))
	for i, v := range vals {
		strs[i] = strconv.Itoa(int(v))
	}
	return strings.Join(strs, sep)
}

// ParseClientHelloJA3Fields extracts the JA3-relevant fields from a ClientHello message body
// (after the handshake header). Returns the JA3Input and ALPN protocols if present.
// This function is used by both the TLS assembler and the QUIC decryption path.
func ParseClientHelloJA3Fields(msg []byte) (ja3 JA3Input, alpnProtocols []string, sni string) {
	if len(msg) < 35 {
		return
	}

	// TLS version from ClientHello (wire version, not supported_versions)
	ja3.TLSVersion = uint16(msg[0])<<8 | uint16(msg[1])

	offset := 34 // skip version(2) + random(32)

	// Session ID
	if offset >= len(msg) {
		return
	}
	sidLen := int(msg[offset])
	offset++
	offset += sidLen

	// Cipher suites
	if offset+2 > len(msg) {
		return
	}
	csLen := int(msg[offset])<<8 | int(msg[offset+1])
	offset += 2
	if offset+csLen > len(msg) {
		return
	}
	for i := 0; i+1 < csLen; i += 2 {
		suite := uint16(msg[offset+i])<<8 | uint16(msg[offset+i+1])
		ja3.CipherSuites = append(ja3.CipherSuites, suite)
	}
	offset += csLen

	// Compression methods
	if offset >= len(msg) {
		return
	}
	compLen := int(msg[offset])
	offset++
	offset += compLen

	// Extensions
	if offset+2 > len(msg) {
		return
	}
	extTotalLen := int(msg[offset])<<8 | int(msg[offset+1])
	offset += 2
	extEnd := offset + extTotalLen
	if extEnd > len(msg) {
		extEnd = len(msg)
	}

	for offset+4 <= extEnd {
		extType := uint16(msg[offset])<<8 | uint16(msg[offset+1])
		extLen := int(msg[offset+2])<<8 | int(msg[offset+3])
		offset += 4
		if offset+extLen > extEnd {
			break
		}
		extBody := msg[offset : offset+extLen]

		ja3.Extensions = append(ja3.Extensions, extType)

		switch extType {
		case 0x000a: // supported_groups / elliptic_curves
			if len(extBody) >= 2 {
				listLen := int(extBody[0])<<8 | int(extBody[1])
				for i := 2; i+1 < 2+listLen && i+1 < len(extBody); i += 2 {
					group := uint16(extBody[i])<<8 | uint16(extBody[i+1])
					ja3.EllipticCurves = append(ja3.EllipticCurves, group)
				}
			}
		case 0x000b: // ec_point_formats
			if len(extBody) >= 1 {
				fmtLen := int(extBody[0])
				for i := 1; i < 1+fmtLen && i < len(extBody); i++ {
					ja3.EllipticCurveFormats = append(ja3.EllipticCurveFormats, extBody[i])
				}
			}
		case 0x0010: // ALPN
			alpnProtocols = parseALPNExtensionBody(extBody)
		case 0x0000: // SNI
			if h := parseServerNameExtensionBody(extBody); h != "" {
				sni = h
			}
		}

		offset += extLen
	}

	return ja3, alpnProtocols, sni
}

// parseALPNExtensionBody parses the ALPN extension body (RFC 7301).
// Format: ProtocolNameList length (2 bytes) + [ ProtocolName length (1 byte) + name ]...
func parseALPNExtensionBody(body []byte) []string {
	if len(body) < 2 {
		return nil
	}
	listLen := int(body[0])<<8 | int(body[1])
	if 2+listLen > len(body) {
		listLen = len(body) - 2
	}
	var protocols []string
	offset := 2
	end := 2 + listLen
	for offset < end && offset < len(body) {
		nameLen := int(body[offset])
		offset++
		if offset+nameLen > end || offset+nameLen > len(body) {
			break
		}
		protocols = append(protocols, string(body[offset:offset+nameLen]))
		offset += nameLen
	}
	return protocols
}
