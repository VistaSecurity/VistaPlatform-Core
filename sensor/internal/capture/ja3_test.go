package capture

import (
	"testing"
)

func TestIsGREASE(t *testing.T) {
	greaseValues := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}
	for _, v := range greaseValues {
		if !isGREASE(v) {
			t.Errorf("expected isGREASE(0x%04x) = true", v)
		}
	}

	nonGREASE := []uint16{0x0000, 0x0001, 0x002f, 0x0033, 0x1301, 0xc02f, 0x00ff}
	for _, v := range nonGREASE {
		if isGREASE(v) {
			t.Errorf("expected isGREASE(0x%04x) = false", v)
		}
	}
}

func TestComputeJA3_KnownVector(t *testing.T) {
	// Known JA3 test vector: a standard Chrome-like ClientHello
	// TLSVersion: 0x0303 (771)
	// Ciphers: 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0x009d, 0x009c
	// Extensions: 0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x002b, 0x002d, 0x001b
	// EllipticCurves: 0x001d, 0x0017, 0x0018
	// EllipticCurveFormats: 0x00
	input := JA3Input{
		TLSVersion:           0x0303,
		CipherSuites:         []uint16{0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0x009d, 0x009c},
		Extensions:           []uint16{0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x002b, 0x002d, 0x001b},
		EllipticCurves:       []uint16{0x001d, 0x0017, 0x0018},
		EllipticCurveFormats: []uint8{0x00},
	}

	hash, raw := ComputeJA3(input)

	// Verify the raw string format
	expectedRaw := "771,4865-4866-4867-49196-49195-49200-49199-157-156,0-23-65281-10-11-35-16-5-13-43-45-27,29-23-24,0"
	if raw != expectedRaw {
		t.Errorf("JA3 raw mismatch:\n  got:  %s\n  want: %s", raw, expectedRaw)
	}

	// Hash should be a 32-char hex string
	if len(hash) != 32 {
		t.Errorf("JA3 hash should be 32 hex chars, got %d: %s", len(hash), hash)
	}
}

func TestComputeJA3_GREASEFiltering(t *testing.T) {
	// Input with GREASE values mixed in — they should be stripped
	input := JA3Input{
		TLSVersion:           0x0303,
		CipherSuites:         []uint16{0x0a0a, 0x1301, 0x1302, 0xfafa},
		Extensions:           []uint16{0x2a2a, 0x0000, 0x000a, 0x3a3a},
		EllipticCurves:       []uint16{0x4a4a, 0x001d, 0x0017},
		EllipticCurveFormats: []uint8{0x00},
	}

	_, raw := ComputeJA3(input)

	// GREASE values should be removed
	expectedRaw := "771,4865-4866,0-10,29-23,0"
	if raw != expectedRaw {
		t.Errorf("JA3 raw with GREASE filtering mismatch:\n  got:  %s\n  want: %s", raw, expectedRaw)
	}
}

func TestComputeJA3_EmptyLists(t *testing.T) {
	input := JA3Input{
		TLSVersion: 0x0303,
	}

	hash, raw := ComputeJA3(input)
	expectedRaw := "771,,,,"
	if raw != expectedRaw {
		t.Errorf("JA3 empty raw mismatch:\n  got:  %s\n  want: %s", raw, expectedRaw)
	}
	if len(hash) != 32 {
		t.Errorf("JA3 hash should be 32 hex chars, got %d", len(hash))
	}
}

func TestParseClientHelloJA3Fields(t *testing.T) {
	// Build a minimal ClientHello message body:
	// version(2) + random(32) + sid_len(1) + sid(0) + cs_len(2) + cs(4) + comp_len(1) + comp(1) + ext_len(2) + extensions
	msg := make([]byte, 0, 200)

	// Client version: TLS 1.2 (0x0303)
	msg = append(msg, 0x03, 0x03)
	// Random: 32 bytes
	msg = append(msg, make([]byte, 32)...)
	// Session ID length: 0
	msg = append(msg, 0x00)
	// Cipher suites: length 4 (2 suites)
	msg = append(msg, 0x00, 0x04)
	msg = append(msg, 0x13, 0x01) // TLS_AES_128_GCM_SHA256
	msg = append(msg, 0xc0, 0x2f) // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	// Compression: length 1, null
	msg = append(msg, 0x01, 0x00)

	// Extensions
	extBlock := buildTestExtensions()
	msg = append(msg, byte(len(extBlock)>>8), byte(len(extBlock)))
	msg = append(msg, extBlock...)

	ja3, alpn, sni := ParseClientHelloJA3Fields(msg)

	if ja3.TLSVersion != 0x0303 {
		t.Errorf("expected TLS version 0x0303, got 0x%04x", ja3.TLSVersion)
	}
	if len(ja3.CipherSuites) != 2 {
		t.Errorf("expected 2 cipher suites, got %d", len(ja3.CipherSuites))
	}
	if ja3.CipherSuites[0] != 0x1301 {
		t.Errorf("expected first cipher 0x1301, got 0x%04x", ja3.CipherSuites[0])
	}
	if len(alpn) != 2 || alpn[0] != "h2" || alpn[1] != "http/1.1" {
		t.Errorf("unexpected ALPN: %v", alpn)
	}
	if sni != "example.com" {
		t.Errorf("expected SNI 'example.com', got '%s'", sni)
	}
}

func buildTestExtensions() []byte {
	var ext []byte

	// SNI extension (0x0000)
	sniPayload := buildSNIExtension("example.com")
	ext = append(ext, 0x00, 0x00) // type
	ext = append(ext, byte(len(sniPayload)>>8), byte(len(sniPayload)))
	ext = append(ext, sniPayload...)

	// Supported groups (0x000a): x25519 (0x001d), secp256r1 (0x0017)
	groupsPayload := []byte{0x00, 0x04, 0x00, 0x1d, 0x00, 0x17}
	ext = append(ext, 0x00, 0x0a)
	ext = append(ext, byte(len(groupsPayload)>>8), byte(len(groupsPayload)))
	ext = append(ext, groupsPayload...)

	// EC point formats (0x000b): uncompressed (0x00)
	ecPayload := []byte{0x01, 0x00}
	ext = append(ext, 0x00, 0x0b)
	ext = append(ext, byte(len(ecPayload)>>8), byte(len(ecPayload)))
	ext = append(ext, ecPayload...)

	// ALPN (0x0010): h2, http/1.1
	alpnPayload := buildALPNExtension("h2", "http/1.1")
	ext = append(ext, 0x00, 0x10)
	ext = append(ext, byte(len(alpnPayload)>>8), byte(len(alpnPayload)))
	ext = append(ext, alpnPayload...)

	return ext
}

func buildSNIExtension(hostname string) []byte {
	nameBytes := []byte(hostname)
	nameLen := len(nameBytes)
	// ServerNameList: list_length(2) + name_type(1) + name_length(2) + name
	listLen := 1 + 2 + nameLen
	payload := make([]byte, 0, 2+listLen)
	payload = append(payload, byte(listLen>>8), byte(listLen))
	payload = append(payload, 0x00) // host_name type
	payload = append(payload, byte(nameLen>>8), byte(nameLen))
	payload = append(payload, nameBytes...)
	return payload
}

func buildALPNExtension(protocols ...string) []byte {
	var nameList []byte
	for _, p := range protocols {
		nameList = append(nameList, byte(len(p)))
		nameList = append(nameList, []byte(p)...)
	}
	payload := make([]byte, 0, 2+len(nameList))
	payload = append(payload, byte(len(nameList)>>8), byte(len(nameList)))
	payload = append(payload, nameList...)
	return payload
}
