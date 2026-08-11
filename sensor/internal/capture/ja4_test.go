package capture

import (
	"strings"
	"testing"
)

func TestComputeJA4_BasicFormat(t *testing.T) {
	input := JA3Input{
		TLSVersion:           0x0303,
		CipherSuites:         []uint16{0x1301, 0x1302, 0x1303, 0xc02f, 0xc030},
		Extensions:           []uint16{0x0000, 0x000a, 0x000b, 0x0010, 0x002b, 0x000d},
		EllipticCurves:       []uint16{0x001d, 0x0017},
		EllipticCurveFormats: []uint8{0x00},
	}
	alpn := []string{"h2", "http/1.1"}

	ja4 := ComputeJA4(input, alpn, true)

	// Format: t<ver><sni><cipherCount><extCount><alpn>_<hash>_<hash>
	parts := strings.Split(ja4, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4 should have 3 underscore-separated parts, got %d: %s", len(parts), ja4)
	}

	sectionA := parts[0]
	// Should start with "t" (TCP TLS)
	if sectionA[0] != 't' {
		t.Errorf("JA4 section a should start with 't', got '%c'", sectionA[0])
	}
	// Version should be "12" for TLS 1.2
	if sectionA[1:3] != "12" {
		t.Errorf("JA4 version should be '12', got '%s'", sectionA[1:3])
	}
	// SNI indicator should be "d" (domain present)
	if sectionA[3] != 'd' {
		t.Errorf("JA4 SNI should be 'd', got '%c'", sectionA[3])
	}
	// Cipher count: 5 ciphers → "05"
	if sectionA[4:6] != "05" {
		t.Errorf("JA4 cipher count should be '05', got '%s'", sectionA[4:6])
	}
	// Extension count: 6 total - SNI - ALPN = 4 → "04"
	if sectionA[6:8] != "04" {
		t.Errorf("JA4 extension count should be '04', got '%s'", sectionA[6:8])
	}
	// ALPN: first 2 chars of "h2" → "h2"
	if sectionA[8:10] != "h2" {
		t.Errorf("JA4 ALPN should be 'h2', got '%s'", sectionA[8:10])
	}

	// Section b and c should be 12-char hex strings
	if len(parts[1]) != 12 {
		t.Errorf("JA4 section b should be 12 chars, got %d: %s", len(parts[1]), parts[1])
	}
	if len(parts[2]) != 12 {
		t.Errorf("JA4 section c should be 12 chars, got %d: %s", len(parts[2]), parts[2])
	}
}

func TestComputeJA4_NoSNI(t *testing.T) {
	input := JA3Input{
		TLSVersion:   0x0303,
		CipherSuites: []uint16{0x1301},
		Extensions:   []uint16{0x000a},
	}

	ja4 := ComputeJA4(input, nil, false)
	parts := strings.Split(ja4, "_")
	sectionA := parts[0]

	// SNI indicator should be "i" (no SNI)
	if sectionA[3] != 'i' {
		t.Errorf("JA4 SNI should be 'i' when no SNI, got '%c'", sectionA[3])
	}
	// ALPN should be "00"
	if sectionA[8:10] != "00" {
		t.Errorf("JA4 ALPN should be '00' when no ALPN, got '%s'", sectionA[8:10])
	}
}

func TestComputeJA4_GREASEFiltering(t *testing.T) {
	input := JA3Input{
		TLSVersion:   0x0303,
		CipherSuites: []uint16{0x0a0a, 0x1301, 0x1302, 0xfafa},
		Extensions:   []uint16{0x2a2a, 0x000a, 0x000b, 0x3a3a},
	}

	ja4 := ComputeJA4(input, nil, false)
	parts := strings.Split(ja4, "_")
	sectionA := parts[0]

	// Should count only non-GREASE ciphers: 2
	if sectionA[4:6] != "02" {
		t.Errorf("JA4 cipher count should be '02' after GREASE filtering, got '%s'", sectionA[4:6])
	}
	// Should count only non-GREASE, non-SNI, non-ALPN extensions: 2
	if sectionA[6:8] != "02" {
		t.Errorf("JA4 extension count should be '02' after GREASE filtering, got '%s'", sectionA[6:8])
	}
}

func TestComputeJA4_TLS13(t *testing.T) {
	input := JA3Input{
		TLSVersion:   0x0304,
		CipherSuites: []uint16{0x1301},
		Extensions:   []uint16{0x002b},
	}

	ja4 := ComputeJA4(input, nil, true)
	parts := strings.Split(ja4, "_")
	// Version should be "13"
	if parts[0][1:3] != "13" {
		t.Errorf("JA4 version for TLS 1.3 should be '13', got '%s'", parts[0][1:3])
	}
}

func TestComputeJA4QUIC(t *testing.T) {
	input := JA3Input{
		TLSVersion:   0x0304,
		CipherSuites: []uint16{0x1301},
		Extensions:   []uint16{0x002b},
	}

	ja4 := ComputeJA4QUIC(input, []string{"h3"}, true)
	// Should start with "q" instead of "t"
	if ja4[0] != 'q' {
		t.Errorf("JA4 QUIC should start with 'q', got '%c'", ja4[0])
	}
}
