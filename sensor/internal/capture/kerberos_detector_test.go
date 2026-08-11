package capture

import (
	"testing"
)

// buildASN1Integer builds a DER-encoded INTEGER TLV
func buildASN1Integer(val int) []byte {
	if val >= 0 && val <= 127 {
		return []byte{0x02, 0x01, byte(val)}
	}
	if val >= 128 && val <= 32767 {
		return []byte{0x02, 0x02, byte(val >> 8), byte(val)}
	}
	// Negative values (e.g., -133, -134)
	if val < 0 && val >= -128 {
		return []byte{0x02, 0x01, byte(val)}
	}
	if val < -128 && val >= -32768 {
		return []byte{0x02, 0x02, byte(val >> 8), byte(val)}
	}
	return []byte{0x02, 0x01, 0x00}
}

// buildASN1Sequence wraps data in a SEQUENCE TLV
func buildASN1Sequence(data []byte) []byte {
	return append([]byte{0x30, byte(len(data))}, data...)
}

// buildASN1Context wraps data in a context-specific constructed tag
func buildASN1Context(tag int, data []byte) []byte {
	return append([]byte{byte(0xA0 | tag), byte(len(data))}, data...)
}

// buildASN1App wraps data in an application constructed tag
func buildASN1App(tag int, data []byte) []byte {
	return append([]byte{byte(0x60 | tag), byte(len(data))}, data...)
}

// buildMinimalASREQ builds a minimal AS-REQ with etypes
func buildMinimalASREQ(etypes []int) []byte {
	// Build etype SEQUENCE OF INTEGER
	var etypeInts []byte
	for _, e := range etypes {
		etypeInts = append(etypeInts, buildASN1Integer(e)...)
	}
	etypeSeq := buildASN1Sequence(etypeInts)

	// Wrap in context [8] (etype field of KDC-REQ-BODY)
	etypeCtx := buildASN1Context(8, etypeSeq)

	// Wrap in SEQUENCE (KDC-REQ-BODY)
	reqBody := buildASN1Sequence(etypeCtx)

	// Wrap in context [4] (req-body field of KDC-REQ)
	reqBodyCtx := buildASN1Context(4, reqBody)

	// Wrap in SEQUENCE (KDC-REQ)
	kdcReq := buildASN1Sequence(reqBodyCtx)

	// Wrap in Application [10] (AS-REQ)
	return buildASN1App(10, kdcReq)
}

func TestParseKerberosPacket_ASREQ(t *testing.T) {
	t.Parallel()

	data := buildMinimalASREQ([]int{18, 17, 23})
	d := parseKerberosPacket(data, "10.0.0.1", "10.0.0.2", 12345, 88, "sensor-1", "eth0")
	if d == nil {
		t.Fatal("expected discovery, got nil")
	}
	if d.Protocol != "Kerberos" {
		t.Errorf("expected Protocol=Kerberos, got %s", d.Protocol)
	}
	if d.Version != "Kerberos 5" {
		t.Errorf("expected Version=Kerberos 5, got %s", d.Version)
	}
	if d.CipherSuite != "AES256-CTS-HMAC-SHA1-96" {
		t.Errorf("expected CipherSuite=AES256-CTS-HMAC-SHA1-96, got %s", d.CipherSuite)
	}
	if d.Confidence != 0.90 {
		t.Errorf("expected Confidence=0.90, got %f", d.Confidence)
	}

	etypes, ok := d.RawMetadata["kerberos_etypes"].([]int)
	if !ok || len(etypes) != 3 {
		t.Fatalf("expected 3 etypes, got %v", d.RawMetadata["kerberos_etypes"])
	}
	if etypes[0] != 18 || etypes[1] != 17 || etypes[2] != 23 {
		t.Errorf("unexpected etypes: %v", etypes)
	}

	names, ok := d.RawMetadata["kerberos_etype_names"].([]string)
	if !ok || len(names) != 3 {
		t.Fatalf("expected 3 etype names, got %v", d.RawMetadata["kerberos_etype_names"])
	}
	if names[2] != "RC4-HMAC" {
		t.Errorf("expected RC4-HMAC, got %s", names[2])
	}
}

func TestParseKerberosPacket_TooShort(t *testing.T) {
	t.Parallel()
	d := parseKerberosPacket(make([]byte, 5), "10.0.0.1", "10.0.0.2", 12345, 88, "s", "eth0")
	if d != nil {
		t.Error("expected nil for too-short data")
	}
}

func TestParseKerberosPacket_InvalidTag(t *testing.T) {
	t.Parallel()
	data := make([]byte, 20)
	data[0] = 0x30 // SEQUENCE, not an application tag
	d := parseKerberosPacket(data, "10.0.0.1", "10.0.0.2", 12345, 88, "s", "eth0")
	if d != nil {
		t.Error("expected nil for non-Kerberos tag")
	}
}

func TestKerberosEtypeName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		etype int
		want  string
	}{
		{18, "AES256-CTS-HMAC-SHA1-96"},
		{17, "AES128-CTS-HMAC-SHA1-96"},
		{23, "RC4-HMAC"},
		{3, "DES-CBC-MD5"},
		{24, "RC4-HMAC-EXP"},
		{999, "etype-999"},
	}
	for _, tt := range tests {
		got := kerberosEtypeName(tt.etype)
		if got != tt.want {
			t.Errorf("kerberosEtypeName(%d) = %s, want %s", tt.etype, got, tt.want)
		}
	}
}

func TestParseASN1Length(t *testing.T) {
	t.Parallel()
	tests := []struct {
		data    []byte
		wantLen int
		wantHdr int
	}{
		{[]byte{0x05}, 5, 1},
		{[]byte{0x7F}, 127, 1},
		{[]byte{0x81, 0x80}, 128, 2},
		{[]byte{0x82, 0x01, 0x00}, 256, 3},
		{[]byte{}, 0, 0},
	}
	for _, tt := range tests {
		gotLen, gotHdr := parseASN1Length(tt.data)
		if gotLen != tt.wantLen || gotHdr != tt.wantHdr {
			t.Errorf("parseASN1Length(%v) = (%d, %d), want (%d, %d)",
				tt.data, gotLen, gotHdr, tt.wantLen, tt.wantHdr)
		}
	}
}
