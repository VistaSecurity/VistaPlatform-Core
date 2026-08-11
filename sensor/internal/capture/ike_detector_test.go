package capture

import (
	"encoding/binary"
	"testing"
)

// buildIKEv2SAInit constructs a minimal IKEv2 SA_INIT packet with a SA payload
// containing one proposal with the specified transforms.
func buildIKEv2SAInit(transforms []testTransform) []byte {
	// Build transforms
	var transformBytes []byte
	for i, t := range transforms {
		tb := make([]byte, 8)
		if i < len(transforms)-1 {
			tb[0] = 3 // more transforms
		} else {
			tb[0] = 0 // last transform
		}
		tLen := 8
		var attrs []byte
		if t.keyLen > 0 {
			// Add key length attribute (TV format: AF=1, Type=14)
			attrs = make([]byte, 4)
			binary.BigEndian.PutUint16(attrs[0:2], 0x800E) // AF=1, Type=14
			binary.BigEndian.PutUint16(attrs[2:4], uint16(t.keyLen))
			tLen += 4
		}
		binary.BigEndian.PutUint16(tb[2:4], uint16(tLen))
		tb[4] = t.transformType
		binary.BigEndian.PutUint16(tb[6:8], t.transformID)
		transformBytes = append(transformBytes, tb...)
		transformBytes = append(transformBytes, attrs...)
	}

	// Build proposal: header(8) + transforms
	proposalLen := 8 + len(transformBytes)
	proposal := make([]byte, 8)
	proposal[0] = 0 // last proposal
	binary.BigEndian.PutUint16(proposal[2:4], uint16(proposalLen))
	proposal[4] = 1 // proposal number
	proposal[5] = 1 // protocol ID: IKE
	proposal[6] = 0 // SPI size
	proposal[7] = uint8(len(transforms))
	proposalData := append(proposal, transformBytes...)

	// Build SA payload: generic header(4) + proposal
	saPayloadLen := 4 + len(proposalData)
	saPayload := make([]byte, 4)
	saPayload[0] = 0 // no next payload
	binary.BigEndian.PutUint16(saPayload[2:4], uint16(saPayloadLen))
	saPayloadData := append(saPayload, proposalData...)

	// Build IKE header (28 bytes)
	header := make([]byte, 28)
	// InitiatorSPI (8 bytes) - non-zero
	binary.BigEndian.PutUint64(header[0:8], 0xDEADBEEFCAFEBABE)
	// ResponderSPI (8 bytes) - zero for SA_INIT
	// NextPayload = SA (33)
	header[16] = ikePayloadSA
	// Version = 2.0
	header[17] = 0x20
	// ExchangeType = SA_INIT (34)
	header[18] = ikeExchangeSAInit
	// Flags = Initiator
	header[19] = 0x08
	// MessageID = 0
	// Total length
	totalLen := 28 + len(saPayloadData)
	binary.BigEndian.PutUint32(header[24:28], uint32(totalLen))

	return append(header, saPayloadData...)
}

type testTransform struct {
	transformType uint8
	transformID   uint16
	keyLen        int
}

func TestParseIKEv2SAInit_ExtractsAlgorithms(t *testing.T) {
	t.Parallel()

	transforms := []testTransform{
		{ikeTransformTypeENCR, 20, 256}, // AES-GCM-16-256
		{ikeTransformTypeENCR, 12, 256}, // AES-CBC-256
		{ikeTransformTypePRF, 5, 0},     // PRF-HMAC-SHA2-256
		{ikeTransformTypeINTEG, 12, 0},  // AUTH-HMAC-SHA2-256-128
		{ikeTransformTypeDH, 14, 0},     // MODP-2048
		{ikeTransformTypeDH, 19, 0},     // ECP-256
	}
	data := buildIKEv2SAInit(transforms)

	d := parseIKEHeader(data, "10.0.0.1", "10.0.0.2", 500, 500, "sensor-1", "eth0")
	if d == nil {
		t.Fatal("expected discovery, got nil")
	}

	if d.Protocol != "IPSec" {
		t.Errorf("expected Protocol=IPSec, got %s", d.Protocol)
	}
	if d.Version != "IKEv2" {
		t.Errorf("expected Version=IKEv2, got %s", d.Version)
	}
	if d.CipherSuite != "AES-GCM-16-256" {
		t.Errorf("expected CipherSuite=AES-GCM-16-256, got %s", d.CipherSuite)
	}
	if d.Confidence != 0.90 {
		t.Errorf("expected Confidence=0.90, got %f", d.Confidence)
	}

	// Check extracted algorithms
	encrAlgs, ok := d.RawMetadata["ipsec_encryption_algs"].([]string)
	if !ok || len(encrAlgs) != 2 {
		t.Fatalf("expected 2 encryption algs, got %v", d.RawMetadata["ipsec_encryption_algs"])
	}
	if encrAlgs[0] != "AES-GCM-16-256" || encrAlgs[1] != "AES-CBC-256" {
		t.Errorf("unexpected encryption algs: %v", encrAlgs)
	}

	prfAlgs, ok := d.RawMetadata["ipsec_prf_algs"].([]string)
	if !ok || len(prfAlgs) != 1 || prfAlgs[0] != "PRF-HMAC-SHA2-256" {
		t.Errorf("unexpected PRF algs: %v", d.RawMetadata["ipsec_prf_algs"])
	}

	integAlgs, ok := d.RawMetadata["ipsec_integrity_algs"].([]string)
	if !ok || len(integAlgs) != 1 || integAlgs[0] != "AUTH-HMAC-SHA2-256-128" {
		t.Errorf("unexpected integrity algs: %v", d.RawMetadata["ipsec_integrity_algs"])
	}

	dhGroups, ok := d.RawMetadata["ipsec_dh_groups"].([]string)
	if !ok || len(dhGroups) != 2 {
		t.Fatalf("expected 2 DH groups, got %v", d.RawMetadata["ipsec_dh_groups"])
	}
	if dhGroups[0] != "MODP-2048" || dhGroups[1] != "ECP-256" {
		t.Errorf("unexpected DH groups: %v", dhGroups)
	}
}

func TestParseIKEv2SAInit_ChaCha20(t *testing.T) {
	t.Parallel()

	transforms := []testTransform{
		{ikeTransformTypeENCR, 28, 0}, // ChaCha20-Poly1305
		{ikeTransformTypePRF, 7, 0},   // PRF-HMAC-SHA2-512
		{ikeTransformTypeINTEG, 0, 0}, // NONE (AEAD)
		{ikeTransformTypeDH, 31, 0},   // Curve25519
	}
	data := buildIKEv2SAInit(transforms)

	d := parseIKEHeader(data, "10.0.0.1", "10.0.0.2", 500, 500, "sensor-1", "eth0")
	if d == nil {
		t.Fatal("expected discovery, got nil")
	}
	if d.CipherSuite != "ChaCha20-Poly1305" {
		t.Errorf("expected CipherSuite=ChaCha20-Poly1305, got %s", d.CipherSuite)
	}

	dhGroups := d.RawMetadata["ipsec_dh_groups"].([]string)
	if len(dhGroups) != 1 || dhGroups[0] != "Curve25519" {
		t.Errorf("unexpected DH groups: %v", dhGroups)
	}
}

func TestParseIKEv1HeaderOnly(t *testing.T) {
	t.Parallel()

	// IKEv1 Main Mode — header only, no SA parsing (IKEv1 not yet supported)
	header := make([]byte, 28)
	binary.BigEndian.PutUint64(header[0:8], 0x1111111111111111)
	header[16] = 1    // NextPayload = SA (v1)
	header[17] = 0x10 // Version 1.0
	header[18] = ikeExchangeIdentityProtection
	header[19] = 0
	binary.BigEndian.PutUint32(header[24:28], 28)

	d := parseIKEHeader(header, "10.0.0.1", "10.0.0.2", 500, 500, "sensor-1", "eth0")
	if d == nil {
		t.Fatal("expected discovery, got nil")
	}
	if d.Version != "IKEv1" {
		t.Errorf("expected IKEv1, got %s", d.Version)
	}
	// IKEv1 SA parsing not implemented — should still return a discovery
	if d.CipherSuite != "" {
		t.Errorf("IKEv1 should not have cipher suite parsed yet, got %s", d.CipherSuite)
	}
}

func TestParseIKEHeader_TooShort(t *testing.T) {
	t.Parallel()
	d := parseIKEHeader(make([]byte, 20), "10.0.0.1", "10.0.0.2", 500, 500, "s", "eth0")
	if d != nil {
		t.Error("expected nil for too-short data")
	}
}

func TestParseIKEHeader_InvalidVersion(t *testing.T) {
	t.Parallel()
	header := make([]byte, 28)
	header[17] = 0x30 // Version 3.0 — invalid
	binary.BigEndian.PutUint32(header[24:28], 28)
	d := parseIKEHeader(header, "10.0.0.1", "10.0.0.2", 500, 500, "s", "eth0")
	if d != nil {
		t.Error("expected nil for invalid version")
	}
}

func TestIkeTransformName_WeakAlgorithms(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ttype uint8
		id    uint16
		klen  int
		want  string
	}{
		{ikeTransformTypeENCR, 2, 0, "DES"},
		{ikeTransformTypeENCR, 3, 0, "3DES"},
		{ikeTransformTypeENCR, 11, 0, "NULL"},
		{ikeTransformTypePRF, 1, 0, "PRF-HMAC-MD5"},
		{ikeTransformTypeINTEG, 1, 0, "AUTH-HMAC-MD5-96"},
		{ikeTransformTypeDH, 1, 0, "MODP-768"},
		{ikeTransformTypeDH, 2, 0, "MODP-1024"},
	}
	for _, tt := range tests {
		got := ikeTransformName(tt.ttype, tt.id, tt.klen)
		if got != tt.want {
			t.Errorf("ikeTransformName(%d, %d, %d) = %s, want %s", tt.ttype, tt.id, tt.klen, got, tt.want)
		}
	}
}
