package capture

import (
	"encoding/binary"
	"testing"

	"github.com/vistasecurity/vistaplatform/sensor/internal/smbutil"
)

// buildSMB2NegotiateResponse constructs a minimal SMB2 NEGOTIATE Response
// wrapped in a NetBIOS Session header.
func buildSMB2NegotiateResponse(dialect uint16, secMode uint16, caps uint32, encCiphers []uint16) []byte {
	// SMB2 NEGOTIATE Response body (minimum 65 bytes, we use 128 for safety)
	bodySize := 128
	// For 3.1.1 with negotiate contexts, we need more space
	contextBytes := []byte{}
	if dialect == 0x0311 && len(encCiphers) > 0 {
		// Build encryption capabilities context
		//   ContextType(2) + DataLength(2) + Reserved(4) + CipherCount(2) + Ciphers(2*N)
		dataLen := 2 + 2*len(encCiphers)
		ctx := make([]byte, 8+dataLen)
		binary.LittleEndian.PutUint16(ctx[0:2], smbNegotiateContextEncryption)
		binary.LittleEndian.PutUint16(ctx[2:4], uint16(dataLen))
		binary.LittleEndian.PutUint16(ctx[8:10], uint16(len(encCiphers)))
		for i, c := range encCiphers {
			binary.LittleEndian.PutUint16(ctx[10+2*i:12+2*i], c)
		}
		// Pad to 8-byte alignment
		for len(ctx)%8 != 0 {
			ctx = append(ctx, 0)
		}
		contextBytes = ctx
	}

	body := make([]byte, bodySize)
	binary.LittleEndian.PutUint16(body[0:2], 65) // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], secMode)
	binary.LittleEndian.PutUint16(body[4:6], dialect)

	if dialect == 0x0311 {
		binary.LittleEndian.PutUint16(body[6:8], 1) // NegotiateContextCount (MS-SMB2)
		binary.LittleEndian.PutUint32(body[24:28], caps)
		// Negotiate contexts appended after body; offset from start of SMB2 header.
		binary.LittleEndian.PutUint32(body[60:64], uint32(64+len(body)))
	} else {
		binary.LittleEndian.PutUint32(body[24:28], caps)
	}

	// SMB2 header (64 bytes)
	header := make([]byte, 64)
	copy(header[0:4], smb2Magic)
	binary.LittleEndian.PutUint16(header[4:6], 64) // StructureSize
	binary.LittleEndian.PutUint16(header[12:14], smb2CommandNegotiate)
	binary.LittleEndian.PutUint32(header[16:20], 0x01) // Flags: Response

	smb2Packet := append(header, body...)
	smb2Packet = append(smb2Packet, contextBytes...)

	// NetBIOS header: Type(1)=0x00 + Length(3)
	nbHeader := make([]byte, 4)
	nbHeader[0] = 0x00
	pktLen := len(smb2Packet)
	nbHeader[1] = byte(pktLen >> 16)
	nbHeader[2] = byte(pktLen >> 8)
	nbHeader[3] = byte(pktLen)

	return append(nbHeader, smb2Packet...)
}

func TestSMBDialectName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		rev  uint16
		want string
	}{
		{0x0202, "SMB 2.0.2"},
		{0x0210, "SMB 2.1"},
		{0x0300, "SMB 3.0"},
		{0x0302, "SMB 3.0.2"},
		{0x0311, "SMB 3.1.1"},
		{0x0999, "SMB 2.x"},
	}
	for _, tt := range tests {
		got := smbutil.DialectName(tt.rev)
		if got != tt.want {
			t.Errorf("smbutil.DialectName(0x%04X) = %s, want %s", tt.rev, got, tt.want)
		}
	}
}

func TestSMBCipherName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		id   uint16
		want string
	}{
		{smbCipherAES128CCM, "AES-128-CCM"},
		{smbCipherAES128GCM, "AES-128-GCM"},
		{smbCipherAES256CCM, "AES-256-CCM"},
		{smbCipherAES256GCM, "AES-256-GCM"},
		{0xFFFF, "Unknown"},
	}
	for _, tt := range tests {
		got := smbCipherName(tt.id)
		if got != tt.want {
			t.Errorf("smbCipherName(0x%04X) = %s, want %s", tt.id, got, tt.want)
		}
	}
}

func TestParseSMBNegotiateContexts_EncryptionCiphers(t *testing.T) {
	t.Parallel()
	// Build a negotiate context list with encryption capabilities
	// ContextType(2) + DataLength(2) + Reserved(4) + CipherCount(2) + Ciphers...
	data := make([]byte, 16)
	binary.LittleEndian.PutUint16(data[0:2], smbNegotiateContextEncryption)
	binary.LittleEndian.PutUint16(data[2:4], 6) // dataLen: 2 + 2*2 ciphers
	// Reserved: data[4:8] = 0
	binary.LittleEndian.PutUint16(data[8:10], 2) // 2 ciphers
	binary.LittleEndian.PutUint16(data[10:12], smbCipherAES256GCM)
	binary.LittleEndian.PutUint16(data[12:14], smbCipherAES128GCM)

	ciphers := parseSMBNegotiateContexts(data, 0, 1)
	if len(ciphers) != 2 {
		t.Fatalf("expected 2 ciphers, got %d", len(ciphers))
	}
	if ciphers[0] != "AES-256-GCM" || ciphers[1] != "AES-128-GCM" {
		t.Errorf("unexpected ciphers: %v", ciphers)
	}
}
