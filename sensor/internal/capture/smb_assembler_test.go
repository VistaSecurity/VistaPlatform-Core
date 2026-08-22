package capture

import (
	"encoding/binary"
	"testing"

	"github.com/vistasecurity/vistaplatform/sensor/internal/smbutil"
)

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
