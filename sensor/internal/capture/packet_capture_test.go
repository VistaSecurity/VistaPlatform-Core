package capture

import "testing"

func TestParseSupportedVersionsExt_ServerHello(t *testing.T) {
	// supported_versions extension in ServerHello:
	// extension type (0x002b), extension length (2), selected_version (0x0304)
	ext := []byte{
		0x00, 0x2b,
		0x00, 0x02,
		0x03, 0x04,
	}

	got := parseSupportedVersionsExt(ext, 0, len(ext))
	if got != "TLS 1.3" {
		t.Fatalf("expected TLS 1.3, got %q", got)
	}
}

func TestParseSupportedVersionsExt_ClientHello(t *testing.T) {
	// supported_versions extension in ClientHello:
	// extension type (0x002b), extension length (5),
	// versions length (4), versions: 0x0304, 0x0303
	ext := []byte{
		0x00, 0x2b,
		0x00, 0x05,
		0x04,
		0x03, 0x04,
		0x03, 0x03,
	}

	got := parseSupportedVersionsExt(ext, 0, len(ext))
	if got != "TLS 1.3" {
		t.Fatalf("expected TLS 1.3, got %q", got)
	}
}
