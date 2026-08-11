package discovery

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestKnownBadCAFingerprintsAreLowercaseHexSHA256 is a format guard: the
// ClassifyCertificateFlags lookup hex-encodes a computed sha256.Sum256 via
// encoding/hex, which always produces lowercase output. A key that isn't
// lowercase 64-char hex can never match and would silently make that entry
// dead weight.
func TestKnownBadCAFingerprintsAreLowercaseHexSHA256(t *testing.T) {
	if len(knownBadCAFingerprints) == 0 {
		t.Fatal("knownBadCAFingerprints is empty")
	}
	for fp, name := range knownBadCAFingerprints {
		if name == "" {
			t.Errorf("fingerprint %q has an empty name", fp)
		}
		if len(fp) != 64 {
			t.Errorf("%s: fingerprint %q has length %d, want 64 (32-byte SHA-256 hex-encoded)", name, fp, len(fp))
		}
		if fp != strings.ToLower(fp) {
			t.Errorf("%s: fingerprint %q is not lowercase (hex.EncodeToString never produces uppercase, so this can never match a lookup)", name, fp)
		}
		if _, err := hex.DecodeString(fp); err != nil {
			t.Errorf("%s: fingerprint %q is not valid hex: %v", name, fp, err)
		}
	}
}
