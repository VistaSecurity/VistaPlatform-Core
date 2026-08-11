package encryption

import (
	"encoding/base64"
	"strings"
	"testing"
)

const testMasterKey = "0123456789abcdef0123456789abcdef" // 32 bytes, test-only

// SHA-256 of the v2 HKDF-derived key for testMasterKey. Pins the derivation;
// see TestV2KeyKnownAnswer. Computed from the constants, not asserted by hand.
const v2KeyKnownAnswerHex = "7c8231a295f75b33653c8a367bd826d2ffd6eb7da735731929d73cab776949ac"

func TestV2RoundTrip(t *testing.T) {
	svc, err := NewService(testMasterKey)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	for _, pt := range []string{"hunter2", "a", "unicode: café ☕ — résumé", string(make([]byte, 4096))} {
		ct, err := svc.Encrypt(pt)
		if err != nil {
			t.Fatalf("Encrypt(%q): %v", pt, err)
		}
		got, err := svc.Decrypt(ct)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if got != pt {
			t.Fatalf("round-trip mismatch: got %q want %q", got, pt)
		}
	}
}

func TestEncryptEmitsVersionByte(t *testing.T) {
	svc, _ := NewService(testMasterKey)

	ct, err := svc.Encrypt("secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(ct)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(raw) == 0 || raw[0] != versionV2 {
		t.Fatalf("expected leading version byte 0x%02x, got %x", versionV2, raw)
	}
}

func TestEmptyStringRoundTrips(t *testing.T) {
	svc, _ := NewService(testMasterKey)

	ct, err := svc.Encrypt("")
	if err != nil {
		t.Fatalf("Encrypt(\"\"): %v", err)
	}
	if ct != "" {
		t.Fatalf("expected empty ciphertext for empty plaintext, got %q", ct)
	}
	got, err := svc.Decrypt("")
	if err != nil {
		t.Fatalf("Decrypt(\"\"): %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty plaintext, got %q", got)
	}
}

func TestWrongMasterKeyFails(t *testing.T) {
	enc, _ := NewService(testMasterKey)
	dec, _ := NewService("fedcba9876543210fedcba9876543210")

	ct, err := enc.Encrypt("top secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := dec.Decrypt(ct); err == nil {
		t.Fatal("expected decrypt with wrong master key to fail, got nil error")
	}
}

// Known-answer test: pins the v2 HKDF derivation so an accidental change to the
// salt, info or algorithm is caught. It has already earned its keep once — a
// repo-wide rename rewrote the salt strings, and this is what noticed. Update
// the constant ONLY alongside a deliberate version bump and a migration.
func TestV2KeyKnownAnswer(t *testing.T) {
	svc, _ := NewService(testMasterKey)

	const wantHex = v2KeyKnownAnswerHex
	got := svc.HashValue(string(svc.keyV2)) // SHA-256 of the derived key, hex
	if got != wantHex {
		t.Fatalf("v2 key derivation changed.\n got SHA-256(key)=%s\nwant SHA-256(key)=%s\n"+
			"If this change is intentional, bump the ciphertext version and update the constant.", got, wantHex)
	}
}

// Ciphertext from a retired key version must fail with an explanation an
// operator can act on. The keys for v0 and v1 no longer exist, so the only
// honest answer is "re-enter the credential" — not "failed to decrypt", which
// sends someone hunting for a corrupted record.
func TestRetiredVersionCiphertextIsReportedClearly(t *testing.T) {
	svc, err := NewService(testMasterKey)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	// A v1-tagged payload: right shape, retired version byte.
	legacy := base64.StdEncoding.EncodeToString(append([]byte{0x01}, make([]byte, 40)...))
	if _, err := svc.Decrypt(legacy); err == nil {
		t.Fatal("expected retired-version ciphertext to fail, got nil error")
	} else if !strings.Contains(err.Error(), "re-enter") {
		t.Fatalf("error should tell the operator what to do, got: %v", err)
	}
}
