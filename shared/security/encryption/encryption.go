package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// Ciphertext versioning gives us a key-rotation path without breaking data at
// rest. Ciphertext is prefixed with its version byte so Decrypt can select the
// right derivation.
//
// v0 (no version byte, PBKDF2) and v1 (0x01, HKDF) are GONE. Their
// domain-separation constants embedded a retired product name, and that name
// cannot be changed in place — the salt and info are HKDF inputs, so editing a
// byte changes the key. Keeping them for backwards compatibility would have
// meant keeping the name, which is the thing being removed.
//
// Dropping them was affordable exactly once: there are no customers and no
// public deployments, so the only ciphertext in existence is test data in our
// own labs. Anything written under v0 or v1 now fails to decrypt with a clear
// error rather than silently returning garbage — see Decrypt.
const versionV2 byte = 0x02

// HKDF-SHA256 domain-separation parameters for the v1 data key. The salt is a
// fixed, non-secret application constant on purpose: HKDF does not require a
// secret or random salt when the input keying material is already high-entropy
// (ENCRYPTION_MASTER_KEY is meant to be a 32-byte random value), and a fixed
// salt keeps derivation deterministic so we never have to persist a per-record
// salt. The info string binds the key to this specific use.
var (
	// DO NOT EDIT THESE TWO STRINGS.
	//
	// They are cryptographic domain-separation constants, not branding. They are
	// HKDF inputs, so changing a single byte changes every derived key and every
	// credential encrypted under the old one becomes permanently undecryptable —
	// integration credentials, SMTP passwords, cloud connector secrets, sensor CA
	// keys. TestV2KeyKnownAnswer pins them for exactly that reason, and it has
	// already caught one repo-wide rename that rewrote them by accident.
	//
	// The "v2" is the version handle. If they ever must change again, add v3 and
	// a migration rather than editing these in place.
	hkdfSalt = []byte("vistaplatform/encryption/hkdf-sha256/v2/salt")
	hkdfInfo = "vistaplatform/encryption/integration-credentials/v2"
)

// Service handles encryption/decryption of integration credentials using
// AES-256-GCM. New data is encrypted under a key derived from the master key
// with HKDF-SHA256 (v1). Data written before this change — derived with the old
// low-iteration PBKDF2 scheme (v0) — is still transparently decrypted.
type Service struct {
	keyV2 []byte // HKDF-SHA256 — the only key; used for Encrypt and Decrypt
}

// NewService derives the encryption keys from the supplied master key.
//
// ENCRYPTION_MASTER_KEY is expected to be a 32-byte high-entropy random value,
// so the v1 key is derived with HKDF-SHA256, which is the right KDF for a
// high-entropy secret (PBKDF2's iteration count only buys anything against a
// low-entropy/password input). The legacy v0 key is retained solely so
// ciphertext written before this change still decrypts.
func NewService(masterKey string) (*Service, error) {
	if masterKey == "" {
		return nil, errors.New("master key is required")
	}

	keyV2, err := hkdf.Key(sha256.New, []byte(masterKey), hkdfSalt, hkdfInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive v2 key: %w", err)
	}

	return &Service{keyV2: keyV2}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM under the v1 (HKDF) key and
// returns base64( versionV2 || nonce || ciphertext ).
func (s *Service) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	sealed, err := gcmSeal(s.keyV2, []byte(plaintext))
	if err != nil {
		return "", err
	}

	out := make([]byte, 0, 1+len(sealed))
	out = append(out, versionV2)
	out = append(out, sealed...)
	return base64.StdEncoding.EncodeToString(out), nil
}

// Decrypt decrypts a base64-encoded ciphertext written under the current key
// version. Ciphertext from a retired version is reported as such rather than
// failing as a generic decrypt error.
func (s *Service) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	if len(data) == 0 || data[0] != versionV2 {
		// Almost certainly v0/v1 ciphertext, whose keys no longer exist. Say so
		// plainly: the value has to be re-entered, and an operator staring at
		// "failed to decrypt" would otherwise go looking for a corrupted record.
		return "", errors.New(
			"ciphertext was written under a retired key version and cannot be decrypted; " +
				"re-enter the credential to store it under the current key")
	}

	pt, err := gcmOpen(s.keyV2, data[1:])
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}
	return string(pt), nil
}

// HashValue returns a SHA-256 hash hex digest for comparison without exposing raw values.
func (s *Service) HashValue(value string) string {
	hash := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", hash)
}

// gcmSeal returns nonce || AES-256-GCM(plaintext) under key, with a fresh
// random nonce prepended (the GCM standard 12-byte nonce).
func gcmSeal(key, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// gcmOpen parses nonce || ciphertext and decrypts it under key.
func gcmOpen(key, data []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertextBytes, nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return gcm, nil
}
