// Package agentcreds defines the ONE canonical wire shape for the credentials
// the platform hands a device agent with an interrogation job, and the only
// implementation of sealing and opening it.
//
// # Why this package exists
//
// The platform and the device agent disagreed about this payload in three
// different ways at once, and every remote interrogation that needed
// credentials failed at the agent as a result:
//
//   - The agent (device-agent/internal/security) expected an envelope
//     {"encrypted_data": "<base64 AES-256-GCM>"}, and treated anything else as
//     already-plaintext credentials.
//   - One platform path sent {"username", "password", "management_url",
//     "device_type", "encrypted": true} where `password` was the DB ciphertext —
//     the "encrypted" flag was never read by anything, and the agent has no
//     access to the platform master key, so it authenticated with ciphertext.
//     Worse, that ciphertext had been through the API's password *masking*
//     helper first, so what actually shipped was `abcd****wxyz`.
//   - The other platform path sent {"_job_key": "<master-key ciphertext>",
//     "config": {...}} with the real fields nested a level down, where the
//     agent's flat lookups for "username"/"password" found nothing at all.
//
// The fix is not to teach either side about the other's shapes. It is to have
// exactly one shape, defined here, that both sides link against — the same
// reason shared/certificates exists for the sensor and its in-cluster twin.
// Contract tests in this package assert the platform's seal and the agent's open
// against each other and against a pinned vector, so the two cannot drift apart
// again.
//
// # Constraints
//
// The device agent cross-compiles for several operating systems with CGO
// disabled, so this package is pure Go and pulls in nothing platform-internal:
// no database, no NATS, no tenant context. It is crypto and encoding only.
//
// # The shape
//
//	{"encrypted_data": "<standard-base64 of nonce || AES-256-GCM ciphertext>"}
//
// The plaintext is a JSON object of credential fields (username, password,
// api_key, token, management_url, insecure_skip_verify, ...). The key is
// SHA-256(jobID || 0x00 || agentSecret), where agentSecret is the agent's
// registration key — a secret the platform and that one agent share, and no
// other agent does. Binding the key to the job id means a captured envelope is
// useless for any other job.
package agentcreds

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// EnvelopeField is the single key of the canonical envelope. Anything else at
// the top level is, by definition, not a sealed credential payload.
const EnvelopeField = "encrypted_data"

// ErrNotSealed reports that a map is not a canonical envelope.
var ErrNotSealed = errors.New("agentcreds: payload is not a sealed credential envelope")

// DeriveKey returns the AES-256 key for a (jobKey, agentSecret) pair.
//
// The empty-agentSecret branch reproduces the agent's original job-id-only
// derivation. It is kept for compatibility with already-deployed agent binaries
// and is deliberately weaker — a job id is not a secret — so callers should
// always pass the agent's registration key.
func DeriveKey(jobKey, agentSecret string) []byte {
	if agentSecret == "" {
		sum := sha256.Sum256([]byte(jobKey))
		return sum[:]
	}
	h := sha256.New()
	_, _ = h.Write([]byte(jobKey))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(agentSecret))
	return h.Sum(nil)
}

// IsSealed reports whether payload is a canonical envelope.
func IsSealed(payload map[string]interface{}) bool {
	if payload == nil {
		return false
	}
	s, ok := payload[EnvelopeField].(string)
	return ok && s != ""
}

// Seal encrypts credentials into the canonical envelope. Called by the platform
// at the moment it hands a job to a specific agent — that is the first point at
// which the agent, and therefore its registration key, is known.
func Seal(credentials map[string]interface{}, jobKey, agentSecret string) (map[string]interface{}, error) {
	plaintext, err := json.Marshal(credentials)
	if err != nil {
		return nil, fmt.Errorf("agentcreds: serialize credentials: %w", err)
	}

	ciphertext, err := encryptAESGCM(plaintext, DeriveKey(jobKey, agentSecret))
	if err != nil {
		return nil, fmt.Errorf("agentcreds: encrypt credentials: %w", err)
	}

	return map[string]interface{}{
		EnvelopeField: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

// Open decrypts a canonical envelope. Returns ErrNotSealed if payload has no
// envelope field, so callers can decide what an unsealed payload means to them
// (the agent still accepts one for backward compatibility with older platforms).
func Open(payload map[string]interface{}, jobKey, agentSecret string) (map[string]interface{}, error) {
	encoded, ok := payload[EnvelopeField].(string)
	if !ok || encoded == "" {
		return nil, ErrNotSealed
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("agentcreds: decode envelope: %w", err)
	}

	plaintext, err := decryptAESGCM(ciphertext, DeriveKey(jobKey, agentSecret))
	if err != nil {
		return nil, fmt.Errorf("agentcreds: decrypt credentials: %w", err)
	}

	var credentials map[string]interface{}
	if err := json.Unmarshal(plaintext, &credentials); err != nil {
		return nil, fmt.Errorf("agentcreds: parse decrypted credentials: %w", err)
	}
	return credentials, nil
}

// Clear zeroes and empties a credentials map to shrink the window in which
// secrets are readable in process memory. Go's GC owns actual deallocation.
func Clear(credentials map[string]interface{}) {
	for k := range credentials {
		credentials[k] = nil
		delete(credentials, k)
	}
}

func encryptAESGCM(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptAESGCM(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("agentcreds: ciphertext too short")
	}
	nonce, body := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, body, nil)
}
