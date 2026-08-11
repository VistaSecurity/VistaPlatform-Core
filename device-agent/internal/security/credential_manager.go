package security

import (
	"encoding/base64"
	"errors"

	"github.com/vistasecurity/vistaplatform/shared/agentcreds"
)

// CredentialManager handles credential decryption for device jobs
type CredentialManager struct {
	// Credentials are decrypted in-memory only and cleared after use
}

// DecryptCredentials decrypts the credential payload the platform attached to a
// job. Credentials are decrypted in-memory only and never stored.
//
// The envelope shape, the key derivation and the crypto all live in
// shared/agentcreds, which the platform links against too — this file is a thin
// agent-side adapter over it. Keeping one implementation is the point: the agent
// and the platform previously each carried their own idea of this payload and
// disagreed three ways, so no remote interrogation needing credentials worked
//
//
// An unsealed map is still accepted and returned as-is, so an agent running
// against an older platform that sends plaintext keeps working.
func DecryptCredentials(encryptedData map[string]interface{}, jobKey, credentialSecret string) (map[string]interface{}, error) {
	creds, err := agentcreds.Open(encryptedData, jobKey, credentialSecret)
	if errors.Is(err, agentcreds.ErrNotSealed) {
		// Backward compatibility: credentials are pre-decrypted by the platform.
		return encryptedData, nil
	}
	if err != nil {
		return nil, err
	}
	return creds, nil
}

// EncryptCredentials seals credentials into the canonical envelope. The platform
// uses shared/agentcreds directly; this wrapper exists for agent-side tests and
// tooling.
func EncryptCredentials(credentials map[string]interface{}, jobKey, credentialSecret string) (map[string]interface{}, error) {
	return agentcreds.Seal(credentials, jobKey, credentialSecret)
}

// DeriveKey derives the AES-256 key for a (jobKey, credentialSecret) pair.
// credentialSecret must be the agent registration key so the key is not
// predictable from the job ID alone.
func DeriveKey(jobKey, credentialSecret string) []byte {
	return agentcreds.DeriveKey(jobKey, credentialSecret)
}

// ClearCredentials clears credentials from memory.
func ClearCredentials(creds map[string]interface{}) {
	agentcreds.Clear(creds)
}

// DecodeBase64 decodes base64-encoded data
func DecodeBase64(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}
