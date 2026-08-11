package services

import (
	"fmt"

	"github.com/vistasecurity/vistaplatform/shared/agentcreds"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

// sensitiveCredentialFields are the credential keys the platform stores
// encrypted. Kept in sync with encryptCredentialsForJob in handlers/devices.go,
// which is what writes the legacy nested shape.
var sensitiveCredentialFields = []string{
	"password", "api_key", "api_token", "client_secret",
	"access_key_id", "secret_access_key", "token",
}

// masterEncryptedFlag is the marker the embedded-device-credential producer sets
// to say "the sensitive fields in this map are master-key ciphertext".
const masterEncryptedFlag = "encrypted"

// legacyJobKeyField is the master-key-encrypted per-job key used by the older
// platform_integrations credential path.
const legacyJobKeyField = "_job_key"

// legacyConfigField holds the fields encrypted under legacyJobKeyField.
const legacyConfigField = "config"

// NormalizeJobCredentials turns whatever is stored in device_jobs.credentials
// into flat plaintext credentials the agent envelope can carry.
//
// It exists because the platform wrote two mutually incompatible shapes and the
// agent could parse neither:
//
//	{"username", "password": <master ct>, "encrypted": true, ...}
//	    → the agent has no master key, so it read the ciphertext as the password
//	{"_job_key": <master ct>, "config": {"password": <jobkey ct>, ...}}
//	    → the agent's flat lookups never descended into "config", so it ran with
//	      no credentials at all
//
// Both are decoded here, on the platform, where the master key lives. The result
// is sealed for exactly one agent by SealCredentialsForAgent and never persisted
// in this form.
func NormalizeJobCredentials(stored map[string]interface{}, masterKey string) (map[string]interface{}, error) {
	if len(stored) == 0 {
		return map[string]interface{}{}, nil
	}

	// Already canonical (re-poll of a job whose credentials were sealed
	// earlier): nothing to do, the agent opens it directly.
	if agentcreds.IsSealed(stored) {
		return stored, nil
	}

	switch {
	case hasString(stored, legacyJobKeyField):
		return normalizeLegacyJobKeyShape(stored, masterKey)
	case isTrue(stored[masterEncryptedFlag]):
		return normalizeMasterEncryptedShape(stored, masterKey)
	default:
		// Plaintext already (e.g. a job created without stored credentials).
		return copyWithout(stored, masterEncryptedFlag), nil
	}
}

// normalizeMasterEncryptedShape decrypts the sensitive fields of the embedded
// device-credential shape with the platform master key.
func normalizeMasterEncryptedShape(stored map[string]interface{}, masterKey string) (map[string]interface{}, error) {
	enc, err := encryption.NewService(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialise master encryption: %w", err)
	}

	out := copyWithout(stored, masterEncryptedFlag)
	for _, field := range sensitiveCredentialFields {
		s, ok := out[field].(string)
		if !ok || s == "" {
			continue
		}
		plaintext, decErr := enc.Decrypt(s)
		if decErr != nil {
			// A field flagged as encrypted that will not decrypt is a real
			// failure, not something to paper over: shipping the ciphertext on
			// is precisely the bug being fixed, and it surfaces at the far end
			// as an unexplained authentication failure against the device.
			return nil, fmt.Errorf("failed to decrypt credential field %q: %w", field, decErr)
		}
		out[field] = plaintext
	}
	return out, nil
}

// normalizeLegacyJobKeyShape unwraps {_job_key, config} into a flat map.
func normalizeLegacyJobKeyShape(stored map[string]interface{}, masterKey string) (map[string]interface{}, error) {
	masterEnc, err := encryption.NewService(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialise master encryption: %w", err)
	}

	encryptedJobKey, _ := stored[legacyJobKeyField].(string)
	jobKey, err := masterEnc.Decrypt(encryptedJobKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt job credential key: %w", err)
	}
	jobEnc, err := encryption.NewService(jobKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialise job encryption: %w", err)
	}

	config, ok := stored[legacyConfigField].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("legacy credential payload has no %q object", legacyConfigField)
	}

	out := make(map[string]interface{}, len(config)+len(stored))
	for k, v := range config {
		out[k] = v
	}
	// Carry any non-sensitive top-level fields (device_type, management_url…)
	// that sit beside the envelope rather than inside config.
	for k, v := range stored {
		if k == legacyJobKeyField || k == legacyConfigField || k == masterEncryptedFlag {
			continue
		}
		if _, exists := out[k]; !exists {
			out[k] = v
		}
	}

	for _, field := range sensitiveCredentialFields {
		s, ok := out[field].(string)
		if !ok || s == "" {
			continue
		}
		plaintext, decErr := jobEnc.Decrypt(s)
		if decErr != nil {
			return nil, fmt.Errorf("failed to decrypt credential field %q: %w", field, decErr)
		}
		out[field] = plaintext
	}
	return out, nil
}

// SealCredentialsForAgent produces the canonical envelope for one agent.
//
// Sealing happens at hand-off rather than at job creation because that is the
// first moment the platform knows WHICH agent will run the job: unassigned
// device_interrogation jobs are claimed by whichever agent (or the in-cluster
// platform worker) polls first, and the envelope key is bound to the claiming
// agent's registration key so no other agent can open it.
func SealCredentialsForAgent(stored map[string]interface{}, jobID, agentSecret, masterKey string) (map[string]interface{}, error) {
	plain, err := NormalizeJobCredentials(stored, masterKey)
	if err != nil {
		return nil, err
	}
	if len(plain) == 0 {
		return map[string]interface{}{}, nil
	}
	if agentcreds.IsSealed(plain) {
		return plain, nil
	}
	sealed, err := agentcreds.Seal(plain, jobID, agentSecret)
	agentcreds.Clear(plain)
	if err != nil {
		return nil, err
	}
	return sealed, nil
}

func hasString(m map[string]interface{}, key string) bool {
	s, ok := m[key].(string)
	return ok && s != ""
}

func isTrue(v interface{}) bool {
	b, ok := v.(bool)
	return ok && b
}

func copyWithout(m map[string]interface{}, drop ...string) map[string]interface{} {
	skip := make(map[string]struct{}, len(drop))
	for _, d := range drop {
		skip[d] = struct{}{}
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		if _, ok := skip[k]; ok {
			continue
		}
		out[k] = v
	}
	return out
}
