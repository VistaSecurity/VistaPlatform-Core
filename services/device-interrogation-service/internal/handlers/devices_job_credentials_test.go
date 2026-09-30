package handlers

import (
	"encoding/json"
	"testing"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

// The legacy platform_integrations credential path wrote {_job_key, config}
// with its own list of job-encrypted keys, and the reader
// (services.NormalizeJobCredentials) decrypts a different one: `username` was
// encrypted and never decrypted, so the agent logged in with a ciphertext as
// the username; `token` was left in the clear and the reader refused it. The
// writer now encrypts exactly the reader's list.
//
// MUTATION-VERIFIED: put `username` back on the job-encrypted list (or drop
// `token` from it) and this goes red.
func TestRekeyIntegrationCredentials_RoundTripsThroughTheReader(t *testing.T) {
	const masterKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	enc, err := encryption.NewService(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	password, _ := enc.Encrypt("device-password")
	// What the integrations handler stores: password encrypted, username in
	// the clear (it is not a secret), a token written before tokens were
	// encrypted.
	stored, _ := json.Marshal(map[string]interface{}{
		"username":       "admin",
		"password":       password,
		"token":          "legacy-plain-token",
		"management_url": "https://device.example.test",
	})

	payload, err := rekeyIntegrationCredentialsForJob(string(stored), masterKey)
	if err != nil {
		t.Fatalf("rekey: %v", err)
	}
	// Through the reader, as the platform does at hand-off.
	var roundTripped map[string]interface{}
	raw, _ := json.Marshal(payload)
	_ = json.Unmarshal(raw, &roundTripped)
	got, err := services.NormalizeJobCredentials(roundTripped, masterKey)
	if err != nil {
		t.Fatalf("the reader refused the writer's payload: %v", err)
	}
	for k, want := range map[string]string{
		"username":       "admin",
		"password":       "device-password",
		"token":          "legacy-plain-token",
		"management_url": "https://device.example.test",
	} {
		if got[k] != want {
			t.Errorf("%s = %v, want %q", k, got[k], want)
		}
	}
}
