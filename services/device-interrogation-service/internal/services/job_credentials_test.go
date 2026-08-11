package services

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/agentcreds"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

const testMasterKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func mustEncrypt(t *testing.T, masterKey, plaintext string) string {
	t.Helper()
	enc, err := encryption.NewService(masterKey)
	if err != nil {
		t.Fatalf("encryption.NewService: %v", err)
	}
	ct, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return ct
}

// --- The PLATFORM half of the two-sided credential contract test -----
//
// The agent half is TestCredentialContract_AgentSide_* in
// device-agent/internal/security/credential_contract_test.go. Both open
// agentcreds.ContractVector, the frozen envelope, because the two modules cannot
// import each other and a shared frozen vector is the only thing that can stop
// them drifting apart — which is exactly what happened here, and what happened
// to the sensor and its in-cluster twin before it.

// TestCredentialContract_PlatformSide_OpensFrozenVector proves the platform
// agrees with the agent about the canonical envelope.
func TestCredentialContract_PlatformSide_OpensFrozenVector(t *testing.T) {
	v := agentcreds.ContractVector

	got, err := agentcreds.Open(v.Envelope, v.JobID, v.Secret)
	if err != nil {
		t.Fatalf("Open(frozen vector) = %v, want nil — the platform no longer speaks the canonical envelope", err)
	}
	for k, want := range v.ExpectedCredentials {
		if got[k] != want {
			t.Fatalf("credential %q = %v, want %v", k, got[k], want)
		}
	}
}

// TestCredentialContract_PlatformSide_SealsCanonicalEnvelope is the core
// regression: whatever internal shape the credentials were stored in,
// SealCredentialsForAgent must emit the canonical envelope and nothing else.
func TestCredentialContract_PlatformSide_SealsCanonicalEnvelope(t *testing.T) {
	v := agentcreds.ContractVector

	// The shape the platform actually stores for embedded device credentials.
	stored := map[string]interface{}{
		"username":             "admin",
		"password":             mustEncrypt(t, testMasterKey, "s3cr3t-p@ss"),
		"management_url":       "https://bigip.example.test",
		"device_type":          "f5",
		"insecure_skip_verify": true,
		"encrypted":            true,
	}

	sealed, err := SealCredentialsForAgent(stored, v.JobID, v.Secret, testMasterKey)
	if err != nil {
		t.Fatalf("SealCredentialsForAgent = %v, want nil", err)
	}
	if !agentcreds.IsSealed(sealed) {
		t.Fatalf("SealCredentialsForAgent produced %v, not a canonical envelope", sealed)
	}
	if len(sealed) != 1 {
		t.Fatalf("envelope has %d keys, want exactly 1 — no credential field may travel outside it", len(sealed))
	}

	// The agent's view: open with (job id, registration key).
	got, err := agentcreds.Open(sealed, v.JobID, v.Secret)
	if err != nil {
		t.Fatalf("Open of the platform's envelope = %v, want nil", err)
	}
	if got["password"] != "s3cr3t-p@ss" {
		t.Fatalf("password = %v, want the DECRYPTED password (this is the shipped bug: the agent received ciphertext)", got["password"])
	}
	if got["username"] != "admin" || got["device_type"] != "f5" {
		t.Fatalf("credentials = %v, want username/device_type carried through", got)
	}
	if _, leaked := got["encrypted"]; leaked {
		t.Fatal("the internal \"encrypted\" marker leaked into the agent payload")
	}
}

// TestNormalizeJobCredentials_LegacyJobKeyShape covers the other stored shape:
// {_job_key, config}. The agent looked for "username"/"password" at the top
// level and found nothing, so remote interrogation ran with no credentials.
func TestNormalizeJobCredentials_LegacyJobKeyShape(t *testing.T) {
	jobKeyBytes := make([]byte, 32)
	for i := range jobKeyBytes {
		jobKeyBytes[i] = byte(i)
	}
	jobKey := hex.EncodeToString(jobKeyBytes)

	jobEnc, err := encryption.NewService(jobKey)
	if err != nil {
		t.Fatalf("encryption.NewService(jobKey): %v", err)
	}
	encryptedPassword, err := jobEnc.Encrypt("legacy-p@ss")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	encryptedUsername := "operator" // username is not in sensitiveCredentialFields

	stored := map[string]interface{}{
		"_job_key": mustEncrypt(t, testMasterKey, jobKey),
		"config": map[string]interface{}{
			"username": encryptedUsername,
			"password": encryptedPassword,
			"host":     "10.0.0.9",
		},
		"device_type": "paloalto",
	}

	got, err := NormalizeJobCredentials(stored, testMasterKey)
	if err != nil {
		t.Fatalf("NormalizeJobCredentials = %v, want nil", err)
	}
	if got["password"] != "legacy-p@ss" {
		t.Fatalf("password = %v, want the decrypted value", got["password"])
	}
	if got["username"] != "operator" {
		t.Fatalf("username = %v, want it flattened out of \"config\"", got["username"])
	}
	if got["host"] != "10.0.0.9" {
		t.Fatalf("host = %v, want non-sensitive config fields carried through", got["host"])
	}
	if got["device_type"] != "paloalto" {
		t.Fatalf("device_type = %v, want top-level fields carried through", got["device_type"])
	}
	if _, present := got["_job_key"]; present {
		t.Fatal("_job_key leaked into the normalised credentials")
	}
	if _, present := got["config"]; present {
		t.Fatal("the nested config object survived normalisation")
	}
}

// TestNormalizeJobCredentials_MaskedPasswordIsRejected is the regression for the
// worst part of the defect. GetDevice masks the password before returning it
// (it feeds API responses), and the interrogation handler used that masked value
// as the credential, so the agent received "abcd****wxyz" — a fragment of a
// ciphertext. Such a value cannot decrypt, and normalisation must say so loudly
// rather than pass it on to be tried against a real device.
func TestNormalizeJobCredentials_MaskedPasswordIsRejected(t *testing.T) {
	real := mustEncrypt(t, testMasterKey, "s3cr3t-p@ss")
	masked := real[:4] + "****" + real[len(real)-4:]

	stored := map[string]interface{}{
		"username":  "admin",
		"password":  masked,
		"encrypted": true,
	}

	_, err := NormalizeJobCredentials(stored, testMasterKey)
	if err == nil {
		t.Fatal("NormalizeJobCredentials accepted a masked password, want a decryption error")
	}
	if !strings.Contains(err.Error(), "password") {
		t.Fatalf("error = %v, want it to name the offending field", err)
	}
}

// TestNormalizeJobCredentials_PlaintextPassthrough — a job created without
// stored credentials, or with genuinely plaintext ones, must still work.
func TestNormalizeJobCredentials_PlaintextPassthrough(t *testing.T) {
	stored := map[string]interface{}{"username": "admin", "password": "plain"}
	got, err := NormalizeJobCredentials(stored, testMasterKey)
	if err != nil {
		t.Fatalf("NormalizeJobCredentials = %v, want nil", err)
	}
	if got["password"] != "plain" {
		t.Fatalf("password = %v, want %q", got["password"], "plain")
	}

	empty, err := NormalizeJobCredentials(nil, testMasterKey)
	if err != nil {
		t.Fatalf("NormalizeJobCredentials(nil) = %v, want nil", err)
	}
	if len(empty) != 0 {
		t.Fatalf("NormalizeJobCredentials(nil) = %v, want an empty map", empty)
	}
}

// TestSealCredentialsForAgent_AlreadySealedIsIdempotent — a re-poll of a job
// whose credentials are already canonical must not be double-sealed, which would
// leave the agent unable to open them.
func TestSealCredentialsForAgent_AlreadySealedIsIdempotent(t *testing.T) {
	v := agentcreds.ContractVector

	sealed, err := SealCredentialsForAgent(v.Envelope, v.JobID, v.Secret, testMasterKey)
	if err != nil {
		t.Fatalf("SealCredentialsForAgent = %v, want nil", err)
	}
	got, err := agentcreds.Open(sealed, v.JobID, v.Secret)
	if err != nil {
		t.Fatalf("Open = %v, want nil — an already-sealed payload was sealed twice", err)
	}
	if got["password"] != v.ExpectedCredentials["password"] {
		t.Fatalf("password = %v, want %v", got["password"], v.ExpectedCredentials["password"])
	}
}

// TestSealCredentialsForAgent_BindsToTheClaimingAgent — the envelope must be
// openable only by the agent that claimed the job, so a second agent that
// intercepts the payload cannot read another tenant's device credentials.
func TestSealCredentialsForAgent_BindsToTheClaimingAgent(t *testing.T) {
	v := agentcreds.ContractVector
	stored := map[string]interface{}{
		"username":  "admin",
		"password":  mustEncrypt(t, testMasterKey, "s3cr3t-p@ss"),
		"encrypted": true,
	}

	sealed, err := SealCredentialsForAgent(stored, v.JobID, "agent-A-registration-key", testMasterKey)
	if err != nil {
		t.Fatalf("SealCredentialsForAgent = %v, want nil", err)
	}
	if _, err := agentcreds.Open(sealed, v.JobID, "agent-B-registration-key"); err == nil {
		t.Fatal("a different agent's key opened the envelope, want failure")
	}
	if _, err := agentcreds.Open(sealed, "00000000-0000-0000-0000-000000000000", "agent-A-registration-key"); err == nil {
		t.Fatal("the envelope replayed onto another job id, want failure")
	}
}
