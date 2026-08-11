package agentcreds

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

const (
	testJobID  = "5f2b1c7a-9c3e-4a1f-8b6d-2e7c1a4d9f30"
	testSecret = "reg-key-9d3f5c8a"
)

func testCreds() map[string]interface{} {
	return map[string]interface{}{
		"username":             "admin",
		"password":             "s3cr3t-p@ss",
		"management_url":       "https://bigip.example.test",
		"device_type":          "f5",
		"insecure_skip_verify": true,
	}
}

// TestRoundTrip is the base guarantee: what Seal produces, Open recovers.
func TestRoundTrip(t *testing.T) {
	sealed, err := Seal(testCreds(), testJobID, testSecret)
	if err != nil {
		t.Fatalf("Seal = %v, want nil", err)
	}
	if !IsSealed(sealed) {
		t.Fatalf("Seal produced %v, which IsSealed rejects", sealed)
	}
	if len(sealed) != 1 {
		t.Fatalf("envelope has %d fields, want exactly 1 (%s)", len(sealed), EnvelopeField)
	}

	got, err := Open(sealed, testJobID, testSecret)
	if err != nil {
		t.Fatalf("Open = %v, want nil", err)
	}
	if got["username"] != "admin" || got["password"] != "s3cr3t-p@ss" {
		t.Fatalf("Open returned %v, want the original credentials", got)
	}
	if got["insecure_skip_verify"] != true {
		t.Fatalf("insecure_skip_verify = %v, want true", got["insecure_skip_verify"])
	}
}

// TestEnvelopeFieldName pins the wire key. Renaming it silently breaks every
// deployed agent: the agent treats an unrecognised payload as plaintext and
// proceeds with garbage rather than failing loudly.
func TestEnvelopeFieldName(t *testing.T) {
	if EnvelopeField != "encrypted_data" {
		t.Fatalf("EnvelopeField = %q, want %q — this is the on-wire contract with every deployed device agent", EnvelopeField, "encrypted_data")
	}
	sealed, err := Seal(testCreds(), testJobID, testSecret)
	if err != nil {
		t.Fatalf("Seal = %v, want nil", err)
	}
	raw, err := json.Marshal(sealed)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	var onWire map[string]json.RawMessage
	if err := json.Unmarshal(raw, &onWire); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if _, ok := onWire["encrypted_data"]; !ok {
		t.Fatalf("serialised envelope = %s, want a top-level \"encrypted_data\" string", raw)
	}
}

// TestDerivedKeyIsPinned locks the key derivation to
// SHA-256(jobID || 0x00 || secret). Both sides derive independently, so a change
// here on one side alone means every envelope fails to open — with an opaque
// "message authentication failed", which is exactly the kind of failure that
// costs a day. Decrypting a vector built by hand (not via Seal) proves the
// derivation itself, not just that Seal and Open agree with each other.
func TestDerivedKeyIsPinned(t *testing.T) {
	key := DeriveKey(testJobID, testSecret)
	if len(key) != 32 {
		t.Fatalf("DeriveKey returned %d bytes, want 32 (AES-256)", len(key))
	}

	plaintext := []byte(`{"username":"admin","password":"s3cr3t-p@ss"}`)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize()) // deterministic vector
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	envelope := map[string]interface{}{
		EnvelopeField: base64.StdEncoding.EncodeToString(ciphertext),
	}
	got, err := Open(envelope, testJobID, testSecret)
	if err != nil {
		t.Fatalf("Open(hand-built vector) = %v, want nil — the key derivation changed", err)
	}
	if got["password"] != "s3cr3t-p@ss" {
		t.Fatalf("Open(hand-built vector) = %v, want the pinned credentials", got)
	}
}

// TestLegacyEmptySecretDerivation pins the job-id-only fallback, which
// already-deployed agent binaries rely on.
func TestLegacyEmptySecretDerivation(t *testing.T) {
	sealed, err := Seal(testCreds(), testJobID, "")
	if err != nil {
		t.Fatalf("Seal = %v, want nil", err)
	}
	got, err := Open(sealed, testJobID, "")
	if err != nil {
		t.Fatalf("Open = %v, want nil", err)
	}
	if got["username"] != "admin" {
		t.Fatalf("Open = %v, want the original credentials", got)
	}
	// The two derivations must not collide, or binding to the registration key
	// would buy nothing.
	if string(DeriveKey(testJobID, "")) == string(DeriveKey(testJobID, testSecret)) {
		t.Fatal("empty-secret and keyed derivations produced the same key")
	}
}

// TestWrongSecretFails — the envelope must be openable only by the agent it was
// sealed for. Without this, any agent that intercepted a job could read another
// agent's device credentials.
func TestWrongSecretFails(t *testing.T) {
	sealed, err := Seal(testCreds(), testJobID, testSecret)
	if err != nil {
		t.Fatalf("Seal = %v, want nil", err)
	}
	if _, err := Open(sealed, testJobID, "some-other-agents-key"); err == nil {
		t.Fatal("Open succeeded with the wrong agent secret, want failure")
	}
}

// TestWrongJobIDFails — binding to the job id means a captured envelope cannot
// be replayed onto a different job.
func TestWrongJobIDFails(t *testing.T) {
	sealed, err := Seal(testCreds(), testJobID, testSecret)
	if err != nil {
		t.Fatalf("Seal = %v, want nil", err)
	}
	if _, err := Open(sealed, "00000000-0000-0000-0000-000000000000", testSecret); err == nil {
		t.Fatal("Open succeeded with the wrong job id, want failure")
	}
}

// TestOpenRejectsUnsealed — a non-envelope must be reported as such, so callers
// choose deliberately what to do rather than silently treating whatever arrived
// as credentials.
func TestOpenRejectsUnsealed(t *testing.T) {
	for name, payload := range map[string]map[string]interface{}{
		"plaintext credentials": {"username": "admin", "password": "hunter2"},
		"legacy nested shape":   {"_job_key": "abc", "config": map[string]interface{}{"password": "x"}},
		"empty envelope field":  {EnvelopeField: ""},
		"empty map":             {},
	} {
		if _, err := Open(payload, testJobID, testSecret); !errors.Is(err, ErrNotSealed) {
			t.Fatalf("Open(%s) = %v, want ErrNotSealed", name, err)
		}
		if IsSealed(payload) {
			t.Fatalf("IsSealed(%s) = true, want false", name)
		}
	}
}

// TestTamperedCiphertextFails — GCM authenticates, so a modified envelope must
// fail rather than yield attacker-chosen credentials.
func TestTamperedCiphertextFails(t *testing.T) {
	sealed, err := Seal(testCreds(), testJobID, testSecret)
	if err != nil {
		t.Fatalf("Seal = %v, want nil", err)
	}
	raw, err := base64.StdEncoding.DecodeString(sealed[EnvelopeField].(string))
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	raw[len(raw)-1] ^= 0xff
	sealed[EnvelopeField] = base64.StdEncoding.EncodeToString(raw)

	if _, err := Open(sealed, testJobID, testSecret); err == nil {
		t.Fatal("Open accepted a tampered envelope, want failure")
	}
}

// TestNoncesAreUnique — a repeated nonce under the same key breaks GCM
// completely. Sealing the same credentials for the same job twice must not
// produce identical bytes.
func TestNoncesAreUnique(t *testing.T) {
	a, err := Seal(testCreds(), testJobID, testSecret)
	if err != nil {
		t.Fatalf("Seal = %v, want nil", err)
	}
	b, err := Seal(testCreds(), testJobID, testSecret)
	if err != nil {
		t.Fatalf("Seal = %v, want nil", err)
	}
	if a[EnvelopeField] == b[EnvelopeField] {
		t.Fatal("two seals produced identical ciphertext — the nonce is not random")
	}
}

// TestClear empties the map so secrets stop being reachable.
func TestClear(t *testing.T) {
	creds := testCreds()
	Clear(creds)
	if len(creds) != 0 {
		t.Fatalf("Clear left %d entries: %v", len(creds), creds)
	}
}
