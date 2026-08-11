package security

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/agentcreds"
)

// This is the AGENT half of the two-sided credential contract test for.
// The platform half is TestCredentialContract_PlatformSide in
// services/device-interrogation-service/internal/services/job_credentials_test.go.
// Both open agentcreds.ContractVector — the frozen envelope — so if either side
// changes the wire shape, its own test fails. The two modules cannot import each
// other, so the shared vector is what holds them together.

// TestCredentialContract_AgentSide_OpensFrozenVector proves the agent parses the
// canonical envelope the platform produces.
func TestCredentialContract_AgentSide_OpensFrozenVector(t *testing.T) {
	v := agentcreds.ContractVector

	got, err := DecryptCredentials(v.Envelope, v.JobID, v.Secret)
	if err != nil {
		t.Fatalf("DecryptCredentials(frozen vector) = %v, want nil — the agent no longer parses the canonical envelope", err)
	}
	for k, want := range v.ExpectedCredentials {
		if got[k] != want {
			t.Fatalf("credential %q = %v, want %v", k, got[k], want)
		}
	}
}

// TestCredentialContract_AgentSide_SealIsOpenableByShared proves the agent's own
// sealer emits the canonical shape, so anything it produces is readable by the
// platform's opener.
func TestCredentialContract_AgentSide_SealIsOpenableByShared(t *testing.T) {
	v := agentcreds.ContractVector

	sealed, err := EncryptCredentials(v.ExpectedCredentials, v.JobID, v.Secret)
	if err != nil {
		t.Fatalf("EncryptCredentials = %v, want nil", err)
	}
	if !agentcreds.IsSealed(sealed) {
		t.Fatalf("EncryptCredentials produced %v, which is not the canonical envelope", sealed)
	}

	got, err := agentcreds.Open(sealed, v.JobID, v.Secret)
	if err != nil {
		t.Fatalf("agentcreds.Open of the agent's own envelope = %v, want nil", err)
	}
	if got["password"] != v.ExpectedCredentials["password"] {
		t.Fatalf("round-tripped password = %v, want %v", got["password"], v.ExpectedCredentials["password"])
	}
}

// TestCredentialContract_AgentSide_KeyDerivationMatches — both sides derive the
// key independently, so the derivation itself has to be identical or every
// envelope fails to open with an opaque authentication error.
func TestCredentialContract_AgentSide_KeyDerivationMatches(t *testing.T) {
	v := agentcreds.ContractVector
	if string(DeriveKey(v.JobID, v.Secret)) != string(agentcreds.DeriveKey(v.JobID, v.Secret)) {
		t.Fatal("agent DeriveKey diverged from shared/agentcreds.DeriveKey")
	}
}

// TestCredentialContract_AgentSide_RejectsMasterEncryptedShape is the direct
// regression for the shipped bug: the platform used to send
// {"username", "password": <master ciphertext>, "encrypted": true}. The agent
// has no master key, so the pre-fix code fell through its plaintext branch and
// logged into the device with the ciphertext (in fact with a MASKED fragment of
// it). That shape must never again reach the agent — and if it somehow does, it
// must not be mistaken for usable credentials.
func TestCredentialContract_AgentSide_RejectsMasterEncryptedShape(t *testing.T) {
	legacy := map[string]interface{}{
		"username":  "admin",
		"password":  "abcd****wxyz", // what the platform actually used to send
		"encrypted": true,
	}
	if agentcreds.IsSealed(legacy) {
		t.Fatal("the master-encrypted shape is being treated as a canonical envelope")
	}

	// DecryptCredentials still returns it verbatim for backward compatibility
	// with genuinely-plaintext platforms; the guarantee this test pins is that
	// the platform no longer produces it (see the platform-side contract test),
	// and that the agent does not pretend to have decrypted anything.
	got, err := DecryptCredentials(legacy, agentcreds.ContractVector.JobID, agentcreds.ContractVector.Secret)
	if err != nil {
		t.Fatalf("DecryptCredentials = %v, want nil", err)
	}
	if got["password"] != "abcd****wxyz" {
		t.Fatalf("password = %v; the agent must not claim to have decrypted an unsealed payload", got["password"])
	}
}
