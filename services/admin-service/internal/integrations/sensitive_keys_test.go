package integrations

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/cloudcredentials"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

// admin-service kept its own copy of the secret-key list, and it did not
// encrypt an AWS external_id, an Azure client_id or a GCP service-account key.
// A platform-shared cloud integration created here stored those in plaintext,
// and the discovery client — which decrypts them — then refused the row. The
// list now comes from shared/cloudcredentials, the one the device-interrogation
// handler and the provider clients use.
//
// MUTATION-VERIFIED: restore the old hard-coded list and every provider key it
// lacked is stored in the clear.
func TestEncryptConfig_EncryptsEveryCloudProviderSecret(t *testing.T) {
	enc, err := encryption.NewService("admin-integrations-test-master-key")
	if err != nil {
		t.Fatal(err)
	}
	s := &IntegrationService{encryptionService: enc}
	config := map[string]interface{}{"tenant_id": "directory-id", "subscription_id": "sub-id", "project_id": "project"}
	for _, k := range cloudcredentials.All() {
		config[k] = "plain-" + k
	}
	stored, err := s.encryptConfig(config)
	if err != nil {
		t.Fatalf("encryptConfig: %v", err)
	}
	for _, k := range cloudcredentials.All() {
		if stored[k] == "plain-"+k {
			t.Errorf("%s was stored in plaintext", k)
		}
	}
	for _, k := range []string{"tenant_id", "subscription_id", "project_id"} {
		if stored[k] != config[k] {
			t.Errorf("identifier %s was transformed: %v", k, stored[k])
		}
	}
	back, err := s.decryptConfig(stored)
	if err != nil {
		t.Fatalf("decryptConfig: %v", err)
	}
	for _, k := range cloudcredentials.All() {
		if back[k] != "plain-"+k {
			t.Errorf("%s did not round-trip: %v", k, back[k])
		}
	}
}

// A row this service wrote before the fix holds the newly listed keys in the
// clear. It stays readable; a key that was always encrypted still fails hard.
func TestDecryptConfig_LegacyPlaintextOnlyForNewlyListedKeys(t *testing.T) {
	enc, err := encryption.NewService("admin-integrations-test-master-key")
	if err != nil {
		t.Fatal(err)
	}
	s := &IntegrationService{encryptionService: enc}
	got, err := s.decryptConfig(map[string]interface{}{"external_id": "legacy-plain", "client_id": "legacy-app-id"})
	if err != nil {
		t.Fatalf("a row written before the fix is unreadable: %v", err)
	}
	if got["external_id"] != "legacy-plain" || got["client_id"] != "legacy-app-id" {
		t.Errorf("legacy plaintext not passed through: %v", got)
	}
	if _, err := s.decryptConfig(map[string]interface{}{"secret_access_key": "not-ciphertext"}); err == nil {
		t.Error("a key that was always encrypted accepted plaintext")
	}
}
