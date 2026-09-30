package handlers

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	awsclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/aws"
	azureclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/azure"
	gcpclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/gcp"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

// These tests close the loop between the two halves of a cloud integration's
// credential handling: the integrations handler ENCRYPTS the config the UI
// sends, and the provider client DECRYPTS it when a discovery run starts. Each
// side used to keep its own list of which keys are secret. When they drifted
// the failure was invisible until a run: Azure's client demanded ciphertext for
// tenant_id/subscription_id that the handler had always stored in plaintext, so
// every UI-created Azure integration failed with "illegal base64" and Azure
// discovery never executed.
//
// So each test runs the REAL handler encryption (h.encryptConfig) on the exact
// config shape frontend-v2's cloud-modals.tsx submits, marshals it the way
// CreateIntegration does, and hands the bytes to the REAL client constructor.
// A future divergence in either list fails here.

const parityTestKey = "unit-test-master-key-parity-0123456789"

// storeAsHandlerWould encrypts a UI config through the handler and returns the
// JSON the row's `config` column would hold.
func storeAsHandlerWould(t *testing.T, uiConfig map[string]interface{}) string {
	t.Helper()
	h := &IntegrationHandlers{encryptionKey: parityTestKey}
	enc, err := h.encryptConfig(uiConfig)
	if err != nil {
		t.Fatalf("encryptConfig: %v", err)
	}
	b, err := json.Marshal(enc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// Azure: the shape PROVIDER_FIELDS.azure + enumerate_compute produces.
//
// MUTATION-VERIFIED: fails against the pre-fix code with
// "failed to decrypt tenant_id: ... illegal base64" (or subscription_id).
func TestCloudClientParity_AzureUIConfigBuildsClient(t *testing.T) {
	const (
		tenantID = "11111111-2222-3333-4444-555555555555"
		clientID = "66666666-7777-8888-9999-000000000000"
		secret   = "azure-client-secret-value"
		subID    = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	)
	ui := map[string]interface{}{
		"tenant_id":         tenantID,
		"client_id":         clientID,
		"client_secret":     secret,
		"subscription_id":   subID,
		"enumerate_compute": true,
	}
	stored := storeAsHandlerWould(t, ui)

	var storedMap map[string]interface{}
	_ = json.Unmarshal([]byte(stored), &storedMap)
	if storedMap["client_secret"] == secret {
		t.Fatal("client_secret stored in plaintext")
	}
	if storedMap["tenant_id"] != tenantID || storedMap["subscription_id"] != subID {
		t.Errorf("tenant_id/subscription_id were transformed (%v / %v) — they are identifiers, not secrets",
			storedMap["tenant_id"], storedMap["subscription_id"])
	}

	// account_id left blank in the modal → the subscription comes from config.
	client, err := azureclient.NewClientFromStoredConfig(uuid.New(), stored, "", parityTestKey)
	if err != nil {
		t.Fatalf("Azure client could not be built from what the handler stored: %v", err)
	}
	if got := client.GetSubscriptionID(); got != subID {
		t.Errorf("subscription = %q, want %q", got, subID)
	}

	// And every credential field decrypts back to exactly what the user typed.
	svc, _ := encryption.NewService(parityTestKey)
	dec, err := azureclient.DecryptConfigMap(svc, storedMap)
	if err != nil {
		t.Fatalf("DecryptConfigMap: %v", err)
	}
	for k, want := range map[string]string{"tenant_id": tenantID, "client_id": clientID, "client_secret": secret, "subscription_id": subID} {
		if dec[k] != want {
			t.Errorf("%s round-trip = %q, want %q", k, dec[k], want)
		}
	}
}

// Rows already written by the UI before this fix hold plaintext tenant_id /
// subscription_id and encrypted client_id / client_secret. They must work with
// no data migration. The row is built WITHOUT the handler, so this does not
// depend on the handler's current list.
func TestCloudClientParity_AzureExistingRowWorksUnchanged(t *testing.T) {
	svc, err := encryption.NewService(parityTestKey)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	encClientID, _ := svc.Encrypt("66666666-7777-8888-9999-000000000000")
	encSecret, _ := svc.Encrypt("azure-client-secret-value")
	row := map[string]interface{}{
		"tenant_id":         "11111111-2222-3333-4444-555555555555",
		"client_id":         encClientID,
		"client_secret":     encSecret,
		"subscription_id":   "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		"enumerate_compute": true,
	}
	b, _ := json.Marshal(row)

	client, err := azureclient.NewClientFromStoredConfig(uuid.New(), string(b), "", parityTestKey)
	if err != nil {
		t.Fatalf("existing UI-written Azure row no longer builds a client: %v", err)
	}
	if client.GetSubscriptionID() != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
		t.Errorf("subscription = %q", client.GetSubscriptionID())
	}

	// The GET path shows the identifiers and masks the secret.
	h := &IntegrationHandlers{encryptionKey: parityTestKey}
	shown := h.decryptAndMask(row)
	if shown["tenant_id"] != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("tenant_id shown as %v, want plaintext", shown["tenant_id"])
	}
	if shown["client_secret"] == "azure-client-secret-value" || shown["client_secret"] == encSecret {
		t.Errorf("client_secret not masked: %v", shown["client_secret"])
	}
}

const parityGCPServiceAccount = `{"type":"service_account","project_id":"parity-proj","private_key_id":"k1",` +
	`"private_key":"not-parsed-at-construction","client_email":"svc@parity-proj.iam.gserviceaccount.com"}`

// GCP: PROVIDER_FIELDS.gcp uses service_account_json; the validator (and the
// client) also accept service_account_key and credentials_json from API callers.
//
// MUTATION-VERIFIED: the service_account_key and credentials_json cases fail
// against the pre-fix handler, which encrypted only service_account_json, so
// the client's decrypt of the plaintext JSON failed.
func TestCloudClientParity_GCPConfigBuildsClient(t *testing.T) {
	for _, field := range []string{"service_account_json", "service_account_key", "credentials_json"} {
		t.Run(field, func(t *testing.T) {
			ui := map[string]interface{}{
				"project_id":        "parity-proj",
				field:               parityGCPServiceAccount,
				"enumerate_compute": true,
			}
			stored := storeAsHandlerWould(t, ui)

			var storedMap map[string]interface{}
			_ = json.Unmarshal([]byte(stored), &storedMap)
			if storedMap[field] == parityGCPServiceAccount {
				t.Fatalf("%s (a service-account private key) stored in plaintext", field)
			}

			client, err := gcpclient.NewClientFromStoredConfig(uuid.New(), stored, "", parityTestKey)
			if err != nil {
				t.Fatalf("GCP client could not be built from what the handler stored: %v", err)
			}
			if client.GetProjectID() != "parity-proj" {
				t.Errorf("project = %q", client.GetProjectID())
			}
		})
	}
}

// AWS: both auth modes the modal offers. access_key is checked all the way to
// the resolved credentials (static provider — no network).
func TestCloudClientParity_AWSConfigBuildsClient(t *testing.T) {
	isolateAWSAuthEnv(t)

	t.Run("access_key", func(t *testing.T) {
		ui := map[string]interface{}{
			"access_key_id":     "AKIAPARITYTEST",
			"secret_access_key": "parity-secret",
			"auth_mode":         "access_key",
			"enumerate_compute": true,
		}
		stored := storeAsHandlerWould(t, ui)
		client, err := awsclient.NewClientFromStoredConfig(context.Background(), uuid.New(), stored, "111122223333", "us-east-1", parityTestKey)
		if err != nil {
			t.Fatalf("AWS client could not be built from what the handler stored: %v", err)
		}
		creds, err := client.GetConfig().Credentials.Retrieve(context.Background())
		if err != nil {
			t.Fatalf("Retrieve: %v", err)
		}
		if creds.AccessKeyID != "AKIAPARITYTEST" || creds.SecretAccessKey != "parity-secret" {
			t.Errorf("credentials did not round-trip: %q / %q", creds.AccessKeyID, creds.SecretAccessKey)
		}
	})

	t.Run("assume_role", func(t *testing.T) {
		ui := map[string]interface{}{
			"assume_role_arn":   "arn:aws:iam::111122223333:role/VistaDiscovery",
			"external_id":       "vista-ext-parity",
			"role_session_name": "vista-discovery",
			"auth_mode":         "assume_role",
			"enumerate_compute": true,
		}
		stored := storeAsHandlerWould(t, ui)
		if _, err := awsclient.NewClientFromStoredConfig(context.Background(), uuid.New(), stored, "", "", parityTestKey); err != nil {
			t.Fatalf("AWS assume-role client could not be built from what the handler stored: %v", err)
		}
	})
}
