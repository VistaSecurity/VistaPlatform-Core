package handlers

import (
	"strings"
	"testing"

	awsclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/aws"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

const awsAuthTestKey = "unit-test-master-key-0123456789abcdef"

// isolateAWSAuthEnv keeps credential resolution off the developer's ~/.aws and
// off IMDS so these tests make no network calls.
func isolateAWSAuthEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_CONFIG_FILE", "/dev/null")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_SESSION_TOKEN", "")
}

// ---------------------------------------------------------------------------
// Fix 3: validateIntegrationConfig
//
// MUTATION-VERIFIED: the assume_role subtests fail against the pre-fix code,
// which unconditionally required access_key_id and secret_access_key for AWS.
// ---------------------------------------------------------------------------

func TestValidateIntegrationConfig_AWSAuthModes(t *testing.T) {
	cases := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
	}{
		// Unchanged behavior for every existing row.
		{"absent auth_mode with both keys", map[string]interface{}{
			"access_key_id": "A", "secret_access_key": "S"}, false},
		{"absent auth_mode missing secret", map[string]interface{}{
			"access_key_id": "A"}, true},
		{"absent auth_mode missing key id", map[string]interface{}{
			"secret_access_key": "S"}, true},
		{"explicit access_key mode missing both", map[string]interface{}{
			"auth_mode": "access_key"}, true},
		{"explicit access_key mode with both", map[string]interface{}{
			"auth_mode": "access_key", "access_key_id": "A", "secret_access_key": "S"}, false},

		// New: assume_role needs the ARN, not the keys.
		{"assume_role without any access keys", map[string]interface{}{
			"auth_mode": "assume_role", "assume_role_arn": "arn:aws:iam::111122223333:role/R"}, false},
		{"assume_role with external id and no keys", map[string]interface{}{
			"auth_mode": "assume_role", "assume_role_arn": "arn:aws:iam::111122223333:role/R",
			"external_id": "vista-ext-1234"}, false},
		{"assume_role chained onto static keys", map[string]interface{}{
			"auth_mode": "assume_role", "assume_role_arn": "arn:aws:iam::111122223333:role/R",
			"access_key_id": "A", "secret_access_key": "S"}, false},
		{"assume_role missing arn", map[string]interface{}{
			"auth_mode": "assume_role", "external_id": "vista-ext-1234"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateIntegrationConfig("aws", tc.config)
			if tc.wantErr && err == nil {
				t.Fatal("want error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("want no error, got %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Fix 4: external_id is a shared secret — encrypted at rest and masked in
// responses. assume_role_arn is neither.
//
// MUTATION-VERIFIED: fails against the pre-fix code, where the handler's
// sensitiveKeys list omitted external_id and stored it verbatim.
// ---------------------------------------------------------------------------

func TestEncryptConfig_ExternalIDIsEncryptedAndRoleARNIsNot(t *testing.T) {
	h := &IntegrationHandlers{encryptionKey: awsAuthTestKey}

	plain := map[string]interface{}{
		"auth_mode":         "assume_role",
		"assume_role_arn":   "arn:aws:iam::111122223333:role/VistaDiscovery",
		"external_id":       "vista-ext-1234",
		"access_key_id":     "AKIATEST",
		"secret_access_key": "secret",
		"region":            "us-east-1",
	}

	enc, err := h.encryptConfig(plain)
	if err != nil {
		t.Fatalf("encryptConfig: %v", err)
	}

	if enc["external_id"] == "vista-ext-1234" {
		t.Fatal("external_id stored in PLAINTEXT — it is a shared secret and half of the assume-role authorization decision")
	}
	if enc["assume_role_arn"] != plain["assume_role_arn"] {
		t.Errorf("assume_role_arn was transformed (%v) — a role ARN is not a secret and the UI displays it", enc["assume_role_arn"])
	}
	if enc["auth_mode"] != "assume_role" {
		t.Errorf("auth_mode = %v, want passthrough", enc["auth_mode"])
	}

	// Round-trips back out.
	dec, err := h.decryptConfig(enc)
	if err != nil {
		t.Fatalf("decryptConfig: %v", err)
	}
	if dec["external_id"] != "vista-ext-1234" {
		t.Errorf("external_id round-trip = %v, want vista-ext-1234", dec["external_id"])
	}

	// And the encrypted value really is our ciphertext.
	svc, err := encryption.NewService(awsAuthTestKey)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if got, err := svc.Decrypt(enc["external_id"].(string)); err != nil || got != "vista-ext-1234" {
		t.Errorf("stored external_id did not decrypt to the original: %q, %v", got, err)
	}
}

func TestMaskSensitiveFields_MasksExternalIDNotRoleARN(t *testing.T) {
	masked := maskSensitiveFields(map[string]interface{}{
		"external_id":     "vista-ext-1234",
		"assume_role_arn": "arn:aws:iam::111122223333:role/VistaDiscovery",
	})
	if masked["external_id"] == "vista-ext-1234" {
		t.Error("external_id returned unmasked in the API response")
	}
	if masked["assume_role_arn"] != "arn:aws:iam::111122223333:role/VistaDiscovery" {
		t.Errorf("assume_role_arn was masked (%v) — the UI needs to display it", masked["assume_role_arn"])
	}
}

// A row written before external_id was classified sensitive holds plaintext.
// The read path must still load it rather than blowing up the integration.
func TestDecryptConfig_LegacyPlaintextExternalID(t *testing.T) {
	h := &IntegrationHandlers{encryptionKey: awsAuthTestKey}
	dec, err := h.decryptConfig(map[string]interface{}{
		"external_id": "vista-ext-plaintext-legacy",
	})
	if err != nil {
		t.Fatalf("decryptConfig: %v", err)
	}
	if dec["external_id"] != "vista-ext-plaintext-legacy" {
		t.Errorf("external_id = %v, want the stored plaintext", dec["external_id"])
	}
}

// The handler's sensitive-key list must agree with the AWS client's, since a
// key encrypted by one and not decrypted by the other is an invisible break.
func TestSensitiveKeys_AWSHalfComesFromTheClientPackage(t *testing.T) {
	has := func(k string) bool {
		for _, s := range sensitiveKeys {
			if s == k {
				return true
			}
		}
		return false
	}
	for _, k := range awsclient.SensitiveConfigKeys {
		if !has(k) {
			t.Errorf("handler sensitiveKeys is missing %q, which awsclient encrypts/decrypts", k)
		}
	}
	if has("assume_role_arn") {
		t.Error("assume_role_arn must not be in sensitiveKeys")
	}
}

// ---------------------------------------------------------------------------
// Fix 5: Test Connection goes through the same client construction as discovery.
// ---------------------------------------------------------------------------

// MUTATION-VERIFIED: against the pre-fix testAWSConnection this returns
// "Missing AWS credentials" (it required access_key_id + secret_access_key
// before doing anything), so the assume_role path could never even be attempted.
func TestTestAWSConnection_AssumeRoleReachesCredentialResolution(t *testing.T) {
	isolateAWSAuthEnv(t)

	res := testAWSConnection(map[string]interface{}{
		"auth_mode":       "assume_role",
		"assume_role_arn": "arn:aws:iam::111122223333:role/VistaDiscovery",
		"external_id":     "vista-ext-1234",
		"region":          "us-east-1",
	})

	if res.Success {
		t.Fatal("unexpected success — no credentials are available in the test environment")
	}
	if strings.Contains(res.Message, "Missing AWS credentials") {
		t.Fatalf("assume_role integration rejected before credential resolution: %q — Test Connection is not using the discovery client's construction path", res.Message)
	}
	// It got as far as actually trying to authenticate.
	if !strings.Contains(res.Message, "AWS authentication failed") {
		t.Errorf("unexpected message %q, want an authentication failure from the STS call", res.Message)
	}
}

// assume_role WITHOUT an ARN is the one thing that should still be rejected up
// front, and via the shared validator's message.
func TestTestAWSConnection_AssumeRoleWithoutARNRejected(t *testing.T) {
	isolateAWSAuthEnv(t)

	res := testAWSConnection(map[string]interface{}{
		"auth_mode": "assume_role",
		"region":    "us-east-1",
	})
	if res.Success {
		t.Fatal("want failure")
	}
	if !strings.Contains(res.Message, "assume_role_arn") {
		t.Errorf("message = %q, want it to name the missing assume_role_arn", res.Message)
	}
}

// Existing access_key integrations keep their pre-change behavior: no keys means
// a fast, local rejection with no STS call.
func TestTestAWSConnection_AccessKeyModeStillRequiresBothKeys(t *testing.T) {
	isolateAWSAuthEnv(t)

	for _, cfg := range []map[string]interface{}{
		{},
		{"access_key_id": "AKIATEST"},
		{"secret_access_key": "secret"},
	} {
		res := testAWSConnection(cfg)
		if res.Success {
			t.Fatalf("want failure for %v", cfg)
		}
		if !strings.Contains(res.Message, "Missing AWS credentials") {
			t.Errorf("message = %q for %v, want a Missing AWS credentials rejection", res.Message, cfg)
		}
	}
}
