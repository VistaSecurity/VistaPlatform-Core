package aws

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

const testMasterKey = "unit-test-master-key-0123456789abcdef"

// isolateAWSEnv makes credential resolution deterministic: no developer's
// ~/.aws, no IMDS round trip, no ambient keys unless the test sets them.
func isolateAWSEnv(t *testing.T) {
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
// Fix 1: the session token must reach the credentials provider.
//
// MUTATION-VERIFIED: this test fails against the pre-fix code, which passed a
// literal "" as the third argument to credentials.NewStaticCredentialsProvider.
// ---------------------------------------------------------------------------

func TestBuildAWSConfig_SessionTokenReachesCredentialsProvider(t *testing.T) {
	isolateAWSEnv(t)
	ctx := context.Background()

	cfg, err := BuildAWSConfig(ctx, CredentialConfig{
		AccessKeyID:     "AKIATEST",
		SecretAccessKey: "secret",
		SessionToken:    "FwoGZXIvYXdzTESTSESSIONTOKEN",
		Region:          "us-west-2",
	})
	if err != nil {
		t.Fatalf("BuildAWSConfig: %v", err)
	}

	// Assert on the RESOLVED credentials, not merely that a config was built.
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if creds.AccessKeyID != "AKIATEST" {
		t.Errorf("AccessKeyID = %q, want AKIATEST", creds.AccessKeyID)
	}
	if creds.SecretAccessKey != "secret" {
		t.Errorf("SecretAccessKey = %q, want secret", creds.SecretAccessKey)
	}
	if creds.SessionToken != "FwoGZXIvYXdzTESTSESSIONTOKEN" {
		t.Errorf("SessionToken = %q, want the configured token (temporary STS credentials are silently broken when this is dropped)", creds.SessionToken)
	}
	if cfg.Region != "us-west-2" {
		t.Errorf("Region = %q, want us-west-2", cfg.Region)
	}
}

// ---------------------------------------------------------------------------
// Fix 2: AssumeRole, external id, and both chaining shapes.
// ---------------------------------------------------------------------------

// MUTATION-VERIFIED against my own change by dropping the `if c.ExternalID != ""`
// guard (turns the "unset" case into a non-nil pointer to "" and fails) and by
// removing the ExternalID assignment entirely (fails the "set" case).
func TestAssumeRoleOptions_ExternalIDOmittedWhenUnset(t *testing.T) {
	var o stscreds.AssumeRoleOptions
	assumeRoleOptions(CredentialConfig{
		AuthMode:      AuthModeAssumeRole,
		AssumeRoleARN: "arn:aws:iam::111122223333:role/VistaDiscovery",
	})(&o)

	if o.ExternalID != nil {
		t.Fatalf("ExternalID = %q (non-nil), want nil — a pointer to the empty string sends ExternalId=\"\" and AWS rejects it for roles that do not require one", *o.ExternalID)
	}
	if o.RoleSessionName != DefaultRoleSessionName {
		t.Errorf("RoleSessionName = %q, want %q", o.RoleSessionName, DefaultRoleSessionName)
	}
}

func TestAssumeRoleOptions_ExternalIDPassedWhenSet(t *testing.T) {
	var o stscreds.AssumeRoleOptions
	assumeRoleOptions(CredentialConfig{
		AuthMode:        AuthModeAssumeRole,
		AssumeRoleARN:   "arn:aws:iam::111122223333:role/VistaDiscovery",
		ExternalID:      "vista-ext-1234",
		RoleSessionName: "custom-session",
	})(&o)

	if o.ExternalID == nil {
		t.Fatal("ExternalID = nil, want the configured external id")
	}
	if *o.ExternalID != "vista-ext-1234" {
		t.Errorf("ExternalID = %q, want vista-ext-1234", *o.ExternalID)
	}
	if o.RoleSessionName != "custom-session" {
		t.Errorf("RoleSessionName = %q, want custom-session", o.RoleSessionName)
	}
}

// assume_role ON TOP OF static access keys: the returned credentials must be an
// AssumeRole provider (cached), and the base config the STS call is signed with
// must be the configured static keys.
func TestBuildAWSConfig_AssumeRoleWithStaticBaseKeys(t *testing.T) {
	isolateAWSEnv(t)
	ctx := context.Background()

	c := CredentialConfig{
		AuthMode:        AuthModeAssumeRole,
		AccessKeyID:     "AKIABASE",
		SecretAccessKey: "basesecret",
		SessionToken:    "basetoken",
		AssumeRoleARN:   "arn:aws:iam::111122223333:role/VistaDiscovery",
		ExternalID:      "vista-ext-1234",
		Region:          "eu-west-1",
	}

	cfg, err := BuildAWSConfig(ctx, c)
	if err != nil {
		t.Fatalf("BuildAWSConfig: %v", err)
	}

	cache, ok := cfg.Credentials.(*aws.CredentialsCache)
	if !ok {
		t.Fatalf("Credentials is %T, want *aws.CredentialsCache", cfg.Credentials)
	}
	if !cache.IsCredentialsProvider(&stscreds.AssumeRoleProvider{}) {
		t.Fatal("cached provider is not *stscreds.AssumeRoleProvider — assume_role mode did not take effect")
	}

	// The credentials the AssumeRole call itself is signed with.
	base, err := buildBaseConfig(ctx, c)
	if err != nil {
		t.Fatalf("buildBaseConfig: %v", err)
	}
	got, err := base.Credentials.Retrieve(ctx)
	if err != nil {
		t.Fatalf("Retrieve base: %v", err)
	}
	if got.AccessKeyID != "AKIABASE" || got.SessionToken != "basetoken" {
		t.Errorf("base credentials = %q/%q, want AKIABASE/basetoken", got.AccessKeyID, got.SessionToken)
	}
}

// assume_role from the AMBIENT default chain (env / IRSA / IMDS) with no static
// keys configured — the shape most AWS customers will actually use.
func TestBuildAWSConfig_AssumeRoleWithoutStaticBaseKeys(t *testing.T) {
	isolateAWSEnv(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAAMBIENT")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambientsecret")
	ctx := context.Background()

	c := CredentialConfig{
		AuthMode:      AuthModeAssumeRole,
		AssumeRoleARN: "arn:aws:iam::111122223333:role/VistaDiscovery",
		Region:        "us-east-2",
	}

	cfg, err := BuildAWSConfig(ctx, c)
	if err != nil {
		t.Fatalf("BuildAWSConfig with no static keys must succeed in assume_role mode: %v", err)
	}
	cache, ok := cfg.Credentials.(*aws.CredentialsCache)
	if !ok {
		t.Fatalf("Credentials is %T, want *aws.CredentialsCache", cfg.Credentials)
	}
	if !cache.IsCredentialsProvider(&stscreds.AssumeRoleProvider{}) {
		t.Fatal("cached provider is not *stscreds.AssumeRoleProvider")
	}

	base, err := buildBaseConfig(ctx, c)
	if err != nil {
		t.Fatalf("buildBaseConfig: %v", err)
	}
	got, err := base.Credentials.Retrieve(ctx)
	if err != nil {
		t.Fatalf("Retrieve base (ambient chain): %v", err)
	}
	if got.AccessKeyID != "AKIAAMBIENT" {
		t.Errorf("base AccessKeyID = %q, want AKIAAMBIENT (ambient chain not used)", got.AccessKeyID)
	}
}

// ---------------------------------------------------------------------------
// Fix 3 + back-compat: auth_mode defaulting and validation.
// ---------------------------------------------------------------------------

// Regression guard for EVERY EXISTING INTEGRATION ROW: no auth_mode key at all
// must behave exactly like access_key mode did before assume-role existed.
func TestCredentialConfig_AbsentAuthModeIsAccessKey(t *testing.T) {
	isolateAWSEnv(t)
	ctx := context.Background()

	c := CredentialConfigFromMap(map[string]interface{}{
		"access_key_id":     "AKIALEGACY",
		"secret_access_key": "legacysecret",
		"region":            "ap-southeast-2",
	})

	if c.AuthMode != "" {
		t.Fatalf("AuthMode = %q, want empty (nothing invented from an absent key)", c.AuthMode)
	}
	if c.ResolvedAuthMode() != AuthModeAccessKey {
		t.Fatalf("ResolvedAuthMode = %q, want %q", c.ResolvedAuthMode(), AuthModeAccessKey)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	cfg, err := BuildAWSConfig(ctx, c)
	if err != nil {
		t.Fatalf("BuildAWSConfig: %v", err)
	}
	if _, isCache := cfg.Credentials.(*aws.CredentialsCache); isCache {
		if cfg.Credentials.(*aws.CredentialsCache).IsCredentialsProvider(&stscreds.AssumeRoleProvider{}) {
			t.Fatal("legacy row resolved to an AssumeRole provider")
		}
	}
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if creds.AccessKeyID != "AKIALEGACY" || creds.SecretAccessKey != "legacysecret" {
		t.Errorf("credentials = %q/%q, want AKIALEGACY/legacysecret", creds.AccessKeyID, creds.SecretAccessKey)
	}
	if creds.SessionToken != "" {
		t.Errorf("SessionToken = %q, want empty for a legacy row that has none", creds.SessionToken)
	}
	if cfg.Region != "ap-southeast-2" {
		t.Errorf("Region = %q, want ap-southeast-2", cfg.Region)
	}
	// An empty auth_mode string (as opposed to an absent key) must behave the same.
	c.AuthMode = ""
	if err := c.Validate(); err != nil {
		t.Fatalf("empty auth_mode string: %v", err)
	}
}

func TestCredentialConfig_Validate(t *testing.T) {
	cases := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
	}{
		{"access_key mode with both keys", map[string]interface{}{
			"auth_mode": "access_key", "access_key_id": "A", "secret_access_key": "S"}, false},
		{"access_key mode missing secret", map[string]interface{}{
			"auth_mode": "access_key", "access_key_id": "A"}, true},
		{"access_key mode missing key id", map[string]interface{}{
			"auth_mode": "access_key", "secret_access_key": "S"}, true},
		{"absent auth_mode with both keys", map[string]interface{}{
			"access_key_id": "A", "secret_access_key": "S"}, false},
		{"absent auth_mode missing keys", map[string]interface{}{}, true},
		{"assume_role with arn and no keys", map[string]interface{}{
			"auth_mode": "assume_role", "assume_role_arn": "arn:aws:iam::1:role/R"}, false},
		{"assume_role with arn, external id, no keys", map[string]interface{}{
			"auth_mode": "assume_role", "assume_role_arn": "arn:aws:iam::1:role/R", "external_id": "x"}, false},
		{"assume_role with arn and base keys", map[string]interface{}{
			"auth_mode": "assume_role", "assume_role_arn": "arn:aws:iam::1:role/R",
			"access_key_id": "A", "secret_access_key": "S"}, false},
		{"assume_role missing arn", map[string]interface{}{"auth_mode": "assume_role"}, true},
		{"unknown auth_mode", map[string]interface{}{
			"auth_mode": "magic", "access_key_id": "A", "secret_access_key": "S"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateConfigMap(tc.config)
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
// Fix 4: external_id encryption + legacy plaintext back-compat.
// ---------------------------------------------------------------------------

func TestSensitiveConfigKeys_IncludesExternalIDNotRoleARN(t *testing.T) {
	has := func(k string) bool {
		for _, s := range SensitiveConfigKeys {
			if s == k {
				return true
			}
		}
		return false
	}
	for _, k := range []string{"access_key_id", "secret_access_key", "session_token", "external_id"} {
		if !has(k) {
			t.Errorf("SensitiveConfigKeys missing %q", k)
		}
	}
	if has("assume_role_arn") {
		t.Error("assume_role_arn must NOT be encrypted — it is not a secret and the UI displays it")
	}
}

// A row saved BEFORE external_id was classified sensitive holds plaintext.
// Decrypting it fails; that must not hard-fail the whole integration.
//
// MUTATION-VERIFIED: removing the legacyPlaintextConfigKeys branch in
// DecryptConfigMap makes this test fail with "failed to decrypt external_id".
func TestDecryptConfigMap_LegacyPlaintextExternalID(t *testing.T) {
	enc, err := encryption.NewService(testMasterKey)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	encKey, _ := enc.Encrypt("AKIAREAL")
	encSecret, _ := enc.Encrypt("realsecret")

	got, err := DecryptConfigMap(enc, map[string]interface{}{
		"access_key_id":     encKey,
		"secret_access_key": encSecret,
		"external_id":       "vista-ext-plaintext-legacy", // never encrypted
		"assume_role_arn":   "arn:aws:iam::1:role/R",
		"auth_mode":         "assume_role",
	})
	if err != nil {
		t.Fatalf("DecryptConfigMap must tolerate a legacy plaintext external_id: %v", err)
	}
	if got["external_id"] != "vista-ext-plaintext-legacy" {
		t.Errorf("external_id = %q, want the stored plaintext", got["external_id"])
	}
	if got["access_key_id"] != "AKIAREAL" || got["secret_access_key"] != "realsecret" {
		t.Errorf("encrypted fields not decrypted: %q / %q", got["access_key_id"], got["secret_access_key"])
	}
	if got["assume_role_arn"] != "arn:aws:iam::1:role/R" {
		t.Errorf("assume_role_arn = %q, want passthrough", got["assume_role_arn"])
	}
}

// The other side of the same coin: the tolerance must NOT extend to fields that
// have always been encrypted. A garbage secret_access_key is a real key
// management failure and must surface, not be handed to AWS as a credential.
func TestDecryptConfigMap_AlwaysEncryptedFieldsStillHardFail(t *testing.T) {
	enc, err := encryption.NewService(testMasterKey)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	encKey, _ := enc.Encrypt("AKIAREAL")

	for _, key := range []string{"access_key_id", "secret_access_key", "session_token"} {
		t.Run(key, func(t *testing.T) {
			cfg := map[string]interface{}{
				"access_key_id":     encKey,
				"secret_access_key": encKey,
			}
			cfg[key] = "not-valid-ciphertext-at-all"
			if _, err := DecryptConfigMap(enc, cfg); err == nil {
				t.Fatalf("want hard failure on undecryptable %s, got nil", key)
			}
		})
	}
}

// Newly written external_id round-trips through encryption normally.
func TestDecryptConfigMap_EncryptedExternalIDRoundTrips(t *testing.T) {
	enc, err := encryption.NewService(testMasterKey)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	encExt, _ := enc.Encrypt("vista-ext-1234")

	got, err := DecryptConfigMap(enc, map[string]interface{}{
		"auth_mode":       "assume_role",
		"assume_role_arn": "arn:aws:iam::1:role/R",
		"external_id":     encExt,
	})
	if err != nil {
		t.Fatalf("DecryptConfigMap: %v", err)
	}
	if got["external_id"] != "vista-ext-1234" {
		t.Errorf("external_id = %q, want vista-ext-1234", got["external_id"])
	}
}
