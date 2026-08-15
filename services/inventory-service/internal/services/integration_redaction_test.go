package services

import (
	"testing"

	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
)

// ListIntegrations decrypts auth_config, so the list response used to hand every
// authenticated tenant member the plaintext credentials for their SIEM / CMDB /
// ITSM connections. Redaction is the second half of the fix (the first is the
// settings.read gate on the route): a list must never yield credential material
// regardless of who is allowed to call it.
func TestRedactIntegrationAuthConfig(t *testing.T) {
	in := shareddb.JSONMap{
		"api_key":       "sk-live-DEADBEEF",
		"password":      "hunter2",
		"client_secret": "s3cr3t",
		"token":         "eyJhbGciOi",
		"private_key":   "-----BEGIN PRIVATE KEY-----",
		// Named the way THIS domain names credentials, not the way a network
		// device does. All three leaked past the shared matcher until it was
		// extended: a header-auth integration stores its credential under
		// `authorization` or a bare `auth`, and a webhook URL carries its token
		// in the path, so the URL is the secret.
		"authorization": "Bearer eyJhbGciOi",
		"auth":          "Basic c3ZjOmh1bnRlcjI=",
		"webhook_url":   "https://hooks.example.com/services/T000/B000/XXXXSECRETXXXX",
		// Connection shape — must survive so the UI can still describe the
		// integration without re-fetching it.
		"username":   "svc-vista",
		"auth_style": "basic",
		"host":       "cmdb.example.com",
		"index":      "vista-events",
		"verify_tls": true,
		"nested": map[string]interface{}{
			"passphrase": "top-secret",
			"region":     "us-east-1",
		},
	}

	out := redactIntegrationAuthConfig(in)

	for _, k := range []string{
		"api_key", "password", "client_secret", "token", "private_key",
		"authorization", "auth", "webhook_url",
	} {
		if got := out[k]; got != "[redacted]" {
			t.Errorf("auth_config[%q] = %v, want it redacted", k, got)
		}
	}
	for k, want := range map[string]interface{}{
		"username":   "svc-vista",
		"auth_style": "basic",
		"host":       "cmdb.example.com",
		"index":      "vista-events",
		"verify_tls": true,
	} {
		if out[k] != want {
			t.Errorf("auth_config[%q] = %v, want %v preserved", k, out[k], want)
		}
	}
	nested, ok := out["nested"].(map[string]interface{})
	if !ok {
		t.Fatalf("nested block lost its shape: %#v", out["nested"])
	}
	if nested["passphrase"] != "[redacted]" {
		t.Errorf("nested passphrase = %v, want redacted", nested["passphrase"])
	}
	if nested["region"] != "us-east-1" {
		t.Errorf("nested region = %v, want preserved", nested["region"])
	}

	// The input is the row we just decrypted; mutating it in place would poison
	// any caller that shares the slice.
	if in["password"] != "hunter2" {
		t.Errorf("input map was mutated: password = %v", in["password"])
	}

	if redactIntegrationAuthConfig(nil) != nil {
		t.Error("nil auth_config should stay nil, not become an empty object")
	}
}
