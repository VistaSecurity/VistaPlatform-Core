package credentials

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

const testKey = "test-master-key-0123456789abcdef"

func newTestCipher(t *testing.T, opts ...Option) *Cipher {
	t.Helper()
	c, err := NewCipher("test", testKey, NotificationChannelPolicy, opts...)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	if !c.Enabled() {
		t.Fatal("cipher should be enabled with a master key")
	}
	return c
}

// TestEncryptMapActuallyEncrypts is the anti-no-op test. The failure mode this
// whole package exists to prevent is an "encrypt" that returns its input, so
// assert on the stored bytes, not on the round trip.
func TestEncryptMapActuallyEncrypts(t *testing.T) {
	c := newTestCipher(t)
	const secret = "https://hooks.slack.com/services/T00/B00/XXXXsupersecret"

	out, err := c.EncryptMap(map[string]interface{}{
		"webhook_url": secret,
		"channel":     "#alerts",
	})
	if err != nil {
		t.Fatalf("EncryptMap: %v", err)
	}

	stored, _ := json.Marshal(out)
	if strings.Contains(string(stored), secret) {
		t.Fatalf("plaintext credential survived encryption: %s", stored)
	}
	if strings.Contains(string(stored), "supersecret") {
		t.Fatalf("credential substring survived encryption: %s", stored)
	}
	if got := out["webhook_url"].(string); !strings.HasPrefix(got, Prefix) {
		t.Fatalf("ciphertext not tagged with %q: %q", Prefix, got)
	}
	if out["channel"] != "#alerts" {
		t.Fatalf("non-credential field was altered: %v", out["channel"])
	}
}

func TestRoundTrip(t *testing.T) {
	c := newTestCipher(t)
	in := map[string]interface{}{
		"webhook_url": "https://hooks.slack.com/secret",
		"channel":     "#alerts",
		"headers":     map[string]interface{}{"Authorization": "Bearer abc", "X-Trace": "on"},
		"auth":        map[string]interface{}{"type": "basic", "username": "svc-user-9f3a2e", "password": "pw-4b71c0-secret"},
		"enabled":     true,
	}

	enc, err := c.EncryptMap(in)
	if err != nil {
		t.Fatalf("EncryptMap: %v", err)
	}
	// Every declared credential must be tagged.
	// Probe values are long and distinctive ON PURPOSE. This assertion is a
	// substring search over the marshalled JSON, and the ciphertext is base64 —
	// so a 2- or 3-character probe like "pw" or "svc" collides with the encoding
	// by chance. Measured at ~5.5% of runs (11/200), it failed claiming
	// `credential "pw" stored in the clear` while the value was plainly
	// `"password":"enc:v1:AjX+c/szRIeD..."`. A false alarm in a leak test is
	// worse than no test: it trains the reader to dismiss the one failure that
	// is real. The property asserted is unchanged — no plaintext credential may
	// appear in the marshalled output — only the probes are now distinctive
	// enough for a chance match to be negligible.
	for _, probe := range []string{"Bearer abc", "svc-user-9f3a2e", "pw-4b71c0-secret", "https://hooks.slack.com/secret"} {
		b, _ := json.Marshal(enc)
		if strings.Contains(string(b), probe) {
			t.Fatalf("credential %q stored in the clear: %s", probe, b)
		}
	}
	// The discriminator and non-credential values must stay readable.
	if enc["auth"].(map[string]interface{})["type"] != "basic" {
		t.Fatal("auth.type must stay readable")
	}
	if enc["headers"].(map[string]interface{})["X-Trace"] == "on" {
		// every header value is a credential by policy — this one is encrypted too
		t.Fatal("expected all header values to be encrypted")
	}

	dec, err := c.DecryptMap(enc)
	if err != nil {
		t.Fatalf("DecryptMap: %v", err)
	}
	if dec["webhook_url"] != in["webhook_url"] {
		t.Fatalf("round trip lost webhook_url: %v", dec["webhook_url"])
	}
	if dec["headers"].(map[string]interface{})["Authorization"] != "Bearer abc" {
		t.Fatalf("round trip lost header: %v", dec["headers"])
	}
	if dec["auth"].(map[string]interface{})["password"] != "pw-4b71c0-secret" {
		t.Fatalf("round trip lost auth.password: %v", dec["auth"])
	}
	if dec["enabled"] != true {
		t.Fatalf("round trip lost non-string value: %v", dec["enabled"])
	}
}

// TestLegacyPlaintextPassesThroughOnRead is the migration guarantee: a row
// written before this package existed still reads correctly.
func TestLegacyPlaintextPassesThroughOnRead(t *testing.T) {
	c := newTestCipher(t)
	legacy := map[string]interface{}{"webhook_url": "https://hooks.slack.com/legacy"}

	dec, err := c.DecryptMap(legacy)
	if err != nil {
		t.Fatalf("DecryptMap on legacy row: %v", err)
	}
	if dec["webhook_url"] != "https://hooks.slack.com/legacy" {
		t.Fatalf("legacy plaintext mangled: %v", dec["webhook_url"])
	}

	// ...and it is encrypted on the next save.
	enc, err := c.EncryptMap(dec)
	if err != nil {
		t.Fatalf("EncryptMap: %v", err)
	}
	if !strings.HasPrefix(enc["webhook_url"].(string), Prefix) {
		t.Fatal("legacy plaintext was not encrypted on next save")
	}
}

// TestEncryptIsIdempotent guards the read-modify-write cycle: a handler that
// loads a row, changes an unrelated field, and saves it back must not
// double-encrypt the credential it never decrypted.
func TestEncryptIsIdempotent(t *testing.T) {
	c := newTestCipher(t)
	once, err := c.EncryptMap(map[string]interface{}{"webhook_url": "secret"})
	if err != nil {
		t.Fatalf("EncryptMap: %v", err)
	}
	twice, err := c.EncryptMap(once)
	if err != nil {
		t.Fatalf("EncryptMap (2nd): %v", err)
	}
	if twice["webhook_url"] != once["webhook_url"] {
		t.Fatal("re-encrypting an already-tagged value changed it")
	}
	dec, err := c.DecryptMap(twice)
	if err != nil {
		t.Fatalf("DecryptMap: %v", err)
	}
	if dec["webhook_url"] != "secret" {
		t.Fatalf("double-encryption corrupted the value: %v", dec["webhook_url"])
	}
}

// TestTaggedCiphertextFailsLoudlyOnWrongKey pins the reason the prefix exists:
// a tagged value that will not decrypt is an error, never a silent
// "assume it was plaintext" that hands ciphertext to a connector.
func TestTaggedCiphertextFailsLoudlyOnWrongKey(t *testing.T) {
	good := newTestCipher(t)
	enc, err := good.EncryptMap(map[string]interface{}{"webhook_url": "secret"})
	if err != nil {
		t.Fatalf("EncryptMap: %v", err)
	}

	bad, err := NewCipher("test", "a-completely-different-master-key", NotificationChannelPolicy)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	if _, err := bad.DecryptMap(enc); err == nil {
		t.Fatal("decrypting tagged ciphertext under the wrong key must error")
	}
}

// TestLegacyUnprefixedCiphertext covers public.integrations, where a
// pre-existing writer stored bare (un-prefixed) ciphertext into the same column
// a new reader must understand.
func TestLegacyUnprefixedCiphertext(t *testing.T) {
	enc, err := encryption.NewService(testKey)
	if err != nil {
		t.Fatalf("encryption.NewService: %v", err)
	}
	bare, err := enc.Encrypt("legacy-api-token")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Without the option, a bare ciphertext is indistinguishable from plaintext
	// and passes through — the behavior a store that never held bare ciphertext
	// wants.
	strict, err := NewCipher("strict", testKey, IntegrationAuthConfigPolicy)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	got, err := strict.DecryptMap(map[string]interface{}{"api_token": bare})
	if err != nil {
		t.Fatalf("DecryptMap: %v", err)
	}
	if got["api_token"] != bare {
		t.Fatalf("strict cipher should pass an unrecognized value through, got %v", got["api_token"])
	}

	// With it, the bare ciphertext is recovered.
	lenient, err := NewCipher("lenient", testKey, IntegrationAuthConfigPolicy, WithLegacyUnprefixedCiphertext())
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	got, err = lenient.DecryptMap(map[string]interface{}{"api_token": bare})
	if err != nil {
		t.Fatalf("DecryptMap: %v", err)
	}
	if got["api_token"] != "legacy-api-token" {
		t.Fatalf("legacy bare ciphertext not recovered: %v", got["api_token"])
	}

	// And real plaintext is still passed through, not mangled — the GCM tag is
	// what makes the guess safe.
	got, err = lenient.DecryptMap(map[string]interface{}{"api_token": "plain-token"})
	if err != nil {
		t.Fatalf("DecryptMap: %v", err)
	}
	if got["api_token"] != "plain-token" {
		t.Fatalf("plaintext mangled by the legacy path: %v", got["api_token"])
	}
}

func TestDisabledCipherIsPassthrough(t *testing.T) {
	c, err := NewCipher("dev", "", NotificationChannelPolicy)
	if err != nil {
		t.Fatalf("NewCipher with empty key must not error: %v", err)
	}
	if c.Enabled() {
		t.Fatal("cipher with no master key must report disabled")
	}
	in := map[string]interface{}{"webhook_url": "secret"}
	out, err := c.EncryptMap(in)
	if err != nil {
		t.Fatalf("EncryptMap: %v", err)
	}
	if out["webhook_url"] != "secret" {
		t.Fatalf("disabled cipher must pass through, got %v", out["webhook_url"])
	}
	if v, err := c.DecryptValue("secret"); err != nil || v != "secret" {
		t.Fatalf("disabled DecryptValue: %q %v", v, err)
	}
}

// TestEncryptMapDoesNotMutateInput guards the aliasing bug: handlers hand us a
// request body they still hold, and an in-place mutation would leave the
// caller's map holding ciphertext it will later render to a user.
func TestEncryptMapDoesNotMutateInput(t *testing.T) {
	c := newTestCipher(t)
	headers := map[string]interface{}{"Authorization": "Bearer abc"}
	in := map[string]interface{}{"webhook_url": "secret", "headers": headers}

	if _, err := c.EncryptMap(in); err != nil {
		t.Fatalf("EncryptMap: %v", err)
	}
	if in["webhook_url"] != "secret" {
		t.Fatalf("input map was mutated: %v", in["webhook_url"])
	}
	if headers["Authorization"] != "Bearer abc" {
		t.Fatalf("nested input map was mutated: %v", headers["Authorization"])
	}
}

func TestJSONHelpers(t *testing.T) {
	c := newTestCipher(t)
	raw := json.RawMessage(`{"webhook_url":"https://hooks.slack.com/secret","channel":"#a"}`)

	enc, err := c.EncryptJSON(raw)
	if err != nil {
		t.Fatalf("EncryptJSON: %v", err)
	}
	if strings.Contains(string(enc), "hooks.slack.com/secret") {
		t.Fatalf("plaintext survived EncryptJSON: %s", enc)
	}

	dec, err := c.DecryptJSON(enc)
	if err != nil {
		t.Fatalf("DecryptJSON: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(dec, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["webhook_url"] != "https://hooks.slack.com/secret" {
		t.Fatalf("round trip lost value: %v", got["webhook_url"])
	}

	// null and empty pass through untouched.
	for _, in := range []json.RawMessage{nil, json.RawMessage("null")} {
		out, err := c.EncryptJSON(in)
		if err != nil {
			t.Fatalf("EncryptJSON(%q): %v", in, err)
		}
		if string(out) != string(in) {
			t.Fatalf("EncryptJSON(%q) = %q", in, out)
		}
	}
}

func TestScalarValueRoundTrip(t *testing.T) {
	c := newTestCipher(t)
	const secret = "https://hooks.slack.com/services/T/B/scalar"

	ct, err := c.EncryptValue(secret)
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	if strings.Contains(ct, "hooks.slack.com") {
		t.Fatalf("plaintext survived EncryptValue: %q", ct)
	}
	if !strings.HasPrefix(ct, Prefix) {
		t.Fatalf("scalar ciphertext not tagged: %q", ct)
	}
	pt, err := c.DecryptValue(ct)
	if err != nil {
		t.Fatalf("DecryptValue: %v", err)
	}
	if pt != secret {
		t.Fatalf("scalar round trip lost value: %q", pt)
	}
	// Legacy plaintext scalar passes through.
	if pt, err := c.DecryptValue("plain-webhook"); err != nil || pt != "plain-webhook" {
		t.Fatalf("legacy scalar: %q %v", pt, err)
	}
	// Empty stays empty (an unset column, not a credential).
	if ct, err := c.EncryptValue(""); err != nil || ct != "" {
		t.Fatalf("empty scalar: %q %v", ct, err)
	}
}

// TestPoliciesCoverKnownCredentialNames pins the denylist so that removing a
// key from BaseIntegrationFields — the exact drift is about — fails a
// test rather than silently shipping a plaintext field.
func TestPoliciesCoverKnownCredentialNames(t *testing.T) {
	required := []string{
		"access_key_id", "secret_access_key", "session_token",
		"api_key", "api_token", "auth_token", "access_token", "refresh_token",
		"client_secret", "password", "private_key", "secret",
		"service_account_json", "service_account_key", "credentials_json",
		"integration_key", "token", "webhook_secret",
	}
	have := make(map[string]bool, len(BaseIntegrationFields))
	for _, f := range BaseIntegrationFields {
		have[f] = true
	}
	for _, k := range required {
		if !have[k] {
			t.Errorf("BaseIntegrationFields is missing credential key %q", k)
		}
	}

	// The notification policy must extend the floor, not replace it.
	nh := make(map[string]bool, len(NotificationChannelPolicy.Fields))
	for _, f := range NotificationChannelPolicy.Fields {
		nh[f] = true
	}
	for _, k := range append([]string{"webhook_url", "url"}, BaseIntegrationFields...) {
		if !nh[k] {
			t.Errorf("NotificationChannelPolicy is missing %q", k)
		}
	}
}
