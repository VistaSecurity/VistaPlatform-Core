package services

import (
	"encoding/json"
	"strings"
	"testing"
)

func secretCfg() map[string]interface{} {
	return map[string]interface{}{
		"webhook_url":     "https://hooks.example.test/services/T0FAKE/B0FAKE/SLACKSECRETPATH",
		"integration_key": "PDROUTINGKEYFAKE0123456789",
		"channel":         "#alerts",
		"recipients":      []interface{}{"ops@example.test"},
		"headers":         map[string]interface{}{"X-Api-Key": "HEADERSECRETFAKE-abcdef", "X-Team": "sre-team-fake"},
		"auth": map[string]interface{}{
			"type": "basic", "username": "svc-user-fake", "password": "BASICPASSWORDFAKE",
		},
	}
}

func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestMaskSecret_Forms(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"https://hooks.example.test/services/T/B/tail", "https://hooks.example.test/" + SecretMask},
		{"https://user:pw@hooks.example.test:8443/x?token=abc", "https://hooks.example.test:8443/" + SecretMask},
		{"PDROUTINGKEYFAKE0123456789", SecretMask + "6789"},
		{"short", SecretMask},
		{"12345678", SecretMask},
		{"123456789", SecretMask + "6789"},
	}
	for _, c := range cases {
		if got := maskSecret(c.in); got != c.want {
			t.Errorf("maskSecret(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMaskChannelConfig_HidesEveryCredentialAndKeepsTheRest(t *testing.T) {
	cfg := secretCfg()
	masked := MaskChannelConfig(cfg)
	out := mustJSON(t, masked)

	for _, secret := range []string{"SLACKSECRETPATH", "T0FAKE", "PDROUTINGKEYFAKE0", "HEADERSECRETFAKE", "sre-team-fake", "BASICPASSWORDFAKE", "svc-user-fake"} {
		if strings.Contains(out, secret) {
			t.Errorf("masked config still contains %q: %s", secret, out)
		}
	}
	for _, keep := range []string{"https://hooks.example.test/", "#alerts", "ops@example.test", `"type":"basic"`, "X-Api-Key", "X-Team", "6789"} {
		if !strings.Contains(out, keep) {
			t.Errorf("masked config lost %q: %s", keep, out)
		}
	}
	// The input must be untouched — delivery reads it.
	if !strings.Contains(mustJSON(t, cfg), "SLACKSECRETPATH") || !strings.Contains(mustJSON(t, cfg["headers"]), "HEADERSECRETFAKE") {
		t.Fatal("MaskChannelConfig mutated its input")
	}
	if MaskChannelConfig(nil) != nil {
		t.Error("nil config must stay nil")
	}
}

// The round trip a UI performs: GET (masked) -> PUT the same body back.
func TestMergeChannelSecrets_MaskedRoundTripKeepsStored(t *testing.T) {
	stored := secretCfg()
	merged := MergeChannelSecrets(stored, MaskChannelConfig(stored))
	if mustJSON(t, merged) != mustJSON(t, stored) {
		t.Fatalf("echoing the masked config back changed the stored one:\n got  %s\n want %s", mustJSON(t, merged), mustJSON(t, stored))
	}
}

func TestMergeChannelSecrets_OmittedOrBlankKeepsStored(t *testing.T) {
	stored := secretCfg()
	incoming := map[string]interface{}{
		"channel": "#renamed", // a non-secret edit
		// webhook_url + integration_key omitted; auth present with blank secrets
		"recipients": []interface{}{"ops@example.test"},
		"headers":    map[string]interface{}{"X-Api-Key": "", "X-Team": "sre-team-fake"},
		"auth":       map[string]interface{}{"type": "basic", "password": ""},
	}
	merged := MergeChannelSecrets(stored, incoming)

	if merged["webhook_url"] != stored["webhook_url"] || merged["integration_key"] != stored["integration_key"] {
		t.Errorf("omitted top-level credentials were not kept: %s", mustJSON(t, merged))
	}
	if merged["channel"] != "#renamed" {
		t.Errorf("non-secret edit lost: %v", merged["channel"])
	}
	h := merged["headers"].(map[string]interface{})
	if h["X-Api-Key"] != "HEADERSECRETFAKE-abcdef" {
		t.Errorf("blank header value did not keep the stored one: %v", h)
	}
	a := merged["auth"].(map[string]interface{})
	if a["password"] != "BASICPASSWORDFAKE" || a["username"] != "svc-user-fake" {
		t.Errorf("blank/omitted nested credentials were not kept: %v", a)
	}
}

func TestMergeChannelSecrets_NewValueReplacesAndOmittedHeaderIsDeleted(t *testing.T) {
	stored := secretCfg()
	incoming := map[string]interface{}{
		"webhook_url": "https://hooks.example.test/services/NEW/NEW/ROTATEDSECRET",
		"headers":     map[string]interface{}{"X-Team": "sre-team-fake"}, // X-Api-Key removed
	}
	merged := MergeChannelSecrets(stored, incoming)

	if merged["webhook_url"] != incoming["webhook_url"] {
		t.Errorf("a genuinely new secret must replace the stored one, got %v", merged["webhook_url"])
	}
	h := merged["headers"].(map[string]interface{})
	if _, ok := h["X-Api-Key"]; ok {
		t.Errorf("an omitted header is a deleted header, but it came back: %v", h)
	}
	// stored map must not be mutated by a merge.
	if stored["webhook_url"] == incoming["webhook_url"] {
		t.Error("MergeChannelSecrets mutated the stored config")
	}
}

func TestMergeChannelSecrets_NilIncomingMeansNoChange(t *testing.T) {
	stored := secretCfg()
	if got := MergeChannelSecrets(stored, nil); mustJSON(t, got) != mustJSON(t, stored) {
		t.Fatalf("nil incoming config must leave the stored config alone, got %s", mustJSON(t, got))
	}
}
