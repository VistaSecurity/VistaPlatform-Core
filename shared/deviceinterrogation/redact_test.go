package deviceinterrogation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// The field names below are the real ones observed in a UniFi UDR interrogation
// whose result was persisted verbatim, secrets and all.
func TestIsSecretFieldName_RedactsRealVendorSecrets(t *testing.T) {
	secret := []string{
		"x_mesh_psk", "x_authkey", "x_vwirekey", "syslog_key", "x_password",
		"password", "passwd", "passphrase", "x_shared_secret", "radius_secret",
		"api_key", "apiKey", "private_key", "privateKey", "auth_token",
		"bearer_token", "session_key", "master_key", "signing_key",
		"encryption_key", "x_ssh_password", "pre_shared_key", "credential",
		"host_key", "wpa_key",
	}
	for _, name := range secret {
		if !isSecretFieldName(name) {
			t.Errorf("field %q should be treated as secret material but was not", name)
		}
	}
}

// The inverse polarity: an over-strict scrubber that eats the posture fields is
// the same bug pointed the other way. These are exactly what we are in business
// to inventory and they must survive.
func TestIsSecretFieldName_KeepsCryptoPostureFields(t *testing.T) {
	safe := []string{
		"key_algorithm", "key_size", "key_length", "key_exchange",
		"key_exchange_algorithm", "key_types", "key_usage",
		"extended_key_usage", "public_key_algorithm", "host_key_type",
		"host_key_fingerprint", "cipher_suite", "protocol_version",
		"signature_alg", "fingerprint_sha256", "not_after", "mac_address",
		"model", "firmware_version", "serial", "subject_dn", "issuer_dn",
	}
	for _, name := range safe {
		if isSecretFieldName(name) {
			t.Errorf("posture field %q was redacted; the scrubber is over-strict", name)
		}
	}
}

func TestRedactMap_RecursesThroughNestedStructures(t *testing.T) {
	in := map[string]interface{}{
		"name":      "Dream Router",
		"key_size":  2048,
		"x_authkey": "6c44255cfd1ae2c09ea2c20aa79538cd",
		"connectivity": map[string]interface{}{
			"uplink_type": "gateway",
			"x_mesh_psk":  "76cb7a67a0650c263bd78635193fc1b2",
		},
		"settings": []interface{}{
			map[string]interface{}{"key": "super_smtp", "x_password": "hunter2"},
		},
	}
	out := RedactMap(in)

	if out["name"] != "Dream Router" || out["key_size"] != 2048 {
		t.Fatalf("non-secret fields were altered: %#v", out)
	}
	if out["x_authkey"] != redactedMarker {
		t.Errorf("top-level secret not redacted: %v", out["x_authkey"])
	}
	nested := out["connectivity"].(map[string]interface{})
	if nested["x_mesh_psk"] != redactedMarker {
		t.Errorf("nested secret not redacted: %v", nested["x_mesh_psk"])
	}
	if nested["uplink_type"] != "gateway" {
		t.Errorf("nested non-secret altered: %v", nested["uplink_type"])
	}
	inSlice := out["settings"].([]interface{})[0].(map[string]interface{})
	if inSlice["x_password"] != redactedMarker {
		t.Errorf("secret inside slice not redacted: %v", inSlice["x_password"])
	}

	// The input must not be mutated — callers may still hold it.
	if in["x_authkey"] == redactedMarker {
		t.Error("RedactMap mutated its input")
	}
}

// The whole point of the exercise: no secret value survives anywhere in the
// serialized result, at any nesting depth.
func TestSanitize_NoSecretValueSurvivesSerialization(t *testing.T) {
	const psk = "76cb7a67a0650c263bd78635193fc1b2"
	const authkey = "6c44255cfd1ae2c09ea2c20aa79538cd"

	result := &InterrogateResult{
		DeviceInfo: map[string]interface{}{
			"controller_name": "Dream Router",
			"super_mgmt":      map[string]interface{}{"x_mesh_psk": psk},
		},
		Assets: []CryptoAsset{{
			Hostname: "AC LR",
			Metadata: map[string]interface{}{
				"model":     "U7LR",
				"x_authkey": authkey,
			},
		}},
	}

	Sanitize(result)

	blob, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, leaked := range []string{psk, authkey} {
		if strings.Contains(string(blob), leaked) {
			t.Errorf("secret %q survived Sanitize in: %s", leaked, blob)
		}
	}
	if !strings.Contains(string(blob), "U7LR") {
		t.Error("Sanitize dropped legitimate inventory data")
	}
}

// leakyInterrogator emits a secret the way a not-yet-written collector might.
type leakyInterrogator struct{}

func (leakyInterrogator) SupportedDeviceTypes() []string { return []string{"leaky-test-device"} }
func (leakyInterrogator) Interrogate(context.Context, DeviceInfo, Credentials) (*InterrogateResult, error) {
	return &InterrogateResult{
		DeviceInfo: map[string]interface{}{"x_mesh_psk": "should-not-escape"},
		Assets: []CryptoAsset{{
			Metadata: map[string]interface{}{"admin_password": "should-not-escape"},
		}},
	}, nil
}

// Registry.Get is the chokepoint that makes redaction structural. If someone
// unwraps it, this fails — which is the point.
func TestRegistryGet_ScrubsInterrogatorOutput(t *testing.T) {
	r := NewRegistry()
	r.Register(leakyInterrogator{})

	interrogator, err := r.Get("leaky-test-device")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	result, err := interrogator.Interrogate(context.Background(), DeviceInfo{}, Credentials{})
	if err != nil {
		t.Fatalf("Interrogate: %v", err)
	}

	blob, _ := json.Marshal(result)
	if strings.Contains(string(blob), "should-not-escape") {
		t.Errorf("Registry.Get did not scrub interrogator output: %s", blob)
	}
}

// convertDeviceToAsset must project onto the allowlist, not copy the raw
// controller object. Regression guard for the original leak.
func TestConvertDeviceToAsset_ProjectsOntoAllowlist(t *testing.T) {
	c := &unifiClient{}
	raw := map[string]interface{}{
		"name":        "AC LR",
		"ip":          "192.0.2.250",
		"mac":         "78:8a:20:4b:ee:40",
		"model":       "U7LR",
		"type":        "uap",
		"version":     "6.6.77.15402",
		"x_authkey":   "6c44255cfd1ae2c09ea2c20aa79538cd",
		"x_vwirekey":  "1d103488353fc6333c2ece3bdedea41a",
		"syslog_key":  "d3ea2b95ba06686b91f0fbe2ca3d1079",
		"x_aes_gcm":   true,
		"radio_table": []interface{}{map[string]interface{}{"name": "wifi0"}},
	}

	asset := c.convertDeviceToAsset(raw, "default")

	for _, dropped := range []string{"x_authkey", "x_vwirekey", "syslog_key", "radio_table"} {
		if _, present := asset.Metadata[dropped]; present {
			t.Errorf("field %q was collected; it is not on the inventory allowlist", dropped)
		}
	}
	if asset.Hostname != "AC LR" || asset.IPAddress != "192.0.2.250" {
		t.Errorf("identity lost: %+v", asset)
	}
	if asset.Metadata["model"] != "U7LR" || asset.Metadata["firmware_version"] != "6.6.77.15402" {
		t.Errorf("inventory fields lost: %#v", asset.Metadata)
	}
}
