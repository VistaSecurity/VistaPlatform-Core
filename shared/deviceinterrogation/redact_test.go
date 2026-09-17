package deviceinterrogation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/redact"
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
		if !redact.IsSecretName(name) {
			t.Errorf("field %q should be treated as secret material but was not", name)
		}
	}
}

// The matcher also backstops tenant integration credentials (the
// inventory-service integrations list runs auth_config through RedactMap), and
// that domain names its secrets differently from a network device: an
// integration's credential is as likely to sit under `authorization`, a bare
// `auth`, or inside a webhook URL as under `api_key`. Those three leaked until
// the fragment list was extended; this pins them.
func TestIsSecretFieldName_RedactsIntegrationCredentialNames(t *testing.T) {
	secret := []string{
		"authorization", "Authorization", "auth", "AUTH",
		"webhook_url", "webhook_uri", "slack_webhook", "incoming_webhook",
		"client_secret", "secret_access_key", "credentials",
	}
	for _, name := range secret {
		if !redact.IsSecretName(name) {
			t.Errorf("field %q should be treated as secret material but was not", name)
		}
	}
}

// `auth` is a whole-name match, never a fragment: these are crypto posture that
// a fragment rule would have eaten. Guarding the scoping decision, not just its
// effect.
func TestIsSecretFieldName_AuthIsWholeNameOnly(t *testing.T) {
	safe := []string{
		"auth_type", "auth_style", "auth_method", "authmethod",
		"authentication", "authentication_algorithm", "authenticated",
	}
	for _, name := range safe {
		if redact.IsSecretName(name) {
			t.Errorf("posture/shape field %q was redacted; `auth` over-matched as a fragment", name)
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
		if redact.IsSecretName(name) {
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
	if out["x_authkey"] != redact.Marker {
		t.Errorf("top-level secret not redacted: %v", out["x_authkey"])
	}
	nested := out["connectivity"].(map[string]interface{})
	if nested["x_mesh_psk"] != redact.Marker {
		t.Errorf("nested secret not redacted: %v", nested["x_mesh_psk"])
	}
	if nested["uplink_type"] != "gateway" {
		t.Errorf("nested non-secret altered: %v", nested["uplink_type"])
	}
	inSlice := out["settings"].([]interface{})[0].(map[string]interface{})
	if inSlice["x_password"] != redact.Marker {
		t.Errorf("secret inside slice not redacted: %v", inSlice["x_password"])
	}

	// The input must not be mutated — callers may still hold it.
	if in["x_authkey"] == redact.Marker {
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
	// "AC LR" is the controller's DISPLAY name — a label, not a hostname (it
	// has a space). It must survive in Metadata for the UI but must NOT become
	// asset.Hostname: the identity layer treats Hostname as a DNS name and
	// rejects a value with a space, which is exactly the reject this test used
	// to require. Identity is not lost — the IP address still identifies the
	// device — see TestConvertDeviceToAsset_DisplayNameNotPromotedToHostname
	// (unifi_ops_test.go) for the dedicated regression test.
	if asset.Hostname != "" || asset.IPAddress != "192.0.2.250" {
		t.Errorf("identity lost: %+v", asset)
	}
	if asset.Metadata["name"] != "AC LR" {
		t.Errorf("display name was not preserved in Metadata: %#v", asset.Metadata["name"])
	}
	if asset.Metadata["model"] != "U7LR" || asset.Metadata["firmware_version"] != "6.6.77.15402" {
		t.Errorf("inventory fields lost: %#v", asset.Metadata)
	}
}

// Sanitize reaches an asset's ServiceHints — and takes only PEM private keys
// out of it.
//
// BOTH polarities, because this guard is easy to get wrong in either
// direction. `service_name` and `service_version` are free text whose ORIGIN is
// outside our control (an HTTP or TLS banner, or on a host inventory the name
// of the process holding a listening socket), so a name-based rule cannot help
// and a value-based one is the only thing that can. But those same fields are
// the service posture we are in business to collect: an over-broad rule that
// took "OpenSSH_9.6" out would silently delete the answer.
//
// To mutation-test: delete the sanitizeServiceHints call from Sanitize and the
// first subtest fails; widen redact.TextPEM past "PRIVATE KEY" and the second
// does.
func TestSanitize_ServiceHints(t *testing.T) {
	const key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----"

	t.Run("a pasted private key is masked", func(t *testing.T) {
		result := &InterrogateResult{Assets: []CryptoAsset{{
			Port: 22,
			ServiceHints: &ServiceHints{
				ServiceName:    "sshd " + key,
				ServiceVersion: key,
			},
		}}}

		Sanitize(result)

		blob, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if strings.Contains(string(blob), "b3BlbnNzaC1rZXktdjEAAAAA") {
			t.Errorf("key material survived Sanitize in ServiceHints: %s", blob)
		}
		hints := result.Assets[0].ServiceHints
		if !strings.Contains(hints.ServiceName, redact.Marker) {
			t.Errorf("service_name was not masked: %q", hints.ServiceName)
		}
		// The text AROUND the block is posture and stays.
		if !strings.HasPrefix(hints.ServiceName, "sshd ") {
			t.Errorf("masking ate the surrounding banner: %q", hints.ServiceName)
		}
	})

	t.Run("real banner posture survives untouched", func(t *testing.T) {
		// Every one of these is a banner or a process name a collector
		// legitimately reports, and several NAME a key or a certificate —
		// which is exactly what an over-broad rule would eat.
		posture := []*ServiceHints{
			{ServiceName: "OpenSSH", ServiceVersion: "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"},
			{ServiceName: "nginx", ServiceVersion: "nginx/1.24.0 (Ubuntu)"},
			{ServiceName: "sshd", Confidence: "reported", IdentificationMethod: "host_socket_owner"},
			{ServiceName: "ssh-agent", ServiceVersion: "OpenSSH_9.6"},
			{ServiceName: "step-ca", ServiceVersion: "private key store 0.27.2"},
			{ServiceName: "postgres", ServiceVersion: "PostgreSQL 17.2 with OpenSSL 3.0.13"},
		}
		for _, hints := range posture {
			want := *hints
			result := &InterrogateResult{Assets: []CryptoAsset{{ServiceHints: hints}}}

			Sanitize(result)

			if *hints != want {
				t.Errorf("Sanitize altered legitimate service posture:\n got %+v\nwant %+v", *hints, want)
			}
		}
	})

	t.Run("a nil ServiceHints is not a panic", func(t *testing.T) {
		result := &InterrogateResult{Assets: []CryptoAsset{{Port: 443}}}
		Sanitize(result)
		if result.Assets[0].ServiceHints != nil {
			t.Error("Sanitize invented a ServiceHints")
		}
	})
}

// TestDatabaseFindingRawConfigIsRedacted is gate 1 D2.
//
// The database path is the one interrogation that does NOT go through
// Registry.Get: the service wrapper needs the typed DatabaseEncryptionFinding
// so it can write `database_encryption_states`, so it called InterrogateDatabase
// directly and the sanitizing wrapper never saw the result. RawConfig is the
// engine's whole settings bag — SHOW VARIABLES, pg_settings — and it went into
// the column verbatim.
//
// It drives InterrogateDatabase ITSELF through the per-engine seam, not
// redact.Map: testing the helper would prove the helper works and say nothing
// about whether the call site calls it.
func TestDatabaseFindingRawConfigIsRedacted(t *testing.T) {
	original := dbInterrogateMy
	t.Cleanup(func() { dbInterrogateMy = original })
	dbInterrogateMy = func(context.Context, string) (*DatabaseEncryptionFinding, error) {
		return &DatabaseEncryptionFinding{
			Engine:     "mysql",
			SSLEnabled: true,
			RawConfig: map[string]interface{}{
				// Posture: must SURVIVE. A redactor that eats these has made
				// the feature useless, which is this guard's other polarity.
				"ssl_cipher":               "TLS_AES_256_GCM_SHA384",
				"tls_version":              "TLSv1.3",
				"have_ssl":                 "YES",
				"ssl_key_size":             "2048",
				"require_secure_transport": "ON",
				// Secrets: must NOT.
				"master_ssl_password": "hunter2",
				"admin_api_key":       "AKIAIOSFODNN7EXAMPLE",
				"replication_secret":  "s3cr3t",
			},
		}, nil
	}

	finding, err := InterrogateDatabase(context.Background(),
		DeviceInfo{DeviceType: "mysql", Hostname: "db.example.test"},
		Credentials{Username: "u", Password: "p"})
	if err != nil {
		t.Fatalf("InterrogateDatabase: %v", err)
	}

	for _, keep := range []string{"ssl_cipher", "tls_version", "have_ssl", "ssl_key_size", "require_secure_transport"} {
		if got, _ := finding.RawConfig[keep].(string); got == "" || got == redact.Marker {
			t.Errorf("%s = %q; crypto POSTURE must survive redaction or the feature reports nothing",
				keep, finding.RawConfig[keep])
		}
	}
	for _, drop := range []string{"master_ssl_password", "admin_api_key", "replication_secret"} {
		if got, _ := finding.RawConfig[drop].(string); got != redact.Marker {
			t.Errorf("%s = %q, want it redacted — a database's settings bag is not ours to keep",
				drop, got)
		}
	}
}
