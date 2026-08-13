package handlers

import (
	"encoding/json"
	"strings"
	"testing"
)

// unifiLeakPayload is the shape a real UniFi interrogation stored: useful crypto
// alongside controller secrets that had no business being persisted. It is the
// regression fixture for both the projection and the redaction backstop.
const unifiLeakPayload = `{
  "success": true,
  "assets": [
    {
      "hostname": "AC LR",
      "ip_address": "198.51.100.250",
      "port": 8443,
      "protocol": "TLS",
      "metadata": {
        "model": "U7LR",
        "x_authkey": "6c44255cfd1ae2c09ea2c20aa79538cd",
        "x_vwirekey": "1d103488353fc6333c2ece3bdedea41a",
        "syslog_key": "d3ea2b95ba06686b91f0fbe2ca3d1079",
        "config_network": {"type": "dhcp", "x_mesh_psk": "76cb7a67a0650c263bd78635193fc1b2"}
      }
    },
    {
      "hostname": "",
      "ip_address": "198.51.100.1",
      "port": 443,
      "protocol": "TLS",
      "asset_type": "appliance",
      "protocol_version": "TLS 1.3",
      "cipher_suite": "TLS_AES_256_GCM_SHA384",
      "key_exchange_algorithm": "ECDHE",
      "key_size": 2048,
      "tls_versions": ["TLS 1.3", "TLS 1.2"],
      "cert_validation_status": "untrusted_ca",
      "cert_validation_error": "x509: certificate signed by unknown authority",
      "service_hints": {"service_name": "UniFi Controller", "confidence": "high"},
      "certificates": [
        {
          "subject_dn": "CN=unifi.local",
          "issuer_dn": "CN=unifi.local",
          "fingerprint_sha256": "4ed12d3f40eb6f06e69df71d0f808fb3c1703d5eb39550bb5bac8201ffd2c743",
          "not_before": "2025-11-11T05:00:04Z",
          "not_after": "2028-02-14T05:00:04Z",
          "key_algorithm": "RSA",
          "signature_alg": "SHA256-RSA"
        }
      ]
    }
  ],
  "metadata": {
    "email": "operator@example.com",
    "settings": [{"key": "super_smtp", "x_password": "hunter2"}]
  },
  "processing": {"materialized": 2, "assets_received": 2, "findings_failed": 0}
}`

func TestBuildJobResults_NoSecretsOrUnprojectedBlobsReachTheClient(t *testing.T) {
	out := buildJobResults("job-1", "completed", unifiLeakPayload)

	blob, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rendered := string(blob)

	// Secret values from the asset metadata, redacted by the backstop.
	for _, secret := range []string{
		"6c44255cfd1ae2c09ea2c20aa79538cd", // x_authkey
		"1d103488353fc6333c2ece3bdedea41a", // x_vwirekey
		"d3ea2b95ba06686b91f0fbe2ca3d1079", // syslog_key
		"76cb7a67a0650c263bd78635193fc1b2", // nested x_mesh_psk
	} {
		if strings.Contains(rendered, secret) {
			t.Errorf("secret %q reached the client payload", secret)
		}
	}

	// The top-level results metadata (admin profile + site settings) is not a
	// projected field at all, so neither the operator's email nor the SMTP
	// password can appear regardless of redaction.
	for _, leaked := range []string{"operator@example.com", "hunter2"} {
		if strings.Contains(rendered, leaked) {
			t.Errorf("unprojected results metadata %q reached the client payload", leaked)
		}
	}
}

func TestBuildJobResults_KeepsTheCryptoPosture(t *testing.T) {
	out := buildJobResults("job-1", "completed", unifiLeakPayload)

	if got := len(out.Assets); got != 2 {
		t.Fatalf("expected 2 assets, got %d", got)
	}
	if out.Summary.TotalAssets != 2 {
		t.Errorf("total_assets = %d, want 2", out.Summary.TotalAssets)
	}
	// Only the controller had a real handshake; the AP came from a management
	// API listing and must not be counted as measured.
	if out.Summary.WithCrypto != 1 {
		t.Errorf("with_crypto = %d, want 1", out.Summary.WithCrypto)
	}
	if out.Summary.WithCertificates != 1 {
		t.Errorf("with_certificates = %d, want 1", out.Summary.WithCertificates)
	}
	if out.Summary.Materialized == nil || *out.Summary.Materialized != 2 {
		t.Errorf("materialized not carried through from the processing log: %v", out.Summary.Materialized)
	}

	ap, controller := out.Assets[0], out.Assets[1]
	if ap.CryptoObserved {
		t.Error("inventory-only asset was marked as having observed crypto")
	}
	if ap.Metadata["model"] != "U7LR" {
		t.Errorf("legitimate inventory metadata lost: %#v", ap.Metadata)
	}
	if !controller.CryptoObserved {
		t.Error("probed asset was not marked as having observed crypto")
	}
	if controller.CipherSuite != "TLS_AES_256_GCM_SHA384" || controller.ProtocolVersion != "TLS 1.3" {
		t.Errorf("crypto posture lost: %+v", controller)
	}
	if controller.ServiceName != "UniFi Controller" {
		t.Errorf("service hint lost: %q", controller.ServiceName)
	}
	if len(controller.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(controller.Certificates))
	}
	cert := controller.Certificates[0]
	if !cert.SelfSigned {
		t.Error("subject == issuer was not flagged self-signed")
	}
	if cert.FingerprintSHA256 == "" || cert.NotAfter == "" || cert.KeyAlgorithm != "RSA" {
		t.Errorf("certificate detail lost: %+v", cert)
	}
}

func TestBuildJobResults_EmptyAndMalformedPayloads(t *testing.T) {
	for name, payload := range map[string]string{
		"empty":     "",
		"malformed": "{not json",
		"no assets": `{"success":true}`,
	} {
		out := buildJobResults("job-1", "pending", payload)
		if out.Assets == nil {
			t.Errorf("%s: assets must serialize as [] not null", name)
		}
		if out.Summary.TotalAssets != 0 {
			t.Errorf("%s: total_assets = %d, want 0", name, out.Summary.TotalAssets)
		}
		if out.JobID != "job-1" || out.Status != "pending" {
			t.Errorf("%s: job identity lost", name)
		}
	}
}
