package deviceinterrogation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every collector that turns a vendor response into asset metadata must project
// onto an allowlist rather than copy the object. These tests feed each converter
// a realistic response WITH the secret fields that vendor actually returns, and
// assert the material does not survive.
//
// The redaction backstop in redact.go would catch most of these by field name.
// That is deliberately not what is being tested here — the point is that the
// data is never collected, so these tests call the converters directly, before
// any redaction runs.

// poison is a value that must never appear in a converted asset.
const poison = "MUST-NOT-BE-COLLECTED"

func assertNoPoison(t *testing.T, label string, v interface{}) {
	t.Helper()
	blob, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("%s: marshal: %v", label, err)
	}
	if strings.Contains(string(blob), poison) {
		t.Errorf("%s: collected material that should have been projected away: %s", label, blob)
	}
}

// FortiOS `vpn.ipsec/phase1-interface` carries psksecret — the tunnel's
// pre-shared key — alongside the proposal we want.
func TestFortinetIPSecProjection_DropsPreSharedKey(t *testing.T) {
	c := &fortinetClient{}
	asset := c.convertIPSecToAsset(map[string]interface{}{
		"name":           "branch-tunnel",
		"remote-gw":      "198.51.100.7",
		"proposal":       "aes256-sha256",
		"dhgrp":          "14",
		"psksecret":      poison,
		"ppk-secret":     poison,
		"authpasswd":     poison,
		"ipv4-split-inc": poison, // not secret, just not on the allowlist
	})

	assertNoPoison(t, "fortinet ipsec", asset)
	if asset.Hostname != "branch-tunnel" {
		t.Errorf("identity lost: %+v", asset)
	}
	if asset.Metadata["dh_group"] != "14" {
		t.Errorf("posture lost: %#v", asset.Metadata)
	}
	if asset.CipherSuite == nil || *asset.CipherSuite != "aes256-sha256" {
		t.Errorf("proposal lost: %+v", asset.CipherSuite)
	}
}

func TestFortinetSSLVPNProjection_DropsUnlistedFields(t *testing.T) {
	c := &fortinetClient{}
	asset := c.convertSSLVPNToAsset(map[string]interface{}{
		"server_hostname": "vpn.example.net",
		"port":            float64(10443),
		"cipher":          "TLS-AES-256-GCM-SHA384",
		"tls_version":     "TLS 1.3",
		"server_cert":     "Fortinet_SSL",
		"x-auth-secret":   poison,
		"admin-password":  poison,
	})

	assertNoPoison(t, "fortinet sslvpn", asset)
	if asset.Hostname != "vpn.example.net" || asset.Port != 10443 {
		t.Errorf("identity lost: %+v", asset)
	}
	if asset.Metadata["certificate_name"] != "Fortinet_SSL" {
		t.Errorf("certificate reference lost: %#v", asset.Metadata)
	}
}

// FortiOS `certificate/local` returns the certificate's own private key.
func TestFortinetCertificateProjection_DropsPrivateKey(t *testing.T) {
	out := processFortinetCertificate(map[string]interface{}{
		"name":        "Fortinet_SSL",
		"private-key": poison,
		"password":    poison,
		"csr":         poison,
		"range":       "global",
	})

	assertNoPoison(t, "fortinet certificate", out)
	if out["name"] != "Fortinet_SSL" {
		t.Errorf("certificate identity lost: %#v", out)
	}
}

// The generic HTTP interrogator reads a device-configurable endpoint, so the
// response shape is under the remote device's control.
func TestHTTPCertificateProjection_DropsUnlistedFields(t *testing.T) {
	out := projectHTTPCertificate(map[string]interface{}{
		"subject":          "CN=api.example.net",
		"issuer":           "CN=Example CA",
		"serial_number":    "0A1B2C",
		"not_after":        "2027-01-01T00:00:00Z",
		"key_algorithm":    "RSA",
		"key_size":         2048,
		"private_key_pem":  poison,
		"passphrase":       poison,
		"enrollment_token": poison,
		"vendor_blob":      map[string]interface{}{"nested": poison},
	})

	assertNoPoison(t, "http certificate", out)
	if out["subject"] != "CN=api.example.net" || out["key_size"] != 2048 {
		t.Errorf("certificate detail lost: %#v", out)
	}
}

// Hyphenated and camelCase spellings must fold to the same fragment — FortiOS
// says `private-key`, PAN-OS says `private_key`, some APIs say `privateKey`.
func TestIsSecretFieldName_FoldsSeparators(t *testing.T) {
	for _, name := range []string{
		"private-key", "private_key", "privateKey", "Private Key",
		"psk-secret", "psk_secret", "x-api-key", "x.api.key",
		"admin-password", "shared-secret",
	} {
		if !isSecretFieldName(name) {
			t.Errorf("field %q should be treated as secret material but was not", name)
		}
	}
	// The load-bearing half: these END in "key", so the catch-all suffix rule
	// would redact them. Only folding lets them match the safe list, which is
	// spelled with underscores. Without folding these are false positives and we
	// lose the public-key algorithm we are in business to report.
	for _, name := range []string{"public-key", "public key", "Public-Key"} {
		if isSecretFieldName(name) {
			t.Errorf("posture field %q was redacted; separator folding is not being applied", name)
		}
	}
	for _, name := range []string{"key-size", "key-algorithm", "host-key-type"} {
		if isSecretFieldName(name) {
			t.Errorf("posture field %q was redacted after separator folding", name)
		}
	}
}

// Projection has to be WIRED, not merely available. This drives the real
// interrogator against a stub device so a future refactor that drops the
// projectHTTPCertificate call is caught, which a direct unit call cannot see.
func TestHTTPInterrogator_ProjectionIsWired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"certificates":[{
			"subject": "CN=api.example.net",
			"key_algorithm": "RSA",
			"private_key_pem": "` + poison + `",
			"passphrase": "` + poison + `"
		}]}`))
	}))
	defer srv.Close()

	result, err := (&HTTPInterrogator{}).Interrogate(
		context.Background(),
		DeviceInfo{DeviceType: "generic_http", ManagementURL: srv.URL, Hostname: ""},
		Credentials{},
	)
	if err != nil {
		t.Fatalf("Interrogate: %v", err)
	}
	assertNoPoison(t, "http interrogator (wired)", result)

	if len(result.Assets) == 0 {
		t.Fatal("no assets returned — the stub response was not parsed")
	}
	if result.Assets[0].Metadata["subject"] != "CN=api.example.net" {
		t.Errorf("certificate detail lost: %#v", result.Assets[0].Metadata)
	}
}
