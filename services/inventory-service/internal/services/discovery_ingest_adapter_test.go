package services

import (
	"encoding/json"
	"testing"
)

// ptrStr / ptrInt are local helpers to keep table rows terse.
func ptrStr(s string) *string { return &s }
func ptrInt(i int) *int       { return &i }

// TestToIngestFinding_ClusterSensorWireShape pins the cluster-sensor → IngestFinding
// contract: the field renames and nested-crypto promotion that previously lived as
// untyped map munging in the HTTP handler. This is the regression guard for the
// "3rd-party discovery produced 0 rows / NULL cert+cipher" class of bug.
func TestToIngestFinding_ClusterSensorWireShape(t *testing.T) {
	// A finding exactly as cluster-sensor-service serialises it: "data" (not
	// "raw_data"), "resolved_ip" (not "ip_address"), crypto nested in "data",
	// and TLS version under "tls_version".
	raw := `{
		"hostname": "www.example.com",
		"resolved_ip": "142.250.80.3",
		"port": 443,
		"protocol": "tls",
		"data": {
			"cipher_suite": "TLS_AES_128_GCM_SHA256",
			"tls_version": "TLS 1.3",
			"key_exchange_algorithm": "ECDHE",
			"key_size": 256,
			"hash_algorithm": "SHA256",
			"cert_subject": "CN=example.com"
		}
	}`

	var csf ClusterSensorFinding
	if err := json.Unmarshal([]byte(raw), &csf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out := csf.ToIngestFinding()

	if out.IPAddress == nil || *out.IPAddress != "142.250.80.3" {
		t.Errorf("resolved_ip should map to ip_address; got %v", out.IPAddress)
	}
	if out.RawData == nil || out.RawData["cert_subject"] != "CN=example.com" {
		t.Errorf(`"data" should be promoted to raw_data with cert details; got %v`, out.RawData)
	}
	if out.CipherSuite == nil || *out.CipherSuite != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("cipher_suite should be back-filled from data; got %v", out.CipherSuite)
	}
	if out.ProtocolVersion == nil || *out.ProtocolVersion != "TLS 1.3" {
		t.Errorf("tls_version should back-fill protocol_version; got %v", out.ProtocolVersion)
	}
	if out.KeyExchangeAlgorithm == nil || *out.KeyExchangeAlgorithm != "ECDHE" {
		t.Errorf("key_exchange_algorithm should be back-filled; got %v", out.KeyExchangeAlgorithm)
	}
	if out.KeySize == nil || *out.KeySize != 256 {
		t.Errorf("key_size should be back-filled as int; got %v", out.KeySize)
	}
	if out.HashAlgorithm == nil || *out.HashAlgorithm != "SHA256" {
		t.Errorf("hash_algorithm should be back-filled; got %v", out.HashAlgorithm)
	}
}

// TestToIngestFinding_NativeFieldsWin verifies that a producer already emitting
// the canonical IngestFinding field names is passed through untouched, and that
// native values take precedence over the cluster-sensor aliases.
func TestToIngestFinding_NativeFieldsWin(t *testing.T) {
	csf := ClusterSensorFinding{
		Hostname:        ptrStr("host.example"),
		IPAddress:       ptrStr("10.0.0.9"),   // native — must win over resolved_ip
		ResolvedIP:      ptrStr("10.0.0.255"), // alias — must be ignored
		RawData:         map[string]interface{}{"k": "native"},
		Data:            map[string]interface{}{"k": "alias", "cipher_suite": "SHOULD_NOT_OVERRIDE"},
		CipherSuite:     ptrStr("TLS_NATIVE"), // native top-level — must win over data
		Protocol:        "tls",
		Port:            ptrInt(8443),
		OperatingSystem: ptrStr("linux"),
	}
	out := csf.ToIngestFinding()

	if *out.IPAddress != "10.0.0.9" {
		t.Errorf("native ip_address must win; got %v", *out.IPAddress)
	}
	if out.RawData["k"] != "native" {
		t.Errorf("native raw_data must win; got %v", out.RawData)
	}
	if *out.CipherSuite != "TLS_NATIVE" {
		t.Errorf("native cipher_suite must not be overridden by data; got %v", *out.CipherSuite)
	}
	if out.OperatingSystem == nil || *out.OperatingSystem != "linux" {
		t.Errorf("pass-through fields must be preserved; got %v", out.OperatingSystem)
	}
}

// TestToIngestFinding_EmptyResolvedIPFallsThrough ensures an empty resolved_ip
// does not clobber a missing ip_address (it stays nil so the DNS fallback in
// routeToExternalConnection can run).
func TestToIngestFinding_EmptyResolvedIPFallsThrough(t *testing.T) {
	csf := ClusterSensorFinding{
		Hostname:   ptrStr("only-hostname.example"),
		ResolvedIP: ptrStr(""),
	}
	out := csf.ToIngestFinding()
	if out.IPAddress != nil && *out.IPAddress != "" {
		t.Errorf("empty resolved_ip should leave ip_address unset; got %v", out.IPAddress)
	}
}
