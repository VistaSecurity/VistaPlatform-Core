package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDiscoveredAsset_JSONRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)

	original := DiscoveredAsset{
		Hostname:             "test.example.com",
		IPAddress:            "10.0.0.1",
		Port:                 443,
		Protocol:             "TLS",
		ProtocolVersion:      "TLS 1.3",
		AssetType:            "load_balancer",
		CipherSuite:          "TLS_AES_256_GCM_SHA384",
		SupportedCiphers:     []string{"TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"},
		KeySize:              256,
		KeyExchangeAlgorithm: "ECDHE",
		HashAlgorithm:        "SHA384",
		TLSVersions:          []string{"TLS 1.3", "TLS 1.2"},
		CertValidationStatus: "valid",
		Certificate: &CertificateInfo{
			SubjectDN:         "CN=test.example.com",
			IssuerDN:          "CN=Test CA",
			SerialNumber:      "123456",
			NotBefore:         now,
			NotAfter:          now.Add(365 * 24 * time.Hour),
			FingerprintSHA256: "abcdef0123456789",
			KeyAlgorithm:      "RSA",
			KeySize:           2048,
			ChainOrder:        0,
		},
		Certificates: []CertificateInfo{
			{SubjectDN: "CN=test.example.com", ChainOrder: 0},
			{SubjectDN: "CN=Test CA", IsCA: true, ChainOrder: 1},
		},
		SSHInfo: &SSHInfo{
			Banner:             "SSH-2.0-OpenSSH_8.9",
			HostKeyType:        "ssh-ed25519",
			HostKeyFingerprint: "SHA256:abc123",
		},
		DeviceInfo: &DeviceIdentity{
			Vendor:          "F5 Networks",
			Model:           "BIG-IP i5800",
			FirmwareVersion: "16.1.0",
			SerialNumber:    "F5-12345",
		},
		ServiceHints: &ServiceHints{
			ServiceName:          "F5 BIG-IP Virtual Server",
			Confidence:           "high",
			IdentificationMethod: "device_config",
		},
		Metadata: map[string]interface{}{
			"virtual_server": "vip-https",
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Unmarshal back
	var decoded DiscoveredAsset
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Verify key fields survived the round trip
	if decoded.Hostname != original.Hostname {
		t.Errorf("Hostname: got %q, want %q", decoded.Hostname, original.Hostname)
	}
	if decoded.AssetType != original.AssetType {
		t.Errorf("AssetType: got %q, want %q", decoded.AssetType, original.AssetType)
	}
	if decoded.KeyExchangeAlgorithm != original.KeyExchangeAlgorithm {
		t.Errorf("KeyExchangeAlgorithm: got %q, want %q", decoded.KeyExchangeAlgorithm, original.KeyExchangeAlgorithm)
	}
	if len(decoded.SupportedCiphers) != 2 {
		t.Errorf("SupportedCiphers: got %d, want 2", len(decoded.SupportedCiphers))
	}
	if len(decoded.TLSVersions) != 2 {
		t.Errorf("TLSVersions: got %d, want 2", len(decoded.TLSVersions))
	}
	if len(decoded.Certificates) != 2 {
		t.Errorf("Certificates: got %d, want 2", len(decoded.Certificates))
	}
	if decoded.CertValidationStatus != "valid" {
		t.Errorf("CertValidationStatus: got %q, want %q", decoded.CertValidationStatus, "valid")
	}
	if decoded.SSHInfo == nil || decoded.SSHInfo.Banner != "SSH-2.0-OpenSSH_8.9" {
		t.Error("SSHInfo not preserved through round trip")
	}
	if decoded.DeviceInfo == nil || decoded.DeviceInfo.Vendor != "F5 Networks" {
		t.Error("DeviceInfo not preserved through round trip")
	}
	if decoded.ServiceHints == nil || decoded.ServiceHints.ServiceName != "F5 BIG-IP Virtual Server" {
		t.Error("ServiceHints not preserved through round trip")
	}
	if decoded.Certificate == nil || decoded.Certificate.FingerprintSHA256 != "abcdef0123456789" {
		t.Error("Certificate fingerprint not preserved through round trip")
	}
}

func TestDiscoveredAsset_BackwardCompatibility(t *testing.T) {
	// Old agent payload with only the original fields
	oldPayload := `{
		"hostname": "old-agent.example.com",
		"ip_address": "10.0.0.1",
		"port": 443,
		"protocol": "TLS",
		"protocol_version": "1.2",
		"cipher_suite": "TLS_RSA_WITH_AES_256_CBC_SHA",
		"key_size": 256,
		"certificate": {
			"subject_dn": "CN=old",
			"issuer_dn": "CN=CA"
		}
	}`

	var asset DiscoveredAsset
	if err := json.Unmarshal([]byte(oldPayload), &asset); err != nil {
		t.Fatalf("failed to unmarshal old payload: %v", err)
	}

	if asset.Hostname != "old-agent.example.com" {
		t.Errorf("Hostname: got %q", asset.Hostname)
	}
	if asset.CipherSuite != "TLS_RSA_WITH_AES_256_CBC_SHA" {
		t.Errorf("CipherSuite: got %q", asset.CipherSuite)
	}
	if asset.Certificate == nil || asset.Certificate.SubjectDN != "CN=old" {
		t.Error("backward compat: Certificate not parsed")
	}

	// New fields should be zero-valued
	if asset.AssetType != "" {
		t.Errorf("AssetType should be empty for old payload, got %q", asset.AssetType)
	}
	if len(asset.SupportedCiphers) != 0 {
		t.Errorf("SupportedCiphers should be empty for old payload, got %d", len(asset.SupportedCiphers))
	}
	if asset.SSHInfo != nil {
		t.Error("SSHInfo should be nil for old payload")
	}
	if asset.DeviceInfo != nil {
		t.Error("DeviceInfo should be nil for old payload")
	}
}

func TestCertificateInfo_ChainOrdering(t *testing.T) {
	chain := []CertificateInfo{
		{SubjectDN: "CN=leaf", ChainOrder: 0, IsCA: false},
		{SubjectDN: "CN=intermediate", ChainOrder: 1, IsCA: true},
		{SubjectDN: "CN=root", ChainOrder: 2, IsCA: true},
	}

	data, err := json.Marshal(chain)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded []CertificateInfo
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(decoded) != 3 {
		t.Fatalf("chain length: got %d, want 3", len(decoded))
	}
	if decoded[0].ChainOrder != 0 || decoded[0].SubjectDN != "CN=leaf" {
		t.Error("leaf cert not at position 0")
	}
	if decoded[2].ChainOrder != 2 || !decoded[2].IsCA {
		t.Error("root cert not at position 2 or not marked as CA")
	}
}

func TestSSHInfo_JSON(t *testing.T) {
	info := SSHInfo{
		Banner:               "SSH-2.0-OpenSSH_9.0",
		HostKeyType:          "ssh-ed25519",
		HostKeyFingerprint:   "SHA256:test123",
		KexAlgorithm:         "curve25519-sha256",
		EncryptionAlgC2S:     "aes256-gcm@openssh.com",
		EncryptionAlgS2C:     "aes256-gcm@openssh.com",
		MACAlgC2S:            "hmac-sha2-256-etm@openssh.com",
		MACAlgS2C:            "hmac-sha2-256-etm@openssh.com",
		CompressionAlgorithm: "none",
		KeyTypes:             []string{"ssh-ed25519", "rsa-sha2-256"},
	}

	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded SSHInfo
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Banner != info.Banner {
		t.Errorf("Banner: got %q, want %q", decoded.Banner, info.Banner)
	}
	if decoded.KexAlgorithm != info.KexAlgorithm {
		t.Errorf("KexAlgorithm: got %q, want %q", decoded.KexAlgorithm, info.KexAlgorithm)
	}
	if len(decoded.KeyTypes) != 2 {
		t.Errorf("KeyTypes: got %d, want 2", len(decoded.KeyTypes))
	}
}

func TestDeviceIdentity_JSON(t *testing.T) {
	di := DeviceIdentity{
		Vendor:          "Cisco",
		Model:           "ASA5525",
		FirmwareVersion: "9.16(3)",
		SerialNumber:    "JMX1234ABCD",
		OSVersion:       "ASA 9.16(3)",
	}

	data, err := json.Marshal(di)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded DeviceIdentity
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Vendor != di.Vendor {
		t.Errorf("Vendor: got %q, want %q", decoded.Vendor, di.Vendor)
	}
	if decoded.OSVersion != di.OSVersion {
		t.Errorf("OSVersion: got %q, want %q", decoded.OSVersion, di.OSVersion)
	}
}
