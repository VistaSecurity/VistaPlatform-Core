package services

import (
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
)

// TestBuildSensorDiscoveryMetadata_KeyContract pins the metadata key names the
// sensor_discoveries pipeline depends on. discovery-processor's
// extractCryptoDetails reads the protocol version from "version" (NOT
// "protocol_version") and the chain from "certificates" — a drift here would
// silently strip enrichment from device-interrogated assets.
func TestBuildSensorDiscoveryMetadata_KeyContract(t *testing.T) {
	deviceID := uuid.New()
	job := &models.DeviceJob{
		TenantID: uuid.New(),
		DeviceID: &deviceID,
	}
	asset := models.DiscoveredAsset{
		Hostname:        "vip.example.com",
		ProtocolVersion: "TLS 1.2",
		CipherSuite:     "ECDHE-RSA-AES256-GCM-SHA384",
		HashAlgorithm:   "SHA384",
		KeySize:         256,
		TLSVersions:     []string{"TLS 1.2", "TLS 1.3"},
		AssetType:       "load_balancer",
		Certificates: []models.CertificateInfo{
			{SubjectDN: "CN=vip.example.com", ChainOrder: 0, CertificatePEM: "x"},
		},
	}

	meta := buildSensorDiscoveryMetadata(job, asset)

	if got := meta["discovery_method"]; got != "device_interrogation" {
		t.Errorf("discovery_method = %v, want device_interrogation", got)
	}
	if got := meta["version"]; got != "TLS 1.2" {
		t.Errorf("version = %v, want TLS 1.2 (extractCryptoDetails reads \"version\")", got)
	}
	if _, ok := meta["protocol_version"]; ok {
		t.Errorf("metadata must NOT use protocol_version key; extractCryptoDetails reads \"version\"")
	}
	if got := meta["cipher_suite"]; got != asset.CipherSuite {
		t.Errorf("cipher_suite = %v, want %v", got, asset.CipherSuite)
	}
	if got := meta["device_id"]; got != deviceID.String() {
		t.Errorf("device_id = %v, want %v", got, deviceID.String())
	}
	certs, ok := meta["certificates"].([]map[string]interface{})
	if !ok || len(certs) != 1 {
		t.Fatalf("certificates: want 1-entry canonical array, got %#v", meta["certificates"])
	}
	if certs[0]["subject_dn"] != "CN=vip.example.com" {
		t.Errorf("certificate subject_dn = %v", certs[0]["subject_dn"])
	}
}

// TestMergeCertFlags verifies precomputed flags + OCSP fields land in the map and
// that empty inputs are a no-op.
func TestMergeCertFlags(t *testing.T) {
	dst := map[string]interface{}{}
	mergeCertFlags(dst, map[string]interface{}{"cert_has_sct": true, "cert_is_ev": true}, "good", "responder=x")
	if dst["cert_has_sct"] != true || dst["cert_is_ev"] != true {
		t.Errorf("flags not merged: %#v", dst)
	}
	if dst["ocsp_status"] != "good" || dst["ocsp_detail"] != "responder=x" {
		t.Errorf("ocsp fields not merged: %#v", dst)
	}

	empty := map[string]interface{}{}
	mergeCertFlags(empty, nil, "", "")
	if len(empty) != 0 {
		t.Errorf("empty merge should be a no-op, got %#v", empty)
	}
}
