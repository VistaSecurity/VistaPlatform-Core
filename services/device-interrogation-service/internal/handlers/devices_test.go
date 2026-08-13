package handlers

import (
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
)

// TestStripBulkyDeviceMetadata_RemovesCertKeys pins L-7: a device list
// response must not carry the certificate-chain metadata cloud discovery
// stashes on devices (e.g. an AWS CloudFront distribution), since nothing on
// the Devices list view reads it and it can run multiple KB per device.
func TestStripBulkyDeviceMetadata_RemovesCertKeys(t *testing.T) {
	d := &models.Device{
		ID: uuid.New(),
		Metadata: models.JSONB{
			"crypto_configs": []interface{}{
				map[string]interface{}{"certificates": []interface{}{
					map[string]interface{}{"certificate_pem": "-----BEGIN CERTIFICATE-----\n...huge...\n-----END CERTIFICATE-----"},
				}},
			},
			"certificates":    []interface{}{"also huge"},
			"auto_discovered": true,
		},
	}
	out := stripBulkyDeviceMetadata([]*models.Device{d})
	if len(out) != 1 {
		t.Fatalf("expected 1 device, got %d", len(out))
	}
	got := out[0].Metadata
	if _, ok := got["crypto_configs"]; ok {
		t.Fatal("expected crypto_configs to be stripped")
	}
	if _, ok := got["certificates"]; ok {
		t.Fatal("expected certificates to be stripped")
	}
	if v, ok := got["auto_discovered"]; !ok || v != true {
		t.Fatalf("expected unrelated metadata to survive, got %v", got)
	}
}

// TestStripBulkyDeviceMetadata_LeavesOrdinaryDevicesUnmodified covers the
// common case (a network device with no crypto_configs/certificates metadata
// at all) — the function must be a no-op, not error or nil out Metadata.
func TestStripBulkyDeviceMetadata_LeavesOrdinaryDevicesUnmodified(t *testing.T) {
	d := &models.Device{
		ID:       uuid.New(),
		Metadata: models.JSONB{"site_id": "abc123"},
	}
	out := stripBulkyDeviceMetadata([]*models.Device{d})
	if out[0].Metadata["site_id"] != "abc123" {
		t.Fatalf("expected metadata untouched, got %v", out[0].Metadata)
	}
}

// TestStripBulkyDeviceMetadata_NilMetadataAndNilDevice covers the
// defensive nil-guards: a device with no metadata at all, and a nil slice
// element, must not panic.
func TestStripBulkyDeviceMetadata_NilMetadataAndNilDevice(t *testing.T) {
	d := &models.Device{ID: uuid.New(), Metadata: nil}
	out := stripBulkyDeviceMetadata([]*models.Device{d, nil})
	if len(out) != 2 {
		t.Fatalf("expected 2 elements preserved, got %d", len(out))
	}
	if out[0].Metadata != nil {
		t.Fatalf("expected nil metadata to stay nil, got %v", out[0].Metadata)
	}
}
