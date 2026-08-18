package services

import (
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
)

// ---------------------------------------------------------------------------
// extractCryptoConfigs
//
// The discovery functions build metadata["crypto_configs"] in memory as a
// []map[string]interface{} holding *string / *int fields, and the resulting
// models.Device is handed to WriteSensorDiscoveries WITHOUT a database round
// trip. The old `.([]interface{})` assertion never matched that, so every
// cloud discovery fell through to the "no crypto configs" branch: one bare
// TLS/443 row per device, no protocol version, no cipher suite, no
// certificates. Nothing errored; the rows simply carried nothing.
// ---------------------------------------------------------------------------

func TestExtractCryptoConfigs_InMemorySliceOfMaps(t *testing.T) {
	version := "TLS 1.0"
	cipher := "ECDHE-ECDSA-AES128-GCM-SHA256"
	keySize := 2048

	md := map[string]interface{}{
		"crypto_configs": []map[string]interface{}{
			{
				"protocol":         "HTTPS",
				"protocol_version": &version, // pointer, as built by discoverLoadBalancers
				"cipher_suite":     &cipher,
				"key_size":         &keySize,
				"port":             443,
				"hostname":         "lb.example.com",
			},
		},
	}

	configs := extractCryptoConfigs(md)
	if len(configs) != 1 {
		t.Fatalf("got %d configs, want 1 — the in-memory []map[string]interface{} "+
			"shape must be recognised or every cloud discovery loses its crypto detail", len(configs))
	}

	// Pointers must have been flattened to plain JSON values, because that is
	// what every downstream reader (getStringFromMap, convertCryptoConfigToAsset)
	// assumes.
	if got := getStringFromMap(configs[0], "protocol_version"); got != "TLS 1.0" {
		t.Fatalf("protocol_version = %q, want %q (a *string here reads as empty downstream)", got, "TLS 1.0")
	}
	if got := getStringFromMap(configs[0], "cipher_suite"); got != cipher {
		t.Fatalf("cipher_suite = %q, want %q", got, cipher)
	}
	if _, ok := configs[0]["key_size"].(float64); !ok {
		t.Fatalf("key_size = %#v, want a JSON number", configs[0]["key_size"])
	}
	if _, ok := configs[0]["port"].(float64); !ok {
		t.Fatalf("port = %#v, want a JSON number", configs[0]["port"])
	}
}

func TestExtractCryptoConfigs_AlreadyJSONShape(t *testing.T) {
	// A device re-read from Postgres arrives already JSON-shaped; both shapes
	// must work.
	md := map[string]interface{}{
		"crypto_configs": []interface{}{
			map[string]interface{}{"protocol": "TLS", "protocol_version": "TLS 1.2"},
		},
	}
	configs := extractCryptoConfigs(md)
	if len(configs) != 1 || getStringFromMap(configs[0], "protocol_version") != "TLS 1.2" {
		t.Fatalf("configs = %#v, want one config with protocol_version TLS 1.2", configs)
	}
}

func TestExtractCryptoConfigs_Absent(t *testing.T) {
	if got := extractCryptoConfigs(nil); got != nil {
		t.Errorf("extractCryptoConfigs(nil) = %v, want nil", got)
	}
	if got := extractCryptoConfigs(map[string]interface{}{}); got != nil {
		t.Errorf("extractCryptoConfigs(empty) = %v, want nil", got)
	}
	if got := extractCryptoConfigs(map[string]interface{}{"crypto_configs": nil}); got != nil {
		t.Errorf("extractCryptoConfigs(nil configs) = %v, want nil", got)
	}
}

// ---------------------------------------------------------------------------
// cloudRegionForDevice
//
// inventory-service's FindOrCreateCloudSegment only runs when BOTH
// cloud_provider and cloud_region are present on the finding. cloud_region was
// never written, so cloud-segment enrichment was dead for every AWS resource.
// ---------------------------------------------------------------------------

func TestCloudRegionForDevice(t *testing.T) {
	dev := func(deviceType string, md map[string]interface{}) models.Device {
		return models.Device{ID: uuid.New(), DeviceType: deviceType, Metadata: models.JSONB(md)}
	}

	tests := []struct {
		name   string
		device models.Device
		want   string
	}{
		{
			name:   "regional resource uses its recorded region",
			device: dev("aws_alb", map[string]interface{}{"region": "eu-west-2"}),
			want:   "eu-west-2",
		},
		{
			name:   "S3 bucket carries its own resolved home region",
			device: dev("aws_s3_bucket", map[string]interface{}{"region": "ap-southeast-2"}),
			want:   "ap-southeast-2",
		},
		{
			// CloudFront is genuinely global. Claiming it lives in the
			// integration's default region would be misleading, so say so.
			name:   "CloudFront is global, not the integration default region",
			device: dev("aws_cloudfront", map[string]interface{}{"distribution_id": "E123"}),
			want:   "global",
		},
		{
			// Better an absent region than an invented one: an empty value
			// simply leaves FindOrCreateCloudSegment unfired, as before.
			name:   "unknown resource with no region stays empty",
			device: dev("aws_mystery", map[string]interface{}{}),
			want:   "",
		},
		{
			name:   "nil metadata is safe",
			device: models.Device{DeviceType: "aws_alb"},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cloudRegionForDevice(tt.device); got != tt.want {
				t.Errorf("cloudRegionForDevice = %q, want %q", got, tt.want)
			}
		})
	}
}
