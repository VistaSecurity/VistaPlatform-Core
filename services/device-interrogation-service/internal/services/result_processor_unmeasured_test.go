package services

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
)

// Unknown stays unknown ( W1.2) at the writer both runtimes share: a TLS,
// DTLS or SSH configuration with no protocol version carries
// unmeasured_components = ["protocol_version"] into sensor_discoveries, which
// the converter copies into raw_data and inventory reads as "partially
// assessed". A measured version carries no marker.
func TestBuildSensorDiscoveryMetadata_UnmeasuredProtocolVersionIsMarked(t *testing.T) {
	deviceID := uuid.New()
	for _, c := range []struct {
		name        string
		asset       models.DiscoveredAsset
		wantVersion interface{} // nil = key absent
		wantMarked  bool
	}{
		{
			name:        "TLS with a measured version",
			asset:       models.DiscoveredAsset{Protocol: "TLS", ProtocolVersion: "TLS 1.0", CipherSuite: "AES128-SHA"},
			wantVersion: "TLS 1.0",
		},
		{
			name:        "TLS with no version",
			asset:       models.DiscoveredAsset{Protocol: "TLS", CipherSuite: "ECDHE+AES-GCM:!aNULL"},
			wantVersion: "",
			wantMarked:  true,
		},
		{
			name:        "DTLS with no version",
			asset:       models.DiscoveredAsset{Protocol: "DTLS"},
			wantVersion: "",
			wantMarked:  true,
		},
		{
			name: "SSH banner 1.99 is the version",
			asset: models.DiscoveredAsset{Protocol: "SSH",
				SSHInfo: &models.SSHInfo{Banner: "SSH-1.99-Cisco-1.25"}},
			wantVersion: "SSH-1.99",
		},
		{
			// An agent built before W1.2 still sends the constant.
			name:        "SSH constant without a banner",
			asset:       models.DiscoveredAsset{Protocol: "SSH", ProtocolVersion: "SSH-2.0"},
			wantVersion: nil,
			wantMarked:  true,
		},
		{
			name:        "IPsec is not version-scored here",
			asset:       models.DiscoveredAsset{Protocol: "IPsec"},
			wantVersion: "",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			meta := buildSensorDiscoveryMetadata(&deviceID, nil, c.asset)
			got, present := meta["version"]
			if c.wantVersion == nil {
				if present {
					t.Errorf("version = %v, want absent", got)
				}
			} else if got != c.wantVersion {
				t.Errorf("version = %v, want %v", got, c.wantVersion)
			}
			marker, marked := meta[unmeasuredComponentsKey]
			if marked != c.wantMarked {
				t.Fatalf("%s present = %v (%v), want %v", unmeasuredComponentsKey, marked, marker, c.wantMarked)
			}
			if marked && !reflect.DeepEqual(marker, []string{"protocol_version"}) {
				t.Errorf("%s = %#v", unmeasuredComponentsKey, marker)
			}
		})
	}
}

// From the collector's own output: an F5 client-ssl profile with no version
// field, converted exactly as the platform runtime converts it, reaches
// sensor_discoveries with no version and the marker — not the "TLS 1.2" the
// collector used to invent.
func TestBuildSensorDiscoveryMetadata_CollectorAssetWithoutVersion(t *testing.T) {
	ca := &di.CryptoAsset{
		IPAddress: "198.51.100.11", Port: 443, Protocol: "TLS", AssetType: "load_balancer",
		Metadata: map[string]interface{}{"tls_versions_disabled": []string{"SSL 3.0", "TLS 1.0", "TLS 1.1"}},
	}
	deviceID := uuid.New()
	meta := buildSensorDiscoveryMetadata(&deviceID, nil, toDiscoveredAsset(ca, nil))
	if v := meta["version"]; v != "" {
		t.Errorf("version = %v, want empty", v)
	}
	if _, ok := meta["tls_versions"]; ok {
		t.Errorf("tls_versions = %v, want absent", meta["tls_versions"])
	}
	if !reflect.DeepEqual(meta[unmeasuredComponentsKey], []string{"protocol_version"}) {
		t.Errorf("%s = %#v", unmeasuredComponentsKey, meta[unmeasuredComponentsKey])
	}
}
