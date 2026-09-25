package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeConsentConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sensor-config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The local probe-consent keys ( W5.13): absent means off and nothing
// owned; the file sets them; the environment overrides the file, like every
// other capture key.
func TestLocalProbeConsentKeys(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		cfg, err := LoadFromFile(writeConsentConfig(t, "sensorId: s\ncapture:\n  activeProbing: true\n"))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Capture.ThirdPartyTLSEnrichment || len(cfg.Capture.OwnedNetworks) != 0 {
			t.Errorf("absent keys gave opt-in=%v owned=%v, want off and none", cfg.Capture.ThirdPartyTLSEnrichment, cfg.Capture.OwnedNetworks)
		}
	})
	t.Run("file", func(t *testing.T) {
		cfg, err := LoadFromFile(writeConsentConfig(t, "sensorId: s\ncapture:\n  thirdPartyTLSEnrichment: true\n  ownedNetworks:\n    - 203.0.113.0/24\n    - 2001:db8::/32\n"))
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.Capture.ThirdPartyTLSEnrichment {
			t.Error("thirdPartyTLSEnrichment: true was not read")
		}
		if want := []string{"203.0.113.0/24", "2001:db8::/32"}; !reflect.DeepEqual(cfg.Capture.OwnedNetworks, want) {
			t.Errorf("ownedNetworks = %v, want %v", cfg.Capture.OwnedNetworks, want)
		}
	})
	t.Run("env overrides file", func(t *testing.T) {
		t.Setenv("THIRD_PARTY_TLS_ENRICHMENT", "false")
		t.Setenv("OWNED_NETWORKS", "198.51.100.0/24, 192.0.2.0/24")
		cfg, err := LoadFromFile(writeConsentConfig(t, "sensorId: s\ncapture:\n  thirdPartyTLSEnrichment: true\n  ownedNetworks: [203.0.113.0/24]\n"))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Capture.ThirdPartyTLSEnrichment {
			t.Error("THIRD_PARTY_TLS_ENRICHMENT=false did not override the file")
		}
		if want := []string{"198.51.100.0/24", "192.0.2.0/24"}; !reflect.DeepEqual(cfg.Capture.OwnedNetworks, want) {
			t.Errorf("ownedNetworks = %v, want %v from the environment", cfg.Capture.OwnedNetworks, want)
		}
	})
	t.Run("env only", func(t *testing.T) {
		t.Setenv("THIRD_PARTY_TLS_ENRICHMENT", "true")
		t.Setenv("OWNED_NETWORKS", "203.0.113.0/24")
		cfg := Load()
		if !cfg.Capture.ThirdPartyTLSEnrichment || !reflect.DeepEqual(cfg.Capture.OwnedNetworks, []string{"203.0.113.0/24"}) {
			t.Errorf("env-only load gave opt-in=%v owned=%v", cfg.Capture.ThirdPartyTLSEnrichment, cfg.Capture.OwnedNetworks)
		}
	})
	t.Run("env only, unset", func(t *testing.T) {
		cfg := Load()
		if cfg.Capture.ThirdPartyTLSEnrichment || len(cfg.Capture.OwnedNetworks) != 0 {
			t.Errorf("env-only load with nothing set gave opt-in=%v owned=%v, want off and none", cfg.Capture.ThirdPartyTLSEnrichment, cfg.Capture.OwnedNetworks)
		}
	})
}
