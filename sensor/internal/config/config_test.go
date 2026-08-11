package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromFilePreservesEnrolledMTLSControlPlaneURLOverEnv(t *testing.T) {
	t.Setenv("CONTROL_PLANE_URL", "https://edge.example.test")

	configPath := filepath.Join(t.TempDir(), "sensor-config.yaml")
	if err := os.WriteFile(configPath, []byte(`sensorId: "8d08afae-1a43-4c56-99b0-f462754d152d"
controlPlaneUrl: "https://agents.example.test:8444"
registrationKey: "REG-0123456789abcdef0123456789abcdef"

security:
  clientCert: "cert"
  clientKey: "key"
  serverCACert: "ca"
  useTLS: true
`), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}

	if cfg.ControlPlaneURL != "https://agents.example.test:8444" {
		t.Fatalf("ControlPlaneURL = %q, want persisted mTLS endpoint", cfg.ControlPlaneURL)
	}
}

func TestLoadFromFileUsesControlPlaneURLEnvBeforeEnrollment(t *testing.T) {
	t.Setenv("CONTROL_PLANE_URL", "https://edge.example.test")

	configPath := filepath.Join(t.TempDir(), "sensor-config.yaml")
	if err := os.WriteFile(configPath, []byte(`sensorId: ""
controlPlaneUrl: "https://bootstrap.example.test"
registrationKey: "REG-0123456789abcdef0123456789abcdef"
`), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}

	if cfg.ControlPlaneURL != "https://edge.example.test" {
		t.Fatalf("ControlPlaneURL = %q, want environment bootstrap URL", cfg.ControlPlaneURL)
	}
}
