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

func TestLoadFromFileVerboseEnvOverridesAbsentKey(t *testing.T) {
	t.Setenv("VERBOSE", "false")

	configPath := filepath.Join(t.TempDir(), "sensor-config.yaml")
	if err := os.WriteFile(configPath, []byte(`controlPlaneUrl: "https://platform.example"
`), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if cfg.Verbose == nil || *cfg.Verbose {
		t.Fatalf("Verbose = %v, want explicit false from VERBOSE env", cfg.Verbose)
	}
}

// TestLoadFromFile_LegacyStorageKeysAreInert pins the upgrade path for sensors
// installed before the write-only encrypted discovery store was removed.
//
// Those hosts have a sensor-config.yaml carrying encryptionKey, keyPath,
// rotationSize, retentionDays, maxStorageSize, minFreeSpaceMB and
// enableCompression under storage:. Those keys no longer map to any field. The
// decoder must keep ignoring them: if config loading is ever switched to strict
// decoding (yaml KnownFields / UnmarshalStrict), every upgraded sensor would
// fail to start on a config file it wrote itself.
func TestLoadFromFile_LegacyStorageKeysAreInert(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sensor-config.yaml")

	legacy := `sensorId: "11111111-2222-3333-4444-555555555555"
controlPlaneUrl: "https://platform.example.com"
reportingIntervalSeconds: 30
storage:
  maxStorageSize: 104857600
  rotationSize: 10485760
  retentionDays: 7
  dataPath: "` + dir + `"
  encryptionKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  keyPath: "/var/lib/crypto-sensor-keys"
  minFreeSpaceMB: 100
  enableCompression: true
capture:
  interfaces: ["eth0"]
`
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("a pre-upgrade sensor config must still load, got: %v", err)
	}

	// The one storage field that survived must come through intact...
	if cfg.Storage.DataPath != dir {
		t.Errorf("Storage.DataPath = %q, want %q", cfg.Storage.DataPath, dir)
	}
	// ...and the rest of the file must not have been derailed by the dead keys.
	if cfg.ControlPlaneURL != "https://platform.example.com" {
		t.Errorf("ControlPlaneURL = %q, want https://platform.example.com", cfg.ControlPlaneURL)
	}
	if len(cfg.Capture.Interfaces) != 1 || cfg.Capture.Interfaces[0] != "eth0" {
		t.Errorf("Capture.Interfaces = %v, want [eth0]", cfg.Capture.Interfaces)
	}
}
