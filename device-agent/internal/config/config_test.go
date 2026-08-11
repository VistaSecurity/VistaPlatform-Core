package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromFilePreservesEnrolledMTLSPlatformURLOverEnv(t *testing.T) {
	t.Setenv("PLATFORM_URL", "https://edge.example.test")

	configPath := filepath.Join(t.TempDir(), "agent-config.yaml")
	if err := os.WriteFile(configPath, []byte(`agent_id: "8d08afae-1a43-4c56-99b0-f462754d152d"
platform_url: https://agents.example.test:8444
registration_key: REG-0123456789abcdef0123456789abcdef
security:
  client_cert: "cert"
  client_key: "key"
  server_ca_cert: "ca"
  use_tls: true
`), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}

	if cfg.PlatformURL != "https://agents.example.test:8444" {
		t.Fatalf("PlatformURL = %q, want persisted mTLS endpoint", cfg.PlatformURL)
	}
}

func TestLoadFromFileUsesPlatformURLEnvBeforeEnrollment(t *testing.T) {
	t.Setenv("PLATFORM_URL", "https://edge.example.test")

	configPath := filepath.Join(t.TempDir(), "agent-config.yaml")
	if err := os.WriteFile(configPath, []byte(`platform_url: https://bootstrap.example.test
registration_key: REG-0123456789abcdef0123456789abcdef
`), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}

	if cfg.PlatformURL != "https://edge.example.test" {
		t.Fatalf("PlatformURL = %q, want environment bootstrap URL", cfg.PlatformURL)
	}
}
