package handlers

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAdvertisedServerCACertUsesPlatformCAWhenAgentMTLSIsRequired(t *testing.T) {
	platformCA := "-----BEGIN CERTIFICATE-----\nplatform\n-----END CERTIFICATE-----\n"
	caPath := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caPath, []byte(platformCA), 0o600); err != nil {
		t.Fatalf("write platform CA: %v", err)
	}

	t.Setenv("AGENT_MTLS_REQUIRED", "true")
	t.Setenv("PLATFORM_CA_CERT_PATH", caPath)

	if got := advertisedServerCACert("tenant-ca"); got != platformCA {
		t.Fatalf("advertised CA = %q, want platform CA", got)
	}
}

func TestAdvertisedServerCACertFallsBackToTenantCA(t *testing.T) {
	t.Setenv("AGENT_MTLS_REQUIRED", "false")
	t.Setenv("PLATFORM_CA_CERT_PATH", filepath.Join(t.TempDir(), "missing.crt"))

	if got := advertisedServerCACert("tenant-ca"); got != "tenant-ca" {
		t.Fatalf("advertised CA = %q, want tenant CA", got)
	}
}
