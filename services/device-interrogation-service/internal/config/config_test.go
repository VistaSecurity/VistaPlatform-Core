package config

import (
	"os"
	"testing"
)

// TestAgentMTLSDefaultsToRequired pins the fail-closed default for discovery
// agents, mirroring the sensor-manager test. Both runtimes resolve the tenant
// from the agent id in the URL path, so that id must be authenticated by a
// client certificate rather than trusted on sight.
func TestAgentMTLSDefaultsToRequired(t *testing.T) {
	// Load() hard-fails without this; unrelated to what is under test.
	t.Setenv("ENCRYPTION_MASTER_KEY", "test-master-key")

	restore, had := os.LookupEnv("AGENT_MTLS_REQUIRED")
	if err := os.Unsetenv("AGENT_MTLS_REQUIRED"); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("AGENT_MTLS_REQUIRED", restore)
		}
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.AgentMTLSRequired {
		t.Fatal("AgentMTLSRequired = false with AGENT_MTLS_REQUIRED unset; " +
			"the default must fail closed")
	}
}

// TestAgentMTLSOptOutIsExplicit verifies the deliberate opt-out still works.
func TestAgentMTLSOptOutIsExplicit(t *testing.T) {
	t.Setenv("ENCRYPTION_MASTER_KEY", "test-master-key")
	t.Setenv("AGENT_MTLS_REQUIRED", "false")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AgentMTLSRequired {
		t.Fatal("AgentMTLSRequired = true despite AGENT_MTLS_REQUIRED=false")
	}
}
