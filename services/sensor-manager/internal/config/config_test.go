package config

import (
	"os"
	"testing"
)

// TestAgentMTLSDefaultsToRequired pins the fail-closed default. An unconfigured
// deployment must authenticate sensors rather than trust a bare sensor UUID:
// the UUID in /sensors/:sensor_id/... is the only thing the tenant binding keys
// off, and UUIDs are not secrets — they appear in URLs, logs and API responses.
// If this ever flips back to false, every unconfigured deployment silently
// accepts discovery submissions from anyone who knows an id.
func TestAgentMTLSDefaultsToRequired(t *testing.T) {
	restore, had := os.LookupEnv("AGENT_MTLS_REQUIRED")
	if err := os.Unsetenv("AGENT_MTLS_REQUIRED"); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("AGENT_MTLS_REQUIRED", restore)
		}
	})

	if got := Load().SensorMTLSRequired; !got {
		t.Fatal("SensorMTLSRequired = false with AGENT_MTLS_REQUIRED unset; " +
			"the default must fail closed")
	}
}

// TestAgentMTLSOptOutIsExplicit verifies the escape hatch still works, so a
// dev/compose deployment can turn enforcement off deliberately and visibly.
func TestAgentMTLSOptOutIsExplicit(t *testing.T) {
	t.Setenv("AGENT_MTLS_REQUIRED", "false")

	if got := Load().SensorMTLSRequired; got {
		t.Fatal("SensorMTLSRequired = true despite AGENT_MTLS_REQUIRED=false")
	}
}
