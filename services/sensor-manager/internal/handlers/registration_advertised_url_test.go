package handlers

import "testing"

// The registration response advertises the mTLS passthrough URL only
// when fail-closed sensor mTLS is enforced AND the chart provided the URL —
// otherwise sensors must keep the URL they registered against.

func TestAdvertisedControlPlaneURLReturnsURLWhenMTLSRequired(t *testing.T) {
	t.Setenv("AGENT_MTLS_REQUIRED", "true")
	t.Setenv("AGENT_MTLS_ADVERTISED_URL", "https://sensors.example.com:8444")

	if got := advertisedControlPlaneURL(); got != "https://sensors.example.com:8444" {
		t.Fatalf("advertisedControlPlaneURL() = %q, want the advertised URL", got)
	}
}

func TestAdvertisedControlPlaneURLEmptyWhenMTLSNotRequired(t *testing.T) {
	t.Setenv("AGENT_MTLS_REQUIRED", "false")
	t.Setenv("AGENT_MTLS_ADVERTISED_URL", "https://sensors.example.com:8444")

	if got := advertisedControlPlaneURL(); got != "" {
		t.Fatalf("advertisedControlPlaneURL() = %q, want empty when mTLS is off", got)
	}
}

func TestAdvertisedControlPlaneURLEmptyWhenURLUnset(t *testing.T) {
	t.Setenv("AGENT_MTLS_REQUIRED", "true")
	t.Setenv("AGENT_MTLS_ADVERTISED_URL", "")

	if got := advertisedControlPlaneURL(); got != "" {
		t.Fatalf("advertisedControlPlaneURL() = %q, want empty when no URL configured", got)
	}
}
