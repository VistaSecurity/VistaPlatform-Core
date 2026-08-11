package config

import (
	"os"
	"testing"
)

func TestPeerURL(t *testing.T) {
	if got := PeerURL("auth-service", true); got != "https://auth-service:8443" {
		t.Errorf("mTLS on: got %q", got)
	}
	if got := PeerURL("auth-service", false); got != "http://auth-service:8080" {
		t.Errorf("mTLS off: got %q", got)
	}
}

func TestPeerServiceURL_EnvOverrideWins(t *testing.T) {
	t.Setenv("INVENTORY_SERVICE_URL", "http://custom-host:9999")
	if got := PeerServiceURL("INVENTORY_SERVICE_URL", "inventory-service", true); got != "http://custom-host:9999" {
		t.Errorf("explicit env should win: got %q", got)
	}
}

func TestPeerServiceURLAuto_DerivesFromUseMTLS(t *testing.T) {
	os.Unsetenv("CBOM_SERVICE_URL")
	t.Setenv("USE_MTLS", "true")
	if got := PeerServiceURLAuto("CBOM_SERVICE_URL", "cbom-service"); got != "https://cbom-service:8443" {
		t.Errorf("USE_MTLS=true: got %q", got)
	}
	t.Setenv("USE_MTLS", "false")
	if got := PeerServiceURLAuto("CBOM_SERVICE_URL", "cbom-service"); got != "http://cbom-service:8080" {
		t.Errorf("USE_MTLS=false: got %q", got)
	}
}
