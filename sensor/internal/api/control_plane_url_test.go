package api

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
)

func TestApplyAdvertisedControlPlaneURL(t *testing.T) {
	cases := []struct {
		name       string
		advertised string
		wantSwitch bool
		wantURL    string
	}{
		{"empty is the non-mTLS no-op", "", false, "https://edge.example.com"},
		{"same URL is a no-op", "https://edge.example.com", false, "https://edge.example.com"},
		{"valid https switches", "https://sensors.example.com:8444", true, "https://sensors.example.com:8444"},
		{"trailing slash is trimmed", "https://sensors.example.com:8444/", true, "https://sensors.example.com:8444"},
		{"plain http is rejected", "http://sensors.example.com:8444", false, "https://edge.example.com"},
		{"garbage is rejected", "not a url", false, "https://edge.example.com"},
		{"scheme-only is rejected", "https://", false, "https://edge.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{ControlPlaneURL: "https://edge.example.com"}
			if got := applyAdvertisedControlPlaneURL(cfg, tc.advertised); got != tc.wantSwitch {
				t.Fatalf("applyAdvertisedControlPlaneURL(%q) = %v, want %v", tc.advertised, got, tc.wantSwitch)
			}
			if cfg.ControlPlaneURL != tc.wantURL {
				t.Fatalf("ControlPlaneURL = %q, want %q", cfg.ControlPlaneURL, tc.wantURL)
			}
		})
	}
}

// The OutboundClient captures ControlPlaneURL at construction, BEFORE
// registration may switch it to the advertised mTLS passthrough endpoint.
// ActivateMTLS must re-sync the base URL or the first post-registration
// session keeps calling the edge host, where the client cert is terminated
// away and fail-closed sensor mTLS 401s every call.
func TestActivateMTLS_ResyncsBaseURLFromConfig(t *testing.T) {
	cfg := &config.Config{ControlPlaneURL: "https://edge.example.com"}
	c := NewOutboundClient(cfg)
	if c.baseURL != "https://edge.example.com" {
		t.Fatalf("precondition: baseURL = %q", c.baseURL)
	}

	// Registration switches the shared config to the passthrough endpoint.
	if !applyAdvertisedControlPlaneURL(cfg, "https://sensors.example.com:8444") {
		t.Fatal("expected the advertised URL to be applied")
	}

	c.ActivateMTLS()
	if c.baseURL != "https://sensors.example.com:8444" {
		t.Fatalf("baseURL after ActivateMTLS = %q, want the advertised mTLS endpoint", c.baseURL)
	}
}
