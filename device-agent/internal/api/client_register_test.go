package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
)

func TestOutboundClient_Register_setsAgentIDOnConfig(t *testing.T) {
	agentID := uuid.New()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/device-interrogation-service/agents/register" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		// Omit client_cert so reconfigureTLS skips (test PEM would not match generated private key).
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"agent_id": agentID.String(),
		})
	}))
	defer srv.Close()

	cfg := &config.Config{
		PlatformURL:     srv.URL,
		RegistrationKey: "REG-0123456789abcdef0123456789abcdef",
	}
	c := NewOutboundClient(cfg)
	if err := c.Register("9.8.7"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if cfg.AgentID != agentID.String() {
		t.Fatalf("cfg.AgentID = %q, want %q", cfg.AgentID, agentID.String())
	}
	if cfg.Security.UseTLS {
		t.Fatal("expected UseTLS false when server omits client_cert in this test")
	}
}

// Under fail-closed agent mTLS the registration response advertises the
// passthrough URL; the agent must switch its base URL to it (and persist via
// the caller's saveConfigFile) or every post-registration call goes to the
// edge host, where the client cert is terminated away and enforcement 401s
//
func TestOutboundClient_Register_switchesToAdvertisedControlPlaneURL(t *testing.T) {
	agentID := uuid.New()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"agent_id":          agentID.String(),
			"control_plane_url": "https://agents.example.com:8444",
		})
	}))
	defer srv.Close()

	cfg := &config.Config{
		PlatformURL:     srv.URL,
		RegistrationKey: "REG-0123456789abcdef0123456789abcdef",
	}
	c := NewOutboundClient(cfg)
	if err := c.Register("9.8.7"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if cfg.PlatformURL != "https://agents.example.com:8444" {
		t.Fatalf("cfg.PlatformURL = %q, want the advertised mTLS endpoint", cfg.PlatformURL)
	}
	if c.baseURL != "https://agents.example.com:8444" {
		t.Fatalf("baseURL = %q, want the advertised mTLS endpoint", c.baseURL)
	}
}

func TestApplyAdvertisedPlatformURL(t *testing.T) {
	cases := []struct {
		name       string
		advertised string
		wantSwitch bool
		wantURL    string
	}{
		{"empty is the non-mTLS no-op", "", false, "https://edge.example.com"},
		{"same URL is a no-op", "https://edge.example.com", false, "https://edge.example.com"},
		{"valid https switches", "https://agents.example.com:8444", true, "https://agents.example.com:8444"},
		{"trailing slash is trimmed", "https://agents.example.com:8444/", true, "https://agents.example.com:8444"},
		{"plain http is rejected", "http://agents.example.com:8444", false, "https://edge.example.com"},
		{"garbage is rejected", "not a url", false, "https://edge.example.com"},
		{"scheme-only is rejected", "https://", false, "https://edge.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{PlatformURL: "https://edge.example.com"}
			if got := applyAdvertisedPlatformURL(cfg, tc.advertised); got != tc.wantSwitch {
				t.Fatalf("applyAdvertisedPlatformURL(%q) = %v, want %v", tc.advertised, got, tc.wantSwitch)
			}
			if cfg.PlatformURL != tc.wantURL {
				t.Fatalf("PlatformURL = %q, want %q", cfg.PlatformURL, tc.wantURL)
			}
		})
	}
}
