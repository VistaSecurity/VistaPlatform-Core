package api

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
)

// getBaseURL pins to the explicit callback config when set, and only falls back
// to CORSOrigins[0] otherwise.
//
// Split out of the former sso_redirect_test.go by the open-core carve: the
// redirect-URI allow-list moved to ee/sso with SSOCallback, but getBaseURL is
// Core (invitation links use it) so its test stays here.
func TestGetBaseURL_prefersExplicitPin(t *testing.T) {
	pinned := &config.Config{
		OAuthCallbackBaseURL: "https://sso.example.com/",
		CORSOrigins:          []string{"https://other.example.com"},
	}
	if got := getBaseURL(pinned); got != "https://sso.example.com" {
		t.Fatalf("with pin: got %q, want https://sso.example.com (trailing slash trimmed)", got)
	}

	fallback := &config.Config{CORSOrigins: []string{"https://first.example.com"}}
	if got := getBaseURL(fallback); got != "https://first.example.com" {
		t.Fatalf("fallback: got %q, want CORSOrigins[0]", got)
	}
}
