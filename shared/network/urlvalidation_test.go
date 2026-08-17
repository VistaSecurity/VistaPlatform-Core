package network

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateWebhookURLRejectsPolicyFailuresPermanently(t *testing.T) {
	cases := []struct {
		name    string
		rawURL  string
		wantMsg string
	}{
		{"unsupported scheme", "ftp://example.com/hook", "unsupported URL scheme"},
		{"missing host", "https:///hook", "URL must contain a hostname"},
		{"blocked hostname case insensitive", "https://LOCALHOST/hook", "not allowed"},
		{"docker host alias", "http://host.docker.internal/hook", "not allowed"},
		{"kubernetes service", "https://kubernetes.default.svc/hook", "not allowed"},
		{"loopback IPv4 literal", "http://127.0.0.1:8080/hook", "private/internal IP address"},
		{"private IPv4 literal", "https://10.1.2.3/hook", "private/internal IP address"},
		{"link local metadata literal", "http://169.254.169.254/latest/meta-data", "private/internal IP address"},
		{"loopback IPv6 literal", "http://[::1]:8080/hook", "private/internal IP address"},
		{"unique local IPv6 literal", "https://[fc00::1]/hook", "private/internal IP address"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateWebhookURL(tc.rawURL)
			if err == nil {
				t.Fatalf("ValidateWebhookURL(%q) = nil, want policy rejection", tc.rawURL)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("ValidateWebhookURL(%q) = %v, want message containing %q", tc.rawURL, err, tc.wantMsg)
			}
			if errors.Is(err, ErrUnresolvableHost) {
				t.Fatalf("ValidateWebhookURL(%q) wrapped ErrUnresolvableHost for a permanent policy rejection: %v", tc.rawURL, err)
			}
		})
	}
}

func TestValidateWebhookURLUnresolvableHostIsTyped(t *testing.T) {
	err := ValidateWebhookURL("https://webhook-target.invalid/path")
	if err == nil {
		t.Fatal("ValidateWebhookURL(.invalid host) = nil, want resolution failure")
	}
	if !errors.Is(err, ErrUnresolvableHost) {
		t.Fatalf("ValidateWebhookURL(.invalid host) = %v, want ErrUnresolvableHost", err)
	}
}

func TestValidateWebhookURLAllowsPublicIPLiteral(t *testing.T) {
	cases := []string{
		"http://8.8.8.8:443/hook",
		"https://[2001:4860:4860::8888]/hook",
	}
	for _, rawURL := range cases {
		t.Run(rawURL, func(t *testing.T) {
			if err := ValidateWebhookURL(rawURL); err != nil {
				t.Fatalf("ValidateWebhookURL(%q) = %v, want nil", rawURL, err)
			}
		})
	}
}
