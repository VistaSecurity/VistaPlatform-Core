package oauth

import "testing"

func TestValidateRedirectURI_Loopback(t *testing.T) {
	client, ok := LookupClient("claude-code")
	if !ok {
		t.Fatal("claude-code client not registered")
	}

	cases := []struct {
		name string
		uri  string
		want bool
	}{
		// RFC 8252 §7.3 — localhost / loopback IPs, any port, http scheme.
		{name: "localhost no port", uri: "http://localhost/callback", want: true},
		{name: "localhost with port", uri: "http://localhost:8912/callback", want: true},
		{name: "localhost uppercase", uri: "http://LOCALHOST:8912/callback", want: true},
		{name: "127.0.0.1 with port", uri: "http://127.0.0.1:33418/callback", want: true},
		{name: "127.0.0.1 no port", uri: "http://127.0.0.1/callback", want: true},
		{name: "IPv4 loopback range", uri: "http://127.0.0.2:9000/cb", want: true},
		{name: "IPv6 loopback with port", uri: "http://[::1]:8080/callback", want: true},
		{name: "IPv6 loopback no port", uri: "http://[::1]/callback", want: true},
		// Rejections.
		{name: "non-loopback http", uri: "http://example.com/callback", want: false},
		{name: "private IP is not loopback", uri: "http://192.168.1.1:8080/callback", want: false},
		{name: "localhost subdomain trick", uri: "http://localhost.evil.com/callback", want: false},
		{name: "https loopback (RFC 8252 uses http)", uri: "https://localhost:8912/callback", want: false},
		{name: "custom scheme", uri: "myapp://localhost/callback", want: false},
		{name: "empty", uri: "", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := client.ValidateRedirectURI(tc.uri); got != tc.want {
				t.Errorf("ValidateRedirectURI(%q) = %v, want %v", tc.uri, got, tc.want)
			}
		})
	}
}

func TestValidateRedirectURI_ClaudeAI(t *testing.T) {
	client, ok := LookupClient("claude-ai")
	if !ok {
		t.Fatal("claude-ai client not registered")
	}

	cases := []struct {
		name string
		uri  string
		want bool
	}{
		{name: "verified exact URI", uri: "https://claude.ai/api/mcp/auth_callback", want: true},
		{name: "trailing slash differs", uri: "https://claude.ai/api/mcp/auth_callback/", want: false},
		{name: "http downgrade", uri: "http://claude.ai/api/mcp/auth_callback", want: false},
		{name: "lookalike host", uri: "https://claude.ai.evil.com/api/mcp/auth_callback", want: false},
		{name: "loopback not allowed", uri: "http://localhost:8080/callback", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := client.ValidateRedirectURI(tc.uri); got != tc.want {
				t.Errorf("ValidateRedirectURI(%q) = %v, want %v", tc.uri, got, tc.want)
			}
		})
	}
}

func TestValidateRedirectURI_ChatGPT(t *testing.T) {
	client, ok := LookupClient("openai-chatgpt")
	if !ok {
		t.Fatal("openai-chatgpt client not registered")
	}

	cases := []struct {
		name string
		uri  string
		want bool
	}{
		// Legacy exact URI.
		{name: "legacy connector-platform URI", uri: "https://chatgpt.com/connector_platform_oauth_redirect", want: true},
		// Current per-connector prefix form.
		{name: "per-connector callback id", uri: "https://chatgpt.com/connector/oauth/abc123", want: true},
		{name: "uuid-style callback id", uri: "https://chatgpt.com/connector/oauth/9f8e7d6c-1a2b-3c4d-5e6f-000000000000", want: true},
		// Host-confusion bypasses.
		{name: "suffix-host bypass", uri: "https://chatgpt.com.evil.com/connector/oauth/x", want: false},
		{name: "userinfo host trick", uri: "https://chatgpt.com@evil.com/connector/oauth/x", want: false},
		{name: "port mismatch", uri: "https://chatgpt.com:8443/connector/oauth/abc123", want: false},
		// Path-boundary bypasses.
		{name: "segment-boundary bypass", uri: "https://chatgpt.com/connector/oauthevil", want: false},
		{name: "prefix with empty remainder", uri: "https://chatgpt.com/connector/oauth/", want: false},
		{name: "empty segment in remainder", uri: "https://chatgpt.com/connector/oauth//x", want: false},
		{name: "dot-dot traversal", uri: "https://chatgpt.com/connector/oauth/../admin", want: false},
		{name: "encoded dot-dot traversal", uri: "https://chatgpt.com/connector/oauth/%2e%2e/admin", want: false},
		{name: "encoded slash cannot forge boundary", uri: "https://chatgpt.com/connector%2Foauth%2Fx", want: false},
		// Query / fragment tricks.
		{name: "query string rejected", uri: "https://chatgpt.com/connector/oauth/abc?next=https://evil.com", want: false},
		{name: "fragment rejected", uri: "https://chatgpt.com/connector/oauth/abc#frag", want: false},
		// Scheme rules.
		{name: "http rejected (non-loopback)", uri: "http://chatgpt.com/connector/oauth/abc123", want: false},
		{name: "loopback not allowed for chatgpt", uri: "http://localhost:8080/connector/oauth/abc123", want: false},
		// Unknown URIs.
		{name: "unrelated path", uri: "https://chatgpt.com/somewhere/else", want: false},
		{name: "empty", uri: "", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := client.ValidateRedirectURI(tc.uri); got != tc.want {
				t.Errorf("ValidateRedirectURI(%q) = %v, want %v", tc.uri, got, tc.want)
			}
		})
	}
}

func TestValidateRedirectURI_Gemini(t *testing.T) {
	client, ok := LookupClient("google-gemini")
	if !ok {
		t.Fatal("google-gemini client not registered")
	}
	// No verified redirect URIs yet — everything must be rejected,
	// including the confidential-client Gemini Enterprise URI.
	for _, uri := range []string{
		"https://gemini.google.com/oauth/callback",
		"https://vertexaisearch.cloud.google.com/oauth-redirect",
		"http://localhost:8080/callback",
	} {
		if client.ValidateRedirectURI(uri) {
			t.Errorf("ValidateRedirectURI(%q) = true, want false (no verified Gemini URIs)", uri)
		}
	}
}

func TestLookupClient_Unknown(t *testing.T) {
	if _, ok := LookupClient("nonsense-client"); ok {
		t.Fatal("unknown client_id must not resolve")
	}
}
