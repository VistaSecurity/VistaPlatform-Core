package oauth

import (
	"net"
	"net/url"
	"strings"
)

// OAuthClient describes a registered public OAuth client (no client secret;
// PKCE is mandatory). All clients in knownClients are first-party AI
// assistants. Add entries here when a new MCP-capable client is verified —
// see the redirect-URI research on.
type OAuthClient struct {
	// Name is shown on the consent page.
	Name string
	// RedirectURIs is the exact allow-list (https only).
	RedirectURIs []string
	// RedirectURIPrefixes allows redirect URIs under an https URL prefix.
	// Each entry must end at a path-segment boundary (a trailing "/" is
	// implied). Matching is performed on the parsed URL, never the raw
	// string — see matchesRedirectPrefix for the exact rules. Use this only
	// for clients whose callback path embeds a per-connector identifier
	// (e.g. ChatGPT's /connector/oauth/{callback_id}).
	RedirectURIPrefixes []string
	// LoopbackOK additionally allows any loopback redirect per RFC 8252 §7.3:
	// http scheme with host "localhost", 127.0.0.1 (any IPv4 loopback), or
	// [::1], on any port. Used for CLI / desktop clients.
	LoopbackOK bool
}

// knownClients is the authoritative allow-list of OAuth clients accepted by
// the /oauth/authorize endpoint. All clients are public (no secret); PKCE is
// always required. Redirect URIs verified per the research.
var knownClients = map[string]OAuthClient{
	"claude-ai": {
		Name: "Claude.ai",
		// Verified against Anthropic's MCP connector docs.
		RedirectURIs: []string{"https://claude.ai/api/mcp/auth_callback"},
	},
	"claude-code": {
		Name: "Claude Code",
		// CLI / desktop — declares http://localhost/callback and may use any
		// loopback host/port per RFC 8252 §7.3.
		LoopbackOK: true,
	},
	"openai-chatgpt": {
		Name: "ChatGPT",
		// Legacy connector-platform callback (exact) plus the current
		// per-connector form https://chatgpt.com/connector/oauth/{callback_id},
		// where callback_id varies per connector.
		RedirectURIs:        []string{"https://chatgpt.com/connector_platform_oauth_redirect"},
		RedirectURIPrefixes: []string{"https://chatgpt.com/connector/oauth/"},
	},
	"google-gemini": {
		Name: "Gemini",
		// No redirect URIs yet: the Gemini consumer app's redirect URI
		// is unpublished — do not add a guess. Gemini CLI uses a loopback
		// redirect (localhost + random port), which would be LoopbackOK if we
		// register it as a distinct client. Gemini Enterprise's published URI
		// (https://vertexaisearch.cloud.google.com/oauth-redirect) requires a
		// client_secret (confidential client), which this public-client-only
		// server does not support.
		RedirectURIs: []string{},
	},
}

// LookupClient returns the OAuthClient for the given client_id, or false if
// the client_id is not in the allow-list.
func LookupClient(clientID string) (OAuthClient, bool) {
	c, ok := knownClients[clientID]
	return c, ok
}

// ValidateRedirectURI reports whether redirectURI is permitted for the client.
func (c OAuthClient) ValidateRedirectURI(redirectURI string) bool {
	if c.LoopbackOK && isLoopback(redirectURI) {
		return true
	}
	for _, allowed := range c.RedirectURIs {
		if redirectURI == allowed {
			return true
		}
	}
	for _, prefix := range c.RedirectURIPrefixes {
		if matchesRedirectPrefix(redirectURI, prefix) {
			return true
		}
	}
	return false
}

// isLoopback reports whether rawURI is a native-app loopback redirect per
// RFC 8252 §7.3: host "localhost", an IPv4 loopback address (127.0.0.0/8),
// or [::1], with any port. The http scheme is allowed for loopback redirects
// only; every other redirect URI must be https.
func isLoopback(rawURI string) bool {
	u, err := url.Parse(rawURI)
	if err != nil {
		return false
	}
	if !strings.EqualFold(u.Scheme, "http") {
		return false
	}
	host := u.Hostname() // strips port and IPv6 brackets
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// matchesRedirectPrefix reports whether rawURI falls under the allowed URL
// prefix. Comparison happens on parsed URLs, never raw strings, so a host
// like "chatgpt.com.evil.com" cannot pass a check against "chatgpt.com".
// Rules:
//   - scheme must be https and equal to the prefix's scheme
//   - host and port must match the prefix exactly; no userinfo
//   - the prefix ends at a path-segment boundary ("/" is appended if
//     missing) and the candidate must extend it by at least one non-empty
//     path segment, so ".../oauthevil" never matches ".../oauth"
//   - matching uses the escaped path, so percent-encoding can't forge a
//     segment boundary; "." / ".." segments and backslashes are rejected
//   - the candidate must carry no query string or fragment
func matchesRedirectPrefix(rawURI, prefix string) bool {
	p, err := url.Parse(prefix)
	if err != nil {
		return false
	}
	u, err := url.Parse(rawURI)
	if err != nil {
		return false
	}
	if !strings.EqualFold(u.Scheme, "https") || !strings.EqualFold(u.Scheme, p.Scheme) {
		return false
	}
	if u.User != nil || !strings.EqualFold(u.Hostname(), p.Hostname()) || u.Port() != p.Port() {
		return false
	}
	if u.RawQuery != "" || u.Fragment != "" || u.RawFragment != "" {
		return false
	}
	prefixPath := p.EscapedPath()
	if !strings.HasSuffix(prefixPath, "/") {
		prefixPath += "/"
	}
	candPath := u.EscapedPath()
	if !strings.HasPrefix(candPath, prefixPath) || len(candPath) == len(prefixPath) {
		return false
	}
	// Reject path traversal on the decoded path (catches %2e%2e too).
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." || strings.Contains(seg, `\`) {
			return false
		}
	}
	// The variable part must be non-empty segments only (no "//" tricks).
	for _, seg := range strings.Split(strings.TrimPrefix(candPath, prefixPath), "/") {
		if seg == "" {
			return false
		}
	}
	return true
}
