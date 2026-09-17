package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// ProtectedResourceMetadataRoot is the RFC 9728 well-known URI for a resource
// identifier with no path component.
//
// Both this and the path-suffixed form below are served. RFC 9728 §3.1 defines
// only the path-suffixed URI for a resource whose identifier has a path — but
// MCP clients in the wild probe the bare root as well (and some probe it
// first), so answering only the spec-exact form leaves those clients falling
// through to whatever else owns `/`. On this platform that is the web-UI
// catch-all, which returns the SPA's index.html with HTTP 200: a client
// following the discovery chain gets HTML where it expects JSON, and a 200
// that proves nothing. See the route guard in
// scripts/test-chart-oauth-protected-resource-route.mjs.
const ProtectedResourceMetadataRoot = "/.well-known/oauth-protected-resource"

// ProtectedResourceMetadataPath is the RFC 9728 §3.1 well-known URI for THIS
// resource. The well-known segment is inserted between the host and the
// resource identifier's path, so the MCP endpoint at
// https://<host>/api/v1/mcp-service/mcp publishes its metadata at
// https://<host>/.well-known/oauth-protected-resource/api/v1/mcp-service/mcp.
const ProtectedResourceMetadataPath = ProtectedResourceMetadataRoot + MCPPath

// ProtectedResourceMetadata is the RFC 9728 protected-resource metadata
// document. It is the one thing that lets an MCP client discover WHICH
// authorization server guards this endpoint; without it a client has nowhere
// to look, and there is no way for a user to hand-configure the authorization
// server in Claude.ai or ChatGPT.
type ProtectedResourceMetadata struct {
	// Resource is the resource identifier — the MCP endpoint itself.
	Resource string `json:"resource"`
	// AuthorizationServers holds issuer identifiers, each of which a client
	// resolves to metadata via /.well-known/oauth-authorization-server. This
	// platform runs exactly one: auth-service, at the public origin.
	AuthorizationServers []string `json:"authorization_servers"`
	// BearerMethodsSupported: the Authorization header only. Query-parameter
	// and form-body bearer tokens are not accepted (and should not be — they
	// leak into access logs).
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceName           string   `json:"resource_name,omitempty"`
}

// Discovery carries the public identity this service advertises to OAuth
// clients. It is the single source for both the `resource_metadata` pointer in
// the 401 challenge and the document that pointer resolves to, so the two
// cannot drift apart.
type Discovery struct {
	// PublicBaseURL is the operator-configured external origin
	// (OAUTH_CALLBACK_BASE_URL, falling back to WEB_UI_BASE_URL — both come
	// from the chart's shared app ConfigMap). Empty means "derive it from the
	// request", which keeps the chain working on an install that has neither
	// set rather than emitting a blank URL.
	PublicBaseURL string
}

// baseURL resolves the external origin for this request.
//
// The configured value wins. When it is absent or unusable the origin is
// derived from the request rather than left blank: an empty discovery URL is
// indistinguishable from a working one to a client — it simply gives up — and
// that silent nothing is exactly the failure this file exists to remove.
func (d Discovery) baseURL(r *http.Request) string {
	if b := normalizeOrigin(d.PublicBaseURL); b != "" {
		return b
	}
	return requestOrigin(r)
}

// ResourceMetadataURL is the absolute URL the 401 challenge points at.
func (d Discovery) ResourceMetadataURL(r *http.Request) string {
	return d.baseURL(r) + ProtectedResourceMetadataPath
}

// Metadata builds the document served at both well-known paths.
func (d Discovery) Metadata(r *http.Request) ProtectedResourceMetadata {
	base := d.baseURL(r)
	return ProtectedResourceMetadata{
		Resource: base + MCPPath,
		// The issuer auth-service publishes in its RFC 8414 metadata is the
		// bare public origin (see oauth.getIssuer), so this must be the bare
		// origin too — a client compares the two.
		AuthorizationServers:   []string{base},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "Vista Platform MCP server",
	}
}

// ServeProtectedResourceMetadata answers the RFC 9728 well-known endpoints.
func (d Discovery) ServeProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	body, err := json.Marshal(d.Metadata(r))
	if err != nil {
		http.Error(w, `{"error":"failed to render resource metadata"}`, http.StatusInternalServerError)
		return
	}
	// Unauthenticated by design: a client has to read this BEFORE it can
	// obtain a credential. It contains only public routing facts.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// normalizeOrigin reduces a configured base URL to a bare scheme://host[:port]
// origin, or "" if it is not usable as one. Rejecting rather than patching up
// a malformed value is deliberate: the result is interpolated into a quoted
// WWW-Authenticate parameter, and a value carrying a quote or backslash could
// forge an additional auth parameter.
func normalizeOrigin(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	origin := u.Scheme + "://" + u.Host
	if strings.ContainsAny(origin, "\"\\ ") {
		return ""
	}
	return origin
}

// requestOrigin derives the external origin from the inbound request. The
// scheme comes from X-Forwarded-Proto because the edge terminates TLS: without
// serviceMtls the hop from Traefik to this pod is plain HTTP, so r.TLS alone
// would advertise http:// for an https:// deployment.
func requestOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if fwd := firstListValue(r.Header.Get("X-Forwarded-Proto")); fwd == "http" || fwd == "https" {
		scheme = fwd
	}
	host := r.Host
	if host == "" {
		// Nothing left to derive from. Still not empty — a syntactically valid
		// URL that fails loudly at fetch time beats a blank parameter a client
		// silently ignores.
		host = "localhost"
	}
	if origin := normalizeOrigin(scheme + "://" + host); origin != "" {
		return origin
	}
	return scheme + "://localhost"
}

// firstListValue returns the first entry of a comma-separated header value.
func firstListValue(v string) string {
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	return strings.ToLower(strings.TrimSpace(v))
}
