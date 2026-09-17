package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// testPublicBaseURL stands in for OAUTH_CALLBACK_BASE_URL. It carries a
// trailing slash on purpose: the chart's value is built by string
// concatenation and an operator override may well end in one, and a doubled
// slash in a resource identifier makes it a different resource.
const testPublicBaseURL = "https://vista.test/"

var testDiscovery = Discovery{PublicBaseURL: testPublicBaseURL}

// resourceMetadataParam extracts the RFC 9728 resource_metadata parameter from
// a WWW-Authenticate challenge. It deliberately accepts an EMPTY value so the
// tests below can assert on emptiness rather than silently reporting "absent"
// for the exact bug being guarded against.
var resourceMetadataRe = regexp.MustCompile(`resource_metadata="([^"]*)"`)

func resourceMetadataParam(t *testing.T, header string) string {
	t.Helper()
	if !strings.HasPrefix(header, "Bearer") {
		t.Fatalf("WWW-Authenticate is not a Bearer challenge: %q", header)
	}
	m := resourceMetadataRe.FindStringSubmatch(header)
	if m == nil {
		t.Fatalf("WWW-Authenticate carries no resource_metadata parameter at all: %q", header)
	}
	return m[1]
}

// challenge drives the REAL router (not the helper in isolation) and returns
// the WWW-Authenticate header from an unauthenticated MCP call. Going through
// the router is the point: a challenge that is correct in `unauthorized` but
// never reaches the wire is the failure mode this package has form for.
func challenge(t *testing.T, disc Discovery, mutate func(*http.Request)) string {
	t.Helper()
	router := NewRouter(NewHandler(NewMCPServer(nil), nil, nil, disc), disc)
	req := httptest.NewRequest(http.MethodPost, MCPPath, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	req.Header.Set("Content-Type", "application/json")
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for an unauthenticated MCP call, got %d", rec.Code)
	}
	return rec.Header().Get("WWW-Authenticate")
}

// TestChallengeCarriesAResolvableResourceMetadataURL is the guard for the
// shipped defect: `WWW-Authenticate: Bearer resource_metadata=""`.
//
// An empty parameter is syntactically a valid challenge, so nothing downstream
// errors — the client simply has no metadata URL to follow and abandons OAuth
// discovery. Asserting only "the header is present" would have passed against
// the broken build; this asserts the VALUE is an absolute URL pointing at the
// path this service actually serves.
//
// Mutation: restore `resource_metadata=""` in unauthorized() — this fails.
func TestChallengeCarriesAResolvableResourceMetadataURL(t *testing.T) {
	got := resourceMetadataParam(t, challenge(t, testDiscovery, nil))

	if strings.TrimSpace(got) == "" {
		t.Fatal("resource_metadata is empty — an MCP client has no way to discover the authorization server")
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("resource_metadata %q does not parse as a URL: %v", got, err)
	}
	if !u.IsAbs() || u.Host == "" {
		t.Fatalf("resource_metadata %q must be an absolute URL; a client resolves it directly", got)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		t.Fatalf("resource_metadata %q has scheme %q, want http(s)", got, u.Scheme)
	}
	if want := "https://vista.test" + ProtectedResourceMetadataPath; got != want {
		t.Fatalf("resource_metadata = %q, want %q", got, want)
	}

	// The pointer must resolve on this service, not merely look well-formed.
	if u.Path != ProtectedResourceMetadataPath {
		t.Fatalf("resource_metadata path %q is not the path this service serves (%q)", u.Path, ProtectedResourceMetadataPath)
	}
	doc := fetchMetadata(t, u.Path)
	if doc.Resource == "" {
		t.Fatal("following resource_metadata produced a document with no `resource`")
	}
}

// TestResourceMetadataIsNeverEmptyWhenUnconfigured pins the fallback. An
// install that sets neither OAUTH_CALLBACK_BASE_URL nor WEB_UI_BASE_URL must
// still advertise a URL — reverting to a blank parameter there would
// reintroduce the same silent failure through the back door.
func TestResourceMetadataIsNeverEmptyWhenUnconfigured(t *testing.T) {
	got := resourceMetadataParam(t, challenge(t, Discovery{}, func(r *http.Request) {
		r.Host = "vista.example"
		// Traefik terminates TLS; without serviceMtls the hop to this pod is
		// plain HTTP, so only this header distinguishes an https deployment.
		r.Header.Set("X-Forwarded-Proto", "https")
	}))
	if want := "https://vista.example" + ProtectedResourceMetadataPath; got != want {
		t.Fatalf("unconfigured fallback resource_metadata = %q, want %q", got, want)
	}
}

// TestConfiguredOriginBeatsTheHostHeader: a configured origin must not be
// overridable by a forged Host header, or a client could be pointed at an
// attacker-chosen authorization server.
func TestConfiguredOriginBeatsTheHostHeader(t *testing.T) {
	got := resourceMetadataParam(t, challenge(t, testDiscovery, func(r *http.Request) {
		r.Host = "attacker.example"
		r.Header.Set("X-Forwarded-Proto", "http")
	}))
	if strings.Contains(got, "attacker.example") {
		t.Fatalf("resource_metadata %q followed the Host header over the configured origin", got)
	}
}

// TestChallengeParameterCannotBeForged: the metadata URL is interpolated into
// a quoted auth-param, so a configured value carrying a quote must be rejected
// rather than allowed to close the string and inject another parameter.
func TestChallengeParameterCannotBeForged(t *testing.T) {
	disc := Discovery{PublicBaseURL: `https://evil.test/", error="none`}
	header := challenge(t, disc, func(r *http.Request) { r.Host = "vista.example" })
	if strings.Count(header, `"`) != 2 {
		t.Fatalf("challenge %q contains extra quoting — a malformed configured origin escaped the auth-param", header)
	}
	if got := resourceMetadataParam(t, header); strings.TrimSpace(got) == "" {
		t.Fatal("rejecting a malformed configured origin must fall back to the request origin, not to an empty parameter")
	}
}

// fetchMetadata GETs a well-known path through the real router and asserts the
// response is JSON — not the web-UI SPA's index.html.
//
// Asserting on status alone would be worthless here. The bug this guards was
// precisely a 200: the front-end catch-all swallowed
// /.well-known/oauth-protected-resource and served index.html with HTTP 200 and
// Content-Type: text/html. So the assertions are on content-type and body
// shape, and the HTML sniff below is explicit.
func fetchMetadata(t *testing.T, path string) ProtectedResourceMetadata {
	t.Helper()
	router := NewRouter(NewHandler(NewMCPServer(nil), nil, nil, testDiscovery), testDiscovery)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d, want 200", path, rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if mt := strings.TrimSpace(strings.Split(ct, ";")[0]); mt != "application/json" {
		t.Fatalf("GET %s: Content-Type %q, want application/json — an HTML body here is the SPA catch-all answering, "+
			"which is a 200 that tells a client nothing", path, ct)
	}
	body, _ := io.ReadAll(rec.Body)
	if head := strings.ToLower(strings.TrimSpace(string(body))); strings.HasPrefix(head, "<!doctype") || strings.HasPrefix(head, "<html") {
		t.Fatalf("GET %s returned an HTML document, not RFC 9728 metadata: %.120s", path, body)
	}

	var doc ProtectedResourceMetadata
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("GET %s: body is not valid JSON (%v): %.200s", path, err, body)
	}
	return doc
}

// TestProtectedResourceMetadataDocument checks the document a client actually
// consumes, on BOTH well-known paths: the RFC 9728 §3.1 path-suffixed URI and
// the bare root some clients probe first.
//
// Mutation: make ServeProtectedResourceMetadata write
// `w.Header().Set("Content-Type", "text/html")` and an index.html body — this
// fails on content-type and on the HTML sniff.
func TestProtectedResourceMetadataDocument(t *testing.T) {
	for _, path := range []string{ProtectedResourceMetadataPath, ProtectedResourceMetadataRoot} {
		t.Run(path, func(t *testing.T) {
			doc := fetchMetadata(t, path)

			if want := "https://vista.test" + MCPPath; doc.Resource != want {
				t.Errorf("resource = %q, want %q (the MCP endpoint is the protected resource)", doc.Resource, want)
			}
			if len(doc.AuthorizationServers) == 0 {
				t.Fatal("authorization_servers is empty — the document names no authorization server, " +
					"which is the whole reason a client fetches it")
			}
			// auth-service publishes the bare public origin as its RFC 8414
			// `issuer` (oauth.getIssuer), and a client compares the two; a
			// path here would make them disagree and fail the flow.
			if got := doc.AuthorizationServers[0]; got != "https://vista.test" {
				t.Errorf("authorization_servers[0] = %q, want the bare issuer origin %q", got, "https://vista.test")
			}
			if len(doc.BearerMethodsSupported) != 1 || doc.BearerMethodsSupported[0] != "header" {
				t.Errorf("bearer_methods_supported = %v, want [header]", doc.BearerMethodsSupported)
			}
		})
	}
}

// TestWellKnownPathMatchesTheResourceIdentifier pins the RFC 9728 §3.1
// construction: the well-known segment is inserted between the host and the
// resource identifier's path. Deriving it by hand elsewhere is how these two
// drift apart.
func TestWellKnownPathMatchesTheResourceIdentifier(t *testing.T) {
	if want := ProtectedResourceMetadataRoot + MCPPath; ProtectedResourceMetadataPath != want {
		t.Fatalf("ProtectedResourceMetadataPath = %q, want %q", ProtectedResourceMetadataPath, want)
	}
	doc := fetchMetadata(t, ProtectedResourceMetadataPath)
	u, err := url.Parse(doc.Resource)
	if err != nil {
		t.Fatalf("resource %q does not parse: %v", doc.Resource, err)
	}
	if got := ProtectedResourceMetadataRoot + u.Path; got != ProtectedResourceMetadataPath {
		t.Fatalf("the served path %q is not the RFC 9728 well-known URI for resource %q (that would be %q)",
			ProtectedResourceMetadataPath, doc.Resource, got)
	}
}

// TestMetadataEndpointsNeedNoCredential: a client reads these before it has
// one. Gating them behind the bearer check would deadlock discovery.
func TestMetadataEndpointsNeedNoCredential(t *testing.T) {
	for _, path := range []string{ProtectedResourceMetadataPath, ProtectedResourceMetadataRoot} {
		router := NewRouter(NewHandler(NewMCPServer(nil), nil, nil, testDiscovery), testDiscovery)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code == http.StatusUnauthorized {
			t.Errorf("GET %s requires a credential; discovery cannot then bootstrap", path)
		}
	}
}
