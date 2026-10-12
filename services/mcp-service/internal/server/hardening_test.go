package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/mcp-service/internal/platform"
	"github.com/vistasecurity/vistaplatform/mcp-service/internal/tools"
)

func garbage(n int) string {
	return "qvpat_" + strings.Repeat(string(rune('d'+n%20)), 20) + strings.Repeat("q", 20+n)
}

// Two requests carrying the same garbage token cost ONE auth-service call: the
// rejection is cached, and the repeat is refused locally.
func TestRejectedTokenIsNegativelyCached(t *testing.T) {
	f := newFixture(t)
	bad := garbage(1)
	for i := 0; i < 2; i++ {
		if status, _ := f.rpc(t, bad, "initialize", initParams()); status != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i, status)
		}
	}
	if got := f.exchanges.Load(); got != 1 {
		t.Fatalf("auth-service exchange calls = %d, want 1 (second rejection must be local)", got)
	}
	// And only the decision auth-service actually took is audited.
	n := 0
	for _, e := range f.audit.all() {
		if e.EventType == "mcp.auth.token_rejected" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("token_rejected audit rows = %d, want 1", n)
	}
}

// Distinct garbage tokens from one address are bounded by the per-address
// limiter: the rest get 429 and never reach auth-service or the audit sink.
func TestGarbageTokenFloodIsRateLimited(t *testing.T) {
	f := newFixtureWith(t, fixtureOpts{exchange: platform.Options{AuthAttemptsPerMinute: 10}})
	limited := 0
	for i := 0; i < 40; i++ {
		status, _ := f.rpc(t, garbage(i), "initialize", initParams())
		switch status {
		case http.StatusTooManyRequests:
			limited++
		case http.StatusUnauthorized:
		default:
			t.Fatalf("unexpected status %d", status)
		}
	}
	if limited == 0 {
		t.Fatal("no request was rate limited")
	}
	if got := f.exchanges.Load(); got > 12 {
		t.Fatalf("auth-service saw %d exchanges for 40 distinct garbage tokens; the limiter should cap it near the burst (10)", got)
	}
	if got := len(f.audit.all()); got > 12 {
		t.Fatalf("%d audit rows written for the flood; rate-limited attempts must not be recorded", got)
	}
}

// A flood with NO bearer is limited too: its refusal writes an audit row.
func TestMissingBearerFloodIsRateLimited(t *testing.T) {
	f := newFixtureWith(t, fixtureOpts{exchange: platform.Options{AuthAttemptsPerMinute: 10}})
	limited := 0
	for i := 0; i < 40; i++ {
		if status, _ := f.rpc(t, "", "initialize", initParams()); status == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("anonymous requests were never rate limited")
	}
	if got := len(f.audit.all()); got > 12 {
		t.Fatalf("%d audit rows for 40 anonymous requests", got)
	}
}

func recordedMissingIP(t *testing.T, f *fixture) string {
	t.Helper()
	e := f.audit.only(t, "mcp.auth.token_missing")
	if e.IPAddress == nil {
		t.Fatal("audit row has no ip")
	}
	return *e.IPAddress
}

func missingBearerWithXFF(t *testing.T, f *fixture, xff string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, f.ts.URL+MCPPath, strings.NewReader(`{}`))
	req.Header.Set("X-Forwarded-For", xff)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
}

// No trusted proxies configured: a client-written X-Forwarded-For is ignored
// and the audit row carries the TCP peer.
func TestSpoofedForwardedForIsIgnoredByDefault(t *testing.T) {
	f := newFixture(t)
	missingBearerWithXFF(t, f, "203.0.113.77")
	if got := recordedMissingIP(t, f); got != "127.0.0.1" {
		t.Fatalf("audit ip = %q, want the TCP peer 127.0.0.1 (a forged header was believed)", got)
	}
}

// With the proxy trusted, the right-most untrusted hop wins — not the
// left-most, which the client wrote.
func TestTrustedProxyYieldsRightmostUntrustedHop(t *testing.T) {
	f := newFixtureWith(t, fixtureOpts{routerOpts: []RouterOption{WithTrustedProxies([]string{"127.0.0.0/8"})}})
	missingBearerWithXFF(t, f, "203.0.113.77, 198.51.100.4")
	if got := recordedMissingIP(t, f); got != "198.51.100.4" {
		t.Fatalf("audit ip = %q, want 198.51.100.4 (right-most untrusted hop)", got)
	}
}

func TestBadTrustedProxyEntryFailsRouterConstruction(t *testing.T) {
	if _, err := NewRouter(http.NotFoundHandler(), testDiscovery, WithTrustedProxies([]string{"not-a-cidr"})); err == nil {
		t.Fatal("an unparsable TRUSTED_PROXY_CIDRS entry must not silently fall back to trusting everyone")
	}
}

func metadataStatus(t *testing.T, d Discovery, host string) (int, string) {
	t.Helper()
	router, err := NewRouter(NewHandler(NewMCPServer(nil), nil, nil, d), d)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, ProtectedResourceMetadataRoot, nil)
	req.Host = host
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// Production without a configured public origin refuses to invent one from the
// Host header (cache poisoning), and says how to fix it.
func TestMetadataRefusedInProductionWithoutBaseURL(t *testing.T) {
	code, body := metadataStatus(t, Discovery{Production: true}, "evil.test")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", code)
	}
	if strings.Contains(body, "evil.test") || !strings.Contains(body, "OAUTH_CALLBACK_BASE_URL") {
		t.Fatalf("body = %s", body)
	}
	// The 401 challenge must not point at a request-chosen host either.
	req := httptest.NewRequest(http.MethodPost, MCPPath, nil)
	req.Host = "evil.test"
	rec := httptest.NewRecorder()
	NewHandler(NewMCPServer(nil), nil, nil, Discovery{Production: true}).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || strings.Contains(rec.Header().Get("WWW-Authenticate"), "evil.test") {
		t.Fatalf("challenge = %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}

func TestMetadataHostFallbackOnlyWhenAllowedOrDev(t *testing.T) {
	if code, _ := metadataStatus(t, Discovery{Production: true, AllowHostFallback: true}, "gw.example"); code != http.StatusOK {
		t.Fatalf("explicit MCP_ALLOW_HOST_FALLBACK: status = %d, want 200", code)
	}
	if code, _ := metadataStatus(t, Discovery{}, "localhost:8100"); code != http.StatusOK {
		t.Fatalf("development: status = %d, want 200", code)
	}
	if code, _ := metadataStatus(t, Discovery{Production: true, PublicBaseURL: "https://vista.example"}, "evil.test"); code != http.StatusOK {
		t.Fatalf("configured production: status = %d, want 200", code)
	}
}

// A failed audit write withholds the read.
func TestAuditFailureFailsToolReadsClosed(t *testing.T) {
	f := newFixture(t)
	f.audit.failTools.Store(true)
	result := callTool(t, f, f.validPAT, "vistaplatform_get_risk_summary", map[string]any{})
	if result["isError"] != true {
		t.Fatalf("read was served although its audit record failed: %v", result)
	}
	text := toolText(t, result)
	if !strings.Contains(text, "audit unavailable") || strings.Contains(text, "total_assets") {
		t.Fatalf("text = %s", text)
	}
}

func TestAuditFailOpenKnobServesTheRead(t *testing.T) {
	f := newFixtureWith(t, fixtureOpts{deps: func(d *tools.Deps) { d.AuditFailOpen = true }})
	f.audit.failTools.Store(true)
	result := callTool(t, f, f.validPAT, "vistaplatform_get_risk_summary", map[string]any{})
	if result["isError"] == true || !strings.Contains(toolText(t, result), "total_assets") {
		t.Fatalf("fail-open read not served: %v", result)
	}
}

// Results are labelled as untrusted tenant content, and capped.
func TestToolResultIsLabelledAndCapped(t *testing.T) {
	const capBytes = 64 << 10
	f := newFixtureWith(t, fixtureOpts{hugeInventory: true, deps: func(d *tools.Deps) { d.MaxResultBytes = capBytes }})
	result := callTool(t, f, f.validPAT, "vistaplatform_get_risk_summary", map[string]any{})
	if result["isError"] == true {
		t.Fatalf("errored: %v", result)
	}
	text := toolText(t, result)
	if len(text) > capBytes {
		t.Fatalf("result is %d bytes, cap %d", len(text), capBytes)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("truncated result is not valid JSON: %v", err)
	}
	if got["truncated"] != true {
		t.Errorf("truncated flag missing: keys %v", keys(got))
	}
	if got["data_origin"] != tools.DataOrigin {
		t.Errorf("data_origin = %v", got["data_origin"])
	}
	if _, stale := got["next_cursor"]; stale {
		t.Error("next_cursor survived truncation; it would skip the omitted rows")
	}
	if got["total"] != float64(4000) {
		t.Errorf("total no longer describes the whole match: %v", got["total"])
	}
}

func TestSmallResultCarriesOriginLabelButNoTruncatedFlag(t *testing.T) {
	f := newFixture(t)
	result := callTool(t, f, f.validPAT, "vistaplatform_get_risk_summary", map[string]any{})
	var got map[string]any
	_ = json.Unmarshal([]byte(toolText(t, result)), &got)
	if got["data_origin"] != tools.DataOrigin || got["truncated"] != nil || got["total_assets"] != float64(12) {
		t.Fatalf("got %v", got)
	}
}

func keys(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
