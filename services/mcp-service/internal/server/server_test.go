package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/mcp-service/internal/auditlog"
	"github.com/vistasecurity/vistaplatform/mcp-service/internal/platform"
	"github.com/vistasecurity/vistaplatform/mcp-service/internal/tools"
)

// fixture wires the real MCP handler to fake auth-service and platform
// backends, exercising the same path a real MCP client hits.
type fixture struct {
	ts           *httptest.Server
	validPAT     string
	limitedPAT   string // assets.read only
	backendAuthz []string
	audit        *auditSink
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		validPAT:   "qvpat_" + strings.Repeat("a", 43),
		limitedPAT: "qvpat_" + strings.Repeat("b", 43),
	}

	// Fake auth-service: exchange endpoint resolving the two test PATs.
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth-service/internal/api-tokens/exchange" {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		perms := []string{"assets.read", "compliance.read", "reports.read"}
		switch body.Token {
		case f.validPAT:
		case f.limitedPAT:
			perms = []string{"assets.read"}
		default:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"Invalid api token"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-jwt-for-" + body.Token[len(body.Token)-6:],
			"expires_at":   time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339),
			"tenant_id":    "11111111-1111-1111-1111-111111111111",
			"user_id":      "22222222-2222-2222-2222-222222222222",
			"email":        "user@example.com",
			"role":         "tenant_admin",
			"permissions":  perms,
		})
	}))
	t.Cleanup(authSrv.Close)

	// Fake platform backend: records the Authorization header and returns
	// recognizable payloads.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.backendAuthz = append(f.backendAuthz, r.Header.Get("Authorization"))
		switch {
		case strings.HasSuffix(r.URL.Path, "/infrastructure-assets"):
			_, _ = w.Write([]byte(`{"assets":[{"id":"a1","hostname":"web01","certificate_pem":"SECRETPEM","raw_data":{"x":1}}],"pagination":{"page":1,"total":1}}`))
		case strings.HasSuffix(r.URL.Path, "/risk/summary"):
			_, _ = w.Write([]byte(`{"total_assets":12,"high_risk":3}`))
		case strings.HasSuffix(r.URL.Path, "/compliance-engine/frameworks"):
			_, _ = w.Write([]byte(`{"frameworks":[{"id":"f1","name":"Best Practices"}]}`))
		case strings.HasSuffix(r.URL.Path, "/frameworks/status"):
			_, _ = w.Write([]byte(`{"frameworks":[{"framework_id":"f1","score":88}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"no such route in fake backend: ` + r.URL.Path + `"}`))
		}
	}))
	t.Cleanup(backend.Close)

	t.Setenv("INTERNAL_AUTH_SECRET", "test-secret")

	f.audit = &auditSink{}
	recorder := auditlog.NewRecorder(f.audit)

	exchanger := platform.NewExchanger(authSrv.URL, nil, recorder)
	client := platform.NewClient(nil, backend.URL, backend.URL, backend.URL)
	mcpServer := NewMCPServer(&tools.Deps{Client: client, Audit: recorder})
	handler := NewHandler(mcpServer, exchanger, recorder)

	router := NewRouter(handler)
	f.ts = httptest.NewServer(router)
	t.Cleanup(f.ts.Close)
	return f
}

// rpc posts a JSON-RPC message to the MCP endpoint.
func (f *fixture) rpc(t *testing.T, token, method string, params any) (int, map[string]any) {
	t.Helper()
	msg := map[string]any{"jsonrpc": "2.0", "id": 1, "method": method}
	if params != nil {
		msg["params"] = params
	}
	b, _ := json.Marshal(msg)
	req, _ := http.NewRequest(http.MethodPost, f.ts.URL+MCPPath, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("rpc %s: %v", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func initParams() map[string]any {
	return map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "test", "version": "0"},
	}
}

func TestRejectsMissingAndInvalidTokens(t *testing.T) {
	f := newFixture(t)

	status, _ := f.rpc(t, "", "initialize", initParams())
	if status != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d, want 401", status)
	}

	status, _ = f.rpc(t, "qvpat_"+strings.Repeat("z", 43), "initialize", initParams())
	if status != http.StatusUnauthorized {
		t.Fatalf("unknown token: status = %d, want 401", status)
	}

	// Non-PAT bearer (e.g. someone pasting a JWT) is rejected before any
	// backend call.
	status, _ = f.rpc(t, "eyJhbGciOi.fake.jwt", "initialize", initParams())
	if status != http.StatusUnauthorized {
		t.Fatalf("non-PAT bearer: status = %d, want 401", status)
	}
}

func TestInitializeAndToolsList(t *testing.T) {
	f := newFixture(t)

	status, out := f.rpc(t, f.validPAT, "initialize", initParams())
	if status != http.StatusOK {
		t.Fatalf("initialize: status = %d body %v", status, out)
	}

	status, out = f.rpc(t, f.validPAT, "tools/list", map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("tools/list: status = %d body %v", status, out)
	}
	result, _ := out["result"].(map[string]any)
	toolList, _ := result["tools"].([]any)
	if len(toolList) != 14 {
		t.Fatalf("tools/list returned %d tools, want 14", len(toolList))
	}
	names := map[string]bool{}
	for _, tl := range toolList {
		tool := tl.(map[string]any)
		name := tool["name"].(string)
		names[name] = true
		if !strings.HasPrefix(name, "vistaplatform_") {
			t.Errorf("tool %q missing vistaplatform_ prefix", name)
		}
		ann, _ := tool["annotations"].(map[string]any)
		if ann == nil || ann["readOnlyHint"] != true {
			t.Errorf("tool %q is not marked read-only", name)
		}
	}
	for _, want := range []string{
		"vistaplatform_query_assets", "vistaplatform_get_asset", "vistaplatform_query_certificates",
		"vistaplatform_query_crypto_configurations", "vistaplatform_query_algorithms",
		"vistaplatform_get_pqc_readiness", "vistaplatform_get_risk_summary",
		"vistaplatform_list_compliance_frameworks", "vistaplatform_get_compliance_summary",
		"vistaplatform_get_control_findings", "vistaplatform_list_cbom_scopes",
		"vistaplatform_list_cbom_artifacts", "vistaplatform_get_cbom_artifact",
		"vistaplatform_compare_cbom_artifacts",
	} {
		if !names[want] {
			t.Errorf("missing tool %q", want)
		}
	}
}

func callTool(t *testing.T, f *fixture, token, name string, args map[string]any) map[string]any {
	t.Helper()
	status, out := f.rpc(t, token, "tools/call", map[string]any{"name": name, "arguments": args})
	if status != http.StatusOK {
		t.Fatalf("tools/call %s: status = %d body %v", name, status, out)
	}
	result, ok := out["result"].(map[string]any)
	if !ok {
		t.Fatalf("tools/call %s: no result in %v", name, out)
	}
	return result
}

func toolText(t *testing.T, result map[string]any) string {
	t.Helper()
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("no content in result %v", result)
	}
	first := content[0].(map[string]any)
	return first["text"].(string)
}

func TestQueryAssetsForwardsJWTAndPrunes(t *testing.T) {
	f := newFixture(t)
	result := callTool(t, f, f.validPAT, "vistaplatform_query_assets", map[string]any{"search": "web", "page_size": 500})

	if result["isError"] == true {
		t.Fatalf("tool errored: %v", result)
	}
	text := toolText(t, result)
	if !strings.Contains(text, "web01") {
		t.Fatalf("asset payload missing: %s", text)
	}
	if strings.Contains(text, "SECRETPEM") || strings.Contains(text, "certificate_pem") || strings.Contains(text, "raw_data") {
		t.Fatalf("heavy fields not pruned: %s", text)
	}

	// The exchanged JWT (not the PAT) must be what reaches the backend.
	found := false
	for _, h := range f.backendAuthz {
		if strings.HasPrefix(h, "Bearer test-jwt-for-") {
			found = true
		}
		if strings.Contains(h, "qvpat_") {
			t.Fatalf("PAT leaked to platform backend: %s", h)
		}
	}
	if !found {
		t.Fatalf("exchanged JWT never reached the backend; saw %v", f.backendAuthz)
	}
}

func TestPermissionGateBlocksUngranted(t *testing.T) {
	f := newFixture(t)

	// limitedPAT carries assets.read only → compliance tool must refuse
	// without touching the backend.
	before := len(f.backendAuthz)
	result := callTool(t, f, f.limitedPAT, "vistaplatform_list_compliance_frameworks", map[string]any{})
	if result["isError"] != true {
		t.Fatalf("expected tool error, got %v", result)
	}
	if text := toolText(t, result); !strings.Contains(text, "compliance.read") {
		t.Fatalf("error should name the missing permission: %s", text)
	}
	if len(f.backendAuthz) != before {
		t.Fatal("backend was called despite missing permission")
	}

	// Same PAT can still use its granted tool.
	result = callTool(t, f, f.limitedPAT, "vistaplatform_get_risk_summary", map[string]any{})
	if result["isError"] == true {
		t.Fatalf("granted tool errored: %v", result)
	}
}

func TestComplianceToolMergesTwoCalls(t *testing.T) {
	f := newFixture(t)
	result := callTool(t, f, f.validPAT, "vistaplatform_list_compliance_frameworks", map[string]any{})
	if result["isError"] == true {
		t.Fatalf("tool errored: %v", result)
	}
	text := toolText(t, result)
	if !strings.Contains(text, "Best Practices") || !strings.Contains(text, "evaluation_status") {
		t.Fatalf("merged framework payload incomplete: %s", text)
	}
}

func TestInvalidUUIDRejectedBeforeBackend(t *testing.T) {
	f := newFixture(t)
	before := len(f.backendAuthz)
	result := callTool(t, f, f.validPAT, "vistaplatform_get_asset", map[string]any{"asset_id": "../../../etc/passwd"})
	if result["isError"] != true {
		t.Fatalf("expected tool error for bad UUID, got %v", result)
	}
	if len(f.backendAuthz) != before {
		t.Fatal("backend was called with unvalidated path input")
	}
}

func TestHealthEndpointUnauthenticated(t *testing.T) {
	f := newFixture(t)
	resp, err := http.Get(f.ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health: %d", resp.StatusCode)
	}
}

func TestMain(m *testing.M) {
	// gin debug noise off for readable test output
	_ = os.Setenv("GIN_MODE", "release")
	fmt.Println()
	os.Exit(m.Run())
}
