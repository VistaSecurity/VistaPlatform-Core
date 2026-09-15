package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/mcp-service/internal/auditlog"
	"github.com/vistasecurity/vistaplatform/mcp-service/internal/platform"
	"github.com/vistasecurity/vistaplatform/mcp-service/internal/tools"
	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
)

const (
	tenantA = "11111111-1111-1111-1111-111111111111"
	tenantB = "33333333-3333-3333-3333-333333333333"
	// tenantBJWTSuffix is what the fake exchange mints for tenantBPAT: the
	// token's last six characters, which are all c's.
	tenantBJWTSuffix = "cccccc"
)

// jsonString renders s as a JSON string literal, for building fixture bodies.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func defaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// fixture wires the real MCP handler to fake auth-service and platform
// backends, exercising the same path a real MCP client hits.
type fixture struct {
	ts         *httptest.Server
	validPAT   string
	limitedPAT string // assets.read only
	tenantBPAT string // a SECOND tenant, for the isolation test
	// backendAuthz and backendURLs are appended in lockstep: index i of one
	// belongs to index i of the other, so a test can ask "what did the call
	// that carried this credential actually request?".
	backendAuthz []string
	backendURLs  []string
	audit        *auditSink
}

// last returns the most recent request URL the fake platform backend saw.
func (f *fixture) last(t *testing.T) *url.URL {
	t.Helper()
	if len(f.backendURLs) == 0 {
		t.Fatal("the backend was never called")
	}
	u, err := url.Parse(f.backendURLs[len(f.backendURLs)-1])
	if err != nil {
		t.Fatalf("parse recorded URL: %v", err)
	}
	return u
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		validPAT:   "qvpat_" + strings.Repeat("a", 43),
		limitedPAT: "qvpat_" + strings.Repeat("b", 43),
		tenantBPAT: "qvpat_" + strings.Repeat("c", 43),
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
		tenant := tenantA
		switch body.Token {
		case f.validPAT:
		case f.limitedPAT:
			perms = []string{"assets.read"}
		case f.tenantBPAT:
			tenant = tenantB
		default:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"Invalid api token"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-jwt-for-" + body.Token[len(body.Token)-6:],
			"expires_at":   time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339),
			"tenant_id":    tenant,
			"user_id":      "22222222-2222-2222-2222-222222222222",
			"email":        "user@example.com",
			"role":         "tenant_admin",
			"permissions":  perms,
		})
	}))
	t.Cleanup(authSrv.Close)

	// Fake platform backend: records the Authorization header and the request
	// URL, then returns recognizable payloads.
	//
	// It stands in for inventory-service closely enough to matter in two ways.
	// It ECHOES a canonical query the way the real handler does — the platform
	// AND-s its default scope in, so the echo is never the string that was sent,
	// which is the whole reason the tool must forward the echo rather than its
	// own input. And it serves rows PER TENANT keyed off the exchanged JWT,
	// standing in for RLS, so a test can prove one tenant's query cannot reach
	// another's rows.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		f.backendAuthz = append(f.backendAuthz, authz)
		f.backendURLs = append(f.backendURLs, r.URL.String())

		q := r.URL.Query().Get("query")
		// The real handler answers 400 with the structured diagnostics of
		// QUERY_LANGUAGE §10 for a query that does not validate.
		if strings.Contains(q, "hostnaem") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"Invalid query","query":` + jsonString(q) +
				`,"errors":[{"code":"unknown_field","message":"no field \"hostnaem\" on assets",` +
				`"span":{"start":0,"end":8},"suggestion":"did you mean \"hostname\"?"}]}`))
			return
		}
		canonical := "status:monitoring"
		if q != "" {
			canonical = "(" + q + ") and status:monitoring"
		}

		switch {
		case strings.HasSuffix(r.URL.Path, "/infrastructure-assets"):
			host, id := "web01", "a1"
			if strings.HasSuffix(authz, tenantBJWTSuffix) {
				host, id = "b-only-host", "b1"
			}
			page := r.URL.Query().Get("page")
			// Two pages exist, so has_next is a real answer on page 1 and a
			// real answer on page 2.
			hasNext := page == "" || page == "1"
			_, _ = fmt.Fprintf(w,
				`{"assets":[{"id":%q,"hostname":%q,"risk_score":0,"risk_assessed_by":[],`+
					`"certificate_pem":"SECRETPEM","raw_data":{"x":1}}],`+
					`"pagination":{"page":%s,"page_size":25,"total":2,"total_pages":2,"has_next":%t},`+
					`"query":%s}`,
				id, host, defaultStr(page, "1"), hasNext, jsonString(canonical))
		case strings.HasSuffix(r.URL.Path, "/infrastructure-assets/facets"):
			level := r.URL.Query().Get("level")
			if level == "" || level == "nonsense" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"Failed to get facets","message":"unknown facet level","levels":["class","risk"]}`))
				return
			}
			_, _ = fmt.Fprintf(w, `{"level":%q,"buckets":[{"key":%q,"count":7}],"query":%s}`,
				level, level+"-bucket", jsonString(canonical))
		// The grounded ask surface. The question chooses the branch, so one fake
		// covers every answer inventory-service can give — including the three
		// that are NOT failures and must come back as a structured
		// "not available" result rather than as a tool error.
		case strings.HasSuffix(r.URL.Path, "/ask"):
			var asked struct {
				Question string `json:"question"`
			}
			_ = json.NewDecoder(r.Body).Decode(&asked)
			switch {
			case strings.Contains(asked.Question, "core-build"):
				w.WriteHeader(http.StatusPaymentRequired)
				_, _ = w.Write([]byte(`{"error":"Asking questions in words is part of Vista Platform Enterprise."}`))
			case strings.Contains(asked.Question, "no-provider"):
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"error":"this deployment has no AI provider configured"}`))
			case strings.Contains(asked.Question, "switched-off"):
				// The ONE 403 that is an availability answer, and it says so
				// with a machine-readable `reason` rather than leaving a client
				// to recognise the sentence.
				w.WriteHeader(http.StatusForbidden)
				// The key is the shared constant, not a literal: inventory-service
				// writes the same one, so a rename cannot leave this fixture
				// green against a platform that stopped saying it.
				_, _ = fmt.Fprintf(w, `{"error":"Your organization has turned the AI assistant off.","reason":%q}`,
					seams.ReasonAssistantDisabled)
			case strings.Contains(asked.Question, "no-read"):
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"Insufficient permissions","required_permission":"assets.read"}`))
			case strings.Contains(asked.Question, "scoped-token"):
				// The OTHER permission 403 the same middleware writes, for a
				// scope-narrowed PAT. Capital P and no `required_permission` in
				// the prose: a client sniffing the message for the word
				// "permission" read this as the tenant kill switch.
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"Permission outside token scope","required_permission":"assets.read"}`))
			case strings.Contains(asked.Question, "stale-session"):
				// A 403 from neither of those: the session must change its
				// password first. Nothing about it is an availability answer.
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"Password change required before this action is allowed",` +
					`"code":"password_change_required"}`))
			case strings.Contains(asked.Question, "untranslatable"):
				w.WriteHeader(http.StatusUnprocessableEntity)
				_, _ = w.Write([]byte(`{"error":"could not be turned into a query","query":"hostnaem:web*",` +
					`"errors":[{"code":"unknown_field","message":"no field \"hostnaem\" on assets",` +
					`"span":{"start":0,"end":8},"suggestion":"did you mean \"hostname\"?"}],"attempts":2}`))
			default:
				_, _ = fmt.Fprintf(w,
					`{"query":%s,"rows":[{"id":"a1","hostname":"web01","certificate_pem":"SECRETPEM"}],`+
						`"text":"One production server matches [row:a1].",`+
						`"citations":[{"kind":"row","ref":"a1"}],`+
						`"tools":[{"tool":"vistaplatform_query_assets","args":{"limit":25}}],`+
						`"provenance":{"source_kind":"inferred","source_ref":"query:model","confidence":0,"model_id":"mock-model-1"}}`,
					jsonString("(environment:production) and status:monitoring"))
			}
		case strings.HasSuffix(r.URL.Path, "/history"):
			_, _ = w.Write([]byte(`{"history":[{"id":"h1","action":"updated","source":"discovery"}]}`))
		case strings.HasSuffix(r.URL.Path, "/asset-classes"):
			_, _ = w.Write([]byte(`{"classes":[{"key":"server","parent":"hardware.computer","path":"hardware.computer.server","label":"Server","is_fixed":true}]}`))
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
	if len(toolList) != 23 {
		t.Fatalf("tools/list returned %d tools, want 23", len(toolList))
	}
	names := map[string]bool{}
	descriptions := map[string]string{}
	for _, tl := range toolList {
		tool := tl.(map[string]any)
		name := tool["name"].(string)
		names[name] = true
		descriptions[name], _ = tool["description"].(string)
		if !strings.HasPrefix(name, "vistaplatform_") {
			t.Errorf("tool %q missing vistaplatform_ prefix", name)
		}
		ann, _ := tool["annotations"].(map[string]any)
		if ann == nil || ann["readOnlyHint"] != true {
			t.Errorf("tool %q is not marked read-only", name)
		}
	}
	for _, want := range []string{
		"vistaplatform_query_assets", "vistaplatform_get_asset", "vistaplatform_get_asset_history",
		"vistaplatform_list_asset_classes", "vistaplatform_list_asset_software",
		"vistaplatform_asset_facets", "vistaplatform_search",
		"vistaplatform_query_certificates",
		"vistaplatform_query_crypto_configurations", "vistaplatform_query_algorithms",
		"vistaplatform_get_pqc_readiness", "vistaplatform_get_risk_summary",
		"vistaplatform_list_compliance_frameworks", "vistaplatform_get_compliance_summary",
		"vistaplatform_get_control_findings", "vistaplatform_list_cbom_scopes",
		"vistaplatform_list_cbom_artifacts", "vistaplatform_get_cbom_artifact",
		"vistaplatform_compare_cbom_artifacts",
		// Relationships (ADR-0003, workstream 2.8).
		"vistaplatform_get_asset_relationships", "vistaplatform_get_asset_neighbourhood",
		"vistaplatform_get_asset_impact",
		// The grounded ask surface (ADR-0008 D1, build-plan 4.4b). It is
		// Enterprise and provider-dependent, but the TOOL is registered in every
		// edition — it answers `{"available": false, "reason": …}` rather than
		// disappearing, for the same reason the endpoint behind it answers 402
		// rather than 404: a tool that vanishes is indistinguishable from a
		// broken server, and an agent cannot report what it cannot see.
		"vistaplatform_ask",
	} {
		if !names[want] {
			t.Errorf("missing tool %q", want)
		}
	}

	// The tool description is the ONLY place an agent can learn the query
	// language — there is no per-field filter argument left to stumble into and
	// no deprecation window (ADR-0007 D2.4). A description that lost the grammar
	// or the examples would leave `query` as an undocumented free-text field.
	for _, name := range []string{"vistaplatform_query_assets", "vistaplatform_asset_facets"} {
		d := descriptions[name]
		for _, want := range []string{
			"environment:production", "cert:(not_after < now+30d)", "risk >= high",
			"crypto:(algorithm.deprecated:true)", "risk:not_assessed",
			"`attr.`", "`fact.`", "`id.`", "`tag.`",
			// The default scope, and that naming `status` steps it aside.
			// Without this an agent cannot know the approval queue and merge
			// tombstones are hidden from it by default, and would report
			// "no such asset" for one that is merely archived.
			"status:monitoring", "status:pending_approval",
		} {
			if !strings.Contains(d, want) {
				t.Errorf("%s description is missing %q — an agent cannot learn the language from it", name, want)
			}
		}
	}

	// Every tool that can return a risk number says what a zero means.
	for _, name := range []string{
		"vistaplatform_query_assets", "vistaplatform_get_asset", "vistaplatform_search",
		"vistaplatform_get_risk_summary", "vistaplatform_query_crypto_configurations",
	} {
		if !strings.Contains(descriptions[name], "NOT ASSESSED") {
			t.Errorf("%s returns a risk number without stating the not-assessed distinction", name)
		}
	}

	// A merged-away asset answers 200 with a tombstone pointer rather than 404,
	// so the one tool that fetches an asset by id has to say what that means —
	// otherwise an agent reports an archived duplicate as live inventory.
	if d := descriptions["vistaplatform_get_asset"]; !strings.Contains(d, "merged_into") || !strings.Contains(d, "TOMBSTONE") {
		t.Error("get_asset does not explain merged_into; an agent would present a tombstone as a live asset")
	}
}

// The legacy per-field filters are GONE, not deprecated: sending one is a
// schema violation, refused before any backend call. A tool that silently
// ignored them would answer a different question from the one it was asked.
func TestLegacyAssetFiltersAreRejected(t *testing.T) {
	f := newFixture(t)
	before := len(f.backendAuthz)
	for _, legacy := range []map[string]any{
		{"search": "web"},
		{"asset_type": []string{"server"}},
		{"risk_level": []string{"high"}},
		{"has_certificates": true},
		{"cert_expiring_within_days": 30},
		{"uses_deprecated_algorithms": true},
		{"sort_by": "hostname"},
	} {
		result := callTool(t, f, f.validPAT, "vistaplatform_query_assets", legacy)
		if result["isError"] != true {
			t.Errorf("legacy argument %v was accepted: %v", legacy, result)
		}
	}
	if len(f.backendAuthz) != before {
		t.Fatal("a rejected argument still reached the backend")
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
	result := callTool(t, f, f.validPAT, "vistaplatform_query_assets",
		map[string]any{"query": "environment:production", "limit": 500})

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

	// The query reaches the platform as ?query=, and limit is clamped to the
	// platform's page-size ceiling rather than passed through.
	got := f.last(t)
	if got.Query().Get("query") != "environment:production" {
		t.Errorf("query not forwarded: %s", got.RawQuery)
	}
	if got.Query().Get("page_size") != "100" {
		t.Errorf("limit not clamped to 100: %s", got.RawQuery)
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

// ADR-0008 D4.4: an agent must be able to show the query that ran, and that is
// NOT the query it sent — the platform AND-s its default scope in. The tool
// forwards the platform's echo verbatim; it must never substitute its input.
func TestQueryAssetsEchoesTheCanonicalQueryThatRan(t *testing.T) {
	f := newFixture(t)
	result := callTool(t, f, f.validPAT, "vistaplatform_query_assets",
		map[string]any{"query": "environment:production"})
	if result["isError"] == true {
		t.Fatalf("tool errored: %v", result)
	}

	var body map[string]any
	if err := json.Unmarshal([]byte(toolText(t, result)), &body); err != nil {
		t.Fatalf("result was not JSON: %v", err)
	}
	got, _ := body["query"].(string)
	if got != "(environment:production) and status:monitoring" {
		t.Fatalf("query echo = %q, want the platform's canonical form", got)
	}
	if got == "environment:production" {
		t.Fatal("the tool echoed its own input instead of what the platform ran")
	}
}

// A query the platform refuses comes back as the DIAGNOSTICS, not as
// "platform API error (HTTP 400)". This is the one error on this surface an
// agent can fix by itself, and it can only fix it if it is told what is wrong
// and where.
func TestInvalidQueryReturnsTheStructuredDiagnostics(t *testing.T) {
	f := newFixture(t)
	result := callTool(t, f, f.validPAT, "vistaplatform_query_assets",
		map[string]any{"query": "hostnaem:web"})
	if result["isError"] != true {
		t.Fatalf("an invalid query was not reported as an error: %v", result)
	}
	text := toolText(t, result)
	for _, want := range []string{
		"unknown_field",         // the machine-readable code
		`no field \"hostnaem\"`, // the message
		`"start":0`, `"end":8`,  // the span, so a caret can be drawn
		`did you mean \"hostname\"?`, // the fix
		"hostnaem:web",               // the query the spans index into
	} {
		if !strings.Contains(text, want) {
			t.Errorf("diagnostic %q missing from the tool error: %s", want, text)
		}
	}
	// And it must be unmistakable that nothing was returned, so the agent does
	// not read "error" as "empty inventory".
	if !strings.Contains(text, "NO rows") {
		t.Errorf("the error does not say that no rows were returned: %s", text)
	}
}

// The cursor is opaque and round-trips: page 1 hands back a token, the token
// fetches page 2, and the last page hands back nothing — an absent next_cursor
// is how a caller knows it is done.
func TestQueryAssetsCursorPaging(t *testing.T) {
	f := newFixture(t)

	first := callTool(t, f, f.validPAT, "vistaplatform_query_assets", map[string]any{})
	var page1 map[string]any
	if err := json.Unmarshal([]byte(toolText(t, first)), &page1); err != nil {
		t.Fatalf("page 1 was not JSON: %v", err)
	}
	cursor, _ := page1["next_cursor"].(string)
	if cursor == "" {
		t.Fatal("has_next was true but no next_cursor was issued")
	}
	if strings.Contains(cursor, "page") || strings.Contains(cursor, "2") {
		t.Errorf("cursor %q is legible; it must be opaque so nobody constructs one", cursor)
	}

	second := callTool(t, f, f.validPAT, "vistaplatform_query_assets", map[string]any{"cursor": cursor})
	if second["isError"] == true {
		t.Fatalf("paging with the issued cursor failed: %v", second)
	}
	if got := f.last(t).Query().Get("page"); got != "2" {
		t.Errorf("cursor resolved to page %q, want 2", got)
	}
	var page2 map[string]any
	_ = json.Unmarshal([]byte(toolText(t, second)), &page2)
	if _, present := page2["next_cursor"]; present {
		t.Error("the last page issued a next_cursor; a caller would page forever")
	}

	// A cursor this tool did not issue is an error, not a silent reset to page
	// one — replaying rows the caller already has would look like the list
	// changed underneath it.
	bad := callTool(t, f, f.validPAT, "vistaplatform_query_assets", map[string]any{"cursor": "not-a-cursor!!"})
	if bad["isError"] != true {
		t.Errorf("a malformed cursor was accepted: %v", bad)
	}
}

func TestAssetFacetsFansOutAndEchoesTheQuery(t *testing.T) {
	f := newFixture(t)
	result := callTool(t, f, f.validPAT, "vistaplatform_asset_facets", map[string]any{
		"query":  "environment:production",
		"facets": []string{"class", "risk"},
	})
	if result["isError"] == true {
		t.Fatalf("tool errored: %v", result)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(toolText(t, result)), &body); err != nil {
		t.Fatalf("result was not JSON: %v", err)
	}
	facets, _ := body["facets"].(map[string]any)
	if len(facets) != 2 || facets["class"] == nil || facets["risk"] == nil {
		t.Fatalf("facets = %v, want one entry per requested facet", body["facets"])
	}
	// The counts describe the same set the list would return, so the echo has
	// to be the same canonical query the list echoes.
	if got, _ := body["query"].(string); got != "(environment:production) and status:monitoring" {
		t.Errorf("facet query echo = %q", got)
	}
	// One request per facet, each carrying the query.
	var levels []string
	for _, raw := range f.backendURLs {
		u, _ := url.Parse(raw)
		if l := u.Query().Get("level"); l != "" {
			levels = append(levels, l)
			if u.Query().Get("query") != "environment:production" {
				t.Errorf("facet %q was counted without the query: %s", l, raw)
			}
		}
	}
	if len(levels) != 2 {
		t.Errorf("facet requests = %v, want one per facet", levels)
	}

	// No facets named is refused with the vocabulary, not with an empty result
	// that would read as "nothing matched".
	empty := callTool(t, f, f.validPAT, "vistaplatform_asset_facets", map[string]any{"facets": []string{}})
	if empty["isError"] != true || !strings.Contains(toolText(t, empty), "environment") {
		t.Errorf("an empty facet list should be refused and list the valid names: %v", empty)
	}

	// The platform's own rejection reaches the caller with its message, not as
	// a bare "Failed to get facets".
	bad := callTool(t, f, f.validPAT, "vistaplatform_asset_facets", map[string]any{"facets": []string{"nonsense"}})
	if bad["isError"] != true {
		t.Fatalf("an unknown facet level was accepted: %v", bad)
	}
	if text := toolText(t, bad); !strings.Contains(text, "unknown facet level") || !strings.Contains(text, "nonsense") {
		t.Errorf("the facet error lost the platform's message: %s", text)
	}
}

func TestListAssetClassesAndHistory(t *testing.T) {
	f := newFixture(t)

	classes := callTool(t, f, f.validPAT, "vistaplatform_list_asset_classes", map[string]any{})
	if classes["isError"] == true {
		t.Fatalf("list_asset_classes errored: %v", classes)
	}
	text := toolText(t, classes)
	for _, want := range []string{"hardware.computer.server", `"label":"Server"`, `"is_fixed":true`} {
		if !strings.Contains(text, want) {
			t.Errorf("class tree missing %q: %s", want, text)
		}
	}

	history := callTool(t, f, f.validPAT, "vistaplatform_get_asset_history",
		map[string]any{"asset_id": "44444444-4444-4444-4444-444444444444"})
	if history["isError"] == true {
		t.Fatalf("get_asset_history errored: %v", history)
	}
	if !strings.Contains(toolText(t, history), `"action":"updated"`) {
		t.Errorf("history payload missing: %s", toolText(t, history))
	}
	if !strings.HasSuffix(f.last(t).Path, "/44444444-4444-4444-4444-444444444444/history") {
		t.Errorf("history requested the wrong path: %s", f.last(t).Path)
	}

	// A non-UUID never shapes a request path.
	bad := callTool(t, f, f.validPAT, "vistaplatform_get_asset_history", map[string]any{"asset_id": "../../etc/passwd"})
	if bad["isError"] != true {
		t.Errorf("history accepted a non-UUID asset_id: %v", bad)
	}
}

// Free text becomes a QUOTED literal, so a value containing a space, a
// parenthesis or a quote is data and cannot change the shape of the query built
// around it.
func TestSearchQuotesTheFreeTextTerm(t *testing.T) {
	f := newFixture(t)

	result := callTool(t, f, f.validPAT, "vistaplatform_search", map[string]any{"text": `pay roll) or class:server`})
	if result["isError"] == true {
		t.Fatalf("search errored: %v", result)
	}
	if got := f.last(t).Query().Get("query"); got != `"pay roll) or class:server"` {
		t.Fatalf("search term not quoted as one literal: %q", got)
	}

	blank := callTool(t, f, f.validPAT, "vistaplatform_search", map[string]any{"text": "   "})
	if blank["isError"] != true {
		t.Errorf("a blank search was accepted and would have returned the whole inventory: %v", blank)
	}
}

// Tenant isolation is the token's, not the tool's: the tool sends no tenant of
// its own, and the rows it gets back are whatever the exchanged JWT can reach.
// Two tenants asking the identical question get disjoint answers.
func TestQueryIsScopedToTheCallersTenant(t *testing.T) {
	f := newFixture(t)
	const q = "environment:production"

	a := callTool(t, f, f.validPAT, "vistaplatform_query_assets", map[string]any{"query": q})
	aText := toolText(t, a)
	b := callTool(t, f, f.tenantBPAT, "vistaplatform_query_assets", map[string]any{"query": q})
	bText := toolText(t, b)

	if !strings.Contains(aText, "web01") || strings.Contains(aText, "b-only-host") {
		t.Errorf("tenant A's query returned tenant B's rows: %s", aText)
	}
	if !strings.Contains(bText, "b-only-host") || strings.Contains(bText, "web01") {
		t.Errorf("tenant B's query returned tenant A's rows: %s", bText)
	}

	// Neither call may carry a tenant id the caller could have chosen: the
	// tenant is decided by the credential, and a tenant parameter on the wire
	// would be a tenant parameter something could tamper with.
	for _, raw := range f.backendURLs {
		if strings.Contains(raw, "tenant") {
			t.Errorf("a tenant parameter reached the platform: %s", raw)
		}
		if strings.Contains(raw, tenantA) || strings.Contains(raw, tenantB) {
			t.Errorf("a tenant id reached the platform on the query string: %s", raw)
		}
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
