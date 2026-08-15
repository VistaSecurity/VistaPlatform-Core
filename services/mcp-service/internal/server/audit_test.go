package server

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	sharedaudit "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// auditSink collects the entries the MCP service hands to the shared audit
// path, standing in for *audit.Middleware.
//
// These tests are written so that deleting the audit call they cover makes them
// FAIL, not pass with an empty slice — every assertion below names an entry it
// requires, rather than merely inspecting whatever happened to be recorded.
type auditSink struct {
	mu      sync.Mutex
	entries []*sharedaudit.ActivityLogRequest
}

func (s *auditSink) LogActivity(_ context.Context, entry *sharedaudit.ActivityLogRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, entry)
	return nil
}

func (s *auditSink) all() []*sharedaudit.ActivityLogRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*sharedaudit.ActivityLogRequest, len(s.entries))
	copy(out, s.entries)
	return out
}

// only returns the single entry with the given event type, failing if there is
// not exactly one. "Exactly one" matters: a duplicated record is as misleading
// as a missing one when someone is reconstructing what an agent read.
func (s *auditSink) only(t *testing.T, eventType string) *sharedaudit.ActivityLogRequest {
	t.Helper()
	var found []*sharedaudit.ActivityLogRequest
	for _, e := range s.all() {
		if e.EventType == eventType {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly 1 audit entry of type %q, got %d (all: %s)", eventType, len(found), s.summary())
	}
	return found[0]
}

func (s *auditSink) summary() string {
	var b []string
	for _, e := range s.all() {
		b = append(b, e.EventType)
	}
	if len(b) == 0 {
		return "<none>"
	}
	return strings.Join(b, ", ")
}

func TestAuditRecordsSuccessfulToolCall(t *testing.T) {
	f := newFixture(t)
	result := callTool(t, f, f.validPAT, "vistaplatform_query_assets",
		map[string]any{"search": "web", "environment": []string{"production"}, "page_size": 10})
	if result["isError"] == true {
		t.Fatalf("tool errored: %v", result)
	}

	e := f.audit.only(t, "mcp.tool.vistaplatform_query_assets")

	if !e.Success {
		t.Errorf("successful read recorded as failure: %+v", e)
	}
	if e.TenantID == nil || e.TenantID.String() != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("tenant not attributed: %v", e.TenantID)
	}
	if e.UserID == nil || e.UserID.String() != "22222222-2222-2222-2222-222222222222" {
		t.Errorf("user not attributed: %v", e.UserID)
	}
	if e.UserEmail == nil || *e.UserEmail != "user@example.com" {
		t.Errorf("user email not attributed: %v", e.UserEmail)
	}
	if e.UserType != "tenant" {
		t.Errorf("user_type = %q, want tenant", e.UserType)
	}
	if e.EventCategory != "asset" {
		t.Errorf("event_category = %q, want asset", e.EventCategory)
	}
	if e.Action != "read" {
		t.Errorf("action = %q, want read — reading IS the sensitive act here", e.Action)
	}
	if e.OccurredAt.IsZero() {
		t.Error("occurred_at not set")
	}

	// Size of the result, so "how much did the agent take" is answerable.
	records, ok := e.Metadata["result_records"].(int)
	if !ok || records != 1 {
		t.Errorf("result_records = %v, want 1", e.Metadata["result_records"])
	}
	if b, ok := e.Metadata["result_bytes"].(int); !ok || b <= 0 {
		t.Errorf("result_bytes = %v, want > 0", e.Metadata["result_bytes"])
	}

	// Arguments are projected, and the free-text one is a preview.
	args, ok := e.Metadata["arguments"].(map[string]any)
	if !ok {
		t.Fatalf("arguments not recorded: %v", e.Metadata)
	}
	if args["search_preview"] != "web" {
		t.Errorf("search_preview = %v, want web", args["search_preview"])
	}
	if _, leaked := args["search"]; leaked {
		t.Error("raw search argument recorded; only the preview should be")
	}
	if env, _ := args["environment"].([]any); len(env) != 1 || env[0] != "production" {
		t.Errorf("environment filter not recorded: %v", args["environment"])
	}

	// The data itself must never be in the record.
	if strings.Contains(f.audit.summary(), "web01") {
		t.Error("hostname leaked into event type")
	}
	for k, v := range e.Metadata {
		if s, ok := v.(string); ok && strings.Contains(s, "web01") {
			t.Errorf("inventory data leaked into audit metadata[%s]: %s", k, s)
		}
	}
}

func TestAuditRecordsDeniedToolCall(t *testing.T) {
	f := newFixture(t)

	// limitedPAT carries assets.read only; the compliance tool is refused by
	// the token-permission gate before any backend call.
	result := callTool(t, f, f.limitedPAT, "vistaplatform_list_compliance_frameworks", map[string]any{})
	if result["isError"] != true {
		t.Fatalf("expected the tool to be refused, got %v", result)
	}

	e := f.audit.only(t, "mcp.tool.vistaplatform_list_compliance_frameworks")

	if e.Success {
		t.Error("denied call recorded as success")
	}
	if e.ErrorCode == nil || *e.ErrorCode != "MCP_PERMISSION_DENIED" {
		t.Errorf("error_code = %v, want MCP_PERMISSION_DENIED", e.ErrorCode)
	}
	if !e.RequiresAttention {
		t.Error("a refused read should be flagged for attention")
	}
	if e.ErrorMessage == nil || !strings.Contains(*e.ErrorMessage, "compliance.read") {
		t.Errorf("error_message should name the missing permission: %v", e.ErrorMessage)
	}
	if !hasTag(e.Tags, "access_denied") {
		t.Errorf("tags = %v, want access_denied", e.Tags)
	}
	// A refused call returned nothing; claiming a record count would be a lie.
	if _, present := e.Metadata["result_records"]; present {
		t.Errorf("denied call recorded a result count: %v", e.Metadata)
	}
}

func TestAuditRecordsFailedToolCall(t *testing.T) {
	f := newFixture(t)

	// The fake backend has no route for the CBOM scopes path → upstream error.
	result := callTool(t, f, f.validPAT, "vistaplatform_list_cbom_scopes", map[string]any{})
	if result["isError"] != true {
		t.Fatalf("expected an upstream failure, got %v", result)
	}

	e := f.audit.only(t, "mcp.tool.vistaplatform_list_cbom_scopes")
	if e.Success {
		t.Error("failed call recorded as success")
	}
	if e.ErrorCode == nil || *e.ErrorCode != "MCP_TOOL_ERROR" {
		t.Errorf("error_code = %v, want MCP_TOOL_ERROR", e.ErrorCode)
	}
	if e.EventCategory != "report" {
		t.Errorf("event_category = %q, want report", e.EventCategory)
	}
}

func TestAuditRecordsTokenExchange(t *testing.T) {
	f := newFixture(t)
	callTool(t, f, f.validPAT, "vistaplatform_get_risk_summary", map[string]any{})

	e := f.audit.only(t, "mcp.auth.token_exchanged")
	if !e.Success {
		t.Error("accepted credential recorded as failure")
	}
	if e.EventCategory != "authentication" {
		t.Errorf("event_category = %q, want authentication", e.EventCategory)
	}
	if e.TenantID == nil || e.UserID == nil {
		t.Errorf("exchange did not attribute an identity: tenant=%v user=%v", e.TenantID, e.UserID)
	}
	fp, _ := e.Metadata["token_fingerprint"].(string)
	if len(fp) != 16 {
		t.Errorf("token_fingerprint = %q, want a 16-char hash prefix", fp)
	}
	if strings.Contains(fp, "qvpat_") || strings.Contains(f.audit.summary(), "qvpat_") {
		t.Error("the API token itself reached the audit record")
	}
	for _, entry := range f.audit.all() {
		for k, v := range entry.Metadata {
			if s, ok := v.(string); ok && strings.Contains(s, f.validPAT) {
				t.Errorf("plaintext PAT recorded in metadata[%s]", k)
			}
		}
	}

	// A second call reuses the cached grant: the credential decision happened
	// once, so it is recorded once — while the second read still gets its own
	// fully attributed tool record.
	callTool(t, f, f.validPAT, "vistaplatform_get_risk_summary", map[string]any{})
	f.audit.only(t, "mcp.auth.token_exchanged")
	var toolCalls int
	for _, entry := range f.audit.all() {
		if entry.EventType == "mcp.tool.vistaplatform_get_risk_summary" {
			toolCalls++
			if entry.TenantID == nil {
				t.Error("a cached-grant read went unattributed")
			}
		}
	}
	if toolCalls != 2 {
		t.Errorf("recorded %d tool calls, want 2", toolCalls)
	}
}

func TestAuditRecordsRejectedToken(t *testing.T) {
	f := newFixture(t)

	status, _ := f.rpc(t, "qvpat_"+strings.Repeat("z", 43), "initialize", initParams())
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}

	e := f.audit.only(t, "mcp.auth.token_rejected")
	if e.Success {
		t.Error("rejected credential recorded as success")
	}
	if !e.RequiresAttention {
		t.Error("a rejected credential should be flagged for attention")
	}
	if e.ErrorCode == nil || *e.ErrorCode != "MCP_AUTH_TOKEN_REJECTED" {
		t.Errorf("error_code = %v", e.ErrorCode)
	}
	// Nothing was resolved, so nothing may be claimed about who it was.
	if e.TenantID != nil || e.UserID != nil {
		t.Errorf("rejected token attributed to an identity: tenant=%v user=%v", e.TenantID, e.UserID)
	}
}

func TestAuditRecordsMissingToken(t *testing.T) {
	f := newFixture(t)

	status, _ := f.rpc(t, "", "initialize", initParams())
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}

	e := f.audit.only(t, "mcp.auth.token_missing")
	if e.Success {
		t.Error("missing credential recorded as success")
	}
	if e.IPAddress == nil || *e.IPAddress == "" {
		t.Error("an anonymous refusal must at least record where it came from")
	}
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}
