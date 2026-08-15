// Package auditlog records what an AI agent did through the MCP surface.
//
// Why this exists as a small adapter rather than the generic gin middleware:
// every MCP request is the same POST to one endpoint carrying JSON-RPC, so
// shared/middleware/audit's LogRequest would write "POST /api/v1/mcp-service/mcp
// 200" for a query that returned the tenant's whole certificate inventory. The
// security-interesting unit here is the tool invocation — which tool, on whose
// behalf, with which filters, and how much came back.
//
// It is an adapter, not a parallel logging store: every event is handed to the
// same shared/middleware/audit.Middleware every other service writes through,
// and reaches audit-service by the same batch/NATS/HTTP path.
//
// What is deliberately NOT recorded: the data itself. A tool call records that
// the inventory was read and how many records came back, never the records.
// Tool arguments are projected onto an explicit allowlist (fail-closed: a field
// added to an input struct later is dropped until it is listed here), and the
// free-text ones are truncated to a preview.
package auditlog

import (
	"context"
	"time"

	sharedaudit "github.com/vistasecurity/vistaplatform/shared/middleware/audit"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// Sink is the subset of shared/middleware/audit.Middleware this package needs.
// Narrow so tests can substitute a collector; *audit.Middleware satisfies it.
type Sink interface {
	LogActivity(ctx context.Context, entry *sharedaudit.ActivityLogRequest) error
}

// Identity is the resolved actor behind an API token, flattened out of
// platform.Grant so this package stays free of mcp-service imports (platform
// imports auditlog, not the other way round).
type Identity struct {
	TenantID string
	UserID   string
	Email    string
	Role     string
}

// RequestContext is the transport-level provenance of the call: who connected
// and from where. Captured at the HTTP edge and carried into tool handlers,
// because by the time a tool runs there is no *http.Request in sight.
type RequestContext struct {
	IPAddress string
	UserAgent string
	RequestID string
}

// Recorder writes MCP audit events to the shared audit path.
type Recorder struct {
	sink Sink
}

// NewRecorder wraps an audit sink. A nil sink is a misconfiguration, not a
// mute switch — every event that cannot be written is reported at error level
// rather than dropped quietly.
func NewRecorder(s Sink) *Recorder {
	return &Recorder{sink: s}
}

// ToolCall is one MCP tool invocation, successful or not.
type ToolCall struct {
	Tool       string
	Permission string
	Identity   Identity
	Request    RequestContext
	// Args is the raw tool input; it is projected onto the allowlist before
	// anything is written.
	Args any
	// ResultBytes is the size of the encoded response — always available, and
	// the honest measure for tools whose result is an object rather than a list.
	ResultBytes int
	// ResultCount is the number of records returned; Counted says whether the
	// response had a countable collection at all. Zero-with-Counted is a real
	// answer ("the query matched nothing"), zero-without is "not applicable".
	ResultCount int
	Counted     bool
	Duration    time.Duration
	// Denied marks the token-permission gate refusing the call, as distinct
	// from the call running and failing.
	Denied bool
	Err    error
}

// RecordToolCall writes the audit record for a tool invocation.
func (r *Recorder) RecordToolCall(ctx context.Context, tc ToolCall) {
	metadata := map[string]any{
		"transport":   "mcp",
		"tool":        tc.Tool,
		"permission":  tc.Permission,
		"duration_ms": tc.Duration.Milliseconds(),
	}
	if args := projectArgs(tc.Args); len(args) > 0 {
		metadata["arguments"] = args
	}
	if tc.Err == nil {
		metadata["result_bytes"] = tc.ResultBytes
		if tc.Counted {
			metadata["result_records"] = tc.ResultCount
		}
	}

	entry := &sharedaudit.ActivityLogRequest{
		TenantID:      parseUUID(tc.Identity.TenantID),
		UserID:        parseUUID(tc.Identity.UserID),
		UserType:      "tenant",
		UserEmail:     strPtr(tc.Identity.Email),
		EventType:     "mcp.tool." + tc.Tool,
		EventCategory: CategoryForPermission(tc.Permission),
		Action:        "read",
		ResourceType:  strPtr("mcp_tool"),
		IPAddress:     strPtr(tc.Request.IPAddress),
		UserAgent:     strPtr(tc.Request.UserAgent),
		RequestID:     strPtr(tc.Request.RequestID),
		Success:       tc.Err == nil,
		Metadata:      metadata,
		Tags:          []string{"mcp", "ai_agent"},
		OccurredAt:    time.Now(),
	}
	if tc.Identity.Role != "" {
		metadata["role"] = tc.Identity.Role
	}
	if tc.Err != nil {
		entry.ErrorMessage = strPtr(truncate(tc.Err.Error(), 200))
		if tc.Denied {
			entry.ErrorCode = strPtr("MCP_PERMISSION_DENIED")
			entry.Tags = append(entry.Tags, "access_denied")
			entry.RequiresAttention = true
		} else {
			entry.ErrorCode = strPtr("MCP_TOOL_ERROR")
		}
	}

	r.write(ctx, entry, "tool call "+tc.Tool)
}

// Auth outcomes. These are the "on whose behalf" half of the record: a tool
// call says what was read, an auth event says which credential was accepted or
// refused, and from where.
const (
	// OutcomeTokenExchanged is a fresh API-token → user-JWT exchange against
	// auth-service. Cached grants do not repeat it; every tool call carries the
	// full identity, so no read is ever left unattributed.
	OutcomeTokenExchanged = "token_exchanged"
	// OutcomeTokenRejected is auth-service refusing the token (invalid,
	// expired, revoked).
	OutcomeTokenRejected = "token_rejected"
	// OutcomeTokenMissing is a request with no usable bearer token; it never
	// reaches auth-service.
	OutcomeTokenMissing = "token_missing"
	// OutcomeBackendUnavailable is auth-service failing to answer — the request
	// is refused, but not because the credential was bad.
	OutcomeBackendUnavailable = "backend_unavailable"
)

// AuthEvent is an authentication decision at the MCP edge.
type AuthEvent struct {
	Outcome  string
	Identity Identity
	Request  RequestContext
	// TokenFingerprint is a truncated SHA-256 of the presented token, so a
	// specific credential can be traced across events without the token itself
	// ever being written down.
	TokenFingerprint string
	Err              error
}

// RecordAuth writes the audit record for an authentication decision.
func (r *Recorder) RecordAuth(ctx context.Context, ev AuthEvent) {
	success := ev.Outcome == OutcomeTokenExchanged

	metadata := map[string]any{
		"transport": "mcp",
		"outcome":   ev.Outcome,
	}
	if ev.TokenFingerprint != "" {
		metadata["token_fingerprint"] = ev.TokenFingerprint
	}
	if ev.Identity.Role != "" {
		metadata["role"] = ev.Identity.Role
	}

	entry := &sharedaudit.ActivityLogRequest{
		TenantID:      parseUUID(ev.Identity.TenantID),
		UserID:        parseUUID(ev.Identity.UserID),
		UserType:      "tenant",
		UserEmail:     strPtr(ev.Identity.Email),
		EventType:     "mcp.auth." + ev.Outcome,
		EventCategory: "authentication",
		Action:        "authenticate",
		ResourceType:  strPtr("api_token"),
		IPAddress:     strPtr(ev.Request.IPAddress),
		UserAgent:     strPtr(ev.Request.UserAgent),
		RequestID:     strPtr(ev.Request.RequestID),
		Success:       success,
		Metadata:      metadata,
		Tags:          []string{"mcp", "ai_agent"},
		OccurredAt:    time.Now(),
	}
	if !success {
		entry.RequiresAttention = true
		entry.Tags = append(entry.Tags, "access_denied")
		entry.ErrorCode = strPtr("MCP_AUTH_" + upperASCII(ev.Outcome))
		if ev.Err != nil {
			entry.ErrorMessage = strPtr(truncate(ev.Err.Error(), 200))
		}
	}

	r.write(ctx, entry, "auth "+ev.Outcome)
}

// write hands the entry to the shared audit path. A missing sink or a rejected
// write is reported loudly: an audit trail that quietly stops recording is
// worse than none, because it still reads as evidence of absence.
func (r *Recorder) write(ctx context.Context, entry *sharedaudit.ActivityLogRequest, what string) {
	if r == nil || r.sink == nil {
		logrus.WithField("event", what).Error("mcp audit sink not configured; MCP activity is NOT being recorded")
		return
	}
	if err := r.sink.LogActivity(ctx, entry); err != nil {
		logrus.WithError(err).WithField("event", what).Error("failed to record MCP audit event")
	}
}

// CategoryForPermission maps a tool's declared API-token permission to an
// audit event_category. The audit.activity_logs valid_event_category CHECK
// accepts only a fixed set, so an unknown permission falls back to "data"
// rather than making the insert fail.
func CategoryForPermission(perm string) string {
	switch perm {
	case "assets.read":
		return "asset"
	case "compliance.read":
		return "compliance"
	case "reports.read":
		return "report"
	default:
		return "data"
	}
}

func parseUUID(s string) *uuid.UUID {
	if s == "" {
		return nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return nil
	}
	return &id
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func upperASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}
