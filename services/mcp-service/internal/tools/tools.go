// Package tools defines the read-only MCP tool surface of VistaPlatform.
//
// Design rules (v1):
//   - Read-only. Every tool carries ReadOnlyHint and wraps a GET (or the
//     GET-shaped compare endpoint). No tool mutates tenant state.
//   - Curated, task-shaped tools — not a 1:1 mirror of the REST surface.
//   - Each tool declares the API-token permission it requires; the handler
//     refuses to run when the token wasn't minted with that permission,
//     independent of what the exchanged user JWT could reach.
//   - Responses are the platform's own JSON with token-hungry fields
//     (certificate_pem, raw_data) pruned, returned as JSON text content.
package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/vistasecurity/vistaplatform/mcp-service/internal/auditlog"
	"github.com/vistasecurity/vistaplatform/mcp-service/internal/platform"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Deps carries everything tool handlers need.
type Deps struct {
	Client *platform.Client
	// Audit records every tool invocation to the shared audit path. Reading is
	// the sensitive act on this surface — it is the one interface built to hand
	// bulk tenant data to a non-human consumer — so successful reads are logged,
	// not just failures.
	Audit *auditlog.Recorder
}

// pruneKeys are stripped from every tool response — large payload fields
// that exist for machine re-verification, not for conversational use.
var pruneKeys = []string{"certificate_pem", "raw_data", "inline_content"}

var errPermission = errors.New("api token lacks the permission required by this tool")

// run wraps a tool body with the permission gate, JSON result encoding and the
// audit record.
//
// Every exit path below writes an audit record — success, permission refusal
// and downstream failure alike. The one path that does not is a request with no
// grant at all, which cannot happen behind the auth middleware and would have
// no tenant to attribute the record to; the middleware has already recorded the
// rejected authentication in that case.
func (d *Deps) run(ctx context.Context, req *mcp.CallToolRequest, perm string, args any, body func() (any, error)) (*mcp.CallToolResult, any, error) {
	g, ok := platform.GrantFromContext(ctx)
	if !ok {
		return nil, nil, platform.ErrUnauthorized
	}

	// Taken from the request rather than repeated at each call site: a tool
	// name written down twice is a tool name that eventually disagrees with
	// itself, and the audit trail is the copy nobody would notice was wrong.
	tool := "unknown"
	if req != nil && req.Params != nil && req.Params.Name != "" {
		tool = req.Params.Name
	}

	started := time.Now()
	record := func(tc auditlog.ToolCall) {
		tc.Tool = tool
		tc.Permission = perm
		tc.Identity = g.Identity()
		tc.Request = platform.RequestContextFrom(ctx)
		tc.Args = args
		tc.Duration = time.Since(started)
		d.Audit.RecordToolCall(ctx, tc)
	}

	if !g.HasPermission(perm) {
		err := fmt.Errorf("%w: needs %q (token has %v) — mint a token including this permission in Settings → API Tokens", errPermission, perm, g.Permissions)
		record(auditlog.ToolCall{Denied: true, Err: err})
		return nil, nil, err
	}

	v, err := body()
	if err != nil {
		record(auditlog.ToolCall{Err: err})
		return nil, nil, err
	}

	v = platform.Prune(v, pruneKeys...)
	b, err := json.Marshal(v)
	if err != nil {
		err = fmt.Errorf("failed to encode result: %w", err)
		record(auditlog.ToolCall{Err: err})
		return nil, nil, err
	}

	// Size, never contents: how much of the tenant's inventory this call
	// handed over is the auditable fact; the inventory itself is not.
	count, counted := auditlog.CountRecords(v)
	record(auditlog.ToolCall{ResultBytes: len(b), ResultCount: count, Counted: counted})

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(b)}},
	}, nil, nil
}

// readOnly is the annotation set shared by every tool: no mutation, same
// args → same result modulo inventory drift, closed world (the tenant's own
// inventory, not the open internet).
func readOnly(title string) *mcp.ToolAnnotations {
	f := false
	return &mcp.ToolAnnotations{
		Title:           title,
		ReadOnlyHint:    true,
		IdempotentHint:  true,
		OpenWorldHint:   &f,
		DestructiveHint: &f,
	}
}

// clampPage normalizes pagination inputs: page >= 1, 1 <= page_size <= 100
// (default 25).
func clampPage(page, pageSize int) (string, string) {
	if page < 1 {
		page = 1
	}
	switch {
	case pageSize < 1:
		pageSize = 25
	case pageSize > 100:
		pageSize = 100
	}
	return strconv.Itoa(page), strconv.Itoa(pageSize)
}

// requireUUID validates path-bound identifiers so tool input can never
// shape a request path.
func requireUUID(field, v string) (string, error) {
	id, err := uuid.Parse(v)
	if err != nil {
		return "", fmt.Errorf("%s must be a UUID, got %q", field, v)
	}
	return id.String(), nil
}

// Register adds every VistaPlatform tool to the server.
func Register(s *mcp.Server, d *Deps) {
	registerInventoryTools(s, d)
	registerComplianceTools(s, d)
	registerCBOMTools(s, d)
}
