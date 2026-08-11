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

	"github.com/vistasecurity/vistaplatform/mcp-service/internal/platform"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Deps carries everything tool handlers need.
type Deps struct {
	Client *platform.Client
}

// pruneKeys are stripped from every tool response — large payload fields
// that exist for machine re-verification, not for conversational use.
var pruneKeys = []string{"certificate_pem", "raw_data", "inline_content"}

var errPermission = errors.New("api token lacks the permission required by this tool")

// run wraps a tool body with the permission gate and JSON result encoding.
func run(ctx context.Context, perm string, body func() (any, error)) (*mcp.CallToolResult, any, error) {
	g, ok := platform.GrantFromContext(ctx)
	if !ok {
		return nil, nil, platform.ErrUnauthorized
	}
	if !g.HasPermission(perm) {
		return nil, nil, fmt.Errorf("%w: needs %q (token has %v) — mint a token including this permission in Settings → API Tokens", errPermission, perm, g.Permissions)
	}
	v, err := body()
	if err != nil {
		return nil, nil, err
	}
	v = platform.Prune(v, pruneKeys...)
	b, err := json.Marshal(v)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode result: %w", err)
	}
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
