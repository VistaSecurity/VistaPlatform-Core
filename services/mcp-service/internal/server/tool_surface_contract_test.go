package server

// The MCP tool surface is a published contract, and it had no guardrail.
//
// Every other service's API is pinned by an OpenAPI document plus contract
// tests. mcp-service speaks JSON-RPC, so OpenAPI does not apply — and nothing
// took its place. The existing tools/list test counts the tools and checks
// their names and read-only hints; what nobody could see was a change to an
// INPUT SCHEMA. Renaming a parameter, narrowing an enum, making an optional
// argument required or dropping a field are all invisible to a count, and every
// one of them breaks an agent mid-conversation with an argument error it cannot
// interpret.
//
// So this is a snapshot of the whole surface — name, description, read-only
// hint and full input schema, canonically serialised — against
// `testdata/tool-surface.json`. A deliberate change is a visible diff in that
// file; an accidental one is a failing test.
//
// Regenerate with: UPDATE_TOOL_SURFACE=1 go test ./internal/server/ -run ToolSurface

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

const toolSurfaceFile = "testdata/tool-surface.json"

// toolSnapshot is one tool, reduced to the parts that are a CONTRACT. The
// annotations' title is deliberately included — it is what a client shows a
// person about to approve a call.
type toolSnapshot struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	ReadOnly    bool            `json:"read_only"`
	Title       string          `json:"title,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
}

func TestToolSurfaceSnapshot(t *testing.T) {
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
	if len(toolList) == 0 {
		t.Fatal("tools/list returned no tools; the snapshot would pin an empty surface, " +
			"which is the one way this guard passes over nothing")
	}

	snapshot := make([]toolSnapshot, 0, len(toolList))
	for _, raw := range toolList {
		tool, _ := raw.(map[string]any)
		name, _ := tool["name"].(string)
		desc, _ := tool["description"].(string)
		ann, _ := tool["annotations"].(map[string]any)
		readOnly, _ := ann["readOnlyHint"].(bool)
		title, _ := ann["title"].(string)

		var schema json.RawMessage
		if in, ok := tool["inputSchema"]; ok {
			// Re-marshalled from the decoded value, so key order is Go's
			// deterministic map ordering rather than the wire's.
			b, err := json.Marshal(in)
			if err != nil {
				t.Fatalf("%s: marshal input schema: %v", name, err)
			}
			schema = b
		}
		snapshot = append(snapshot, toolSnapshot{
			Name: name, Description: desc, ReadOnly: readOnly, Title: title, InputSchema: schema,
		})
	}
	sortSnapshots(snapshot)

	got, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	got = append(got, '\n')

	if os.Getenv("UPDATE_TOOL_SURFACE") != "" {
		if err := os.MkdirAll(filepath.Dir(toolSurfaceFile), 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(toolSurfaceFile, got, 0o644); err != nil {
			t.Fatalf("write snapshot: %v", err)
		}
		t.Logf("wrote %s (%d tools)", toolSurfaceFile, len(snapshot))
		return
	}

	want, err := os.ReadFile(toolSurfaceFile)
	if err != nil {
		t.Fatalf("read %s: %v\nRegenerate with UPDATE_TOOL_SURFACE=1", toolSurfaceFile, err)
	}
	if string(got) != string(want) {
		t.Errorf("the MCP tool surface has changed.\n\n"+
			"This is a PUBLISHED contract: an agent mid-conversation gets an argument error it "+
			"cannot interpret when a parameter is renamed, an enum narrowed or an optional "+
			"argument made required — and a tool COUNT cannot see any of those.\n\n"+
			"If the change is deliberate, regenerate with:\n"+
			"  UPDATE_TOOL_SURFACE=1 go test ./internal/server/ -run ToolSurface\n"+
			"and review the diff.\n\n--- got ---\n%s", string(got))
	}
}

func sortSnapshots(s []toolSnapshot) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j].Name < s[j-1].Name; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
