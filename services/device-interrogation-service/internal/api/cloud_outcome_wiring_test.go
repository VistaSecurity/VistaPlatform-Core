package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// slice E — the WIRING guard.
//
// CLAUDE.md's repeated lesson: "a fix can compile, pass its tests, and still do
// nothing in production", and "test the WIRING, not just the helper". The
// recorder, the dispatch and the projection all have real behavioural tests
// next door; the three lines that connect them to a running job live inside
// discoverCloudResourcesHandler's background goroutine, which needs a
// Postgres, a live AWS integration and a NATS client to reach. It is not
// unit-testable, and "untestable" is exactly where a wiring line gets deleted
// without anything going red.
//
// So this reads the handler's own source. It is a narrow guard — it asserts
// the three calls exist inside that function and that its JobResult's Success
// is not a literal again — and it is mutation-proven: deleting any of the three
// lines, or restoring `Success: true`, fails it.
//
// Not a substitute for a behavioural test. It is what is available.

func cloudHandlerSource(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatalf("read router.go: %v", err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "router.go", raw, 0)
	if err != nil {
		t.Fatalf("parse router.go: %v", err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "discoverCloudResourcesHandler" {
			continue
		}
		return string(raw[fset.Position(fn.Pos()).Offset:fset.Position(fn.End()).Offset])
	}
	t.Fatal("discoverCloudResourcesHandler not found in router.go — did it move? The guard must move with it.")
	return ""
}

func TestCloudDiscoveryHandler_WiresOutcomeRecorder(t *testing.T) {
	src := cloudHandlerSource(t)

	// 1. A recorder is created for the requested resource types...
	if !strings.Contains(src, "services.NewCloudOutcomeRecorder(req.ResourceTypes)") {
		t.Error("the cloud discovery handler no longer seeds a CloudOutcomeRecorder: every resource type would report nothing")
	}
	// 2. ...and attached to the context the collectors run under. Without this
	//    the collectors record into nothing and the result is silent again.
	if !strings.Contains(src, "services.WithCloudOutcomes(ctx,") {
		t.Error("the recorder is never attached to the discovery context — the collectors have nothing to record into")
	}
	// 3. ...and the outcomes decide both the metadata and `success`.
	if !strings.Contains(src, "outcomes.ApplyToJobResult(metadata)") {
		t.Error("the recorded outcomes never reach the stored job result")
	}
}

func TestCloudDiscoveryHandler_SuccessIsNotAConstant(t *testing.T) {
	src := cloudHandlerSource(t)
	if strings.Contains(src, "Success:     true") || strings.Contains(src, "Success: true") {
		t.Fatal("the cloud job result reports a constant `success: true` again — " +
			"a resource type that could not be collected is indistinguishable from an empty account (#1924)")
	}
	if !strings.Contains(src, "Success:     cloudSuccess") {
		t.Error("`success` is no longer derived from the per-resource-type outcomes")
	}
}
