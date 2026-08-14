package services

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// The mirror into sensor_discoveries is what carries a discovery job's findings
// to inventory. It used to be gated on probeOpts["result_sink"] ==
// "sensor_discoveries", an option exactly one caller ever set, so every
// wizard-created job's findings reached inventory only if a browser posted them
// back. These tests pin the two properties that replaced that: the mirror runs
// for every job, and it runs once per finding.

func TestMirrorMetadata_StampsProvenanceWithoutGating(t *testing.T) {
	data := map[string]interface{}{"cipher_suite": "TLS_AES_128_GCM_SHA256"}

	job := mirrorMetadata(data, false)
	if job["discovery_source"] != "discovery_job" {
		t.Fatalf("wizard/discovery job stamped %v, want discovery_job", job["discovery_source"])
	}
	if job["cipher_suite"] != "TLS_AES_128_GCM_SHA256" {
		t.Fatal("probe data was not carried into the mirrored metadata")
	}

	scan := mirrorMetadata(data, true)
	if scan["discovery_source"] != "active_scan" {
		t.Fatalf("active scan stamped %v, want active_scan", scan["discovery_source"])
	}

	// The caller's map must not be mutated — findings are also written to
	// discovery_findings from the same struct.
	if _, leaked := data["discovery_source"]; leaked {
		t.Fatal("mirrorMetadata mutated the caller's data map")
	}
}

// TestProcessTarget_MirrorsUnconditionallyAndOnce reads processTarget's AST.
//
// A behavioural test would need a live Postgres and a platform sensor row; the
// property at risk is structural — a re-introduced `if` around the mirror call,
// or a second call site — and that is exactly what this sees. Mutation-verified:
// restoring the result_sink gate, or duplicating the call, fails it.
func TestProcessTarget_MirrorsUnconditionallyAndOnce(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "job_processor.go", nil, 0)
	if err != nil {
		t.Fatalf("parse job_processor.go: %v", err)
	}

	var body *ast.BlockStmt
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if ok && fn.Name.Name == "processTarget" {
			body = fn.Body
			return false
		}
		return true
	})
	if body == nil {
		t.Fatal("processTarget not found — this guard is inert; fix it rather than deleting it")
	}

	callSites := 0
	guardedCallSites := 0
	var walk func(n ast.Node, insideIf bool)
	walk = func(n ast.Node, insideIf bool) {
		if n == nil {
			return
		}
		switch node := n.(type) {
		case *ast.IfStmt:
			// The `if err := ...; err != nil` wrapper around the mirror call is
			// error handling, not a gate: the call lives in the init statement,
			// which we walk as NOT inside a condition.
			if node.Init != nil {
				walk(node.Init, insideIf)
			}
			walk(node.Cond, true)
			walk(node.Body, true)
			if node.Else != nil {
				walk(node.Else, true)
			}
			return
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "mirrorFindingToSensorDiscoveries" {
				callSites++
				if insideIf {
					guardedCallSites++
				}
			}
		}
		for _, child := range children(n) {
			walk(child, insideIf)
		}
	}
	walk(body, false)

	if callSites != 1 {
		t.Fatalf("processTarget has %d mirror call sites, want exactly 1 — more than one double-writes every finding", callSites)
	}
	if guardedCallSites != 0 {
		t.Fatal("the mirror into sensor_discoveries is conditional again — every discovery job must reach the ingestion queue, not just the ones carrying a routing option")
	}

	src, rerr := os.ReadFile("job_processor.go")
	if rerr != nil {
		t.Fatalf("read job_processor.go: %v", rerr)
	}
	if strings.Contains(string(src), "result_sink") {
		t.Fatal("result_sink is back in job_processor.go — the mirror must not be opt-in")
	}
}

// children yields an AST node's direct children via ast.Inspect on a one-level walk.
func children(n ast.Node) []ast.Node {
	var out []ast.Node
	first := true
	ast.Inspect(n, func(c ast.Node) bool {
		if first {
			first = false
			return true
		}
		if c != nil {
			out = append(out, c)
		}
		return false
	})
	return out
}
