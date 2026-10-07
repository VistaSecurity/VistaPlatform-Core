package main

// Every http.Server this binary starts must set read-header, read, write and
// idle timeouts. A server without them keeps a connection (and its goroutine)
// open for as long as the peer likes, which is a slowloris from anywhere that
// can reach the pod.
//
// cmd is package main, so the wiring cannot be driven from a test; the guard
// reads the real main.go as syntax instead (the same approach as the body
// ceiling guard in cluster-sensor-service) and checks every http.Server
// composite literal in it. Deleting a field from any of them fails this.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestEveryHTTPServerLiteralSetsTimeouts(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	required := []string{"ReadHeaderTimeout", "ReadTimeout", "WriteTimeout", "IdleTimeout"}
	servers := 0
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Server" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "http" {
			return true
		}
		servers++
		set := map[string]bool{}
		for _, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				if key, ok := kv.Key.(*ast.Ident); ok {
					set[key.Name] = true
				}
			}
		}
		for _, field := range required {
			if !set[field] {
				t.Errorf("http.Server literal at %s does not set %s", fset.Position(lit.Pos()), field)
			}
		}
		return true
	})

	// The scan itself must find the servers: a renamed type or a moved literal
	// would otherwise pass vacuously.
	if servers < 2 {
		t.Fatalf("found %d http.Server literals in main.go, expected the health server and the HTTP API server", servers)
	}
}
