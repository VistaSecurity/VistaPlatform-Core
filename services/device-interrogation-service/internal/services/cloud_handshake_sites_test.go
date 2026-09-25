package services

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// cloudHandshakeSites is the number of cloud collector sites that make a live
// TLS handshake: the AWS load balancers, API Gateway and CloudFront, the Azure
// application gateway, and the GCP HTTPS and SSL proxies. Pinned so a new site
// cannot appear without this test being looked at.
const cloudHandshakeSites = 6

// Every cloud collector that makes a handshake must carry its key-exchange
// measurement onto the crypto config it builds from it. The measurement is
// made inside TLSHandshakeService, so a site that forgets
// applyHandshakeKeyExchange compiles, passes every other test and silently
// drops the group — which is exactly what removing it from all six sites used
// to do. This walks the source: in every function that calls
// cloudTLSHandshake, there must be as many applyHandshakeKeyExchange calls as
// handshakes. The CloudFront path is additionally driven for real by
// TestIntegration_CloudFrontCollector_CarriesTLSKeyExchange.
func TestCloudHandshakeSitesApplyKeyExchange(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "cloud_discovery_service.go", nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	total := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		handshakes, applies := 0, 0
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok {
				switch id.Name {
				case "cloudTLSHandshake":
					handshakes++
				case "applyHandshakeKeyExchange":
					applies++
				}
			}
			// A handshake made any other way would bypass the check.
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "PerformHandshake" {
				t.Errorf("%s calls PerformHandshake directly (%s) — route it through cloudTLSHandshake", fn.Name.Name, fset.Position(call.Pos()))
			}
			return true
		})
		if handshakes != applies {
			t.Errorf("%s makes %d handshake(s) but applies the key-exchange measurement %d time(s)", fn.Name.Name, handshakes, applies)
		}
		total += handshakes
	}
	if total != cloudHandshakeSites {
		t.Errorf("found %d cloud handshake sites, want %d — update cloudHandshakeSites and make sure the new site applies the measurement", total, cloudHandshakeSites)
	}
}
