package services

// Every struct this package hands to sqlx as a scan destination must name its
// columns with `db` tags. Without a tag sqlx matches a column to a field by
// the field's lowercased Go NAME, and the commercial image is built with
// garble, which renames untagged struct fields: the Core binary scans fine,
// the obfuscated one fails with "missing destination name ..." before it
// reads a single row, and the handler reports a 500 with nothing in the
// log. That is how POST /infrastructure-assets/enrich-all broke on every
// commercial install while the same code passed its tests here.
//
// The check is static: it parses this package's non-test sources and, for
// every call of the form `x.Select(&dest, …)` / `x.Get(&dest, …)` /
// `x.SelectContext(ctx, &dest, …)` / `x.GetContext(ctx, &dest, …)` whose
// destination is a local variable declared with an anonymous struct type
// (`var dest struct{…}` or `var dest []struct{…}`), requires a `db` tag on
// each exported field. Named types are left to their own definitions.
//
// Mutation: drop the `db:"ip"` tag in enrichment_service.go and this fails.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestSQLXScanDestinationsNameTheirColumnsWithDBTags(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var violations []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		violations = append(violations, untaggedScanStructFields(t, name)...)
	}
	if len(violations) > 0 {
		t.Fatalf("sqlx scan destinations with untagged exported fields (add `db:\"<column>\"`; garble renames untagged fields and the commercial binary then fails every scan into them):\n  %s",
			strings.Join(violations, "\n  "))
	}
}

var sqlxScanMethods = map[string]int{ // method → index of the destination argument
	"Select": 0, "Get": 0, "SelectContext": 1, "GetContext": 1,
}

func untaggedScanStructFields(t *testing.T, path string) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var out []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		// Anonymous-struct locals declared in this function, by name.
		anon := map[string]*ast.StructType{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			st := anonymousStruct(vs.Type)
			if st == nil {
				return true
			}
			for _, nm := range vs.Names {
				anon[nm.Name] = st
			}
			return true
		})
		if len(anon) == 0 {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			idx, ok := sqlxScanMethods[sel.Sel.Name]
			if !ok || len(call.Args) <= idx {
				return true
			}
			un, ok := call.Args[idx].(*ast.UnaryExpr)
			if !ok || un.Op != token.AND {
				return true
			}
			id, ok := un.X.(*ast.Ident)
			if !ok {
				return true
			}
			st, ok := anon[id.Name]
			if !ok {
				return true
			}
			for _, fld := range st.Fields.List {
				tagged := false
				if fld.Tag != nil {
					_, tagged = reflect.StructTag(strings.Trim(fld.Tag.Value, "`")).Lookup("db")
				}
				if tagged {
					continue
				}
				for _, nm := range fld.Names {
					if nm.IsExported() {
						out = append(out, fset.Position(nm.Pos()).String()+": "+id.Name+"."+nm.Name)
					}
				}
			}
			return true
		})
	}
	return out
}

// anonymousStruct returns the struct type behind `struct{…}`, `[]struct{…}`
// or `*struct{…}`, else nil.
func anonymousStruct(expr ast.Expr) *ast.StructType {
	switch x := expr.(type) {
	case *ast.StructType:
		return x
	case *ast.ArrayType:
		return anonymousStruct(x.Elt)
	case *ast.StarExpr:
		return anonymousStruct(x.X)
	}
	return nil
}
