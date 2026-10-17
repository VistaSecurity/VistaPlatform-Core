package dcim

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// declaredKinds reads the generated file's own source, so the test does not
// trust AllObjectKinds to be complete: dropping a constant from the slice (or
// the info map) must fail here.
func declaredKinds(t *testing.T) []ObjectKind {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "objectkind_gen.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []ObjectKind
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, s := range g.Specs {
			vs := s.(*ast.ValueSpec)
			if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "ObjectKind" {
				continue
			}
			for _, v := range vs.Values {
				out = append(out, ObjectKind(v.(*ast.BasicLit).Value[1:len(v.(*ast.BasicLit).Value)-1]))
			}
		}
	}
	return out
}

func TestParseObjectKindRoundTripsEveryKind(t *testing.T) {
	declared := declaredKinds(t)
	if len(declared) == 0 {
		t.Fatal("no ObjectKind constants found in objectkind_gen.go")
	}
	inAll := map[ObjectKind]bool{}
	for _, k := range AllObjectKinds {
		inAll[k] = true
	}
	if len(AllObjectKinds) != len(declared) {
		t.Fatalf("AllObjectKinds has %d entries, %d constants are declared", len(AllObjectKinds), len(declared))
	}
	for _, k := range declared {
		if !inAll[k] {
			t.Errorf("constant %q missing from AllObjectKinds", k)
		}
		got, ok := ParseObjectKind(string(k))
		if !ok || got != k {
			t.Errorf("ParseObjectKind(%q) = %q, %v", k, got, ok)
		}
		if k.Label() == "" || k.Plural() == "" || k.Phase() == "" {
			t.Errorf("%q: label/plural/phase must be set", k)
		}
	}
}

func TestParseObjectKindRejectsUnknown(t *testing.T) {
	for _, s := range []string{"", "Asset", "network_asset", "subnet"} {
		if _, ok := ParseObjectKind(s); ok {
			t.Errorf("ParseObjectKind(%q) accepted", s)
		}
	}
}

func TestObjectKindMetadata(t *testing.T) {
	if ObjectKindAsset.Table() != "assets" || ObjectKindEndpoint.Table() != "asset_endpoints" {
		t.Error("reserved kinds must map to their existing tables")
	}
	if ObjectKindPrefix.Table() != "prefixes" || ObjectKindPrefix.Label() != "Prefix" {
		t.Errorf("prefix: %q %q", ObjectKindPrefix.Table(), ObjectKindPrefix.Label())
	}
	if ObjectKindUnresolvedTermination.NetBox() != "" {
		t.Error("unresolved_termination has no NetBox counterpart")
	}
	if ObjectKind("nope").Table() != "" {
		t.Error("unknown kind must yield empty metadata")
	}
}
