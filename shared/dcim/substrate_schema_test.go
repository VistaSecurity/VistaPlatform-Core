package dcim_test

// The object-kind CHECK in schema.sql is written by hand from the generated Go
// list; this test keeps the two equal without a database, so the PR gate (which
// provisions none) catches a vocabulary row added without its schema twin.
// TestIntegration_ObjectKindCheck_MatchesGeneratedList asserts the same against
// the applied function.
//
// Mutation, both polarities: add a kind to the vocabulary (Go list only) →
// "missing from the schema"; add a literal to the schema only → "not in
// dcim.AllObjectKinds". Both fail.

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

var kindFunc = regexp.MustCompile(`(?s)CREATE OR REPLACE FUNCTION public\.dcim_object_kinds\(\) RETURNS text\[\].*?SELECT ARRAY\[(.*?)\]::text\[\]`)
var quoted = regexp.MustCompile(`'([a-z0-9_]+)'`)

func schemaKinds(t *testing.T, rel string) []string {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(here), "..", "..", rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	m := kindFunc.FindSubmatch(raw)
	if m == nil {
		t.Fatalf("%s: public.dcim_object_kinds() not found — the parity check cannot run", rel)
	}
	var out []string
	for _, q := range quoted.FindAllSubmatch(m[1], -1) {
		out = append(out, string(q[1]))
	}
	return out
}

func TestSchemaObjectKindList_EqualsGeneratedList(t *testing.T) {
	for _, rel := range []string{"scripts/database/schema.sql", "charts/vistaplatform/files/schema/schema.sql"} {
		got := schemaKinds(t, rel)
		in := map[string]bool{}
		for _, k := range got {
			if in[k] {
				t.Errorf("%s: %q listed twice", rel, k)
			}
			in[k] = true
		}
		goKinds := map[string]bool{}
		for _, k := range dcim.AllObjectKinds {
			goKinds[string(k)] = true
			if !in[string(k)] {
				t.Errorf("%s: kind %q is in dcim.AllObjectKinds but missing from public.dcim_object_kinds()", rel, k)
			}
		}
		for _, k := range got {
			if !goKinds[k] {
				t.Errorf("%s: %q is in public.dcim_object_kinds() but not in dcim.AllObjectKinds", rel, k)
			}
		}
		// Same order as the registry, so a diff of the two reads cleanly.
		want := make([]string, 0, len(dcim.AllObjectKinds))
		for _, k := range dcim.AllObjectKinds {
			want = append(want, string(k))
		}
		if !t.Failed() && strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: kinds are not in registry order", rel)
		}
	}
}
