package handlers

// The IPAM contract (DCIM BUILD_PLAN row 1.3). The engine returns each row as
// Postgres serialises it, so the API shape IS the table: this test holds every
// OpenAPI object schema to its table's column list in schema.sql, and every
// create/update input schema to the engine's writable columns. A column added
// to the table, the spec or the engine without the other two goes red here —
// without a database, so it runs in `make api-contract`.
//
// ipam_contract_integration_test.go drives the real handlers over the real
// schema and validates the bodies against these schemas.

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

func repoFile(t *testing.T, parts ...string) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	p := filepath.Join(append([]string{filepath.Dir(thisFile), "..", "..", "..", ".."}, parts...)...)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

func tableColumns(t *testing.T, schemaSQL, table string) []string {
	t.Helper()
	m := regexp.MustCompile(`(?s)CREATE TABLE IF NOT EXISTS public\.` + table + ` \((.*?)\n\);`).FindStringSubmatch(schemaSQL)
	if m == nil {
		t.Fatalf("no CREATE TABLE for %s in schema.sql", table)
	}
	var cols []string
	for _, line := range strings.Split(m[1], "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "--") || strings.HasPrefix(line, "CONSTRAINT") ||
			strings.HasPrefix(line, "AND ") || strings.HasPrefix(line, "OR ") {
			continue
		}
		// A reserved word is a quoted identifier ("default", row 5.1).
		cols = append(cols, strings.Trim(strings.Fields(line)[0], `"`))
	}
	return cols
}

func pascalKey(k string) string {
	var b strings.Builder
	for _, part := range strings.Split(k, "_") {
		b.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}
	return b.String()
}

type openapiSchema struct {
	Required   []string               `yaml:"required"`
	Properties map[string]interface{} `yaml:"properties"`
}

func TestIPAMContract_SchemasMatchTablesAndEngine(t *testing.T) {
	sqlText := repoFile(t, "scripts", "database", "schema.sql")
	var spec struct {
		Paths      map[string]interface{} `yaml:"paths"`
		Components struct {
			Schemas map[string]openapiSchema `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal([]byte(repoFile(t, "api", "openapi", "inventory-service.openapi.yaml")), &spec); err != nil {
		t.Fatal(err)
	}
	objs := services.IPAMObjects()
	if len(objs) != 13 {
		t.Fatalf("engine serves %d IPAM objects, want 13", len(objs))
	}
	keys := func(m map[string]interface{}) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	for _, o := range objs {
		name := pascalKey(o.Kind)
		read, ok := spec.Components.Schemas[name]
		if !ok {
			t.Errorf("no OpenAPI schema %s for %s", name, o.Table)
			continue
		}
		cols := tableColumns(t, sqlText, o.Table)
		want := slices.Clone(cols)
		// Computed members some reads add (list joins), optional in the schema.
		switch o.Table {
		case "prefixes":
			want = append(want, "utilization", "child_count", "ip_count")
		case "vlans":
			want = append(want, "prefixes")
		case "ip_addresses":
			want = append(want, "asset")
		}
		slices.Sort(want)
		if got := keys(read.Properties); !slices.Equal(got, want) {
			t.Errorf("%s properties %v\n  != %s columns %v", name, got, o.Table, want)
		}
		req := slices.Clone(read.Required)
		slices.Sort(req)
		slices.Sort(cols)
		if !slices.Equal(req, cols) {
			t.Errorf("%s.required %v != every column %v (to_jsonb emits all of them)", name, req, cols)
		}
		writable := slices.Clone(o.Writable)
		slices.Sort(writable)
		for _, in := range []string{name + "CreateInput", name + "UpdateInput"} {
			s, ok := spec.Components.Schemas[in]
			if !ok {
				t.Errorf("no OpenAPI schema %s", in)
				continue
			}
			if got := keys(s.Properties); !slices.Equal(got, writable) {
				t.Errorf("%s properties %v\n  != the engine's writable columns %v", in, got, writable)
			}
		}
		creq := slices.Clone(spec.Components.Schemas[name+"CreateInput"].Required)
		oreq := slices.Clone(o.Required)
		slices.Sort(creq)
		slices.Sort(oreq)
		if !slices.Equal(creq, oreq) {
			t.Errorf("%sCreateInput.required %v != engine %v", name, creq, oreq)
		}
		for _, p := range []string{"/ipam/" + o.Route, "/ipam/" + o.Route + "/{id}"} {
			if _, ok := spec.Paths[p]; !ok {
				t.Errorf("OpenAPI has no path %s", p)
			}
		}
	}
	for _, p := range []string{"/ipam/prefixes/tree", "/ipam/find"} {
		if _, ok := spec.Paths[p]; !ok {
			t.Errorf("OpenAPI has no path %s", p)
		}
	}
}
