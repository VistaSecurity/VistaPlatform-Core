package handlers

// The custom-field contract (DCIM BUILD_PLAN row 5.1). As for IPAM and the device
// catalogue, the engine returns each row as Postgres serialises it, so the API
// shape IS the table: every OpenAPI object schema is held to its table's column
// list in schema.sql (plus the list-only extras), and every create/update input
// schema to the engine's writable columns. A column added to one of table,
// spec or engine without the other two goes red here.

import (
	"slices"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

func TestCustomFieldsContract_SchemasMatchTablesAndEngine(t *testing.T) {
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
	objs := services.CustomFieldObjects()
	if len(objs) != 2 {
		t.Fatalf("engine serves %d custom-field objects, want 2", len(objs))
	}
	keys := func(m map[string]interface{}) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	listOnly := map[string][]string{}
	for _, o := range objs {
		name := pascalKey(o.Kind)
		read, ok := spec.Components.Schemas[name]
		if !ok {
			t.Errorf("no OpenAPI schema %s for %s", name, o.Table)
			continue
		}
		cols := tableColumns(t, sqlText, o.Table)
		want := append(slices.Clone(cols), listOnly[o.Table]...)
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
		for _, p := range []string{"/dcim/" + o.Route, "/dcim/" + o.Route + "/{id}"} {
			if _, ok := spec.Paths[p]; !ok {
				t.Errorf("OpenAPI has no path %s", p)
			}
		}
	}
}
