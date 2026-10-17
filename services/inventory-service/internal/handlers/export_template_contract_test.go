package handlers

// The export-template contract (DCIM BUILD_PLAN row 5.5): the OpenAPI schema is
// held to the table's column list and the create/update inputs to the engine's
// writable columns.

import (
	"slices"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

func TestExportTemplateContract_SchemasMatchTableAndEngine(t *testing.T) {
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
	keys := func(m map[string]interface{}) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	objs := services.ExportTemplateObjects()
	if len(objs) != 1 {
		t.Fatalf("expected 1 export-template object, got %d", len(objs))
	}
	o := objs[0]
	name := pascalKey(o.Kind)
	read, ok := spec.Components.Schemas[name]
	if !ok {
		t.Fatalf("no OpenAPI schema %s", name)
	}
	want := slices.Clone(tableColumns(t, sqlText, o.Table))
	slices.Sort(want)
	if got := keys(read.Properties); !slices.Equal(got, want) {
		t.Errorf("%s properties %v\n  != %s columns %v", name, got, o.Table, want)
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
	for _, p := range []string{"/dcim/export-templates", "/dcim/export-templates/{id}", "/dcim/export/preview"} {
		if _, ok := spec.Paths[p]; !ok {
			t.Errorf("OpenAPI has no path %s", p)
		}
	}
}
