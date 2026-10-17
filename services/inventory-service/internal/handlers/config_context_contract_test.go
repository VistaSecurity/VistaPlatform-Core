package handlers

// The config-context contract (DCIM BUILD_PLAN row 5.3): the OpenAPI schema is
// held to the table's column list and the create/update inputs to the engine's
// writable columns, as for contacts.

import (
	"slices"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

func TestConfigContextContract_SchemasMatchTableAndEngine(t *testing.T) {
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
	objs := services.ConfigContextObjects()
	if len(objs) != 1 {
		t.Fatalf("expected 1 config-context object, got %d", len(objs))
	}
	o := objs[0]
	name := pascalKey(o.Kind)
	read, ok := spec.Components.Schemas[name]
	if !ok {
		t.Fatalf("no OpenAPI schema %s", name)
	}
	cols := tableColumns(t, sqlText, o.Table)
	want := slices.Clone(cols)
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
	for _, p := range []string{"/dcim/config-contexts", "/dcim/config-contexts/{id}", "/dcim/assets/{id}/config-context"} {
		if _, ok := spec.Paths[p]; !ok {
			t.Errorf("OpenAPI has no path %s", p)
		}
	}
}
