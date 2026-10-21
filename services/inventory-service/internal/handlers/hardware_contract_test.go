package handlers

// The hardware contract (DCIM BUILD_PLAN row 2.4): module bays, modules,
// inventory item roles, inventory items, virtual chassis. As for the
// components, the engine returns each row as Postgres serialises it, so every
// OpenAPI object schema is held to its table's column list in schema.sql, and
// every create/update input schema to the engine's writable columns.

import (
	"slices"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

func TestHardwareContract_SchemasMatchTablesAndEngine(t *testing.T) {
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
	objs := services.HardwareObjects()
	if len(objs) != 6 {
		t.Fatalf("engine serves %d hardware kinds, want 6", len(objs))
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
		slices.Sort(cols)
		if got := keys(read.Properties); !slices.Equal(got, cols) {
			t.Errorf("%s properties %v\n  != %s columns %v", name, got, o.Table, cols)
		}
		req := slices.Clone(read.Required)
		slices.Sort(req)
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
		paths := []string{"/dcim/" + o.Route, "/dcim/" + o.Route + "/{id}"}
		if o.Route == "module-bays" || o.Route == "modules" || o.Route == "inventory-items" || o.Route == "virtual-device-contexts" {
			paths = append(paths, "/dcim/assets/{id}/"+o.Route)
		}
		for _, p := range paths {
			if _, ok := spec.Paths[p]; !ok {
				t.Errorf("OpenAPI has no path %s", p)
			}
		}
	}
}

// DCIM gap 8: the RMA case is held to rma_cases' column list and its update
// input to the engine's writable columns, like the hardware kinds above, and
// the spares actions have their paths.
//
// Mutation: drop a column from RmaCase (or add one to rma_cases without the
// schema property), or drop a writable property from RmaCaseUpdateInput → red.
func TestHardwareContract_RMACaseMatchesTableAndEngine(t *testing.T) {
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
	o := services.RMACaseObject()
	keys := func(m map[string]interface{}) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	cols := tableColumns(t, sqlText, o.Table)
	slices.Sort(cols)
	read := spec.Components.Schemas["RmaCase"]
	if got := keys(read.Properties); !slices.Equal(got, cols) {
		t.Errorf("RmaCase properties %v\n  != %s columns %v", got, o.Table, cols)
	}
	req := slices.Clone(read.Required)
	slices.Sort(req)
	if !slices.Equal(req, cols) {
		t.Errorf("RmaCase.required %v != every column %v", req, cols)
	}
	writable := slices.Clone(o.Writable)
	slices.Sort(writable)
	if got := keys(spec.Components.Schemas["RmaCaseUpdateInput"].Properties); !slices.Equal(got, writable) {
		t.Errorf("RmaCaseUpdateInput properties %v\n  != the engine's writable columns %v", got, writable)
	}
	for _, p := range []string{"/dcim/rma-cases", "/dcim/rma-cases/{id}", "/dcim/inventory-items/{id}/install",
		"/dcim/inventory-items/{id}/remove", "/dcim/inventory-items/{id}/rma"} {
		if _, ok := spec.Paths[p]; !ok {
			t.Errorf("OpenAPI has no path %s", p)
		}
	}
}
