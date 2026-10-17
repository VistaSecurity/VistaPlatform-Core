package handlers

// The device catalogue contract (DCIM BUILD_PLAN row 2.2). As for IPAM, the
// engine returns each row as Postgres serialises it, so the API shape IS the
// table: every OpenAPI object schema is held to its table's column list in
// schema.sql, and every create/update input schema to the engine's writable
// columns (minus the template parent ids, which the path sets). A column added
// to one of table, spec or engine without the other two goes red here.

import (
	"slices"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

func TestCatalogueContract_SchemasMatchTablesAndEngine(t *testing.T) {
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
	objs := services.CatalogueObjects()
	if len(objs) != 5+9 {
		t.Fatalf("engine serves %d catalogue objects, want 5 objects + 9 template kinds", len(objs))
	}
	keys := func(m map[string]interface{}) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	isTemplate := func(route string) bool { return slices.Contains(services.DeviceTypeTemplateRoutes(), route) }
	for _, o := range objs {
		name := pascalKey(o.Kind)
		read, ok := spec.Components.Schemas[name]
		if !ok {
			t.Errorf("no OpenAPI schema %s for %s", name, o.Table)
			continue
		}
		cols := tableColumns(t, sqlText, o.Table)
		want := slices.Clone(cols)
		if o.Table == "device_types" {
			want = append(want, "manufacturer", "interface_template_count") // list rows only
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
		writable := slices.DeleteFunc(slices.Clone(o.Writable), func(c string) bool {
			return isTemplate(o.Route) && (c == "device_type_id" || c == "module_type_id")
		})
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
		var paths []string
		if isTemplate(o.Route) {
			paths = append(paths, "/dcim/device-types/{id}/"+o.Route, "/dcim/device-types/{id}/"+o.Route+"/{template_id}")
			if slices.Contains(services.ModuleTypeTemplateRoutes(), o.Route) {
				paths = append(paths, "/dcim/module-types/{id}/"+o.Route, "/dcim/module-types/{id}/"+o.Route+"/{template_id}")
			}
		} else {
			paths = append(paths, "/dcim/"+o.Route, "/dcim/"+o.Route+"/{id}")
		}
		for _, p := range paths {
			if _, ok := spec.Paths[p]; !ok {
				t.Errorf("OpenAPI has no path %s", p)
			}
		}
	}
	for _, p := range []string{"/dcim/assets/{id}/hardware", "/dcim/assets/{id}/device-type"} {
		if _, ok := spec.Paths[p]; !ok {
			t.Errorf("OpenAPI has no path %s", p)
		}
	}
}
