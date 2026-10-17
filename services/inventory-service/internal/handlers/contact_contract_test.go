package handlers

// The contacts and image attachments contract (DCIM BUILD_PLAN row 2.8). As
// for the device catalogue, the engine returns each row as Postgres serialises
// it, so every OpenAPI object schema is held to its table's column list in
// schema.sql (plus the inlined `contact`/`role` on assignment list rows), and
// every create/update input schema to the engine's writable columns.

import (
	"slices"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

func TestContactContract_SchemasMatchTablesAndEngine(t *testing.T) {
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
	objs := append(services.ContactObjects(), services.ImageObjects()...)
	if len(objs) != 4 {
		t.Fatalf("expected 3 contact objects + images, got %d", len(objs))
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
		if o.Table == "contact_assignments" {
			want = append(want, "contact", "role") // list rows only
		}
		slices.Sort(want)
		if got := keys(read.Properties); !slices.Equal(got, want) {
			t.Errorf("%s properties %v\n  != %s columns %v", name, got, o.Table, want)
		}
		req := slices.Clone(read.Required)
		slices.Sort(req)
		slices.Sort(cols)
		if !slices.Equal(req, cols) {
			t.Errorf("%s.required %v != every column %v", name, req, cols)
		}
		if o.Table == "image_attachments" {
			// Upload is multipart; there is no JSON create/update input.
			for _, p := range []string{"/dcim/objects/{kind}/{id}/images", "/dcim/images", "/dcim/images/{id}", "/dcim/images/{id}/download"} {
				if _, ok := spec.Paths[p]; !ok {
					t.Errorf("OpenAPI has no path %s", p)
				}
			}
			continue
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
	for _, p := range []string{"/dcim/objects/{kind}/{id}/contacts"} {
		if _, ok := spec.Paths[p]; !ok {
			t.Errorf("OpenAPI has no path %s", p)
		}
	}
}
