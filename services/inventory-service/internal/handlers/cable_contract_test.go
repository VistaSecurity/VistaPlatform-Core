package handlers

// The cable contract (DCIM BUILD_PLAN row 3.2): the Cable schema is the
// cables table's column list plus the two named ends, and the create/update
// inputs are the engine's writable columns plus the two ends. A column added
// to the table, the spec or the OpenAPI without the others goes red here.

import (
	"slices"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

func TestCableContract_SchemaMatchesTableAndEngine(t *testing.T) {
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
	o := services.CableObject()
	cols := append(tableColumns(t, sqlText, o.Table), "a_terminations", "b_terminations")
	slices.Sort(cols)
	read := spec.Components.Schemas["Cable"]
	if got := keys(read.Properties); !slices.Equal(got, cols) {
		t.Errorf("Cable properties %v\n  != cables columns + ends %v", got, cols)
	}
	req := slices.Clone(read.Required)
	slices.Sort(req)
	if !slices.Equal(req, cols) {
		t.Errorf("Cable.required %v != %v", req, cols)
	}
	writable := append(slices.Clone(o.Writable), "a_terminations", "b_terminations")
	slices.Sort(writable)
	for _, in := range []string{"CableCreateInput", "CableUpdateInput"} {
		if got := keys(spec.Components.Schemas[in].Properties); !slices.Equal(got, writable) {
			t.Errorf("%s properties %v\n  != writable columns + ends %v", in, got, writable)
		}
	}
	for _, p := range []string{"/dcim/cables", "/dcim/cables/{id}", "/dcim/interfaces/{id}/trace", "/dcim/front-ports/{id}/trace",
		"/dcim/rear-ports/{id}/trace", "/dcim/console-ports/{id}/trace", "/dcim/console-server-ports/{id}/trace",
		"/dcim/circuit-terminations/{id}/trace", "/dcim/assets/{id}/interface-posture"} {
		if _, ok := spec.Paths[p]; !ok {
			t.Errorf("OpenAPI has no path %s", p)
		}
	}
}
