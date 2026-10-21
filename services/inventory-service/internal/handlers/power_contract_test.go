package handlers

// The power objects' contract (DCIM BUILD_PLAN row 6.1), the rack objects'
// test over power panels and feeds. As for IPAM and the device catalogue, the engine returns each row as Postgres serialises it, so
// the API shape IS the table: every OpenAPI object schema is held to its
// table's column list in schema.sql (plus the list rows' summaries), and every
// create/update input schema to the engine's writable columns. A column added
// to one of table, spec or engine without the other two goes red here.

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

func TestPowerContract_SchemasMatchTablesAndEngine(t *testing.T) {
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
	objs := services.PowerObjects()
	if len(objs) != 2 {
		t.Fatalf("engine serves %d power objects, want 2", len(objs))
	}
	listExtras := map[string][]string{
		"power_panels": {"site", "location", "feed_count"},
		"power_feeds":  {"power_panel", "rack", "connected_endpoint"},
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
		want := append(slices.Clone(cols), listExtras[o.Table]...)
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
	for _, p := range []string{"/dcim/assets/{id}/power", "/dcim/power-ports/{id}/trace", "/dcim/power-outlets/{id}/trace", "/dcim/power-feeds/{id}/trace"} {
		if _, ok := spec.Paths[p]; !ok {
			t.Errorf("OpenAPI has no path %s", p)
		}
	}
}

// The rack power budget (row 6.2) is a Go struct, not a table: every schema of
// GET /dcim/racks/{id}/power is held to its struct's JSON names, and each
// property the struct always emits is required.
//
// Mutation: add a field to services.RackPowerFeed without the spec → red.
func TestPowerContract_RackPowerBudgetMatchesTheStructs(t *testing.T) {
	var spec struct {
		Paths      map[string]interface{} `yaml:"paths"`
		Components struct {
			Schemas map[string]openapiSchema `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal([]byte(repoFile(t, "api", "openapi", "inventory-service.openapi.yaml")), &spec); err != nil {
		t.Fatal(err)
	}
	if _, ok := spec.Paths["/dcim/racks/{id}/power"]; !ok {
		t.Error("OpenAPI has no path /dcim/racks/{id}/power")
	}
	for name, typ := range map[string]reflect.Type{
		"RackPowerBudget": reflect.TypeOf(services.RackPowerBudget{}),
		"RackPowerFeed":   reflect.TypeOf(services.RackPowerFeed{}),
		"RackPowerLeg":    reflect.TypeOf(services.RackPowerLeg{}),
		"RackPowerDevice": reflect.TypeOf(services.RackPowerDevice{}),
	} {
		var fields []string
		for i := 0; i < typ.NumField(); i++ {
			fields = append(fields, strings.Split(typ.Field(i).Tag.Get("json"), ",")[0])
		}
		slices.Sort(fields)
		s, ok := spec.Components.Schemas[name]
		if !ok {
			t.Errorf("no OpenAPI schema %s", name)
			continue
		}
		var props []string
		for k := range s.Properties {
			props = append(props, k)
		}
		slices.Sort(props)
		req := slices.Clone(s.Required)
		slices.Sort(req)
		if !slices.Equal(props, fields) || !slices.Equal(req, fields) {
			t.Errorf("%s: properties %v, required %v != the struct's %v", name, props, req, fields)
		}
	}
}
