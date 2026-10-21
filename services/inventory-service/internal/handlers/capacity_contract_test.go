package handlers

// The capacity contract (DCIM gap 6): every JSON object the capacity route
// returns is an OpenAPI schema whose properties, and required list, are exactly
// the Go struct's json keys, nested objects included; and the path is in the
// spec. A field added to the Go type without the spec (or the reverse) goes red.

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

func jsonKeys(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		if tag := t.Field(i).Tag.Get("json"); tag != "" && tag != "-" {
			out = append(out, strings.Split(tag, ",")[0])
		}
	}
	slices.Sort(out)
	return out
}

func TestCapacityContract_SchemasMatchGoTypes(t *testing.T) {
	var spec struct {
		Paths      map[string]interface{} `yaml:"paths"`
		Components struct {
			Schemas map[string]openapiSchema `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal([]byte(repoFile(t, "api", "openapi", "inventory-service.openapi.yaml")), &spec); err != nil {
		t.Fatal(err)
	}
	if _, ok := spec.Paths["/dcim/capacity"]; !ok {
		t.Error("OpenAPI has no path /dcim/capacity")
	}
	for schema, typ := range map[string]reflect.Type{
		"CapacityReport":           reflect.TypeOf(services.CapacityReport{}),
		"CapacityRackTotals":       reflect.TypeOf(services.RackTotals{}),
		"CapacitySite":             reflect.TypeOf(services.SiteCapacity{}),
		"CapacityRack":             reflect.TypeOf(services.RackCapacity{}),
		"CapacitySwitchInterfaces": reflect.TypeOf(services.SwitchPorts{}),
		"CapacityPorts":            reflect.TypeOf(services.PortCapacity{}),
		"CapacityPrefixFill":       reflect.TypeOf(services.PrefixFill{}),
		"CapacityPrefixes":         reflect.TypeOf(services.PrefixCapacity{}),
		"CapacityCableByStatus":    reflect.TypeOf(services.CableByStatus{}),
		"CapacityPlannedCable":     reflect.TypeOf(services.PlannedCable{}),
		"CapacityCables":           reflect.TypeOf(services.CableBacklog{}),
	} {
		s, ok := spec.Components.Schemas[schema]
		if !ok {
			t.Errorf("OpenAPI has no schema %s", schema)
			continue
		}
		want := jsonKeys(typ)
		var props []string
		for k := range s.Properties {
			props = append(props, k)
		}
		slices.Sort(props)
		if !slices.Equal(props, want) {
			t.Errorf("%s properties %v != %s json keys %v", schema, props, typ.Name(), want)
		}
		req := slices.Clone(s.Required)
		slices.Sort(req)
		if !slices.Equal(req, want) {
			t.Errorf("%s.required %v != %v", schema, req, want)
		}
	}
}
