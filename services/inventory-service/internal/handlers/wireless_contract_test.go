package handlers

// The wireless contract (DCIM BUILD_PLAN row 4.4), same shape as the IPAM one:
// every OpenAPI object schema equals its table's columns (plus the list-read
// extras), every input schema equals the engine's writable columns, and no
// schema anywhere can carry a pre-shared key.

import (
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

func TestWirelessContract_SchemasMatchTablesAndEngine(t *testing.T) {
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
	objs := services.WirelessObjects()
	if len(objs) != 3 {
		t.Fatalf("engine serves %d wireless objects, want 3", len(objs))
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
		switch o.Table {
		case "wireless_lans":
			want = append(want, "algorithm_code", "algorithm_strength", "algorithm_risk_score", "interface_count")
		case "wireless_links":
			want = append(want, "algorithm_code", "algorithm_strength", "algorithm_risk_score",
				"interface_a_name", "interface_a_asset_id", "interface_b_name", "interface_b_asset_id")
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
		for _, p := range []string{"/wireless/" + o.Route, "/wireless/" + o.Route + "/{id}"} {
			if _, ok := spec.Paths[p]; !ok {
				t.Errorf("OpenAPI has no path %s", p)
			}
		}
	}
}

// A pre-shared key is never a column, a field or a parameter of the wireless
// objects (collect posture, never key material).
func TestWirelessContract_NoKeyMaterialColumns(t *testing.T) {
	sqlText := repoFile(t, "scripts", "database", "schema.sql")
	for _, table := range []string{"wireless_lan_groups", "wireless_lans", "wireless_links"} {
		for _, c := range tableColumns(t, sqlText, table) {
			l := strings.ToLower(c)
			if strings.Contains(l, "psk") && l != "auth_psk_present" || strings.Contains(l, "passphrase") || strings.Contains(l, "secret") || l == "key" || strings.HasSuffix(l, "_key") {
				t.Errorf("%s.%s looks like key material", table, c)
			}
		}
	}
	for _, o := range services.WirelessObjects() {
		for _, w := range o.Writable {
			l := strings.ToLower(w)
			if strings.Contains(l, "passphrase") || strings.Contains(l, "secret") || (strings.Contains(l, "psk") && l != "auth_psk_present") {
				t.Errorf("%s accepts %q", o.Route, w)
			}
		}
	}
}
