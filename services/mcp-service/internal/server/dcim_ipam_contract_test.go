package server

// Contract test for the interface / IPAM / Business Unit read tools (DCIM
// BUILD_PLAN row 1.10).
//
// Each tool is called through the REAL MCP handler and the request it makes of
// inventory-service is checked against the REAL inventory-service OpenAPI
// document: the path must be a documented route with a GET operation, every
// query parameter the tool sent must be declared by that operation, every
// required parameter must have been sent, enumerated values must be members of
// the enum, and the operation must document a 200. A tool whose call path
// drifts from the spec (a renamed filter, a moved route) goes red here — which
// is the only thing standing between a tool and an agent receiving a silent
// "filter ignored" answer.

import (
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

const inventorySpecPath = "../../../../api/openapi/inventory-service.openapi.yaml"
const inventorySpecBase = "/api/v2/inventory-service"

type specDoc map[string]any

func loadInventorySpec(t *testing.T) specDoc {
	t.Helper()
	raw, err := os.ReadFile(inventorySpecPath)
	if err != nil {
		t.Fatalf("read the inventory-service OpenAPI document: %v", err)
	}
	var d specDoc
	if err := yaml.Unmarshal(raw, &d); err != nil {
		t.Fatalf("parse the inventory-service OpenAPI document: %v", err)
	}
	return d
}

func asMap(v any) map[string]any { m, _ := v.(map[string]any); return m }
func asList(v any) []any         { l, _ := v.([]any); return l }

// resolve follows a local $ref.
func (d specDoc) resolve(v any) map[string]any {
	m := asMap(v)
	for {
		ref, ok := m["$ref"].(string)
		if !ok {
			return m
		}
		var cur any = map[string]any(d)
		for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			cur = asMap(cur)[part]
		}
		m = asMap(cur)
	}
}

// operation finds the GET operation for a concrete request path: an exact
// literal route wins over a templated one (/ipam/prefixes/tree over
// /ipam/prefixes/{id}).
func (d specDoc) operation(path string) (tmpl string, op, pathItem map[string]any) {
	paths := asMap(d["paths"])
	if item, ok := paths[path]; ok {
		return path, asMap(asMap(item)["get"]), asMap(item)
	}
	segs := strings.Split(path, "/")
	for tmpl, item := range paths {
		ts := strings.Split(tmpl, "/")
		if len(ts) != len(segs) {
			continue
		}
		match := true
		for i := range ts {
			wild := strings.HasPrefix(ts[i], "{") && strings.HasSuffix(ts[i], "}")
			if !wild && ts[i] != segs[i] {
				match = false
				break
			}
		}
		if match {
			return tmpl, asMap(asMap(item)["get"]), asMap(item)
		}
	}
	return "", nil, nil
}

func TestDcimIPAMToolsMatchInventoryOpenAPI(t *testing.T) {
	spec := loadInventorySpec(t)
	specForSchemas = spec
	f := newFixture(t)

	const (
		asset = "11111111-1111-4111-8111-111111111111"
		other = "22222222-2222-4222-8222-222222222222"
	)
	cases := []struct {
		tool string
		args map[string]any
		path string // the template the tool must hit
		sent []string
	}{
		{"vistaplatform_list_interfaces", map[string]any{"asset_id": asset, "name": "Gi0/1", "mac_address": "00:11:22:33:44:55", "type": "1000base-t", "enabled": true, "q": "uplink", "limit": 10, "offset": 20},
			"/dcim/interfaces", []string{"asset_id", "name", "mac_address", "type", "enabled", "q", "limit", "offset"}},
		{"vistaplatform_get_asset_interfaces", map[string]any{"asset_id": asset, "q": "lag", "limit": 5},
			"/dcim/assets/{id}/interfaces", []string{"q", "limit"}},
		{"vistaplatform_list_prefixes", map[string]any{"vrf_id": "global", "parent": "10.0.0.0/8", "contains": "10.1.2.3", "status": "active", "business_unit_id": other, "q": "lab", "limit": 5},
			"/ipam/prefixes", []string{"vrf_id", "within", "contains", "status", "business_unit_id", "q", "limit"}},
		{"vistaplatform_get_prefix", map[string]any{"prefix_id": other, "available_limit": 5},
			"/ipam/prefixes/{id}", []string{"limit"}},
		{"vistaplatform_list_ip_addresses", map[string]any{"parent": "10.0.0.0/24", "vrf_id": other, "assigned_interface_id": asset, "status": "active", "dns_name": "a.example", "q": "x"},
			"/ipam/ip-addresses", []string{"parent", "vrf_id", "assigned_kind", "assigned_id", "status", "dns_name", "q", "limit"}},
		{"vistaplatform_find_ip", map[string]any{"address": "10.1.2.3", "vrf": "global"},
			"/ipam/find", []string{"address", "vrf"}},
		{"vistaplatform_list_vlans", map[string]any{"group_id": asset, "site_id": other, "vid": 100, "status": "active", "q": "mgmt"},
			"/ipam/vlans", []string{"group_id", "site_id", "vid", "status", "q", "limit"}},
		{"vistaplatform_list_business_units", map[string]any{},
			"/dcim/business-units", nil},
		{"vistaplatform_get_object_changes", map[string]any{"kind": "prefix", "id": other, "since": "2026-10-01T00:00:00Z"},
			"/dcim/changes", []string{"object_kind", "object_id", "since", "limit"}},
	}

	for _, c := range cases {
		t.Run(c.tool, func(t *testing.T) {
			res := callTool(t, f, f.validPAT, c.tool, c.args)
			if isErr, _ := res["isError"].(bool); isErr {
				t.Fatalf("%s returned an error against the fake: %v", c.tool, res)
			}
			u := f.last(t)
			if !strings.HasPrefix(u.Path, inventorySpecBase) {
				t.Fatalf("%s called %q, outside %s", c.tool, u.Path, inventorySpecBase)
			}
			route := strings.TrimPrefix(u.Path, inventorySpecBase)
			tmpl, op, item := spec.operation(route)
			if op == nil {
				t.Fatalf("%s calls GET %s, which the OpenAPI document does not define", c.tool, route)
			}
			if tmpl != c.path {
				t.Fatalf("%s hit %s, want the route %s", c.tool, tmpl, c.path)
			}
			if asMap(op["responses"])["200"] == nil {
				t.Errorf("GET %s documents no 200", tmpl)
			}

			declared := map[string]map[string]any{}
			for _, plist := range [][]any{asList(item["parameters"]), asList(op["parameters"])} {
				for _, p := range plist {
					pm := spec.resolve(p)
					if pm["in"] == "query" {
						declared[pm["name"].(string)] = pm
					}
				}
			}
			q := u.Query()
			assertSent(t, c.tool, q, declared)
			for _, k := range c.sent {
				if q.Get(k) == "" {
					t.Errorf("%s did not send %q; sent %v", c.tool, k, q)
				}
			}
		})
	}
}

// assertSent checks a request's query against an operation's declared parameters.
func assertSent(t *testing.T, tool string, q url.Values, declared map[string]map[string]any) {
	t.Helper()
	for k, vs := range q {
		p, ok := declared[k]
		if !ok {
			t.Errorf("%s sent query parameter %q, which the operation does not declare", tool, k)
			continue
		}
		schema := resolveSchema(p["schema"])
		if enum := asList(schema["enum"]); len(enum) > 0 {
			found := false
			for _, e := range enum {
				if e == vs[0] {
					found = true
				}
			}
			if !found {
				t.Errorf("%s sent %s=%q, not in the documented enum %v", tool, k, vs[0], enum)
			}
		}
	}
	for name, p := range declared {
		if req, _ := p["required"].(bool); req && q.Get(name) == "" {
			t.Errorf("%s did not send the required parameter %q", tool, name)
		}
	}
}

var specForSchemas specDoc

func resolveSchema(v any) map[string]any {
	if specForSchemas == nil {
		return asMap(v)
	}
	return specForSchemas.resolve(v)
}
