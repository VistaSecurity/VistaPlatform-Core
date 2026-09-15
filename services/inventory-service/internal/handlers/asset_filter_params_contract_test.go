package handlers

// Every filter parameter the asset list BINDS must be in the spec.
//
// `models.AssetFilters` carries ~44 `form:` tags and the spec documented four
// of them. The rest were honoured, undocumented, and — for one of them,
// `discovery_source` — honoured by the list and silently dropped by a count
// beside it. An undocumented parameter is worse than a missing one: a caller
// cannot tell a filter that works from a filter that is ignored, and neither
// can a reviewer.
//
// The list comes from the STRUCT, by reflection, so a new filter field arrives
// here as a failing assertion rather than as a parameter nobody wrote down.

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// specParameterNames returns the documented query-parameter names of one
// operation, resolving the `$ref` components the spec shares between endpoints.
func specParameterNames(t *testing.T, path, method string) map[string]bool {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	specPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..",
		"api", "openapi", "inventory-service.openapi.yaml")
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	// Decoded through `any`: a path item puts `parameters` (an array) beside its
	// operations, so a typed `map[path]map[method]…` shape fails on every path
	// that has one. The spec is data here, not a schema.
	var asAny any
	if err := yaml.Unmarshal(raw, &asAny); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	doc, _ := asAny.(map[string]any)
	paths, _ := doc["paths"].(map[string]any)
	item, _ := paths[path].(map[string]any)
	op, ok := item[method].(map[string]any)
	if !ok {
		t.Fatalf("%s %s is not in the spec", method, path)
	}
	components, _ := doc["components"].(map[string]any)
	sharedParams, _ := components["parameters"].(map[string]any)

	out := map[string]bool{}
	params, _ := op["parameters"].([]any)
	for _, raw := range params {
		p, _ := raw.(map[string]any)
		if name, _ := p["name"].(string); name != "" {
			out[name] = true
			continue
		}
		ref, _ := p["$ref"].(string)
		if ref == "" {
			continue
		}
		key := ref[strings.LastIndex(ref, "/")+1:]
		shared, _ := sharedParams[key].(map[string]any)
		if name, _ := shared["name"].(string); name != "" {
			out[name] = true
		}
	}
	return out
}

// boundFormTags walks models.AssetFilters for every `form:` tag gin will bind.
func boundFormTags() []string {
	var out []string
	seen := map[string]bool{}
	var walk func(reflect.Type)
	walk = func(t reflect.Type) {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.Anonymous && f.Type.Kind() == reflect.Struct {
				walk(f.Type)
				continue
			}
			tag := f.Tag.Get("form")
			if tag == "" || tag == "-" {
				continue
			}
			name := strings.Split(tag, ",")[0]
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	walk(reflect.TypeOf(models.AssetFilters{}))
	return out
}

func TestContract_EveryBoundAssetFilterIsDocumented(t *testing.T) {
	documented := specParameterNames(t, "/infrastructure-assets", "get")
	bound := boundFormTags()

	if len(bound) < 10 {
		t.Fatalf("only %d form tags found on AssetFilters; the reflection walk has stopped walking, "+
			"which is the one way this guard passes over nothing", len(bound))
	}

	for _, name := range bound {
		if !documented[name] {
			t.Errorf("GET /infrastructure-assets binds %q and the spec does not document it.\n"+
				"An undocumented filter is worse than a missing one: a caller cannot tell a filter "+
				"that works from one that is ignored. Add it as a deprecated parameter naming its "+
				"query-language equivalent.", name)
		}
	}

	// The other direction: a documented parameter nothing binds is a promise the
	// server does not keep.
	boundSet := map[string]bool{}
	for _, n := range bound {
		boundSet[n] = true
	}
	// Pagination and the query itself are not AssetFilters fields on every path.
	notFilters := map[string]bool{"limit": true, "offset": true, "level": true, "days": true}
	for name := range documented {
		if boundSet[name] || notFilters[name] {
			continue
		}
		t.Errorf("the spec documents %q on GET /infrastructure-assets and nothing binds it; "+
			"a documented filter that is not read is a promise the server does not keep", name)
	}
}

// TestContract_TheListDescriptionDoesNotPromiseClassKey: the prose named
// `class_key`, which is not a parameter and never was. The class filter is
// `query=class:<key>`, and it matches the whole SUBTREE under that key — a
// difference a caller has to be told about, not left to discover.
func TestContract_TheListDescriptionDoesNotPromiseClassKey(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..",
		"api", "openapi", "inventory-service.openapi.yaml"))
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	// Decoded through `any` rather than a typed struct: sibling operations put
	// arrays where this one puts a string (`tags`, `parameters`), and a typed
	// decode of the whole document fails on them.
	var asAny any
	if err := yaml.Unmarshal(raw, &asAny); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	doc, _ := asAny.(map[string]any)
	paths, _ := doc["paths"].(map[string]any)
	list, _ := paths["/infrastructure-assets"].(map[string]any)
	get, _ := list["get"].(map[string]any)
	desc, _ := get["description"].(string)
	if desc == "" {
		t.Fatal("the list operation has no description; this guard would pass over nothing")
	}
	if strings.Contains(desc, "class_key") && !strings.Contains(desc, "no `class_key` parameter") {
		t.Errorf("the description names `class_key` as if it were a parameter. It is not:\n%s", desc)
	}
	if !strings.Contains(desc, "class:<key>") {
		t.Error("the description must name the real class filter, `query=class:<key>`")
	}
}
