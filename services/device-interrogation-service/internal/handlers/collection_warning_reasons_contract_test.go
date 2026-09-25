package handlers

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
)

// The spec's reason enum and the shared core's closed set are one list written
// twice. A reason added to the core and not to the spec would fail every
// response carrying it; one added to the spec and not the core would promise
// clients a value that is never sent. Pinned in both directions.
func TestContract_CollectionWarningReasonsMatchTheCore(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	specPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..",
		"api", "openapi", "device-interrogation-service.openapi.yaml")
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	var spec struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Enum []string `yaml:"enum"`
				} `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	specEnum := spec.Components.Schemas["JobResultCollectionWarning"].Properties["reason"].Enum
	if len(specEnum) == 0 {
		t.Fatal("JobResultCollectionWarning.reason has no enum in the spec; this test has stopped reading it")
	}

	var core []string
	for _, r := range di.WarningReasons() {
		core = append(core, string(r))
	}
	sort.Strings(core)
	sorted := append([]string(nil), specEnum...)
	sort.Strings(sorted)

	if len(core) != len(sorted) {
		t.Fatalf("spec reasons %v != core reasons %v", sorted, core)
	}
	for i := range core {
		if core[i] != sorted[i] {
			t.Fatalf("spec reasons %v != core reasons %v", sorted, core)
		}
	}
}
