package scoring

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/healthbands"
	"gopkg.in/yaml.v3"
)

func TestContract_HealthRatingVocabulary(t *testing.T) {
	raw, err := os.ReadFile("../../../../api/openapi/tenant-health-service.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Components struct {
			Schemas map[string]struct {
				Enum       []string `yaml:"enum"`
				Properties map[string]struct {
					Ref string `yaml:"$ref"`
				} `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	enum := spec.Components.Schemas["TenantHealthStatus"].Enum
	want := []string{healthbands.Unknown, "critical"} // explicit historical compatibility only
	for _, b := range healthbands.Definitions() {
		want = append(want, string(b.Value))
	}
	slices.Sort(enum)
	slices.Sort(want)
	if !slices.Equal(enum, want) {
		t.Fatalf("health status contract=%v want %v", enum, want)
	}
	for name, schema := range spec.Components.Schemas {
		if field, ok := schema.Properties["health_status"]; ok && field.Ref != "#/components/schemas/TenantHealthStatus" {
			t.Fatalf("%s.health_status bypasses canonical contract", name)
		}
	}
	if spec.Components.Schemas["HealthDataPoint"].Properties["status"].Ref != "#/components/schemas/TenantHealthStatus" {
		t.Fatal("history status bypasses contract")
	}
	for i := 0; i <= 10; i++ {
		metrics := measuredMetrics()
		metrics.ComplianceScore = float64(i * 10)
		response := NewHealthScorer().CalculateHealthScore(metrics)
		body, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		var wire struct {
			Status string `json:"health_status"`
		}
		if err := json.Unmarshal(body, &wire); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(enum, wire.Status) || wire.Status == "critical" {
			t.Fatalf("new assessment violates contract: %s", body)
		}
	}
}
