package handlers

// The rule-kind vocabulary has ONE owner, `shared/classify`, and four
// downstreams: the `rule_kind` CHECK on `classification_rules`, the matcher,
// this service's validator, and the `ClassificationRuleKind` enum in the OpenAPI
// contract. Only the last of those is in a different language, and it is the one
// that gets left behind.
//
// Not hypothetically. Workstream 2.10b added `cdp_capabilities`,
// `lldp_capability` and `mdns_service`; the spec stayed at eight while this API
// served eleven in its `kinds` field and ACCEPTED eleven on POST. Every gate was
// green, because `make api-contract` regenerates the client FROM the spec and
// checks for drift against the spec — never against the engine — and no contract
// test here validated the list response against the schema. The visible cost is a
// generated TypeScript client whose `rule_kind` union cannot express a rule the
// console offers to create.
//
// So this reads the spec's enum and compares it to the vocabulary the handlers
// actually serve, in both directions: a kind the spec is missing, and a kind the
// spec invents.

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/classificationrules"
)

func TestClassificationRuleKind_SpecMatchesTheEngine(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	specPath := filepath.Join(
		filepath.Dir(thisFile), "..", "..", "..", "..",
		"api", "openapi", "admin-service.openapi.yaml",
	)
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read spec %s: %v", specPath, err)
	}
	var doc struct {
		Components struct {
			Schemas struct {
				ClassificationRuleKind struct {
					Enum []string `yaml:"enum"`
				} `yaml:"ClassificationRuleKind"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal spec: %v", err)
	}

	inSpec := map[string]bool{}
	for _, k := range doc.Components.Schemas.ClassificationRuleKind.Enum {
		inSpec[k] = true
	}
	if len(inSpec) == 0 {
		t.Fatal("ClassificationRuleKind has no enum in the spec; this test would then prove nothing")
	}
	for _, k := range classificationrules.Kinds() {
		if !inSpec[k] {
			t.Errorf("rule kind %q is served and accepted by this API but is not in the "+
				"ClassificationRuleKind enum — a generated client cannot express a rule the "+
				"console offers to create", k)
		}
		delete(inSpec, k)
	}
	for k := range inSpec {
		t.Errorf("the spec declares rule kind %q, which the engine does not implement — a "+
			"client would offer a kind no rule can ever match on", k)
	}
}
