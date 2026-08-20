package services

// Unit coverage for the per-source auto-approval setting: how a segment's
// stored sources map onto the discovery_auto_approval_rules `source` condition
// shared/approval evaluates, and what an unset value means.

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

func TestApprovalRuleSourceCondition(t *testing.T) {
	cases := []struct {
		name    string
		sources []string
		want    string
	}{
		{"sensor only", []string{models.AutoApproveSourceSensor}, "sensor_discoveries"},
		{"cloud only", []string{models.AutoApproveSourceCloud}, "cloud_discovery"},
		{"both", []string{models.AutoApproveSourceSensor, models.AutoApproveSourceCloud}, "all"},
		{"order does not matter", []string{models.AutoApproveSourceCloud, models.AutoApproveSourceSensor}, "all"},
		// A rule with no source at all matches everything in the evaluator, so
		// an empty list must never reach it as "no condition".
		{"empty falls back to sensor", nil, "sensor_discoveries"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := approvalRuleSourceCondition(tc.sources); got != tc.want {
				t.Fatalf("approvalRuleSourceCondition(%v) = %q, want %q", tc.sources, got, tc.want)
			}
		})
	}
}

// The upgrade default, at unit level: a segment stored before the setting
// existed reads back sensor-only, so an upgrade cannot widen a tenant's
// approval policy behind their back.
func TestAutoApproveSourcesFromMetadata_DefaultsToSensorOnly(t *testing.T) {
	for name, meta := range map[string]models.JSONB{
		"nil metadata":            nil,
		"empty metadata":          {},
		"unrelated keys only":     {"region": "us-east-1"},
		"wrong type for the key":  {models.AutoApproveSourcesKey: "cloud"},
		"empty list for the key":  {models.AutoApproveSourcesKey: []interface{}{}},
		"unknown values for key":  {models.AutoApproveSourcesKey: []interface{}{"carrier-pigeon"}},
		"cloud only, stored well": {models.AutoApproveSourcesKey: []interface{}{"cloud"}},
	} {
		t.Run(name, func(t *testing.T) {
			got := models.AutoApproveSourcesFromMetadata(meta)
			wantCloud := name == "cloud only, stored well"
			hasCloud := models.AutoApproveSourcesInclude(got, models.AutoApproveSourceCloud)
			if hasCloud != wantCloud {
				t.Fatalf("AutoApproveSourcesFromMetadata(%v) = %v; cloud coverage %v, want %v", meta, got, hasCloud, wantCloud)
			}
			if len(got) == 0 {
				t.Fatalf("AutoApproveSourcesFromMetadata(%v) returned no sources — an auto-approving segment would silently cover nothing", meta)
			}
		})
	}
}

func TestWithAutoApproveSourcesPreservesOtherKeys(t *testing.T) {
	out := withAutoApproveSources(map[string]interface{}{"region": "us-east-1"}, []string{models.AutoApproveSourceCloud})
	meta, ok := out.(models.JSONB)
	if !ok {
		t.Fatalf("withAutoApproveSources returned %T, want models.JSONB", out)
	}
	if meta["region"] != "us-east-1" {
		t.Fatalf("stamping the sources dropped an unrelated metadata key: %v", meta)
	}
	if !models.AutoApproveSourcesInclude(models.AutoApproveSourcesFromMetadata(meta), models.AutoApproveSourceCloud) {
		t.Fatalf("sources did not round-trip through metadata: %v", meta)
	}
}
