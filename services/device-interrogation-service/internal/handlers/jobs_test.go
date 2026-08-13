package handlers

import (
	"testing"

	"github.com/google/uuid"
)

// TestAssetsDiscoveredFromResults_PrefersProcessingMaterialized pins the
// priority order added for H-8: when the ResultProcessor's honest
// "processing.materialized" count is present it wins over the executor's own
// metadata.assets_count/devices_count, because the latter only describes what
// the executor claims to have sent, not what actually landed.
func TestAssetsDiscoveredFromResults_PrefersProcessingMaterialized(t *testing.T) {
	resultsJSON := `{
		"metadata": {"assets_count": 0, "devices_count": 5},
		"processing": {"materialized": 3}
	}`
	got := assetsDiscoveredFromResults(resultsJSON)
	if got == nil || *got != 3 {
		t.Fatalf("expected materialized count 3, got %v", got)
	}
}

// TestAssetsDiscoveredFromResults_FallsBackToMetadata covers execution paths
// that never run ResultProcessor (no "processing" key at all) — the direct
// in-service cloud discovery handler, prior to any pipeline step.
func TestAssetsDiscoveredFromResults_FallsBackToMetadata(t *testing.T) {
	cases := []struct {
		name string
		json string
		want int
	}{
		{"assets_count preferred over devices_count", `{"metadata":{"assets_count":2,"devices_count":9}}`, 2},
		{"devices_count used when assets_count absent", `{"metadata":{"devices_count":4}}`, 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := assetsDiscoveredFromResults(tc.json)
			if got == nil || *got != tc.want {
				t.Fatalf("expected %d, got %v", tc.want, got)
			}
		})
	}
}

// TestAssetsDiscoveredFromResults_NoData covers the "—" case: a job whose
// results carry neither a processing summary nor metadata counts (e.g. the
// in-cluster device-interrogation path before PR's honest counts, or an
// unparseable/empty payload) legitimately has nothing to report.
func TestAssetsDiscoveredFromResults_NoData(t *testing.T) {
	cases := []string{
		"",
		"{}",
		`{"metadata":{"device_id":"x"}}`,
		`not json`,
	}
	for _, c := range cases {
		if got := assetsDiscoveredFromResults(c); got != nil {
			t.Fatalf("expected nil for %q, got %v", c, *got)
		}
	}
}

// TestAssetsDiscoveredFromResults_ZeroIsHonest ensures a genuine zero
// (materialized: 0, e.g. an interrogation that ran and found nothing) is
// reported as 0, not treated as "absent" and rendered as "—". Zero and absent
// are different claims — the whole point of H-8.
func TestAssetsDiscoveredFromResults_ZeroIsHonest(t *testing.T) {
	got := assetsDiscoveredFromResults(`{"processing":{"materialized":0}}`)
	if got == nil || *got != 0 {
		t.Fatalf("expected honest zero, got %v", got)
	}
}

// TestExecutorLabel pins M-9's attribution rule: a nil agent_id means the
// in-cluster platform agent ran the job (there is no device_agents row to
// name), a non-nil agent_id prefers the joined agent's name, and falls back to
// a generic label only when the name itself is empty.
func TestExecutorLabel(t *testing.T) {
	agentID := uuid.New()
	name := "devicewin1"
	empty := ""

	cases := []struct {
		name      string
		agentID   *uuid.UUID
		agentName *string
		want      string
	}{
		{"no agent = platform agent", nil, nil, "Platform Agent"},
		{"named device agent", &agentID, &name, "devicewin1"},
		{"agent with no name", &agentID, nil, "Device Agent"},
		{"agent with empty name", &agentID, &empty, "Device Agent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := executorLabel(tc.agentID, tc.agentName); got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}
