package services

import "testing"

// TestProcessingLog_ZeroAssetPayloadIsNotACleanSuccess pins the honesty rule the
// first live fleet data broke: an interrogation that genuinely found 12 devices
// persisted `assets_received: 0, findings_created: 0, fully_materialized: true`
// because a payload with no assets runs no steps and therefore fails none.
//
// When the discovery job already holds findings, the empty payload is proof that
// results were materialized somewhere this processor could not see, and the
// summary must not claim a clean run.
func TestProcessingLog_ZeroAssetPayloadIsNotACleanSuccess(t *testing.T) {
	p := &ProcessingLog{AssetsReceived: 0, DiscoveryJobID: "job-1", ExistingFindings: 12}

	s := p.Summary()
	if s["fully_materialized"] != false {
		t.Errorf("fully_materialized = %v, want false: a zero-asset payload against a job holding %d findings is not a clean success", s["fully_materialized"], p.ExistingFindings)
	}
	// The headline must describe reality, not the empty payload.
	if s["materialized"] != 12 {
		t.Errorf("materialized = %v, want 12 (findings already on the discovery job)", s["materialized"])
	}
	if s["existing_findings"] != 12 {
		t.Errorf("existing_findings = %v, want 12", s["existing_findings"])
	}
	if s["assets_received"] != 0 {
		t.Errorf("assets_received = %v, want 0 — the payload count stays honest too", s["assets_received"])
	}
}

// TestProcessingLog_EmptyRunStaysClean guards the opposite polarity: a job that
// genuinely discovered nothing has nothing hiding behind it, so it must still
// report a clean success. Without this the rule above would flag every empty
// cloud sweep as a problem.
func TestProcessingLog_EmptyRunStaysClean(t *testing.T) {
	p := &ProcessingLog{AssetsReceived: 0, DiscoveryJobID: "job-1"}

	s := p.Summary()
	if s["fully_materialized"] != true {
		t.Errorf("fully_materialized = %v, want true for a genuinely empty run", s["fully_materialized"])
	}
	if s["materialized"] != 0 {
		t.Errorf("materialized = %v, want 0", s["materialized"])
	}
}

// TestProcessingLog_NormalRunUnchanged pins that the ordinary agent path — a
// payload of assets, all materialized here — keeps its previous summary.
func TestProcessingLog_NormalRunUnchanged(t *testing.T) {
	p := &ProcessingLog{AssetsReceived: 2, DiscoveryJobID: "job-1"}
	p.ok("a.example.net", StageDiscoveryTarget)
	p.ok("a.example.net", StageDiscoveryFinding)
	p.ok("b.example.net", StageDiscoveryTarget)
	p.ok("b.example.net", StageDiscoveryFinding)

	s := p.Summary()
	if s["materialized"] != 2 {
		t.Errorf("materialized = %v, want 2", s["materialized"])
	}
	if s["fully_materialized"] != true {
		t.Errorf("fully_materialized = %v, want true", s["fully_materialized"])
	}
}

// TestProcessingLog_FailedStepIsNeverFullyMaterialized keeps the original
// failure signal intact — a failed step at any stage sinks the flag regardless
// of what else is true.
func TestProcessingLog_FailedStepIsNeverFullyMaterialized(t *testing.T) {
	for _, stage := range []string{StageDiscoveryTarget, StageDiscoveryFinding, StageSensorDiscovery} {
		p := &ProcessingLog{AssetsReceived: 1, DiscoveryJobID: "job-1"}
		p.ok("a.example.net", StageDiscoveryTarget)
		p.ok("a.example.net", StageDiscoveryFinding)
		p.fail("a.example.net", stage, errFake{})

		if s := p.Summary(); s["fully_materialized"] != false {
			t.Errorf("stage %s: fully_materialized = %v, want false", stage, s["fully_materialized"])
		}
	}
}

type errFake struct{}

func (errFake) Error() string { return "boom" }
