package handlers

import "testing"

func TestCloudIdentityFromResultsDistinguishesRetainedEvidence(t *testing.T) {
	counts := cloudIdentityFromResults(`{"metadata":{"identity":{"assets_created":0,"assets_matched":2,"approval_pending":1,"observations_retained":3,"conflicts":1,"rejected_inputs":0}}}`)
	if counts == nil || counts.AssetsMatched != 2 || counts.ObservationsRetained != 3 || counts.ApprovalPending != 1 || counts.Conflicts != 1 {
		t.Fatalf("identity summary lost: %+v", counts)
	}
	if cloudIdentityFromResults(`{"metadata":{}}`) != nil {
		t.Fatal("legacy job fabricated identity counts")
	}
}
