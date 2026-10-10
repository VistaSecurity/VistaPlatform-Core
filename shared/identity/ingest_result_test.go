package identity

import "testing"

// EvidenceHeld is what tells a caller across the sightings route not to treat
// the run as materialized (platform ADR-0003 D2); an acknowledgement that drops
// it reports held evidence as an ordinary link.
func TestIngestResult_CarriesEvidenceHeld(t *testing.T) {
	res := Resolution{Outcome: OutcomeSupporting, Asset: AssetRef{TenantID: "t", ID: "a"}, ObservationID: "o", EvidenceHeld: true}
	if got := res.IngestResult(); !got.EvidenceHeld || got.AssetID != "a" || got.ObservationID != "o" {
		t.Fatalf("IngestResult = %+v, want EvidenceHeld carried", got)
	}
	if got := (Resolution{Outcome: OutcomeMatched}).IngestResult(); got.EvidenceHeld {
		t.Fatalf("IngestResult = %+v, want EvidenceHeld false for a match", got)
	}
}
