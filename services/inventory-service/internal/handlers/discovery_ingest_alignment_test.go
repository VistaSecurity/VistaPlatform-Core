package handlers

import "testing"

// The per-finding statuses the import response carries are read by index on the
// far side, where each index names a discovery ROW. A finding this handler could
// not parse is dropped before ingest ever sees it, so the two slices are not the
// same length — and an off-by-one here would stamp one discovery with another's
// outcome, marking a row approved because its neighbour's asset was.
func TestAlignToRequestSurvivesADroppedFinding(t *testing.T) {
	// Three were sent; the middle one was malformed, so ingest saw two.
	got := alignToRequest(3, []int{0, 2}, []string{"monitoring", "pending_approval"})
	want := []string{"monitoring", "", "pending_approval"}

	if len(got) != len(want) {
		t.Fatalf("got %d statuses for 3 findings, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("finding %d reported %q, want %q — the gap left by the finding that could not be "+
				"parsed has shifted every answer after it", i, got[i], want[i])
		}
	}
}

// An answer shorter or longer than the findings it describes must not run off
// the end of either slice.
func TestAlignToRequestIgnoresAnswersItCannotPlace(t *testing.T) {
	got := alignToRequest(2, []int{1}, []string{"monitoring", "monitoring", "monitoring"})
	if len(got) != 2 {
		t.Fatalf("got %d statuses, want 2", len(got))
	}
	if got[0] != "" || got[1] != "monitoring" {
		t.Fatalf("got %v, want [\"\" \"monitoring\"]", got)
	}
}
