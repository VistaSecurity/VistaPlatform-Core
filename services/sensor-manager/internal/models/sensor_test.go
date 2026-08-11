package models

import "testing"

// IsAllowedReportingInterval is the validation source of truth for the
// operator-controllable reporting interval — the API rejects anything
// outside this set and the frontend dropdown renders the same list.
func TestIsAllowedReportingInterval(t *testing.T) {
	// Every advertised preset must be accepted.
	for _, sec := range AllowedReportingIntervals {
		if !IsAllowedReportingInterval(sec) {
			t.Errorf("preset %d should be allowed", sec)
		}
	}

	// The expected menu, pinned so an accidental edit to the slice is caught.
	want := []int{30, 60, 300, 900, 1800, 3600, 7200, 14400, 28800, 43200, 86400}
	if len(AllowedReportingIntervals) != len(want) {
		t.Fatalf("preset count changed: got %d, want %d", len(AllowedReportingIntervals), len(want))
	}
	for i, v := range want {
		if AllowedReportingIntervals[i] != v {
			t.Errorf("preset[%d] = %d, want %d", i, AllowedReportingIntervals[i], v)
		}
	}

	// Non-presets (including off-by-one, zero, negative, and absurd values) must
	// be rejected.
	for _, sec := range []int{0, -1, 31, 45, 59, 100, 600, 3601, 90000} {
		if IsAllowedReportingInterval(sec) {
			t.Errorf("value %d should be rejected", sec)
		}
	}
}
