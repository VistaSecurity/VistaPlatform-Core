package ladder

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
)

// TestCVSSIsTheCVSSLadder pins the default's five rungs by value. They are the
// CVSS v3.1/v4.0 qualitative severity ratings ×10, and they must equal
// models.RiskBands — which this package cannot import, so the parity assertion
// lives at the other end, in
// services/inventory-service/internal/services/query_registry_catalog_test.go.
// This half pins what that one compares against.
func TestCVSSIsTheCVSSLadder(t *testing.T) {
	want := []catalog.Band{
		{Label: "Critical", Min: 90},
		{Label: "High", Min: 70},
		{Label: "Medium", Min: 40},
		{Label: "Low", Min: 1},
		{Label: "Informational", Min: 0},
	}
	got := CVSS.Bands()
	if len(got) != len(want) {
		t.Fatalf("CVSS has %d rungs, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("rung %d: got {%s %d}, want {%s %d}",
				i, got[i].Label, got[i].Min, want[i].Label, want[i].Min)
		}
	}
}

// TestBandsIsACopy: the ladder is a package-level value, so a caller that
// sorted or truncated the returned slice in place would move every band
// predicate in the process — silently, and for everyone.
func TestBandsIsACopy(t *testing.T) {
	first := CVSS.Bands()
	first[0] = catalog.Band{Label: "Tampered", Min: -1}
	if again := CVSS.Bands()[0]; again.Label != "Critical" || again.Min != 90 {
		t.Errorf("mutating the returned slice changed the ladder: %+v", again)
	}
}

// TestFromRungsRejectsAMisorderedLadder is the mutation half of the panic.
//
// catalog.BandBounds reads rung i-1 as rung i's exclusive upper bound, so a
// ladder that does not strictly descend yields empty or overlapping intervals —
// the 60-vs-70 drift, one layer deeper. Accepting one silently would leave
// every test in the product passing against a ladder that answers wrongly.
func TestFromRungsRejectsAMisorderedLadder(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		critical, high, medium, l int
	}{
		{"equal rungs", 90, 90, 40, 1},
		{"inverted", 40, 70, 90, 1},
		{"low at zero collides with informational", 90, 70, 40, 0},
		{"negative", 90, 70, 40, -5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("a ladder that does not strictly descend must panic")
				}
				if msg, _ := r.(string); !strings.Contains(msg, "strictly descending") {
					t.Errorf("panic %q does not say what is wrong", msg)
				}
			}()
			FromRungs(tc.critical, tc.high, tc.medium, tc.l)
		})
	}
}

// TestFromRungsAcceptsANonCVSSLadder is the same guard pointed the other way.
// The RUNG VALUES are the caller's; only the labels and their order are fixed,
// and an over-strict check that only accepted 90/70/40/1 would make the
// parameter decorative.
func TestFromRungsAcceptsANonCVSSLadder(t *testing.T) {
	l := FromRungs(95, 75, 45, 5)
	if got, ok := catalog.BandAtLeast(l, "high"); !ok || got != 75 {
		t.Errorf("BandAtLeast(high) = %d,%v want 75,true", got, ok)
	}
	min, max, hasMax, ok := catalog.BandBounds(l, "medium")
	if !ok || min != 45 || max != 75 || !hasMax {
		t.Errorf("BandBounds(medium) = %d,%d,%v,%v want 45,75,true,true", min, max, hasMax, ok)
	}
	if labels := strings.Join(catalog.BandLabels(l, true), ","); labels !=
		"critical,high,medium,low,informational,"+catalog.NotAssessed {
		t.Errorf("BandLabels = %q", labels)
	}
}
