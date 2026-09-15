package model

import (
	"strings"
	"testing"
)

// The OUI half of [FeatureSchemaID], pinned.
//
// It used to be `len(derivedOUI)` — the row COUNT — and a count cannot see the
// two edits that actually move buckets:
//
//   - A vendor RENAMED. `NamespaceOUI` hashes the vendor NAME, so
//     "Cisco Systems" → "Cisco Systems, Inc." sends every Cisco device to a
//     different bucket with the row count unmoved.
//   - A row added and another removed in the same release. Net zero rows, two
//     vendors' devices in new buckets.
//
// Either way the shipped weights file still loads and still scores, and every
// device of the affected vendor is silently classified by weights fitted to a
// bucket it is no longer in. That is precisely what the fingerprint exists to
// refuse, so it hashes the table's CONTENTS.
//
// The counterpart matters as much: an add-then-REMOVE of the same row — a
// catalogue edit reverted before release — must leave the fingerprint where it
// was, or every such round trip would force a retrain that changes nothing. A
// guard that fires on everything is the same bug as one that fires on nothing.
func TestOUIFingerprintTracksContentsNotRowCount(t *testing.T) {
	base := map[string]string{
		"001122": "Cisco Systems",
		"aabbcc": "Juniper Networks",
		"ddeeff": "Fortinet",
	}
	want := hashOUITable(base)

	t.Run("renaming one vendor moves it", func(t *testing.T) {
		renamed := cloneOUI(base)
		renamed["001122"] = "Cisco Systems, Inc."
		if got := hashOUITable(renamed); got == want {
			t.Errorf("renaming a vendor left the fingerprint at %s; every device in "+
				"that OUI now hashes to a different bucket and the old weights would "+
				"load anyway", got)
		}
	})

	t.Run("one row out, one row in, same count", func(t *testing.T) {
		swapped := cloneOUI(base)
		delete(swapped, "ddeeff")
		swapped["112233"] = "Palo Alto Networks"
		if len(swapped) != len(base) {
			t.Fatalf("the swap changed the row count (%d → %d); this case is meant to "+
				"be the one a COUNT cannot see", len(base), len(swapped))
		}
		if got := hashOUITable(swapped); got == want {
			t.Errorf("swapping one vendor for another left the fingerprint at %s", got)
		}
	})

	t.Run("adding then removing the same row changes nothing", func(t *testing.T) {
		round := cloneOUI(base)
		round["445566"] = "Arista Networks"
		if hashOUITable(round) == want {
			t.Fatalf("adding a row did not move the fingerprint; the round trip below " +
				"would then prove nothing")
		}
		delete(round, "445566")
		if got := hashOUITable(round); got != want {
			t.Errorf("add-then-remove left the fingerprint at %s, want %s — a reverted "+
				"catalogue edit must not force a retrain", got, want)
		}
	})

	t.Run("iteration order does not reach the hash", func(t *testing.T) {
		// Maps iterate in a randomised order in Go, so a hash that did not sort
		// would be a fingerprint that changed between two runs of the SAME
		// build — which would reject the shipped weights at random.
		for range 50 {
			if got := hashOUITable(cloneOUI(base)); got != want {
				t.Fatalf("hash is %s on one run and %s on another", got, want)
			}
		}
	})

	t.Run("the pair separator cannot be forged", func(t *testing.T) {
		// "ab"+"cd" and "abc"+"d" must not hash the same. A prefix is hex and a
		// vendor is a name, so neither can contain the NUL the writer inserts —
		// but the property is what makes that reasoning safe to rely on.
		a := hashOUITable(map[string]string{"ab": "cd"})
		b := hashOUITable(map[string]string{"abc": "d"})
		if a == b {
			t.Errorf("two different tables hash alike (%s); the pair separator is not "+
				"doing its job", a)
		}
	})
}

// TestFeatureSchemaIDCarriesTheOUIContentHash pins the WIRING: the hash has to
// be part of the id the weights file is validated against, not merely computed.
func TestFeatureSchemaIDCarriesTheOUIContentHash(t *testing.T) {
	deriveFromRules()
	id := FeatureSchemaID()
	want := "ouihash=" + hashOUITable(derivedOUI)
	if !strings.Contains(id, want) {
		t.Fatalf("FeatureSchemaID() = %q, which does not carry %q — the content hash "+
			"is computed and then not used, which is the same as not computing it", id, want)
	}

	// And it MOVES when the table does. Mutating the derived table directly is
	// the only way to reach this from a test: the table is compiled in, and a
	// fingerprint that does not track it is exactly the bug.
	const probe = "00005e"
	original, had := derivedOUI[probe]
	derivedOUI[probe] = "A Vendor That Is Not In The Table"
	t.Cleanup(func() {
		if had {
			derivedOUI[probe] = original
			return
		}
		delete(derivedOUI, probe)
	})
	if got := FeatureSchemaID(); got == id {
		t.Errorf("FeatureSchemaID() is %q both before and after an edit to the OUI "+
			"table; a weights file trained against the old table would still load", got)
	}
}

func cloneOUI(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
