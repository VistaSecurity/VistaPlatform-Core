package services

// The guard the family breakdown's doc comment has always claimed.
//
// `quantumSafeFamilyPrimitives` (algorithm_service.go) is an ALLOWLIST used for
// the per-family worklist; `QuantumVulnerablePrimitives` (cryptoassess) is the
// DENYLIST the per-implementation classifier uses. Two lists, two directions,
// one subject — and the comment on the allowlist says they are "kept in sync by
// TestPQC_FamilyAndImplementationViewsAgree".
//
// That test did not exist. The comment named a guard nobody had written, which
// is the same failure mode as a guard that cannot fail: it tells a reader the
// question is already answered. Written here, and mutation-checked — moving any
// member of the denylist into the allowlist fails it.

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/cryptoassess"
)

// The two views may not disagree about a primitive.
//
// A primitive in BOTH lists would mean the family worklist calls a family
// quantum-safe while the classifier counts every implementation using it as
// needing migration — the page would print "already quantum-safe: RSA" beside a
// headline that counts those same configurations as the migration backlog.
func TestPQC_FamilyAndImplementationViewsAgree(t *testing.T) {
	if len(cryptoassess.QuantumVulnerablePrimitives) == 0 {
		t.Fatal("the vulnerable denylist is empty — this test would pass vacuously")
	}
	if len(quantumSafeFamilyPrimitives) == 0 {
		t.Fatal("the family allowlist is empty — this test would pass vacuously")
	}

	for _, vulnerable := range cryptoassess.QuantumVulnerablePrimitives {
		if quantumSafeFamilyPrimitives[vulnerable] {
			t.Errorf("primitive %q is on the family QUANTUM-SAFE allowlist and on the "+
				"implementation VULNERABLE denylist at once: a family using it would be "+
				"reported safe while every implementation using it is counted as needing "+
				"migration", vulnerable)
		}
	}
}

// The slice bound into the family query must carry exactly the map's members.
//
// The map is the definition; the slice exists only because the query now decides
// per-family safety with bool_and and an aggregate cannot consult a Go map. A
// second literal list is how the two would drift.
func TestPQC_FamilySafePrimitiveSliceMatchesTheMap(t *testing.T) {
	got := quantumSafeFamilyPrimitiveSlice()
	if len(got) != len(quantumSafeFamilyPrimitives) {
		t.Fatalf("slice has %d primitives, map has %d", len(got), len(quantumSafeFamilyPrimitives))
	}
	seen := map[string]bool{}
	for _, p := range got {
		if !quantumSafeFamilyPrimitives[p] {
			t.Errorf("slice carries %q, which is not in the map", p)
		}
		if seen[p] {
			t.Errorf("slice repeats %q", p)
		}
		seen[p] = true
	}
	for p := range quantumSafeFamilyPrimitives {
		if !seen[p] {
			t.Errorf("map carries %q, which the slice omits", p)
		}
	}
	// Sorted, so the bound parameter is stable across runs and a query plan or a
	// failure message does not depend on Go's map iteration order.
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Errorf("slice is not sorted: %q before %q", got[i-1], got[i])
		}
	}
}
