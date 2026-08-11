package services

import (
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
)

// The reconcile diff is the central correctness risk in ADR-0014: it must converge
// (idempotent), resurface violations that returned, and inactivate exactly the
// findings that no longer violate — never duplicating or losing a pair. reconcilePlan
// is pure, so these run without a database.

func set(pairs ...controlAsset) map[controlAsset]bool {
	m := make(map[controlAsset]bool, len(pairs))
	for _, p := range pairs {
		m[p] = true
	}
	return m
}

func sortPairs(in []controlAsset) []controlAsset {
	out := append([]controlAsset(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].ControlID != out[j].ControlID {
			return out[i].ControlID.String() < out[j].ControlID.String()
		}
		return out[i].AssetID.String() < out[j].AssetID.String()
	})
	return out
}

func TestReconcilePlan(t *testing.T) {
	c1, c2 := uuid.New(), uuid.New()
	a1, a2 := uuid.New(), uuid.New()
	p11 := controlAsset{c1, a1}
	p12 := controlAsset{c1, a2}
	p21 := controlAsset{c2, a1}

	t.Run("new violation activates, stale inactivates", func(t *testing.T) {
		stored := set(p11, p21) // p11 still violates, p21 no longer does
		now := set(p11, p12)    // p11 persists, p12 is new
		act, inact := reconcilePlan(stored, now)
		if got := sortPairs(act); len(got) != 2 || got[0] == got[1] {
			t.Fatalf("expected 2 distinct activations, got %v", got)
		}
		if len(inact) != 1 || inact[0] != p21 {
			t.Fatalf("expected p21 inactivated, got %v", inact)
		}
	})

	t.Run("idempotent: same inputs twice => identical plan", func(t *testing.T) {
		stored := set(p11, p21)
		now := set(p11, p12)
		a1, i1 := reconcilePlan(stored, now)
		a2, i2 := reconcilePlan(stored, now)
		if len(a1) != len(a2) || len(i1) != len(i2) {
			t.Fatalf("plan not stable across runs: %v/%v vs %v/%v", a1, i1, a2, i2)
		}
	})

	t.Run("converged state: stored == violations => no churn", func(t *testing.T) {
		s := set(p11, p12)
		act, inact := reconcilePlan(s, s)
		// every active pair is re-asserted (upsert is idempotent) and nothing inactivates
		if len(act) != 2 {
			t.Fatalf("expected 2 re-asserted, got %d", len(act))
		}
		if len(inact) != 0 {
			t.Fatalf("expected 0 inactivations on a converged state, got %v", inact)
		}
	})

	t.Run("all cleared: violations empty => all stored inactivate", func(t *testing.T) {
		stored := set(p11, p12, p21)
		act, inact := reconcilePlan(stored, map[controlAsset]bool{})
		if len(act) != 0 {
			t.Fatalf("expected 0 activations, got %v", act)
		}
		if len(inact) != 3 {
			t.Fatalf("expected 3 inactivations, got %d", len(inact))
		}
	})

	t.Run("first run: nothing stored => all activate, none inactivate", func(t *testing.T) {
		now := set(p11, p12)
		act, inact := reconcilePlan(map[controlAsset]bool{}, now)
		if len(act) != 2 || len(inact) != 0 {
			t.Fatalf("expected 2 activate / 0 inactivate, got %d / %d", len(act), len(inact))
		}
	})

	t.Run("resurfaced: violation returns after being cleared", func(t *testing.T) {
		// p11 was inactivated last round (not in storedActive), now violates again.
		stored := set(p12)
		now := set(p11, p12)
		act, inact := reconcilePlan(stored, now)
		var foundResurface bool
		for _, p := range act {
			if p == p11 {
				foundResurface = true
			}
		}
		if !foundResurface {
			t.Fatalf("expected p11 to resurface in activations, got %v", act)
		}
		if len(inact) != 0 {
			t.Fatalf("expected no inactivations, got %v", inact)
		}
	})
}

// buildAssetViolations is the per-asset reconcile's new pure logic (ADR-0015):
// collapse per-control results into one (control, asset) pair per violating control
// for a SINGLE asset, keeping the first finding as representative, and never letting a
// cross-asset finding leak in. Pure, so no database.
func TestBuildAssetViolations(t *testing.T) {
	c1, c2 := uuid.New(), uuid.New()
	asset := uuid.New()
	other := uuid.New()

	t.Run("scopes to target asset; one pair per control; first kept; nil skipped", func(t *testing.T) {
		results := map[uuid.UUID]*EvaluationResult{
			c1: {ControlID: c1, Findings: []models.ComplianceFinding{
				{ControlID: c1, AssetID: asset, Summary: "first"},
				{ControlID: c1, AssetID: asset, Summary: "second"},      // same pair → deduped
				{ControlID: c1, AssetID: other, Summary: "other-asset"}, // filtered out
			}},
			c2: {ControlID: c2, Findings: []models.ComplianceFinding{
				{ControlID: c2, AssetID: other, Summary: "other-only"}, // no pair for target
			}},
			uuid.New(): nil, // nil result skipped
		}
		viol, byPair := buildAssetViolations(results, asset)

		if len(viol) != 1 {
			t.Fatalf("expected exactly 1 violating pair for the target asset, got %d", len(viol))
		}
		ca := controlAsset{ControlID: c1, AssetID: asset}
		if !viol[ca] {
			t.Fatalf("expected (c1, asset) to violate")
		}
		if byPair[ca].Summary != "first" {
			t.Fatalf("expected the first finding kept as representative, got %q", byPair[ca].Summary)
		}
		if viol[controlAsset{ControlID: c2, AssetID: asset}] {
			t.Fatalf("c2 had only an other-asset finding; it must not violate for the target asset")
		}
	})

	t.Run("no findings for the asset => empty set (pass derives from absence)", func(t *testing.T) {
		results := map[uuid.UUID]*EvaluationResult{
			c1: {ControlID: c1, Findings: []models.ComplianceFinding{
				{ControlID: c1, AssetID: other, Summary: "x"},
			}},
		}
		viol, byPair := buildAssetViolations(results, asset)
		if len(viol) != 0 || len(byPair) != 0 {
			t.Fatalf("expected empty violation set, got %d/%d", len(viol), len(byPair))
		}
	})
}
