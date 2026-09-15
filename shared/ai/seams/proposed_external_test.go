// Package seams_test is an EXTERNAL test package: it can see only what a real
// consumer of shared/ai/seams sees. That is the only place the Proposed
// marker's actual property can be stated, because from inside the package
// everything satisfies everything.
package seams_test

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
)

// withEmbed is what a phase-4 implementation's own output type looks like: its
// own fields, plus the embedded Proposal.
type withEmbed struct {
	seams.Proposal
	Verdict string
}

// The positive case, proven by the compiler. Go promotes the methods of an
// embedded field INCLUDING the unexported one, so embedding seams.Proposal is
// how a type in another package satisfies seams.Proposed — and that is the
// intended mechanism, not a hole in a barrier. It is the gRPC
// mustEmbedUnimplemented pattern: embedding is the only way in, and embedding
// is what drags the four provenance fields along with it.
var (
	_ seams.Proposed = withEmbed{}
	_ seams.Proposed = (*withEmbed)(nil)
)

// withoutEmbed declares the same provenance fields by hand and does NOT embed
// Proposal.
type withoutEmbed struct {
	SourceKind string
	SourceRef  string
	Confidence float64
	ModelID    string
	Verdict    string
}

// Provenance is exported and can be declared anywhere; the unexported marker
// cannot. This type therefore has half the interface and satisfies none of it.
func (withoutEmbed) Provenance() seams.Proposal { return seams.Proposal{} }

// The negative case. Uncommenting this line does not compile —
//
//	var _ seams.Proposed = withoutEmbed{}
//
//	cannot use withoutEmbed{} as seams.Proposed value: withoutEmbed does not
//	implement seams.Proposed (missing method proposal)
//
// which is a claim a comment cannot keep honest, so the runtime assertion below
// keeps it: if the marker were ever exported, or Proposed reduced to its
// exported half, this type would start satisfying it and the test fails.
func TestProposed_RequiresTheEmbed(t *testing.T) {
	var handWritten any = withoutEmbed{
		SourceKind: "inferred",
		SourceRef:  "classifier:hand-written",
		Confidence: 0.99,
	}
	if _, ok := handWritten.(seams.Proposed); ok {
		t.Error("a type that declares the provenance fields by hand satisfies Proposed; " +
			"the unexported marker is gone, and with it the guarantee that a proposal " +
			"carries the fields rather than merely claiming to")
	}

	var embedded any = withEmbed{
		Proposal: seams.NewProposal("onnx-v1", "classifier:onnx-v1", 0.7),
		Verdict:  "router",
	}
	got, ok := embedded.(seams.Proposed)
	if !ok {
		t.Fatal("a type embedding seams.Proposal does not satisfy Proposed; " +
			"embedding it is how an implementation outside this package is meant to " +
			"produce a proposal at all")
	}

	// And the embed is what carries the provenance, which is the whole reason
	// to insist on it.
	p := seams.ProposalOf(got)
	if p.SourceKind != seams.SourceKindInferred || p.SourceRef == "" || p.ModelID != "onnx-v1" {
		t.Errorf("provenance did not come through the embed: %+v", p)
	}
}

// ADR-0008 D4.2 — "inferred never overwrites measured" — is NOT enforced by
// this type, or anywhere in this package. It is a rule about a write against an
// existing value, so it needs the existing value's source_kind to compare
// against; that lands at the facts layer in phase 3. Nothing here checks it,
// and the package documentation says so rather than implying the marker covers
// it. This test exists to be found by whoever goes looking for the check.
func TestD42_IsNotEnforcedHere(t *testing.T) {
	t.Log("D4.2 (inferred never overwrites measured) is enforced at the facts layer " +
		"in phase 3, not by seams.Proposed. See ADR-0008 D4.2.")
}
