package services

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// A finding that lands on no asset is logged as what actually happened
//: a merge proposal (with its id) when one was opened, otherwise an
// unresolved observation with its outcome and admission reason — never "merge
// proposal  was opened" with an empty id.
func TestNoAssetIngestMessage_SaysWhatHappened(t *testing.T) {
	label := "10.0.0.5:22/SSH"

	proposal := noAssetIngestMessage(label, identity.Resolution{
		Outcome:    identity.OutcomeConflict,
		Candidates: []identity.MergeCandidate{{}, {}},
		Proposal:   identity.ProposalRef{ID: "prop-123"},
	})
	if !strings.Contains(proposal, "merge proposal prop-123 was opened") || !strings.Contains(proposal, "belong to 2 existing asset(s)") {
		t.Errorf("with a proposal: %q", proposal)
	}
	if strings.Contains(proposal, "unresolved observation") {
		t.Errorf("with a proposal, the message must not claim an observation: %q", proposal)
	}

	unresolved := noAssetIngestMessage(label, identity.Resolution{
		Outcome:         identity.OutcomeUnresolved,
		ObservationID:   "obs-9",
		AdmissionReason: "dynamic_address_without_device_binding",
	})
	for _, want := range []string{
		label,
		"evidence retained as an unresolved observation",
		"outcome unresolved",
		"reason dynamic_address_without_device_binding",
		"observation obs-9",
		"no asset was created and no merge proposal exists",
	} {
		if !strings.Contains(unresolved, want) {
			t.Errorf("unresolved: %q lacks %q", unresolved, want)
		}
	}
	if strings.Contains(unresolved, "was opened") || strings.Contains(unresolved, "existing asset(s)") {
		t.Errorf("unresolved, no proposal: the message claims one, or candidates there are none of: %q", unresolved)
	}

	bare := noAssetIngestMessage(label, identity.Resolution{Outcome: identity.OutcomeUnresolved})
	if !strings.Contains(bare, "reason none recorded") || !strings.Contains(bare, "observation none") {
		t.Errorf("no reason or observation id: %q", bare)
	}
}
