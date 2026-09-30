package services

import (
	"testing"

	"github.com/google/uuid"
)

// The floor path stores observation_asset_id as "". It is not a participant:
// counting it made {"", survivor} look like two records ( A2). The DB
// integration test TestIntegration_MergeProposal_EmptyObservationIDResolvesOnMerge
// pins the end-to-end outcome, where the liveness count also happens to
// discard "" — this pins the guard itself, so removing it cannot hide behind
// the second one.
func TestRemapMergeParticipants_EmptyObservationIsNotAParticipant(t *testing.T) {
	survivor, source := uuid.New(), uuid.New()
	changes := map[string]any{
		"observation_asset_id": "",
		"candidates": []any{
			map[string]any{"asset_id": survivor.String()},
			map[string]any{"asset_id": source.String()},
		},
	}
	ids := remapMergeParticipants(changes, map[string]bool{source.String(): true}, survivor)
	if len(ids) != 1 || !ids[survivor.String()] {
		t.Fatalf("participants = %v, want only the survivor", ids)
	}
	if got := changes["observation_asset_id"]; got != "" {
		t.Fatalf("empty observation id was rewritten to %v", got)
	}
	if cs := changes["candidates"].([]any); len(cs) != 1 {
		t.Fatalf("candidates not deduplicated onto the survivor: %v", cs)
	}
}

func TestRemapMergeParticipants_MovesObservationOntoSurvivor(t *testing.T) {
	survivor, source, third := uuid.New(), uuid.New(), uuid.New()
	changes := map[string]any{
		"observation_asset_id": source.String(),
		"candidates":           []any{map[string]any{"asset_id": third.String()}},
	}
	ids := remapMergeParticipants(changes, map[string]bool{source.String(): true}, survivor)
	if len(ids) != 2 || !ids[survivor.String()] || !ids[third.String()] {
		t.Fatalf("participants = %v, want survivor and third", ids)
	}
	if got := changes["observation_asset_id"]; got != survivor.String() {
		t.Fatalf("observation = %v, want survivor", got)
	}
}
