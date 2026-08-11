package api

// Pins the reconcileAutoSteps behavior (checklist auto-completion): steps the
// tenant has real evidence for complete themselves, everything else is left to
// the manual flow. Uses the stubOnboardingStore from the contract test file.

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func defaultRawSteps() []map[string]interface{} {
	return []map[string]interface{}{
		{"id": "define_networks", "title": "Add network segments", "required": true},
		{"id": "add_locations", "title": "Add locations", "required": true},
		{"id": "deploy_agent", "title": "Add an agent", "required": true},
	}
}

func runReconcile(store *stubOnboardingStore, completed, skipped map[string]bool) {
	reconcileAutoSteps(context.Background(), store, uuid.New(), uuid.New(), uuid.New(), defaultRawSteps(), completed, skipped)
}

func TestReconcileAutoSteps_allEvidence_completesAndFinishes(t *testing.T) {
	store := &stubOnboardingStore{evidenceSegments: true, evidenceLocations: true, evidenceAgents: true}
	completed := map[string]bool{}

	runReconcile(store, completed, map[string]bool{})

	if len(store.upsertCompletedIDs) != 3 {
		t.Fatalf("upserted %v, want all 3 steps", store.upsertCompletedIDs)
	}
	for _, id := range []string{"define_networks", "add_locations", "deploy_agent"} {
		if !completed[id] {
			t.Errorf("step %s not marked completed in-place", id)
		}
	}
	if !store.markCompleteCalled {
		t.Error("all required steps complete but MarkOnboardingComplete not called")
	}
}

func TestReconcileAutoSteps_partialEvidence_leavesRestPending(t *testing.T) {
	store := &stubOnboardingStore{evidenceSegments: true} // no locations, no agents
	completed := map[string]bool{}

	runReconcile(store, completed, map[string]bool{})

	if len(store.upsertCompletedIDs) != 1 || store.upsertCompletedIDs[0] != "define_networks" {
		t.Fatalf("upserted %v, want only define_networks", store.upsertCompletedIDs)
	}
	if store.markCompleteCalled {
		t.Error("onboarding marked complete with required steps still pending")
	}
}

func TestReconcileAutoSteps_alreadyCompleteOrSkipped_notReUpserted(t *testing.T) {
	store := &stubOnboardingStore{evidenceSegments: true, evidenceLocations: true, evidenceAgents: true}
	completed := map[string]bool{"define_networks": true, "add_locations": true}
	skipped := map[string]bool{"deploy_agent": true}

	runReconcile(store, completed, skipped)

	if len(store.upsertCompletedIDs) != 0 {
		t.Fatalf("upserted %v for steps already completed/skipped", store.upsertCompletedIDs)
	}
	// Nothing was pending, so detection short-circuits and never marks complete
	// (completion for fully-manual state is the manual flow's job).
	if store.markCompleteCalled {
		t.Error("MarkOnboardingComplete called from a no-op reconcile")
	}
}

func TestReconcileAutoSteps_detectionError_leavesStateUntouched(t *testing.T) {
	store := &stubOnboardingStore{evidenceErr: context.DeadlineExceeded}
	completed := map[string]bool{}

	runReconcile(store, completed, map[string]bool{})

	if len(store.upsertCompletedIDs) != 0 || len(completed) != 0 || store.markCompleteCalled {
		t.Errorf("reconcile mutated state on detection error: upserts=%v completed=%v marked=%v",
			store.upsertCompletedIDs, completed, store.markCompleteCalled)
	}
}

func TestReconcileAutoSteps_unknownSteps_manualOnly(t *testing.T) {
	store := &stubOnboardingStore{evidenceSegments: true, evidenceLocations: true, evidenceAgents: true}
	completed := map[string]bool{}
	custom := []map[string]interface{}{{"id": "custom_step", "title": "Custom", "required": true}}

	reconcileAutoSteps(context.Background(), store, uuid.New(), uuid.New(), uuid.New(), custom, completed, map[string]bool{})

	if len(store.upsertCompletedIDs) != 0 || store.markCompleteCalled {
		t.Errorf("custom step auto-completed: upserts=%v marked=%v", store.upsertCompletedIDs, store.markCompleteCalled)
	}
}
