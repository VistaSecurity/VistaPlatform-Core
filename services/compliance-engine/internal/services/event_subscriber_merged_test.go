package services

// `inventory.lifecycle.asset.merged` → the two compliance events a merge is.
//
// Accepting a merge moves exactly the rows findings are computed FROM —
// endpoints, crypto configurations, certificates, facts — out of one asset and
// into another, and neither side publishes `compliance.asset.changed`. Before
// this consumer the merged-away asset kept its materialised findings forever
// (open, against an archived asset nobody can remediate, counted in the tenant's
// score) while the survivor's score ignored everything it had just absorbed.
// Both numbers were wrong and nothing anywhere said so.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/events"
)

func mergedEnvelope(t *testing.T, payload events.AssetMergedPayload, tenant uuid.UUID) events.LifecycleEnvelope {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return events.LifecycleEnvelope{
		EventID:   uuid.New(),
		EventType: "asset.merged",
		TenantID:  tenant,
		Timestamp: time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC),
		Source:    "approvals",
		Payload:   raw,
	}
}

// TestMergedToComplianceEvents_IsTwoEvents: a merge is two facts, and handling
// either alone leaves a tenant's compliance score wrong in a different way.
func TestMergedToComplianceEvents_IsTwoEvents(t *testing.T) {
	tenant, survivor, merged, proposal := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	envelope := mergedEnvelope(t, events.AssetMergedPayload{
		SurvivorAssetID: survivor,
		MergedAssetID:   merged,
		ClassKey:        "server",
		ProposalID:      proposal,
		DecidedBy:       "11111111-1111-1111-1111-111111111111",
	}, tenant)

	deleted, changed, ok := mergedToComplianceEvents(envelope)
	if !ok {
		t.Fatal("a well-formed merge must be actionable")
	}

	// The merged-away id is gone as a SUBJECT — its findings are retired the
	// same way a deleted asset's are. Pointing this at the survivor instead
	// would retire the findings of the asset that just grew.
	if deleted.AssetID != merged {
		t.Errorf("the deletion must name the MERGED-AWAY asset, got %s", deleted.AssetID)
	}
	if deleted.EventType != events.EventTypeAssetDeleted {
		t.Errorf("deletion event type = %q, want %q", deleted.EventType, events.EventTypeAssetDeleted)
	}
	// The survivor CHANGED, by more than an ordinary update: it absorbed another
	// asset's whole cryptographic surface.
	if changed.AssetID != survivor {
		t.Errorf("the change must name the SURVIVOR, got %s", changed.AssetID)
	}
	if changed.EventType != events.EventTypeAssetChanged {
		t.Errorf("change event type = %q, want %q", changed.EventType, events.EventTypeAssetChanged)
	}
	if changed.ChangeType != events.ChangeTypeUpdated {
		t.Errorf("change type = %q, want %q", changed.ChangeType, events.ChangeTypeUpdated)
	}

	for name, got := range map[string]uuid.UUID{"deleted": deleted.TenantID, "changed": changed.TenantID} {
		if got != tenant {
			t.Errorf("%s event carries tenant %s, want %s", name, got, tenant)
		}
	}

	// Both carry WHY, so a finding retired here is not an unexplained deletion
	// of an asset that still exists.
	for name, meta := range map[string]map[string]interface{}{"deleted": deleted.Metadata, "changed": changed.Metadata} {
		if meta["reason"] != "asset_merged" {
			t.Errorf("%s event metadata reason = %v, want asset_merged", name, meta["reason"])
		}
		if meta["proposal_id"] != proposal.String() {
			t.Errorf("%s event metadata lost the proposal id", name)
		}
		if meta["survivor_asset_id"] != survivor.String() || meta["merged_asset_id"] != merged.String() {
			t.Errorf("%s event metadata must name both sides", name)
		}
		if meta["decided_by"] != "11111111-1111-1111-1111-111111111111" {
			t.Errorf("%s event metadata lost the reviewer", name)
		}
	}
}

// TestMergedToComplianceEvents_RefusesHalfAMerge is the other polarity. Each of
// these would reconcile HALF a merge, and half is worse than none: it leaves the
// tenant's score wrong in a way that looks deliberate.
func TestMergedToComplianceEvents_RefusesHalfAMerge(t *testing.T) {
	tenant := uuid.New()
	id := uuid.New()
	for name, payload := range map[string]events.AssetMergedPayload{
		"no survivor":     {MergedAssetID: id},
		"nothing merged":  {SurvivorAssetID: id},
		"neither":         {},
		"one asset, both": {SurvivorAssetID: id, MergedAssetID: id},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, ok := mergedToComplianceEvents(mergedEnvelope(t, payload, tenant)); ok {
				t.Error("this envelope cannot be acted on and must be refused")
			}
		})
	}

	t.Run("a payload that is not a merge", func(t *testing.T) {
		envelope := events.LifecycleEnvelope{
			EventID: uuid.New(), TenantID: tenant, Payload: json.RawMessage(`"not an object"`),
		}
		if _, _, ok := mergedToComplianceEvents(envelope); ok {
			t.Error("an undecodable payload must be refused, not acted on")
		}
	})

	// And the passing twin: the minimum an actionable merge needs. Without it
	// the four cases above could be satisfied by a function that refuses
	// everything.
	t.Run("the minimum that IS actionable", func(t *testing.T) {
		survivor, merged := uuid.New(), uuid.New()
		_, _, ok := mergedToComplianceEvents(mergedEnvelope(t, events.AssetMergedPayload{
			SurvivorAssetID: survivor, MergedAssetID: merged,
		}, tenant))
		if !ok {
			t.Error("two distinct asset ids are all a merge needs to be actionable")
		}
	})
}

// TestComplianceSubscribesToAssetMerged pins the WIRING, not just the
// translation.
//
// A handler nothing subscribes to is the exact shape of the bug this consumer
// closes — `asset.merged` was published for a release with no consumer at all —
// so the translation being correct is worth nothing until something delivers a
// message to it.
func TestComplianceSubscribesToAssetMerged(t *testing.T) {
	s := &EventSubscriberService{}
	subscriptions, handlers := s.subscriptionPlan()

	// The pairing is by index, so unequal lengths mean every subject after the
	// mismatch is handled by the wrong function — silently, and only in
	// production. Start() would also panic or drop one, depending on which side
	// is shorter.
	if len(subscriptions) != len(handlers) {
		t.Fatalf("%d subjects and %d handlers: the plan pairs them by index and they must match",
			len(subscriptions), len(handlers))
	}

	found := false
	for _, cfg := range subscriptions {
		if cfg.Subject != events.SubjectLifecycleAssetMerged {
			continue
		}
		found = true
		if cfg.Stream != "INVENTORY_LIFECYCLE" {
			t.Errorf("asset.merged is on stream %q, want INVENTORY_LIFECYCLE", cfg.Stream)
		}
		if cfg.Durable == "" {
			t.Error("asset.merged needs a durable name, or a restart loses the merges it missed")
		}
		if cfg.MaxDeliver < 2 {
			t.Errorf("MaxDeliver = %d: a merge that failed to reconcile must be redelivered", cfg.MaxDeliver)
		}
	}
	if !found {
		t.Fatalf("nothing subscribes to %s — the merge event has no consumer again",
			events.SubjectLifecycleAssetMerged)
	}

	// Every durable name is distinct: two subscriptions sharing one would have
	// them compete for the same messages rather than each getting all of them.
	seen := map[string]string{}
	for _, cfg := range subscriptions {
		if prev, dup := seen[cfg.Durable]; dup {
			t.Errorf("durable %q is used by both %q and %q", cfg.Durable, prev, cfg.Subject)
		}
		seen[cfg.Durable] = cfg.Subject
	}
}
