package services

// What the asset timeline records, and what it must stop recording.
//
// `asset_history` is the answer to "who accepted this, and when" six months
// later. It had two problems pointing in opposite directions: the three
// decisions a human actually makes wrote NOTHING to it, and a status re-assert
// that changed nothing wrote an entry every time.
//
// Skips without TEST_DATABASE_URL.

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// historyRows returns the (action, actor) pairs recorded for one asset.
func historyRows(t *testing.T, svc *AssetService, tenant, asset uuid.UUID) []struct {
	Action string
	Actor  *uuid.UUID
} {
	t.Helper()
	rows, err := svc.db.Query(
		`SELECT action, actor_user_id FROM asset_history WHERE tenant_id=$1 AND asset_id=$2 ORDER BY seq`,
		tenant, asset)
	if err != nil {
		t.Fatalf("read history: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []struct {
		Action string
		Actor  *uuid.UUID
	}
	for rows.Next() {
		var r struct {
			Action string
			Actor  *uuid.UUID
		}
		if err := rows.Scan(&r.Action, &r.Actor); err != nil {
			t.Fatalf("scan history: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("history rows: %v", err)
	}
	return out
}

// seedReviewer writes a real user. `asset_history.actor_user_id` has a foreign
// key to `users`, so a decision attributed to a random uuid is rejected by the
// database — which is correct, and is why the reviewer here is a real one.
func seedReviewer(t *testing.T, svc *AssetService, tenant uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := svc.db.Exec(`
		INSERT INTO users (id, tenant_id, email, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, true, NOW(), NOW())`,
		id, tenant, "reviewer-"+id.String()[:8]+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

// TestIntegration_ApproveAndDeny_RecordAnAttributableDecision is gate 1 B5.
//
// Approving is the single most consequential thing a person does to an asset,
// and it wrote nothing to the timeline at all: the history said the asset was
// discovered and then, with no entry in between, that it was being monitored.
// No record that anybody decided, and none of who.
func TestIntegration_ApproveAndDeny_RecordAnAttributableDecision(t *testing.T) {
	svc, _, tenant := newIdentityFixture(t)
	reviewer := seedReviewer(t, svc, tenant)

	approved, err := svc.CreateAsset(tenant, models.AssetInput{
		ClassKey: assetclass.KeyServer, Hostname: ptr("approve-me.example.test"),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	denied, err := svc.CreateAsset(tenant, models.AssetInput{
		ClassKey: assetclass.KeyServer, Hostname: ptr("deny-me.example.test"),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := svc.ApproveAssets(tenant, []uuid.UUID{approved.ID}, reviewer); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := svc.DenyAssets(tenant, []uuid.UUID{denied.ID}, reviewer); err != nil {
		t.Fatalf("deny: %v", err)
	}

	for _, tc := range []struct {
		asset  uuid.UUID
		action string
	}{
		{approved.ID, string(identity.ActionApproved)},
		{denied.ID, string(identity.ActionDenied)},
	} {
		found := false
		for _, r := range historyRows(t, svc, tenant, tc.asset) {
			if r.Action != tc.action {
				continue
			}
			found = true
			if r.Actor == nil {
				t.Errorf("%s was recorded with no actor; an anonymous decision is not an audit trail", tc.action)
			} else if *r.Actor != reviewer {
				t.Errorf("%s recorded actor %s, want the reviewer %s", tc.action, *r.Actor, reviewer)
			}
		}
		if !found {
			t.Errorf("no %s entry in the asset's timeline", tc.action)
		}
	}
}

// TestIntegration_SetAssetStatus_RecordsOnlyRealChanges is gate 1 B10.
//
// The UPDATE carries `asset_status <> $1`, so re-asserting the status an asset
// already has changes nothing — and the history row was written anyway. A host
// observed every fifteen minutes accumulated ninety-six `approved` rows a day,
// each claiming an approval that never happened, and the real decision was
// buried in them.
func TestIntegration_SetAssetStatus_RecordsOnlyRealChanges(t *testing.T) {
	svc, _, tenant := newIdentityFixture(t)

	asset, err := svc.CreateAsset(tenant, models.AssetInput{
		ClassKey: assetclass.KeyServer, Hostname: ptr("polled.example.test"),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	source := identity.Source{Kind: identity.SourceMeasured, Ref: "sensor"}
	// First move: a real change.
	if err := svc.setAssetStatus(nil, tenant, asset.ID, identity.StatusMonitoring, source); err != nil {
		t.Fatalf("first status set: %v", err)
	}
	before := countAction(historyRows(t, svc, tenant, asset.ID), string(identity.ActionApproved))
	if before != 1 {
		t.Fatalf("%d approved entries after the first move, want 1", before)
	}

	// Four no-op polls.
	for i := 0; i < 4; i++ {
		if err := svc.setAssetStatus(nil, tenant, asset.ID, identity.StatusMonitoring, source); err != nil {
			t.Fatalf("poll %d: %v", i, err)
		}
	}
	after := countAction(historyRows(t, svc, tenant, asset.ID), string(identity.ActionApproved))
	if after != 1 {
		t.Errorf("%d approved entries after four no-op polls, want 1 — history is a log of changes, "+
			"not of attempts", after)
	}
}

func countAction(rows []struct {
	Action string
	Actor  *uuid.UUID
}, action string) int {
	n := 0
	for _, r := range rows {
		if r.Action == action {
			n++
		}
	}
	return n
}

// TestIntegration_UpdateAsset_RefusesToChangeStatus is gate 1 B7.
//
// Approval is a cascade, not a column: it promotes the asset's pending
// relationships and materialises the findings deferred while it waited. A PUT
// that wrote `asset_status` did the column and none of the cascade, producing a
// monitored asset with an empty Relationships tab and no findings — and nothing
// to retry it. Denying is worse still: the suppression that is half of what
// "denied" means was skipped entirely.
func TestIntegration_UpdateAsset_RefusesToChangeStatus(t *testing.T) {
	svc, _, tenant := newIdentityFixture(t)

	asset, err := svc.CreateAsset(tenant, models.AssetInput{
		ClassKey: assetclass.KeyServer, Hostname: ptr("status-edit.example.test"),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	before := asset.AssetStatus

	monitoring := identity.StatusMonitoring
	_, _, err = svc.UpdateAsset(tenant, asset.ID, models.AssetInput{AssetStatus: &monitoring}, uuid.New())
	if err == nil {
		t.Fatal("PUT accepted asset_status; approval is a cascade and the column alone leaves it half done")
	}
	if !strings.Contains(err.Error(), "asset_status cannot be changed") {
		t.Errorf("err = %v, want it to name the endpoints that do the cascade", err)
	}

	after, err := svc.GetAssetByID(tenant, asset.ID)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if after.AssetStatus != before {
		t.Errorf("asset_status moved %s → %s despite the refusal", before, after.AssetStatus)
	}
}

// TestIntegration_UpdateAsset_RefusesAnUnknownClass is gate 1 B8. An unknown key
// used to be written straight through — classPathForKey falls back to the key
// itself — producing an asset in a class no facet can select, no CMDB sync can
// map and no identifier precedence exists for.
func TestIntegration_UpdateAsset_RefusesAnUnknownClass(t *testing.T) {
	svc, _, tenant := newIdentityFixture(t)

	asset, err := svc.CreateAsset(tenant, models.AssetInput{
		ClassKey: assetclass.KeyServer, Hostname: ptr("class-edit.example.test"),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, _, err := svc.UpdateAsset(tenant, asset.ID,
		models.AssetInput{ClassKey: "not_a_class_anybody_registered"}, uuid.New()); err == nil {
		t.Fatal("PUT accepted an unknown class_key")
	}

	// A REAL class still works, and records who declared it.
	actor := seedReviewer(t, svc, tenant)
	if _, _, err := svc.UpdateAsset(tenant, asset.ID,
		models.AssetInput{ClassKey: assetclass.KeyFirewall}, actor); err != nil {
		t.Fatalf("a known class must be accepted: %v", err)
	}
	var key, sourceKind string
	var sourceRef *string
	if err := svc.db.QueryRow(
		`SELECT class_key, class_source_kind, class_source_ref FROM assets WHERE tenant_id=$1 AND id=$2`,
		tenant, asset.ID).Scan(&key, &sourceKind, &sourceRef); err != nil {
		t.Fatalf("re-read class: %v", err)
	}
	if key != assetclass.KeyFirewall || sourceKind != "declared" {
		t.Errorf("class = %q/%q, want firewall/declared", key, sourceKind)
	}
	if sourceRef == nil || *sourceRef != actor.String() {
		t.Errorf("class_source_ref = %v, want the actor %s — a declared class with no decider is "+
			"indistinguishable from one nobody set", sourceRef, actor)
	}
}
