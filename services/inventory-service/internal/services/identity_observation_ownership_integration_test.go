package services

// The Observations suggestion and the Decide action share ONE ownership rule
// ( item 9). Before it, the table offered "Ready to confirm" on dynamic
// addresses an established asset already owned, and Confirm — which refuses
// whenever any identifier has an owner — answered every one with "changed
// since you looked".
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_ObservationOwnership_SuggestionAndDecisionAgree(t *testing.T) {
	db, tenant := getTestDBAndTenant(t)
	testdb.WithSchemaShareLock(t, db.DB.DB, func() {
		ctx := context.Background()
		svc := NewAssetService(db)
		actor := seedUser(t, db, tenant)
		if _, err := db.Exec(`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason)
		 SELECT $1,id,'{"quantity":100}'::jsonb,'ownership regression' FROM billable_items WHERE key='max_assets'`, tenant); err != nil {
			t.Fatal(err)
		}
		segment := seedSegment(t, db, tenant, "Home", "192.0.2.0/24")
		scope := segment.String()
		ev := func(addr string, extra ...string) string {
			ids := fmt.Sprintf(`{"kind":"ip_address","value":%q,"scope":%q}`, addr, scope)
			for _, e := range extra {
				ids += "," + e
			}
			return fmt.Sprintf(`{"identifiers":[%s],"endpoints":[{"address":%q,"port":22,"transport":"tcp","protocol":"ssh"}]}`, ids, addr)
		}
		now := time.Now().UTC().Add(-time.Hour)
		owner := seedOwnerAsset(t, db.DB.DB, tenant, "dream-router", "monitoring", false, [3]string{"ip_address", "192.0.2.10", scope})
		other := seedOwnerAsset(t, db.DB.DB, tenant, "nas", "monitoring", false, [3]string{"mac_address", "aa:bb:cc:00:10:02", ""})

		owned := insertObservationRow(t, db.DB.DB, tenant, "unresolved", []string{rDynamic}, "", "scan", scope, ev("192.0.2.10"), now)
		multi := insertObservationRow(t, db.DB.DB, tenant, "unresolved", []string{rDynamic}, "", "scan", scope,
			ev("192.0.2.10", `{"kind":"mac_address","value":"aa:bb:cc:00:10:02"}`), now)
		free := insertObservationRow(t, db.DB.DB, tenant, "unresolved", []string{rDynamic}, "", "scan", scope, ev("192.0.2.11"), now)

		get := func(id uuid.UUID) IdentityObservation {
			t.Helper()
			o, err := svc.GetIdentityObservation(ctx, tenant, id)
			if err != nil {
				t.Fatal(err)
			}
			return o
		}

		// The symptom: the owned row must not be offered as Confirm.
		o := get(owned)
		if o.Needs == NeedsReadyToConfirm || o.SuggestedAction == SuggestConfirm {
			t.Fatalf("an address an established asset owns was suggested %s/%s", o.Needs, o.SuggestedAction)
		}
		if o.Needs != NeedsLinkExisting || o.SuggestedAction != SuggestLink || o.LinkAsset == nil || o.LinkAsset.ID != owner || o.LinkAsset.Name != "dream-router" {
			t.Fatalf("owned row: needs=%s action=%s link=%+v, want link_existing/link to dream-router", o.Needs, o.SuggestedAction, o.LinkAsset)
		}
		if !strings.Contains(o.SuggestedReason, "dream-router") || uuidRE.MatchString(o.SuggestedReason) {
			t.Fatalf("suggested reason %q", o.SuggestedReason)
		}
		if m := get(multi); m.Needs != NeedsReview || m.SuggestedAction != SuggestNone || m.LinkAsset != nil {
			t.Fatalf("multiply-owned row: needs=%s action=%s link=%+v, want needs_review/none", m.Needs, m.SuggestedAction, m.LinkAsset)
		}
		if f := get(free); f.Needs != NeedsReadyToConfirm || f.SuggestedAction != SuggestConfirm || f.LinkAsset != nil {
			t.Fatalf("unowned row: needs=%s action=%s", f.Needs, f.SuggestedAction)
		}

		// The list and its chips agree with the detail read.
		page, err := svc.ListIdentityObservationsFiltered(ctx, tenant, ObservationListFilter{State: "unresolved", Page: 1, PageSize: 50})
		if err != nil {
			t.Fatal(err)
		}
		if c := page.Counts; c == nil || c.ReadyToConfirm != 1 || c.LinkExisting != 1 || c.NeedsReview != 1 || c.All != 3 {
			t.Fatalf("counts %+v, want ready 1 / link 1 / review 1 / all 3", page.Counts)
		}
		if only, err := svc.ListIdentityObservationsFiltered(ctx, tenant, ObservationListFilter{State: "unresolved", Page: 1, PageSize: 50, Needs: []string{NeedsLinkExisting}}); err != nil || only.Total != 1 || only.Observations[0].ID != owned {
			t.Fatalf("link_existing filter: %+v %v", only, err)
		}

		// What Confirm would have done: the decision refuses it, in bulk and alone.
		if _, err := svc.DecideIdentityObservation(ctx, tenant, owned, actor, "confirmed", ObservationDecisionInput{Reason: "x"}); !errors.Is(err, ErrObservationChanged) {
			t.Fatalf("single confirm of an owned address: %v, want ErrObservationChanged", err)
		}
		_, items, err := svc.BulkDecideIdentityObservations(ctx, tenant, actor, "confirm", []uuid.UUID{owned, multi}, ObservationDecisionInput{Reason: "x"})
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range items {
			if !errors.Is(it.Err, ErrObservationNotReady) {
				t.Fatalf("bulk confirm of %s: %v, want not-ready (the table no longer offers it)", it.ID, it.Err)
			}
		}

		// Bulk Link refuses what the table does not suggest linking…
		_, items, err = svc.BulkDecideIdentityObservations(ctx, tenant, actor, "link", []uuid.UUID{multi, free}, ObservationDecisionInput{Reason: "x"})
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range items {
			if !errors.Is(it.Err, ErrObservationNotReady) {
				t.Fatalf("bulk link of %s: %v, want not-ready", it.ID, it.Err)
			}
		}
		// …and a client-named asset is never honoured: the target is the owner.
		_, items, err = svc.BulkDecideIdentityObservations(ctx, tenant, actor, "link", []uuid.UUID{owned}, ObservationDecisionInput{Reason: "Linked from Observations", AssetID: &other})
		if err != nil || len(items) != 1 || items[0].Err != nil {
			t.Fatalf("bulk link of the owned row: %+v %v", items, err)
		}
		if items[0].Result.AssetID != owner.String() {
			t.Fatalf("linked to %s, want the owner %s", items[0].Result.AssetID, owner)
		}
		done := get(owned)
		if done.State != "linked" || done.AssetID == nil || *done.AssetID != owner {
			t.Fatalf("after link: state=%s asset=%v", done.State, done.AssetID)
		}
		// A repeat is idempotent.
		if _, items, _ = svc.BulkDecideIdentityObservations(ctx, tenant, actor, "link", []uuid.UUID{owned}, ObservationDecisionInput{Reason: "again"}); items[0].Err != nil {
			t.Fatalf("repeat bulk link: %v", items[0].Err)
		}

		// The single-row Link to the same owner — the path the UI's Link button
		// takes — succeeds where Confirm was refused.
		again := insertObservationRow(t, db.DB.DB, tenant, "unresolved", []string{rDynamic}, "", "scan", scope, ev("192.0.2.10", `{"kind":"hostname","value":"dream-router-alt","scope":"`+scope+`"}`), now)
		if _, err := svc.DecideIdentityObservation(ctx, tenant, again, actor, "confirmed", ObservationDecisionInput{Reason: "x"}); !errors.Is(err, ErrObservationChanged) {
			t.Fatalf("confirm: %v", err)
		}
		if res, err := svc.DecideIdentityObservation(ctx, tenant, again, actor, "linked", ObservationDecisionInput{Reason: "x", AssetID: &owner}); err != nil || res.AssetID != owner.String() {
			t.Fatalf("link to the suggested owner: %+v %v", res, err)
		}

		// The unowned row still confirms in bulk.
		_, items, err = svc.BulkDecideIdentityObservations(ctx, tenant, actor, "confirm", []uuid.UUID{free}, ObservationDecisionInput{Reason: "Recognised"})
		if err != nil || items[0].Err != nil {
			t.Fatalf("bulk confirm of the unowned row: %+v %v", items, err)
		}
	})
}
