package services

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

func actionRowCount(t *testing.T, svc *AssetService, tenant, asset uuid.UUID, action identity.HistoryAction) int {
	t.Helper()
	n := 0
	for _, r := range historyRows(t, svc, tenant, asset) {
		if r.Action == string(action) {
			n++
		}
	}
	return n
}

func assetStatusOf(t *testing.T, svc *AssetService, tenant, asset uuid.UUID) string {
	t.Helper()
	var st string
	if err := svc.db.QueryRow(`SELECT asset_status FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, asset).Scan(&st); err != nil {
		t.Fatalf("read status: %v", err)
	}
	return st
}

// A second approve of the same asset is a no-op: it reports nothing changed,
// writes no history row and leaves the status alone. Without the transition
// predicate the UPDATE matched the already-monitored row and everything
// downstream (history, event, deferred-crypto replay) ran again.
func TestIntegration_ApproveTwice_SecondChangesNothing(t *testing.T) {
	svc, _, tenant := newIdentityFixture(t)
	reviewer := seedReviewer(t, svc, tenant)
	a, err := svc.CreateAsset(tenant, models.AssetInput{ClassKey: assetclass.KeyServer, Hostname: ptr("twice.example.test")})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	unknown := uuid.New()

	first, err := svc.ApproveAssetsReport(tenant, []uuid.UUID{a.ID, unknown}, reviewer)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if len(first.Changed) != 1 || first.Changed[0] != a.ID {
		t.Fatalf("first approve changed %v, want [%s]", first.Changed, a.ID)
	}
	if len(first.Skipped) != 1 || first.Skipped[0] != unknown {
		t.Fatalf("first approve skipped %v, want the unknown id", first.Skipped)
	}

	second, err := svc.ApproveAssetsReport(tenant, []uuid.UUID{a.ID}, reviewer)
	if err != nil {
		t.Fatalf("second approve: %v", err)
	}
	if len(second.Changed) != 0 || len(second.Skipped) != 1 {
		t.Fatalf("second approve = %+v, want nothing changed and the id skipped", second)
	}
	if n := actionRowCount(t, svc, tenant, a.ID, identity.ActionApproved); n != 1 {
		t.Errorf("approved history rows = %d, want exactly 1", n)
	}
}

// Deny only acts on the approval queue. A monitored asset is not flipped to
// denied (and suppressed) by a stray deny, and a second deny is a no-op.
func TestIntegration_Deny_OnlyFromPending_AndNotRepeated(t *testing.T) {
	svc, _, tenant := newIdentityFixture(t)
	reviewer := seedReviewer(t, svc, tenant)
	monitored, err := svc.CreateAsset(tenant, models.AssetInput{ClassKey: assetclass.KeyServer, Hostname: ptr("live.example.test")})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	pending, err := svc.CreateAsset(tenant, models.AssetInput{ClassKey: assetclass.KeyServer, Hostname: ptr("queued.example.test")})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.ApproveAssets(tenant, []uuid.UUID{monitored.ID}, reviewer); err != nil {
		t.Fatalf("approve: %v", err)
	}

	res, err := svc.DenyAssetsReport(tenant, []uuid.UUID{monitored.ID, pending.ID}, reviewer)
	if err != nil {
		t.Fatalf("deny: %v", err)
	}
	if len(res.Changed) != 1 || res.Changed[0] != pending.ID {
		t.Fatalf("deny changed %v, want only the pending asset", res.Changed)
	}
	if st := assetStatusOf(t, svc, tenant, monitored.ID); st != identity.StatusMonitoring {
		t.Errorf("monitored asset is now %q; a deny must not flip it", st)
	}
	if n := actionRowCount(t, svc, tenant, monitored.ID, identity.ActionDenied); n != 0 {
		t.Errorf("monitored asset has %d denied history rows, want 0", n)
	}

	again, err := svc.DenyAssetsReport(tenant, []uuid.UUID{pending.ID}, reviewer)
	if err != nil {
		t.Fatalf("second deny: %v", err)
	}
	if len(again.Changed) != 0 {
		t.Errorf("second deny changed %v, want nothing", again.Changed)
	}
	if n := actionRowCount(t, svc, tenant, pending.ID, identity.ActionDenied); n != 1 {
		t.Errorf("denied history rows = %d, want exactly 1", n)
	}
}

// Delete, restore and update of an id that is not there answer ErrNotFound.
// Success for nothing is what published asset-deleted events and wrote audit
// rows for rows that never changed.
func TestIntegration_WritesToMissingAsset_AreNotFound(t *testing.T) {
	svc, _, tenant := newIdentityFixture(t)
	missing := uuid.New()

	if err := svc.DeleteAsset(tenant, missing); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteAsset(unknown) = %v, want ErrNotFound", err)
	}
	if err := svc.RestoreAsset(tenant, missing); !errors.Is(err, ErrNotFound) {
		t.Errorf("RestoreAsset(unknown) = %v, want ErrNotFound", err)
	}
	if _, _, err := svc.UpdateAsset(tenant, missing, models.AssetInput{Description: ptr("x")}, uuid.Nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateAsset(unknown) = %v, want ErrNotFound", err)
	}

	a, err := svc.CreateAsset(tenant, models.AssetInput{ClassKey: assetclass.KeyServer, Hostname: ptr("gone.example.test")})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.DeleteAsset(tenant, a.ID); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	if err := svc.DeleteAsset(tenant, a.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second DeleteAsset = %v, want ErrNotFound", err)
	}
}
