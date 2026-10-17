package services

// DB-integration test for the Changes lens (DCIM BUILD_PLAN row 5.2): a change
// to an asset's interface or address shows on the ASSET's Changes tab through
// `include_related`. Skipped unless TEST_DATABASE_URL is set.

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/journal"
)

func TestIntegration_ChangesLens_AssetTabListsRelatedChanges(t *testing.T) {
	f := newIPAMFixture(t)
	asset := ifaceSeedAsset(t, f.owner, f.tenant, "monitoring")
	other := ifaceSeedAsset(t, f.owner, f.tenant, "monitoring")
	user := uuid.New()
	ctx := changes.WithSource(changes.WithActor(context.Background(), changes.Actor{UserID: user, UserName: "ops@example.test"}), changes.SourceUI)

	// A real interface update through the service, then an address on it
	// through the IPAM engine, then a journal entry on the asset.
	isvc := NewInterfaceService(f.app)
	iface, err := isvc.Create(ctx, f.tenant, user, InterfaceInput{AssetID: asset, Name: "eth0", Type: "1000base-t"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := isvc.Patch(ctx, f.tenant, iface.ID, map[string]json.RawMessage{"mtu": json.RawMessage(`9000`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := isvc.Create(ctx, f.tenant, user, InterfaceInput{AssetID: other, Name: "eth0", Type: "1000base-t"}); err != nil {
		t.Fatal(err)
	}
	f.ctx = ctx
	ip := f.create(t, "ip-addresses", map[string]any{"address": "10.77.0.5/24", "assigned_kind": "interface", "assigned_id": iface.ID.String()})
	if err := database.WithTenantTx(ctx, f.app, f.tenant, func(tx *sql.Tx) error {
		_, err := journal.Add(ctx, tx, changes.InTx(tx), f.tenant, dcim.ObjectKindAsset, asset, journal.KindInfo, "swapped the SFP")
		return err
	}); err != nil {
		t.Fatal(err)
	}

	list := func(related bool, a uuid.UUID) map[string]bool {
		t.Helper()
		var rows []changes.ObjectChange
		if err := database.WithTenantTx(ctx, f.app, f.tenant, func(tx *sql.Tx) error {
			var err error
			rows, _, err = changes.List(ctx, tx, changes.Filter{TenantID: f.tenant, ObjectKind: dcim.ObjectKindAsset, ObjectID: a, IncludeRelated: related})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, r := range rows {
			got[string(r.ObjectKind)+"/"+string(r.Action)] = true
			if r.ObjectKind != dcim.ObjectKindAsset && (r.RelatedKind == nil || *r.RelatedKind != dcim.ObjectKindAsset || *r.RelatedID != a) {
				t.Errorf("%s change related to %v/%v, want the asset", r.ObjectKind, r.RelatedKind, r.RelatedID)
			}
		}
		return got
	}
	if got := list(false, asset); len(got) != 0 {
		t.Errorf("without include_related the asset's own tab lists %v; nothing changed the asset row itself", got)
	}
	got := list(true, asset)
	for _, want := range []string{"interface/create", "interface/update", "ip_address/create", "journal_entry/create"} {
		if !got[want] {
			t.Errorf("asset tab with include_related is missing %s; got %v", want, got)
		}
	}
	// Another asset's interface is not ours.
	if n := len(list(true, other)); n != 1 {
		t.Errorf("the other asset sees %d kinds of change, want only its own interface create", n)
	}
	// The detail carries the diff: the mtu moved.
	var upd changes.ObjectChange
	_ = database.WithTenantTx(ctx, f.app, f.tenant, func(tx *sql.Tx) error {
		rows, _, err := changes.List(ctx, tx, changes.Filter{TenantID: f.tenant, ObjectKind: dcim.ObjectKindInterface, ObjectID: iface.ID, Action: changes.ActionUpdate})
		if err == nil && len(rows) == 1 {
			upd, err = changes.Get(ctx, tx, f.tenant, rows[0].ID)
		}
		return err
	})
	diff := changes.FieldDiffs(upd)
	if len(diff) != 1 || diff[0].Field != "mtu" || string(diff[0].After) != "9000" {
		t.Errorf("diff = %+v", diff)
	}
	_ = ip
}
