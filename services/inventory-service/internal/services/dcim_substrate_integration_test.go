package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/journal"
	"github.com/vistasecurity/vistaplatform/shared/dcim/tags"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// "Done means" for BUILD_PLAN row 0.3, at the service layer: on a real asset a
// tenant adds a journal entry and tags that persist, the change log shows
// them, and another tenant can neither read nor write them — through the
// app-role pool production uses, so RLS is live.
func TestIntegration_DcimSubstrate_AssetJournalAndTags(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	a, b := testdb.NewTenant(t, owner), testdb.NewTenant(t, owner)
	asset := uuid.New()
	if _, err := owner.Exec(`
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1, $2, 'substrate.example.test', 'server', 'hardware.computer.server', 'monitoring', NOW(), NOW(), NOW(), NOW())`, asset, a); err != nil {
		t.Fatalf("seed asset: %v", err)
	}

	svc := NewDcimSubstrateService(app)
	ctx := changes.WithSource(changes.WithActor(context.Background(), changes.Actor{UserID: uuid.New(), UserName: "op@example.test"}), changes.SourceUI)

	e, err := svc.AddJournal(ctx, a, dcim.ObjectKindAsset, asset, journal.KindInfo, "racked in MDF row 2")
	if err != nil {
		t.Fatalf("add journal: %v", err)
	}
	tg, err := svc.CreateTag(ctx, a, tags.Input{Name: "PCI scope"})
	if err != nil {
		t.Fatalf("create tag: %v", err)
	}
	if _, err := svc.SetObjectTags(ctx, a, dcim.ObjectKindAsset, asset, []uuid.UUID{tg.ID}); err != nil {
		t.Fatalf("set tags: %v", err)
	}

	entries, total, err := svc.ListJournal(ctx, a, dcim.ObjectKindAsset, asset, 10, 0)
	if err != nil || total != 1 || entries[0].ID != e.ID {
		t.Fatalf("journal read back: %v total=%d %+v", err, total, entries)
	}
	got, err := svc.ObjectTags(ctx, a, dcim.ObjectKindAsset, asset)
	if err != nil || len(got) != 1 || got[0].Slug != "pci-scope" {
		t.Fatalf("tags read back: %v %+v", err, got)
	}
	log, total, err := svc.ListChanges(ctx, changes.Filter{TenantID: a, ObjectKind: dcim.ObjectKindAsset, ObjectID: asset})
	if err != nil || total != 1 || log[0].ChangedFields[0] != "tags" {
		t.Fatalf("asset change log: %v total=%d %+v", err, total, log)
	}

	// Tenant B: the asset does not exist for it — reads and writes are 404s,
	// not empty successes and not writes onto A's asset.
	if _, _, err := svc.ListJournal(ctx, b, dcim.ObjectKindAsset, asset, 10, 0); !errors.Is(err, ErrDcimObjectNotFound) {
		t.Errorf("tenant B read A's journal: %v", err)
	}
	if _, err := svc.AddJournal(ctx, b, dcim.ObjectKindAsset, asset, journal.KindInfo, "x"); !errors.Is(err, ErrDcimObjectNotFound) {
		t.Errorf("tenant B wrote on A's asset: %v", err)
	}
	if _, err := svc.SetObjectTags(ctx, b, dcim.ObjectKindAsset, asset, nil); !errors.Is(err, ErrDcimObjectNotFound) {
		t.Errorf("tenant B set tags on A's asset: %v", err)
	}
	if list, err := svc.ListTags(ctx, b); err != nil || len(list) != 0 {
		t.Errorf("tenant B sees tags: %v %+v", err, list)
	}
	if _, err := svc.UpdateTag(ctx, b, tg.ID, TagPatch{}); !errors.Is(err, tags.ErrNotFound) {
		t.Errorf("tenant B edited A's tag: %v", err)
	}

	// A kind whose table has not shipped is "no such object", not a 500.
	if _, _, err := svc.ListJournal(ctx, a, dcim.ObjectKindRack, uuid.New(), 10, 0); !errors.Is(err, ErrDcimObjectNotFound) {
		t.Errorf("journal on an unshipped kind: %v", err)
	}

	// Renaming a tag whose slug was generated regenerates it.
	name := "PCI DSS scope"
	up, err := svc.UpdateTag(ctx, a, tg.ID, TagPatch{Name: &name})
	if err != nil || up.Slug != "pci-dss-scope" {
		t.Errorf("rename: %v %+v", err, up)
	}
	if err := svc.DeleteTag(ctx, a, tg.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := svc.ObjectTags(ctx, a, dcim.ObjectKindAsset, asset); len(got) != 0 {
		t.Errorf("deleted tag still on the asset: %+v", got)
	}
}
