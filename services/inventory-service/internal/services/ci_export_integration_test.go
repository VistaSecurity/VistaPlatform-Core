package services

// The internal CI export (platform ADR-0002 D4, M3) and the link/presence
// source writes against a real Postgres: what a connector running OUTSIDE this
// service can read of the inventory, and that every read and write is scoped
// to the ONE tenant the call names.
//
// The connector-level behaviour (push scope, echo suppression, retirement,
// relationships) is pinned end to end in the integration service's CMDB tests,
// which drive the real binary through the real HTTP path. What is pinned HERE
// is the inventory's half: tenant isolation, the field allowlist, the retired
// state, approved-only relationships and the paging.
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

type ciFixture struct {
	*sourceFixture
	ci *CIExportService
}

func newCIFixture(t *testing.T) *ciFixture {
	t.Helper()
	f := newSourceFixture(t)
	return &ciFixture{sourceFixture: f, ci: NewCIExportService(f.db, NewAssetService(f.db))}
}

func (f *ciFixture) asset(t *testing.T, tenant uuid.UUID, host, status, extra string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := f.db.Exec(`
		INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path, asset_status, risk_score,
		                    owner_email, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1, $2, $3, $3, 'server', 'hardware.computer.server', $4, 75, 'owner@example.test', NOW(), NOW(), NOW(), NOW())`,
		id, tenant, host, status); err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	if extra != "" {
		if _, err := f.db.Exec(`UPDATE assets SET `+extra+` WHERE id = $1`, id); err != nil {
			t.Fatalf("update asset: %v", err)
		}
	}
	return id
}

func (f *ciFixture) edge(t *testing.T, tenant, from, to uuid.UUID, typ, status string) {
	t.Helper()
	if _, err := f.db.Exec(`INSERT INTO asset_relationships (tenant_id, from_asset_id, to_asset_id, type, status, source_kind)
		VALUES ($1, $2, $3, $4, $5, 'declared')`, tenant, from, to, typ, status); err != nil {
		t.Fatalf("insert edge: %v", err)
	}
}

func itemIDs(items []CIExportItem) map[uuid.UUID]CIExportItem {
	out := map[uuid.UUID]CIExportItem{}
	for _, it := range items {
		out[it.ID] = it
	}
	return out
}

// Tenant B's approved asset is never in tenant A's export, and the push scope
// (approved, not archived, not merged away) is the export's, not the caller's.
func TestIntegration_CIExport_ItemsAreTenantAndScopeLimited(t *testing.T) {
	f := newCIFixture(t)
	ctx := context.Background()
	a, b := f.tenant(t), f.tenant(t)
	approved := f.asset(t, a, "a-approved.example.test", "monitoring", "")
	pending := f.asset(t, a, "a-pending.example.test", "pending_approval", "")
	archived := f.asset(t, a, "a-archived.example.test", "archived", "")
	merged := f.asset(t, a, "a-merged.example.test", "monitoring", `metadata = metadata || '{"merged_into":"x"}'::jsonb`)
	otherTenants := f.asset(t, b, "b-approved.example.test", "monitoring", "")

	items, err := f.ci.ExportItems(ctx, a, uuid.Nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := itemIDs(items)
	if _, ok := got[approved]; !ok {
		t.Errorf("the approved asset is not exported")
	}
	for name, id := range map[string]uuid.UUID{"pending": pending, "archived": archived, "merged": merged, "tenant B's": otherTenants} {
		if _, ok := got[id]; ok {
			t.Errorf("the %s asset was exported to tenant A", name)
		}
	}
	it := got[approved]
	if it.Category != "infrastructure_asset" || it.RiskScore == nil || *it.RiskScore != 75 || it.RiskLevel != "High" {
		t.Errorf("exported item = %+v, want an infrastructure_asset scored 75 banded High", it)
	}
}

// Paging walks the whole scope once, in id order, whatever the page size.
func TestIntegration_CIExport_ItemsPageByID(t *testing.T) {
	f := newCIFixture(t)
	ctx := context.Background()
	tenant := f.tenant(t)
	var want []string
	for i := 0; i < 5; i++ {
		want = append(want, f.asset(t, tenant, uuid.NewString()[:8]+".example.test", "monitoring", "").String())
	}
	sort.Strings(want)
	var got []string
	after := uuid.Nil
	for pages := 0; pages < 10; pages++ {
		page, err := f.ci.ExportItems(ctx, tenant, after, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range page {
			got = append(got, it.ID.String())
		}
		if len(page) < 2 {
			break
		}
		after = page[len(page)-1].ID
	}
	if len(got) != len(want) {
		t.Fatalf("paged %d items, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("paged %v, want %v in id order", got, want)
		}
	}
}

// Detail: only this tenant's ids answer; the retired state is the complement
// of the push scope; the fields are the allowlist and nothing else.
func TestIntegration_CIExport_AssetsDetail(t *testing.T) {
	f := newCIFixture(t)
	ctx := context.Background()
	a, b := f.tenant(t), f.tenant(t)
	live := f.asset(t, a, "a-live.example.test", "monitoring", "")
	archived := f.asset(t, a, "a-archived.example.test", "archived", "")
	stale := f.asset(t, a, "a-stale.example.test", "monitoring", "stale_status = 'archived'")
	merged := f.asset(t, a, "a-merged.example.test", "monitoring", `metadata = metadata || '{"merged_into":"x"}'::jsonb`)
	deleted := f.asset(t, a, "a-deleted.example.test", "monitoring", "deleted_at = NOW()")
	foreign := f.asset(t, b, "b-live.example.test", "monitoring", "")
	if err := f.svc.writeFacts(ctx, a, live, identity.Source{Kind: identity.SourceImported, Ref: "cmdb:p"},
		[]SourceFact{{Key: "os.name", Value: "Ubuntu"}}, time.Now().UTC()); err != nil {
		t.Fatalf("write fact: %v", err)
	}
	if _, err := f.svc.identity.AttachIdentifiers(ctx, identity.AssetRef{TenantID: a.String(), ID: live.String()},
		[]identity.Identifier{{Kind: identity.KindCMDBSysID, Value: "SRV1", Scope: "profile-1", Confidence: 1,
			Source: identity.Source{Kind: identity.SourceImported, Ref: "cmdb:profile-1"}}}); err != nil {
		t.Fatalf("attach identifier: %v", err)
	}

	out, err := f.ci.ExportAssets(ctx, a, CIExportAssetQuery{
		AssetIDs: []uuid.UUID{live, archived, stale, merged, deleted, foreign},
		Fields:   true, FactKeys: []string{"os.name"}, CryptoPosture: true,
		IdentifierKind: string(identity.KindCMDBSysID), IdentifierScope: "profile-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[uuid.UUID]CIExportAsset{}
	for _, x := range out {
		byID[x.ID] = x
	}
	if _, ok := byID[foreign]; ok {
		t.Fatal("tenant B's asset answered tenant A's export")
	}
	if len(byID) != 5 {
		t.Fatalf("exported %d assets, want 5", len(byID))
	}
	if byID[live].Retired {
		t.Error("a live asset is reported retired")
	}
	for name, id := range map[string]uuid.UUID{"archived": archived, "stale-archived": stale, "merged": merged, "deleted": deleted} {
		if !byID[id].Retired {
			t.Errorf("the %s asset is not reported retired", name)
		}
	}
	l := byID[live]
	allowed := map[string]bool{}
	for _, n := range CIExportAssetFieldNames() {
		allowed[n] = true
	}
	for k := range l.Fields {
		if !allowed[k] {
			t.Errorf("field %q is exported but not on the allowlist", k)
		}
	}
	if l.Fields["hostname"] != "a-live.example.test" || l.Fields["owner_email"] != "owner@example.test" || l.Fields["class_key"] != "server" {
		t.Errorf("fields = %v", l.Fields)
	}
	if l.Facts["os.name"] != "Ubuntu" {
		t.Errorf("facts = %v", l.Facts)
	}
	if len(l.Identifiers) != 1 || l.Identifiers[0] != "SRV1" {
		t.Errorf("identifiers = %v, want [SRV1]", l.Identifiers)
	}
	if l.CryptoPosture == nil {
		t.Error("the live asset has no crypto posture")
	}
	if byID[archived].CryptoPosture != nil {
		t.Error("a retired asset carries a crypto posture")
	}

	// Unregistered facts and non-link identifier kinds are refused as asked.
	var qe *ErrCIExportQuery
	if _, err := f.ci.ExportAssets(ctx, a, CIExportAssetQuery{AssetIDs: []uuid.UUID{live}, FactKeys: []string{"no.such.key"}}); !errors.As(err, &qe) {
		t.Errorf("an unregistered fact key = %v, want a query error", err)
	}
	if _, err := f.ci.ExportAssets(ctx, a, CIExportAssetQuery{AssetIDs: []uuid.UUID{live}, IdentifierKind: "serial_number", IdentifierScope: "x"}); !errors.As(err, &qe) {
		t.Errorf("a serial-number identifier export = %v, want a query error", err)
	}
}

// Only approved edges, only this tenant's.
func TestIntegration_CIExport_RelationshipsAreApprovedAndTenantScoped(t *testing.T) {
	f := newCIFixture(t)
	ctx := context.Background()
	a, b := f.tenant(t), f.tenant(t)
	x, y := f.asset(t, a, "a-x.example.test", "monitoring", ""), f.asset(t, a, "a-y.example.test", "monitoring", "")
	bx, by := f.asset(t, b, "b-x.example.test", "monitoring", ""), f.asset(t, b, "b-y.example.test", "monitoring", "")
	f.edge(t, a, x, y, "runs_on", "active")
	f.edge(t, a, y, x, "depends_on", "pending")
	f.edge(t, b, bx, by, "runs_on", "active")

	rels, err := f.ci.ExportRelationships(ctx, a, uuid.Nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rels) != 1 || rels[0].FromAssetID != x || rels[0].ToAssetID != y || rels[0].Type != "runs_on" {
		t.Fatalf("relationships = %+v, want only tenant A's approved x runs_on y", rels)
	}
}

// A link or a presence change naming another tenant's asset writes nothing
// and says not_found.
func TestIntegration_SourceLinksAndPresence_AreTenantScoped(t *testing.T) {
	f := newCIFixture(t)
	ctx := context.Background()
	a, b := f.tenant(t), f.tenant(t)
	mine := f.asset(t, a, "a-mine.example.test", "monitoring", "")
	theirs := f.asset(t, b, "b-theirs.example.test", "monitoring", "")
	src := identity.Source{Kind: identity.SourceImported, Ref: "cmdb:profile-1"}

	res, err := f.svc.AttachLinks(ctx, a, src, []SourceLink{
		{AssetID: mine, Kind: "cmdb_sys_id", Value: "SRV-A", Scope: "profile-1"},
		{AssetID: theirs, Kind: "cmdb_sys_id", Value: "SRV-B", Scope: "profile-1"},
		{AssetID: mine, Kind: "serial_number", Value: "SN", Scope: "profile-1"},
		{AssetID: mine, Kind: "cmdb_sys_id", Value: "SRV-C", Scope: ""},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{SourceItemRecorded, SourceItemNotFound, SourceOutcomeError, SourceOutcomeError}
	for i, w := range want {
		if res[i].Outcome != w {
			t.Errorf("link %d = %+v, want %s", i, res[i], w)
		}
	}
	// Refused by this service's own rules, not by whatever the identity
	// repository happens to make of the item.
	if !strings.Contains(res[2].Error, "is not a source link") {
		t.Errorf("a serial-number link = %+v; want refused as not a source link", res[2])
	}
	if !strings.Contains(res[3].Error, "needs its scope") {
		t.Errorf("an unscoped link = %+v; want refused for its missing scope", res[3])
	}
	var n int
	if err := f.db.QueryRow(`SELECT count(*) FROM asset_identifiers WHERE kind = 'cmdb_sys_id' AND value = 'SRV-B'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("a link naming tenant B's asset was written")
	}
	if err := f.db.QueryRow(`SELECT count(*) FROM asset_identifiers WHERE tenant_id = $1 AND asset_id = $2 AND kind = 'cmdb_sys_id' AND value = 'SRV-A' AND scope = 'profile-1'`, a, mine).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Error("tenant A's link was not attached")
	}

	pres, err := f.svc.RecordPresence(ctx, a, src, "servicenow", []SourcePresence{
		{AssetID: mine, Presence: "absent", Reason: "retired in ServiceNow"},
		{AssetID: theirs, Presence: "absent", Reason: "retired in ServiceNow"},
		{AssetID: mine, Presence: "gone"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, w := range []string{SourceItemRecorded, SourceItemNotFound, SourceOutcomeError} {
		if pres[i].Outcome != w {
			t.Errorf("presence %d = %+v, want %s", i, pres[i], w)
		}
	}
	if err := f.db.QueryRow(`SELECT count(*) FROM asset_history WHERE asset_id = $1 AND changes_json ? 'source_presence'`, theirs).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("a presence change naming tenant B's asset was written on its timeline")
	}
	var presence string
	if err := f.db.QueryRow(`SELECT changes_json->'source_presence'->>'presence' FROM asset_history
		WHERE tenant_id = $1 AND asset_id = $2 AND changes_json ? 'source_presence'`, a, mine).Scan(&presence); err != nil {
		t.Fatalf("read presence: %v", err)
	}
	if presence != "absent" {
		t.Errorf("presence = %q, want absent", presence)
	}
}
