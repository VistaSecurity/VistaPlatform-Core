package services

// DB-integration tests for DCIM gap 1: virtual device contexts and an
// interface's membership of them. Skipped unless TEST_DATABASE_URL is set; run
// with make test-integration-db. The services run on the NON-OWNER app role,
// so RLS is in force as in production.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/shared/query"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func vdcSeedIP(t *testing.T, owner *sql.DB, tenant, iface uuid.UUID, addr string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	var assigned any
	if iface != uuid.Nil {
		assigned = iface
	}
	kind := any(nil)
	if assigned != nil {
		kind = "interface"
	}
	if err := owner.QueryRow(`INSERT INTO ip_addresses (tenant_id, address, assigned_kind, assigned_id) VALUES ($1, $2, $3, $4) RETURNING id`,
		tenant, addr, kind, assigned).Scan(&id); err != nil {
		t.Fatalf("seed ip %s: %v", addr, err)
	}
	return id
}

func vdcCreate(t *testing.T, hw *HardwareService, ctx context.Context, tenant uuid.UUID, body map[string]any) map[string]any {
	t.Helper()
	raw, err := hw.Create(ctx, tenant, HardwareVirtualDeviceContext, compBody(t, body))
	if err != nil {
		t.Fatalf("create context %v: %v", body, err)
	}
	return compDecode(t, raw)
}

// A context is the asset's: CRUD through the engine, NetBox's status set,
// identity and identifier unique per asset, primary addresses of the right
// family on the asset's interfaces, every write in the change log, and the
// asset's delete taking the context with it.
//
// Mutation: drop the identifier range check → the out-of-range message is
// lost; drop the oneOf(operational_status) check → "unknown" is stored
// (the CHECK answers 400 too, so drop both to see it land); drop
// checkContextPrimaryIP → the IPv6-into-primary_ip4 and the other asset's
// address are accepted; drop the identifier unique index → the duplicate
// identifier is accepted.
func TestIntegration_VirtualDeviceContexts_CRUDAndRules(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	hw := NewHardwareService(app)
	ifs := NewInterfaceService(app)
	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")
	other := ifaceSeedAsset(t, owner, tenant, "monitoring")
	eth, err := ifs.Create(ctx, tenant, uuid.Nil, InterfaceInput{AssetID: asset, Name: "port1", Type: "1000base-t"})
	if err != nil {
		t.Fatal(err)
	}
	otherEth, err := ifs.Create(ctx, tenant, uuid.Nil, InterfaceInput{AssetID: other, Name: "port1", Type: "1000base-t"})
	if err != nil {
		t.Fatal(err)
	}
	v4 := vdcSeedIP(t, owner, tenant, eth.ID, "10.20.0.1/24")
	v6 := vdcSeedIP(t, owner, tenant, eth.ID, "2001:db8::1/64")
	foreign := vdcSeedIP(t, owner, tenant, otherEth.ID, "10.30.0.1/24")
	loose := vdcSeedIP(t, owner, tenant, uuid.Nil, "10.40.0.1/24")

	c := vdcCreate(t, hw, ctx, tenant, map[string]any{"asset_id": asset, "name": "vsys1", "identifier": 1,
		"primary_ip4_id": v4, "primary_ip6_id": v6})
	if c["operational_status"] != "active" || c["status"] != "active" || c["source_kind"] != "declared" {
		t.Errorf("defaults: %v", c)
	}
	id := uuid.MustParse(c["id"].(string))

	for name, body := range map[string]map[string]any{
		"unknown status":        {"asset_id": asset, "name": "a", "operational_status": "unknown"},
		"negative identifier":   {"asset_id": asset, "name": "b", "identifier": -1},
		"identifier too big":    {"asset_id": asset, "name": "c", "identifier": 40000},
		"v6 as primary_ip4":     {"asset_id": asset, "name": "d", "primary_ip4_id": v6},
		"v4 as primary_ip6":     {"asset_id": asset, "name": "e", "primary_ip6_id": v4},
		"other asset's address": {"asset_id": asset, "name": "f", "primary_ip4_id": foreign},
		"unassigned address":    {"asset_id": asset, "name": "g", "primary_ip4_id": loose},
		"no such address":       {"asset_id": asset, "name": "h", "primary_ip4_id": uuid.New()},
		"empty name":            {"asset_id": asset, "name": ""},
		"no such business unit": {"asset_id": asset, "name": "i", "business_unit_id": uuid.New()},
	} {
		if _, err := hw.Create(ctx, tenant, HardwareVirtualDeviceContext, compBody(t, body)); !errors.Is(err, ErrIPAMInvalid) {
			t.Errorf("%s: %v, want invalid", name, err)
		}
	}
	// The range is the service's, so the caller is told it (the column is a
	// smallint and would otherwise answer a bare out-of-range error).
	if _, err := hw.Create(ctx, tenant, HardwareVirtualDeviceContext, compBody(t, map[string]any{"asset_id": asset, "name": "j", "identifier": 40000})); err == nil ||
		!strings.Contains(err.Error(), "0 to 32767") {
		t.Errorf("identifier out of range: %v, want the 0 to 32767 rule", err)
	}
	if _, err := hw.Create(ctx, tenant, HardwareVirtualDeviceContext, compBody(t, map[string]any{"asset_id": asset, "name": "vsys1"})); !errors.Is(err, ErrIPAMConflict) {
		t.Errorf("same name on the asset: %v, want conflict", err)
	}
	if _, err := hw.Create(ctx, tenant, HardwareVirtualDeviceContext, compBody(t, map[string]any{"asset_id": asset, "name": "vsys2", "identifier": 1})); !errors.Is(err, ErrIPAMConflict) {
		t.Errorf("same identifier on the asset: %v, want conflict", err)
	}
	// The same name and identifier on ANOTHER asset is fine.
	vdcCreate(t, hw, ctx, tenant, map[string]any{"asset_id": other, "name": "vsys1", "identifier": 1})

	if _, err := hw.Update(ctx, tenant, HardwareVirtualDeviceContext, id, compBody(t, map[string]any{"asset_id": other})); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("moving a context to another asset: %v, want invalid", err)
	}
	raw, err := hw.Update(ctx, tenant, HardwareVirtualDeviceContext, id, compBody(t, map[string]any{"operational_status": "planned", "primary_ip6_id": nil}))
	if err != nil {
		t.Fatal(err)
	}
	if got := compDecode(t, raw); got["operational_status"] != "planned" || got["primary_ip6_id"] != nil {
		t.Errorf("after patch: %v", got)
	}
	list, total, err := hw.ListForAsset(ctx, tenant, asset, HardwareVirtualDeviceContext, IPAMListParams{Limit: 50})
	if err != nil || total != 1 || len(list) != 1 {
		t.Fatalf("asset list: %d (%v)", total, err)
	}
	if _, total, _ := hw.List(ctx, tenant, HardwareVirtualDeviceContext, IPAMListParams{Limit: 50, Filters: map[string]string{"operational_status": "planned"}}); total != 1 {
		t.Errorf("operational_status filter: %d, want 1", total)
	}

	// Deleting the primary address clears the reference (ON DELETE SET NULL).
	if _, err := owner.Exec(`DELETE FROM ip_addresses WHERE id = $1`, v4); err != nil {
		t.Fatal(err)
	}
	if raw, err := hw.Get(ctx, tenant, HardwareVirtualDeviceContext, id); err != nil || compDecode(t, raw)["primary_ip4_id"] != nil {
		t.Errorf("after deleting the address: %s (%v)", raw, err)
	}

	var n int
	if err := owner.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND object_kind = 'virtual_device_context' AND object_id = $2`, tenant, id).Scan(&n); err != nil || n < 2 {
		t.Errorf("change records: %d (%v), want the create and the update", n, err)
	}
	if _, err := owner.Exec(`DELETE FROM assets WHERE id = $1`, asset); err != nil {
		t.Fatal(err)
	}
	if _, err := hw.Get(ctx, tenant, HardwareVirtualDeviceContext, id); !errors.Is(err, ErrIPAMNotFound) {
		t.Errorf("context outlived its asset: %v", err)
	}
}

// An interface's membership is the junction: written by id or by name, only
// contexts of the interface's own asset, read back as names, {id, name} and
// ids, and cleared by an empty list. The context's delete removes the link.
//
// Mutation: drop the asset check in ifaceResolveContexts (the count) → the
// other asset's context is accepted; drop ifaceReplaceContexts from Patch →
// the membership never changes; read vdcs from i.vdcs again → the read fails,
// the column is gone.
func TestIntegration_VirtualDeviceContexts_InterfaceMembership(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	hw := NewHardwareService(app)
	ifs := NewInterfaceService(app)
	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")
	other := ifaceSeedAsset(t, owner, tenant, "monitoring")
	a := vdcCreate(t, hw, ctx, tenant, map[string]any{"asset_id": asset, "name": "root"})
	b := vdcCreate(t, hw, ctx, tenant, map[string]any{"asset_id": asset, "name": "customer-a"})
	x := vdcCreate(t, hw, ctx, tenant, map[string]any{"asset_id": other, "name": "root"})
	aID, bID, xID := uuid.MustParse(a["id"].(string)), uuid.MustParse(b["id"].(string)), uuid.MustParse(x["id"].(string))

	// Create by name.
	got, err := ifs.Create(ctx, tenant, uuid.Nil, InterfaceInput{AssetID: asset, Name: "port1", Type: "1000base-t", VDCs: []string{"root"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.VDCs) != 1 || got.VDCs[0] != "root" || len(got.VirtualDeviceContexts) != 1 || got.VirtualDeviceContexts[0].ID != aID ||
		len(got.VirtualDeviceContextIDs) != 1 || got.VirtualDeviceContextIDs[0] != aID {
		t.Fatalf("created by name: %+v / %+v / %v", got.VDCs, got.VirtualDeviceContexts, got.VirtualDeviceContextIDs)
	}
	if _, err := ifs.Create(ctx, tenant, uuid.Nil, InterfaceInput{AssetID: asset, Name: "port2", Type: "1000base-t", VDCs: []string{"nope"}}); err == nil {
		t.Error("a name that is no context of the asset was accepted")
	}
	if _, err := ifs.Create(ctx, tenant, uuid.Nil, InterfaceInput{AssetID: asset, Name: "port3", Type: "1000base-t", VirtualDeviceContextIDs: []uuid.UUID{xID}}); err == nil {
		t.Error("another asset's context was accepted on create")
	}

	patch := func(body string) (Interface, error) {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatal(err)
		}
		return ifs.Patch(ctx, tenant, got.ID, m)
	}
	if out, err := patch(fmt.Sprintf(`{"virtual_device_context_ids":["%s","%s"]}`, aID, bID)); err != nil || len(out.VDCs) != 2 || out.VDCs[0] != "customer-a" || out.VDCs[1] != "root" {
		t.Errorf("patch by ids: %v (%v)", out.VDCs, err)
	}
	if _, err := patch(fmt.Sprintf(`{"virtual_device_context_ids":["%s"]}`, xID)); err == nil {
		t.Error("another asset's context was accepted on patch")
	}
	var ierr *InterfaceValidationError
	if _, err := patch(fmt.Sprintf(`{"virtual_device_context_ids":["%s"],"vdcs":["root"]}`, aID)); !errors.As(err, &ierr) {
		t.Errorf("ids and names together: %v, want a validation error", err)
	}
	// A patch that names neither keeps the membership.
	if out, err := patch(`{"description":"uplink"}`); err != nil || len(out.VirtualDeviceContextIDs) != 2 {
		t.Errorf("unrelated patch dropped the membership: %v (%v)", out.VirtualDeviceContextIDs, err)
	}
	if out, err := patch(`{"vdcs":["root"]}`); err != nil || len(out.VirtualDeviceContextIDs) != 1 || out.VirtualDeviceContextIDs[0] != aID {
		t.Errorf("patch by name: %v (%v)", out.VirtualDeviceContextIDs, err)
	}
	// The legacy column is gone: the junction is the only membership store.
	var legacy bool
	if err := owner.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'interfaces' AND column_name = 'vdcs')`).Scan(&legacy); err != nil || legacy {
		t.Errorf("interfaces.vdcs still exists (%v), want it dropped", err)
	}
	// The membership change is in the interface's change log.
	var changed bool
	if err := owner.QueryRow(`SELECT EXISTS (SELECT 1 FROM object_changes WHERE tenant_id = $1 AND object_kind = 'interface' AND object_id = $2
		AND 'virtual_device_context_ids' = ANY (changed_fields))`, tenant, got.ID).Scan(&changed); err != nil || !changed {
		t.Errorf("no interface change names virtual_device_context_ids (%v)", err)
	}
	if err := hw.Delete(ctx, tenant, HardwareVirtualDeviceContext, aID); err != nil {
		t.Fatal(err)
	}
	if cur, err := ifs.Get(ctx, tenant, got.ID); err != nil || len(cur.VDCs) != 0 || len(cur.VirtualDeviceContexts) != 0 {
		t.Errorf("after deleting the context: %v / %v (%v)", cur.VDCs, cur.VirtualDeviceContexts, err)
	}
	if out, err := patch(`{"virtual_device_context_ids":[]}`); err != nil || len(out.VirtualDeviceContextIDs) != 0 {
		t.Errorf("clearing: %v (%v)", out.VirtualDeviceContextIDs, err)
	}
}

// Both tables are tenant-isolated: another tenant lists no context, reads no
// membership, and cannot insert either row against the first tenant's ids.
//
// Mutation: drop either <table>_tenant_isolation policy (or its ENABLE ROW
// LEVEL SECURITY) in the gap1 block → that subtest goes red.
func TestIntegration_VirtualDeviceContexts_RLS(t *testing.T) {
	owner, app, tenantA := ifaceFixture(t)
	tenantB := testdb.NewTenant(t, owner)
	ctx := ifaceActorCtx()
	hw := NewHardwareService(app)
	ifs := NewInterfaceService(app)
	asset := ifaceSeedAsset(t, owner, tenantA, "monitoring")
	c := vdcCreate(t, hw, ctx, tenantA, map[string]any{"asset_id": asset, "name": "vdom-a"})
	eth, err := ifs.Create(ctx, tenantA, uuid.Nil, InterfaceInput{AssetID: asset, Name: "port1", Type: "1000base-t", VDCs: []string{"vdom-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, total, err := hw.List(ctx, tenantB, HardwareVirtualDeviceContext, IPAMListParams{Limit: 50}); err != nil || total != 0 {
		t.Errorf("tenant B listed %d of tenant A's contexts (%v)", total, err)
	}
	if _, err := hw.Get(ctx, tenantB, HardwareVirtualDeviceContext, uuid.MustParse(c["id"].(string))); !errors.Is(err, ErrIPAMNotFound) {
		t.Errorf("tenant B read tenant A's context: %v", err)
	}
	testdb.AsTenant(t, owner, tenantB, func(tx *sql.Tx) {
		var n int
		if err := tx.QueryRow(`SELECT count(*) FROM interface_virtual_device_contexts`).Scan(&n); err != nil || n != 0 {
			t.Errorf("tenant B sees %d memberships (%v)", n, err)
		}
		for table, stmt := range map[string]string{
			"virtual_device_contexts": fmt.Sprintf(`INSERT INTO virtual_device_contexts (tenant_id, asset_id, name) VALUES ('%s', '%s', 'x')`, tenantA, asset),
			"interface_virtual_device_contexts": fmt.Sprintf(`INSERT INTO interface_virtual_device_contexts (tenant_id, interface_id, virtual_device_context_id) VALUES ('%s', '%s', '%s')`,
				tenantA, eth.ID, c["id"]),
		} {
			if _, err := tx.Exec("SAVEPOINT s"); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(stmt); err == nil {
				t.Errorf("%s: tenant B inserted a row for tenant A", table)
			}
			if _, err := tx.Exec("ROLLBACK TO SAVEPOINT s"); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// An asset merge moves the contexts: a same-name pair collapses onto the
// survivor's (its interface memberships follow), the rest move, and an
// identifier the survivor already uses is released rather than aborting the
// merge.
//
// Mutation: drop the "move contexts" step → contexts are left on the
// merged-away asset; drop the re-point step → the moved interface loses its
// membership with the dropped duplicate; drop the identifier release → the
// merge fails on virtual_device_contexts_identifier_uniq.
func TestIntegration_VirtualDeviceContexts_MergeMovesThem(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	hw := NewHardwareService(app)
	ifs := NewInterfaceService(app)
	source := ifaceSeedAsset(t, owner, tenant, "monitoring")
	survivor := ifaceSeedAsset(t, owner, tenant, "monitoring")
	vdcCreate(t, hw, ctx, tenant, map[string]any{"asset_id": source, "name": "root", "identifier": 0})
	vdcCreate(t, hw, ctx, tenant, map[string]any{"asset_id": source, "name": "tenant-b", "identifier": 5})
	keep := vdcCreate(t, hw, ctx, tenant, map[string]any{"asset_id": survivor, "name": "root", "identifier": 0, "description": "survivor's"})
	vdcCreate(t, hw, ctx, tenant, map[string]any{"asset_id": survivor, "name": "other", "identifier": 5})
	eth, err := ifs.Create(ctx, tenant, uuid.Nil, InterfaceInput{AssetID: source, Name: "port9", Type: "1000base-t", VDCs: []string{"root", "tenant-b"}})
	if err != nil {
		t.Fatal(err)
	}

	tx, err := sqlx.NewDb(owner, "postgres").BeginTxx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := moveAssetChildren(context.Background(), tx, tenant, source, survivor); err != nil {
		_ = tx.Rollback()
		t.Fatalf("moveAssetChildren: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if n := compCount(t, owner, "virtual_device_contexts", tenant, source); n != 0 {
		t.Errorf("%d contexts left on the merged-away asset", n)
	}
	if n := compCount(t, owner, "virtual_device_contexts", tenant, survivor); n != 3 {
		t.Errorf("survivor holds %d contexts, want root, other and the moved tenant-b", n)
	}
	var ident sql.NullInt64
	if err := owner.QueryRow(`SELECT identifier FROM virtual_device_contexts WHERE tenant_id = $1 AND asset_id = $2 AND name = 'tenant-b'`, tenant, survivor).Scan(&ident); err != nil || ident.Valid {
		t.Errorf("moved tenant-b identifier = %v (%v), want released (the survivor's other uses 5)", ident, err)
	}
	cur, err := ifs.Get(ctx, tenant, eth.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cur.AssetID != survivor || len(cur.VDCs) != 2 {
		t.Fatalf("moved interface: asset %s, contexts %v", cur.AssetID, cur.VDCs)
	}
	found := false
	for _, c := range cur.VirtualDeviceContexts {
		if c.ID.String() == keep["id"] {
			found = true
		}
	}
	if !found {
		t.Errorf("the moved interface's root membership does not name the survivor's root: %+v", cur.VirtualDeviceContexts)
	}
}

// The query language reaches an interface's contexts (QUERY_LANGUAGE §15):
// `interface:(virtual_device_context:"vsys1")` finds the asset whose
// interface is in vsys1, and `!=` finds interfaces in no context of that name.
//
// Mutation: read the junction's name from the wrong side (vdc.description) in
// shapes.go's interface.virtual_device_context builder → the hit is lost.
func TestIntegration_VirtualDeviceContexts_Query(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	hw := NewHardwareService(app)
	ifs := NewInterfaceService(app)
	hit := ifaceSeedAsset(t, owner, tenant, "monitoring")
	miss := ifaceSeedAsset(t, owner, tenant, "monitoring")
	vdcCreate(t, hw, ctx, tenant, map[string]any{"asset_id": hit, "name": "vsys1"})
	vdcCreate(t, hw, ctx, tenant, map[string]any{"asset_id": miss, "name": "vsys2"})
	if _, err := ifs.Create(ctx, tenant, uuid.Nil, InterfaceInput{AssetID: hit, Name: "ethernet1/1", Type: "1000base-t", VDCs: []string{"vsys1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := ifs.Create(ctx, tenant, uuid.Nil, InterfaceInput{AssetID: miss, Name: "ethernet1/1", Type: "1000base-t", VDCs: []string{"vsys2"}}); err != nil {
		t.Fatal(err)
	}
	match := func(q string) map[uuid.UUID]bool {
		t.Helper()
		c, err := query.Compile(q, "asset", query.DefaultCatalog(), query.DefaultOptionsFor(query.DefaultCatalog()))
		if err != nil {
			t.Fatalf("compile %q: %v", q, err)
		}
		out := map[uuid.UUID]bool{}
		testdb.AsTenant(t, owner, tenant, func(tx *sql.Tx) {
			rows, err := tx.Query("SELECT a.id FROM assets a WHERE a.tenant_id = '"+tenant.String()+"' AND "+c.Where, c.Args...)
			if err != nil {
				t.Fatalf("run %q: %v", q, err)
			}
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var id uuid.UUID
				if err := rows.Scan(&id); err != nil {
					t.Fatal(err)
				}
				out[id] = true
			}
		})
		return out
	}
	if got := match(`interface:(virtual_device_context:"VSYS1")`); !got[hit] || len(got) != 1 {
		t.Errorf("in vsys1: %v", got)
	}
	if got := match(`interface:(virtual_device_context != "vsys1")`); !got[miss] || got[hit] || len(got) != 1 {
		t.Errorf("not in vsys1: %v", got)
	}
}
