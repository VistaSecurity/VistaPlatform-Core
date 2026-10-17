package services

// DB-integration tests for the interface store (DCIM BUILD_PLAN row 1.2).
// Skipped unless TEST_DATABASE_URL is set; run with make test-integration-db.
//
// The service runs on the NON-OWNER app role throughout, so RLS is in force
// exactly as in production; the owner connection only seeds.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/query"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
	"github.com/vistasecurity/vistaplatform/shared/testdb/dcimfixture"
)

func ifaceSeedAsset(t *testing.T, owner *sql.DB, tenant uuid.UUID, status string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := owner.Exec(`
		INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path, asset_status)
		VALUES ($1, $2, $3, $3, 'switch', 'hardware.network.switch', $4)`,
		id, tenant, "sw-"+id.String()[:8], status); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	return id
}

// ifaceSeedVLAN inserts a VLAN (row 1.3's table) for the tenant.
func ifaceSeedVLAN(t *testing.T, owner *sql.DB, tenant uuid.UUID, vid int) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := owner.QueryRow(`INSERT INTO vlans (tenant_id, vid, name) VALUES ($1, $2, $3) RETURNING id`,
		tenant, vid, fmt.Sprintf("vlan-%d", vid)).Scan(&id); err != nil {
		t.Fatalf("seed vlan: %v", err)
	}
	return id
}

// ifaceMemoryRecorder records every change the service hands it.
type ifaceMemoryRecorder struct {
	mu      sync.Mutex
	changes []InterfaceChange
}

func (r *ifaceMemoryRecorder) RecordInterfaceChange(_ context.Context, tx *sql.Tx, c InterfaceChange) error {
	if tx == nil {
		return errors.New("recorded outside the writer's transaction")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.changes = append(r.changes, c)
	return nil
}

func (r *ifaceMemoryRecorder) actions() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.changes))
	for _, c := range r.changes {
		out = append(out, string(c.Action)+":"+string(c.Source))
	}
	return out
}

func ifaceFixture(t *testing.T) (owner, app *sql.DB, tenant uuid.UUID) {
	t.Helper()
	owner = testdb.Connect(t)
	tenant = testdb.NewTenant(t, owner)
	app = testdb.ConnectAsAppRole(t, owner)
	return owner, app, tenant
}

func TestIntegration_Interfaces_RLS(t *testing.T) {
	owner, app, tenantA := ifaceFixture(t)
	tenantB := testdb.NewTenant(t, owner)
	ctx := ifaceActorCtx()
	svc := NewInterfaceService(app)

	assetA := ifaceSeedAsset(t, owner, tenantA, "monitoring")
	created, err := svc.Create(ctx, tenantA, uuid.Nil, InterfaceInput{
		AssetID: assetA, Name: "GigabitEthernet1/0/1", Type: "1000base-t", MACAddress: ifaceStrp("00:11:22:33:44:55"),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Tenant B sees none of it, by list, by get, or by MAC.
	list, total, err := svc.List(ctx, tenantB, InterfaceFilter{})
	if err != nil || total != 0 || len(list) != 0 {
		t.Fatalf("tenant B listed %d/%d of tenant A's interfaces (%v)", len(list), total, err)
	}
	if _, err := svc.Get(ctx, tenantB, created.ID); !errors.Is(err, ErrInterfaceNotFound) {
		t.Fatalf("tenant B got tenant A's interface: %v", err)
	}
	if list, _, _ := svc.List(ctx, tenantB, InterfaceFilter{MACAddress: "00:11:22:33:44:55"}); len(list) != 0 {
		t.Fatalf("tenant B found tenant A's interface by MAC")
	}

	// Writing a row for tenant A while scoped to tenant B is refused by the
	// policy's WITH CHECK, on all three tables.
	testdb.AsTenant(t, owner, tenantB, func(tx *sql.Tx) {
		for _, stmt := range []struct{ name, sql string }{
			{"interfaces", `INSERT INTO interfaces (tenant_id, asset_id, name, type) VALUES ($1, '` + assetA.String() + `', 'x', 'other')`},
			{"mac_addresses", `INSERT INTO mac_addresses (tenant_id, interface_id, mac) VALUES ($1, '` + created.ID.String() + `', '00:11:22:33:44:66')`},
			{"interface_tagged_vlans", `INSERT INTO interface_tagged_vlans (tenant_id, interface_id, vlan_id) VALUES ($1, '` + created.ID.String() + `', gen_random_uuid())`},
		} {
			if _, err := tx.Exec("SAVEPOINT s"); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(stmt.sql, tenantA); err == nil {
				t.Errorf("%s: a cross-tenant insert was accepted", stmt.name)
			}
			if _, err := tx.Exec("ROLLBACK TO SAVEPOINT s"); err != nil {
				t.Fatal(err)
			}
		}
	})

	// And tenant B reading the child tables directly sees nothing.
	testdb.AsTenant(t, owner, tenantB, func(tx *sql.Tx) {
		for _, tbl := range []string{"interfaces", "mac_addresses", "interface_tagged_vlans"} {
			var n int
			if err := tx.QueryRow("SELECT count(*) FROM " + tbl + " WHERE tenant_id = '" + tenantA.String() + "'").Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != 0 {
				t.Errorf("%s: tenant B reads %d of tenant A's rows", tbl, n)
			}
		}
	})
}

func TestIntegration_Interfaces_NameUniquePerAsset_IgnoresRejected(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	svc := NewInterfaceService(app)
	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")
	other := ifaceSeedAsset(t, owner, tenant, "monitoring")

	in := InterfaceInput{AssetID: asset, Name: "eth0", Type: "1000base-t"}
	first, err := svc.Create(ctx, tenant, uuid.Nil, in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.Create(ctx, tenant, uuid.Nil, in); !errors.Is(err, ErrInterfaceNameTaken) {
		t.Fatalf("second eth0 on one asset: want ErrInterfaceNameTaken, got %v", err)
	}
	// Case-sensitive, like NetBox: ETH0 is another interface.
	if _, err := svc.Create(ctx, tenant, uuid.Nil, InterfaceInput{AssetID: asset, Name: "ETH0", Type: "1000base-t"}); err != nil {
		t.Fatalf("ETH0 beside eth0 refused: %v", err)
	}
	// Another asset may have its own eth0.
	if _, err := svc.Create(ctx, tenant, uuid.Nil, InterfaceInput{AssetID: other, Name: "eth0", Type: "1000base-t"}); err != nil {
		t.Fatalf("eth0 on a second asset refused: %v", err)
	}
	// A rejected row does not hold the name.
	if _, err := owner.Exec(`UPDATE interfaces SET status = 'rejected' WHERE id = $1`, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(ctx, tenant, uuid.Nil, in); err != nil {
		t.Fatalf("eth0 beside a rejected eth0 refused: %v", err)
	}
}

func TestIntegration_UpsertObserved_NeverOverwritesDeclaredEnabled(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	svc := NewInterfaceService(app)
	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")

	off := false
	declared, err := svc.Create(ctx, tenant, uuid.Nil, InterfaceInput{
		AssetID: asset, Name: "GigabitEthernet1/0/24", Type: "1000base-t", Enabled: &off,
		Description: ifaceStrp("to core, shut pending change CHG-1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	speed := int64(1_000_000)
	res, err := svc.UpsertObserved(ctx, tenant, asset, "snmp", []ObservedInterface{{
		Name: "Gi1/0/24", Vendor: "cisco", MAC: "00:11:22:33:44:55", SpeedKbps: &speed,
		OperationalStatus: "up", AdminStatus: "up", Description: "uplink",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Created != 0 || res.Updated != 1 {
		t.Fatalf("Gi1/0/24 must fold onto the declared GigabitEthernet1/0/24: %s", res)
	}
	got, err := svc.Get(ctx, tenant, declared.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Enabled {
		t.Error("a measured admin status of up overwrote the declared enabled=false")
	}
	if got.Description == nil || *got.Description != "to core, shut pending change CHG-1" {
		t.Errorf("a measured ifAlias overwrote the declared description: %v", got.Description)
	}
	if got.AdminStatus == nil || *got.AdminStatus != "up" || got.OperationalStatus == nil || *got.OperationalStatus != "up" {
		t.Errorf("measured statuses not written: admin=%v oper=%v", got.AdminStatus, got.OperationalStatus)
	}
	if got.SpeedKbps == nil || *got.SpeedKbps != speed || got.MACAddress == nil || *got.MACAddress != "00:11:22:33:44:55" {
		t.Errorf("measured speed/MAC not written: %v %v", got.SpeedKbps, got.MACAddress)
	}
	if got.ObservationCount != 1 || got.SourceKind != "declared" {
		t.Errorf("observation_count=%d source_kind=%s; want 1, declared", got.ObservationCount, got.SourceKind)
	}

	// A NEW measured interface takes its asset's approval and the device's
	// admin state as its first `enabled`.
	pendingAsset := ifaceSeedAsset(t, owner, tenant, "pending_approval")
	if _, err := svc.UpsertObserved(ctx, tenant, pendingAsset, "agent", []ObservedInterface{
		{Name: "eth0", Vendor: "linux", AdminStatus: "down"},
	}); err != nil {
		t.Fatal(err)
	}
	list, _, err := svc.List(ctx, tenant, InterfaceFilter{AssetID: &pendingAsset})
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %d", err, len(list))
	}
	if list[0].Status != "pending" || list[0].Enabled || list[0].SourceKind != "measured" {
		t.Errorf("new observed interface on a pending asset: status=%s enabled=%t source=%s", list[0].Status, list[0].Enabled, list[0].SourceKind)
	}
	// Once the asset is approved, the next observation brings its pending
	// interfaces with it.
	if _, err := owner.Exec(`UPDATE assets SET asset_status = 'monitoring' WHERE tenant_id = $1 AND id = $2`, tenant, pendingAsset); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpsertObserved(ctx, tenant, pendingAsset, "agent", []ObservedInterface{{Name: "eth0", Vendor: "linux"}}); err != nil {
		t.Fatal(err)
	}
	if got, _ := svc.Get(ctx, tenant, list[0].ID); got.Status != "active" || got.Enabled {
		t.Errorf("after asset approval: status=%s enabled=%t; want active, still disabled", got.Status, got.Enabled)
	}
}

func TestIntegration_UpsertObserved_MarksAbsentStale(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	svc := NewInterfaceService(app)
	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")

	if _, err := svc.UpsertObserved(ctx, tenant, asset, "agent", []ObservedInterface{
		{Name: "eth0", Vendor: "linux"}, {Name: "eth1", Vendor: "linux"}, {Name: "eth2", Vendor: "linux"},
	}); err != nil {
		t.Fatal(err)
	}
	declared, err := svc.Create(ctx, tenant, uuid.Nil, InterfaceInput{AssetID: asset, Name: "bond0", Type: "lag"})
	if err != nil {
		t.Fatal(err)
	}
	// eth1 and bond0 last seen 40 days ago; eth2 yesterday.
	if _, err := owner.Exec(`UPDATE interfaces SET last_seen_at = now() - interval '40 days'
	                          WHERE asset_id = $1 AND name IN ('eth1', 'bond0')`, asset); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`UPDATE interfaces SET last_seen_at = now() - interval '1 day'
	                          WHERE asset_id = $1 AND name = 'eth2'`, asset); err != nil {
		t.Fatal(err)
	}
	res, err := svc.UpsertObserved(ctx, tenant, asset, "agent", []ObservedInterface{{Name: "eth0", Vendor: "linux"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.MarkedStale != 1 {
		t.Fatalf("want exactly eth1 marked stale, got %s", res)
	}
	byName := map[string]Interface{}
	list, _, _ := svc.List(ctx, tenant, InterfaceFilter{AssetID: &asset, Limit: 50})
	for _, i := range list {
		byName[i.Name] = i
	}
	if len(byName) != 4 {
		t.Fatalf("an absent interface was deleted: %v", byName)
	}
	if byName["eth1"].Status != "stale" {
		t.Errorf("eth1 (absent 40d): status %s, want stale", byName["eth1"].Status)
	}
	if byName["eth2"].Status != "active" {
		t.Errorf("eth2 (absent 1d, inside the window): status %s, want active", byName["eth2"].Status)
	}
	if byName["bond0"].Status != "active" || byName["bond0"].ID != declared.ID {
		t.Errorf("declared bond0 was swept: status %s", byName["bond0"].Status)
	}
	// Seen again → active again.
	if _, err := svc.UpsertObserved(ctx, tenant, asset, "agent", []ObservedInterface{{Name: "eth1", Vendor: "linux"}}); err != nil {
		t.Fatal(err)
	}
	if got, _ := svc.Get(ctx, tenant, byName["eth1"].ID); got.Status != "active" {
		t.Errorf("re-observed eth1: status %s, want active", got.Status)
	}
}

func TestIntegration_Interfaces_RecordsChanges(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	rec := &ifaceMemoryRecorder{}
	svc := NewInterfaceService(app).WithRecorder(rec)
	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")

	lag, err := svc.Create(ctx, tenant, uuid.Nil, InterfaceInput{AssetID: asset, Name: "Port-channel1", Type: "lag"})
	if err != nil {
		t.Fatal(err)
	}
	vlan := ifaceSeedVLAN(t, owner, tenant, 10)
	members, err := svc.BulkCreate(ctx, tenant, uuid.Nil, []InterfaceInput{
		{AssetID: asset, Name: "GigabitEthernet1/0/24", Type: "1000base-t", LagID: &lag.ID, Mode: ifaceStrp("tagged"), TaggedVLANIDs: []uuid.UUID{vlan}},
		{AssetID: asset, Name: "GigabitEthernet1/0/23", Type: "1000base-t", LagID: &lag.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(members[0].TaggedVLANIDs) != 1 || members[0].TaggedVLANIDs[0] != vlan || *members[0].LagID != lag.ID {
		t.Fatalf("member not stored as tagged LAG member: %+v", members[0])
	}
	if _, err := svc.Patch(ctx, tenant, members[1].ID, map[string]json.RawMessage{"description": json.RawMessage(`"spare"`)}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, tenant, lag.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpsertObserved(ctx, tenant, asset, "snmp", []ObservedInterface{{Name: "Gi1/0/1", Vendor: "cisco"}}); err != nil {
		t.Fatal(err)
	}

	got := fmt.Sprint(rec.actions())
	// create LAG, 2× create members, patch, delete LAG + 2 detached members,
	// intake create.
	want := "[create: create: create: update: delete: update: update: create:intake:snmp]"
	if got != want {
		t.Fatalf("changes recorded:\n got %s\nwant %s", got, want)
	}
	after, _ := svc.Get(ctx, tenant, members[0].ID)
	if after.LagID != nil {
		t.Errorf("deleting the LAG left the member pointing at it")
	}
}

// Budget (DATA_MODEL §12): the Interfaces tab's page for an asset with 200
// interfaces, on the app role, under 100 ms — beside the DCIM scale fixture's
// tenant (Small by default, §12's Scale1 with DCIM_SCALE=1). Recorded through
// dcimfixture.AssertUnder: informative on PRs, enforced nightly.
func TestIntegration_Interfaces_PageBudget(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	svc := NewInterfaceService(app)
	scale := dcimfixture.Small()
	if os.Getenv("DCIM_SCALE") == "1" {
		scale = dcimfixture.Scale1()
	}
	sum := dcimfixture.Populate(context.Background(), t, owner, tenant, scale)
	if sum.Counts["interfaces"] != scale.Interfaces() {
		t.Fatalf("fixture wrote %d interfaces, want %d (skipped: %v)", sum.Counts["interfaces"], scale.Interfaces(), sum.Skipped)
	}
	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")
	if _, err := owner.Exec(`
		INSERT INTO interfaces (tenant_id, asset_id, name, type, mac_address, mode)
		SELECT $1, $2, 'GigabitEthernet1/0/' || g, '1000base-t',
		       ('02:ff:00:00:' || lpad(to_hex(g / 256), 2, '0') || ':' || lpad(to_hex(g % 256), 2, '0'))::macaddr8,
		       'access'
		  FROM generate_series(1, 200) g`, tenant, asset); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`INSERT INTO mac_addresses (tenant_id, interface_id, mac, is_primary)
		SELECT tenant_id, id, mac_address, true FROM interfaces WHERE asset_id = $1`, asset); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`ANALYZE interfaces; ANALYZE mac_addresses`); err != nil {
		t.Fatal(err)
	}
	// Warm once, then take the best of five.
	if _, _, err := svc.List(ctx, tenant, InterfaceFilter{AssetID: &asset, Limit: 200}); err != nil {
		t.Fatal(err)
	}
	best := time.Hour
	for k := 0; k < 5; k++ {
		start := time.Now()
		list, total, err := svc.List(ctx, tenant, InterfaceFilter{AssetID: &asset, Limit: 200})
		el := time.Since(start)
		if err != nil || total != 200 || len(list) != 200 {
			t.Fatalf("list: %v total=%d len=%d", err, total, len(list))
		}
		if el < best {
			best = el
		}
		if list[1].Name != "GigabitEthernet1/0/2" {
			t.Fatalf("natural order broken: second row is %s", list[1].Name)
		}
	}
	t.Logf("tenant: %d assets, %d interfaces from the fixture", len(sum.AssetIDs), sum.Counts["interfaces"])
	dcimfixture.AssertUnder(t, "interfaces page (asset with 200 interfaces)", best, 100*time.Millisecond)
}

// The production recorder: a person's create and patch land in object_changes
// attributed to them; intake lands as intake:<producer> with no actor.
func TestIntegration_Interfaces_WritesObjectChanges(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	svc := NewInterfaceService(app)
	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")
	user := uuid.New()
	ctx := changes.WithSource(changes.WithActor(context.Background(), changes.Actor{UserID: user, UserName: "ops@example.test"}), changes.SourceUI)

	i, err := svc.Create(ctx, tenant, user, InterfaceInput{AssetID: asset, Name: "eth0", Type: "1000base-t"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Patch(ctx, tenant, i.ID, map[string]json.RawMessage{"mtu": json.RawMessage(`9000`)}); err != nil {
		t.Fatal(err)
	}
	// Without an actor a UI change is refused, and nothing is written.
	if _, err := svc.Create(context.Background(), tenant, uuid.Nil, InterfaceInput{AssetID: asset, Name: "eth9", Type: "1000base-t"}); !errors.Is(err, changes.ErrNoActor) {
		t.Fatalf("anonymous create: want changes.ErrNoActor, got %v", err)
	}
	if _, err := svc.UpsertObserved(context.Background(), tenant, asset, "agent", []ObservedInterface{{Name: "eth1", Vendor: "linux"}}); err != nil {
		t.Fatal(err)
	}

	rows, err := owner.Query(`SELECT action, source, coalesce(user_id::text, ''), changed_fields
	                            FROM object_changes WHERE tenant_id = $1 AND object_kind = 'interface'
	                           ORDER BY created_at, action`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var got []string
	for rows.Next() {
		var action, source, uid string
		var fields []byte
		if err := rows.Scan(&action, &source, &uid, &fields); err != nil {
			t.Fatal(err)
		}
		who := "nobody"
		if uid == user.String() {
			who = "user"
		}
		got = append(got, action+"/"+source+"/"+who)
	}
	want := "[create/ui/user update/ui/user create/intake:agent/nobody]"
	if fmt.Sprint(got) != want {
		t.Fatalf("object_changes:\n got %v\nwant %s", got, want)
	}
	var n int
	if err := owner.QueryRow(`SELECT count(*) FROM interfaces WHERE tenant_id = $1 AND name = 'eth9'`, tenant).Scan(&n); err != nil || n != 0 {
		t.Fatalf("the refused create left a row behind (%d, %v)", n, err)
	}
}

// ifaceActorCtx is a request context as changes.Middleware leaves it: a
// signed-in person using the UI.
func ifaceActorCtx() context.Context {
	return changes.WithSource(changes.WithActor(context.Background(),
		changes.Actor{UserID: uuid.New(), UserName: "tester@example.test"}), changes.SourceUI)
}

// The query language reaches interfaces (QUERY_LANGUAGE §15): the predicate
// the Inventory page sends finds the asset by an interface's MAC as the API
// shows it, not as macaddr8 stores it, and ignores a rejected interface.
func TestIntegration_Interfaces_QueryByMAC(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	svc := NewInterfaceService(app)
	hit := ifaceSeedAsset(t, owner, tenant, "monitoring")
	miss := ifaceSeedAsset(t, owner, tenant, "monitoring")
	if _, err := svc.Create(ctx, tenant, uuid.Nil, InterfaceInput{AssetID: hit, Name: "Gi1/0/24", Type: "1000base-t", MACAddress: ifaceStrp("00-11-22-33-44-55")}); err != nil {
		t.Fatal(err)
	}
	rej, err := svc.Create(ctx, tenant, uuid.Nil, InterfaceInput{AssetID: miss, Name: "eth0", Type: "1000base-t", MACAddress: ifaceStrp("00:11:22:33:44:66")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`UPDATE interfaces SET status = 'rejected' WHERE id = $1`, rej.ID); err != nil {
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
	if got := match(`interface:(mac_address:"00:11:22:33:44:55")`); !got[hit] || got[miss] || len(got) != 1 {
		t.Errorf("by MAC: %v", got)
	}
	if got := match(`interface:(mac_address:"00:11:22:33:44:66")`); len(got) != 0 {
		t.Errorf("a rejected interface's MAC matched: %v", got)
	}
	if got := match(`interface:(name = "Gi1/0/24" and type:1000base-t)`); !got[hit] || len(got) != 1 {
		t.Errorf("by name and type: %v", got)
	}
}

// A merge moves the merged-away asset's interfaces onto the survivor: a
// same-name pair keeps the survivor's row (with the source's extra MAC and
// observation count folded in), a LAG member of the source's duplicate LAG is
// re-pointed at the survivor's LAG rather than unhooked, and the rest move.
func TestIntegration_Interfaces_MergeMovesInterfaces(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	svc := NewInterfaceService(app)
	survivor := ifaceSeedAsset(t, owner, tenant, "monitoring")
	source := ifaceSeedAsset(t, owner, tenant, "monitoring")

	mk := func(asset uuid.UUID, in InterfaceInput) Interface {
		t.Helper()
		in.AssetID = asset
		i, err := svc.Create(ctx, tenant, uuid.Nil, in)
		if err != nil {
			t.Fatal(err)
		}
		return i
	}
	survPo := mk(survivor, InterfaceInput{Name: "Port-channel1", Type: "lag", Description: ifaceStrp("survivor's")})
	mk(source, InterfaceInput{Name: "Port-channel1", Type: "lag", Description: ifaceStrp("source's"), MACAddress: ifaceStrp("02:00:00:00:00:99")})
	srcPo, _, _ := svc.List(ctx, tenant, InterfaceFilter{AssetID: &source, Name: "Port-channel1"})
	member := mk(source, InterfaceInput{Name: "GigabitEthernet1/0/1", Type: "1000base-t", LagID: &srcPo[0].ID})
	if _, err := owner.Exec(`UPDATE interfaces SET observation_count = 3 WHERE id = $1`, srcPo[0].ID); err != nil {
		t.Fatal(err)
	}
	// An address and an FHRP assignment on the source's duplicate LAG.
	if _, err := owner.Exec(`INSERT INTO ip_addresses (tenant_id, address, assigned_kind, assigned_id) VALUES ($1, '10.9.9.9/24', 'interface', $2)`, tenant, srcPo[0].ID); err != nil {
		t.Fatal(err)
	}
	var fhrp uuid.UUID
	if err := owner.QueryRow(`INSERT INTO fhrp_groups (tenant_id, protocol, group_id) VALUES ($1, 'vrrp2', 7) RETURNING id`, tenant).Scan(&fhrp); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`INSERT INTO fhrp_group_assignments (tenant_id, group_id, interface_id) VALUES ($1, $2, $3)`, tenant, fhrp, srcPo[0].ID); err != nil {
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

	left, _, _ := svc.List(ctx, tenant, InterfaceFilter{AssetID: &source})
	if len(left) != 0 {
		t.Fatalf("%d interfaces left on the merged-away asset", len(left))
	}
	got, _, _ := svc.List(ctx, tenant, InterfaceFilter{AssetID: &survivor})
	if len(got) != 2 {
		t.Fatalf("survivor has %d interfaces, want 2 (one Port-channel1, the member)", len(got))
	}
	po, _ := svc.Get(ctx, tenant, survPo.ID)
	if po.Description == nil || *po.Description != "survivor's" || po.ObservationCount != 3 {
		t.Errorf("survivor's LAG: description=%v count=%d; want survivor's, 3", po.Description, po.ObservationCount)
	}
	if len(po.MACAddresses) != 1 || po.MACAddresses[0].MAC != "02:00:00:00:00:99" || po.MACAddresses[0].IsPrimary {
		t.Errorf("the source LAG's MAC did not move across as an additional MAC: %+v", po.MACAddresses)
	}
	var ipOn, fhrpOn uuid.UUID
	if err := owner.QueryRow(`SELECT assigned_id FROM ip_addresses WHERE tenant_id = $1 AND host(address) = '10.9.9.9'`, tenant).Scan(&ipOn); err != nil || ipOn != survPo.ID {
		t.Errorf("address assigned to %s (%v); want the survivor's Port-channel1", ipOn, err)
	}
	if err := owner.QueryRow(`SELECT interface_id FROM fhrp_group_assignments WHERE tenant_id = $1 AND group_id = $2`, tenant, fhrp).Scan(&fhrpOn); err != nil || fhrpOn != survPo.ID {
		t.Errorf("FHRP assignment on %s (%v); want the survivor's Port-channel1", fhrpOn, err)
	}
	m, _ := svc.Get(ctx, tenant, member.ID)
	if m.AssetID != survivor || m.LagID == nil || *m.LagID != survPo.ID {
		t.Errorf("member: asset=%s lag=%v; want the survivor and its Port-channel1", m.AssetID, m.LagID)
	}
}

// The VLAN / VRF references are tenant-paired (row 1.3's tables): a VLAN that
// does not exist, or belongs to another tenant, is a 422 naming the field;
// deleting a VLAN detaches the interfaces that used it.
func TestIntegration_Interfaces_VLANReferences(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	other := testdb.NewTenant(t, owner)
	ctx := ifaceActorCtx()
	svc := NewInterfaceService(app)
	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")
	mine := ifaceSeedVLAN(t, owner, tenant, 10)
	theirs := ifaceSeedVLAN(t, owner, other, 20)

	field := func(err error) string {
		var ve *InterfaceValidationError
		if errors.As(err, &ve) {
			return ve.Field
		}
		return fmt.Sprint(err)
	}
	for _, tc := range []struct {
		name string
		in   InterfaceInput
		want string
	}{
		{"unknown untagged", InterfaceInput{Mode: ifaceStrp("access"), UntaggedVLANID: ptrUUID(uuid.New())}, "untagged_vlan_id"},
		{"another tenant's untagged", InterfaceInput{Mode: ifaceStrp("access"), UntaggedVLANID: &theirs}, "untagged_vlan_id"},
		{"another tenant's tagged", InterfaceInput{Mode: ifaceStrp("tagged"), TaggedVLANIDs: []uuid.UUID{mine, theirs}}, "tagged_vlan_ids"},
		{"unknown VRF", InterfaceInput{VRFID: ptrUUID(uuid.New())}, "vrf_id"},
	} {
		tc.in.AssetID, tc.in.Name, tc.in.Type = asset, "eth-"+tc.name, "1000base-t"
		if _, err := svc.Create(ctx, tenant, uuid.Nil, tc.in); field(err) != tc.want {
			t.Errorf("%s: got %v, want a 422 on %s", tc.name, err, tc.want)
		}
	}

	i, err := svc.Create(ctx, tenant, uuid.Nil, InterfaceInput{AssetID: asset, Name: "Gi1/0/1", Type: "1000base-t",
		Mode: ifaceStrp("tagged"), UntaggedVLANID: &mine, TaggedVLANIDs: []uuid.UUID{mine}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`DELETE FROM vlans WHERE id = $1`, mine); err != nil {
		t.Fatal(err)
	}
	got, _ := svc.Get(ctx, tenant, i.ID)
	if got.UntaggedVLANID != nil || len(got.TaggedVLANIDs) != 0 {
		t.Errorf("after the VLAN was deleted: untagged=%v tagged=%v; want both cleared", got.UntaggedVLANID, got.TaggedVLANIDs)
	}
}

// /ipam/find names the asset holding an address through the interface it is
// assigned to (row 1.3's lookup over row 1.2's table); an address cannot be
// assigned to another tenant's interface; deleting the interface leaves the
// address in IPAM, unassigned.
func TestIntegration_Interfaces_IPAMFindThroughInterface(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	other := testdb.NewTenant(t, owner)
	ctx := ifaceActorCtx()
	svc := NewInterfaceService(app)
	ipamSvc := NewIPAMService(app)
	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")
	i, err := svc.Create(ctx, tenant, uuid.Nil, InterfaceInput{AssetID: asset, Name: "Vlan10", Type: "virtual"})
	if err != nil {
		t.Fatal(err)
	}
	foreign := ifaceSeedAsset(t, owner, other, "monitoring")
	fi, err := svc.Create(ctx, other, uuid.Nil, InterfaceInput{AssetID: foreign, Name: "eth0", Type: "1000base-t"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ipamSvc.Create(ctx, tenant, "ip-addresses", []byte(`{"address":"10.20.0.7/24","assigned_kind":"interface","assigned_id":"`+fi.ID.String()+`"}`)); err == nil {
		t.Fatal("an address was assigned to another tenant's interface")
	}
	if _, err := ipamSvc.Create(ctx, tenant, "ip-addresses", []byte(`{"address":"10.20.0.5/24","assigned_kind":"interface","assigned_id":"`+i.ID.String()+`"}`)); err != nil {
		t.Fatalf("assign to own interface: %v", err)
	}
	res, err := ipamSvc.FindAddress(ctx, tenant, netip.MustParseAddr("10.20.0.5"), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Asset == nil || res[0].Asset.ID != asset || res[0].Asset.Via != "interface" {
		t.Fatalf("find: %+v; want the asset, via its interface", res)
	}

	// The Networks lens's address table names the same asset.
	rows, _, err := ipamSvc.List(ctx, tenant, "ip-addresses", IPAMListParams{Limit: 50})
	if err != nil || len(rows) != 1 {
		t.Fatalf("list ip-addresses: %v (%d rows)", err, len(rows))
	}
	var listed struct {
		Asset *struct {
			ID   uuid.UUID `json:"id"`
			Name string    `json:"name"`
		} `json:"asset"`
	}
	if err := json.Unmarshal(rows[0], &listed); err != nil || listed.Asset == nil || listed.Asset.ID != asset {
		t.Fatalf("address table asset column: %s (%v); want the interface's asset", rows[0], err)
	}

	if err := svc.Delete(ctx, tenant, i.ID); err != nil {
		t.Fatal(err)
	}
	var kind sql.NullString
	if err := owner.QueryRow(`SELECT assigned_kind FROM ip_addresses WHERE tenant_id = $1 AND host(address) = '10.20.0.5'`, tenant).Scan(&kind); err != nil {
		t.Fatalf("the address went with the interface: %v", err)
	}
	if kind.Valid {
		t.Errorf("address still assigned (%s) to a deleted interface", kind.String)
	}
}

func ptrUUID(u uuid.UUID) *uuid.UUID { return &u }
