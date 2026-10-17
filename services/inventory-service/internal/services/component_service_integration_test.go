package services

// DB-integration tests for the asset components (DCIM BUILD_PLAN row 3.1).
// Skipped unless TEST_DATABASE_URL is set; run with make test-integration-db.
// The services run on the NON-OWNER app role, so RLS is in force as in
// production; the owner connection seeds assets and platform templates.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func compBody(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func compDecode(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return m
}

func compCount(t *testing.T, db *sql.DB, table string, tenant, asset uuid.UUID) int {
	t.Helper()
	var n int
	if err := db.QueryRow(fmt.Sprintf(`SELECT count(*) FROM %s WHERE tenant_id = $1 AND asset_id = $2`, table), tenant, asset).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// A tenant sees only its own components, on every one of the seven tables, and
// a session scoped to another tenant cannot write a row for it.
//
// Mutation: drop the tenant_isolation policy of any table (or its ENABLE ROW
// LEVEL SECURITY) in schema.sql → that table's listing or cross-tenant insert
// subtest goes red.
func TestIntegration_Components_RLS(t *testing.T) {
	owner, app, tenantA := ifaceFixture(t)
	tenantB := testdb.NewTenant(t, owner)
	ctx := ifaceActorCtx()
	svc := NewComponentService(app)
	assetA := ifaceSeedAsset(t, owner, tenantA, "monitoring")

	rear := compDecode(t, mustCreateComponent(t, svc, ctx, tenantA, ComponentRearPort, map[string]any{"asset_id": assetA, "name": "Rear1", "type": "lc", "positions": 2}))
	mustCreateComponent(t, svc, ctx, tenantA, ComponentFrontPort, map[string]any{"asset_id": assetA, "name": "Front1", "type": "lc", "rear_port_id": rear["id"], "rear_port_position": 1})
	mustCreateComponent(t, svc, ctx, tenantA, ComponentConsolePort, map[string]any{"asset_id": assetA, "name": "con 0", "type": "rj-45", "speed": 9600})
	mustCreateComponent(t, svc, ctx, tenantA, ComponentConsoleServerPort, map[string]any{"asset_id": assetA, "name": "port1", "type": "rj-45"})
	mustCreateComponent(t, svc, ctx, tenantA, ComponentDeviceBay, map[string]any{"asset_id": assetA, "name": "Bay1"})
	pp := compDecode(t, mustCreateComponent(t, svc, ctx, tenantA, ComponentPowerPort, map[string]any{"asset_id": assetA, "name": "PSU1", "type": "iec-60320-c14", "maximum_draw": 500}))
	mustCreateComponent(t, svc, ctx, tenantA, ComponentPowerOutlet, map[string]any{"asset_id": assetA, "name": "Out1", "power_port_id": pp["id"], "feed_leg": "A"})

	for _, route := range ComponentRoutes() {
		rows, total, err := svc.List(ctx, tenantB, route, IPAMListParams{Limit: 50})
		if err != nil || total != 0 || len(rows) != 0 {
			t.Errorf("%s: tenant B listed %d/%d of tenant A's rows (%v)", route, len(rows), total, err)
		}
		if _, total, err := svc.ListForAsset(ctx, tenantA, assetA, route, IPAMListParams{Limit: 50}); err != nil || total != 1 {
			t.Errorf("%s: tenant A's asset listing = %d (%v), want 1", route, total, err)
		}
		if _, _, err := svc.ListForAsset(ctx, tenantB, assetA, route, IPAMListParams{Limit: 50}); !errors.Is(err, ErrIPAMNotFound) {
			t.Errorf("%s: tenant B listing tenant A's asset: %v, want not found", route, err)
		}
	}

	testdb.AsTenant(t, owner, tenantB, func(tx *sql.Tx) {
		for _, route := range ComponentRoutes() {
			table := replaceDash(route)
			stmt := fmt.Sprintf(`INSERT INTO %s (tenant_id, asset_id, name%s) VALUES ($1, '%s', 'x'%s)`, table, extraCols(route), assetA, extraVals(route))
			if _, err := tx.Exec("SAVEPOINT s"); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(stmt, tenantA); err == nil {
				t.Errorf("%s: a cross-tenant insert was accepted", table)
			}
			if _, err := tx.Exec("ROLLBACK TO SAVEPOINT s"); err != nil {
				t.Fatal(err)
			}
			var n int
			if err := tx.QueryRow(fmt.Sprintf(`SELECT count(*) FROM %s WHERE tenant_id = $1`, table), tenantA).Scan(&n); err != nil || n != 0 {
				t.Errorf("%s: tenant B reads %d of tenant A's rows (%v)", table, n, err)
			}
		}
	})
}

func extraCols(route string) string {
	switch route {
	case ComponentRearPort:
		return ", type"
	case ComponentFrontPort:
		return ", type, rear_port_id"
	}
	return ""
}

func extraVals(route string) string {
	switch route {
	case ComponentRearPort:
		return ", 'lc'"
	case ComponentFrontPort:
		return ", 'lc', gen_random_uuid()"
	}
	return ""
}

func mustCreateComponent(t *testing.T, svc *ComponentService, ctx context.Context, tenant uuid.UUID, route string, m map[string]any) json.RawMessage {
	t.Helper()
	raw, err := svc.Create(ctx, tenant, route, compBody(t, m))
	if err != nil {
		t.Fatalf("create %s %v: %v", route, m["name"], err)
	}
	return raw
}

// A front port is one position of one rear port ON ITS OWN ASSET: the position
// is inside the rear port's `positions`, the pair is unique, the rear port
// cannot shrink under a mapped position, and a component never changes asset.
//
// Mutation: drop the `pos > positions` check in prepareFrontPort → the
// out-of-range front port is accepted; drop front_ports_rear_position_uniq →
// the duplicate mapping is accepted; drop the max(rear_port_position) check in
// prepareRearPort → the shrink is accepted; drop sameAssetRef → the front port
// maps a rear port of another asset.
func TestIntegration_Components_FrontToRearMapping(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	svc := NewComponentService(app)
	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")
	other := ifaceSeedAsset(t, owner, tenant, "monitoring")

	rear := compDecode(t, mustCreateComponent(t, svc, ctx, tenant, ComponentRearPort, map[string]any{"asset_id": asset, "name": "Rear1", "type": "lc", "positions": 2}))
	otherRear := compDecode(t, mustCreateComponent(t, svc, ctx, tenant, ComponentRearPort, map[string]any{"asset_id": other, "name": "Rear1", "type": "lc", "positions": 2}))
	f2 := compDecode(t, mustCreateComponent(t, svc, ctx, tenant, ComponentFrontPort, map[string]any{"asset_id": asset, "name": "F2", "type": "lc", "rear_port_id": rear["id"], "rear_port_position": 2}))

	cases := []struct {
		name string
		body map[string]any
		want error
	}{
		{"position beyond positions", map[string]any{"asset_id": asset, "name": "F3", "type": "lc", "rear_port_id": rear["id"], "rear_port_position": 3}, ErrIPAMInvalid},
		{"position zero", map[string]any{"asset_id": asset, "name": "F0", "type": "lc", "rear_port_id": rear["id"], "rear_port_position": 0}, ErrIPAMInvalid},
		{"duplicate (rear port, position)", map[string]any{"asset_id": asset, "name": "Fdup", "type": "lc", "rear_port_id": rear["id"], "rear_port_position": 2}, ErrIPAMConflict},
		{"rear port of another asset", map[string]any{"asset_id": asset, "name": "Fx", "type": "lc", "rear_port_id": otherRear["id"], "rear_port_position": 1}, ErrIPAMInvalid},
		{"no rear port", map[string]any{"asset_id": asset, "name": "Fn", "type": "lc"}, ErrIPAMInvalid},
		{"unknown type", map[string]any{"asset_id": asset, "name": "Fu", "type": "banana", "rear_port_id": rear["id"]}, ErrIPAMInvalid},
		{"same name twice on an asset", map[string]any{"asset_id": asset, "name": "F2", "type": "lc", "rear_port_id": rear["id"], "rear_port_position": 1}, ErrIPAMConflict},
		{"no such asset", map[string]any{"asset_id": uuid.New(), "name": "Fa", "type": "lc", "rear_port_id": rear["id"]}, ErrIPAMInvalid},
	}
	for _, c := range cases {
		if _, err := svc.Create(ctx, tenant, ComponentFrontPort, compBody(t, c.body)); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	// Position 1 is free (and defaulted when omitted).
	f1 := compDecode(t, mustCreateComponent(t, svc, ctx, tenant, ComponentFrontPort, map[string]any{"asset_id": asset, "name": "F1", "type": "lc", "rear_port_id": rear["id"]}))
	if f1["rear_port_position"] != float64(1) {
		t.Errorf("default rear_port_position = %v, want 1", f1["rear_port_position"])
	}

	// The rear port cannot shrink below a mapped position.
	if _, err := svc.Update(ctx, tenant, ComponentRearPort, uuid.MustParse(rear["id"].(string)), []byte(`{"positions":1}`)); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("shrinking a rear port under a mapped front port: %v, want invalid", err)
	}
	// Moving a front port onto a taken position is a conflict; onto a free one, fine.
	if _, err := svc.Update(ctx, tenant, ComponentFrontPort, uuid.MustParse(f2["id"].(string)), []byte(`{"rear_port_position":1}`)); !errors.Is(err, ErrIPAMConflict) {
		t.Errorf("moving onto a taken position: %v, want conflict", err)
	}
	// A component never moves asset.
	if _, err := svc.Update(ctx, tenant, ComponentFrontPort, uuid.MustParse(f2["id"].(string)), compBody(t, map[string]any{"asset_id": other})); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("changing asset_id: %v, want invalid", err)
	}
	// Deleting the rear port takes its front ports with it.
	if err := svc.Delete(ctx, tenant, ComponentRearPort, uuid.MustParse(rear["id"].(string))); err != nil {
		t.Fatal(err)
	}
	if n := compCount(t, owner, "front_ports", tenant, asset); n != 0 {
		t.Errorf("front ports left after deleting their rear port: %d", n)
	}
	// Every write above that succeeded was recorded.
	var recorded int
	if err := owner.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND object_kind = 'front_port'`, tenant).Scan(&recorded); err != nil || recorded != 2 {
		t.Errorf("front_port change records = %d (%v), want 2 (two creates)", recorded, err)
	}
}

// Device bays hold at most one asset each, one asset sits in at most one bay,
// and never in its own; outlets draw from a power port of their own asset.
//
// Mutation: drop device_bays_installed_asset_uniq → the second bay accepts the
// same asset; drop the self check in prepareDeviceBay → the asset installs in
// itself.
func TestIntegration_Components_BaysAndPower(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	svc := NewComponentService(app)
	chassis := ifaceSeedAsset(t, owner, tenant, "monitoring")
	blade := ifaceSeedAsset(t, owner, tenant, "monitoring")
	other := ifaceSeedAsset(t, owner, tenant, "monitoring")

	b1 := compDecode(t, mustCreateComponent(t, svc, ctx, tenant, ComponentDeviceBay, map[string]any{"asset_id": chassis, "name": "Bay1", "installed_asset_id": blade}))
	if b1["installed_asset_id"] != blade.String() {
		t.Fatalf("installed asset = %v", b1["installed_asset_id"])
	}
	if _, err := svc.Create(ctx, tenant, ComponentDeviceBay, compBody(t, map[string]any{"asset_id": chassis, "name": "Bay2", "installed_asset_id": blade})); !errors.Is(err, ErrIPAMConflict) {
		t.Errorf("one asset in two bays: %v, want conflict", err)
	}
	if _, err := svc.Create(ctx, tenant, ComponentDeviceBay, compBody(t, map[string]any{"asset_id": chassis, "name": "Bay3", "installed_asset_id": chassis})); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("an asset in its own bay: %v, want invalid", err)
	}
	// Deleting the installed asset empties the bay, it does not delete it.
	if _, err := owner.Exec(`DELETE FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, blade); err != nil {
		t.Fatal(err)
	}
	var inst sql.NullString
	if err := owner.QueryRow(`SELECT installed_asset_id::text FROM device_bays WHERE id = $1`, b1["id"]).Scan(&inst); err != nil || inst.Valid {
		t.Errorf("bay after its asset was deleted: installed=%v (%v), want an empty bay", inst, err)
	}

	pp := compDecode(t, mustCreateComponent(t, svc, ctx, tenant, ComponentPowerPort, map[string]any{"asset_id": chassis, "name": "PSU1", "maximum_draw": 400, "allocated_draw": 300}))
	if _, err := svc.Create(ctx, tenant, ComponentPowerPort, compBody(t, map[string]any{"asset_id": chassis, "name": "PSU2", "maximum_draw": 100, "allocated_draw": 200})); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("allocated above maximum: %v, want invalid", err)
	}
	if _, err := svc.Create(ctx, tenant, ComponentPowerOutlet, compBody(t, map[string]any{"asset_id": other, "name": "Out1", "power_port_id": pp["id"]})); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("an outlet fed by another asset's power port: %v, want invalid", err)
	}
	if _, err := svc.Create(ctx, tenant, ComponentPowerOutlet, compBody(t, map[string]any{"asset_id": chassis, "name": "Out1", "power_port_id": pp["id"], "feed_leg": "D"})); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("feed leg D: %v, want invalid", err)
	}
	// Created through the asset-scoped route.
	raw, err := svc.CreateForAsset(ctx, tenant, chassis, ComponentPowerOutlet, []byte(fmt.Sprintf(`{"name":"Out1","power_port_id":%q,"feed_leg":"A"}`, pp["id"])))
	if err != nil {
		t.Fatalf("asset-scoped create: %v", err)
	}
	if got := compDecode(t, raw)["asset_id"]; got != chassis.String() {
		t.Errorf("asset-scoped create put the outlet on %v", got)
	}
	if _, err := svc.CreateForAsset(ctx, tenant, chassis, ComponentPowerOutlet, compBody(t, map[string]any{"name": "Out2", "asset_id": other})); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("asset-scoped create naming another asset: %v, want invalid", err)
	}
}

// seedComponentTemplates adds the row-3.1 template kinds to a platform device
// type that already carries catSeedPlatformType's interface and console
// templates: two rear ports of 2 positions, four front ports mapped onto them,
// a console server port, a device bay, a power port and an outlet on it, and a
// {module} console port that must wait.
func seedComponentTemplates(t *testing.T, owner *sql.DB, dt uuid.UUID) {
	t.Helper()
	ids := map[string]uuid.UUID{}
	for _, n := range []string{"Rear 1", "Rear 2"} {
		var id uuid.UUID
		if err := owner.QueryRow(`INSERT INTO rear_port_templates (tenant_id, device_type_id, name, type, positions) VALUES (NULL, $1, $2, 'lc', 2) RETURNING id`, dt, n).Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids[n] = id
	}
	for i, n := range []string{"Front 1", "Front 2", "Front 3", "Front 4"} {
		rear := "Rear 1"
		if i >= 2 {
			rear = "Rear 2"
		}
		if _, err := owner.Exec(`INSERT INTO front_port_templates (tenant_id, device_type_id, name, type, rear_port_id, rear_port_position) VALUES (NULL, $1, $2, 'lc', $3, $4)`,
			dt, n, ids[rear], i%2+1); err != nil {
			t.Fatal(err)
		}
	}
	var pp uuid.UUID
	if err := owner.QueryRow(`INSERT INTO power_port_templates (tenant_id, device_type_id, name, type, maximum_draw) VALUES (NULL, $1, 'PSU1', 'iec-60320-c14', 715) RETURNING id`, dt).Scan(&pp); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO console_server_port_templates (tenant_id, device_type_id, name, type) VALUES (NULL, $1, 'aux 0', 'usb-a')`,
		`INSERT INTO device_bay_templates (tenant_id, device_type_id, name) VALUES (NULL, $1, 'Bay 1')`,
		`INSERT INTO console_port_templates (tenant_id, device_type_id, name, type) VALUES (NULL, $1, 'con {module}', 'rj-45')`,
	} {
		if _, err := owner.Exec(q, dt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := owner.Exec(`INSERT INTO power_outlet_templates (tenant_id, device_type_id, name, type, power_port_id, feed_leg) VALUES (NULL, $1, 'Out 1', 'iec-60320-c13', $2, 'A')`, dt, pp); err != nil {
		t.Fatal(err)
	}
}

// ApplyDeviceType on a C9300-class type creates EVERY component kind from the
// templates — rear ports before the front ports that map onto them — and
// re-applying changes nothing. A person's edits and a mapping are never
// overwritten, a name with data survives a type switch, and every create is a
// change record.
//
// Mutation: instantiate front ports before rear ports (swap instantiateOrder) →
// every front port is skipped "names no rear port"; drop the `existing` lookup
// → the re-apply hits the identity index or duplicates; fill without the
// `cur[k] == nil` guard → the person's label is overwritten; drop the
// cable_id guard in removeStale → the cabled port is deleted by the switch.
func TestIntegration_Components_ApplyDeviceType_AllKinds_Idempotent(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	cat := NewCatalogueService(app)
	comps := NewComponentService(app)
	_, c9300 := catSeedPlatformType(t, owner, "Cisco", "Catalyst 9300-48P "+uuid.NewString()[:6], 4)
	seedComponentTemplates(t, owner, c9300)
	_, bare := catSeedPlatformType(t, owner, "Cisco", "Bare "+uuid.NewString()[:6], 1)
	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")

	res, err := cat.ApplyDeviceType(ctx, tenant, asset, c9300)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	want := map[string]int{ComponentRearPort: 2, ComponentFrontPort: 4, ComponentConsolePort: 1, ComponentConsoleServerPort: 1,
		ComponentDeviceBay: 1, ComponentPowerPort: 1, ComponentPowerOutlet: 1}
	for route, n := range want {
		if got := res.Components[route].Created; got != n {
			t.Errorf("%s created = %d, want %d (%+v)", route, got, n, res.Components[route])
		}
	}
	if len(res.Components[ComponentConsolePort].Skipped) != 1 {
		t.Errorf("the {module} console template should be skipped: %+v", res.Components[ComponentConsolePort])
	}
	if len(res.NotInstantiated) != 0 {
		t.Errorf("not_instantiated = %v, want none (no module bay templates)", res.NotInstantiated)
	}
	// The mapping resolved: Front 3 is Rear 2's position 1, Front 4 its position 2.
	var rearName string
	var pos int
	if err := owner.QueryRow(`SELECT r.name, f.rear_port_position FROM front_ports f JOIN rear_ports r ON r.id = f.rear_port_id
		WHERE f.tenant_id = $1 AND f.asset_id = $2 AND f.name = 'Front 4'`, tenant, asset).Scan(&rearName, &pos); err != nil || rearName != "Rear 2" || pos != 2 {
		t.Errorf("Front 4 maps to %q position %d (%v), want Rear 2 position 2", rearName, pos, err)
	}
	var outletPort sql.NullString
	if err := owner.QueryRow(`SELECT p.name FROM power_outlets o JOIN power_ports p ON p.id = o.power_port_id WHERE o.tenant_id = $1 AND o.asset_id = $2`, tenant, asset).Scan(&outletPort); err != nil || outletPort.String != "PSU1" {
		t.Errorf("outlet fed by %q (%v), want PSU1", outletPort.String, err)
	}

	// A person edits a label and clears nothing else; re-apply is a no-op.
	var conID uuid.UUID
	if err := owner.QueryRow(`SELECT id FROM console_ports WHERE tenant_id = $1 AND asset_id = $2 AND name = 'con 0'`, tenant, asset).Scan(&conID); err != nil {
		t.Fatal(err)
	}
	if _, err := comps.Update(ctx, tenant, ComponentConsolePort, conID, []byte(`{"label":"Management console"}`)); err != nil {
		t.Fatal(err)
	}
	again, err := cat.ApplyDeviceType(ctx, tenant, asset, c9300)
	if err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	for route := range want {
		r := again.Components[route]
		if r.Created != 0 || r.Updated != 0 || r.Removed != 0 || r.Unchanged != want[route] {
			t.Errorf("re-apply of %s not idempotent: %+v", route, r)
		}
	}
	var label string
	if err := owner.QueryRow(`SELECT label FROM console_ports WHERE id = $1`, conID).Scan(&label); err != nil || label != "Management console" {
		t.Errorf("the person's label was overwritten: %q (%v)", label, err)
	}
	var changeCount int
	if err := owner.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND object_kind = 'front_port' AND action = 'create'`, tenant).Scan(&changeCount); err != nil || changeCount != 4 {
		t.Errorf("front_port create records = %d (%v), want 4", changeCount, err)
	}

	// Switching to a type with no templates removes what carries nothing and
	// keeps a cabled port, a marked-connected one, and a bay with an asset.
	// cable_id references cables (row 3.2), so the cable is a real row.
	var cableID uuid.UUID
	if err := owner.QueryRow(`INSERT INTO cables (tenant_id) VALUES ($1) RETURNING id`, tenant).Scan(&cableID); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`UPDATE console_server_ports SET cable_id = $3, cable_end = 'A' WHERE tenant_id = $1 AND asset_id = $2`, tenant, asset, cableID); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`UPDATE rear_ports SET mark_connected = true WHERE tenant_id = $1 AND asset_id = $2 AND name = 'Rear 2'`, tenant, asset); err != nil {
		t.Fatal(err)
	}
	sw, err := cat.ApplyDeviceType(ctx, tenant, asset, bare)
	if err != nil {
		t.Fatalf("switch type: %v", err)
	}
	if n := compCount(t, owner, "console_server_ports", tenant, asset); n != 1 {
		t.Errorf("cabled console server port survived? count = %d, want 1", n)
	}
	if n := compCount(t, owner, "rear_ports", tenant, asset); n != 1 {
		t.Errorf("rear ports after the switch = %d, want only the marked-connected Rear 2", n)
	}
	// Front 3/4 hang off Rear 2 and carry nothing, so they go; Rear 2 stays.
	if n := compCount(t, owner, "front_ports", tenant, asset); n != 0 {
		t.Errorf("front ports after the switch = %d, want 0", n)
	}
	if sw.Components[ComponentFrontPort].Removed != 4 || sw.Components[ComponentDeviceBay].Removed != 1 || sw.Components[ComponentPowerOutlet].Removed != 1 {
		t.Errorf("removals: %+v", sw.Components)
	}
}

// An asset merge carries the source's port components to the survivor: a
// same-name pair keeps the survivor's row (observations folded), the source's
// front ports follow onto the survivor's rear port where the position is free
// (and are dropped where the survivor already maps it), an empty surviving bay
// takes the source bay's installed asset, and nothing is left on the source.
//
// Mutation: drop moveMergeComponents from moveAssetChildren → rows are left on
// the merged-away asset (and TestMergeMovesEveryForeignKeyToAssets stays green
// only because the tables are listed as children); drop the front-port
// re-point step → Front2 vanishes with the dropped rear port.
func TestIntegration_Components_MergeMovesThem(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	svc := NewComponentService(app)
	source := ifaceSeedAsset(t, owner, tenant, "monitoring")
	survivor := ifaceSeedAsset(t, owner, tenant, "monitoring")
	blade := ifaceSeedAsset(t, owner, tenant, "monitoring")

	srcRear := compDecode(t, mustCreateComponent(t, svc, ctx, tenant, ComponentRearPort, map[string]any{"asset_id": source, "name": "Rear1", "type": "lc", "positions": 4}))
	dstRear := compDecode(t, mustCreateComponent(t, svc, ctx, tenant, ComponentRearPort, map[string]any{"asset_id": survivor, "name": "Rear1", "type": "lc", "positions": 4, "description": "survivor's"}))
	mustCreateComponent(t, svc, ctx, tenant, ComponentFrontPort, map[string]any{"asset_id": survivor, "name": "FrontA", "type": "lc", "rear_port_id": dstRear["id"], "rear_port_position": 1})
	mustCreateComponent(t, svc, ctx, tenant, ComponentFrontPort, map[string]any{"asset_id": source, "name": "FrontB", "type": "lc", "rear_port_id": srcRear["id"], "rear_port_position": 1}) // position taken on the survivor
	mustCreateComponent(t, svc, ctx, tenant, ComponentFrontPort, map[string]any{"asset_id": source, "name": "FrontC", "type": "lc", "rear_port_id": srcRear["id"], "rear_port_position": 2}) // free: follows
	mustCreateComponent(t, svc, ctx, tenant, ComponentConsolePort, map[string]any{"asset_id": source, "name": "con 0"})
	mustCreateComponent(t, svc, ctx, tenant, ComponentConsolePort, map[string]any{"asset_id": survivor, "name": "con 0", "label": "survivor's"})
	mustCreateComponent(t, svc, ctx, tenant, ComponentConsolePort, map[string]any{"asset_id": source, "name": "aux 0"})
	mustCreateComponent(t, svc, ctx, tenant, ComponentDeviceBay, map[string]any{"asset_id": source, "name": "Bay1", "installed_asset_id": blade})
	mustCreateComponent(t, svc, ctx, tenant, ComponentDeviceBay, map[string]any{"asset_id": survivor, "name": "Bay1"})
	if _, err := owner.Exec(`UPDATE console_ports SET observation_count = 3 WHERE tenant_id = $1 AND asset_id = $2 AND name = 'con 0'`, tenant, source); err != nil {
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

	for _, table := range []string{"console_ports", "console_server_ports", "rear_ports", "front_ports", "device_bays", "power_ports", "power_outlets"} {
		if n := compCount(t, owner, table, tenant, source); n != 0 {
			t.Errorf("%d %s left on the merged-away asset", n, table)
		}
	}
	names := func(table string) map[string]bool {
		rows, err := owner.Query(fmt.Sprintf(`SELECT name FROM %s WHERE tenant_id = $1 AND asset_id = $2`, table), tenant, survivor)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		out := map[string]bool{}
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				t.Fatal(err)
			}
			out[n] = true
		}
		return out
	}
	if got := names("console_ports"); len(got) != 2 || !got["con 0"] || !got["aux 0"] {
		t.Errorf("survivor's console ports = %v, want con 0 and aux 0", got)
	}
	if got := names("front_ports"); len(got) != 2 || !got["FrontA"] || !got["FrontC"] {
		t.Errorf("survivor's front ports = %v, want FrontA (its own) and FrontC (followed); FrontB's position was taken", got)
	}
	var label sql.NullString
	var count int
	if err := owner.QueryRow(`SELECT label, observation_count FROM console_ports WHERE tenant_id = $1 AND asset_id = $2 AND name = 'con 0'`, tenant, survivor).Scan(&label, &count); err != nil ||
		label.String != "survivor's" || count != 3 {
		t.Errorf("survivor's con 0: label=%q count=%d (%v), want survivor's and the folded 3", label.String, count, err)
	}
	var rearOfC uuid.UUID
	if err := owner.QueryRow(`SELECT rear_port_id FROM front_ports WHERE tenant_id = $1 AND asset_id = $2 AND name = 'FrontC'`, tenant, survivor).Scan(&rearOfC); err != nil || rearOfC.String() != dstRear["id"] {
		t.Errorf("FrontC maps to %v (%v), want the survivor's Rear1", rearOfC, err)
	}
	var inst sql.NullString
	if err := owner.QueryRow(`SELECT installed_asset_id::text FROM device_bays WHERE tenant_id = $1 AND asset_id = $2 AND name = 'Bay1'`, tenant, survivor).Scan(&inst); err != nil || inst.String != blade.String() {
		t.Errorf("survivor's empty Bay1 holds %q (%v), want the blade the source's Bay1 held", inst.String, err)
	}
}
