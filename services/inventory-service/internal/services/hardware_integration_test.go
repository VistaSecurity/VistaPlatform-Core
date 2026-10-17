package services

// DB-integration tests for DCIM row 2.4: module bays, modules, inventory
// items, virtual chassis and device-bay installs. Skipped unless
// TEST_DATABASE_URL is set; run with make test-integration-db. The services
// run on the NON-OWNER app role, so RLS is in force as in production.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// hwSeedModuleType inserts a platform module type with the given interface
// template names (type 10gbase-x-sfpp), a `con {module}` console port template
// and a nested `SFP {module}` module bay template.
func hwSeedModuleType(t *testing.T, owner *sql.DB, mfr uuid.UUID, model string, ifaces ...string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := owner.QueryRow(`INSERT INTO module_types (tenant_id, manufacturer_id, model, slug, part_number) VALUES (NULL, $1, $2, $3, $2) RETURNING id`,
		mfr, model, Slugify(model)+"-"+uuid.NewString()[:8]).Scan(&id); err != nil {
		t.Fatalf("seed module type: %v", err)
	}
	for _, n := range ifaces {
		if _, err := owner.Exec(`INSERT INTO interface_templates (tenant_id, module_type_id, name, type) VALUES (NULL, $1, $2, '10gbase-x-sfpp')`, id, n); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []string{
		`INSERT INTO console_port_templates (tenant_id, module_type_id, name, type) VALUES (NULL, $1, 'con {module}', 'rj-45')`,
		`INSERT INTO module_bay_templates (tenant_id, module_type_id, name, position) VALUES (NULL, $1, 'SFP {module}', '{module}')`,
	} {
		if _, err := owner.Exec(q, id); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

// hwBayTemplate adds a module bay template to a device type.
func hwBayTemplate(t *testing.T, owner *sql.DB, dt uuid.UUID, name, position string) {
	t.Helper()
	var pos any
	if position != "" {
		pos = position
	}
	if _, err := owner.Exec(`INSERT INTO module_bay_templates (tenant_id, device_type_id, name, position) VALUES (NULL, $1, $2, $3)`, dt, name, pos); err != nil {
		t.Fatal(err)
	}
}

func hwBayID(t *testing.T, owner *sql.DB, asset uuid.UUID, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := owner.QueryRow(`SELECT id FROM module_bays WHERE asset_id = $1 AND name = $2`, asset, name).Scan(&id); err != nil {
		t.Fatalf("module bay %q: %v", name, err)
	}
	return id
}

func hwInterface(t *testing.T, owner *sql.DB, asset uuid.UUID, name string) (id uuid.UUID, module uuid.NullUUID, sourceKind string, obs int) {
	t.Helper()
	if err := owner.QueryRow(`SELECT id, module_id, source_kind, observation_count FROM interfaces WHERE asset_id = $1 AND name = $2`, asset, name).
		Scan(&id, &module, &sourceKind, &obs); err != nil {
		t.Fatalf("interface %q: %v", name, err)
	}
	return
}

// The five tables are tenant-isolated: another tenant lists none of them and
// cannot insert into them; a tenant reads the platform inventory item roles
// but may not change them.
//
// Mutation: drop a <table>_tenant_isolation policy (or its ENABLE ROW LEVEL
// SECURITY) in the 2.4 block → that table's subtest goes red.
func TestIntegration_Hardware_RLS(t *testing.T) {
	owner, app, tenantA := ifaceFixture(t)
	tenantB := testdb.NewTenant(t, owner)
	ctx := ifaceActorCtx()
	hw := NewHardwareService(app)
	cat := NewCatalogueService(app)
	mfr, dt := catSeedPlatformType(t, owner, "Cisco", "C9300 RLS "+uuid.NewString()[:6], 1)
	hwBayTemplate(t, owner, dt, "Network Module", "1")
	mt := hwSeedModuleType(t, owner, mfr, "C9300-NM-RLS-"+uuid.NewString()[:6], "TenGigabitEthernet1/{module}/1")
	asset := ifaceSeedAsset(t, owner, tenantA, "monitoring")
	if _, err := cat.ApplyDeviceType(ctx, tenantA, asset, dt); err != nil {
		t.Fatal(err)
	}
	if _, err := hw.Create(ctx, tenantA, HardwareModule, compBody(t, map[string]any{"module_bay_id": hwBayID(t, owner, asset, "Network Module"), "module_type_id": mt})); err != nil {
		t.Fatalf("install: %v", err)
	}
	if _, err := hw.Create(ctx, tenantA, HardwareInventoryItem, compBody(t, map[string]any{"asset_id": asset, "name": "PSU A"})); err != nil {
		t.Fatal(err)
	}
	if _, err := hw.Create(ctx, tenantA, HardwareVirtualChassis, compBody(t, map[string]any{"name": "stack-" + uuid.NewString()[:6]})); err != nil {
		t.Fatal(err)
	}
	role, err := hw.Create(ctx, tenantA, HardwareInventoryItemRole, compBody(t, map[string]any{"name": "Optic " + uuid.NewString()[:6]}))
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{HardwareModuleBay, HardwareModule, HardwareInventoryItem, HardwareVirtualChassis} {
		if rows, total, err := hw.List(ctx, tenantB, route, IPAMListParams{Limit: 50}); err != nil || total != 0 || len(rows) != 0 {
			t.Errorf("%s: tenant B listed %d of tenant A's rows (%v)", route, total, err)
		}
		if _, total, err := hw.List(ctx, tenantA, route, IPAMListParams{Limit: 50}); err != nil || total == 0 {
			t.Errorf("%s: tenant A lists %d (%v)", route, total, err)
		}
	}
	if _, err := hw.Get(ctx, tenantB, HardwareInventoryItemRole, catID(t, role)); !errors.Is(err, ErrIPAMNotFound) {
		t.Errorf("tenant B read tenant A's inventory item role: %v", err)
	}
	roles, _, err := hw.List(ctx, tenantB, HardwareInventoryItemRole, IPAMListParams{Limit: 50, Filters: map[string]string{"slug": "psu"}})
	if err != nil || len(roles) != 1 {
		t.Fatalf("the platform psu role is not readable: %d (%v)", len(roles), err)
	}
	if _, err := hw.Update(ctx, tenantB, HardwareInventoryItemRole, catID(t, roles[0]), compBody(t, map[string]any{"name": "mine"})); !errors.Is(err, ErrIPAMReadOnly) {
		t.Errorf("a tenant edited a platform role: %v, want read-only", err)
	}
	bay := hwBayID(t, owner, asset, "Network Module")
	testdb.AsTenant(t, owner, tenantB, func(tx *sql.Tx) {
		for table, stmt := range map[string]string{
			"module_bays":     fmt.Sprintf(`INSERT INTO module_bays (tenant_id, asset_id, name) VALUES ($1, '%s', 'x')`, asset),
			"modules":         fmt.Sprintf(`INSERT INTO modules (tenant_id, asset_id, module_bay_id, module_type_id) VALUES ($1, '%s', '%s', '%s')`, asset, bay, mt),
			"inventory_items": fmt.Sprintf(`INSERT INTO inventory_items (tenant_id, asset_id, name) VALUES ($1, '%s', 'x')`, asset),
			"virtual_chassis": `INSERT INTO virtual_chassis (tenant_id, name) VALUES ($1, 'x')`,
		} {
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
			if err := tx.QueryRow(`SELECT count(*) FROM `+table+` WHERE tenant_id = $1`, tenantA).Scan(&n); err != nil || n != 0 {
				t.Errorf("%s: tenant B reads %d of tenant A's rows (%v)", table, n, err)
			}
		}
	})
}

// ApplyDeviceType places the type's module bays; installing a module type
// places its templates with `{module}` replaced by the bay's position, merged by
// name with what a collector measured (adopted, never duplicated, measured
// fields untouched); installing it again changes nothing; another type in the
// bay is a conflict; a bay with no position refuses a placeholder.
//
// Mutation: drop the `{module}` substitution (templateSource.substitute
// returning the raw name) → `TenGigabitEthernet1/1/2` is never created, red;
// drop the adoption (`cur.ModuleID == nil` branch) → the measured port keeps
// no module, red; drop the `existing[name]` merge in
// instantiateModuleInterfacesTx → the install hits the identity index, red.
func TestIntegration_Hardware_InstallModule(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	hw := NewHardwareService(app)
	cat := NewCatalogueService(app)
	mfr, dt := catSeedPlatformType(t, owner, "Cisco", "C9300 Install "+uuid.NewString()[:6], 2)
	hwBayTemplate(t, owner, dt, "Network Module", "1")
	hwBayTemplate(t, owner, dt, "PS1", "")
	nm := hwSeedModuleType(t, owner, mfr, "C9300-NM-4X-"+uuid.NewString()[:6],
		"TenGigabitEthernet1/{module}/1", "TenGigabitEthernet1/{module}/2", "TenGigabitEthernet1/{module}/3", "TenGigabitEthernet1/{module}/4")
	other := hwSeedModuleType(t, owner, mfr, "C9300-NM-8X-"+uuid.NewString()[:6], "TenGigabitEthernet1/{module}/8")
	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")

	res, err := cat.ApplyDeviceType(ctx, tenant, asset, dt)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := res.Components[HardwareModuleBay].Created; got != 2 {
		t.Fatalf("module bays created %d, want 2 (result %+v)", got, res.Components)
	}
	// A collector measured the first SFP port before anyone installed the
	// module (the 1.5 seam's write: measured, observed, carrying a MAC).
	measured := uuid.New()
	if _, err := owner.Exec(`INSERT INTO interfaces (id, tenant_id, asset_id, name, type, mac_address, source_kind, observation_count, status)
		VALUES ($1, $2, $3, 'TenGigabitEthernet1/1/1', 'other', '00:11:22:33:44:01', 'measured', 3, 'active')`, measured, tenant, asset); err != nil {
		t.Fatal(err)
	}
	bay := hwBayID(t, owner, asset, "Network Module")
	ins, err := hw.InstallModule(ctx, tenant, map[string]any{"module_bay_id": bay.String(), "module_type_id": nm.String(), "serial": "FOC1"})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	module := uuid.MustParse(fmt.Sprint(ins.Module["id"]))
	if ins.Interfaces.Created != 3 || ins.Interfaces.Updated != 1 {
		t.Errorf("interfaces created %d updated %d, want 3 and 1 (the measured port adopted)", ins.Interfaces.Created, ins.Interfaces.Updated)
	}
	for _, n := range []string{"TenGigabitEthernet1/1/2", "TenGigabitEthernet1/1/3", "TenGigabitEthernet1/1/4"} {
		if _, mod, sk, _ := hwInterface(t, owner, asset, n); !mod.Valid || mod.UUID != module || sk != "declared" {
			t.Errorf("%s: module %v source %s, want the module, declared", n, mod, sk)
		}
	}
	id, mod, sk, obs := hwInterface(t, owner, asset, "TenGigabitEthernet1/1/1")
	if id != measured || !mod.Valid || mod.UUID != module || sk != "measured" || obs != 3 {
		t.Errorf("the measured port: id %v module %v source %s obs %d — want it adopted, still measured", id, mod, sk, obs)
	}
	var typ, mac string
	if err := owner.QueryRow(`SELECT type, mac_address::text FROM interfaces WHERE id = $1`, measured).Scan(&typ, &mac); err != nil || typ != "10gbase-x-sfpp" || mac == "" {
		t.Errorf("the measured port: type %q (want filled from `other`), mac %q (want kept) (%v)", typ, mac, err)
	}
	var con, nested int
	_ = owner.QueryRow(`SELECT count(*) FROM console_ports WHERE asset_id = $1 AND name = 'con 1' AND module_id = $2`, asset, module).Scan(&con)
	_ = owner.QueryRow(`SELECT count(*) FROM module_bays WHERE asset_id = $1 AND name = 'SFP 1' AND position = '1' AND module_id = $2`, asset, module).Scan(&nested)
	if con != 1 || nested != 1 {
		t.Errorf("con 1: %d, nested bay SFP 1 (position 1): %d — want one each, carrying the module", con, nested)
	}
	var changes int
	_ = owner.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND object_kind = 'module' AND object_id = $2`, tenant, module).Scan(&changes)
	if changes != 1 {
		t.Errorf("module change records = %d, want 1", changes)
	}

	assets := NewAssetService(&database.DB{DB: sqlx.NewDb(owner, "postgres")})
	var model string
	if err := owner.QueryRow(`SELECT model FROM module_types WHERE id = $1`, nm).Scan(&model); err != nil {
		t.Fatal(err)
	}
	for q, want := range map[string]int{`module_type = "` + model + `"`: 1, `module_type != "` + model + `"`: 0, `module_type = "C9300-NM-NONE"`: 0} {
		_, total, err := assets.GetAssets(tenant, models.AssetFilters{Query: q, Page: 1, PageSize: 50, AssetStatus: []string{"monitoring"}})
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if total != want {
			t.Errorf("%s matched %d, want %d", q, total, want)
		}
	}

	before := compCount(t, owner, "interfaces", tenant, asset)
	again, err := hw.InstallModule(ctx, tenant, map[string]any{"module_bay_id": bay.String(), "module_type_id": nm.String()})
	if err != nil || !again.AlreadyInstalled || again.Interfaces.Created != 0 || again.Interfaces.Updated != 0 {
		t.Errorf("re-install: %+v (%v), want already installed and nothing changed", again, err)
	}
	if after := compCount(t, owner, "interfaces", tenant, asset); after != before {
		t.Errorf("re-install changed the interface count %d → %d", before, after)
	}
	if _, err := hw.InstallModule(ctx, tenant, map[string]any{"module_bay_id": bay.String(), "module_type_id": other.String()}); !errors.Is(err, ErrIPAMConflict) {
		t.Errorf("another type into an occupied bay: %v, want conflict", err)
	}
	ps1 := hwBayID(t, owner, asset, "PS1")
	if _, err := hw.InstallModule(ctx, tenant, map[string]any{"module_bay_id": ps1.String(), "module_type_id": other.String()}); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("a {module} type into a bay with no position: %v, want invalid", err)
	}
}

// Removing a module deletes the components it declared and nothing else: the
// measured port it adopted stays, with module_id cleared; so does a declared
// port someone cabled. Its nested bay goes.
//
// Mutation: drop `c.observation_count = 0` from releaseModuleTx → the observed
// port is deleted, red; drop the `kept` UPDATE → the CASCADE takes the measured
// port, red; drop the per-table keep clause → the connected port goes, red.
func TestIntegration_Hardware_RemoveModuleKeepsMeasured(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	hw := NewHardwareService(app)
	cat := NewCatalogueService(app)
	mfr, dt := catSeedPlatformType(t, owner, "Cisco", "C9300 Remove "+uuid.NewString()[:6], 1)
	hwBayTemplate(t, owner, dt, "Network Module", "1")
	nm := hwSeedModuleType(t, owner, mfr, "C9300-NM-2X-"+uuid.NewString()[:6], "TenGigabitEthernet1/{module}/1", "TenGigabitEthernet1/{module}/2",
		"TenGigabitEthernet1/{module}/3", "TenGigabitEthernet1/{module}/4")
	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")
	if _, err := cat.ApplyDeviceType(ctx, tenant, asset, dt); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`INSERT INTO interfaces (tenant_id, asset_id, name, type, source_kind, observation_count, status)
		VALUES ($1, $2, 'TenGigabitEthernet1/1/1', '10gbase-x-sfpp', 'measured', 2, 'active')`, tenant, asset); err != nil {
		t.Fatal(err)
	}
	ins, err := hw.InstallModule(ctx, tenant, map[string]any{"module_bay_id": hwBayID(t, owner, asset, "Network Module").String(), "module_type_id": nm.String()})
	if err != nil {
		t.Fatal(err)
	}
	module := uuid.MustParse(fmt.Sprint(ins.Module["id"]))
	if _, err := owner.Exec(`UPDATE interfaces SET mark_connected = true WHERE asset_id = $1 AND name = 'TenGigabitEthernet1/1/3'`, asset); err != nil {
		t.Fatal(err)
	}
	// A collector has since reported the module's fourth port: still the
	// module's declaration, but it carries an observation now.
	if _, err := owner.Exec(`UPDATE interfaces SET observation_count = 1 WHERE asset_id = $1 AND name = 'TenGigabitEthernet1/1/4'`, asset); err != nil {
		t.Fatal(err)
	}
	if err := hw.RemoveModule(ctx, tenant, module); err != nil {
		t.Fatalf("remove: %v", err)
	}
	present := func(name string) (bool, uuid.NullUUID) {
		var mod uuid.NullUUID
		err := owner.QueryRow(`SELECT module_id FROM interfaces WHERE asset_id = $1 AND name = $2`, asset, name).Scan(&mod)
		return err == nil, mod
	}
	if ok, mod := present("TenGigabitEthernet1/1/1"); !ok || mod.Valid {
		t.Errorf("the measured port: present %v, module %v — want kept, module cleared", ok, mod)
	}
	if ok, _ := present("TenGigabitEthernet1/1/2"); ok {
		t.Error("the module's data-free port survived the removal")
	}
	if ok, mod := present("TenGigabitEthernet1/1/3"); !ok || mod.Valid {
		t.Errorf("the connected port: present %v, module %v — want kept", ok, mod)
	}
	if ok, mod := present("TenGigabitEthernet1/1/4"); !ok || mod.Valid {
		t.Errorf("the observed port: present %v, module %v — want kept", ok, mod)
	}
	var n int
	_ = owner.QueryRow(`SELECT count(*) FROM console_ports WHERE asset_id = $1 AND name = 'con 1'`, asset).Scan(&n)
	var bays int
	_ = owner.QueryRow(`SELECT count(*) FROM module_bays WHERE asset_id = $1 AND name = 'SFP 1'`, asset).Scan(&bays)
	var mods int
	_ = owner.QueryRow(`SELECT count(*) FROM modules WHERE id = $1`, module).Scan(&mods)
	if n != 0 || bays != 0 || mods != 0 {
		t.Errorf("after removal: con 1 %d, nested bay %d, module %d — want all gone", n, bays, mods)
	}
}

// c9300Sighting is the C9300 stack as the Cisco collector reports it
// (shared/deviceinterrogation hardware_observation_test.go's fixture after
// setHardware): two members, two power supplies and an uplink module each,
// four SFPs named after their ports.
func c9300Sighting(serial1 string, sfpSerial string) identity.Sighting {
	pri15, pri14 := 15, 14
	items := []identity.ObservedInventoryItem{}
	for _, sw := range []string{"1", "2"} {
		for _, psu := range []string{"A", "B"} {
			items = append(items, identity.ObservedInventoryItem{Name: "Switch " + sw + " - Power Supply " + psu, Role: "psu",
				Manufacturer: "Cisco Systems", PartID: "PWR-C1-715WAC-P", Serial: "DCB" + sw + psu})
		}
		items = append(items, identity.ObservedInventoryItem{Name: "Switch " + sw + " FRU Uplink Module 1", Role: "linecard",
			Manufacturer: "Cisco Systems", PartID: "C9300-NM-8X", Serial: "FOCNM" + sw, Description: "8x10G Uplink Module"})
		for _, p := range []string{"1", "2"} {
			name := "Te" + sw + "/1/" + p
			items = append(items, identity.ObservedInventoryItem{Name: name, Role: "transceiver", Manufacturer: "Cisco Systems",
				PartID: "SFP-10G-SR", Serial: sfpSerial + sw + p, Interface: "TenGigabitEthernet" + sw + "/1/" + p})
		}
	}
	return identity.Sighting{
		Source:     identity.Source{Kind: identity.SourceMeasured, Ref: interrogationSourcePrefix + "core-stack", Mode: identity.ModeActive},
		Channel:    identity.ChannelAuthenticatedSession,
		ObservedAt: time.Now().UTC(),
		Identifiers: []identity.SightedIdentifier{
			{Kind: identity.KindSerialNumber, Value: serial1},
		},
		Interfaces: []identity.ObservedInterface{
			{Name: "TenGigabitEthernet1/1/1", Type: "10gbase-x-sfpp"}, {Name: "TenGigabitEthernet1/1/2", Type: "10gbase-x-sfpp"},
			{Name: "TenGigabitEthernet2/1/1", Type: "10gbase-x-sfpp"}, {Name: "TenGigabitEthernet2/1/2", Type: "10gbase-x-sfpp"},
		},
		InventoryItems: items,
		VirtualChassis: &identity.ObservedVirtualChassis{Name: "c93xx Stack", Members: []identity.ObservedVirtualChassisMember{
			{Position: 1, Priority: &pri15, Master: true, Serial: serial1, Model: "C9300-48P"},
			{Position: 2, Priority: &pri14, Serial: serial1 + "-2", Model: "C9300-48P"},
		}},
	}
}

// The C9300 stack through the REAL internal sightings intake: twelve inventory
// items (four SFPs linked to their ports), the stack with both members — the
// second matched by the serial its own asset carries — and on the next run the
// same rows, no duplicates, the observation counted and a changed measured
// serial taken; a serial a person typed is never overwritten.
//
// Mutations: drop the UpsertObservedHardware call from IngestSightings → no
// item, red; drop the `(asset, parent, name)` lookup in hardwareWriter.item →
// the second run duplicates (identity index), red; drop the interface link in
// itemLink → the SFPs link nothing, red; drop the member-by-serial lookup →
// member 2 is not in the chassis, red.
func TestIntegration_Hardware_ObservedStackIsIdempotent(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewAssetService(db)
	serial := "FOC" + uuid.NewString()[:8]
	member2 := ifaceSeedAsset(t, raw, tenant, "monitoring")
	if _, err := raw.Exec(`UPDATE assets SET serial = $2 WHERE id = $1`, member2, serial+"-2"); err != nil {
		t.Fatal(err)
	}

	res, err := svc.IngestSightings(context.Background(), tenant, []SightingItem{{Sighting: c9300Sighting(serial, "AVD")}})
	if err != nil || res[0].AssetID == "" {
		t.Fatalf("IngestSightings: %+v (%v)", res, err)
	}
	asset := uuid.MustParse(res[0].AssetID)
	count := func() int {
		var n int
		if err := raw.QueryRow(`SELECT count(*) FROM inventory_items WHERE tenant_id = $1 AND asset_id = $2`, tenant, asset).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(); n != 10 {
		t.Fatalf("inventory items = %d, want 10", n)
	}
	var linked int
	_ = raw.QueryRow(`SELECT count(*) FROM inventory_items i JOIN interfaces f ON f.id = i.component_id
		WHERE i.asset_id = $1 AND i.component_kind = 'interface' AND f.name = 'TenGigabitEthernet' || substr(i.name, 3)`, asset).Scan(&linked)
	if linked != 4 {
		t.Errorf("SFPs linked to their ports = %d, want 4", linked)
	}
	var psuRole int
	_ = raw.QueryRow(`SELECT count(*) FROM inventory_items i JOIN inventory_item_roles r ON r.id = i.role_id
		WHERE i.asset_id = $1 AND r.slug = 'psu' AND i.discovered AND i.source_kind = 'measured'`, asset).Scan(&psuRole)
	if psuRole != 4 {
		t.Errorf("discovered measured PSUs with the psu role = %d, want 4", psuRole)
	}
	hw := NewHardwareService(raw)
	vc, err := hw.AssetVirtualChassis(context.Background(), tenant, asset)
	if err != nil || vc.Chassis == nil || len(vc.Members) != 2 {
		t.Fatalf("virtual chassis %+v (%v), want two members", vc, err)
	}
	if m := vc.Members[0]; m.AssetID != asset || m.VCPosition == nil || *m.VCPosition != 1 || !m.IsMaster {
		t.Errorf("member 1 %+v, want the observed asset at 1, master", m)
	}
	if m := vc.Members[1]; m.AssetID != member2 || m.VCPosition == nil || *m.VCPosition != 2 || m.VCPriority == nil || *m.VCPriority != 14 {
		t.Errorf("member 2 %+v, want the serial's asset at 2, priority 14", m)
	}

	// The query language reaches the rows (QUERY_LANGUAGE §15 D8).
	for q, want := range map[string]int{
		`inventory_item.serial = DCB1A`:    1,
		`inventory_item.serial = NOPE`:     0,
		`virtual_chassis = "c93xx Stack"`:  2,
		`virtual_chassis != "c93xx Stack"`: 0,
	} {
		_, total, err := svc.GetAssets(tenant, models.AssetFilters{Query: q, Page: 1, PageSize: 50,
			AssetStatus: []string{"monitoring", "pending_approval"}})
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if total != want {
			t.Errorf("%s matched %d, want %d", q, total, want)
		}
	}

	// A person types the serial of one PSU; the next run changes every SFP's.
	if _, err := raw.Exec(`UPDATE inventory_items SET source_kind = 'declared', serial = 'TYPED' WHERE asset_id = $1 AND name = 'Switch 1 - Power Supply A'`, asset); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.IngestSightings(context.Background(), tenant, []SightingItem{{Sighting: c9300Sighting(serial, "NEW")}}); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 10 {
		t.Errorf("after the second run inventory items = %d, want still 10", n)
	}
	var sfpSerial, psuSerial string
	var obs int
	_ = raw.QueryRow(`SELECT serial, observation_count FROM inventory_items WHERE asset_id = $1 AND name = 'Te1/1/1'`, asset).Scan(&sfpSerial, &obs)
	_ = raw.QueryRow(`SELECT serial FROM inventory_items WHERE asset_id = $1 AND name = 'Switch 1 - Power Supply A'`, asset).Scan(&psuSerial)
	if sfpSerial != "NEW11" || obs != 2 || psuSerial != "TYPED" {
		t.Errorf("after the second run: SFP serial %q obs %d (want NEW11, 2); typed PSU serial %q (want TYPED)", sfpSerial, obs, psuSerial)
	}
	var chassis int
	_ = raw.QueryRow(`SELECT count(*) FROM virtual_chassis WHERE tenant_id = $1`, tenant).Scan(&chassis)
	if chassis != 1 {
		t.Errorf("virtual chassis rows = %d, want 1", chassis)
	}
}

// A device bay's installed asset and the child's own parent_asset_id /
// device_bay_id are one fact: installing sets the child's pair, emptying the
// bay clears it, and a racked asset is refused.
//
// Mutation: drop syncDeviceBayChild from the device-bays spec → the child's
// parent stays NULL, red; drop the racked check → the racked asset is
// accepted, red.
func TestIntegration_Hardware_DeviceBayInstall(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	comps := NewComponentService(app)
	parent := ifaceSeedAsset(t, owner, tenant, "monitoring")
	child := ifaceSeedAsset(t, owner, tenant, "monitoring")
	bay := compDecode(t, mustCreateComponent(t, comps, ctx, tenant, ComponentDeviceBay, map[string]any{"asset_id": parent, "name": "Bay 1"}))
	bayID := uuid.MustParse(fmt.Sprint(bay["id"]))
	if _, err := comps.Update(ctx, tenant, ComponentDeviceBay, bayID, compBody(t, map[string]any{"installed_asset_id": child})); err != nil {
		t.Fatalf("install: %v", err)
	}
	pair := func() (uuid.NullUUID, uuid.NullUUID) {
		var p, b uuid.NullUUID
		if err := owner.QueryRow(`SELECT parent_asset_id, device_bay_id FROM assets WHERE id = $1`, child).Scan(&p, &b); err != nil {
			t.Fatal(err)
		}
		return p, b
	}
	if p, b := pair(); p.UUID != parent || b.UUID != bayID {
		t.Errorf("child after install: parent %v bay %v, want %s / %s", p, b, parent, bayID)
	}
	if _, err := comps.Update(ctx, tenant, ComponentDeviceBay, bayID, compBody(t, map[string]any{"installed_asset_id": nil})); err != nil {
		t.Fatal(err)
	}
	if p, b := pair(); p.Valid || b.Valid {
		t.Errorf("child after removal: parent %v bay %v, want both cleared", p, b)
	}
	rack := uuid.New()
	var site uuid.UUID
	if err := owner.QueryRow(`INSERT INTO sites (tenant_id, name, slug) VALUES ($1, $2, $2) RETURNING id`, tenant, "s-"+uuid.NewString()[:6]).Scan(&site); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`INSERT INTO racks (id, tenant_id, name, site_id) VALUES ($1, $2, 'R1', $3)`, rack, tenant, site); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`UPDATE assets SET rack_id = $2, position = 10, face = 'front' WHERE id = $1`, child, rack); err != nil {
		t.Fatal(err)
	}
	if _, err := comps.Update(ctx, tenant, ComponentDeviceBay, bayID, compBody(t, map[string]any{"installed_asset_id": child})); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("installing a racked asset: %v, want invalid", err)
	}
}

// Virtual chassis membership by hand: add with position and priority, a taken
// position is a conflict, an asset in another chassis is refused, the master
// must be a member, deleting the chassis releases its members.
func TestIntegration_Hardware_VirtualChassisMembership(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	hw := NewHardwareService(app)
	a, b := ifaceSeedAsset(t, owner, tenant, "monitoring"), ifaceSeedAsset(t, owner, tenant, "monitoring")
	vcRaw, err := hw.Create(ctx, tenant, HardwareVirtualChassis, compBody(t, map[string]any{"name": "stack-a", "master_asset_id": a}))
	if err != nil {
		t.Fatal(err)
	}
	vc := catID(t, vcRaw)
	one, two := 1, 2
	if _, err := hw.AddVirtualChassisMember(ctx, tenant, vc, VirtualChassisMemberInput{AssetID: b, VCPosition: &one}); !errors.Is(err, ErrIPAMConflict) {
		t.Errorf("a taken position: %v, want conflict (the master took 1)", err)
	}
	members, err := hw.AddVirtualChassisMember(ctx, tenant, vc, VirtualChassisMemberInput{AssetID: b, VCPosition: &two, VCPriority: &one})
	if err != nil || len(members) != 2 || !members[0].IsMaster || members[1].AssetID != b {
		t.Fatalf("members %+v (%v)", members, err)
	}
	other, err := hw.Create(ctx, tenant, HardwareVirtualChassis, compBody(t, map[string]any{"name": "stack-b"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hw.AddVirtualChassisMember(ctx, tenant, catID(t, other), VirtualChassisMemberInput{AssetID: b}); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("an asset in another chassis: %v, want invalid", err)
	}
	c := ifaceSeedAsset(t, owner, tenant, "monitoring")
	if _, err := hw.Update(ctx, tenant, HardwareVirtualChassis, vc, compBody(t, map[string]any{"master_asset_id": c})); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("a non-member master: %v, want invalid", err)
	}
	if err := hw.Delete(ctx, tenant, HardwareVirtualChassis, vc); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = owner.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND (virtual_chassis_id IS NOT NULL OR vc_position IS NOT NULL)`, tenant).Scan(&n)
	if n != 0 {
		t.Errorf("%d assets still carry chassis columns after the chassis was deleted", n)
	}
}
