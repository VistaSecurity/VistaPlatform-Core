package services

// DB-integration tests for the device catalogue (DCIM BUILD_PLAN row 2.2).
// Skipped unless TEST_DATABASE_URL is set; run with make test-integration-db.
//
// The service runs on the NON-OWNER app role, so RLS is in force exactly as in
// production; the owner connection seeds the platform rows (as seed.sql does).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// catSeedPlatformType inserts a platform manufacturer + device type with n
// 1000base-t interface templates named GigabitEthernet1/0/1..n (as the
// library's C9300-48P), plus extra templates of other kinds.
func catSeedPlatformType(t *testing.T, owner *sql.DB, mfr, model string, n int) (manufacturer, deviceType uuid.UUID) {
	t.Helper()
	slug := Slugify(mfr)
	if err := owner.QueryRow(`
		INSERT INTO manufacturers (tenant_id, name, slug) VALUES (NULL, $1, $2)
		ON CONFLICT ((COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid)), slug) DO UPDATE SET name = EXCLUDED.name
		RETURNING id`, mfr, slug).Scan(&manufacturer); err != nil {
		t.Fatalf("seed manufacturer: %v", err)
	}
	if err := owner.QueryRow(`
		INSERT INTO device_types (tenant_id, manufacturer_id, model, slug, part_number, u_height)
		VALUES (NULL, $1, $2, $3, $2, 1) RETURNING id`, manufacturer, model, Slugify(model)+"-"+uuid.NewString()[:8]).Scan(&deviceType); err != nil {
		t.Fatalf("seed device type: %v", err)
	}
	for i := 1; i <= n; i++ {
		if _, err := owner.Exec(`
			INSERT INTO interface_templates (tenant_id, device_type_id, name, type, poe_mode, poe_type)
			VALUES (NULL, $1, $2, '1000base-t', 'pse', 'type2-ieee802.3at')`, deviceType, fmt.Sprintf("GigabitEthernet1/0/%d", i)); err != nil {
			t.Fatalf("seed template: %v", err)
		}
	}
	if _, err := owner.Exec(`INSERT INTO console_port_templates (tenant_id, device_type_id, name, type) VALUES (NULL, $1, 'con 0', 'rj-45')`, deviceType); err != nil {
		t.Fatalf("seed console template: %v", err)
	}
	return manufacturer, deviceType
}

func catFixture(t *testing.T) (owner, app *sql.DB, tenant uuid.UUID, svc *CatalogueService) {
	t.Helper()
	owner, app, tenant = ifaceFixture(t)
	return owner, app, tenant, NewCatalogueService(app)
}

func catID(t *testing.T, raw json.RawMessage) uuid.UUID {
	t.Helper()
	var m struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return m.ID
}

// Platform rows are readable by a tenant and refused on every write (403 via
// ErrIPAMReadOnly); a tenant's own rows are invisible to another tenant, and
// a tenant cannot add a template under a platform type.
//
// Mutation: drop `Catalogue: true` from the device-types spec → the PATCH of a
// platform type reaches the UPDATE and the engine answers not-found instead of
// read-only (the FOR ALL policy hides it); drop the FOR SELECT catalogue_read
// policy → the platform row is not listed; drop prepareTemplateParent's NULL
// check → the template insert fails RLS instead of answering read-only.
func TestIntegration_Catalogue_PlatformRowsReadOnly_TenantRowsIsolated(t *testing.T) {
	owner, _, tenantA, svc := catFixture(t)
	tenantB := testdb.NewTenant(t, owner)
	ctx := ifaceActorCtx()
	mfr, dt := catSeedPlatformType(t, owner, "Cisco", "Catalyst 9300-48P "+uuid.NewString()[:6], 2)

	// Readable.
	if _, err := svc.Get(ctx, tenantA, "device-types", dt); err != nil {
		t.Fatalf("tenant cannot read a platform device type: %v", err)
	}
	rows, _, err := svc.List(ctx, tenantA, "device-types", IPAMListParams{Filters: map[string]string{"manufacturer_id": mfr.String(), "scope": "platform"}, Limit: 50})
	if err != nil || len(rows) == 0 {
		t.Fatalf("platform device type not listed (%d rows, %v)", len(rows), err)
	}
	// Not writable.
	if _, err := svc.Update(ctx, tenantA, "device-types", dt, []byte(`{"comments":"mine now"}`)); !errors.Is(err, ErrIPAMReadOnly) {
		t.Fatalf("PATCH of a platform device type: %v, want read-only", err)
	}
	if err := svc.Delete(ctx, tenantA, "manufacturers", mfr); !errors.Is(err, ErrIPAMReadOnly) {
		t.Fatalf("DELETE of a platform manufacturer: %v, want read-only", err)
	}
	if _, err := svc.CreateTemplate(ctx, tenantA, TemplateParent{Kind: "device-types", ID: dt}, TemplateInterface,
		[]byte(`{"name":"Ethernet9","type":"1000base-t"}`)); !errors.Is(err, ErrIPAMReadOnly) {
		t.Fatalf("template under a platform type: %v, want read-only", err)
	}
	tpls, _, err := svc.ListTemplates(ctx, tenantA, TemplateParent{Kind: "device-types", ID: dt}, TemplateInterface, IPAMListParams{Limit: 50})
	if err != nil || len(tpls) != 2 {
		t.Fatalf("platform templates: %d (%v), want 2", len(tpls), err)
	}
	tplID := catID(t, tpls[0])
	if err := svc.DeleteTemplate(ctx, tenantA, TemplateParent{Kind: "device-types", ID: dt}, TemplateInterface, tplID); !errors.Is(err, ErrIPAMReadOnly) {
		t.Fatalf("DELETE of a platform template: %v, want read-only", err)
	}

	// A tenant's own manufacturer and type: writable by it, invisible to B.
	own, err := svc.Create(ctx, tenantA, "manufacturers", []byte(`{"name":"Acme Widgets"}`))
	if err != nil {
		t.Fatalf("create tenant manufacturer: %v", err)
	}
	ownID := catID(t, own)
	ownType, err := svc.Create(ctx, tenantA, "device-types", []byte(fmt.Sprintf(`{"manufacturer_id":%q,"model":"W-24","u_height":"0.5"}`, ownID)))
	if err != nil {
		t.Fatalf("create tenant device type: %v", err)
	}
	ownTypeID := catID(t, ownType)
	if _, err := svc.CreateTemplate(ctx, tenantA, TemplateParent{Kind: "device-types", ID: ownTypeID}, TemplateInterface,
		[]byte(`{"name":"eth0","type":"1000base-t"}`)); err != nil {
		t.Fatalf("template under the tenant's own type: %v", err)
	}
	if _, err := svc.Get(ctx, tenantB, "manufacturers", ownID); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("tenant B read tenant A's manufacturer: %v", err)
	}
	if _, err := svc.Update(ctx, tenantB, "device-types", ownTypeID, []byte(`{"comments":"x"}`)); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("tenant B patched tenant A's device type: %v", err)
	}
	if _, err := svc.Create(ctx, tenantB, "device-types", []byte(fmt.Sprintf(`{"manufacturer_id":%q,"model":"Sneaky"}`, ownID))); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("tenant B built a type on tenant A's manufacturer: %v", err)
	}
	// Uniqueness is per scope: a tenant may hold its own "cisco" beside the
	// platform's (NetBox's per-tenant catalogue), but not two of them.
	if _, err := svc.Create(ctx, tenantA, "manufacturers", []byte(`{"name":"Cisco Systems","slug":"cisco"}`)); err != nil {
		t.Fatalf("tenant manufacturer with a platform slug: %v", err)
	}
	if _, err := svc.Create(ctx, tenantA, "manufacturers", []byte(`{"name":"Cisco Again","slug":"cisco"}`)); !errors.Is(err, ErrIPAMConflict) {
		t.Fatalf("second tenant manufacturer with the same slug: %v, want conflict", err)
	}

	// RLS on the plain pool: tenant B's session cannot insert a row claiming
	// tenant A (USING doubles as WITH CHECK).
	_, app2, _ := ifaceFixture(t)
	tx, err := app2.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.tenant_id', $1, true)`, tenantB.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO manufacturers (tenant_id, name, slug) VALUES ($1, 'x', 'x-cross')`, tenantA); err == nil {
		t.Fatal("tenant B inserted a manufacturer for tenant A")
	}
}

// ApplyDeviceType merges the template's interfaces with the ones SNMP already
// measured, by canonical name: a measured `Gi1/0/1` and the template's
// `GigabitEthernet1/0/1` are one row; its MAC, speed and oper status are kept;
// `other` becomes the template's type; nothing is duplicated.
//
// Mutation: make InstantiateInterfaceTemplatesTx skip the `existing` lookup
// (always insert) → the insert hits interfaces_identity_uniq or the count is
// 52+12; remove the `cur.Type == "other"` fill → type stays other.
func TestIntegration_Catalogue_ApplyDeviceType_MergesMeasured(t *testing.T) {
	owner, app, tenant, svc := catFixture(t)
	ctx := ifaceActorCtx()
	_, dt := catSeedPlatformType(t, owner, "Cisco", "Catalyst 9300-48P "+uuid.NewString()[:6], 48)
	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")

	// SNMP measured 12 of the ports, short-named, with MACs and speeds.
	ifs := NewInterfaceService(app)
	var obs []ObservedInterface
	for i := 1; i <= 12; i++ {
		speed := int64(1_000_000)
		obs = append(obs, ObservedInterface{
			Name: fmt.Sprintf("Gi1/0/%d", i), Vendor: "cisco", Type: "other",
			MAC: fmt.Sprintf("00:11:22:33:44:%02x", i), SpeedKbps: &speed, OperationalStatus: "up", AdminStatus: "up",
		})
	}
	if _, err := ifs.UpsertObserved(ctx, tenant, asset, "snmp", obs); err != nil {
		t.Fatalf("observe: %v", err)
	}

	res, err := svc.ApplyDeviceType(ctx, tenant, asset, dt)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.Interfaces.Created != 36 || res.Interfaces.Updated != 12 {
		t.Fatalf("apply: created %d updated %d, want 36 and 12 (%+v)", res.Interfaces.Created, res.Interfaces.Updated, res.Interfaces)
	}
	if res.Components[ComponentConsolePort].Created != 1 || len(res.NotInstantiated) != 0 {
		t.Fatalf("the console template was not instantiated (row 3.1): components %+v, not instantiated %+v", res.Components, res.NotInstantiated)
	}
	list, total, err := ifs.List(ctx, tenant, InterfaceFilter{AssetID: &asset, Limit: 200})
	if err != nil || total != 48 {
		t.Fatalf("interfaces on the asset: %d (%v), want 48 — merged, not duplicated", total, err)
	}
	for _, i := range list {
		if i.Type != "1000base-t" {
			t.Fatalf("%s type %q, want the template's 1000base-t", i.Name, i.Type)
		}
		if i.Name == "GigabitEthernet1/0/3" {
			if i.MACAddress == nil || *i.MACAddress != "00:11:22:33:44:03" || i.SpeedKbps == nil || *i.SpeedKbps != 1_000_000 ||
				i.OperationalStatus == nil || *i.OperationalStatus != "up" || i.SourceKind != "measured" {
				t.Fatalf("measured fields of %s were not kept: %+v", i.Name, i)
			}
		}
	}
	hw, err := svc.Hardware(ctx, tenant, asset)
	if err != nil || hw.DeviceType == nil || hw.DeviceType.ID != dt || hw.Manufacturer == nil || hw.Manufacturer.Name != "Cisco" {
		t.Fatalf("hardware after apply: %+v (%v)", hw, err)
	}
	var recorded int
	if err := owner.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND object_kind = 'interface' AND source = 'ui'`, tenant).Scan(&recorded); err != nil || recorded != 48 {
		t.Fatalf("change records for the apply: %d (%v), want 48 (36 creates + 12 fills)", recorded, err)
	}
}

// Re-applying the same type changes nothing; switching to another type adds
// its interfaces, never deletes a measured one, and removes only what the
// previous type declared that carries no data.
//
// Mutation: drop the `cur.ObservationCount > 0` guard → the observed
// template interface is deleted; drop `*cur.SourceRef == ref` → re-apply
// deletes its own rows; drop `wanted[name]` → shared names are removed.
func TestIntegration_Catalogue_ApplyDeviceType_IdempotentAndAdditive(t *testing.T) {
	owner, app, tenant, svc := catFixture(t)
	ctx := ifaceActorCtx()
	_, small := catSeedPlatformType(t, owner, "Cisco", "Small "+uuid.NewString()[:6], 8)
	_, big := catSeedPlatformType(t, owner, "Cisco", "Big "+uuid.NewString()[:6], 4)
	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")
	ifs := NewInterfaceService(app)

	// A measured interface the templates do not name.
	if _, err := ifs.UpsertObserved(ctx, tenant, asset, "snmp", []ObservedInterface{{Name: "Vlan1", Vendor: "cisco"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApplyDeviceType(ctx, tenant, asset, small); err != nil {
		t.Fatalf("apply: %v", err)
	}
	again, err := svc.ApplyDeviceType(ctx, tenant, asset, small)
	if err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if again.Interfaces.Created != 0 || again.Interfaces.Updated != 0 || again.Interfaces.Removed != 0 || again.Interfaces.Unchanged != 8 {
		t.Fatalf("re-apply was not idempotent: %+v", again.Interfaces)
	}

	// Ports 7 and 8 now carry data: 7 was observed by a collector, 8 has an
	// address. Ports 5 and 6 carry nothing.
	if _, err := ifs.UpsertObserved(ctx, tenant, asset, "snmp", []ObservedInterface{
		{Name: "Vlan1", Vendor: "cisco"}, {Name: "GigabitEthernet1/0/7", Vendor: "cisco", OperationalStatus: "up"},
	}); err != nil {
		t.Fatal(err)
	}
	var port8 uuid.UUID
	if err := owner.QueryRow(`SELECT id FROM interfaces WHERE tenant_id = $1 AND asset_id = $2 AND name = 'GigabitEthernet1/0/8'`, tenant, asset).Scan(&port8); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`INSERT INTO ip_addresses (tenant_id, address, assigned_kind, assigned_id) VALUES ($1, '10.9.9.8/24', 'interface', $2)`, tenant, port8); err != nil {
		t.Fatalf("seed address: %v", err)
	}

	sw, err := svc.ApplyDeviceType(ctx, tenant, asset, big)
	if err != nil {
		t.Fatalf("switch type: %v", err)
	}
	// big has ports 1-4: all four exist (re-attributed), ports 5 and 6 go,
	// 7 (observed) and 8 (addressed) stay, Vlan1 (measured) stays.
	if sw.Interfaces.Created != 0 || sw.Interfaces.Removed != 2 {
		t.Fatalf("switch: %+v, want 0 created and 2 removed", sw.Interfaces)
	}
	names := map[string]bool{}
	list, _, err := ifs.List(ctx, tenant, InterfaceFilter{AssetID: &asset, Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range list {
		names[i.Name] = true
	}
	for _, keep := range []string{"Vlan1", "GigabitEthernet1/0/1", "GigabitEthernet1/0/4", "GigabitEthernet1/0/7", "GigabitEthernet1/0/8"} {
		if !names[keep] {
			t.Fatalf("%s was removed by the type switch (have %v)", keep, names)
		}
	}
	for _, gone := range []string{"GigabitEthernet1/0/5", "GigabitEthernet1/0/6"} {
		if names[gone] {
			t.Fatalf("%s (declared by the old type, no data) was kept", gone)
		}
	}
	// Back to small: additive again — 5 and 6 come back, nothing is lost.
	back, err := svc.ApplyDeviceType(ctx, tenant, asset, small)
	if err != nil || back.Interfaces.Created != 2 || back.Interfaces.Removed != 0 {
		t.Fatalf("switch back: %+v (%v), want 2 created and none removed", back, err)
	}
}

// A device type applies to hardware-class assets only, and the hardware patch
// checks the references it writes are the tenant's or the platform's.
func TestIntegration_Catalogue_Hardware_PatchAndClassRule(t *testing.T) {
	owner, _, tenant, svc := catFixture(t)
	ctx := ifaceActorCtx()
	_, dt := catSeedPlatformType(t, owner, "Arista", "DCS-7050 "+uuid.NewString()[:6], 1)
	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")

	var vm uuid.UUID
	if err := owner.QueryRow(`INSERT INTO assets (tenant_id, hostname, class_key, class_path, asset_status)
		VALUES ($1, 'vm1', 'virtual_machine', 'virtual.virtual_machine', 'monitoring') RETURNING id`, tenant).Scan(&vm); err != nil {
		t.Fatalf("seed vm: %v", err)
	}
	if _, err := svc.ApplyDeviceType(ctx, tenant, vm, dt); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("device type on a virtual machine: %v, want invalid", err)
	}

	var role uuid.UUID
	if err := owner.QueryRow(`SELECT id FROM device_roles WHERE tenant_id IS NULL AND slug = 'switch'`).Scan(&role); err != nil {
		t.Fatalf("the seeded `switch` device role: %v", err)
	}
	hw, err := svc.UpdateHardware(ctx, tenant, asset, HardwarePatch{
		"device_role_id": json.RawMessage(fmt.Sprintf("%q", role)),
		"serial":         json.RawMessage(`"FOC1234X0YZ"`),
		"asset_tag":      json.RawMessage(`"IT-0042"`),
	})
	if err != nil {
		t.Fatalf("patch hardware: %v", err)
	}
	if hw.DeviceRole == nil || hw.DeviceRole.Slug != "switch" || hw.Serial == nil || *hw.Serial != "FOC1234X0YZ" || hw.AssetTag == nil || *hw.AssetTag != "IT-0042" {
		t.Fatalf("hardware after patch: %+v", hw)
	}
	if _, err := svc.UpdateHardware(ctx, tenant, asset, HardwarePatch{"platform_id": json.RawMessage(fmt.Sprintf("%q", uuid.New()))}); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("unknown platform: %v, want invalid", err)
	}
	// The asset tag is unique per tenant among live assets.
	other := ifaceSeedAsset(t, owner, tenant, "monitoring")
	if _, err := svc.UpdateHardware(ctx, tenant, other, HardwarePatch{"asset_tag": json.RawMessage(`"IT-0042"`)}); !errors.Is(err, ErrIPAMConflict) {
		t.Fatalf("duplicate asset tag: %v, want conflict", err)
	}
	if _, err := svc.UpdateHardware(ctx, tenant, asset, HardwarePatch{"serial": json.RawMessage(`null`)}); err != nil {
		t.Fatalf("clear serial: %v", err)
	}
	var serial sql.NullString
	if err := owner.QueryRow(`SELECT serial FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, asset).Scan(&serial); err != nil || serial.Valid {
		t.Fatalf("serial not cleared: %v %v", serial, err)
	}
}
