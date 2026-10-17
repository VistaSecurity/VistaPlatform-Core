package services

// DB-integration tests for the internal DCIM import surface (BUILD_PLAN row
// 5.6, dcim_import.go). Skipped unless TEST_DATABASE_URL is set; run with make
// test-integration-db. The service runs on the NON-OWNER app role, so RLS is
// in force exactly as in production.

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func importOne(t *testing.T, svc *DCIMImportService, tenant uuid.UUID, kind dcim.ObjectKind, ref string, values map[string]any) ImportWriteResult {
	t.Helper()
	res, err := svc.Write(context.Background(), tenant, "device42", kind, []ImportWrite{{SourceRef: ref, PeerID: ref[strings.LastIndex(ref, ":")+1:], Values: values}})
	if err != nil {
		t.Fatalf("write %s: %v", kind, err)
	}
	if res[0].Error != "" {
		t.Fatalf("write %s %s: %s", kind, ref, res[0].Error)
	}
	return res[0]
}

// A whole chain — business unit, site, location, rack, manufacturer, device
// type, interface pair and the cable between them — written, matched again on
// source_ref, stamped as imported, change-recorded as intake:device42, and
// invisible to another tenant.
func TestIntegration_DCIMImport_WritesMatchesAndIsolates(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	svc := NewDCIMImportService(app, &database.DB{DB: sqlx.NewDb(app, "postgres")})
	ctx := context.Background()
	p := "device42:" + uuid.NewString() + ":"

	bu := importOne(t, svc, tenant, dcim.ObjectKindBusinessUnit, p+"business_units:1", map[string]any{"name": "Acme Corp"})
	site := importOne(t, svc, tenant, dcim.ObjectKindSite, p+"sites:10", map[string]any{"name": "HQ " + p[9:17], "physical_address": "1 Main St", "business_unit_id": bu.ID.String()})
	loc := importOne(t, svc, tenant, dcim.ObjectKindLocation, p+"locations:20", map[string]any{"name": "Hall A", "site_id": site.ID.String()})
	rack := importOne(t, svc, tenant, dcim.ObjectKindRack, p+"racks:30", map[string]any{"name": "R01", "site_id": site.ID.String(), "location_id": loc.ID.String(), "u_height": 42})
	mfr := importOne(t, svc, tenant, dcim.ObjectKindManufacturer, p+"manufacturers:dell", map[string]any{"name": "Dell " + p[9:17]})
	dt := importOne(t, svc, tenant, dcim.ObjectKindDeviceType, p+"device_types:40", map[string]any{"model": "R640", "manufacturer_id": mfr.ID.String(), "u_height": 1})
	for _, r := range []ImportWriteResult{bu, site, loc, rack, mfr, dt} {
		if r.Action != ImportCreated {
			t.Fatalf("first write action %q", r.Action)
		}
	}
	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")
	ifA := importOne(t, svc, tenant, dcim.ObjectKindInterface, p+"interfaces:60", map[string]any{"asset_id": asset.String(), "name": "Gi1/0/1", "type": "1000base-t"})
	ifB := importOne(t, svc, tenant, dcim.ObjectKindInterface, p+"interfaces:61", map[string]any{"asset_id": asset.String(), "name": "Gi1/0/2", "type": "1000base-t"})
	cable := importOne(t, svc, tenant, dcim.ObjectKindCable, p+"cables:if60-if61", map[string]any{
		"a_terminations": []map[string]any{{"termination_kind": "interface", "termination_id": ifA.ID.String()}},
		"b_terminations": []map[string]any{{"termination_kind": "interface", "termination_id": ifB.ID.String()}},
	})

	// Matched on source_ref: a second write updates the same object.
	again := importOne(t, svc, tenant, dcim.ObjectKindSite, p+"sites:10", map[string]any{"physical_address": "2 Elm St"})
	if again.Action != ImportUpdated || again.ID != site.ID {
		t.Fatalf("second site write = %+v, want an update of %s", again, site.ID)
	}
	var addr, kind, ref string
	if err := owner.QueryRow(`SELECT physical_address, source_kind, source_ref FROM sites WHERE id = $1`, site.ID).Scan(&addr, &kind, &ref); err != nil {
		t.Fatal(err)
	}
	if addr != "2 Elm St" || kind != "imported" || ref != p+"sites:10" {
		t.Fatalf("site row: %q %q %q", addr, kind, ref)
	}
	for table, id := range map[string]uuid.UUID{"racks": rack.ID, "device_types": dt.ID, "interfaces": ifA.ID, "cables": cable.ID, "locations": loc.ID} {
		var k string
		if err := owner.QueryRow(`SELECT source_kind FROM `+table+` WHERE id = $1`, id).Scan(&k); err != nil || k != "imported" {
			t.Errorf("%s source_kind = %q (%v)", table, k, err)
		}
	}
	var n int
	if err := owner.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND source = 'intake:device42'`, tenant).Scan(&n); err != nil || n < 9 {
		t.Errorf("intake:device42 change records = %d (%v)", n, err)
	}

	objs, err := svc.Objects(ctx, tenant, dcim.ObjectKindRack, p+"racks:")
	if err != nil || len(objs) != 1 || objs[0].ID != rack.ID || objs[0].Values["name"] != "R01" {
		t.Fatalf("objects = %+v (%v)", objs, err)
	}

	// Another tenant sees none of it and its own write with the same ref is
	// its own object.
	other := testdb.NewTenant(t, owner)
	if objs, _ := svc.Objects(ctx, other, dcim.ObjectKindRack, p+"racks:"); len(objs) != 0 {
		t.Fatalf("another tenant listed %d racks", len(objs))
	}
	theirs := importOne(t, svc, other, dcim.ObjectKindBusinessUnit, p+"business_units:1", map[string]any{"name": "Acme Corp"})
	if theirs.Action != ImportCreated || theirs.ID == bu.ID {
		t.Fatalf("another tenant's write matched this tenant's object: %+v", theirs)
	}

	// A reference outside the producer's namespace is refused per item.
	res, err := svc.Write(ctx, tenant, "device42", dcim.ObjectKindSite, []ImportWrite{{SourceRef: "netbox:1", Values: map[string]any{"name": "x"}}})
	if err != nil || res[0].Error == "" {
		t.Fatalf("a netbox: ref was accepted: %+v %v", res, err)
	}

	// Placement: the device type applied and the asset racked.
	pos := 10.0
	pres, err := svc.Placements(ctx, tenant, "device42", []ImportPlacement{{AssetID: asset, DeviceTypeID: &dt.ID, RackID: &rack.ID, Position: &pos, Face: "front"}})
	if err != nil || pres[0].Error != "" {
		t.Fatalf("placement: %+v %v", pres, err)
	}
	var rk uuid.UUID
	var dtID uuid.UUID
	if err := owner.QueryRow(`SELECT rack_id, device_type_id FROM assets WHERE id = $1`, asset).Scan(&rk, &dtID); err != nil || rk != rack.ID || dtID != dt.ID {
		t.Fatalf("asset placement %s %s (%v)", rk, dtID, err)
	}
}
