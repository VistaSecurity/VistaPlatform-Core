package services

// DB-integration tests for the tenant device-type import and the "done means"
// path of DCIM row 2.2: a tenant takes the Cisco C9300-48P (from the seed
// subset, or imported from the library when the seed is absent), assigns it to
// a discovered switch, applies templates, and the switch's interfaces are the
// type's ports merged with the ones SNMP had already measured.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func libFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "shared", "dcim", "devicetypelib", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A library YAML the catalogue lacks becomes the tenant's own type with every
// template; a second import of it, or of a type the platform already has, is
// `exists`; a bad document leaves nothing behind (one transaction).
//
// Mutation: drop the existing-type lookup in importOne → the second import
// creates a duplicate and fails on the slug index (conflict), not `exists`.
func TestIntegration_Catalogue_ImportLibraryYAML(t *testing.T) {
	owner, _, tenant, svc := catFixture(t)
	ctx := ifaceActorCtx()

	res, err := svc.ImportDeviceTypes(ctx, tenant, libFixture(t, "panduit-cpa24bly.yaml"))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(res) != 1 || res[0].Status != "created" || res[0].Templates != 48 {
		t.Fatalf("import result %+v, want created with 48 templates", res)
	}
	var mapped, tenantRows int
	if err := owner.QueryRow(`SELECT count(*) FROM front_port_templates WHERE device_type_id = $1 AND rear_port_id IS NOT NULL`, res[0].DeviceTypeID).Scan(&mapped); err != nil || mapped != 24 {
		t.Fatalf("front ports mapped to rear ports: %d (%v), want 24", mapped, err)
	}
	if err := owner.QueryRow(`SELECT count(*) FROM device_types WHERE id = $1 AND tenant_id = $2 AND source_kind = 'imported'
		AND external_ids->'library'->>'front_image' = 'elevation-images/Panduit/panduit-cpa24bly.front.png'`, res[0].DeviceTypeID, tenant).Scan(&tenantRows); err != nil || tenantRows != 1 {
		t.Fatalf("imported type is not the tenant's, imported, with its image path (%d, %v)", tenantRows, err)
	}

	again, err := svc.ImportDeviceTypes(ctx, tenant, libFixture(t, "panduit-cpa24bly.yaml"))
	if err != nil || again[0].Status != "exists" || again[0].DeviceTypeID != res[0].DeviceTypeID {
		t.Fatalf("re-import: %+v (%v), want exists", again, err)
	}

	bad := append(libFixture(t, "apc-ap7900b.yaml"), []byte("\n---\nmanufacturer: APC\n")...)
	if _, err := svc.ImportDeviceTypes(ctx, tenant, bad); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("a request with an invalid document: %v, want invalid", err)
	}
	var pdu int
	if err := owner.QueryRow(`SELECT count(*) FROM device_types WHERE tenant_id = $1 AND part_number = 'AP7900B'`, tenant).Scan(&pdu); err != nil || pdu != 0 {
		t.Fatalf("a failed request left %d rows behind (%v)", pdu, err)
	}
}

// DCIM row 2.2 "done means": the C9300-48P on a switch SNMP measured 12 ports
// of — the Interfaces tab shows 48 typed GigabitEthernet ports, the 12 measured
// ones carrying their MACs, nothing duplicated.
func TestIntegration_Catalogue_DoneMeans_C9300OnMeasuredSwitch(t *testing.T) {
	owner, app, tenant, svc := catFixture(t)
	ctx := ifaceActorCtx()

	res, err := svc.ImportDeviceTypes(ctx, tenant, libFixture(t, "cisco-c9300-48p.yaml"))
	if err != nil || len(res) != 1 {
		t.Fatalf("import or find the C9300-48P: %+v (%v)", res, err)
	}
	dt := res[0].DeviceTypeID
	t.Logf("C9300-48P: %s (%s)", dt, res[0].Status)

	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")
	ifs := NewInterfaceService(app)
	var obs []ObservedInterface
	for i := 1; i <= 12; i++ {
		speed := int64(1_000_000)
		obs = append(obs, ObservedInterface{Name: fmt.Sprintf("Gi1/0/%d", i), Vendor: "cisco",
			MAC: fmt.Sprintf("00:aa:bb:cc:dd:%02x", i), SpeedKbps: &speed, OperationalStatus: "up"})
	}
	if _, err := ifs.UpsertObserved(ctx, tenant, asset, "snmp", obs); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApplyDeviceType(ctx, tenant, asset, dt); err != nil {
		t.Fatalf("apply: %v", err)
	}
	list, _, err := ifs.List(ctx, tenant, InterfaceFilter{AssetID: &asset, Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	var gig, measured int
	for _, i := range list {
		if strings.HasPrefix(i.Name, "GigabitEthernet1/0/") {
			gig++
			if i.Type != "1000base-t" {
				t.Fatalf("%s type %q", i.Name, i.Type)
			}
			if i.MACAddress != nil {
				measured++
			}
		}
	}
	if gig != 48 || measured != 12 || len(list) != 51 {
		t.Fatalf("interfaces: %d total, %d GigabitEthernet1/0/x, %d with a measured MAC — want 51, 48, 12", len(list), gig, measured)
	}
}
