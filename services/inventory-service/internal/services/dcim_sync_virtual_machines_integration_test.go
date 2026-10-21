package services

// DB-integration tests for the NetBox VM sync's inventory side, on the
// NON-OWNER app role (RLS in force). Skipped unless TEST_DATABASE_URL is set.
//
// A VM create adopts the asset the identity engine resolved — never a NetBox
// device's asset, never one already claimed by ANOTHER NetBox VM — and writes
// its cluster and resources through the virtualization service's rules; a VM
// interface is created only on such a VM.
//
// MUTATIONS (each goes red; restore afterwards):
//   - drop the requireVMSide call in claimVM → a device's asset is adopted as
//     NetBox VM 12;
//   - drop the "already NetBox virtual machine" refusal in claimVM → a second
//     NetBox VM takes over the first one's asset;
//   - drop the requireVMSide call in createVMKind's vm_interface branch → a VM
//     interface is created on a device.

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
)

func vmSyncSeedAsset(t *testing.T, owner *sql.DB, tenant uuid.UUID, class, path, metadata string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := owner.Exec(`INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path, asset_status, metadata)
		VALUES ($1, $2, $3, $3, $4, $5, 'monitoring', $6::jsonb)`, id, tenant, class+"-"+id.String()[:8], class, path, metadata); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	return id
}

func TestIntegration_DCIMSync_VMAdoptionGuards(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	s := NewDCIMSyncService(app, &database.DB{DB: sqlx.NewDb(app, "postgres")})
	ctx := changes.WithSource(context.Background(), changes.SyncSource("netbox"))
	kvm := virtPlatformType(t, owner, "kvm")
	var cluster uuid.UUID
	if err := owner.QueryRow(`INSERT INTO clusters (tenant_id, name, type_id) VALUES ($1, 'c-adopt', $2) RETURNING id`, tenant, kvm).Scan(&cluster); err != nil {
		t.Fatalf("seed cluster: %v", err)
	}
	device := vmSyncSeedAsset(t, owner, tenant, "server", "hardware.compute.server", `{"netbox_device_id": 12}`)
	deviceAsVM := vmSyncSeedAsset(t, owner, tenant, "virtual_machine", "virtual.virtual_machine", `{"netbox_device_id": 13}`)
	vm := vmSyncSeedAsset(t, owner, tenant, "virtual_machine", "virtual.virtual_machine", `{}`)

	write := func(kind string, w SyncWrite) string {
		t.Helper()
		res, err := s.Write(ctx, tenant, "netbox", dcim.ObjectKind(kind), []SyncWrite{w})
		if err != nil {
			t.Fatalf("write: %v", err)
		}
		return res[0].Error
	}
	adopt := func(asset uuid.UUID, peer string) string {
		return write("virtual_machine", SyncWrite{Op: "create", ID: asset, PeerID: peer,
			Values: map[string]any{"cluster_id": cluster.String(), "display_name": "x", "vcpus": 2, "memory_mb": 2048}})
	}

	if e := adopt(device, "12"); !strings.Contains(e, "not a virtual machine this sync owns") {
		t.Errorf("adopting a device's asset as NetBox VM 12 = %q, want refused", e)
	}
	if e := adopt(deviceAsVM, "13"); !strings.Contains(e, "not a virtual machine this sync owns") {
		t.Errorf("adopting a NetBox device's asset classed as a VM = %q, want refused", e)
	}
	if e := adopt(vm, "21"); e != "" {
		t.Fatalf("adopting a VM: %s", e)
	}
	var got string
	if err := owner.QueryRow(`SELECT (metadata ->> 'netbox_vm_id') || '/' || cluster_id::text || '/' || vcpus::int || '/' || memory_mb
		FROM assets WHERE id = $1`, vm).Scan(&got); err != nil || got != "21/"+cluster.String()+"/2/2048" {
		t.Errorf("adopted VM = %q (%v)", got, err)
	}
	if e := adopt(vm, "22"); !strings.Contains(e, "already NetBox virtual machine 21") {
		t.Errorf("a second NetBox VM onto the same asset = %q, want refused", e)
	}
	if e := write("vm_interface", SyncWrite{Op: "create", PeerID: "601", Values: map[string]any{"asset_id": device.String(), "name": "eth0"}}); !strings.Contains(e, "not a virtual machine") {
		t.Errorf("a VM interface on a device = %q, want refused", e)
	}
	if e := write("vm_interface", SyncWrite{Op: "create", PeerID: "601", Values: map[string]any{"asset_id": vm.String(), "name": "eth0"}}); e != "" {
		t.Fatalf("a VM interface on the VM: %s", e)
	}
	if err := owner.QueryRow(`SELECT type || '/' || (external_ids ->> 'netbox:vm_interface') || '/' || (external_ids ? 'netbox')::text
		FROM interfaces WHERE asset_id = $1`, vm).Scan(&got); err != nil || got != "virtual/601/false" {
		t.Errorf("VM interface = %q (%v)", got, err)
	}
	// The device interface listing never shows it; the VM interface listing does.
	ifs, _, err := s.ListObjects(ctx, tenant, dcim.ObjectKind("interface"), uuid.Nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range ifs {
		if o.Values["asset_id"] == vm.String() {
			t.Error("a VM's interface is listed as a device interface")
		}
	}
	vifs, _, err := s.ListObjects(ctx, tenant, dcim.ObjectKind("vm_interface"), uuid.Nil, 100)
	if err != nil || len(vifs) != 1 {
		t.Fatalf("VM interfaces listed = %d (%v), want 1", len(vifs), err)
	}
	if ext, _ := vifs[0].Values["external_ids"].(map[string]any); ext["netbox"] != "601" {
		t.Errorf("the VM interface is listed with external_ids %v, want netbox 601", vifs[0].Values["external_ids"])
	}
	vms, _, err := s.ListObjects(ctx, tenant, dcim.ObjectKind("virtual_machine"), uuid.Nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range vms {
		if o.ID == device || o.ID == deviceAsVM {
			t.Errorf("asset %s (a NetBox device's) is listed as a VM", o.ID)
		}
	}
	if len(vms) != 1 || vms[0].ID != vm {
		t.Errorf("VMs listed = %d, want the one adopted", len(vms))
	}
}
