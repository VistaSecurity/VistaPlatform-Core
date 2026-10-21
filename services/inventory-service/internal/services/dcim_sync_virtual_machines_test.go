package services

// NetBox VM sync, without a database: the two sync kinds are routed to their
// own writers (never the generic engine, never the device asset's), a VM is
// never created without the asset the identity engine resolved, and each
// kind's peer id lives under its own key — so a NetBox device 12 and VM 12
// (or device interface 601 and VM interface 601) can never be one object here.
//
// MUTATIONS (each goes red; restore afterwards):
//   - drop the createVMKind call in create() → a VM create falls to the
//     generic path ("has no writer") and the no-id refusal is gone;
//   - make syncPeerKey answer the bare peer for vm_interface → the key test
//     fails (and, in the DB suite, a VM interface takes a device interface's
//     NetBox id).

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/syncauthority"
)

func TestDCIMSync_VMKindsHaveWriters(t *testing.T) {
	for _, k := range []dcim.ObjectKind{syncKindVirtualMachine, syncKindVMInterface} {
		spec, ok := syncauthority.Kind(k)
		if !ok {
			t.Fatalf("%s is not a synced kind", k)
		}
		if spec.Object == "" || spec.Stored() == k {
			t.Errorf("%s is not a sync kind over another object (object %q)", k, spec.Object)
		}
		if syncTableOf(k) == "" {
			t.Errorf("%s has no table", k)
		}
	}
	if syncTableOf(syncKindVirtualMachine) != "assets" || syncTableOf(syncKindVMInterface) != "interfaces" {
		t.Errorf("tables = %s, %s; want assets, interfaces", syncTableOf(syncKindVirtualMachine), syncTableOf(syncKindVMInterface))
	}
}

func TestDCIMSync_VMIsNeverCreatedWithoutTheResolvedAsset(t *testing.T) {
	s := NewDCIMSyncService(nil, nil)
	res, err := s.Write(context.Background(), uuid.New(), "netbox", syncKindVirtualMachine,
		[]SyncWrite{{Op: "create", Values: map[string]any{"display_name": "vm-1"}, PeerID: "12"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res[0].Error, "identity engine") {
		t.Errorf("a VM create without the resolved asset = %q, want the identity-engine refusal", res[0].Error)
	}
	// A column the registry does not sync is refused before anything runs.
	res, _ = s.Write(context.Background(), uuid.New(), "netbox", syncKindVirtualMachine,
		[]SyncWrite{{Op: "update", ID: uuid.New(), Values: map[string]any{"asset_status": "monitoring"}}})
	if !strings.Contains(res[0].Error, "not a synced column") {
		t.Errorf("an approval-state write = %q, want refused", res[0].Error)
	}
	if err := s.Delete(context.Background(), uuid.New(), "netbox", syncKindVirtualMachine, uuid.New()); !errors.Is(err, ErrSyncInvalid) {
		t.Errorf("a VM delete without the asset writer = %v, want ErrSyncInvalid", err)
	}
}

func TestDCIMSync_EachKindKeepsItsOwnPeerKey(t *testing.T) {
	if got := syncPeerKey("netbox", dcim.ObjectKindInterface); got != "netbox" {
		t.Errorf("a device interface's key = %q, want netbox", got)
	}
	if got := syncPeerKey("netbox", syncKindVMInterface); got == "netbox" || got == "" {
		t.Errorf("a VM interface's key = %q: it must differ from a device interface's", got)
	}
	if vmPeerKey == "netbox_device_id" {
		t.Error("a VM's NetBox id shares the device import's metadata key")
	}
	if syncStored(syncKindVirtualMachine) != dcim.ObjectKindAsset || syncStored(syncKindVMInterface) != dcim.ObjectKindInterface {
		t.Error("the sync kinds' changes are not recorded under their objects")
	}
}
