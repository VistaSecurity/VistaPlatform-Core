package services

// Row 4.5's inventory side of the NetBox sync, without a database: every
// synced kind has a writer, and a parked termination names a parent and
// columns the sync may write.

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/syncauthority"
)

// Every kind the authority registry syncs can be written here: by the IPAM
// engine, by the row 4.1–4.4 object engine, or by its own writer (business
// units, interfaces). mac_address has authorities but no wire mapping yet.
func TestDCIMSync_EverySyncedKindHasAWriter(t *testing.T) {
	s := NewDCIMSyncService(nil, nil)
	own := map[dcim.ObjectKind]bool{dcim.ObjectKindBusinessUnit: true, dcim.ObjectKindInterface: true, dcim.ObjectKindMacAddress: true}
	// Row 2.6's typed kinds (SiteService, the asset's own writers):
	// TestDCIMSync_RowTwoSixTypedKindsHaveWriters.
	for k := range dcimSiteKinds {
		own[k] = true
	}
	own[dcim.ObjectKindAsset] = true
	// Row 3.5: a cable is written by CableService (dcim_sync_cabling_test.go).
	own[dcim.ObjectKindCable] = true
	// NetBox VM sync: the two sync kinds are written by their objects'
	// services (dcim_sync_virtual_machines.go; TestDCIMSync_VMKindsHaveWriters).
	own[syncKindVirtualMachine], own[syncKindVMInterface] = true, true
	for _, k := range syncauthority.Kinds() {
		if own[k.Kind] {
			continue
		}
		sp, eng := s.engineFor(k.Kind)
		if sp == nil || eng == nil {
			t.Errorf("%s is synced but has no writer", k.Kind)
			continue
		}
		if sp.Table != k.Kind.Table() {
			t.Errorf("%s writes %s, want %s", k.Kind, sp.Table, k.Kind.Table())
		}
		// The matcher and the link step need the peer id column.
		if _, ok := sp.col("external_ids"); !ok && !sp.Catalogue {
			t.Errorf("%s cannot carry a peer id (no external_ids in its engine spec)", k.Kind)
		}
	}
}

func TestDCIMSync_ParkOnParentIsChecked(t *testing.T) {
	s := NewDCIMSyncService(nil, nil)
	ctx := context.Background()
	for name, p := range map[string]SyncPark{
		"wrong parent": {OriginKind: dcim.ObjectKindL2vpn, OriginID: uuid.New(), FarKind: dcim.ObjectKindInterface, FarPeerID: "1",
			Intent: "assignment", CreateKind: dcim.ObjectKindTunnelTermination},
		"not a parked kind": {OriginKind: dcim.ObjectKindCircuit, OriginID: uuid.New(), FarKind: dcim.ObjectKindSite, FarPeerID: "1",
			Intent: "assignment", CreateKind: dcim.ObjectKindCircuitTermination},
		"unsynced column": {OriginKind: dcim.ObjectKindTunnel, OriginID: uuid.New(), FarKind: dcim.ObjectKindInterface, FarPeerID: "1",
			Intent: "assignment", CreateKind: dcim.ObjectKindTunnelTermination, Values: map[string]any{"source_kind": "declared"}},
	} {
		if err := s.Park(ctx, uuid.New(), "netbox", []SyncPark{p}); !errors.Is(err, ErrSyncInvalid) {
			t.Errorf("%s: err = %v, want ErrSyncInvalid", name, err)
		}
	}
}
