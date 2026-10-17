package services

// Row 3.5's inventory side of the NetBox sync, without a database: the port
// kinds are object-engine kinds, a cable is written by CableService, and a
// parked cable is checked before it is stored.
//
// MUTATIONS (each goes red; restore afterwards): drop componentSpecs() from
// dcimSyncSpecs → TestDCIMSync_EverySyncedKindHasAWriter; remove the
// parkCable call in Park → TestDCIMSync_ParkedCableIsChecked.

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

func TestDCIMSync_PortKindsWriteThroughTheirComponentSpecs(t *testing.T) {
	s := NewDCIMSyncService(nil, nil)
	for k := range syncPortKinds {
		sp, _ := s.engineFor(k)
		if sp == nil || sp.Prepare == nil || sp.AfterWrite == nil {
			t.Errorf("%s: no component spec (its Prepare rules and path recompute would not run)", k)
		}
	}
	if sp, _ := s.engineFor(dcim.ObjectKindDeviceBay); sp != nil {
		t.Error("device bays are not synced by row 3.5")
	}
}

func TestDCIMSync_ParkedCableIsChecked(t *testing.T) {
	s := NewDCIMSyncService(nil, nil)
	ends := map[string]any{
		"a_terminations": []any{map[string]any{"termination_kind": "interface", "termination_id": uuid.NewString()}},
		"b_terminations": []any{map[string]any{"termination_kind": "interface", "peer_id": "81"}},
	}
	for name, p := range map[string]SyncPark{
		"origin not a termination": {OriginKind: dcim.ObjectKindTunnel, OriginID: uuid.New(), FarKind: dcim.ObjectKindInterface, FarPeerID: "81",
			Intent: "cable", CreateKind: dcim.ObjectKindCable, PeerID: "903", Values: ends},
		"wrong intent": {OriginKind: dcim.ObjectKindInterface, OriginID: uuid.New(), FarKind: dcim.ObjectKindInterface, FarPeerID: "81",
			Intent: "assignment", CreateKind: dcim.ObjectKindCable, PeerID: "903", Values: ends},
		"no peer id": {OriginKind: dcim.ObjectKindInterface, OriginID: uuid.New(), FarKind: dcim.ObjectKindInterface, FarPeerID: "81",
			Intent: "cable", CreateKind: dcim.ObjectKindCable, Values: ends},
		"unsynced column": {OriginKind: dcim.ObjectKindInterface, OriginID: uuid.New(), FarKind: dcim.ObjectKindInterface, FarPeerID: "81",
			Intent: "cable", CreateKind: dcim.ObjectKindCable, PeerID: "903", Values: map[string]any{"status": "active"}},
	} {
		if err := s.Park(context.Background(), uuid.New(), "netbox", []SyncPark{p}); !errors.Is(err, ErrSyncInvalid) {
			t.Errorf("%s: Park = %v, want ErrSyncInvalid", name, err)
		}
	}
}

func TestDCIMSync_ACableCreateNamesOnlyTerminationsThatAreHere(t *testing.T) {
	for name, v := range map[string]any{
		"empty":       []any{},
		"by peer id":  []any{map[string]any{"termination_kind": "interface", "peer_id": "81"}},
		"placeholder": []any{map[string]any{"termination_kind": "interface", "termination_id": "peer:interface:81"}},
	} {
		if err := checkSyncEnd(v, "b_terminations"); !errors.Is(err, ErrSyncInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := checkSyncEnd([]any{map[string]any{"termination_kind": "interface", "termination_id": uuid.NewString()}}, "a_terminations"); err != nil {
		t.Errorf("a resolved end refused: %v", err)
	}
}
