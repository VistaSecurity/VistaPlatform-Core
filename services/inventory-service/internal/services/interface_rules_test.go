package services

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// The interface write rules (DCIM BUILD_PLAN row 1.2), as the pure function the
// service calls on create, bulk create and patch. Each case names the check it
// pins; removing that check turns the case green-when-it-should-be-red.

func ifaceStrp(s string) *string { return &s }

func ifaceWantField(t *testing.T, err error, field string) {
	t.Helper()
	var ve *InterfaceValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want a validation error on %s, got %v", field, err)
	}
	if ve.Field != field {
		t.Fatalf("want a validation error on %s, got one on %s (%s)", field, ve.Field, ve.Message)
	}
}

func TestInterfaces_LAGRules(t *testing.T) {
	asset, otherAsset := uuid.New(), uuid.New()
	po1, po2, gi1, gi2, foreignPo, vlan := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	refs := map[uuid.UUID]interfaceRef{
		po1:       {ID: po1, AssetID: asset, Type: "lag"},
		po2:       {ID: po2, AssetID: asset, Type: "lag"},
		gi1:       {ID: gi1, AssetID: asset, Type: "1000base-t"},
		gi2:       {ID: gi2, AssetID: asset, Type: "1000base-t", ParentID: &gi1},
		foreignPo: {ID: foreignPo, AssetID: otherAsset, Type: "lag"},
		vlan:      {ID: vlan, AssetID: asset, Type: "virtual"},
	}
	look := ifaceMapLookup(refs)
	base := func(typ string) InterfaceInput {
		return InterfaceInput{AssetID: asset, Name: "GigabitEthernet1/0/24", Type: typ}
	}

	t.Run("member of a LAG is accepted", func(t *testing.T) {
		in := base("1000base-t")
		in.LagID = &po1
		if err := validateInterface(in, uuid.New(), look); err != nil {
			t.Fatalf("valid LAG membership refused: %v", err)
		}
	})
	t.Run("member of a non-LAG interface is refused", func(t *testing.T) {
		in := base("1000base-t")
		in.LagID = &gi1
		ifaceWantField(t, validateInterface(in, uuid.New(), look), "lag_id")
	})
	t.Run("a LAG cannot be a member of a LAG", func(t *testing.T) {
		in := base("lag")
		in.LagID = &po2
		ifaceWantField(t, validateInterface(in, uuid.New(), look), "lag_id")
	})
	t.Run("a LAG on another asset is refused", func(t *testing.T) {
		in := base("1000base-t")
		in.LagID = &foreignPo
		ifaceWantField(t, validateInterface(in, uuid.New(), look), "lag_id")
	})
	t.Run("a virtual interface cannot be a LAG member", func(t *testing.T) {
		in := base("virtual")
		in.LagID = &po1
		ifaceWantField(t, validateInterface(in, uuid.New(), look), "lag_id")
	})
	t.Run("an interface cannot be its own LAG", func(t *testing.T) {
		in := base("lag")
		in.LagID = &po1
		ifaceWantField(t, validateInterface(in, po1, look), "lag_id")
	})
	t.Run("an unknown LAG is refused", func(t *testing.T) {
		in := base("1000base-t")
		missing := uuid.New()
		in.LagID = &missing
		ifaceWantField(t, validateInterface(in, uuid.New(), look), "lag_id")
	})
	t.Run("parent on another asset is refused", func(t *testing.T) {
		in := base("virtual")
		in.ParentID = &foreignPo
		ifaceWantField(t, validateInterface(in, uuid.New(), look), "parent_id")
	})
	t.Run("parent cycle is refused", func(t *testing.T) {
		// gi2's parent is gi1; making gi1's parent gi2 closes the loop.
		in := base("1000base-t")
		in.ParentID = &gi2
		ifaceWantField(t, validateInterface(in, gi1, look), "parent_id")
	})
	t.Run("parent self-reference is refused", func(t *testing.T) {
		in := base("virtual")
		in.ParentID = &vlan
		ifaceWantField(t, validateInterface(in, vlan, look), "parent_id")
	})
	t.Run("bridge on another asset is refused", func(t *testing.T) {
		in := base("virtual")
		in.BridgeID = &foreignPo
		ifaceWantField(t, validateInterface(in, uuid.New(), look), "bridge_id")
	})
	t.Run("a subinterface of a LAG is accepted", func(t *testing.T) {
		in := base("virtual")
		in.Name = "Port-channel1.100"
		in.ParentID = &po1
		if err := validateInterface(in, uuid.New(), look); err != nil {
			t.Fatalf("valid parent refused: %v", err)
		}
	})
}

func TestInterfaces_ModeRules(t *testing.T) {
	asset := uuid.New()
	look := ifaceMapLookup(map[uuid.UUID]interfaceRef{})
	v10, v20 := uuid.New(), uuid.New()
	base := func() InterfaceInput {
		return InterfaceInput{AssetID: asset, Name: "Gi1/0/1", Type: "1000base-t"}
	}
	ok := func(t *testing.T, in InterfaceInput) {
		t.Helper()
		if err := validateInterface(in, uuid.New(), look); err != nil {
			t.Fatalf("valid 802.1Q shape refused: %v", err)
		}
	}

	t.Run("untagged VLAN without a mode is refused", func(t *testing.T) {
		in := base()
		in.UntaggedVLANID = &v10
		ifaceWantField(t, validateInterface(in, uuid.New(), look), "untagged_vlan_id")
	})
	t.Run("access with an untagged VLAN is accepted", func(t *testing.T) {
		in := base()
		in.Mode, in.UntaggedVLANID = ifaceStrp("access"), &v10
		ok(t, in)
	})
	t.Run("tagged without tagged VLANs is refused", func(t *testing.T) {
		in := base()
		in.Mode = ifaceStrp("tagged")
		ifaceWantField(t, validateInterface(in, uuid.New(), look), "tagged_vlan_ids")
	})
	t.Run("tagged with tagged VLANs is accepted", func(t *testing.T) {
		in := base()
		in.Mode, in.TaggedVLANIDs, in.UntaggedVLANID = ifaceStrp("tagged"), []uuid.UUID{v10, v20}, &v10
		ok(t, in)
	})
	t.Run("tagged-all with tagged VLANs is refused", func(t *testing.T) {
		in := base()
		in.Mode, in.TaggedVLANIDs = ifaceStrp("tagged-all"), []uuid.UUID{v10}
		ifaceWantField(t, validateInterface(in, uuid.New(), look), "tagged_vlan_ids")
	})
	t.Run("tagged-all alone is accepted", func(t *testing.T) {
		in := base()
		in.Mode = ifaceStrp("tagged-all")
		ok(t, in)
	})
	t.Run("access with tagged VLANs is refused", func(t *testing.T) {
		in := base()
		in.Mode, in.TaggedVLANIDs = ifaceStrp("access"), []uuid.UUID{v10}
		ifaceWantField(t, validateInterface(in, uuid.New(), look), "tagged_vlan_ids")
	})
	t.Run("tagged VLANs without a mode are refused", func(t *testing.T) {
		in := base()
		in.TaggedVLANIDs = []uuid.UUID{v10}
		ifaceWantField(t, validateInterface(in, uuid.New(), look), "tagged_vlan_ids")
	})
	t.Run("an unknown mode is refused", func(t *testing.T) {
		in := base()
		in.Mode = ifaceStrp("trunk")
		ifaceWantField(t, validateInterface(in, uuid.New(), look), "mode")
	})
	t.Run("duplicate tagged VLANs are refused", func(t *testing.T) {
		in := base()
		in.Mode, in.TaggedVLANIDs = ifaceStrp("tagged"), []uuid.UUID{v10, v10}
		ifaceWantField(t, validateInterface(in, uuid.New(), look), "tagged_vlan_ids")
	})
}

func TestInterfaces_FieldRules(t *testing.T) {
	asset := uuid.New()
	look := ifaceMapLookup(map[uuid.UUID]interfaceRef{})
	in := InterfaceInput{AssetID: asset, Name: "eth0", Type: "not-a-type"}
	ifaceWantField(t, validateInterface(in, uuid.New(), look), "type")
	in.Type = "1000base-t"
	mtu := 0
	in.MTU = &mtu
	ifaceWantField(t, validateInterface(in, uuid.New(), look), "mtu")
	in.MTU = nil
	in.MACAddress = ifaceStrp("zz:zz")
	ifaceWantField(t, validateInterface(in, uuid.New(), look), "mac_address")
	in.MACAddress = ifaceStrp("0011.2233.4455")
	if err := validateInterface(in, uuid.New(), look); err != nil {
		t.Fatalf("dotted MAC refused: %v", err)
	}
	in.RFRole = ifaceStrp("ap")
	ifaceWantField(t, validateInterface(in, uuid.New(), look), "rf_role")
	in.Type = "ieee802.11ax"
	if err := validateInterface(in, uuid.New(), look); err != nil {
		t.Fatalf("wireless field on a wireless type refused: %v", err)
	}
	in.Name = " eth0"
	ifaceWantField(t, validateInterface(in, uuid.New(), look), "name")
}

func TestInterfaces_MACDisplay(t *testing.T) {
	for in, want := range map[string]string{
		"00:11:22:ff:fe:33:44:55": "00:11:22:33:44:55",
		"00:11:22:33:44:55:66:77": "00:11:22:33:44:55:66:77",
	} {
		if got := ifaceDisplayMAC(in); got != want {
			t.Errorf("display(%s) = %s, want %s", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"00-11-22-33-44-55": "00:11:22:33:44:55",
		"001122334455":      "00:11:22:33:44:55",
		"00:11:22:AA:BB:CC": "00:11:22:aa:bb:cc",
	} {
		if got, err := ifaceNormalizeMAC(in); err != nil || got != want {
			t.Errorf("normalize(%s) = %s, %v; want %s", in, got, err, want)
		}
	}
}

func TestInterfaces_PatchRefusesIdentityAndLifecycle(t *testing.T) {
	cur := InterfaceInput{AssetID: uuid.New(), Name: "eth0", Type: "1000base-t"}
	for _, k := range []string{"asset_id", "status", "source_kind", "operational_status", "observation_count"} {
		if _, err := ifaceApplyPatch(cur, map[string]json.RawMessage{k: json.RawMessage(`null`)}); !errors.Is(err, ErrInterfaceImmutable) {
			t.Errorf("patch of %s: want ErrInterfaceImmutable, got %v", k, err)
		}
	}
	got, err := ifaceApplyPatch(cur, map[string]json.RawMessage{"description": json.RawMessage(`"uplink"`), "mtu": json.RawMessage(`9000`)})
	if err != nil || got.Description == nil || *got.Description != "uplink" || got.MTU == nil || *got.MTU != 9000 || got.Name != "eth0" {
		t.Fatalf("merge patch: %+v, %v", got, err)
	}
	if _, err := ifaceApplyPatch(cur, map[string]json.RawMessage{"bogus": json.RawMessage(`1`)}); err == nil {
		t.Fatal("unknown field accepted")
	}
}
