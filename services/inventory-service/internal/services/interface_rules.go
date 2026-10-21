package services

// The interface object's shape and the rules a write must satisfy (DCIM
// BUILD_PLAN row 1.2; DATA_MODEL §2.4; asset-inventory ADR-0010 D3).
//
// The rules are a pure function over the candidate and a lookup of the other
// interfaces it names, so they are tested without a database
// (interface_rules_test.go) and the service applies exactly the same function
// on create, patch and bulk create. They follow NetBox 4.x's Interface.clean():
//
//   - LAG: `lag_id` names an interface of type `lag` on the SAME asset; a LAG
//     cannot itself be a member of a LAG; a virtual interface cannot be a
//     member.
//   - parent / bridge: same asset, never the interface itself, no cycles.
//   - 802.1Q: an untagged VLAN needs a mode; `tagged` needs at least one tagged
//     VLAN (the brief's rule; NetBox merely allows them); tagged VLANs are
//     refused in every other mode (`tagged-all` already carries every VLAN).
//   - wireless fields only on an ieee802.11 type.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// Interface is one row of `interfaces` as the API returns it.
type Interface struct {
	ID                 uuid.UUID    `json:"id"`
	AssetID            uuid.UUID    `json:"asset_id"`
	ModuleID           *uuid.UUID   `json:"module_id"`
	Name               string       `json:"name"`
	Label              *string      `json:"label"`
	Type               string       `json:"type"`
	TypeLabel          string       `json:"type_label"`
	Enabled            bool         `json:"enabled"`
	MgmtOnly           bool         `json:"mgmt_only"`
	MTU                *int         `json:"mtu"`
	MACAddress         *string      `json:"mac_address"`
	MACAddresses       []MacAddress `json:"mac_addresses"`
	SpeedKbps          *int64       `json:"speed_kbps"`
	Duplex             *string      `json:"duplex"`
	Mode               *string      `json:"mode"`
	UntaggedVLANID     *uuid.UUID   `json:"untagged_vlan_id"`
	TaggedVLANIDs      []uuid.UUID  `json:"tagged_vlan_ids"`
	VRFID              *uuid.UUID   `json:"vrf_id"`
	ParentID           *uuid.UUID   `json:"parent_id"`
	BridgeID           *uuid.UUID   `json:"bridge_id"`
	LagID              *uuid.UUID   `json:"lag_id"`
	RFRole             *string      `json:"rf_role"`
	RFChannel          *string      `json:"rf_channel"`
	RFChannelFrequency *float64     `json:"rf_channel_frequency"`
	RFChannelWidth     *float64     `json:"rf_channel_width"`
	TxPower            *int         `json:"tx_power"`
	PoEMode            *string      `json:"poe_mode"`
	PoEType            *string      `json:"poe_type"`
	WWN                *string      `json:"wwn"`
	OperationalStatus  *string      `json:"operational_status"`
	AdminStatus        *string      `json:"admin_status"`
	// VDCs is the names of the virtual device contexts the interface belongs
	// to (row 1.2's field, now read from interface_virtual_device_contexts);
	// VirtualDeviceContexts and VirtualDeviceContextIDs are the same
	// membership as {id, name} and as the ids a PATCH sends (DCIM gap 1).
	VDCs                    []string                  `json:"vdcs"`
	VirtualDeviceContexts   []VirtualDeviceContextRef `json:"virtual_device_contexts"`
	VirtualDeviceContextIDs []uuid.UUID               `json:"virtual_device_context_ids"`
	MarkConnected           bool                      `json:"mark_connected"`
	CableID                 *uuid.UUID                `json:"cable_id"`
	CableEnd                *string                   `json:"cable_end"`
	SourceKind              string                    `json:"source_kind"`
	SourceRef               *string                   `json:"source_ref"`
	CustomFields            map[string]any            `json:"custom_fields"`
	Description             *string                   `json:"description"`
	Comments                *string                   `json:"comments"`
	Status                  string                    `json:"status"`
	FirstSeenAt             time.Time                 `json:"first_seen_at"`
	LastSeenAt              time.Time                 `json:"last_seen_at"`
	ObservationCount        int                       `json:"observation_count"`
	ApprovedBy              *uuid.UUID                `json:"approved_by"`
	ApprovedAt              *time.Time                `json:"approved_at"`
	CreatedAt               time.Time                 `json:"created_at"`
	UpdatedAt               time.Time                 `json:"updated_at"`
	CreatedBy               *uuid.UUID                `json:"created_by"`
	// VLANTranslationPolicyID is the interface's VLAN translation policy
	// (DCIM gap 10; NetBox Interface.vlan_translation_policy).
	VLANTranslationPolicyID *uuid.UUID `json:"vlan_translation_policy_id"`
}

// MacAddress is one row of `mac_addresses`.
type MacAddress struct {
	ID         uuid.UUID `json:"id"`
	MAC        string    `json:"mac"`
	IsPrimary  bool      `json:"is_primary"`
	SourceKind string    `json:"source_kind"`
}

// InterfaceInput is the writable shape: the body of a create, and what a patch
// is merged onto. Absent nullable fields are nil; a patch that sends `null`
// clears them.
type InterfaceInput struct {
	AssetID            uuid.UUID   `json:"asset_id"`
	Name               string      `json:"name"`
	Label              *string     `json:"label"`
	Type               string      `json:"type"`
	Enabled            *bool       `json:"enabled"`
	MgmtOnly           bool        `json:"mgmt_only"`
	MTU                *int        `json:"mtu"`
	MACAddress         *string     `json:"mac_address"`
	MACAddresses       []string    `json:"mac_addresses"`
	SpeedKbps          *int64      `json:"speed_kbps"`
	Duplex             *string     `json:"duplex"`
	Mode               *string     `json:"mode"`
	UntaggedVLANID     *uuid.UUID  `json:"untagged_vlan_id"`
	TaggedVLANIDs      []uuid.UUID `json:"tagged_vlan_ids"`
	VRFID              *uuid.UUID  `json:"vrf_id"`
	ParentID           *uuid.UUID  `json:"parent_id"`
	BridgeID           *uuid.UUID  `json:"bridge_id"`
	LagID              *uuid.UUID  `json:"lag_id"`
	RFRole             *string     `json:"rf_role"`
	RFChannel          *string     `json:"rf_channel"`
	RFChannelFrequency *float64    `json:"rf_channel_frequency"`
	RFChannelWidth     *float64    `json:"rf_channel_width"`
	TxPower            *int        `json:"tx_power"`
	PoEMode            *string     `json:"poe_mode"`
	PoEType            *string     `json:"poe_type"`
	WWN                *string     `json:"wwn"`
	// The interface's virtual device contexts (DCIM gap 1): ids of contexts on
	// the same asset, or — the row 1.2 form — their names in VDCs. A write
	// names one or the other.
	VDCs                    []string       `json:"vdcs"`
	VirtualDeviceContextIDs []uuid.UUID    `json:"virtual_device_context_ids"`
	MarkConnected           bool           `json:"mark_connected"`
	Description             *string        `json:"description"`
	Comments                *string        `json:"comments"`
	CustomFields            map[string]any `json:"custom_fields"`
	// The interface's VLAN translation policy (DCIM gap 10), one of the
	// tenant's vlan_translation_policies; null clears it.
	VLANTranslationPolicyID *uuid.UUID `json:"vlan_translation_policy_id"`
}

// InterfaceValidationError is a rule a write broke; the API answers 422 with
// the field it names.
type InterfaceValidationError struct {
	Field   string
	Message string
}

func (e *InterfaceValidationError) Error() string { return e.Field + ": " + e.Message }

func ifaceInvalid(field, format string, args ...any) error {
	return &InterfaceValidationError{Field: field, Message: fmt.Sprintf(format, args...)}
}

// Errors the handlers map onto statuses.
var (
	ErrInterfaceNotFound      = errors.New("interface not found")
	ErrInterfaceAssetNotFound = errors.New("asset not found")
	ErrInterfaceNameTaken     = errors.New("an interface with this name already exists on the asset")
	ErrInterfaceImmutable     = errors.New("field cannot be changed")
)

// interfaceRef is what the rules need to know about an interface a candidate
// names as its LAG, parent or bridge.
type interfaceRef struct {
	ID       uuid.UUID
	AssetID  uuid.UUID
	Type     string
	LagID    *uuid.UUID
	ParentID *uuid.UUID
	BridgeID *uuid.UUID
}

// interfaceLookup answers for an interface id in the caller's tenant.
type interfaceLookup func(id uuid.UUID) (interfaceRef, bool)

// ifaceMaxChainWalk bounds the cycle walk. Real hierarchies are two or three deep
// (a subinterface of a LAG); anything near this is already a cycle.
const ifaceMaxChainWalk = 64

// validateInterface applies every rule to a candidate. selfID is the id the row
// has or will have (uuid.Nil is never a valid reference).
func validateInterface(in InterfaceInput, selfID uuid.UUID, lookup interfaceLookup) error {
	if in.AssetID == uuid.Nil {
		return ifaceInvalid("asset_id", "is required")
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return ifaceInvalid("name", "is required")
	}
	if name != in.Name {
		return ifaceInvalid("name", "must not begin or end with whitespace")
	}
	if len(name) > 64 {
		return ifaceInvalid("name", "must be at most 64 characters")
	}
	t, ok := dcim.ParseInterfaceType(in.Type)
	if !ok {
		return ifaceInvalid("type", "%q is not an interface type", in.Type)
	}
	if in.MTU != nil && (*in.MTU < 1 || *in.MTU > 65536) {
		return ifaceInvalid("mtu", "must be between 1 and 65536")
	}
	if in.SpeedKbps != nil && *in.SpeedKbps < 0 {
		return ifaceInvalid("speed_kbps", "must not be negative")
	}
	if in.Duplex != nil {
		if _, ok := dcim.ParseInterfaceDuplex(*in.Duplex); !ok {
			return ifaceInvalid("duplex", "%q is not a duplex", *in.Duplex)
		}
	}
	if in.PoEMode != nil {
		if _, ok := dcim.ParsePoEMode(*in.PoEMode); !ok {
			return ifaceInvalid("poe_mode", "%q is not a PoE mode", *in.PoEMode)
		}
	}
	if in.PoEType != nil {
		if _, ok := dcim.ParsePoEType(*in.PoEType); !ok {
			return ifaceInvalid("poe_type", "%q is not a PoE type", *in.PoEType)
		}
	}
	if in.MACAddress != nil {
		if _, err := ifaceNormalizeMAC(*in.MACAddress); err != nil {
			return ifaceInvalid("mac_address", "%v", err)
		}
	}
	for _, m := range in.MACAddresses {
		if _, err := ifaceNormalizeMAC(m); err != nil {
			return ifaceInvalid("mac_addresses", "%v", err)
		}
	}
	if err := ifaceValidateWireless(in, t); err != nil {
		return err
	}
	if err := ifaceValidateMode(in); err != nil {
		return err
	}
	return ifaceValidateHierarchy(in, t, selfID, lookup)
}

func ifaceValidateWireless(in InterfaceInput, t dcim.InterfaceType) error {
	if dcim.InterfaceTypeGroup(t) == "wireless" {
		return nil
	}
	if in.RFRole != nil || in.RFChannel != nil || in.RFChannelFrequency != nil || in.RFChannelWidth != nil {
		return ifaceInvalid("rf_role", "wireless fields apply only to a wireless (ieee802.11) interface type")
	}
	return nil
}

// ifaceValidateMode is the 802.1Q rule set.
func ifaceValidateMode(in InterfaceInput) error {
	if in.Mode == nil {
		if in.UntaggedVLANID != nil {
			return ifaceInvalid("untagged_vlan_id", "an untagged VLAN needs an 802.1Q mode")
		}
		if len(in.TaggedVLANIDs) > 0 {
			return ifaceInvalid("tagged_vlan_ids", "tagged VLANs need mode \"tagged\"")
		}
		return nil
	}
	mode, ok := dcim.ParseInterfaceMode(*in.Mode)
	if !ok {
		return ifaceInvalid("mode", "%q is not an 802.1Q mode", *in.Mode)
	}
	switch mode {
	case dcim.InterfaceModeTagged:
		if len(in.TaggedVLANIDs) == 0 {
			return ifaceInvalid("tagged_vlan_ids", "mode \"tagged\" needs at least one tagged VLAN")
		}
	case dcim.InterfaceModeTaggedAll:
		if len(in.TaggedVLANIDs) > 0 {
			return ifaceInvalid("tagged_vlan_ids", "mode \"tagged-all\" carries every VLAN; it takes no tagged VLAN list")
		}
	default:
		if len(in.TaggedVLANIDs) > 0 {
			return ifaceInvalid("tagged_vlan_ids", "tagged VLANs need mode \"tagged\"")
		}
	}
	seen := map[uuid.UUID]bool{}
	for _, v := range in.TaggedVLANIDs {
		if v == uuid.Nil || seen[v] {
			return ifaceInvalid("tagged_vlan_ids", "VLAN ids must be distinct and non-empty")
		}
		seen[v] = true
	}
	return nil
}

// ifaceValidateHierarchy is the LAG / parent / bridge rule set.
func ifaceValidateHierarchy(in InterfaceInput, t dcim.InterfaceType, selfID uuid.UUID, lookup interfaceLookup) error {
	if in.LagID != nil {
		if *in.LagID == selfID {
			return ifaceInvalid("lag_id", "an interface cannot be its own LAG")
		}
		lag, ok := lookup(*in.LagID)
		if !ok {
			return ifaceInvalid("lag_id", "no such interface")
		}
		if lag.AssetID != in.AssetID {
			return ifaceInvalid("lag_id", "the LAG must be an interface of the same asset")
		}
		if lag.Type != string(dcim.InterfaceTypeLag) {
			return ifaceInvalid("lag_id", "the LAG must be an interface of type \"lag\"")
		}
		if t == dcim.InterfaceTypeLag {
			return ifaceInvalid("lag_id", "a LAG cannot be a member of another LAG")
		}
		if t == dcim.InterfaceTypeVirtual || t == dcim.InterfaceTypeBridge {
			return ifaceInvalid("lag_id", "a virtual interface cannot be a LAG member")
		}
	}
	for _, rel := range []struct {
		field string
		id    *uuid.UUID
		next  func(interfaceRef) *uuid.UUID
	}{
		{"parent_id", in.ParentID, func(r interfaceRef) *uuid.UUID { return r.ParentID }},
		{"bridge_id", in.BridgeID, func(r interfaceRef) *uuid.UUID { return r.BridgeID }},
	} {
		if rel.id == nil {
			continue
		}
		if *rel.id == selfID {
			return ifaceInvalid(rel.field, "an interface cannot reference itself")
		}
		target, ok := lookup(*rel.id)
		if !ok {
			return ifaceInvalid(rel.field, "no such interface")
		}
		if target.AssetID != in.AssetID {
			return ifaceInvalid(rel.field, "must be an interface of the same asset")
		}
		// Walk up from the target; reaching selfID closes a cycle.
		cur := rel.next(target)
		for steps := 0; cur != nil; steps++ {
			if *cur == selfID || steps > ifaceMaxChainWalk {
				return ifaceInvalid(rel.field, "would create a cycle")
			}
			r, ok := lookup(*cur)
			if !ok {
				break
			}
			cur = rel.next(r)
		}
	}
	return nil
}

// ifaceNormalizeMAC accepts the usual spellings (colon, hyphen, dot, bare) of an
// EUI-48 or EUI-64 and returns the lowercase colon form.
func ifaceNormalizeMAC(s string) (string, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return "", errors.New("MAC address is empty")
	}
	if len(raw) == 12 || len(raw) == 16 {
		// Bare hex: insert colons so net.ParseMAC accepts it.
		var b strings.Builder
		for i := 0; i < len(raw); i += 2 {
			if i > 0 {
				b.WriteByte(':')
			}
			b.WriteString(raw[i : i+2])
		}
		raw = b.String()
	}
	hw, err := net.ParseMAC(raw)
	if err != nil || (len(hw) != 6 && len(hw) != 8) {
		return "", fmt.Errorf("%q is not a MAC address", s)
	}
	return hw.String(), nil
}

// ifaceDisplayMAC turns Postgres's macaddr8 rendering back into the form it was
// written in. macaddr8 stores an EUI-48 as the EUI-64 with ff:fe in the middle
// (00:11:22:33:44:55 → 00:11:22:ff:fe:33:44:55); nobody reads a MAC that way.
func ifaceDisplayMAC(s string) string {
	parts := strings.Split(s, ":")
	if len(parts) == 8 && strings.EqualFold(parts[3], "ff") && strings.EqualFold(parts[4], "fe") {
		return strings.Join(append(parts[:3:3], parts[5:]...), ":")
	}
	return s
}

// ifaceInputOf is the writable projection of a stored interface, what a patch is
// merged onto.
func ifaceInputOf(i Interface) InterfaceInput {
	enabled := i.Enabled
	var extra []string
	for _, m := range i.MACAddresses {
		if !m.IsPrimary {
			extra = append(extra, m.MAC)
		}
	}
	return InterfaceInput{
		AssetID: i.AssetID, Name: i.Name, Label: i.Label, Type: i.Type, Enabled: &enabled,
		MgmtOnly: i.MgmtOnly, MTU: i.MTU, MACAddress: i.MACAddress, MACAddresses: extra,
		SpeedKbps: i.SpeedKbps, Duplex: i.Duplex, Mode: i.Mode, UntaggedVLANID: i.UntaggedVLANID,
		TaggedVLANIDs: i.TaggedVLANIDs, VRFID: i.VRFID, ParentID: i.ParentID, BridgeID: i.BridgeID,
		LagID: i.LagID, RFRole: i.RFRole, RFChannel: i.RFChannel, RFChannelFrequency: i.RFChannelFrequency,
		RFChannelWidth: i.RFChannelWidth, TxPower: i.TxPower, PoEMode: i.PoEMode, PoEType: i.PoEType,
		WWN: i.WWN, VirtualDeviceContextIDs: i.VirtualDeviceContextIDs, MarkConnected: i.MarkConnected, Description: i.Description,
		Comments: i.Comments, CustomFields: i.CustomFields, VLANTranslationPolicyID: i.VLANTranslationPolicyID,
	}
}

// ifacePatchImmutable are the keys a PATCH may not send: identity and lifecycle are
// not edited through the object (moving an interface to another asset is a
// delete and a create, as NetBox's UI makes it).
var ifacePatchImmutable = map[string]bool{
	"id": true, "asset_id": true, "status": true, "source_kind": true, "source_ref": true,
	"first_seen_at": true, "last_seen_at": true, "observation_count": true,
	"operational_status": true, "admin_status": true, "created_at": true, "updated_at": true,
	"created_by": true, "approved_by": true, "approved_at": true, "cable_id": true, "cable_end": true,
}

// ifaceApplyPatch merges a JSON merge-patch onto the current writable shape.
func ifaceApplyPatch(cur InterfaceInput, patch map[string]json.RawMessage) (InterfaceInput, error) {
	for k := range patch {
		if ifacePatchImmutable[k] {
			return cur, fmt.Errorf("%w: %s", ErrInterfaceImmutable, k)
		}
	}
	base, err := json.Marshal(cur)
	if err != nil {
		return cur, err
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(base, &merged); err != nil {
		return cur, err
	}
	for k, v := range patch {
		merged[k] = v
	}
	body, err := json.Marshal(merged)
	if err != nil {
		return cur, err
	}
	var out InterfaceInput
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return cur, ifaceInvalid("body", "%v", err)
	}
	return out, nil
}
