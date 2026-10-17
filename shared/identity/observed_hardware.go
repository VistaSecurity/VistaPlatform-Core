package identity

import (
	"fmt"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/dcim/ifnames"
)

// The hardware half of the intake seam (DCIM BUILD_PLAN row 2.4, ADR-0010 D4):
// what a collector read of a device's physical parts — ENTITY-MIB
// entPhysicalTable over SNMP, Cisco `show inventory` / `show switch` over SSH —
// carried on the sighting beside its interfaces. Like the tunnels (row 4.3),
// none of it is identity: the engine never reads it, and inventory-service
// writes it on the engine's transaction once the sighting resolved to an asset
// (inventory_item_service.go UpsertObservedHardware), measured fields only.
//
// Posture only: names, part numbers and serials of hardware parts. Nothing
// here can carry a credential.

// ObservedInventoryItem is one hardware part a collector listed.
type ObservedInventoryItem struct {
	// Name as the device names the part ("Switch 1 - Power Supply A",
	// "Te1/1/1"); 1-64 characters. With Parent, the item's identity.
	Name string `json:"name"`
	// Parent names another item of the same observation this one sits in
	// (entPhysicalContainedIn); empty at the top level.
	Parent string `json:"parent,omitempty"`
	// Role is an inventory item role slug the collector inferred from the
	// part's class (psu, fan, transceiver, linecard, supervisor, cpu, memory,
	// disk); empty when it cannot tell.
	Role         string `json:"role,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	PartID       string `json:"part_id,omitempty"`
	Serial       string `json:"serial,omitempty"`
	AssetTag     string `json:"asset_tag,omitempty"`
	Description  string `json:"description,omitempty"`
	// Interface names the interface this part IS or plugs into (a
	// transceiver's port, entAliasMappingTable's ifIndex); the item is linked
	// to it when the asset has an interface of that canonical name.
	Interface string `json:"interface,omitempty"`
}

// ObservedModule is a field-replaceable module seen in a named bay.
type ObservedModule struct {
	// Bay names the module bay (the slot's name) on the asset.
	Bay string `json:"bay"`
	// PartID is the module's product id (PID / entPhysicalModelName); the
	// module type is the tenant's or the platform's with that part number or
	// model. An unknown part installs nothing (the inventory item records it).
	PartID   string `json:"part_id"`
	Serial   string `json:"serial,omitempty"`
	AssetTag string `json:"asset_tag,omitempty"`
}

// ObservedVirtualChassisMember is one member of a stack.
type ObservedVirtualChassisMember struct {
	// Position is the member's stack number (`show switch` Switch#), 0-255.
	Position int `json:"position"`
	// Priority is the stack priority, 0-255; nil when the source did not say.
	Priority *int `json:"priority,omitempty"`
	// Master marks the active / master member.
	Master bool   `json:"master,omitempty"`
	Serial string `json:"serial,omitempty"`
	Model  string `json:"model,omitempty"`
}

// ObservedVirtualChassis is the stack an observed device is the management
// face of.
type ObservedVirtualChassis struct {
	// Name of the chassis; empty lets the writer name it after the asset.
	Name    string                         `json:"name,omitempty"`
	Domain  string                         `json:"domain,omitempty"`
	Members []ObservedVirtualChassisMember `json:"members"`
}

// maxObservedInventoryItems bounds one sighting's items: a modular chassis
// lists a few hundred parts; a list longer than this is truncated and reported
// rather than written unbounded.
const maxObservedInventoryItems = 2000

// NormalizeObservedHardware canonicalises a sighting's hardware: names
// trimmed and bounded, duplicates (by parent and name) kept once, a parent the
// observation does not list dropped to the top level, interface names
// canonicalised, a chassis with fewer than two members dropped. What the
// schema could not hold is dropped and reported.
func NormalizeObservedHardware(items []ObservedInventoryItem, modules []ObservedModule, vc *ObservedVirtualChassis) ([]ObservedInventoryItem, []ObservedModule, *ObservedVirtualChassis, []string) {
	var dropped []string
	clip := func(s string, n int) string {
		s = strings.TrimSpace(s)
		if len(s) > n {
			return s[:n]
		}
		return s
	}
	names := map[string]bool{}
	for _, it := range items {
		names[strings.TrimSpace(it.Name)] = true
	}
	var outI []ObservedInventoryItem
	seen := map[string]bool{}
	for _, raw := range items {
		o := raw
		o.Name = strings.TrimSpace(o.Name)
		if o.Name == "" || len(o.Name) > 64 {
			dropped = append(dropped, fmt.Sprintf("inventory item %q: an inventory item name is 1-64 characters", raw.Name))
			continue
		}
		o.Parent = strings.TrimSpace(o.Parent)
		if o.Parent == o.Name || !names[o.Parent] {
			o.Parent = ""
		}
		key := o.Parent + "\x00" + o.Name
		if seen[key] {
			continue
		}
		seen[key] = true
		if len(outI) == maxObservedInventoryItems {
			dropped = append(dropped, fmt.Sprintf("inventory items beyond %d not recorded", maxObservedInventoryItems))
			break
		}
		o.Role = strings.ToLower(strings.TrimSpace(o.Role))
		o.Manufacturer = clip(o.Manufacturer, 100)
		o.PartID = clip(o.PartID, 50)
		o.Serial = clip(o.Serial, 50)
		o.AssetTag = clip(o.AssetTag, 50)
		o.Description = clip(o.Description, 200)
		if o.Interface != "" {
			o.Interface, _ = ifnames.Canonical("", strings.TrimSpace(o.Interface))
		}
		outI = append(outI, o)
	}
	var outM []ObservedModule
	bays := map[string]bool{}
	for _, raw := range modules {
		o := raw
		o.Bay, o.PartID = strings.TrimSpace(o.Bay), clip(o.PartID, 100)
		o.Serial, o.AssetTag = clip(o.Serial, 50), clip(o.AssetTag, 50)
		if o.Bay == "" || len(o.Bay) > 64 || o.PartID == "" {
			dropped = append(dropped, fmt.Sprintf("module in bay %q: a bay name and a part id are required", raw.Bay))
			continue
		}
		if bays[o.Bay] {
			continue
		}
		bays[o.Bay] = true
		outM = append(outM, o)
	}
	if vc != nil {
		out := ObservedVirtualChassis{Name: clip(vc.Name, 64), Domain: clip(vc.Domain, 30)}
		pos := map[int]bool{}
		for _, m := range vc.Members {
			if m.Position < 0 || m.Position > 255 || pos[m.Position] {
				dropped = append(dropped, fmt.Sprintf("virtual chassis member %d: a position is 0-255 and unique", m.Position))
				continue
			}
			pos[m.Position] = true
			if m.Priority != nil && (*m.Priority < 0 || *m.Priority > 255) {
				m.Priority = nil
			}
			m.Serial, m.Model = clip(m.Serial, 50), clip(m.Model, 100)
			out.Members = append(out.Members, m)
		}
		if len(out.Members) < 2 {
			vc = nil
		} else {
			vc = &out
		}
	}
	return outI, outM, vc, dropped
}
