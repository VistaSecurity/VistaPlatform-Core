package deviceinterrogation

// The hardware an interrogated device reports about itself (DCIM row 2.4,
// ADR-0010 D4): its inventory items (power supplies, fans, transceivers, line
// cards), the modules in its bays and the stack it manages. Read from SNMP
// ENTITY-MIB entPhysicalTable (+ entAliasMappingTable for the port a part plugs
// into) and from Cisco `show inventory` / `show switch`, which the collectors
// already ran and used only for the chassis model and serial.
//
// The wire form of identity.ObservedInventoryItem / ObservedModule /
// ObservedVirtualChassis (shared/identity/observed_hardware.go), spelled here
// with the same JSON names for the reason the network types are (this package
// is vendored into the standalone device agent). device-interrogation-service
// decodes it with unknown fields refused, so the two spellings cannot drift.
//
// Posture only: names, part numbers, serials. Every field is a typed
// projection of the device's answer.

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/dcim/ifnames"
)

// ObservedInventoryItem mirrors identity.ObservedInventoryItem.
type ObservedInventoryItem struct {
	Name         string `json:"name"`
	Parent       string `json:"parent,omitempty"`
	Role         string `json:"role,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	PartID       string `json:"part_id,omitempty"`
	Serial       string `json:"serial,omitempty"`
	AssetTag     string `json:"asset_tag,omitempty"`
	Description  string `json:"description,omitempty"`
	Interface    string `json:"interface,omitempty"`
}

// ObservedModule mirrors identity.ObservedModule.
type ObservedModule struct {
	Bay      string `json:"bay"`
	PartID   string `json:"part_id"`
	Serial   string `json:"serial,omitempty"`
	AssetTag string `json:"asset_tag,omitempty"`
}

// ObservedVirtualChassisMember mirrors identity.ObservedVirtualChassisMember.
type ObservedVirtualChassisMember struct {
	Position int    `json:"position"`
	Priority *int   `json:"priority,omitempty"`
	Master   bool   `json:"master,omitempty"`
	Serial   string `json:"serial,omitempty"`
	Model    string `json:"model,omitempty"`
}

// ObservedVirtualChassis mirrors identity.ObservedVirtualChassis.
type ObservedVirtualChassis struct {
	Name    string                         `json:"name,omitempty"`
	Domain  string                         `json:"domain,omitempty"`
	Members []ObservedVirtualChassisMember `json:"members"`
}

// maxHardwareItems bounds the inventory items one interrogation reports.
const maxHardwareItems = 2000

// hardwareRole infers an inventory item role slug (seed.sql's platform roles)
// from what the device calls the part. "" when it cannot tell.
func hardwareRole(class int64, text string) string {
	t := strings.ToLower(text)
	switch {
	case class == 6 || strings.Contains(t, "power supply") || strings.Contains(t, "psu") || strings.HasPrefix(t, "pwr-"):
		return "psu"
	case class == 7 || strings.Contains(t, "fan"):
		return "fan"
	case strings.Contains(t, "sfp") || strings.Contains(t, "transceiver") || strings.Contains(t, "gbic") || strings.Contains(t, "xfp") || strings.Contains(t, "base-"):
		return "transceiver"
	case strings.Contains(t, "supervisor") || strings.Contains(t, "routing engine") || strings.Contains(t, "route processor"):
		return "supervisor"
	case class == 12 || strings.Contains(t, "cpu"):
		return "cpu"
	case class == 9 || strings.Contains(t, "module") || strings.Contains(t, "line card") || strings.Contains(t, "linecard"):
		return "linecard"
	}
	return ""
}

// ---------------------------------------------------------------------------
// SNMP: ENTITY-MIB entPhysicalTable

// entPhysicalTable columns read for hardware (snmp_ops.go has class, serial,
// manufacturer, model and firmware).
const (
	snmpOIDEntPhysicalDescr       = "1.3.6.1.2.1.47.1.1.1.1.2"
	snmpOIDEntPhysicalContainedIn = "1.3.6.1.2.1.47.1.1.1.1.4"
	snmpOIDEntPhysicalParentRel   = "1.3.6.1.2.1.47.1.1.1.1.6"
	snmpOIDEntPhysicalName        = "1.3.6.1.2.1.47.1.1.1.1.7"
	snmpOIDEntPhysicalAssetID     = "1.3.6.1.2.1.47.1.1.1.1.15"
	// entAliasMappingIdentifier, indexed (entPhysicalIndex, logical index):
	// the OID of the ifIndex a port entity is (ifIndex.<n>).
	snmpOIDEntAliasMappingIdentifier = "1.3.6.1.2.1.47.1.3.2.1.2"
)

// entPhysicalClass values (ENTITY-MIB PhysicalClass).
const (
	entClassContainer = 5
	entClassChassis   = 3
	entClassStack     = 11
	entClassPort      = 10
	entClassModule    = 9
	entClassSensor    = 8
)

// snmpEntity is one entPhysicalTable row.
type snmpEntity struct {
	index, parent                             string
	class                                     int64
	relPos                                    int64
	name, descr, serial, mfg, model, assetTag string
}

// snmpHardware projects entPhysicalTable onto the device's hardware: every
// field-replaceable part (power supply, fan, module, CPU) as an inventory item
// whose parent is the nearest listed ancestor (containers and the chassis are
// not items: a slot is a place, the chassis is the device); a module in a
// container (a slot) also as an observed module in the bay of that slot's name;
// and, when the agent reports more than one chassis under a stack, the stack's
// members by position. A transceiver's port (entAliasMappingTable → ifIndex)
// names the interface it plugs into. Sensors are skipped.
func snmpHardware(walk func(string) map[string]snmpVarBind, ifNameByIndex map[string]string, vendorHint string) ([]ObservedInventoryItem, []ObservedModule, *ObservedVirtualChassis) {
	classes := walk(snmpOIDEntPhysicalClass)
	if len(classes) == 0 {
		return nil, nil, nil
	}
	contained := walk(snmpOIDEntPhysicalContainedIn)
	relPos := walk(snmpOIDEntPhysicalParentRel)
	names := walk(snmpOIDEntPhysicalName)
	descrs := walk(snmpOIDEntPhysicalDescr)
	serials := walk(snmpOIDEntPhysicalSerialNum)
	mfgs := walk(snmpOIDEntPhysicalMfgName)
	models := walk(snmpOIDEntPhysicalModelName)
	assetIDs := walk(snmpOIDEntPhysicalAssetID)
	alias := walk(snmpOIDEntAliasMappingIdentifier)

	ents := map[string]*snmpEntity{}
	var order []string
	for index, b := range classes {
		c, _ := b.Int()
		e := &snmpEntity{index: index, class: c,
			name: strings.TrimSpace(names[index].Text()), descr: strings.TrimSpace(descrs[index].Text()),
			serial: strings.TrimSpace(serials[index].Text()), mfg: strings.TrimSpace(mfgs[index].Text()),
			model: strings.TrimSpace(models[index].Text()), assetTag: strings.TrimSpace(assetIDs[index].Text())}
		if p, ok := contained[index].Int(); ok && p > 0 {
			e.parent = strconv.FormatInt(p, 10)
		}
		e.relPos, _ = relPos[index].Int()
		if e.name == "" {
			e.name = e.descr
		}
		ents[index] = e
		order = append(order, index)
	}
	sort.Slice(order, func(i, j int) bool { return snmpIndexLess(order[i], order[j]) })

	// The interface a port entity is: entAliasMappingIdentifier's value is
	// ifIndex.<n> (1.3.6.1.2.1.2.2.1.1.<n>).
	portIf := map[string]string{}
	for idx, b := range alias {
		ent := strings.SplitN(idx, ".", 2)[0]
		v := b.Text()
		if i := strings.LastIndex(v, "."); i >= 0 && strings.HasPrefix(v, "1.3.6.1.2.1.2.2.1.1.") {
			if name := ifNameByIndex[v[i+1:]]; name != "" {
				portIf[ent] = name
			}
		}
	}

	emitted := map[string]bool{}
	isItem := func(e *snmpEntity) bool {
		switch e.class {
		case entClassContainer, entClassChassis, entClassStack, entClassSensor, entClassPort:
			return false
		}
		return e.name != ""
	}
	itemParent := func(e *snmpEntity) string {
		for p, hops := e.parent, 0; p != "" && hops < 32; hops++ {
			pe := ents[p]
			if pe == nil {
				return ""
			}
			if emitted[p] {
				return pe.name
			}
			p = pe.parent
		}
		return ""
	}
	// The interface a part plugs into: a port entity above it.
	itemInterface := func(e *snmpEntity) string {
		for p, hops := e.parent, 0; p != "" && hops < 4; hops++ {
			if name := portIf[p]; name != "" {
				return name
			}
			pe := ents[p]
			if pe == nil {
				return ""
			}
			p = pe.parent
		}
		return portIf[e.index]
	}

	var (
		items   []ObservedInventoryItem
		modules []ObservedModule
		members []ObservedVirtualChassisMember
		stack   string
	)
	for _, idx := range order {
		e := ents[idx]
		if e.class == entClassStack && stack == "" {
			stack = e.name
		}
		if e.class == entClassChassis && e.parent != "" && ents[e.parent] != nil && ents[e.parent].class == entClassStack {
			pos := int(e.relPos)
			if pos <= 0 {
				pos = len(members) + 1
			}
			members = append(members, ObservedVirtualChassisMember{Position: pos, Serial: e.serial, Model: e.model, Master: len(members) == 0})
		}
		if !isItem(e) || len(items) == maxHardwareItems {
			continue
		}
		mfg := e.mfg
		if mfg == "" {
			mfg = vendorHint
		}
		it := ObservedInventoryItem{Name: e.name, Parent: itemParent(e), Role: hardwareRole(e.class, e.name+" "+e.descr+" "+e.model),
			Manufacturer: mfg, PartID: e.model, Serial: e.serial, AssetTag: e.assetTag, Interface: itemInterface(e)}
		if e.descr != e.name {
			it.Description = e.descr
		}
		items = append(items, it)
		emitted[idx] = true
		if e.class == entClassModule && e.model != "" {
			if pe := ents[e.parent]; pe != nil && pe.class == entClassContainer && pe.name != "" {
				modules = append(modules, ObservedModule{Bay: pe.name, PartID: e.model, Serial: e.serial, AssetTag: e.assetTag})
			}
		}
	}
	var vc *ObservedVirtualChassis
	if len(members) > 1 {
		vc = &ObservedVirtualChassis{Name: stack, Members: members}
	}
	return items, modules, vc
}

// ---------------------------------------------------------------------------
// Cisco: `show inventory`, `show switch`

// ciscoInventoryEntry is one NAME/DESCR + PID/VID/SN pair of `show inventory`.
type ciscoInventoryEntry struct {
	Name, Description, PID, VID, Serial string
}

// ciscoParseInventoryEntries returns every entry of `show inventory`, in order.
func ciscoParseInventoryEntries(output string) []ciscoInventoryEntry {
	var out []ciscoInventoryEntry
	var cur *ciscoInventoryEntry
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if m := ciscoInventoryNameRE.FindStringSubmatch(trimmed); m != nil {
			if cur != nil {
				out = append(out, *cur)
			}
			cur = &ciscoInventoryEntry{Name: strings.TrimSpace(m[1]), Description: strings.TrimSpace(m[2])}
			continue
		}
		if cur == nil {
			continue
		}
		if m := ciscoInventoryPIDRE.FindStringSubmatch(trimmed); m != nil {
			cur.PID, cur.VID, cur.Serial = strings.TrimSpace(m[1]), strings.TrimSpace(m[2]), strings.TrimSpace(m[3])
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}

// ciscoStackMemberRE is a stack member's own entry ("Switch 2"); its parts
// are named after it ("Switch 2 - Power Supply A", "Switch 2 FRU Uplink
// Module 1").
var ciscoStackMemberRE = regexp.MustCompile(`(?i)^switch\s+(\d+)$`)

// ciscoStackEntry is the stack's own entry ("c93xx Stack").
var ciscoStackEntryRE = regexp.MustCompile(`(?i)\bstack\b`)

// ciscoStackMembers returns the stack member positions `show inventory`
// lists, so the caller asks `show switch` only of a stack.
func ciscoStackMembers(entries []ciscoInventoryEntry) map[int]ciscoInventoryEntry {
	out := map[int]ciscoInventoryEntry{}
	for _, e := range entries {
		if m := ciscoStackMemberRE.FindStringSubmatch(e.Name); m != nil {
			n, _ := strconv.Atoi(m[1])
			out[n] = e
		}
	}
	return out
}

// ciscoSwitchRowRE is a member row of `show switch`:
// `*1       Active   0cd0.f8a1.b200     15     V02     Ready`.
var ciscoSwitchRowRE = regexp.MustCompile(`^\s*(\*?)\s*(\d+)\s+(Active|Standby|Member|Master)\s+\S+\s+(\d+)\s`)

// ciscoSwitchRow is one member of `show switch`.
type ciscoSwitchRow struct {
	Position, Priority int
	Role               string
}

func ciscoParseShowSwitch(output string) []ciscoSwitchRow {
	var out []ciscoSwitchRow
	for _, line := range strings.Split(output, "\n") {
		m := ciscoSwitchRowRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		pos, _ := strconv.Atoi(m[2])
		pri, _ := strconv.Atoi(m[4])
		out = append(out, ciscoSwitchRow{Position: pos, Priority: pri, Role: strings.ToLower(m[3])})
	}
	return out
}

// ciscoHardware projects `show inventory` (and, for a stack, `show switch`)
// onto the device's hardware. Every entry but the chassis, the stack and the
// members' own entries is an inventory item (`show inventory` is flat: no
// parent). An entry named like an interface (`Te1/1/1`, a transceiver) names
// that interface. Stack members become the virtual chassis: position and
// serial from `show inventory`, priority and the active member from `show
// switch` when it answered.
func ciscoHardware(entries []ciscoInventoryEntry, chassis ciscoChassis, showSwitch string) ([]ObservedInventoryItem, *ObservedVirtualChassis) {
	members := ciscoStackMembers(entries)
	var items []ObservedInventoryItem
	stack := ""
	for _, e := range entries {
		switch {
		case ciscoStackEntryRE.MatchString(e.Name) && len(members) > 0:
			stack = e.Name
			continue
		case e.Name == chassis.Name && e.Serial == chassis.Serial && e.PID == chassis.PID:
			continue
		case ciscoStackMemberRE.MatchString(e.Name):
			continue
		case e.Name == "" || len(items) == maxHardwareItems:
			continue
		}
		it := ObservedInventoryItem{Name: e.Name, Role: hardwareRole(0, e.Name+" "+e.Description+" "+e.PID),
			Manufacturer: ciscoVendor, PartID: e.PID, Serial: e.Serial}
		if e.Description != e.Name {
			it.Description = e.Description
		}
		if ciscoLooksLikeInterface(e.Name) {
			it.Interface = e.Name
		}
		items = append(items, it)
	}
	if len(members) < 2 {
		return items, nil
	}
	rows := map[int]ciscoSwitchRow{}
	for _, r := range ciscoParseShowSwitch(showSwitch) {
		rows[r.Position] = r
	}
	positions := make([]int, 0, len(members))
	for p := range members {
		positions = append(positions, p)
	}
	sort.Ints(positions)
	vc := &ObservedVirtualChassis{Name: stack}
	for _, p := range positions {
		e := members[p]
		m := ObservedVirtualChassisMember{Position: p, Serial: e.Serial, Model: e.PID}
		if r, ok := rows[p]; ok {
			pri := r.Priority
			m.Priority = &pri
			m.Master = r.Role == "active" || r.Role == "master"
		}
		vc.Members = append(vc.Members, m)
	}
	if len(rows) == 0 && len(vc.Members) > 0 {
		// No `show switch`: the member whose serial is the chassis's (the
		// one the session answered on) is taken as the master.
		for i := range vc.Members {
			vc.Members[i].Master = vc.Members[i].Serial != "" && vc.Members[i].Serial == chassis.Serial
		}
	}
	return items, vc
}

// ciscoInterfaceNameRE is an interface-shaped inventory name: Te1/1/1,
// GigabitEthernet1/0/49, Hu1/0/1.
var ciscoInterfaceNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z-]*\d+(/\d+)+$`)

func ciscoLooksLikeInterface(name string) bool {
	return ciscoInterfaceNameRE.MatchString(strings.TrimSpace(name))
}

// setHardware stores the device's hardware on the result's network
// observation (creating one when the collector produced no network posture),
// with interface names canonicalised for the vendor family as the interfaces
// themselves are, and the item list bounded.
func (r *InterrogateResult) setHardware(items []ObservedInventoryItem, modules []ObservedModule, vc *ObservedVirtualChassis, family, endpoint string) {
	if len(items) == 0 && len(modules) == 0 && vc == nil {
		return
	}
	if len(items) > maxHardwareItems {
		r.warnTruncated(endpoint, "Inventory items", maxHardwareItems)
		items = items[:maxHardwareItems]
	}
	for i := range items {
		if items[i].Interface != "" {
			items[i].Interface, _ = ifnames.Canonical(family, items[i].Interface)
		}
	}
	if r.Network == nil {
		r.Network = &NetworkObservation{Vendor: ifnames.NormalizeVendor(family)}
	}
	r.Network.InventoryItems, r.Network.Modules, r.Network.VirtualChassis = items, modules, vc
}
