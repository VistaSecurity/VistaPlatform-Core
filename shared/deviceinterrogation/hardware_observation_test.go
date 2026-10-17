package deviceinterrogation

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/snmpfake"
)

// The C9300 stack fixture (2 members, 2 power supplies and an uplink module
// each, 4 SFPs): `show inventory` + `show switch` project onto the inventory
// items, their roles and serials, the SFPs' interfaces, and the stack.
//
// Mutation: drop the SN capture in ciscoParseInventoryEntries → the serial
// assertions fail; drop the member branch in ciscoHardware → the chassis
// assertions fail.
func TestCiscoHardware_C9300Stack(t *testing.T) {
	inv := ciscoFixture(t, "cisco_c9300_stack_show_inventory.txt")
	entries := ciscoParseInventoryEntries(inv)
	items, vc := ciscoHardware(entries, ciscoParseInventory(inv), ciscoFixture(t, "cisco_c9300_stack_show_switch.txt"))
	byName := map[string]ObservedInventoryItem{}
	roles := map[string]int{}
	for _, it := range items {
		byName[it.Name] = it
		roles[it.Role]++
	}
	if len(items) != 10 || roles["psu"] != 4 || roles["transceiver"] != 4 || roles["linecard"] != 2 {
		t.Fatalf("items %d, roles %v; want 10 items: 4 psu, 4 transceiver, 2 linecard\n%+v", len(items), roles, items)
	}
	if got := byName["Switch 2 - Power Supply B"]; got.Serial != "DCB2341G0B2" || got.PartID != "PWR-C1-715WAC-P" || got.Manufacturer != ciscoVendor {
		t.Errorf("PSU projected as %+v", got)
	}
	if got := byName["Te1/1/2"]; got.Interface != "Te1/1/2" || got.Serial != "AVD2201A002" {
		t.Errorf("SFP projected as %+v (want its interface named)", got)
	}
	for _, n := range []string{"Switch 1", "Switch 2", "c93xx Stack"} {
		if _, ok := byName[n]; ok {
			t.Errorf("%q is a member / the stack, not an inventory item", n)
		}
	}
	if vc == nil || len(vc.Members) != 2 || vc.Name != "c93xx Stack" {
		t.Fatalf("virtual chassis %+v; want the stack with 2 members", vc)
	}
	m1, m2 := vc.Members[0], vc.Members[1]
	if m1.Position != 1 || !m1.Master || m1.Serial != "FOC2432L0AB" || m1.Priority == nil || *m1.Priority != 15 {
		t.Errorf("member 1 %+v", m1)
	}
	if m2.Position != 2 || m2.Master || m2.Serial != "FOC2432L0CD" || m2.Priority == nil || *m2.Priority != 14 {
		t.Errorf("member 2 %+v", m2)
	}
}

// A router's `show inventory` (no stack) yields items and no chassis; the
// chassis entry itself is never an item.
func TestCiscoHardware_RouterHasNoStack(t *testing.T) {
	inv := ciscoFixture(t, "cisco_ios_show_inventory.txt")
	items, vc := ciscoHardware(ciscoParseInventoryEntries(inv), ciscoParseInventory(inv), "")
	if vc != nil {
		t.Errorf("a router reported a virtual chassis: %+v", vc)
	}
	chassis := ciscoParseInventory(inv)
	for _, it := range items {
		if it.Name == chassis.Name && it.Serial == chassis.Serial {
			t.Errorf("the chassis entry %q was reported as an inventory item", it.Name)
		}
	}
}

func TestCiscoParseShowSwitch(t *testing.T) {
	rows := ciscoParseShowSwitch(ciscoFixture(t, "cisco_c9300_stack_show_switch.txt"))
	if len(rows) != 2 || rows[0].Position != 1 || rows[0].Role != "active" || rows[1].Priority != 14 {
		t.Fatalf("rows %+v", rows)
	}
}

// A generic SNMP chassis: entPhysicalTable with a chassis, a slot holding a
// line card, a port holding an SFP (entAliasMapping → ifIndex 7), two power
// supplies and a fan; sensors and containers are not items.
//
// Mutation: ignore entPhysicalContainedIn → the SFP's parent assertion fails;
// drop the serial walk → the serial assertion fails.
func TestSNMPHardware_GenericChassis(t *testing.T) {
	i := func(n int64) snmpVarBind { return snmpVarBind{Tag: snmpTagInteger, Raw: encodeTestInt(n)} }
	s := func(v string) snmpVarBind { return snmpVarBind{Tag: snmpTagOctetString, Raw: []byte(v)} }
	o := func(v string) snmpVarBind { return snmpVarBind{Tag: snmpTagOID, Raw: encodeTestOID(v)} }
	cols := map[string]map[string]snmpVarBind{
		snmpOIDEntPhysicalClass:       {"1": i(3), "2": i(5), "3": i(9), "4": i(10), "5": i(9), "6": i(6), "7": i(6), "8": i(7), "9": i(8)},
		snmpOIDEntPhysicalContainedIn: {"1": i(0), "2": i(1), "3": i(2), "4": i(3), "5": i(4), "6": i(1), "7": i(1), "8": i(1), "9": i(1)},
		snmpOIDEntPhysicalName: {"1": s("Chassis"), "2": s("Slot 1"), "3": s("Line card 1"), "4": s("port 1/1"),
			"5": s("SFP 1/1"), "6": s("PSU 1"), "7": s("PSU 2"), "8": s("Fan tray"), "9": s("Temp sensor")},
		snmpOIDEntPhysicalSerialNum:      {"1": s("CH-001"), "3": s("LC-001"), "5": s("SFP-001"), "6": s("PSU-001"), "7": s("PSU-002")},
		snmpOIDEntPhysicalModelName:      {"1": s("XR-9000"), "3": s("LC-48X"), "5": s("SFP-10G-SR"), "6": s("PWR-1100")},
		snmpOIDEntPhysicalMfgName:        {"3": s("Acme Networks")},
		snmpOIDEntAliasMappingIdentifier: {"4.0": o("1.3.6.1.2.1.2.2.1.1.7")},
	}
	walk := func(col string) map[string]snmpVarBind { return cols[col] }
	items, modules, vc := snmpHardware(walk, map[string]string{"7": "TenGigabitEthernet1/1"}, "Acme")
	byName := map[string]ObservedInventoryItem{}
	for _, it := range items {
		byName[it.Name] = it
	}
	if len(items) != 5 {
		t.Fatalf("items %+v; want line card, SFP, 2 PSUs, fan", items)
	}
	if got := byName["SFP 1/1"]; got.Parent != "Line card 1" || got.Interface != "TenGigabitEthernet1/1" || got.Serial != "SFP-001" || got.Role != "transceiver" {
		t.Errorf("SFP %+v", got)
	}
	if got := byName["Line card 1"]; got.Parent != "" || got.Manufacturer != "Acme Networks" || got.Role != "linecard" {
		t.Errorf("line card %+v", got)
	}
	if got := byName["PSU 2"]; got.Manufacturer != "Acme" || got.Role != "psu" || got.Serial != "PSU-002" {
		t.Errorf("PSU %+v", got)
	}
	if len(modules) != 1 || modules[0].Bay != "Slot 1" || modules[0].PartID != "LC-48X" {
		t.Errorf("modules %+v; want the line card in Slot 1", modules)
	}
	if vc != nil {
		t.Errorf("one chassis is no stack: %+v", vc)
	}
}

// encodeTestInt is a BER INTEGER's content octets (two's complement, minimal).
func encodeTestInt(n int64) []byte {
	var out []byte
	for {
		out = append([]byte{byte(n)}, out...)
		n >>= 8
		if (n == 0 && out[0]&0x80 == 0) || (n == -1 && out[0]&0x80 != 0) {
			return out
		}
	}
}

// encodeTestOID is a BER OBJECT IDENTIFIER's content octets.
func encodeTestOID(dotted string) []byte {
	var arcs []int
	for _, p := range strings.Split(dotted, ".") {
		n, _ := strconv.Atoi(p)
		arcs = append(arcs, n)
	}
	out := []byte{byte(arcs[0]*40 + arcs[1])}
	for _, a := range arcs[2:] {
		var b []byte
		b = append(b, byte(a&0x7f))
		for a >>= 7; a > 0; a >>= 7 {
			b = append([]byte{byte(a&0x7f) | 0x80}, b...)
		}
		out = append(out, b...)
	}
	return out
}

// The SNMP collector itself (not just the projection) puts entPhysicalTable's
// parts on the network observation: a power supply and an SFP in a port whose
// entAliasMappingTable row names ifIndex 1 (Gi1/0/1).
//
// Mutation: drop the snmpHardware call from snmpCollectNetwork → red.
func TestSNMPNetwork_CarriesEntPhysicalHardware(t *testing.T) {
	rec := snmpfake.L3Switch48()
	rec.MIB = append(rec.MIB,
		snmpfake.Int("1.3.6.1.2.1.47.1.1.1.1.5.2", 6), snmpfake.Int("1.3.6.1.2.1.47.1.1.1.1.4.2", 1),
		snmpfake.Str("1.3.6.1.2.1.47.1.1.1.1.7.2", "Switch 1 - Power Supply A"), snmpfake.Str("1.3.6.1.2.1.47.1.1.1.1.11.2", "DCB2341G0A1"),
		snmpfake.Int("1.3.6.1.2.1.47.1.1.1.1.5.3", 10), snmpfake.Int("1.3.6.1.2.1.47.1.1.1.1.4.3", 1),
		snmpfake.Str("1.3.6.1.2.1.47.1.1.1.1.7.3", "GigabitEthernet1/0/1 port"),
		snmpfake.Int("1.3.6.1.2.1.47.1.1.1.1.5.4", 9), snmpfake.Int("1.3.6.1.2.1.47.1.1.1.1.4.4", 3),
		snmpfake.Str("1.3.6.1.2.1.47.1.1.1.1.7.4", "GigabitEthernet1/0/1 SFP"), snmpfake.Str("1.3.6.1.2.1.47.1.1.1.1.13.4", "GLC-SX-MMD"),
		snmpfake.OIDValue("1.3.6.1.2.1.47.1.3.2.1.2.3.0", "1.3.6.1.2.1.2.2.1.1.1"),
	)
	n := snmpNetworkOf(t, rec).Network
	byName := map[string]ObservedInventoryItem{}
	for _, it := range n.InventoryItems {
		byName[it.Name] = it
	}
	if psu := byName["Switch 1 - Power Supply A"]; psu.Serial != "DCB2341G0A1" || psu.Role != "psu" {
		t.Errorf("PSU %+v (items %+v)", psu, n.InventoryItems)
	}
	if sfp := byName["GigabitEthernet1/0/1 SFP"]; sfp.Interface != "GigabitEthernet1/0/1" || sfp.PartID != "GLC-SX-MMD" {
		t.Errorf("SFP %+v, want its port's interface", sfp)
	}
}

// The Cisco collection itself files the stack: ciscoCollectOps over the C9300
// stack outputs leaves the items (SFP interfaces canonicalised as the
// interfaces are) and the two-member chassis on result.Network.
//
// Mutation: drop the setHardware call from ciscoCollectOps → red.
func TestCiscoCollectOps_FilesTheStackHardware(t *testing.T) {
	outputs := map[string]string{
		"show inventory": ciscoFixture(t, "cisco_c9300_stack_show_inventory.txt"),
		"show switch":    ciscoFixture(t, "cisco_c9300_stack_show_switch.txt"),
	}
	run := func(_ context.Context, command string) (string, bool, error) {
		if out, ok := outputs[command]; ok {
			return out, true, nil
		}
		return "", false, os.ErrNotExist
	}
	result := &InterrogateResult{}
	ciscoCollectOps(context.Background(), result, run, map[string]interface{}{"os_name": "IOS-XE"})
	n := result.Network
	if n == nil || len(n.InventoryItems) != 10 || n.VirtualChassis == nil || len(n.VirtualChassis.Members) != 2 {
		t.Fatalf("network observation %+v, want 10 items and a two-member chassis", n)
	}
	for _, it := range n.InventoryItems {
		if it.Name == "Te1/1/1" && it.Interface != "TenGigabitEthernet1/1/1" {
			t.Errorf("SFP interface %q, want the canonical TenGigabitEthernet1/1/1", it.Interface)
		}
	}
}
