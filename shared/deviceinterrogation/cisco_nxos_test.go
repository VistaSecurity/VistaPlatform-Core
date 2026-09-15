package deviceinterrogation

import (
	"context"
	"testing"
)

// NX-OS is the fourth platform this collector reaches, and it formats every
// command differently from IOS. Two of those differences meant a Nexus produced
// no os.version and no net.interfaces at all, and one produced a phantom.

func TestCiscoNXOS_VersionSerialAndChassisParse(t *testing.T) {
	c := &ciscoSSHClient{}
	info, err := c.parseSystemInfo(ciscoFixture(t, "cisco_nxos_show_version.txt"))
	if err != nil {
		t.Fatalf("parseSystemInfo: %v", err)
	}

	// "NXOS: version 9.3(10)" — lower case, and two lines BELOW
	// "BIOS: version 07.67". A bare case-insensitive match takes the bootloader.
	if info["version"] != "9.3(10)" {
		t.Errorf("version = %v, want the NXOS software version, not the BIOS's", info["version"])
	}
	if info["os_name"] != "NX-OS" {
		t.Errorf("os_name = %v, want NX-OS", info["os_name"])
	}
	if info["serial_number"] != "FDO21120U5D" {
		t.Errorf("serial = %v, want the Processor Board ID", info["serial_number"])
	}
	uptime, _ := info["uptime"].(string)
	if seconds, ok := ciscoParseUptime(uptime); !ok || seconds != 20*86400+2*3600+15*60+51 {
		t.Errorf("uptime %q parsed to (%d, %v)", uptime, seconds, ok)
	}

	// The chassis, not the line card, the power supply or the fan.
	chassis := ciscoParseInventory(ciscoFixture(t, "cisco_nxos_show_inventory.txt"))
	if chassis.PID != "N9K-C93180YC-EX" || chassis.Serial != "FDO21120U5D" {
		t.Errorf("NX-OS chassis = %+v", chassis)
	}
	if ciscoClassHintForPID(chassis.PID) != "switch" {
		t.Errorf("a Nexus 9000 was not proposed as a switch: %q", ciscoClassHintForPID(chassis.PID))
	}

	// The IOS and IOS-XE fixtures must not have regressed: the NX-OS pattern is
	// tried first, and a pattern that matched everything would be worse than the
	// gap it closes.
	for fixture, want := range map[string]string{
		"cisco_ios_show_version.txt":   "15.2(4)E10",
		"cisco_iosxe_show_version.txt": "17.09.04a",
		"cisco_asa_show_version.txt":   "9.12(4)56",
	} {
		other, err := c.parseSystemInfo(ciscoFixture(t, fixture))
		if err != nil {
			t.Fatalf("parseSystemInfo(%s): %v", fixture, err)
		}
		if other["version"] != want {
			t.Errorf("%s: version = %v, want %q", fixture, other["version"], want)
		}
	}
}

// NX-OS folds both interface states into one "protocol-up/link-up/admin-up"
// triple and prints a VRF banner above the table. That banner is exactly six
// whitespace-separated fields, so the IOS row parser admitted it and invented an
// interface called "IP" on every Nexus.
//
// To mutation-test: drop the address-column check from
// ciscoParseIPInterfaceBrief and the phantom assertion fails; drop the NX-OS
// triple branch and the state assertions fail.
func TestCiscoParseIPInterfaceBrief_ReadsTheNXOSThreeColumnForm(t *testing.T) {
	interfaces := ciscoParseIPInterfaceBrief(ciscoFixture(t, "cisco_nxos_show_ip_interface_brief.txt"))

	byName := map[string]map[string]interface{}{}
	for _, iface := range interfaces {
		byName[iface["name"].(string)] = iface
	}
	if len(byName) != 5 {
		t.Fatalf("expected five NX-OS interfaces, got %v", interfaceNames(interfaces))
	}
	// The VRF banner and the column header are not interfaces.
	for _, phantom := range []string{"IP", "Interface"} {
		if _, present := byName[phantom]; present {
			t.Errorf("a header line was parsed as an interface %q: %v", phantom, interfaceNames(interfaces))
		}
	}

	up := byName["Vlan10"]
	if up["admin_state"] != "up" || up["state"] != "up" {
		t.Errorf("Vlan10 states wrong: %+v", up)
	}
	if addrs, ok := up["addresses"].([]interface{}); !ok || len(addrs) != 1 || addrs[0] != "192.0.2.1" {
		t.Errorf("Vlan10 address lost: %+v", up)
	}
	// An interface that is up administratively but whose protocol is down is a
	// different fact from one someone shut down. NX-OS states both in the same
	// column, and collapsing them loses the only half an operator can act on.
	linkDown := byName["Vlan20"]
	if linkDown["admin_state"] != "up" || linkDown["state"] != "down" {
		t.Errorf("Vlan20 read as administratively down: %+v", linkDown)
	}
	shut := byName["Ethernet1/48"]
	if shut["admin_state"] != "down" || shut["state"] != "down" {
		t.Errorf("Ethernet1/48 states wrong: %+v", shut)
	}

	// Inverse polarity: the IOS six-column form still reads, including the
	// "unassigned" rows that carry no address.
	ios := ciscoParseIPInterfaceBrief(ciscoFixture(t, "cisco_iosxe_show_ip_interface_brief.txt"))
	if len(ios) == 0 {
		t.Fatal("the IOS brief form stopped parsing")
	}
}

// The whole collection, NX-OS shaped. `show interfaces` on a Nexus is a
// different shape that ciscoParseInterfaces reads nothing out of, so the brief
// form is the ONLY source of net.interfaces there — the layer-3 interfaces, not
// the full port table. This asserts the platform still produces an ops set,
// because a collector that silently reports nothing for a whole platform is the
// failure this codebase keeps paying for.
func TestCiscoCollectOps_NXOSStillProducesTheOpsSet(t *testing.T) {
	c := &ciscoSSHClient{}
	sysInfo, err := c.parseSystemInfo(ciscoFixture(t, "cisco_nxos_show_version.txt"))
	if err != nil {
		t.Fatalf("parseSystemInfo: %v", err)
	}

	result := &InterrogateResult{}
	// `show interfaces`, `show vlan brief`, CDP, LLDP and ARP answer with an
	// error, which is what a platform that formats them differently or does not
	// implement them looks like from here.
	pid := ciscoCollectOps(context.Background(), result, newCiscoFixtureRunner(t, map[string]string{
		"show inventory":          "cisco_nxos_show_inventory.txt",
		"show ip interface brief": "cisco_nxos_show_ip_interface_brief.txt",
	}), sysInfo)

	assertObservationsValid(t, "cisco ops (nx-os)", result)
	assertNoPoison(t, "cisco ops (nx-os)", result)

	if pid != "N9K-C93180YC-EX" {
		t.Errorf("chassis PID = %q", pid)
	}
	for key, want := range map[string]any{
		factHWVendor:         ciscoVendor,
		factHWModel:          "N9K-C93180YC-EX",
		factHWSerial:         "FDO21120U5D",
		factOSName:           "NX-OS",
		factOSVersion:        "9.3(10)",
		factNetUptimeSeconds: 20*86400 + 2*3600 + 15*60 + 51,
	} {
		if got := factValue(t, result, key); got != want {
			t.Errorf("%s = %v (%T), want %v", key, got, got, want)
		}
	}

	interfaces, ok := factValue(t, result, factNetInterfaces).([]map[string]interface{})
	if !ok {
		t.Fatalf("no net.interfaces fact reached the result; facts: %v", factKeys(result))
	}
	if len(interfaces) != 5 {
		t.Errorf("NX-OS interfaces = %v, want the five layer-3 interfaces", interfaceNames(interfaces))
	}
}
