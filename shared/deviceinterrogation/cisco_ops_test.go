package deviceinterrogation

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ciscoFixture(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(body)
}

// newCiscoFixtureRunner answers every ops command from a fixture, so the tests
// below drive the REAL collection path rather than its parsers one at a time.
// Projection has to be wired, not merely available.
func newCiscoFixtureRunner(t *testing.T, fixtures map[string]string) ciscoRunner {
	t.Helper()
	return func(_ context.Context, command string) (string, bool, error) {
		name, ok := fixtures[command]
		if !ok {
			// A platform that does not implement a command answers with an
			// error, which is the case the collector has to survive.
			return "", false, os.ErrNotExist
		}
		return ciscoFixture(t, name), false, nil
	}
}

func ciscoIOSFixtures() map[string]string {
	return map[string]string{
		"show inventory":             "cisco_ios_show_inventory.txt",
		"show interfaces":            "cisco_ios_show_interfaces.txt",
		"show ip interface brief":    "cisco_iosxe_show_ip_interface_brief.txt",
		"show vlan brief":            "cisco_ios_show_vlan_brief.txt",
		"show cdp neighbors detail":  "cisco_ios_show_cdp_neighbors_detail.txt",
		"show lldp neighbors detail": "cisco_iosxe_show_lldp_neighbors_detail.txt",
		"show ip arp":                "cisco_ios_show_ip_arp.txt",
	}
}

// --- identity ---------------------------------------------------------------

// `show version` was parsed for a model with a regex that matched the banner's
// own first line, so every IOS-XE device in a fleet reported its model as
// "IOS". hw.model is half the key into the hardware end-of-support catalogue.
func TestCiscoSystemInfo_ReadsModelFromHardwareLineNotTheBanner(t *testing.T) {
	cases := []struct {
		fixture string
		osName  string
		version string
		model   string
		serial  string
		uptime  int
	}{
		{
			fixture: "cisco_ios_show_version.txt",
			osName:  "IOS",
			version: "15.2(4)E10",
			model:   "WS-C3750X-48P",
			serial:  "FDO1734X0AB",
			uptime:  2*365*86400 + 30*7*86400 + 4*86400 + 5*3600 + 12*60,
		},
		{
			fixture: "cisco_iosxe_show_version.txt",
			osName:  "IOS-XE",
			version: "17.09.04a",
			model:   "C9300-48P",
			serial:  "FCW2140L0GH",
			uptime:  86400 + 2*3600 + 3*60,
		},
		{
			fixture: "cisco_asa_show_version.txt",
			osName:  "ASA",
			version: "9.12(4)56",
			model:   "ASA5525",
			serial:  "FCH1934ABCD",
			uptime:  5*86400 + 4*3600,
		},
	}

	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			info := ciscoParseShowVersionForTest(t, ciscoFixture(t, tc.fixture))
			if info["model"] != tc.model {
				t.Errorf("model = %v, want %q", info["model"], tc.model)
			}
			if info["version"] != tc.version {
				t.Errorf("version = %v, want %q", info["version"], tc.version)
			}
			if info["serial_number"] != tc.serial {
				t.Errorf("serial = %v, want %q", info["serial_number"], tc.serial)
			}
			if info["os_name"] != tc.osName {
				t.Errorf("os_name = %v, want %q", info["os_name"], tc.osName)
			}
			uptime, _ := info["uptime"].(string)
			seconds, ok := ciscoParseUptime(uptime)
			if !ok || seconds != tc.uptime {
				t.Errorf("uptime %q parsed to (%d, %v), want (%d, true)", uptime, seconds, ok, tc.uptime)
			}
		})
	}
}

func TestCiscoParseUptime_RefusesToInventAZero(t *testing.T) {
	for _, in := range []string{"", "unknown", "never", "-"} {
		if seconds, ok := ciscoParseUptime(in); ok {
			t.Errorf("ciscoParseUptime(%q) = (%d, true); an unreadable uptime must not read as a fresh boot", in, seconds)
		}
	}
}

func TestCiscoParseInventory_KeepsTheChassisAndNothingBelowIt(t *testing.T) {
	// IOS-XE names it outright.
	xe := ciscoParseInventory(ciscoFixture(t, "cisco_iosxe_show_inventory.txt"))
	if xe.PID != "C9300-48P" || xe.Serial != "FCW2140L0GH" {
		t.Errorf("IOS-XE chassis = %+v, want the C9300-48P entry", xe)
	}

	// Older IOS names the root entry after its stack position; the first entry
	// of the containment tree is the chassis.
	ios := ciscoParseInventory(ciscoFixture(t, "cisco_ios_show_inventory.txt"))
	if ios.PID != "WS-C3750X-48P-S" || ios.Serial != "FDO1734X0AB" {
		t.Errorf("IOS chassis = %+v, want the WS-C3750X entry", ios)
	}

	// The guard: an inventory whose first entry is a subcomponent yields no
	// chassis at all rather than a power supply's serial.
	only := ciscoParseInventory(`NAME: "Switch 1 Power Supply Module 0", DESCR: "715W AC Power Supply"
PID: PWR-C1-715WAC     , VID: V02  , SN: DTN2138W0FG
`)
	if only.PID != "" || only.Serial != "" {
		t.Errorf("a power supply was reported as the chassis: %+v", only)
	}
}

// --- interfaces, VLANs, neighbours ------------------------------------------

func TestCiscoParseInterfaces_ReadsBothStatesAndBandwidth(t *testing.T) {
	interfaces := ciscoParseInterfaces(ciscoFixture(t, "cisco_ios_show_interfaces.txt"))
	byName := map[string]map[string]interface{}{}
	for _, iface := range interfaces {
		byName[iface["name"].(string)] = iface
	}
	if len(byName) != 5 {
		t.Fatalf("expected five interfaces, got %v", interfaceNames(interfaces))
	}

	up := byName["GigabitEthernet1/0/1"]
	if up["state"] != "up" || up["admin_state"] != "up" || up["mac"] != "00:b0:e1:a2:b3:c4" || up["speed"] != 1000 {
		t.Errorf("Gi1/0/1 projection wrong: %+v", up)
	}
	if addrs, ok := up["addresses"].([]interface{}); !ok || len(addrs) != 1 || addrs[0] != "198.51.100.2/24" {
		t.Errorf("Gi1/0/1 address lost: %+v", up)
	}
	// The interface description is the operator's free text and is not
	// collected — net.interfaces has no field for it and nothing reads it.
	assertNoPoison(t, "cisco interfaces", interfaces)

	// "administratively down" is an administrative down; a bare "down" is a
	// link that failed with the interface still configured up. Collapsing them
	// loses the only half an operator can act on.
	shut := byName["GigabitEthernet1/0/2"]
	if shut["admin_state"] != "down" || shut["state"] != "down" {
		t.Errorf("shut interface: %+v", shut)
	}
	notConnected := byName["GigabitEthernet1/0/3"]
	if notConnected["admin_state"] != "up" || notConnected["state"] != "down" {
		t.Errorf("unplugged interface read as administratively down: %+v", notConnected)
	}

	// A 64 Kbit serial rounds to 0 Mbit, and 0 means "unknown" in the schema.
	if _, hasSpeed := byName["Serial0/1/0"]["speed"]; hasSpeed {
		t.Errorf("a sub-megabit link was reported as 0 Mbit/s: %+v", byName["Serial0/1/0"])
	}
}

func TestCiscoMergeBriefInterfaces_MatchesAbbreviatedNames(t *testing.T) {
	detailed := ciscoParseInterfaces(ciscoFixture(t, "cisco_ios_show_interfaces.txt"))
	brief := ciscoParseIPInterfaceBrief(ciscoFixture(t, "cisco_iosxe_show_ip_interface_brief.txt"))
	merged := ciscoMergeBriefInterfaces(detailed, brief)

	names := interfaceNames(merged)
	// Five from `show interfaces`, plus Lo0 which only the brief view listed.
	// "Gi1/0/1" must NOT appear beside "GigabitEthernet1/0/1": matching on the
	// literal string is how one interface becomes two rows.
	if len(merged) != 6 {
		t.Fatalf("expected six merged interfaces, got %d: %v", len(merged), names)
	}
	for _, abbreviated := range []string{"Gi1/0/1", "Gi1/0/2", "Gi1/0/3", "Vl10"} {
		if contains(names, abbreviated) {
			t.Errorf("abbreviated name %q survived the merge as its own interface: %v", abbreviated, names)
		}
	}
	if !contains(names, "Lo0") {
		t.Errorf("an interface only the brief view listed was dropped: %v", names)
	}

	byName := map[string]map[string]interface{}{}
	for _, iface := range merged {
		byName[iface["name"].(string)] = iface
	}
	// The detailed view measured more, so it wins where both spoke.
	if byName["GigabitEthernet1/0/1"]["mac"] != "00:b0:e1:a2:b3:c4" {
		t.Errorf("the detailed view's MAC was lost in the merge: %+v", byName["GigabitEthernet1/0/1"])
	}
	if byName["Vlan10"]["state"] != "up" {
		t.Errorf("Vlan10 lost its state: %+v", byName["Vlan10"])
	}
}

func TestCiscoParseVlanBrief_SkipsReservedAndSuspendedVlans(t *testing.T) {
	vlans := ciscoParseVlanBrief(ciscoFixture(t, "cisco_ios_show_vlan_brief.txt"))
	got := map[int]string{}
	for _, vlan := range vlans {
		got[vlan["id"].(int)] = vlan["name"].(string)
	}
	want := map[int]string{1: "default", 10: "Users", 20: "Voice"}
	if len(got) != len(want) {
		t.Fatalf("VLANs = %+v, want %+v", got, want)
	}
	for id, name := range want {
		if got[id] != name {
			t.Errorf("VLAN %d = %q, want %q", id, got[id], name)
		}
	}
	// 1002-1005 are the FDDI/token-ring defaults every IOS switch ships with;
	// 30 is suspended and carries nothing.
	for _, id := range []int{30, 1002, 1003, 1004, 1005} {
		if _, present := got[id]; present {
			t.Errorf("VLAN %d should not be reported as a segment: %+v", id, got)
		}
	}
}

func TestCiscoParseCDPNeighbors_IgnoresTheVersionBanner(t *testing.T) {
	neighbors, edges := ciscoParseCDPNeighbors(ciscoFixture(t, "cisco_ios_show_cdp_neighbors_detail.txt"))

	// The `Version :` block in the fixture carries an enable secret and an SNMP
	// community. Neither is stripped afterwards — the parser never reads a line
	// whose prefix it does not know.
	assertNoPoison(t, "cisco cdp neighbours", neighbors)
	assertNoPoison(t, "cisco cdp edges", edges)

	if len(neighbors) != 2 || len(edges) != 2 {
		t.Fatalf("expected two neighbours and two edges, got %d/%d", len(neighbors), len(edges))
	}
	first := neighbors[0]
	if first["protocol"] != "cdp" || first["remote_name"] != "core-sw-1.example.net" ||
		first["remote_address"] != "198.51.100.1" ||
		first["local_port"] != "GigabitEthernet1/0/1" || first["remote_port"] != "GigabitEthernet1/0/24" {
		t.Errorf("CDP projection wrong: %+v", first)
	}

	edge := edges[0]
	if edge.Type != relTypeConnectsTo || edge.Direction != SubjectToPeer {
		t.Errorf("edge shape wrong: %+v", edge)
	}
	if edge.Peer.Identifier(IdentifierFQDN) != "core-sw-1.example.net" ||
		edge.Peer.Identifier(IdentifierIPAddress) != "198.51.100.1" {
		t.Errorf("peer identifiers lost: %+v", edge.Peer)
	}
	if edge.Peer.ClassHint != "switch" {
		t.Errorf("class hint = %q, want switch (from the WS-C platform)", edge.Peer.ClassHint)
	}
	if edge.Attributes["discovery_protocol"] != "cdp" ||
		edge.Attributes["local_port"] != "GigabitEthernet1/0/1" ||
		edge.Attributes["remote_port"] != "GigabitEthernet1/0/24" {
		t.Errorf("port attributes lost: %+v", edge.Attributes)
	}
	if edges[1].Peer.ClassHint != "router" {
		t.Errorf("ISR neighbour class hint = %q, want router", edges[1].Peer.ClassHint)
	}
}

func TestCiscoParseLLDPNeighbors_BothIOSFormats(t *testing.T) {
	// IOS-XE prints "Local Intf"; IOS 15.x does not print it at all, and a
	// parser written against one silently reads nothing on the other.
	xeNeighbors, xeEdges := ciscoParseLLDPNeighbors(ciscoFixture(t, "cisco_iosxe_show_lldp_neighbors_detail.txt"))
	assertNoPoison(t, "cisco lldp neighbours (IOS-XE)", xeNeighbors)
	assertNoPoison(t, "cisco lldp edges (IOS-XE)", xeEdges)
	if len(xeNeighbors) != 2 || len(xeEdges) != 2 {
		t.Fatalf("IOS-XE: expected two neighbours and two edges, got %d/%d: %+v", len(xeNeighbors), len(xeEdges), xeNeighbors)
	}
	first := xeNeighbors[0]
	if first["protocol"] != "lldp" || first["remote_mac"] != "00:b0:e1:a2:00:01" ||
		first["remote_name"] != "core-sw-1.example.net" || first["remote_port"] != "Gi1/0/24" ||
		first["local_port"] != "Gi1/0/1" || first["remote_address"] != "198.51.100.1" {
		t.Errorf("IOS-XE LLDP projection wrong: %+v", first)
	}
	// "not advertised" is a placeholder, not a name.
	second := xeNeighbors[1]
	if _, named := second["remote_name"]; named {
		t.Errorf("\"not advertised\" was stored as a system name: %+v", second)
	}
	if second["remote_mac"] != "0c:47:c9:aa:bb:cc" {
		t.Errorf("a neighbour identified only by chassis MAC was lost: %+v", second)
	}

	iosNeighbors, iosEdges := ciscoParseLLDPNeighbors(ciscoFixture(t, "cisco_ios_show_lldp_neighbors_detail.txt"))
	assertNoPoison(t, "cisco lldp neighbours (IOS)", iosNeighbors)
	assertNoPoison(t, "cisco lldp edges (IOS)", iosEdges)
	if len(iosNeighbors) != 1 || len(iosEdges) != 1 {
		t.Fatalf("IOS: expected one neighbour and one edge, got %d/%d", len(iosNeighbors), len(iosEdges))
	}
	only := iosNeighbors[0]
	// This entry's chassis id is an address rather than a MAC.
	if only["remote_name"] != "rtr-edge-1.example.net" || only["remote_address"] != "198.51.100.9" {
		t.Errorf("IOS LLDP projection wrong: %+v", only)
	}
	if _, hasMAC := only["remote_mac"]; hasMAC {
		t.Errorf("an address was recorded as a MAC: %+v", only)
	}
	if _, hasLocal := only["local_port"]; hasLocal {
		t.Errorf("a local port was invented for a format that does not report one: %+v", only)
	}
}

func TestCiscoSplitRecords_FallsBackToTheStartKey(t *testing.T) {
	// Some platforms print no rule between entries.
	records := ciscoSplitRecords("Chassis id: aaaa.bbbb.cccc\nPort id: Gi0/1\nChassis id: dddd.eeee.ffff\nPort id: Gi0/2\n", "Chassis id:")
	if len(records) != 2 {
		t.Fatalf("expected two records from the key-based split, got %d: %q", len(records), records)
	}
	if !strings.Contains(records[0], "Gi0/1") || !strings.Contains(records[1], "Gi0/2") {
		t.Errorf("records were split in the wrong place: %q", records)
	}
}

func TestCiscoParseARP_SkipsIncompleteEntries(t *testing.T) {
	neighbors := ciscoParseARP(ciscoFixture(t, "cisco_ios_show_ip_arp.txt"))
	if len(neighbors) != 3 {
		t.Fatalf("expected the three resolved ARP entries, got %+v", neighbors)
	}
	first := neighbors[0]
	if first["protocol"] != "arp" || first["remote_mac"] != "00:b0:e1:a2:00:01" ||
		first["remote_address"] != "198.51.100.1" || first["local_port"] != "GigabitEthernet1/0/1" {
		t.Errorf("ARP projection wrong: %+v", first)
	}
	for _, entry := range neighbors {
		if entry["remote_address"] == "198.51.100.77" {
			t.Errorf("an incomplete ARP entry was reported as a neighbour: %+v", entry)
		}
	}
}

// --- the wired collection ---------------------------------------------------

func TestCiscoCollectOps_EmitsTheOpsSet(t *testing.T) {
	result := &InterrogateResult{}
	sysInfo := ciscoParseShowVersionForTest(t, ciscoFixture(t, "cisco_iosxe_show_version.txt"))
	pid := ciscoCollectOps(context.Background(), result, newCiscoFixtureRunner(t, ciscoIOSFixtures()), sysInfo)

	assertObservationsValid(t, "cisco ops", result)
	assertNoPoison(t, "cisco ops", result)

	if pid != "WS-C3750X-48P-S" {
		t.Errorf("chassis PID = %q, want the inventory's chassis entry", pid)
	}
	for key, want := range map[string]any{
		factHWVendor:         ciscoVendor,
		factHWModel:          "WS-C3750X-48P-S", // the inventory PID supersedes `show version`
		factHWSerial:         "FDO1734X0AB",
		factOSName:           "IOS-XE",
		factOSVersion:        "17.09.04a",
		factNetUptimeSeconds: 86400 + 2*3600 + 3*60,
		factMgmtProtocol:     ciscoManagementProtocol,
		factMgmtPlaintext:    false,
	} {
		if got := factValue(t, result, key); got != want {
			t.Errorf("%s = %v (%T), want %v", key, got, got, want)
		}
	}

	for _, key := range []string{factNetInterfaces, factNetVlans, factNetNeighbors} {
		if !hasFact(result, key) {
			t.Errorf("no %s fact reached the result; facts: %v", key, factKeys(result))
		}
	}

	// CDP, LLDP and ARP land in ONE net.neighbors fact — asset_facts is unique
	// on (asset, key, source_ref), so three facts would be two silent
	// overwrites.
	neighbors, ok := factValue(t, result, factNetNeighbors).([]map[string]interface{})
	if !ok {
		t.Fatalf("net.neighbors is %T, want []map[string]interface{}", factValue(t, result, factNetNeighbors))
	}
	counts := map[string]int{}
	for _, entry := range neighbors {
		counts[entry["protocol"].(string)]++
	}
	if counts["cdp"] != 2 || counts["lldp"] != 2 || counts["arp"] != 3 {
		t.Errorf("neighbour protocols = %v, want 2 cdp / 2 lldp / 3 arp", counts)
	}

	if edges := relationshipsOfType(result, relTypeConnectsTo); len(edges) != 4 {
		t.Errorf("expected two CDP and two LLDP edges, got %d", len(edges))
	}

	// The Cisco interrogator needs an SSH session, so it is the one collector
	// here that cannot be driven through the Registry — which is what applies
	// Sanitize in production. Applying it by hand to the collected result is
	// what keeps Cisco covered by the same claim as F5 and Fortinet: both that
	// the backstop runs clean over what this collector emits, and that it does
	// not eat the posture it walks past.
	Sanitize(result)
	assertObservationsValid(t, "cisco ops (sanitized)", result)
	assertNoPoison(t, "cisco ops (sanitized)", result)
	blob, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(blob), "PRIVATE KEY") {
		t.Errorf("a PEM private key survived Sanitize: %s", blob)
	}
	for _, survivor := range []string{"core-sw-1.example.net", "GigabitEthernet1/0/1", "WS-C3750X-48P-S"} {
		if !strings.Contains(string(blob), survivor) {
			t.Errorf("Sanitize destroyed %q, which is the inventory this collector exists to produce", survivor)
		}
	}
}

// A device that answers none of the ops commands must still produce a usable
// result — and must not claim facts it never read.
func TestCiscoCollectOps_SurvivesUnavailableCommands(t *testing.T) {
	result := &InterrogateResult{}
	pid := ciscoCollectOps(context.Background(), result, newCiscoFixtureRunner(t, nil), map[string]interface{}{})

	assertObservationsValid(t, "cisco ops (no commands)", result)
	if pid != "" {
		t.Errorf("a chassis PID was reported for a device that answered nothing: %q", pid)
	}
	for _, key := range []string{factHWModel, factHWSerial, factOSName, factOSVersion, factNetUptimeSeconds, factNetInterfaces, factNetVlans, factNetNeighbors} {
		if hasFact(result, key) {
			t.Errorf("%s was emitted for a response that never arrived: %v", key, factKeys(result))
		}
	}
	// Vendor and management plane are known from having connected at all.
	if !hasFact(result, factHWVendor) || !hasFact(result, factMgmtProtocol) {
		t.Errorf("the facts the connection itself establishes were lost: %v", factKeys(result))
	}
	if len(result.Relationships) != 0 {
		t.Errorf("edges were emitted with no neighbour data: %+v", result.Relationships)
	}
}

// --- the secrets rule -------------------------------------------------------

// `show running-config | include ssl cipher` is the ONE running-config form
// this collector may run. The fixture is what the device returns when the
// filter is ignored — every secret a Cisco configuration carries — and the
// parser must produce the cipher lines and nothing else.
func TestCiscoRunningConfigProjection_KeepsOnlyCipherLines(t *testing.T) {
	c := &ciscoSSHClient{host: "198.51.100.5"}
	configs := c.parseRunningCryptoConfig(ciscoFixture(t, "cisco_ios_show_running_config_filtered.txt"))

	assertNoPoison(t, "cisco running-config", configs)
	if len(configs) != 2 {
		t.Fatalf("expected the two `ssl cipher` lines, got %+v", configs)
	}
	assets := make([]CryptoAsset, 0, len(configs))
	for _, config := range configs {
		assets = append(assets, c.convertSSLConfigToAsset(config))
	}
	assertNoPoison(t, "cisco ssl assets", assets)
	if !contains(assets[0].SupportedCiphers, "ECDHE-RSA-AES256-GCM-SHA384") {
		t.Errorf("cipher posture lost: %+v", assets[0].SupportedCiphers)
	}
}

// --- the output bound -------------------------------------------------------

func TestBoundedWriter_StopsAtTheLimitAndSaysSo(t *testing.T) {
	w := &boundedWriter{limit: 10}
	n, err := w.Write([]byte("0123456789"))
	if n != 10 || err != nil {
		t.Fatalf("Write = (%d, %v), want (10, nil)", n, err)
	}
	if w.truncated {
		t.Error("a write that exactly fills the limit is not a truncation")
	}
	// The producer must never see an error: closing the pipe mid-command would
	// surface as a command failure and lose the rows we did read.
	if n, err := w.Write([]byte("overflow")); n != 8 || err != nil {
		t.Fatalf("overflow Write = (%d, %v), want (8, nil)", n, err)
	}
	if !w.truncated {
		t.Error("the overflow was not recorded as a truncation")
	}
	if w.buf.String() != "0123456789" {
		t.Errorf("buffer = %q, want the first 10 bytes only", w.buf.String())
	}

	partial := &boundedWriter{limit: 4}
	_, _ = partial.Write([]byte("abcdefgh"))
	if partial.buf.String() != "abcd" || !partial.truncated {
		t.Errorf("partial write = %q truncated=%v, want \"abcd\" true", partial.buf.String(), partial.truncated)
	}
}

func TestCiscoBound_CapsATableAtTheRowLimit(t *testing.T) {
	rows := make([]map[string]interface{}, ciscoMaxTableRows+25)
	for i := range rows {
		rows[i] = map[string]interface{}{"name": "x"}
	}
	if got := ciscoBound("interfaces", rows); len(got) != ciscoMaxTableRows {
		t.Errorf("bounded table has %d rows, want %d", len(got), ciscoMaxTableRows)
	}
	short := rows[:3]
	if got := ciscoBound("interfaces", short); len(got) != 3 {
		t.Errorf("a table under the bound was truncated: %d rows", len(got))
	}
}

// --- class hints ------------------------------------------------------------

func TestCiscoClassHintForPID(t *testing.T) {
	cases := map[string]string{
		"WS-C3750X-48P-S":  "switch",
		"C9300-48P":        "switch",
		"C9800-40-K9":      "wireless_controller", // longest prefix wins over C9...
		"C9500-48Y4C":      "switch",
		"N9K-C93180YC-EX":  "switch",
		"ISR4331/K9":       "router",
		"ASR1001-X":        "router",
		"C8300-1N1S-6T":    "router",
		"ASA5525":          "firewall",
		"FPR2110":          "firewall",
		"AIR-AP1852I-B-K9": "access_point",
		"AIR-CT5520-K9":    "wireless_controller",
		"UNKNOWN-PID":      "",
		"":                 "",
	}
	for pid, want := range cases {
		if got := ciscoClassHintForPID(pid); got != want {
			t.Errorf("ciscoClassHintForPID(%q) = %q, want %q", pid, got, want)
		}
	}
}

func TestCiscoDeviceIdentity_PrefersWhatTheDeviceSaid(t *testing.T) {
	sysInfo := ciscoParseShowVersionForTest(t, ciscoFixture(t, "cisco_iosxe_show_version.txt"))
	// The record says "cisco_switch"; the banner says IOS-XE and the inventory
	// says C9300-48P. The device's own answers win.
	identity := ciscoDeviceIdentity(sysInfo, "cisco_switch", "C9300-48P")
	if identity.Vendor != ciscoVendor {
		t.Errorf("vendor = %q, want %q (one spelling across SSH and SNMP)", identity.Vendor, ciscoVendor)
	}
	if identity.Model != "C9300-48P" || identity.OSVersion != "IOS-XE 17.09.04a" {
		t.Errorf("identity = %+v", identity)
	}
	if identity.ClassHint != "switch" {
		t.Errorf("class hint = %q, want switch", identity.ClassHint)
	}

	// No banner and no inventory: the operator's device type is the fallback.
	fallback := ciscoDeviceIdentity(map[string]interface{}{}, "cisco_asa", "")
	if fallback.ClassHint != "firewall" {
		t.Errorf("fallback class hint = %q, want firewall", fallback.ClassHint)
	}
	if fallback.Model != "" {
		t.Errorf("a model was invented for a device that stated none: %+v", fallback)
	}
}

// --- helpers ----------------------------------------------------------------

// ciscoParseShowVersionForTest runs the production `show version` projection
// over a fixture, through the real client method rather than a copy of it.
func ciscoParseShowVersionForTest(t *testing.T, output string) map[string]interface{} {
	t.Helper()
	c := &ciscoSSHClient{}
	info, err := c.parseSystemInfo(output)
	if err != nil {
		t.Fatalf("parseSystemInfo: %v", err)
	}
	return info
}

func interfaceNames(interfaces []map[string]interface{}) []string {
	names := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		name, _ := iface["name"].(string)
		names = append(names, name)
	}
	return names
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
