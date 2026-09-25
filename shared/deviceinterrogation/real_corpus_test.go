package deviceinterrogation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This file drives every fixture under testdata/real/ through the collector
// function that is meant to parse it. The corpus is real, captured device
// output (see testdata/real/README.md and each vendor directory's
// PROVENANCE.md) — not hand-written text shaped to make a parser succeed.
//
// The mapping from file to parser function is an explicit table, not a
// filename convention the test infers from — see W0.4's brief in
// docsv4/internal/developer/standards/features/discovery-beyond-the-lab.md:
// "map files → parser via a table in the test, not by guessing from names."
// A row with a nil parseFn documents a fixture kept for a command our
// collectors do not parse at all yet (a coverage gap, not a parser bug); the
// test still loads the file and asserts it is non-empty, but calls nothing.
//
// Every row with a parser asserts CORRECT behaviour on the real output — the
// exact peer, key size, row count or port the device printed. W0.4
// landed these rows asserting the then-current, wrong behaviour under a
// knownGap label; W3.2 fixed the parsers and turned each one into the hard
// assertion below. TestRealCorpus_EveryParsedRowAssertsCorrectBehaviour keeps
// it that way: a knownGap is allowed only on a row with no parser.
type corpusCase struct {
	// file is relative to testdata/real/cisco/<osFamily>/.
	osFamily string
	file     string
	command  string // the real CLI command/API call that produced this output
	// parse is nil for a fixture kept only to document a coverage gap (no
	// collector parses this command at all). Otherwise it must not panic.
	parse func(t *testing.T, output string)
	// knownGap explains a row kept for a command no collector parses yet (a
	// coverage gap). It is allowed ONLY with a nil parse: a row that calls a
	// parser asserts the correct result, never a documented wrong one.
	knownGap string
}

func realFixturePath(osFamily, file string) string {
	return filepath.Join("testdata", "real", "cisco", osFamily, file)
}

func readRealFixture(t *testing.T, osFamily, file string) string {
	t.Helper()
	path := realFixturePath(osFamily, file)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read real fixture %s: %v", path, err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		t.Fatalf("real fixture %s is empty", path)
	}
	return string(data)
}

// cases is the file -> parser table. Every *.txt file under
// testdata/real/cisco/ must appear here exactly once — TestRealCorpus_NoOrphanFixtures
// enforces that so a fixture can never silently stop being exercised.
func realCorpusCases() []corpusCase {
	return []corpusCase{
		// ---------------------------------------------------------------
		// cisco_ios (classic IOS and one IOS-XE banner variant)
		// ---------------------------------------------------------------
		{
			osFamily: "cisco_ios", file: "show_version.txt", command: "show version",
			parse: func(t *testing.T, output string) {
				if got := ciscoOSName(output); got != "IOS" {
					t.Errorf("ciscoOSName = %q, want IOS", got)
				}
				c := &ciscoSSHClient{}
				info, err := c.parseSystemInfo(output)
				if err != nil {
					t.Fatalf("parseSystemInfo: %v", err)
				}
				if info["version"] == nil || info["version"] == "" {
					t.Error("parseSystemInfo: version not extracted from real show version")
				}
				if info["uptime"] == nil || info["uptime"] == "" {
					t.Error("parseSystemInfo: uptime not extracted from real show version")
				}
			},
		},
		{
			osFamily: "cisco_ios", file: "show_version_iosxe.txt", command: "show version",
			parse: func(t *testing.T, output string) {
				if got := ciscoOSName(output); got != "IOS-XE" {
					t.Errorf("ciscoOSName = %q, want IOS-XE", got)
				}
				c := &ciscoSSHClient{}
				info, err := c.parseSystemInfo(output)
				if err != nil {
					t.Fatalf("parseSystemInfo: %v", err)
				}
				if info["version"] == nil || info["version"] == "" {
					t.Error("parseSystemInfo: version not extracted from real IOS-XE show version")
				}
			},
		},
		{
			// Real-world data, not a parser defect: this Cisco 3640's chassis
			// line is "NAME: \"3640 chassis\"" followed by "PID:  , VID: 0xFF,
			// SN: <serial>" — the PID is genuinely blank on the wire. The
			// correct result is the chassis serial with NO PID (never the
			// network module's PID from the next entry); hw.model then comes
			// from the `show version` fallback in ciscoCollectOps.
			osFamily: "cisco_ios", file: "show_inventory.txt", command: "show inventory",
			parse: func(t *testing.T, output string) {
				chassis := ciscoParseInventory(output)
				if chassis.Name != "3640 chassis" || chassis.Serial != "REDACTEDSN1" || chassis.PID != "" {
					t.Errorf("ciscoParseInventory = %+v, want the 3640 chassis entry: serial REDACTEDSN1 and its genuinely blank PID", chassis)
				}
			},
		},
		{
			osFamily: "cisco_ios", file: "show_ip_interface_brief.txt", command: "show ip interface brief",
			parse: func(t *testing.T, output string) {
				rows := ciscoParseIPInterfaceBrief(output)
				if len(rows) == 0 {
					t.Error("ciscoParseIPInterfaceBrief: 0 rows from real show ip interface brief")
				}
			},
		},
		{
			osFamily: "cisco_ios", file: "show_vlan.txt", command: "show vlan",
			parse: func(t *testing.T, output string) {
				vlans := ciscoParseVlanBrief(output)
				if len(vlans) == 0 {
					t.Error("ciscoParseVlanBrief: 0 VLANs from real show vlan")
				}
				for _, v := range vlans {
					if id, _ := v["id"].(int); id >= 1002 && id <= 1005 {
						t.Errorf("ciscoParseVlanBrief: leaked a reserved FDDI/token-ring default VLAN: %+v", v)
					}
				}
			},
		},
		{
			osFamily: "cisco_ios", file: "show_cdp_neighbors_detail.txt", command: "show cdp neighbors detail",
			parse: func(t *testing.T, output string) {
				neighbors, edges := ciscoParseCDPNeighbors(output)
				if len(neighbors) == 0 || len(edges) == 0 {
					t.Errorf("ciscoParseCDPNeighbors: got %d neighbors / %d edges from real IOS CDP output, want > 0 of each", len(neighbors), len(edges))
				}
			},
		},
		{
			osFamily: "cisco_ios", file: "show_lldp_neighbors_detail__1.txt", command: "show lldp neighbors detail",
			parse: func(t *testing.T, output string) {
				neighbors, edges := ciscoParseLLDPNeighbors(output)
				if len(neighbors) == 0 || len(edges) == 0 {
					t.Errorf("ciscoParseLLDPNeighbors: got %d neighbors / %d edges from real IOS LLDP output, want > 0 of each", len(neighbors), len(edges))
				}
			},
		},
		{
			osFamily: "cisco_ios", file: "show_ip_arp.txt", command: "show ip arp",
			parse: func(t *testing.T, output string) {
				rows := ciscoParseARP(output)
				if len(rows) == 0 {
					t.Error("ciscoParseARP: 0 rows from real IOS show ip arp")
				}
				for _, r := range rows {
					if r["remote_address"] == nil || r["remote_mac"] == nil {
						t.Errorf("ciscoParseARP: incomplete row %+v", r)
					}
				}
			},
		},
		{
			osFamily: "cisco_ios", file: "show_interfaces.txt", command: "show interfaces",
			parse: func(t *testing.T, output string) {
				rows := ciscoParseInterfaces(output)
				if len(rows) == 0 {
					t.Error("ciscoParseInterfaces: 0 rows from real show interfaces")
				}
			},
		},
		{
			// Two GRE-over-IPsec flows (Tunnel1, Tunnel2), both NAT-traversed
			// ("current_peer … port 4500", "UDP-Encaps"), transform
			// "esp-256-aes esp-sha-hmac" — which IOS prints for `esp-aes 256`.
			// Fixed: the peer comes from current_peer (there is no "addr="
			// token in real output), and the "in use settings" line that
			// follows the transform no longer zeroes the key size.
			osFamily: "cisco_ios", file: "show_crypto_ipsec_sa_detail.txt", command: "show crypto ipsec sa detail",
			parse: func(t *testing.T, output string) {
				c := &ciscoSSHClient{host: "192.0.2.10"}
				assertCiscoSAs(t, c.parseIPSecSA(output), []ciscoCryptoConfig{
					{Interface: "Tunnel1", Name: "Tunnel1-head-0", LocalAddress: "192.0.2.2", PeerAddress: "198.51.100.2", Port: 4500, NATTraversal: true, Mode: "transport", CipherSuite: "AES-256-CBC", KeySize: 256, HashAlg: "SHA1"},
					{Interface: "Tunnel2", Name: "Tunnel2-head-0", LocalAddress: "192.0.2.2", PeerAddress: "203.0.113.2", Port: 4500, NATTraversal: true, Mode: "transport", CipherSuite: "AES-256-CBC", KeySize: 256, HashAlg: "SHA1"},
				})
			},
		},
		{
			// The closest real IKEv2 capture available: `show crypto session
			// detail`, not the `show crypto ikev2 sa` the collector runs (no
			// licence-compatible real capture of that exists yet; the table
			// form is covered by TestCiscoIKEv2SA_* with the documented
			// format). This command carries no Encr:/Hash:/DH Grp: fields, so
			// the correct result has addresses, port and version and NO
			// cipher — a parser that invented one would fail here.
			osFamily: "cisco_ios", file: "show_crypto_session_detail_ikev2.txt", command: "show crypto session detail",
			parse: func(t *testing.T, output string) {
				c := &ciscoSSHClient{}
				assertCiscoSAs(t, c.parseIKEv2SA(output), []ciscoCryptoConfig{
					{LocalAddress: "203.0.113.2", PeerAddress: "192.0.2.3", Port: 4500, NATTraversal: true, IKEVersion: "IKEv2"},
				})
			},
		},

		// ---------------------------------------------------------------
		// cisco_nxos
		// ---------------------------------------------------------------
		{
			osFamily: "cisco_nxos", file: "show_version.txt", command: "show version",
			parse: func(t *testing.T, output string) {
				if got := ciscoOSName(output); got != "NX-OS" {
					t.Errorf("ciscoOSName = %q, want NX-OS", got)
				}
				c := &ciscoSSHClient{}
				info, err := c.parseSystemInfo(output)
				if err != nil {
					t.Fatalf("parseSystemInfo: %v", err)
				}
				if info["version"] == nil || info["version"] == "" {
					t.Error("parseSystemInfo: version not extracted from real NX-OS show version (the NXOS:/system: version pattern)")
				}
			},
		},
		{
			osFamily: "cisco_nxos", file: "show_inventory.txt", command: "show inventory",
			parse: func(t *testing.T, output string) {
				chassis := ciscoParseInventory(output)
				if chassis.PID == "" || chassis.Serial == "" {
					t.Errorf("ciscoParseInventory: got %+v, want a populated chassis PID and serial from real NX-OS inventory", chassis)
				}
			},
		},
		{
			osFamily: "cisco_nxos", file: "show_ip_interface_brief.txt", command: "show ip interface brief",
			parse: func(t *testing.T, output string) {
				rows := ciscoParseIPInterfaceBrief(output)
				if len(rows) == 0 {
					t.Error("ciscoParseIPInterfaceBrief: 0 rows from real NX-OS show ip interface brief")
				}
			},
		},
		{
			osFamily: "cisco_nxos", file: "show_vlan.txt", command: "show vlan",
			parse: func(t *testing.T, output string) {
				vlans := ciscoParseVlanBrief(output)
				if len(vlans) == 0 {
					t.Error("ciscoParseVlanBrief: 0 VLANs from real NX-OS show vlan")
				}
			},
		},
		{
			osFamily: "cisco_nxos", file: "show_cdp_neighbors_detail.txt", command: "show cdp neighbors detail",
			parse: func(t *testing.T, output string) {
				neighbors, edges := ciscoParseCDPNeighbors(output)
				if len(neighbors) == 0 || len(edges) == 0 {
					t.Errorf("ciscoParseCDPNeighbors: got %d neighbors / %d edges from real NX-OS CDP output (no space after 'Device ID:'), want > 0 of each", len(neighbors), len(edges))
				}
			},
		},
		{
			// NX-OS names the local port "Local Port id:" and the management
			// address "Management Address:"; the IOS keys ("Local Intf:",
			// "IP:") read neither, so every Nexus edge lost its local port and
			// every neighbour its address.
			osFamily: "cisco_nxos", file: "show_lldp_neighbors_detail.txt", command: "show lldp neighbors detail",
			parse: func(t *testing.T, output string) {
				neighbors, edges := ciscoParseLLDPNeighbors(output)
				if len(neighbors) != 4 || len(edges) != 4 {
					t.Fatalf("ciscoParseLLDPNeighbors: %d neighbours / %d edges, want 4 / 4", len(neighbors), len(edges))
				}
				want := map[string]interface{}{"protocol": "lldp", "remote_mac": "00:14:1c:57:a4:8b", "remote_name": "Switch.cisco.com", "remote_port": "Fa1/0/9", "local_port": "mgmt0", "remote_address": "192.0.2.2"}
				assertCiscoEntry(t, "first NX-OS LLDP neighbour", neighbors[0], want)
				if edges[0].Attributes["local_port"] != "mgmt0" || edges[0].Attributes["remote_port"] != "Fa1/0/9" {
					t.Errorf("first edge attributes = %v, want local_port mgmt0 / remote_port Fa1/0/9", edges[0].Attributes)
				}
				for i, n := range neighbors {
					if n["local_port"] == nil || n["remote_address"] == nil {
						t.Errorf("neighbour %d lost its local port or address: %v", i, n)
					}
				}
			},
		},
		{
			// NX-OS `show ip arp`: "<addr> <age> <mac> <interface>", no
			// leading "Internet" column. 23 table rows; the INCOMPLETE one is
			// not a neighbour.
			osFamily: "cisco_nxos", file: "show_ip_arp.txt", command: "show ip arp",
			parse: func(t *testing.T, output string) {
				rows := ciscoParseARP(output)
				if len(rows) != 22 {
					t.Fatalf("ciscoParseARP: %d rows from real NX-OS show ip arp, want 22 (23 rows, one INCOMPLETE)", len(rows))
				}
				assertCiscoEntry(t, "first NX-OS ARP row", rows[0], map[string]interface{}{"protocol": "arp", "remote_address": "192.0.2.2", "remote_mac": "3c:60:f4:0e:f9:c3", "local_port": "Ethernet1/41"})
				for _, r := range rows {
					if r["remote_address"] == "198.51.100.9" {
						t.Errorf("the INCOMPLETE entry was reported as a neighbour: %v", r)
					}
				}
			},
		},

		// ---------------------------------------------------------------
		// cisco_xr (IOS-XR)
		// ---------------------------------------------------------------
		{
			// "Cisco IOS XR Software, Version 6.1.4" — IOS-XR, a different OS
			// from IOS with its own advisories and EOL rows. It used to match
			// no case at all and leave os.name unset for every XR box.
			osFamily: "cisco_xr", file: "show_version.txt", command: "show version",
			parse: func(t *testing.T, output string) {
				if got := ciscoOSName(output); got != "IOS-XR" {
					t.Errorf("ciscoOSName = %q, want IOS-XR", got)
				}
				c := &ciscoSSHClient{}
				info, err := c.parseSystemInfo(output)
				if err != nil {
					t.Fatalf("parseSystemInfo: %v", err)
				}
				if info["version"] != "6.1.4" || info["model"] != "NCS-5500" || info["os_name"] != "IOS-XR" {
					t.Errorf("parseSystemInfo = %v, want version 6.1.4, model NCS-5500, os_name IOS-XR", info)
				}
				if seconds, ok := ciscoParseUptime(info["uptime"].(string)); !ok || seconds != 4*7*86400+6*86400+3600+42*60 {
					t.Errorf("uptime %v parsed to %d, want 4 weeks 6 days 1 hour 42 minutes", info["uptime"], seconds)
				}
			},
		},
		{
			// A Cisco 8200: the chassis entry is "Rack 0", and its description
			// names the port form factor "QSFP56-DD" — which a substring match
			// for "sfp" read as a transceiver, discarding the chassis. Words
			// are matched as words now, and "Rack N" is XR's chassis.
			osFamily: "cisco_xr", file: "show_inventory.txt", command: "show inventory",
			parse: func(t *testing.T, output string) {
				chassis := ciscoParseInventory(output)
				if chassis.Name != "Rack 0" || chassis.PID != "8202-32FH-M" || chassis.Serial != "REDACTEDSN1" {
					t.Errorf("ciscoParseInventory = %+v, want Rack 0 / 8202-32FH-M / REDACTEDSN1", chassis)
				}
			},
		},
		{
			// IOS-XR's five columns: Interface, IP-Address, Status, Protocol,
			// Vrf-Name. Status "Shutdown" is the administrative down.
			osFamily: "cisco_xr", file: "show_ip_interface_brief.txt", command: "show ip interface brief",
			parse: func(t *testing.T, output string) {
				rows := ciscoParseIPInterfaceBrief(output)
				if len(rows) != 6 {
					t.Fatalf("ciscoParseIPInterfaceBrief: %d rows from real XR output, want 6", len(rows))
				}
				assertCiscoEntry(t, "shut XR interface", rows[0], map[string]interface{}{"name": "GigabitEthernet0/0/1/18", "admin_state": "down", "state": "down"})
				assertCiscoEntry(t, "addressed XR sub-interface", rows[4], map[string]interface{}{"name": "TenGigE0/0/2/0.2396", "admin_state": "up", "state": "up"})
				if addrs, _ := rows[4]["addresses"].([]interface{}); len(addrs) != 1 || addrs[0] != "198.51.100.2" {
					t.Errorf("TenGigE0/0/2/0.2396 addresses = %v, want [198.51.100.2]", rows[4]["addresses"])
				}
				if _, present := rows[0]["addresses"]; present {
					t.Errorf("an unassigned XR interface was given an address: %v", rows[0])
				}
			},
		},
		{
			// IOS-XR prints "Interface:" and "Port ID (outgoing port):" on
			// two lines. The one-line regex never matched, so every XR CDP
			// edge lost both port names. (The gap row asserted on attribute
			// keys "local_interface"/"remote_interface", which no code has
			// ever written — it could not fail either way.)
			osFamily: "cisco_xr", file: "show_cdp_neighbors_detail.txt", command: "show cdp neighbors detail",
			parse: func(t *testing.T, output string) {
				neighbors, edges := ciscoParseCDPNeighbors(output)
				if len(neighbors) == 0 || len(edges) != len(neighbors) {
					t.Fatalf("ciscoParseCDPNeighbors: %d neighbours / %d edges from real XR CDP output", len(neighbors), len(edges))
				}
				assertCiscoEntry(t, "first XR CDP neighbour", neighbors[0], map[string]interface{}{"protocol": "cdp", "remote_name": "nyc-dc-dcm005.ntc.com", "remote_address": "192.0.2.2", "local_port": "MgmtEth0/RSP0/CPU0/0", "remote_port": "GigabitEthernet1/9"})
				for i, e := range edges {
					if e.Attributes["local_port"] == nil || e.Attributes["remote_port"] == nil {
						t.Errorf("edge %d lost a port name: %v", i, e.Attributes)
					}
				}
			},
		},
		{
			// IOS-XR names the local port "Local Interface:" and lists the
			// management address as "IPv4 address:" under "Management
			// Addresses:"; neither was read.
			osFamily: "cisco_xr", file: "show_lldp_neighbors_detail.txt", command: "show lldp neighbors detail",
			parse: func(t *testing.T, output string) {
				neighbors, edges := ciscoParseLLDPNeighbors(output)
				if len(neighbors) != 5 || len(edges) != 5 {
					t.Fatalf("ciscoParseLLDPNeighbors: %d neighbours / %d edges, want 5 / 5", len(neighbors), len(edges))
				}
				assertCiscoEntry(t, "first XR LLDP neighbour", neighbors[0], map[string]interface{}{"protocol": "lldp", "remote_mac": "6c:03:b5:aa:bb:cc", "remote_name": "router-400.router.com", "remote_port": "Fou1/0/22", "local_port": "FourHundredGigE0/0/0/0", "remote_address": "192.0.2.2"})
			},
		},
		{
			// IOS-XR `show arp` (the collector now sends XR this command, not
			// `show ip arp` — TestCiscoCollectOps_PerPlatformCommands):
			// "<addr> <age> <mac> <state> <type> <interface>" per line card.
			// Three cards × ten rows; per card one "Interface" row (the
			// router's own address) and one Incomplete row are not
			// neighbours, leaving 24.
			osFamily: "cisco_xr", file: "show_arp.txt", command: "show arp",
			parse: func(t *testing.T, output string) {
				rows := ciscoParseARP(output)
				if len(rows) != 24 {
					t.Fatalf("ciscoParseARP: %d rows from real XR show arp, want 24", len(rows))
				}
				assertCiscoEntry(t, "first XR ARP row", rows[0], map[string]interface{}{"protocol": "arp", "remote_address": "198.51.100.2", "remote_mac": "aa:bb:cc:00:65:00", "local_port": "GigabitEthernet0/0/0/0"})
				for _, r := range rows {
					if r["remote_address"] == "192.0.2.2" {
						t.Errorf("the router's own interface address was reported as a neighbour: %v", r)
					}
				}
			},
		},

		// ---------------------------------------------------------------
		// cisco_asa
		// ---------------------------------------------------------------
		{
			osFamily: "cisco_asa", file: "show_version.txt", command: "show version",
			parse: func(t *testing.T, output string) {
				if got := ciscoOSName(output); got != "ASA" {
					t.Errorf("ciscoOSName = %q, want ASA", got)
				}
				c := &ciscoSSHClient{}
				info, err := c.parseSystemInfo(output)
				if err != nil {
					t.Fatalf("parseSystemInfo: %v", err)
				}
				if info["uptime"] == nil || info["uptime"] == "" {
					t.Error("parseSystemInfo: uptime not extracted from real ASA show version (the ASA 'up' wording, not IOS 'uptime is')")
				}
			},
		},
		{
			osFamily: "cisco_asa", file: "show_inventory.txt", command: "show inventory",
			parse: func(t *testing.T, output string) {
				chassis := ciscoParseInventory(output)
				if chassis.PID == "" || chassis.Serial == "" {
					t.Errorf("ciscoParseInventory: got %+v, want a populated PID/serial from real ASA inventory ('Name:' not 'NAME:')", chassis)
				}
			},
		},
		{
			osFamily: "cisco_asa", file: "show_interface_ip_brief.txt", command: "show interface ip brief",
			parse: func(t *testing.T, output string) {
				rows := ciscoParseIPInterfaceBrief(output)
				if len(rows) == 0 {
					t.Error("ciscoParseIPInterfaceBrief: 0 rows from real ASA show interface ip brief")
				}
			},
		},
		{
			// ASA `show arp`: "<nameif> <addr> <mac> <age>" — the interface
			// comes FIRST.
			osFamily: "cisco_asa", file: "show_arp.txt", command: "show arp",
			parse: func(t *testing.T, output string) {
				rows := ciscoParseARP(output)
				if len(rows) != 5 {
					t.Fatalf("ciscoParseARP: %d rows from real ASA show arp, want 5", len(rows))
				}
				assertCiscoEntry(t, "first ASA ARP row", rows[0], map[string]interface{}{"protocol": "arp", "remote_address": "192.0.2.2", "remote_mac": "44:4e:6d:f8:b9:7e", "local_port": "outside"})
				assertCiscoEntry(t, "last ASA ARP row", rows[4], map[string]interface{}{"protocol": "arp", "remote_address": "198.51.100.3", "remote_mac": "24:01:c7:5e:3a:cb", "local_port": "INSIDE"})
			},
		},
		{
			// Numbered sessions ("1 <peer> User Resp No AM_Active 3des SHA
			// preshrd 86400"): the peer is the SECOND column, not the row
			// number, and "AM_Active" is as active as "AM_ACTIVE" — all four
			// real sessions, each with its negotiated cipher and hash.
			osFamily: "cisco_asa", file: "show_crypto_ikev1_sa_detail.txt", command: "show crypto ikev1 sa detail",
			parse: func(t *testing.T, output string) {
				c := &ciscoSSHClient{}
				want := []ciscoCryptoConfig{}
				for _, peer := range []string{"192.0.2.2", "198.51.100.2", "203.0.113.2", "192.0.2.3"} {
					want = append(want, ciscoCryptoConfig{PeerAddress: peer, Port: 500, IKEVersion: "IKEv1", CipherSuite: "3DES", HashAlg: "SHA1"})
				}
				configs := c.parseISAKMPSA(output)
				assertCiscoSAs(t, configs, want)
				if len(configs) > 0 && (configs[0].Metadata["state"] != "AM_Active" || configs[0].Metadata["ike_auth_method"] != "preshrd") {
					t.Errorf("first session metadata = %v, want state AM_Active and auth method preshrd", configs[0].Metadata)
				}
			},
		},
		{
			// Three SAs: an RA tunnel on outside2, and TWO crypto-map
			// sequences under one "interface: COLO" — which splitting on
			// "interface:" alone merged into one row. The second is
			// NAT-traversed (endpoints "/4500", "NAT-T-Encaps"); the third's
			// sanitised peer "REMOTE-PEER-…" is not an address, so it has
			// none rather than a label pretending to be one.
			osFamily: "cisco_asa", file: "show_crypto_ipsec_sa.txt", command: "show crypto ipsec sa",
			parse: func(t *testing.T, output string) {
				c := &ciscoSSHClient{}
				assertCiscoSAs(t, c.parseIPSecSA(output), []ciscoCryptoConfig{
					{Interface: "outside2", Name: "def", LocalAddress: "192.0.2.2", PeerAddress: "198.51.100.2", Port: 500, Mode: "tunnel", CipherSuite: "3DES", HashAlg: "MD5"},
					{Interface: "COLO", Name: "COLO-MAP", LocalAddress: "192.0.2.3", PeerAddress: "192.0.2.4", Port: 4500, NATTraversal: true, Mode: "tunnel", IKEVersion: "IKEv1", CipherSuite: "AES-256-CBC", KeySize: 256, HashAlg: "MD5"},
					{Interface: "COLO", Name: "COLO-MAP", Port: 500, Mode: "tunnel", IKEVersion: "IKEv1", CipherSuite: "AES-256-CBC", KeySize: 256, HashAlg: "MD5"},
				})
			},
		},
	}
}

func TestRealCorpus(t *testing.T) {
	for _, tc := range realCorpusCases() {
		tc := tc
		name := tc.osFamily + "/" + tc.file
		t.Run(name, func(t *testing.T) {
			output := readRealFixture(t, tc.osFamily, tc.file)
			if tc.parse == nil {
				// No collector parses this command yet; the fixture is kept
				// for a future coverage slice. Nothing to call — just prove
				// the file is real, non-empty content (readRealFixture
				// already did) and record why.
				if tc.knownGap == "" {
					t.Fatal("table row has nil parse and no knownGap explaining why — every row must explain itself")
				}
				t.Skipf("no parser for %q yet (%s)", tc.command, tc.knownGap)
				return
			}
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC parsing real %s output from %s (command %q): %v", tc.osFamily, tc.file, tc.command, r)
				}
			}()
			tc.parse(t, output)
		})
	}
}

// TestRealCorpus_NoOrphanFixtures fails if a *.txt file exists under
// testdata/real/cisco/ that isn't wired into realCorpusCases(), or if a case
// names a file that doesn't exist on disk. Either drift means the corpus and
// the test have stopped agreeing about what is actually exercised.
func TestRealCorpus_NoOrphanFixtures(t *testing.T) {
	wired := map[string]bool{}
	for _, tc := range realCorpusCases() {
		key := tc.osFamily + "/" + tc.file
		if wired[key] {
			t.Errorf("duplicate table row for %s", key)
		}
		wired[key] = true
		if _, err := os.Stat(realFixturePath(tc.osFamily, tc.file)); err != nil {
			t.Errorf("table row %s: %v", key, err)
		}
	}

	root := filepath.Join("testdata", "real", "cisco")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".txt") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		// rel is "<osFamily>/<file>" since fixtures are one level deep.
		if !wired[filepath.ToSlash(rel)] {
			t.Errorf("fixture %s exists but is not wired into realCorpusCases()", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
}

// A knownGap on a row that runs a parser is how a wrong result gets asserted as
// expected: the row documents the defect and the test pins it in place. W3.2
// removed every such row; this keeps the corpus from growing them back.
func TestRealCorpus_EveryParsedRowAssertsCorrectBehaviour(t *testing.T) {
	for _, tc := range realCorpusCases() {
		if tc.parse != nil && tc.knownGap != "" {
			t.Errorf("%s/%s runs a parser AND carries a knownGap — assert the correct result instead of documenting the wrong one", tc.osFamily, tc.file)
		}
	}
}

// assertCiscoSAs compares parsed VPN rows with the expected ones on the fields
// that describe the tunnel. Metadata is checked by the callers that care.
func assertCiscoSAs(t *testing.T, got, want []ciscoCryptoConfig) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("parsed %d SAs, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		g, w := got[i], want[i]
		type view struct {
			Interface, Name, LocalAddress, PeerAddress string
			Port                                       int
			NATTraversal                               bool
			Mode, IKEVersion, CipherSuite              string
			KeySize                                    int
			HashAlg                                    string
		}
		gv := view{g.Interface, g.Name, g.LocalAddress, g.PeerAddress, g.Port, g.NATTraversal, g.Mode, g.IKEVersion, g.CipherSuite, g.KeySize, g.HashAlg}
		wv := view{w.Interface, w.Name, w.LocalAddress, w.PeerAddress, w.Port, w.NATTraversal, w.Mode, w.IKEVersion, w.CipherSuite, w.KeySize, w.HashAlg}
		if gv != wv {
			t.Errorf("SA %d:\n got  %+v\n want %+v", i, gv, wv)
		}
	}
}

// assertCiscoEntry checks the named keys of a parsed table row.
func assertCiscoEntry(t *testing.T, what string, got map[string]interface{}, want map[string]interface{}) {
	t.Helper()
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s: %s = %v, want %v (row %v)", what, key, got[key], value, got)
		}
	}
}
