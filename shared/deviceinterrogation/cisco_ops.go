package deviceinterrogation

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/classify"
)

// Cisco ops facts and observed topology (asset-inventory ADR-0004 D1 item 4).
//
// The Cisco interrogator already opens an SSH session and runs eight `show`
// commands; every one of them is about crypto, and the device is never asked
// what it IS or what it is plugged into. Seven more commands answer the ops
// set, and all seven are read-only `show` commands an operator runs daily.
//
// What is added: `show inventory` (the chassis PID and serial — the join key
// to the hardware end-of-support catalogue), `show version`'s uptime,
// `show ip interface brief` + `show interfaces`, `show vlan brief`,
// `show cdp neighbors detail`, `show lldp neighbors detail` and `show ip arp`.
// CDP and LLDP also produce `connects_to` edges with the port names on both
// ends.
//
// What is NOT added, and why:
//
//   - `show running-config` in any broader form. The collector asks for
//     `| include ssl cipher` and nothing else, because the section form returns
//     `crypto isakmp key <PSK>`, `enable secret`, `snmp-server community` and
//     every tunnel-group password on the box. That rule predates this file and
//     stands; nothing here widens it.
//   - `show ip route`. ADR-0004 D1 asks for routes "summarised as next-hop
//     count", and IOS cannot be asked for that summary — only for the whole
//     table, as unbounded free text whose shape differs across IOS, IOS-XE,
//     NX-OS and ASA. Retrieving a customer's full routing table to derive one
//     integer is the layer-1 "don't retrieve it" rule pointed the wrong way.
//     (FortiOS CAN answer it as structured JSON, so net.route_next_hop_count is
//     emitted there — see fortinet_ops.go.)
//   - `show mac address-table`. The MAC of every host on every segment is
//     endpoint discovery wearing a switch's clothing — the same decision as
//     UniFi's client list and SNMP's dot1dTpFdbTable, deferred with them.
//   - A neighbour's `Version` / `System Description` block. CDP and LLDP both
//     advertise a multi-line software banner; it is unbounded vendor free text
//     and no consumer reads it. The parsers below only ever read lines whose
//     prefix is a key they know, so the banner is ignored structurally rather
//     than stripped afterwards.
//
// Every parser is a table/keyed-line reader that ignores lines it does not
// recognise, and every one is fed both an IOS and an IOS-XE fixture, because
// the two format the same command differently often enough that a parser
// written against one silently reads nothing on the other.

// ciscoVendor is the manufacturer of every device this collector reaches.
//
// Spelled to match the sysObjectID enterprise-9 hint in classhint.go: the same
// device interrogated over SSH and walked over SNMP must not produce two
// spellings of its vendor, because hw.vendor is half the key into the hardware
// end-of-support catalogue.
const ciscoVendor = "Cisco Systems"

// ciscoMaxCommandBytes bounds one command's output.
//
// The bound is the point. `show interfaces` on a 48-port switch is ~80 KB and
// `show ip arp` on a core router is unbounded by anything we control; a
// collector that reads whatever a remote device chooses to send has handed the
// device control of its own memory. A truncated read SAYS it was truncated
// rather than passing a partial table off as a complete one.
const ciscoMaxCommandBytes = 256 * 1024

// ciscoMaxTableRows bounds the entries taken from one parsed table, matching
// the SNMP walk bound for the same reason and so the two collectors describe a
// large device the same way.
const ciscoMaxTableRows = 500

// ciscoRunner runs one CLI command, returning its (possibly truncated) output
// and whether the byte bound cut it short.
//
// It exists as a seam so the ops collection can be driven end to end from
// fixtures: the collection path a test exercises is the one production runs,
// not a re-implementation of it.
type ciscoRunner func(ctx context.Context, command string) (string, bool, error)

// ciscoManagementProtocol is what mgmt.protocol records for this collector.
// Reaching the device at all means an SSH session was established, so the
// management plane is encrypted — the opposite of the SNMP v2c case, and
// recorded with the same explicitness.
const ciscoManagementProtocol = "ssh"

// ciscoCollectOps runs the ops command set and emits the facts and edges it
// describes, returning the chassis PID so the caller can propose a class.
//
// Every step is best-effort and independent: a switch answers `show vlan
// brief` and a router does not, an ASA answers neither CDP nor LLDP, and
// losing the whole interrogation over a command the platform does not
// implement would be worse than losing one fact.
func ciscoCollectOps(ctx context.Context, result *InterrogateResult, run ciscoRunner, sysInfo map[string]interface{}) string {
	osName, _ := sysInfo["os_name"].(string)

	// --- identity ---------------------------------------------------------
	result.addFact(factHWVendor, ciscoVendor, ConfidenceDerived)

	chassis := ciscoChassis{}
	if out, ok := ciscoRun(ctx, result, run, "show inventory", "Chassis model and serial not collected"); ok {
		chassis = ciscoParseInventory(out)
	}

	model := chassis.PID
	if model == "" {
		model, _ = sysInfo["model"].(string)
	}
	if model != "" {
		result.addFact(factHWModel, model, ConfidenceReported)
	}
	serial := chassis.Serial
	if serial == "" {
		serial, _ = sysInfo["serial_number"].(string)
	}
	if serial != "" {
		result.addFact(factHWSerial, serial, ConfidenceReported)
	}

	// IOS, IOS-XE, NX-OS and ASA software are operating systems, not firmware
	// blobs: a vendor advisory names "IOS-XE 17.9.4a" and the EOL catalogue is
	// keyed on product plus version. hw.firmware_version is left for devices
	// whose firmware IS their software, which these are not — the same split
	// PAN-OS is recorded under.
	if name, ok := sysInfo["os_name"].(string); ok && name != "" {
		result.addFact(factOSName, name, ConfidenceDerived)
	}
	if version, ok := sysInfo["version"].(string); ok && version != "" {
		result.addFact(factOSVersion, version, ConfidenceReported)
	}
	if uptime, ok := sysInfo["uptime"].(string); ok {
		if seconds, ok := ciscoParseUptime(uptime); ok {
			result.addFact(factNetUptimeSeconds, seconds, ConfidenceReported)
		}
	}

	// --- interfaces -------------------------------------------------------
	var interfaces []map[string]interface{}
	if out, ok := ciscoRun(ctx, result, run, "show interfaces", "Interface state and speed not collected"); ok {
		interfaces = ciscoParseInterfaces(out)
	}
	if out, ok := ciscoRun(ctx, result, run, ciscoBriefCommand(osName), "Interface addresses not collected"); ok {
		interfaces = ciscoMergeBriefInterfaces(interfaces, ciscoParseIPInterfaceBrief(out))
	}
	if len(interfaces) > 0 {
		result.addFact(factNetInterfaces, ciscoBound(result, "show interfaces", "Interface table", interfaces), ConfidenceReported)
	}

	// --- VLANs ------------------------------------------------------------
	if out, ok := ciscoRun(ctx, result, run, "show vlan brief", "VLANs not collected"); ok {
		if vlans := ciscoParseVlanBrief(out); len(vlans) > 0 {
			result.addFact(factNetVlans, ciscoBound(result, "show vlan brief", "VLAN table", vlans), ConfidenceReported)
		}
	}

	// --- neighbours and edges --------------------------------------------
	//
	// CDP, LLDP and ARP land in ONE net.neighbors fact: asset_facts is unique
	// on (asset, key, source_ref), so emitting the key three times would have
	// the last write silently replace the first two.
	var neighbors []map[string]interface{}

	for _, discovery := range []struct {
		command string
		effect  string
		parse   func(string) ([]map[string]interface{}, []RelationshipObservation)
	}{
		{"show cdp neighbors detail", "CDP neighbours not collected", ciscoParseCDPNeighbors},
		{"show lldp neighbors detail", "LLDP neighbours not collected", ciscoParseLLDPNeighbors},
	} {
		out, ok := ciscoRun(ctx, result, run, discovery.command, discovery.effect)
		if !ok {
			continue
		}
		found, edges := discovery.parse(out)
		neighbors = append(neighbors, found...)
		for _, edge := range edges {
			result.addRelationship(edge)
		}
	}

	arpCommand := ciscoARPCommand(osName)
	if out, ok := ciscoRun(ctx, result, run, arpCommand, "ARP neighbours not collected"); ok {
		neighbors = append(neighbors, ciscoParseARP(out)...)
	}

	if len(neighbors) > 0 {
		result.addFact(factNetNeighbors, ciscoBound(result, arpCommand, "Neighbour table", neighbors), ConfidenceReported)
	}

	// --- management plane -------------------------------------------------
	//
	// The collector reached the device over SSH, but that says nothing about
	// whether the device ALSO accepts telnet, which is the plaintext
	// management finding (P-08). The device is asked, narrowly, per platform;
	// what it cannot answer stays unassessed rather than defaulting to "not
	// plaintext" — an explicit false is an answer, and this collector used to
	// give it without ever looking.
	telnetCommand := ciscoTelnetCommand(osName)
	enabled, known := false, false
	if out, ok := ciscoRun(ctx, result, run, telnetCommand, "Whether the device accepts telnet was not assessed"); ok {
		enabled, known = ciscoTelnetEnabled(osName, out)
	}
	switch {
	case known && enabled:
		result.addFact(factMgmtProtocol, ciscoTelnetProtocol, ConfidenceReported)
		result.addFact(factMgmtPlaintext, true, ConfidenceReported)
	case known:
		result.addFact(factMgmtProtocol, ciscoManagementProtocol, ConfidenceReported)
		result.addFact(factMgmtPlaintext, false, ConfidenceReported)
	default:
		result.addFact(factMgmtProtocol, ciscoManagementProtocol, ConfidenceReported)
	}

	return chassis.PID
}

// ciscoTelnetProtocol is what mgmt.protocol records when the device accepts
// telnet: the plaintext protocol it offers, beside the SSH we used.
const ciscoTelnetProtocol = "telnet"

// ciscoARPCommand is each platform's ARP table command. IOS-XR and ASA have no
// `show ip arp` — it is `show arp` on both — so asking every device the IOS
// question read no ARP table from either.
func ciscoARPCommand(osName string) string {
	switch osName {
	case "IOS-XR", "ASA":
		return "show arp"
	}
	return "show ip arp"
}

// ciscoBriefCommand is each platform's interface-address summary. ASA's word
// order differs: `show interface ip brief`.
func ciscoBriefCommand(osName string) string {
	if osName == "ASA" {
		return "show interface ip brief"
	}
	return "show ip interface brief"
}

// ciscoTelnetCommand is each platform's narrow question "is telnet enabled?".
//
// Every form is filtered to the lines that answer it. IOS keeps telnet on the
// VTY lines' `transport input`; NX-OS behind a feature, whose state
// `show feature` prints either way; ASA and IOS-XR in their own `telnet`
// configuration section, which holds addresses, a timeout and a server count
// and nothing that authenticates. The broader running-config is never read —
// see ciscoForbiddenFragments in the tests.
func ciscoTelnetCommand(osName string) string {
	switch osName {
	case "NX-OS":
		return "show feature | include telnet"
	case "ASA", "IOS-XR":
		return "show running-config telnet"
	}
	return "show running-config | include ^line vty|transport input"
}

var (
	ciscoXRTelnetServerRE  = regexp.MustCompile(`(?i)^telnet\s+(?:vrf\s+\S+\s+)?ipv[46]\s+server\b`)
	ciscoXRNoConfigRE      = regexp.MustCompile(`(?i)^%\s*No such configuration item`)
	ciscoASATelnetTimeout  = regexp.MustCompile(`(?i)^telnet\s+timeout\s+\d+`)
	ciscoInvalidInputRE    = regexp.MustCompile(`(?im)^\s*(?:ERROR:\s*)?% ?(?:invalid|incomplete|ambiguous) (?:input|command)`)
	ciscoRefusalLineStarts = []string{"%", "error:"}
)

// ciscoCLIRefusal reports whether any line of output is the CLI talking about
// the command rather than answering it: IOS/NX-OS/XR print those lines with a
// leading "%" ("% Invalid input", "% Permission denied for the role",
// "% This command is not authorized"), ASA with "ERROR: %".
func ciscoCLIRefusal(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		for _, start := range ciscoRefusalLineStarts {
			if strings.HasPrefix(lower, start) {
				return true
			}
		}
	}
	return false
}

// ciscoTelnetEnabled reads the answer to ciscoTelnetCommand. known is false
// when the output cannot settle it.
//
// Every "no" needs POSITIVE evidence that the command ran and was answered —
// an empty output is not one. A refusal ("% Permission denied for the role",
// "ERROR: % Invalid input …"), a filter that matched nothing because the
// account could not read the configuration, and output that belongs to some
// other command all look empty, and reading them as "telnet off" put an
// unfounded mgmt.plaintext=false on the device. The evidence per platform:
//
//   - IOS / IOS-XE: every `line vty` block carries an explicit `transport
//     input`. A block without one takes the release's default, which has been
//     `all` (telnet included) on some releases — unknown, unless another block
//     already enables telnet.
//   - NX-OS: `show feature` prints the telnet feature's state, enabled or
//     disabled.
//   - ASA: the telnet section always carries `telnet timeout N`; an access
//     line (`telnet <address> <mask> <nameif>`) is telnet on.
//   - IOS-XR: a `telnet … server` line is telnet on; XR's own
//     "% No such configuration item(s)" is the explicit statement that nothing
//     is configured.
func ciscoTelnetEnabled(osName, output string) (enabled, known bool) {
	lines := strings.Split(output, "\n")

	if osName == "IOS-XR" {
		noConfig := false
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			switch {
			case ciscoXRTelnetServerRE.MatchString(trimmed):
				return true, true
			case ciscoXRNoConfigRE.MatchString(trimmed):
				noConfig = true
			case strings.HasPrefix(trimmed, "%") || strings.HasPrefix(strings.ToLower(trimmed), "error:"):
				return false, false
			}
		}
		return false, noConfig
	}

	if ciscoCLIRefusal(output) {
		return false, false
	}

	switch osName {
	case "NX-OS":
		for _, line := range lines {
			fields := strings.Fields(strings.ToLower(line))
			if len(fields) >= 2 && fields[0] == "telnet" {
				state := fields[len(fields)-1]
				switch {
				case strings.HasPrefix(state, "enabled"):
					return true, true
				case strings.HasPrefix(state, "disabled"):
					return false, true
				}
			}
		}
		return false, false
	case "ASA":
		timeoutSeen := false
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if ciscoASATelnetTimeout.MatchString(trimmed) {
				timeoutSeen = true
				continue
			}
			fields := strings.Fields(strings.ToLower(trimmed))
			// "telnet <address> <mask> <nameif>" / "telnet <prefix> <nameif>".
			if len(fields) >= 3 && fields[0] == "telnet" {
				return true, true
			}
		}
		return false, timeoutSeen
	}

	blocks, explicit := 0, 0
	inVTY, blockExplicit := false, false
	closeBlock := func() {
		if inVTY && blockExplicit {
			explicit++
		}
	}
	for _, line := range lines {
		trimmed := strings.ToLower(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(trimmed, "line vty"):
			closeBlock()
			inVTY, blockExplicit = true, false
			blocks++
		case strings.HasPrefix(trimmed, "transport input") && inVTY:
			// A `transport input` before any `line vty` belongs to the
			// console or aux line, which the filter lets through too.
			blockExplicit = true
			for _, proto := range strings.Fields(trimmed)[2:] {
				if proto == "telnet" || proto == "all" {
					return true, true
				}
			}
		}
	}
	closeBlock()
	return false, blocks > 0 && explicit == blocks
}

// ciscoRun runs one command and reports on result whatever stops its output
// being complete, returning the output only when there is something to parse.
//
//   - an error from the session is a warning classified from the error;
//   - an AAA command-authorization refusal is permission_denied. IOS prints it
//     as command OUTPUT with a clean exit, so without this check the refusal
//     was parsed as an empty table and reported as "nothing configured";
//   - output cut at ciscoMaxCommandBytes, or stopped at a pager prompt, is
//     still returned (the rows we read are true) and is a truncated warning,
//     because a partial table presented as a complete one is the
//     silent-success failure this codebase keeps paying for.
//
// `% Invalid input detected` is deliberately NOT reported. It means both "this
// platform has no such command" (a switch asked for `show crypto map`) and
// "this privilege level cannot run it", and a warning on every switch for every
// crypto command would bury the ones that matter.
func ciscoRun(ctx context.Context, result *InterrogateResult, run ciscoRunner, command, effect string) (string, bool) {
	out, truncated, err := run(ctx, command)
	if err != nil {
		result.warn(command, err, effect)
		return "", false
	}
	if ciscoAuthorizationRefused(out) {
		// A fixed detail, never the output: the output is the device's text,
		// and this is persisted.
		result.warnAs(WarningPermissionDenied, command, effect, "the device refused this command to the account (command authorization)")
		return "", false
	}
	if truncated {
		result.warnAs(WarningTruncated, command,
			fmt.Sprintf("Output cut short, at the %d-byte bound or at a pager prompt; the facts derived from it are partial", ciscoMaxCommandBytes), "")
	}
	return out, true
}

// ciscoRefusalLines is how many leading lines of a command's output are checked
// for an authorization refusal. IOS prints the refusal as the whole answer, so
// it is always within the first lines; looking further would let a matching
// string deep inside legitimate output (a banner, a description) throw the
// whole table away.
const ciscoRefusalLines = 3

// ciscoAuthorizationRefused reports whether the device refused the command to
// this account. Only the first ciscoRefusalLines lines are read, each on its
// own.
// ciscoAuthorizationRefusals are the lines a device prints INSTEAD of a
// command's output when the account may not run it: IOS AAA command
// authorization, NX-OS role-based access ("% Permission denied for the role"),
// and IOS-XR task-group authorization ("% This command is not authorized").
var ciscoAuthorizationRefusals = []string{
	"% authorization failed",
	"command authorization failed",
	"% permission denied",
	"% this command is not authorized",
}

func ciscoAuthorizationRefused(output string) bool {
	lines := strings.SplitN(output, "\n", ciscoRefusalLines+1)
	if len(lines) > ciscoRefusalLines {
		lines = lines[:ciscoRefusalLines]
	}
	for _, line := range lines {
		lower := strings.ToLower(strings.TrimSpace(line))
		for _, refusal := range ciscoAuthorizationRefusals {
			if strings.HasPrefix(lower, refusal) {
				return true
			}
		}
	}
	return false
}

// ciscoBound caps a parsed table at ciscoMaxTableRows and records the cut on
// result, naming the command the table came from.
func ciscoBound(result *InterrogateResult, command, table string, rows []map[string]interface{}) []map[string]interface{} {
	if len(rows) <= ciscoMaxTableRows {
		return rows
	}
	result.warnTruncated(command, table, ciscoMaxTableRows)
	return rows[:ciscoMaxTableRows]
}

// ciscoChassis is the chassis row of `show inventory`.
//
// Only the chassis. The other rows are the device's power supplies, fans,
// transceivers and stack modules, and a module is a PART of an asset, not an
// asset: attributing a power supply's serial to the device would put the wrong
// serial in the CMDB join key, and emitting a subject-less fact per module
// would attribute every module's identity to the chassis at once.
type ciscoChassis struct {
	Name        string
	Description string
	PID         string
	Serial      string
}

var (
	ciscoInventoryNameRE = regexp.MustCompile(`(?i)^NAME:\s*"([^"]*)"\s*,\s*DESCR:\s*"([^"]*)"`)
	ciscoInventoryPIDRE  = regexp.MustCompile(`(?i)^PID:\s*(\S*)\s*,\s*VID:\s*(\S*)\s*,\s*SN:\s*(\S*)`)
)

// ciscoSubcomponentWords name the kinds of entry `show inventory` lists BELOW
// the chassis. They exist to stop a fan tray's serial from being reported as
// the device's when the chassis row does not say "chassis" in so many words.
//
// They are matched as WORDS. A bare substring match found "sfp" inside
// "QSFP56-DD" — the port form factor a Cisco 8200 names in its own chassis
// description — and discarded the chassis, so a real 8200 reported no model
// and no serial at all.
var ciscoSubcomponentWords = []string{
	"power supply", "psu", "fan", "transceiver", "sfp", "gbic",
	"module", "daughter", "slot", "sensor", "uplink", "adapter", "card", "linecard",
}

// ciscoSubcomponentREs are ciscoSubcomponentWords as whole-word patterns (a
// plural counts: "Fans", "Modules").
var ciscoSubcomponentREs = func() []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(ciscoSubcomponentWords))
	for _, word := range ciscoSubcomponentWords {
		out = append(out, regexp.MustCompile(`(?:^|[^a-z0-9])`+regexp.QuoteMeta(word)+`s?(?:$|[^a-z0-9])`))
	}
	return out
}()

// ciscoRackNameRE is IOS-XR's name for the chassis entry: "Rack 0".
var ciscoRackNameRE = regexp.MustCompile(`(?i)^rack\s+\d+$`)

// ciscoParseInventory returns the chassis entry of `show inventory`.
//
// The chassis is the entry whose NAME or DESCR says "chassis" — an ISR says
// NAME: "Chassis", a Catalyst 9300 stack says "Switch 1 Chassis", an ASA says
// "Chassis". Older IOS switches name the root entry after its stack position
// ("1") and say nothing about a chassis at all, so the fallback is the FIRST
// entry: `show inventory` walks the ENTITY-MIB containment tree and the root
// is always printed first.
//
// The fallback is guarded rather than taken blindly. A first entry whose name
// or description reads as a power supply, a transceiver or a module is a
// subcomponent, and reporting its serial as the device's would put the wrong
// value in the one field a CMDB joins on.
func ciscoParseInventory(output string) ciscoChassis {
	var entries []ciscoChassis
	var current *ciscoChassis

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if m := ciscoInventoryNameRE.FindStringSubmatch(trimmed); m != nil {
			if current != nil {
				entries = append(entries, *current)
			}
			current = &ciscoChassis{Name: m[1], Description: m[2]}
			continue
		}
		if current == nil {
			continue
		}
		if m := ciscoInventoryPIDRE.FindStringSubmatch(trimmed); m != nil {
			current.PID = strings.TrimSpace(m[1])
			current.Serial = strings.TrimSpace(m[3])
		}
	}
	if current != nil {
		entries = append(entries, *current)
	}

	for _, entry := range entries {
		if strings.Contains(strings.ToLower(entry.Name), "chassis") ||
			strings.Contains(strings.ToLower(entry.Description), "chassis") ||
			ciscoRackNameRE.MatchString(strings.TrimSpace(entry.Name)) {
			return entry
		}
	}
	if len(entries) > 0 && !ciscoLooksLikeSubcomponent(entries[0]) {
		return entries[0]
	}
	return ciscoChassis{}
}

// ciscoLooksLikeSubcomponent reports whether an inventory entry describes a
// part of a device rather than the device.
func ciscoLooksLikeSubcomponent(entry ciscoChassis) bool {
	text := strings.ToLower(entry.Name + " " + entry.Description)
	for _, word := range ciscoSubcomponentREs {
		if word.MatchString(text) {
			return true
		}
	}
	return false
}

// ciscoUptimeUnitRE matches the "<n> <unit>" pairs an uptime string is made of,
// in either the IOS form ("2 years, 30 weeks, 4 days, 5 hours, 12 minutes") or
// the ASA form ("5 days 4 hours"), which differ only in punctuation.
var ciscoUptimeUnitRE = regexp.MustCompile(`(?i)(\d+)\s*(year|week|day|hour|minute|second)s?`)

var ciscoUptimeUnitSeconds = map[string]int{
	"year":   365 * 86400,
	"week":   7 * 86400,
	"day":    86400,
	"hour":   3600,
	"minute": 60,
	"second": 1,
}

// ciscoParseUptime converts an IOS or ASA uptime string into seconds.
//
// Reported as a bool rather than a zero, because an uptime we could not read is
// not a device that booted this instant — and net.uptime_seconds is read as a
// patching signal, so a fabricated zero says the opposite of the truth.
func ciscoParseUptime(uptime string) (int, bool) {
	matches := ciscoUptimeUnitRE.FindAllStringSubmatch(uptime, -1)
	if len(matches) == 0 {
		return 0, false
	}
	total := 0
	for _, m := range matches {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return 0, false
		}
		total += n * ciscoUptimeUnitSeconds[strings.ToLower(m[2])]
	}
	return total, true
}

var (
	ciscoInterfaceHeaderRE = regexp.MustCompile(`^(\S+) is ([^,]+), line protocol is (\S+)`)
	ciscoInterfaceMACRE    = regexp.MustCompile(`(?i)address is ([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})`)
	ciscoInterfaceAddrRE   = regexp.MustCompile(`(?i)^Internet address is (\S+)`)
	ciscoInterfaceBWRE     = regexp.MustCompile(`(?i)\bBW (\d+) Kbit`)
)

// ciscoParseInterfaces projects `show interfaces` onto net.interfaces items.
//
// `show interfaces` is the superset view — it carries the name, both states,
// the MAC, the address and the bandwidth — so it is parsed first and
// `show ip interface brief` is merged into it, rather than the other way
// round: the long name is the one an operator matches against a cable label.
func ciscoParseInterfaces(output string) []map[string]interface{} {
	var out []map[string]interface{}
	var current map[string]interface{}

	flush := func() {
		if current != nil {
			out = append(out, current)
			current = nil
		}
	}

	for _, line := range strings.Split(output, "\n") {
		if m := ciscoInterfaceHeaderRE.FindStringSubmatch(strings.TrimRight(line, "\r")); m != nil {
			flush()
			current = map[string]interface{}{
				"name":        m[1],
				"admin_state": ciscoAdminState(m[2]),
				"state":       ciscoLinkState(m[3]),
			}
			continue
		}
		if current == nil {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if _, seen := current["mac"]; !seen {
			if m := ciscoInterfaceMACRE.FindStringSubmatch(trimmed); m != nil {
				if mac, err := canonicalMAC(m[1]); err == nil {
					current["mac"] = mac
				}
			}
		}
		if m := ciscoInterfaceAddrRE.FindStringSubmatch(trimmed); m != nil {
			if addr := ciscoNormalizeCIDR(m[1]); addr != "" {
				current["addresses"] = []interface{}{addr}
			}
		}
		if _, seen := current["speed"]; !seen {
			if m := ciscoInterfaceBWRE.FindStringSubmatch(trimmed); m != nil {
				// BW is in Kbit/s; net.interfaces speed is Mbit/s. A sub-megabit
				// link (a 64 Kbit serial) rounds to 0, which the schema reads as
				// "unknown" — so it is left out rather than reported as zero.
				if kbit, err := strconv.Atoi(m[1]); err == nil && kbit >= 1000 {
					current["speed"] = kbit / 1000
				}
			}
		}
	}
	flush()
	return out
}

// ciscoAdminState reads the administrative half of "X is <state>, line protocol
// is <state>". Only "administratively down" is an administrative down; "down"
// there is a link that failed with the interface still configured up.
func ciscoAdminState(state string) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(state)), "administratively") {
		return "down"
	}
	return "up"
}

// ciscoLinkState maps a line-protocol state onto the fact vocabulary. Anything
// unrecognised is "unknown" rather than "down": a state we cannot read is not
// an interface that is off.
func ciscoLinkState(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "up":
		return "up"
	case "down":
		return "down"
	default:
		return "unknown"
	}
}

// ciscoParseIPInterfaceBrief projects `show ip interface brief` onto
// net.interfaces items.
//
// The Status column holds "administratively down" — two words — so the row is
// read from both ends: the first four columns are fixed, the LAST is Protocol,
// and whatever lies between them is Status however many words it runs to.
//
// NX-OS prints a THIRD shape from the same command — three columns, with both
// states folded into one "protocol-up/link-up/admin-up" triple — and it is
// handled here rather than under its own command. `show interfaces` on a Nexus
// is a different shape again (it says "Ethernet1/1 is up" with no ", line
// protocol is", which ciscoParseInterfaces reads nothing out of), so on NX-OS
// the brief form is the ONLY source of net.interfaces. That means the Nexus
// interface list is its LAYER-3 interfaces, which is what this command reports;
// the full port table would need a fourth command and is not collected.
//
// Every row is validated on its ADDRESS column. IOS puts an address or the word
// "unassigned" there and nothing else, so a line that has neither is not a row
// — which is what keeps NX-OS's `IP Interface Status for VRF "default"(1)`
// banner out of the inventory. That banner is exactly six whitespace-separated
// fields, so the old length check admitted it and invented an interface called
// "IP" on every Nexus.
func ciscoParseIPInterfaceBrief(output string) []map[string]interface{} {
	var out []map[string]interface{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if strings.EqualFold(fields[0], "Interface") {
			continue // header row
		}
		name := fields[0]
		address := fields[1]
		addr := ciscoNormalizeCIDR(address)
		if addr == "" && !ciscoUnassignedAddress(address) {
			continue // not a row: a banner, a VRF header, a column heading
		}

		var adminState, linkState string
		switch {
		case len(fields) >= 6:
			// IOS / IOS-XE: Interface, IP-Address, OK?, Method, Status…, Protocol
			adminState = ciscoAdminState(strings.Join(fields[4:len(fields)-1], " "))
			linkState = ciscoLinkState(fields[len(fields)-1])
		case len(fields) == 5 && ciscoIsXRStatus(fields[2]) && ciscoLinkState(fields[3]) != "unknown":
			// IOS-XR: Interface, IP-Address, Status, Protocol, Vrf-Name.
			// Status is the interface's own state, "Shutdown" being the
			// administrative down.
			adminState = "up"
			if strings.EqualFold(fields[2], "shutdown") {
				adminState = "down"
			}
			linkState = ciscoLinkState(fields[3])
		case ciscoIsNXOSStatusTriple(fields[2]):
			adminState, linkState = ciscoNXOSInterfaceStates(fields[2])
		default:
			continue
		}

		entry := map[string]interface{}{
			"name":        name,
			"admin_state": adminState,
			"state":       linkState,
		}
		// "unassigned" is IOS for "no address", and recording it as one would
		// put a word where an address belongs.
		if addr != "" {
			entry["addresses"] = []interface{}{addr}
		}
		out = append(out, entry)
	}
	return out
}

// ciscoIsXRStatus reports whether a column is an IOS-XR brief Status value.
func ciscoIsXRStatus(v string) bool {
	switch strings.ToLower(v) {
	case "up", "down", "shutdown":
		return true
	}
	return false
}

// ciscoUnassignedAddress reports whether the address column says "no address"
// rather than holding one.
func ciscoUnassignedAddress(v string) bool {
	s := strings.TrimSpace(v)
	return strings.EqualFold(s, "unassigned") || strings.EqualFold(s, "N/A")
}

// ciscoIsNXOSStatusTriple reports whether a column is NX-OS's combined state,
// "protocol-up/link-up/admin-up".
func ciscoIsNXOSStatusTriple(v string) bool {
	lower := strings.ToLower(v)
	return strings.Contains(lower, "admin-") && strings.Contains(lower, "/")
}

// ciscoNXOSInterfaceStates splits NX-OS's combined state into the two states
// the fact vocabulary keeps apart.
//
// `admin-*` is the administrative half — someone typed `shutdown` — and
// `protocol-*` is the operational one, which is the same split IOS expresses as
// two separate columns. `link-*` is the physical layer below the protocol; the
// protocol state is taken because it is what IOS's Protocol column means, and
// one fact key must not mean two things depending on which platform wrote it.
func ciscoNXOSInterfaceStates(triple string) (adminState, linkState string) {
	adminState, linkState = "unknown", "unknown"
	for _, part := range strings.Split(strings.ToLower(triple), "/") {
		switch {
		case strings.HasPrefix(part, "admin-"):
			adminState = ciscoLinkState(strings.TrimPrefix(part, "admin-"))
		case strings.HasPrefix(part, "protocol-"):
			linkState = ciscoLinkState(strings.TrimPrefix(part, "protocol-"))
		}
	}
	return adminState, linkState
}

// ciscoMergeBriefInterfaces folds the brief view into the detailed one.
//
// The two commands name the same interface differently — `show interfaces`
// prints "GigabitEthernet1/0/1" and some platforms' brief output prints
// "Gi1/0/1" — so they are matched on Cisco's own abbreviation rule: the
// alphabetic head of one is a prefix of the other's and the numeric tail is
// identical. Matching on the literal string instead is how one interface
// becomes two rows in the inventory.
func ciscoMergeBriefInterfaces(detailed, brief []map[string]interface{}) []map[string]interface{} {
	out := detailed
	for _, entry := range brief {
		name, _ := entry["name"].(string)
		head, tail := ciscoInterfaceKey(name)
		matched := false
		for i, existing := range out {
			existingName, _ := existing["name"].(string)
			eHead, eTail := ciscoInterfaceKey(existingName)
			if eTail != tail || (!strings.HasPrefix(eHead, head) && !strings.HasPrefix(head, eHead)) {
				continue
			}
			// The detailed view wins on every field it states; the brief view
			// only fills gaps. Both describe the same interface, and the
			// detailed one measured more of it.
			for key, value := range entry {
				if key == "name" {
					continue
				}
				if _, present := out[i][key]; !present {
					out[i][key] = value
				}
			}
			// Keep the longer of the two names — the unabbreviated one.
			if len(existingName) < len(name) {
				out[i]["name"] = name
			}
			matched = true
			break
		}
		if !matched {
			out = append(out, entry)
		}
	}
	return out
}

// ciscoInterfaceKey splits an interface name into its lower-cased alphabetic
// head and the rest ("GigabitEthernet1/0/1" → "gigabitethernet", "1/0/1").
func ciscoInterfaceKey(name string) (head, tail string) {
	lower := strings.ToLower(strings.TrimSpace(name))
	for i, r := range lower {
		if r >= '0' && r <= '9' {
			return lower[:i], lower[i:]
		}
	}
	return lower, ""
}

// ciscoNormalizeCIDR canonicalises an address, returning "" for IOS's
// "unassigned" and anything else that is not an address.
func ciscoNormalizeCIDR(v string) string {
	s := strings.TrimSpace(v)
	if s == "" || strings.EqualFold(s, "unassigned") || strings.EqualFold(s, "N/A") {
		return ""
	}
	return panNormalizeCIDR(s)
}

var ciscoVlanRowRE = regexp.MustCompile(`^(\d+)\s+(\S+)\s+(\S+)`)

// ciscoParseVlanBrief projects `show vlan brief` onto net.vlans items.
//
// Only active VLANs, and never 1002–1005: those four are the FDDI and
// token-ring defaults every IOS switch ships with and nobody configured, so
// reporting them as segments would put four phantom networks on every switch's
// page. A suspended VLAN is excluded for the reason a disabled UniFi network
// is — it is configured but carries nothing, and a segment nobody can be on is
// a phantom too.
//
// `show vlan brief` wraps its Ports column onto indented continuation lines;
// those do not start with a VLAN id, so the row regex ignores them.
func ciscoParseVlanBrief(output string) []map[string]interface{} {
	var out []map[string]interface{}
	for _, line := range strings.Split(output, "\n") {
		m := ciscoVlanRowRE.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		id, err := strconv.Atoi(m[1])
		if err != nil || id <= 0 || id > 4094 {
			continue
		}
		if id >= 1002 && id <= 1005 {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(m[3]), "act") {
			continue
		}
		out = append(out, map[string]interface{}{"id": id, "name": m[2]})
	}
	return out
}

var (
	ciscoCDPDeviceRE    = regexp.MustCompile(`(?i)^Device ID:\s*(.+)$`)
	ciscoCDPAddressRE   = regexp.MustCompile(`(?i)^IP(?:v4)? address:\s*(\S+)`)
	ciscoCDPPlatformRE  = regexp.MustCompile(`(?i)^Platform:\s*([^,]+),\s*Capabilities:\s*(.*)$`)
	ciscoCDPInterfaceRE = regexp.MustCompile(`(?i)^Interface:\s*([^,]+),\s*Port ID \(outgoing port\):\s*(.+)$`)
	// IOS-XR prints the two halves of that line on two lines.
	ciscoCDPLocalOnlyRE  = regexp.MustCompile(`(?i)^Interface:\s*([^,\s]+)\s*$`)
	ciscoCDPRemoteOnlyRE = regexp.MustCompile(`(?i)^Port ID \(outgoing port\):\s*(.+)$`)
	// The `Version :` block's FIRST line, and only when it is on the same line
	// as the key. IOS prints the version on the line AFTER `Version :`, so this
	// matches the one-line form some implementations use; the multi-line form
	// is handled by taking the line that follows. Either way what is kept is
	// one bounded line — see boundedAdvertisement.
	ciscoCDPVersionRE = regexp.MustCompile(`(?i)^Version\s*:\s*(.*)$`)
)

// ciscoParseCDPNeighbors projects `show cdp neighbors detail` onto
// net.neighbors items and the connects_to edges built from them.
//
// The `Version :` block that follows each entry is a multi-line software
// banner. It is not skipped — it is never looked at: only lines whose prefix
// matches one of the four keys above are read, so a banner line is ignored by
// the same rule that ignores every other line the parser does not know.
func ciscoParseCDPNeighbors(output string) ([]map[string]interface{}, []RelationshipObservation) {
	var neighbors []map[string]interface{}
	var edges []RelationshipObservation

	for _, record := range ciscoSplitRecords(output, "Device ID:") {
		var deviceID, address, platform, capabilities, local, remote, version string
		// The `Version :` key and its value are usually on consecutive lines.
		// `wantVersion` carries the key across to the next iteration; nothing
		// else in the record is read positionally, which is what keeps the rest
		// of the banner ignored by the same rule that ignores every other line.
		wantVersion := false
		for _, line := range strings.Split(record, "\n") {
			trimmed := strings.TrimSpace(line)
			if wantVersion {
				wantVersion = false
				if version == "" && trimmed != "" {
					version = advertisedVersion(trimmed)
					continue
				}
			}
			switch {
			case deviceID == "" && ciscoCDPDeviceRE.MatchString(trimmed):
				deviceID = ciscoAdvertised(ciscoCDPDeviceRE.FindStringSubmatch(trimmed)[1])
			case address == "" && ciscoCDPAddressRE.MatchString(trimmed):
				address = ciscoAdvertised(ciscoCDPAddressRE.FindStringSubmatch(trimmed)[1])
			case platform == "" && ciscoCDPPlatformRE.MatchString(trimmed):
				m := ciscoCDPPlatformRE.FindStringSubmatch(trimmed)
				platform, capabilities = ciscoAdvertised(m[1]), strings.TrimSpace(m[2])
			case local == "" && ciscoCDPInterfaceRE.MatchString(trimmed):
				m := ciscoCDPInterfaceRE.FindStringSubmatch(trimmed)
				local, remote = ciscoAdvertised(m[1]), ciscoAdvertised(m[2])
			case local == "" && ciscoCDPLocalOnlyRE.MatchString(trimmed):
				local = ciscoAdvertised(ciscoCDPLocalOnlyRE.FindStringSubmatch(trimmed)[1])
			case remote == "" && ciscoCDPRemoteOnlyRE.MatchString(trimmed):
				remote = ciscoAdvertised(ciscoCDPRemoteOnlyRE.FindStringSubmatch(trimmed)[1])
			case version == "" && ciscoCDPVersionRE.MatchString(trimmed):
				raw := strings.TrimSpace(ciscoCDPVersionRE.FindStringSubmatch(trimmed)[1])
				if raw != "" {
					version = advertisedVersion(raw)
				} else {
					wantVersion = true
				}
			}
		}
		if deviceID == "" {
			continue
		}

		// CDP's Device ID is a hostname on IOS and the chassis MAC on some
		// third-party implementations; both are identities, and canonicalMAC is
		// the arbiter rather than a guess here.
		entry := map[string]interface{}{"protocol": "cdp", "remote_name": deviceID}
		if mac, err := canonicalMAC(deviceID); err == nil {
			entry["remote_mac"] = mac
		}
		if addr, err := canonicalIP(address); err == nil {
			entry["remote_address"] = addr
		}
		if remote != "" {
			entry["remote_port"] = remote
		}
		if local != "" {
			entry["local_port"] = local
		}
		neighbors = append(neighbors, entry)

		peer := peerRef(deviceID, ciscoPeerClassHint(platform, capabilities))
		// The posture the neighbour advertised, carried rather than consumed
		// and dropped. The class hint above is this service's answer; these are
		// the EVIDENCE, which is what the ingest side needs to reach its own —
		// a peer's class used to be argued from its MAC prefix alone.
		peer.Platform = advertisedProduct(platform)
		peer.SoftwareVersion = version
		peer.CDPCapabilities = ciscoCDPCapabilityNames(capabilities)
		peer.AddIdentifier(IdentifierMACAddress, deviceID)
		peer.AddIdentifier(IdentifierIPAddress, address)
		addHostIdentifiers(&peer, deviceID)
		if len(peer.Identifiers) == 0 {
			continue
		}
		edges = append(edges, ciscoNeighborEdge(peer, "cdp", local, remote, ""))
	}
	return neighbors, edges
}

var (
	// "Local Intf:" (IOS), "Local Port id:" (NX-OS), "Local Interface:" (IOS-XR).
	ciscoLLDPLocalRE    = regexp.MustCompile(`(?i)^(?:Local Intf|Local Port id|Local Interface):\s*(\S+)`)
	ciscoLLDPChassisRE  = regexp.MustCompile(`(?i)^Chassis id:\s*(.+)$`)
	ciscoLLDPPortRE     = regexp.MustCompile(`(?i)^Port id:\s*(.+)$`)
	ciscoLLDPPortDescRE = regexp.MustCompile(`(?i)^Port Description:\s*(.+)$`)
	ciscoLLDPSysNameRE  = regexp.MustCompile(`(?i)^System Name:\s*(.+)$`)
	// "IP:" (IOS), "Management Address:" (NX-OS), "IPv4 address:" under
	// "Management Addresses:" (IOS-XR).
	ciscoLLDPMgmtIPRE = regexp.MustCompile(`(?i)^(?:IP|Management Address|IPv4 address):\s*(\S+)`)
	// `System Description:` is a multi-line banner and its value is on the
	// FOLLOWING line in IOS's rendering, like CDP's `Version :`.
	ciscoLLDPSysDescRE = regexp.MustCompile(`(?i)^System Description:\s*(.*)$`)
	// `Enabled Capabilities:` is what the neighbour is ACTUALLY doing;
	// `System Capabilities:` is what it is able to do. The enabled line is the
	// one a classification should read — a switch with routing compiled in but
	// not configured is a switch — so the enabled line wins when both appear.
	ciscoLLDPSysCapRE     = regexp.MustCompile(`(?i)^System Capabilities:\s*(.*)$`)
	ciscoLLDPEnabledCapRE = regexp.MustCompile(`(?i)^Enabled Capabilities:\s*(.*)$`)
)

// ciscoParseLLDPNeighbors projects `show lldp neighbors detail` onto
// net.neighbors items and connects_to edges.
//
// `System Description:` is the same unbounded banner CDP's `Version :` is, and
// is ignored by the same rule. `Chassis id` is a MAC on most implementations
// and a management address on some, so both are tried and whichever parses is
// kept — neither is assumed.
func ciscoParseLLDPNeighbors(output string) ([]map[string]interface{}, []RelationshipObservation) {
	var neighbors []map[string]interface{}
	var edges []RelationshipObservation

	for _, record := range ciscoSplitRecords(output, "Chassis id:") {
		var local, chassis, port, portDesc, sysName, mgmtIP, sysDesc, sysCaps, enabledCaps string
		wantSysDesc := false
		for _, line := range strings.Split(record, "\n") {
			trimmed := strings.TrimSpace(line)
			if wantSysDesc {
				wantSysDesc = false
				// Only a line that is not itself a key: an empty
				// `System Description:` followed immediately by
				// `Time remaining:` means the neighbour advertised none.
				if sysDesc == "" && trimmed != "" && !strings.Contains(trimmed, ":") {
					sysDesc = trimmed
					continue
				}
			}
			switch {
			case sysDesc == "" && ciscoLLDPSysDescRE.MatchString(trimmed):
				raw := strings.TrimSpace(ciscoLLDPSysDescRE.FindStringSubmatch(trimmed)[1])
				if raw != "" {
					sysDesc = raw
				} else {
					wantSysDesc = true
				}
			case enabledCaps == "" && ciscoLLDPEnabledCapRE.MatchString(trimmed):
				enabledCaps = strings.TrimSpace(ciscoLLDPEnabledCapRE.FindStringSubmatch(trimmed)[1])
			case sysCaps == "" && ciscoLLDPSysCapRE.MatchString(trimmed):
				sysCaps = strings.TrimSpace(ciscoLLDPSysCapRE.FindStringSubmatch(trimmed)[1])
			case local == "" && ciscoLLDPLocalRE.MatchString(trimmed):
				local = ciscoAdvertised(ciscoLLDPLocalRE.FindStringSubmatch(trimmed)[1])
			case chassis == "" && ciscoLLDPChassisRE.MatchString(trimmed):
				chassis = ciscoAdvertised(ciscoLLDPChassisRE.FindStringSubmatch(trimmed)[1])
			case portDesc == "" && ciscoLLDPPortDescRE.MatchString(trimmed):
				portDesc = ciscoAdvertised(ciscoLLDPPortDescRE.FindStringSubmatch(trimmed)[1])
			case port == "" && ciscoLLDPPortRE.MatchString(trimmed):
				port = ciscoAdvertised(ciscoLLDPPortRE.FindStringSubmatch(trimmed)[1])
			case sysName == "" && ciscoLLDPSysNameRE.MatchString(trimmed):
				sysName = ciscoAdvertised(ciscoLLDPSysNameRE.FindStringSubmatch(trimmed)[1])
			case mgmtIP == "" && ciscoLLDPMgmtIPRE.MatchString(trimmed):
				mgmtIP = ciscoAdvertised(ciscoLLDPMgmtIPRE.FindStringSubmatch(trimmed)[1])
			}
		}

		entry := map[string]interface{}{"protocol": "lldp"}
		if mac, err := canonicalMAC(chassis); err == nil {
			entry["remote_mac"] = mac
		}
		if sysName != "" {
			entry["remote_name"] = sysName
		}
		if port != "" {
			entry["remote_port"] = port
		}
		if local != "" {
			entry["local_port"] = local
		}
		// A chassis id that is an address rather than a MAC is still the
		// neighbour's address; the management address wins when both are given.
		if addr, err := canonicalIP(mgmtIP); err == nil {
			entry["remote_address"] = addr
		} else if addr, err := canonicalIP(chassis); err == nil {
			entry["remote_address"] = addr
		}
		// A neighbour with neither a MAC nor a name is a port with something on
		// it — true, but not a neighbour anything can be said about.
		if entry["remote_mac"] == nil && entry["remote_name"] == nil {
			continue
		}
		neighbors = append(neighbors, entry)

		peer := peerRef(sysName, "")
		// The leading product segment only. A system description is free text;
		// what classifies is the product at the front of it, and what follows
		// is build metadata and configured values.
		peer.Platform = advertisedProduct(sysDesc)
		peer.SoftwareVersion = advertisedVersion(sysDesc)
		if enabledCaps != "" {
			peer.LLDPCapabilities = lldpCapabilityNames(enabledCaps)
		} else {
			peer.LLDPCapabilities = lldpCapabilityNames(sysCaps)
		}
		peer.AddIdentifier(IdentifierMACAddress, chassis)
		peer.AddIdentifier(IdentifierIPAddress, mgmtIP)
		peer.AddIdentifier(IdentifierIPAddress, chassis)
		addHostIdentifiers(&peer, sysName)
		if len(peer.Identifiers) == 0 {
			continue
		}
		edges = append(edges, ciscoNeighborEdge(peer, "lldp", local, port, portDesc))
	}
	return neighbors, edges
}

// ciscoPlaceholders are the strings LLDP and CDP print where a neighbour
// advertised nothing. They are placeholders, not values: storing
// "not advertised" as a system name puts a sentence where an identity belongs,
// and two neighbours that both advertise nothing would read as the same device.
var ciscoPlaceholders = []string{"not advertised", "unknown", "n/a", "-", "none"}

// ciscoAdvertised returns the value, or "" when the device printed a
// placeholder instead of one.
func ciscoAdvertised(v string) string {
	s := strings.TrimSpace(v)
	for _, placeholder := range ciscoPlaceholders {
		if strings.EqualFold(s, placeholder) {
			return ""
		}
	}
	return s
}

// ciscoNeighborEdge builds one connects_to edge with the port names on both
// ends, which is the type-specific detail ADR-0003 D2 names for this type.
func ciscoNeighborEdge(peer PeerRef, protocol, local, remote, remoteDescription string) RelationshipObservation {
	attributes := map[string]interface{}{"discovery_protocol": protocol}
	if local != "" {
		attributes["local_port"] = local
	}
	if remote != "" {
		attributes["remote_port"] = remote
	}
	if remoteDescription != "" {
		attributes["remote_port_description"] = remoteDescription
	}
	return RelationshipObservation{
		Type:       relTypeConnectsTo,
		Direction:  SubjectToPeer,
		Peer:       peer,
		Attributes: attributes,
	}
}

// ciscoParseARP projects an ARP table onto net.neighbors items.
//
// Four real layouts, one per platform, and only the first had been read:
//
//   - IOS/IOS-XE `show ip arp`: `Internet <addr> <age> <mac> <type> [<iface>]`
//   - NX-OS `show ip arp`: `<addr> <age> <mac> <iface>`
//   - IOS-XR `show arp`: `<addr> <age> <mac> <state> <type> <iface>`, per line
//     card; state "Interface" is the router's OWN address, not a neighbour
//   - ASA `show arp`: `<nameif> <addr> <mac> <age>`
//
// An "Incomplete" row is an address the device asked about and got no answer
// to — not a neighbour it saw — and canonicalMAC rejects it (XR prints it with
// an all-zero MAC), which is what keeps it out.
func ciscoParseARP(output string) []map[string]interface{} {
	var out []map[string]interface{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		var addrToken, macToken, iface string
		switch {
		case strings.EqualFold(fields[0], "Internet") && len(fields) >= 4:
			addrToken, macToken = fields[1], fields[3]
			if len(fields) >= 6 {
				iface = fields[5]
			}
		case ciscoIsAddress(fields[0]):
			addrToken, macToken = fields[0], fields[2]
			switch {
			case len(fields) >= 6:
				if strings.EqualFold(fields[3], "Interface") {
					continue
				}
				iface = fields[5]
			case len(fields) >= 4:
				iface = fields[3]
			}
		case ciscoIsAddress(fields[1]):
			iface, addrToken, macToken = fields[0], fields[1], fields[2]
		default:
			continue
		}
		mac, err := canonicalMAC(macToken)
		if err != nil {
			continue
		}
		addr, err := canonicalIP(addrToken)
		if err != nil {
			continue
		}
		entry := map[string]interface{}{"protocol": "arp", "remote_mac": mac, "remote_address": addr}
		if iface = strings.TrimSpace(iface); iface != "" {
			entry["local_port"] = iface
		}
		out = append(out, entry)
	}
	return out
}

func ciscoIsAddress(v string) bool {
	_, err := canonicalIP(v)
	return err == nil
}

// ciscoSplitRecords splits a `... detail` output into one chunk per neighbour.
//
// IOS separates entries with a rule of dashes; some versions and some
// platforms print none, so the fallback splits before each occurrence of the
// key that starts a record. Both forms occur on gear a customer has, and a
// parser that handles only the one it was written against reads nothing at all
// on the other.
func ciscoSplitRecords(output, startKey string) []string {
	lines := strings.Split(output, "\n")
	var records []string
	var current []string
	separated := false

	flush := func() {
		if len(current) > 0 {
			records = append(records, strings.Join(current, "\n"))
			current = nil
		}
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) >= 4 && strings.Trim(trimmed, "-") == "" {
			separated = true
			flush()
			continue
		}
		current = append(current, line)
	}
	flush()

	if separated {
		return records
	}

	// No separators: split before each record-start key instead.
	records = nil
	current = nil
	lowerKey := strings.ToLower(startKey)
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), lowerKey) {
			flush()
		}
		current = append(current, line)
	}
	flush()
	return records
}

// ciscoPeerClassHint proposes what a CDP neighbour is, from the platform PID it
// advertises and, failing that, from its advertised capabilities.
//
// A hint, never a decision — it reaches Approvals as a proposal (ADR-0002
// classifier seam). An unrecognised platform yields no hint at all, because a
// wrong class is worse than an absent one.
//
// Both halves are now RULES. The capability fallback used to be a switch
// statement here — `contains "switch"` then `contains "router"` — which was the
// last class hint left outside standards/classification-rules.yaml after 2.10a,
// and it was in the worst place for one: a mapping nobody could see, curate or
// cite. It is three `cdp_capabilities` rules now, and the answers are unchanged
// except for the one the review of that move deliberately re-decided: a device
// advertising BOTH bits is `network_device` rather than `switch`, because
// `switch` is right for a Catalyst doing inter-VLAN routing and wrong for an ISR
// with a switch module, and both advertise exactly those two bits.
// TestCiscoPeerClassHint_MatchesThePreRulesBehaviour is the transcription, with
// that exception named in it.
//
// Both halves go to the engine in ONE call rather than two, so the PID and the
// capabilities argue with each other through the ordinary arbitration instead of
// through a hand-written precedence. A PID rule sits at 0.85 and a capability
// rule at 0.65–0.70, well over the conflict epsilon, so a recognised PID still
// wins — but a neighbour advertising a Catalyst PID while claiming only the
// `host` capability is now a conflict somebody can see rather than a silent
// first-match-wins.
func ciscoPeerClassHint(platform, capabilities string) string {
	// "cisco WS-C3750X-48P" — the PID is what follows the vendor word.
	pid := strings.TrimSpace(platform)
	if fields := strings.Fields(pid); len(fields) > 1 && strings.EqualFold(fields[0], "cisco") {
		pid = fields[1]
	}
	return classHintEngine().Classify(context.Background(), classify.ClassifyInput{
		Vendor:          ciscoVendor,
		Model:           pid,
		CDPCapabilities: ciscoCDPCapabilityNames(capabilities),
	}).Class
}

// ciscoCDPCapabilityNames turns the capability list `show cdp neighbors detail`
// prints — "Router Switch IGMP", "Trans-Bridge Source-Route-Bridge" — into the
// names shared/hostobs' CDP decoder produces from the same bitmask, which is the
// vocabulary the `cdp_capabilities` rules are written in.
//
// One vocabulary, two producers: a live capture reads the bits, an SSH session
// reads IOS's rendering of them, and a rule has to fire for both or the same
// device classifies differently depending on how we happened to see it. Anything
// IOS prints that is not in the table is DROPPED rather than passed through
// lower-cased — an unmapped word would reach the engine as a capability name
// nothing can ever match, which reads as evidence and is not.
func ciscoCDPCapabilityNames(capabilities string) []string {
	var out []string
	for _, field := range strings.Fields(capabilities) {
		if name, ok := ciscoCDPCapabilityWords[strings.ToLower(strings.Trim(field, ","))]; ok {
			out = append(out, name)
		}
	}
	return out
}

// ciscoCDPCapabilityWords maps the capability words `show cdp neighbors detail`
// prints onto the names shared/hostobs' decoder produces from the bitmask.
//
// The full words, not the single-letter codes: the detail output spells them
// out, and the letters belong to the summary table's legend, which this parser
// never reads. Adding them "just in case" would mean a `Platform:` line
// containing a stray "R" could contribute a capability nothing observed.
var ciscoCDPCapabilityWords = map[string]string{
	"router":              "router",
	"switch":              "switch",
	"trans-bridge":        "transparent_bridge",
	"source-route-bridge": "source_route_bridge",
	"host":                "host",
	"igmp":                "igmp_capable",
	"repeater":            "repeater",
	"phone":               "voip_phone",
	"remote":              "remotely_managed",
	"cvta":                "cvta_phone",
	"two-port":            "two_port_mac_relay",
}
