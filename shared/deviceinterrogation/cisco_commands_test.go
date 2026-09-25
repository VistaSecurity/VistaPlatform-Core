package deviceinterrogation

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The Cisco command set is a CLOSED LIST, and this is the guard over all of it.
//
// It used to cover `ciscoCollectOps` only — the ops commands this workstream
// added — while the eight crypto commands in cisco.go, including the one
// `show running-config` the collector is allowed to run, were guarded by
// nothing. That is the wrong half: `| include ssl cipher` is the single most
// security-load-bearing string in the package, and widening it is a one-word
// edit in a file no test was reading.
//
// The scan is the package source, not a live device. A CLI command has to be
// written down as a string literal somewhere, so parsing EVERY non-test
// cisco*.go file for literals finds every one of them — including in a file
// added later (the session layer, cisco_ssh.go, was the first; a fixed pair of
// file names would have skipped it). TestCiscoCommands_EveryPlatformIsWired
// below drives the collection dynamically for every OS family as well, so the
// static list is checked against something that actually runs.
func ciscoSourceFiles(t *testing.T) []string {
	t.Helper()
	matches, err := filepath.Glob("cisco*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	var out []string
	for _, m := range matches {
		if !strings.HasSuffix(m, "_test.go") {
			out = append(out, m)
		}
	}
	if len(out) < 4 {
		t.Fatalf("found only %v; the scan has stopped seeing the collector's source", out)
	}
	return out
}

// ciscoAllowedCommands is every CLI command this package may run, spelled out.
//
// Adding a command means editing this list, which is the point: a reviewer sees
// the command set change in the diff rather than having to notice a new
// `executeCommand` call among several hundred lines.
var ciscoAllowedCommands = []string{
	// crypto posture (cisco.go) — predates the ops workstream
	"show crypto ikev2 sa",
	"show crypto ipsec sa",
	"show crypto isakmp sa",
	"show crypto ikev1 sa detail", // ASA: IKEv1 only, with the negotiated cipher and hash
	"show crypto map",
	"show running-config | include ssl cipher",
	"show ssl",
	"show version",
	"show webvpn",
	// ops facts and topology (cisco_ops.go)
	"show cdp neighbors detail",
	"show interfaces",
	"show inventory",
	"show ip arp",
	"show arp", // IOS-XR and ASA
	"show ip interface brief",
	"show interface ip brief", // ASA
	"show lldp neighbors detail",
	"show vlan brief",
	// telnet on the management plane (cisco_ops.go). Each is filtered to the
	// lines that answer the question and none carries a secret: VTY
	// `transport input` lines, the NX-OS telnet feature's state, and the
	// ASA / IOS-XR `telnet` section (addresses, a timeout, a server count).
	"show running-config | include ^line vty|transport input",
	"show feature | include telnet",
	"show running-config telnet",
	// privilege (cisco_ssh.go): the level the account is at, IOS and ASA
	"show privilege",
	"show curpriv",
}

// ciscoAllowedSessionCommands are the non-`show` lines the session layer
// writes: raising privilege, turning the pager off, leaving. `enable`'s secret
// is written only at the password prompt enable asks for, and is not a
// command. "configure", "write", "copy", "reload" and every other mode or
// state change are absent, and TestCiscoCommands_SessionWritesOnlyTheseLines
// holds the shell to this list on the wire.
var ciscoAllowedSessionCommands = []string{
	"enable",
	"terminal length 0",
	"terminal pager 0",
	"exit",
}

// ciscoForbiddenFragments must not appear in ANY string literal in either file.
//
// `show running-config` is the exception that proves the rule: it is allowed
// only in the exact filtered form above, so the fragment check runs over
// commands that are NOT on the allowlist. The section form returns
// `crypto isakmp key <PSK>`, `enable secret`, `snmp-server community` and every
// tunnel-group password on the box.
var ciscoForbiddenFragments = []string{
	"running-config",
	"startup-config",
	"show config",
	"show tech",
	"mac address-table",
	"show ip route",
	"show snmp",
	"show crypto key",
	"more ",
	"| section",
	"dir ",
	"terminal ",
}

func TestCiscoCommands_TheWholeInterrogatorRunsAClosedList(t *testing.T) {
	found := ciscoCommandLiterals(t, ciscoSourceFiles(t)...)

	if len(found) == 0 {
		t.Fatal("the source scan found no commands at all; it has stopped testing what it claims to")
	}

	allowed := map[string]bool{}
	for _, command := range ciscoAllowedCommands {
		allowed[command] = true
	}
	for _, command := range found {
		if !allowed[command] {
			t.Errorf("the Cisco interrogator runs %q, which is not in ciscoAllowedCommands. If the command is intended, add it there — deliberately, having read what it returns on every platform.", command)
		}
	}
	for _, command := range ciscoAllowedCommands {
		if !contains(found, command) {
			t.Errorf("ciscoAllowedCommands lists %q but no call site does; the list has drifted from the code it guards", command)
		}
	}
}

// The secrets rule, applied to every string literal in both files rather than
// to the command set alone — so a fragment appended to build a wider command is
// caught too.
func TestCiscoCommands_NeverAskForAWiderRunningConfig(t *testing.T) {
	allowed := map[string]bool{}
	for _, command := range append(append([]string{}, ciscoAllowedCommands...), ciscoAllowedSessionCommands...) {
		allowed[command] = true
	}

	// The pager prompts are text the device PRINTS, matched in its output —
	// ASA's "<--- More --->" contains "more " without being the `more` command.
	for _, marker := range ciscoPagerMarkers {
		allowed[marker] = true
	}

	literals := ciscoStringLiterals(t, ciscoSourceFiles(t)...)
	if len(literals) < 20 {
		t.Fatalf("the source scan found only %d string literals; it has stopped walking the files", len(literals))
	}

	for _, literal := range literals {
		if allowed[literal] {
			continue // the one filtered running-config form, and its siblings
		}
		lower := strings.ToLower(literal)
		for _, fragment := range ciscoForbiddenFragments {
			if strings.Contains(lower, fragment) {
				t.Errorf("the Cisco interrogator holds the literal %q, which contains %q — configuration, an unbounded table, or a command that returns key material", literal, fragment)
			}
		}
	}
}

// Driven dynamically, for every OS family: the static list above is only worth
// something if the commands it names are the ones that actually go out — and
// the per-platform choices (XR's `show arp`, ASA's `show interface ip brief`
// and `show crypto ikev1 sa detail`, each OS's telnet question) are exactly the
// commands a single-platform run would never reach.
func TestCiscoCommands_EveryPlatformIsWired(t *testing.T) {
	asked := map[string]bool{}
	run := func(_ context.Context, command string) (string, bool, error) {
		asked[command] = true
		return "", false, os.ErrNotExist
	}
	for _, osName := range []string{"", "IOS", "IOS-XE", "NX-OS", "IOS-XR", "ASA"} {
		ciscoCollectOps(context.Background(), &InterrogateResult{}, run, map[string]interface{}{"os_name": osName})
		c := &ciscoSSHClient{osName: osName}
		c.getCryptoConfigs(context.Background(), &InterrogateResult{}, run)
		c.getSSLConfigs(context.Background(), &InterrogateResult{}, run)
	}
	if len(asked) == 0 {
		t.Fatal("the collection ran no commands at all")
	}
	for command := range asked {
		if !contains(ciscoAllowedCommands, command) {
			t.Errorf("the collection asked for %q, which is not on the allowlist", command)
		}
	}
	// Every allowlisted command is reached by some platform, except the
	// session layer's own (`show version` goes through runFirst and the
	// privilege queries through ensurePrivilege, both driven by the SSH tests).
	for _, command := range ciscoAllowedCommands {
		switch command {
		case "show version", "show privilege", "show curpriv":
			continue
		}
		if !asked[command] {
			t.Errorf("ciscoAllowedCommands lists %q but no platform's collection asks for it", command)
		}
	}
}

// ciscoCommandLiterals returns every string literal in the named package files
// that reads as a CLI command.
func ciscoCommandLiterals(t *testing.T, files ...string) []string {
	t.Helper()
	var out []string
	for _, literal := range ciscoStringLiterals(t, files...) {
		if strings.HasPrefix(strings.ToLower(literal), "show ") {
			out = append(out, literal)
		}
	}
	sort.Strings(out)
	return out
}

// ciscoStringLiterals parses the named files and returns every string literal
// in them, deduplicated. Comments are not literals, so the files' own prose
// about the commands they refuse to run does not trip the checks above.
func ciscoStringLiterals(t *testing.T, files ...string) []string {
	t.Helper()
	seen := map[string]bool{}
	var out []string
	for _, file := range files {
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil || seen[value] {
				return true
			}
			seen[value] = true
			out = append(out, value)
			return true
		})
	}
	return out
}
