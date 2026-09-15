package deviceinterrogation

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
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
// The scan is the package source, not a live device, because the crypto
// commands are issued from a method that needs an SSH session and cannot be
// driven from a fixture. A CLI command has to be written down as a string
// literal somewhere, so parsing both files for literals finds every one of
// them. TestCiscoCommands_OpsSetIsWired below drives the ops half dynamically
// as well, so the static list is checked against something that actually runs.
const (
	ciscoSourceFile    = "cisco.go"
	ciscoOpsSourceFile = "cisco_ops.go"
)

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
	"show ip interface brief",
	"show lldp neighbors detail",
	"show vlan brief",
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
	found := ciscoCommandLiterals(t, ciscoSourceFile, ciscoOpsSourceFile)

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
	for _, command := range ciscoAllowedCommands {
		allowed[command] = true
	}

	literals := ciscoStringLiterals(t, ciscoSourceFile, ciscoOpsSourceFile)
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

// The ops half, driven dynamically: the static list above is only worth
// something if the commands it names are the ones that actually go out.
func TestCiscoCommands_OpsSetIsWired(t *testing.T) {
	var asked []string
	run := func(_ context.Context, command string) (string, bool, error) {
		asked = append(asked, command)
		return "", false, os.ErrNotExist
	}
	ciscoCollectOps(context.Background(), &InterrogateResult{}, run, map[string]interface{}{})

	if len(asked) == 0 {
		t.Fatal("the ops collection ran no commands at all")
	}
	for _, command := range asked {
		if !contains(ciscoAllowedCommands, command) {
			t.Errorf("the ops collection asked for %q, which is not on the allowlist", command)
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
