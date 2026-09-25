package deviceinterrogation

import (
	"context"
	"errors"
	"testing"
)

// Telnet on the management plane (finding P-08, Cisco half). The collector
// reached the device over SSH, which says nothing about whether it ALSO
// accepts telnet; it used to report mgmt.plaintext=false without asking.

func TestCiscoTelnetEnabled_PerPlatform(t *testing.T) {
	for _, tc := range []struct {
		name, os, output string
		enabled, known   bool
	}{
		{"IOS: every VTY block SSH only", "IOS", "line vty 0 4\n transport input ssh\nline vty 5 15\n transport input ssh\n", false, true},
		{"IOS: telnet on one block", "IOS-XE", "line vty 0 4\n transport input ssh\nline vty 5 15\n transport input telnet ssh\n", true, true},
		{"IOS: transport input all", "IOS", "line vty 0 15\n transport input all\n", true, true},
		{"IOS: none", "IOS", "line vty 0 4\n transport input none\n", false, true},
		// A block with no transport line takes the release default, which has
		// been `all` on some releases: unknown, not "no telnet".
		{"IOS: a block with no transport line", "IOS", "line vty 0 4\n transport input ssh\nline vty 5 15\n", false, false},
		// ... unless another block already enables telnet.
		{"IOS: default block beside a telnet block", "IOS", "line vty 0 4\n transport input telnet\nline vty 5 15\n", true, true},
		// The filter also lets the console's transport line through; it comes
		// before any `line vty` and is not the VTY's.
		{"IOS: console transport before the VTY lines", "IOS", " transport input telnet\nline vty 0 4\n transport input ssh\n", false, true},
		{"unknown OS, IOS shape", "", "line vty 0 4\n transport input ssh\n", false, true},
		{"IOS: no VTY lines at all", "", "", false, false},
		{"NX-OS: feature enabled", "NX-OS", "telnet                1          enabled\n", true, true},
		{"NX-OS: feature disabled", "NX-OS", "telnet                1          disabled\n", false, true},
		{"ASA: telnet from an inside subnet", "ASA", "telnet 192.0.2.0 255.255.255.0 inside\ntelnet timeout 5\n", true, true},
		{"ASA: only the timeout", "ASA", "telnet timeout 5\n", false, true},
		{"IOS-XR: telnet server", "IOS-XR", "Wed Mar 14 12:31:28.607 UTC\ntelnet vrf default ipv4 server max-servers 10\n", true, true},
		{"IOS-XR: nothing configured, said so", "IOS-XR", "Wed Mar 14 12:31:28.607 UTC\n% No such configuration item(s)\n", false, true},

		// Refusals and silence are never "telnet off" (review of, B1).
		{"NX-OS: role refused", "NX-OS", "% Permission denied for the role\n", false, false},
		{"NX-OS: empty", "NX-OS", "", false, false},
		{"ASA: invalid input behind ERROR:", "ASA", "ERROR: % Invalid input detected at '^' marker.\n", false, false},
		{"ASA: blank line", "ASA", "\n", false, false},
		{"ASA: below 15, refused", "ASA", "ERROR: Command authorization failed\n", false, false},
		{"IOS-XR: not authorized", "IOS-XR", "% This command is not authorized\n", false, false},
		{"IOS-XR: permission denied", "IOS-XR", "% Permission denied\n", false, false},
		{"IOS-XR: empty", "IOS-XR", "", false, false},
		{"IOS: permission denied", "IOS", "% Permission denied\n", false, false},
		{"IOS: invalid input", "IOS", "                                  ^\n% Invalid input detected at '^' marker.\n", false, false},
		// A refusal line anywhere, even after an answer-shaped line, leaves it
		// unknown: the answer is not this command's.
		{"IOS: VTY lines then a refusal", "IOS", "line vty 0 4\n transport input ssh\n% Authorization failed.\n", false, false},
	} {
		enabled, known := ciscoTelnetEnabled(tc.os, tc.output)
		if enabled != tc.enabled || known != tc.known {
			t.Errorf("%s: enabled=%v known=%v, want %v/%v", tc.name, enabled, known, tc.enabled, tc.known)
		}
	}
}

// Role and task-group refusals on NX-OS and IOS-XR are permission_denied
// warnings, not empty tables.
func TestCiscoAuthorizationRefused_EveryPlatform(t *testing.T) {
	for _, out := range []string{
		"% Authorization failed.\n",
		"Command authorization failed.\n",
		"% Permission denied for the role\n",
		"Wed Mar 14 12:31:28.607 UTC\n% This command is not authorized\n",
	} {
		if !ciscoAuthorizationRefused(out) {
			t.Errorf("not recognised as a refusal: %q", out)
		}
	}
	if ciscoAuthorizationRefused("Interface  IP-Address\nGi0/1  192.0.2.1\n") {
		t.Error("ordinary output read as a refusal")
	}
}

// Wired: the collection asks each platform its own question and the answer
// becomes the mgmt.* facts — including NOT emitting mgmt.plaintext when the
// device could not answer.
func TestCiscoCollectOps_TelnetDecidesTheManagementFacts(t *testing.T) {
	vtyCommand := "show running-config | include ^line vty|transport input"
	for _, tc := range []struct {
		name          string
		output        string
		err           error
		wantProtocol  string
		wantPlaintext any // nil = no fact
	}{
		{"telnet enabled", "line vty 0 4\n transport input telnet ssh\n", nil, "telnet", true},
		{"ssh only", "line vty 0 4\n transport input ssh\n", nil, "ssh", false},
		{"default transport", "line vty 0 4\n", nil, "ssh", nil},
		{"refused to the account", "% Authorization failed.\n", nil, "ssh", nil},
		{"command error", "", errors.New("boom"), "ssh", nil},
	} {
		result := &InterrogateResult{collector: ciscoCollector}
		run := func(_ context.Context, command string) (string, bool, error) {
			if command == vtyCommand {
				return tc.output, false, tc.err
			}
			return "", false, errors.New("not implemented")
		}
		ciscoCollectOps(context.Background(), result, run, map[string]interface{}{"os_name": "IOS-XE"})
		if got := factValue(t, result, factMgmtProtocol); got != tc.wantProtocol {
			t.Errorf("%s: mgmt.protocol = %v, want %v", tc.name, got, tc.wantProtocol)
		}
		if tc.wantPlaintext == nil {
			if hasFact(result, factMgmtPlaintext) {
				t.Errorf("%s: mgmt.plaintext = %v emitted for a device that did not answer the question", tc.name, factValue(t, result, factMgmtPlaintext))
			}
		} else if got := factValue(t, result, factMgmtPlaintext); got != tc.wantPlaintext {
			t.Errorf("%s: mgmt.plaintext = %v, want %v", tc.name, got, tc.wantPlaintext)
		}
	}
}

// Each platform is asked its own command set: IOS-XR and ASA have no
// `show ip arp`, ASA spells the brief `show interface ip brief`, and each asks
// its own telnet question.
func TestCiscoCollectOps_PerPlatformCommands(t *testing.T) {
	for _, tc := range []struct {
		os                  string
		want, mustNotAskFor []string
	}{
		{"IOS-XR", []string{"show arp", "show ip interface brief", "show running-config telnet"}, []string{"show ip arp"}},
		{"ASA", []string{"show arp", "show interface ip brief", "show running-config telnet"}, []string{"show ip arp", "show ip interface brief"}},
		{"NX-OS", []string{"show ip arp", "show ip interface brief", "show feature | include telnet"}, []string{"show arp"}},
		{"IOS-XE", []string{"show ip arp", "show ip interface brief", "show running-config | include ^line vty|transport input"}, []string{"show arp"}},
	} {
		asked := map[string]bool{}
		run := func(_ context.Context, command string) (string, bool, error) {
			asked[command] = true
			return "", false, errors.New("not implemented")
		}
		ciscoCollectOps(context.Background(), &InterrogateResult{}, run, map[string]interface{}{"os_name": tc.os})
		for _, command := range tc.want {
			if !asked[command] {
				t.Errorf("%s was not asked %q; asked %v", tc.os, command, asked)
			}
		}
		for _, command := range tc.mustNotAskFor {
			if asked[command] {
				t.Errorf("%s was asked %q, which that platform does not have", tc.os, command)
			}
		}
	}
}

// The real XR `show arp` reaches net.neighbors through the wired collection.
func TestCiscoCollectOps_XRARPReachesTheNeighbourFact(t *testing.T) {
	arp := readRealFixture(t, "cisco_xr", "show_arp.txt")
	run := func(_ context.Context, command string) (string, bool, error) {
		if command == "show arp" {
			return arp, false, nil
		}
		return "", false, errors.New("not implemented")
	}
	result := &InterrogateResult{}
	ciscoCollectOps(context.Background(), result, run, map[string]interface{}{"os_name": "IOS-XR"})
	neighbors, ok := factValue(t, result, factNetNeighbors).([]map[string]interface{})
	if !ok || len(neighbors) != 24 {
		t.Fatalf("net.neighbors = %v, want the 24 XR ARP neighbours", factValue(t, result, factNetNeighbors))
	}
}
