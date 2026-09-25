package deviceinterrogation

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

// Unit tests for the platform fixes whose real-corpus row exercises two
// mechanisms at once, so each mechanism is pinned on its own.

// "QSFP56-DD" is a port form factor, not a transceiver entry: subcomponent
// words are matched as words.
func TestCiscoLooksLikeSubcomponent_WordsNotSubstrings(t *testing.T) {
	for _, tc := range []struct {
		entry ciscoChassis
		want  bool
	}{
		{ciscoChassis{Name: "1", Description: "Cisco 8200 2RU 32x400G QSFP56-DD w/IOS XR"}, false},
		{ciscoChassis{Name: "1", Description: "Catalyst 9300 48x SFP28 10G"}, false},
		{ciscoChassis{Name: "Te1/1/1", Description: "SFP-10GBase-SR"}, true},
		{ciscoChassis{Name: "Gi0/1", Description: "1000BaseSX SFP"}, true},
		{ciscoChassis{Name: "PS 1", Description: "Power Supply 715W"}, true},
		{ciscoChassis{Name: "0/FT0", Description: "Fan tray"}, true},
		{ciscoChassis{Name: "0/1", Description: "Linecard 36x100G"}, true},
		{ciscoChassis{Name: "Slot 2", Description: "Network Modules"}, true},
	} {
		if got := ciscoLooksLikeSubcomponent(tc.entry); got != tc.want {
			t.Errorf("ciscoLooksLikeSubcomponent(%+v) = %v, want %v", tc.entry, got, tc.want)
		}
	}
}

// XR names its chassis "Rack 0" — found by name even when an entry before it
// would otherwise win the first-entry fallback.
func TestCiscoParseInventory_XRRackIsTheChassis(t *testing.T) {
	output := `NAME: "0/RP0/CPU0", DESCR: "Route Processor Card"
PID: 8800-RP           , VID: V01, SN: SN-RP

NAME: "Rack 0", DESCR: "Cisco 8800 8-slot"
PID: 8808              , VID: V01, SN: SN-RACK
`
	if got := ciscoParseInventory(output); got.PID != "8808" || got.Serial != "SN-RACK" {
		t.Errorf("ciscoParseInventory = %+v, want the Rack 0 entry", got)
	}
}

// IOS-XR can suffix its version with the image variant.
func TestCiscoSystemInfo_XRVersionVariantIsNotTheVersion(t *testing.T) {
	info, _ := (&ciscoSSHClient{}).parseSystemInfo("Cisco IOS XR Software, Version 6.1.4[Default]\nCopyright (c) 2013-2016 by Cisco Systems, Inc.\n")
	if info["version"] != "6.1.4" || info["os_name"] != "IOS-XR" {
		t.Errorf("parseSystemInfo = %v, want version 6.1.4 on IOS-XR", info)
	}
	// NX-OS keeps its parenthesised release.
	info, _ = (&ciscoSSHClient{}).parseSystemInfo("Cisco Nexus Operating System (NX-OS) Software\n  NXOS: version 9.3(10)\n")
	if info["version"] != "9.3(10)" {
		t.Errorf("NX-OS version = %v", info["version"])
	}
}

// An IPv6 management address has to be bracketed to dial.
func TestCiscoDialAddress_IPv6(t *testing.T) {
	if got := ciscoDialAddress("2001:db8::1", 22); got != "[2001:db8::1]:22" {
		t.Errorf("ciscoDialAddress = %q", got)
	}
	if got := ciscoDialAddress("192.0.2.1", 2222); got != "192.0.2.1:2222" {
		t.Errorf("ciscoDialAddress = %q", got)
	}
}

// NAT traversal stated only in the SA's settings ("UDP-Encaps"), with no port
// printed anywhere, is still UDP 4500.
func TestCiscoIPSecSA_NATTraversalWithoutAPortIs4500(t *testing.T) {
	output := `interface: GigabitEthernet0/0
    Crypto map tag: CMAP, local addr 192.0.2.1
   protected vrf: (none)
   local  ident (addr/mask/prot/port): (192.0.2.0/255.255.255.0/0/0)
   remote ident (addr/mask/prot/port): (198.51.100.0/255.255.255.0/0/0)
   current_peer 198.51.100.1
     inbound esp sas:
      spi: 0x1(1)
        transform: esp-aes esp-sha256-hmac ,
        in use settings ={Tunnel UDP-Encaps, }
   protected vrf: (none)
   local  ident (addr/mask/prot/port): (192.0.2.0/255.255.255.0/0/0)
   remote ident (addr/mask/prot/port): (203.0.113.0/255.255.255.0/0/0)
   current_peer 203.0.113.1
     inbound esp sas:
      spi: 0x2(2)
        transform: esp-gcm 256 ,
        in use settings ={Tunnel, }
   protected vrf: (none)
   local  ident (addr/mask/prot/port): (192.0.2.0/255.255.255.0/0/0)
   remote ident (addr/mask/prot/port): (198.51.100.64/255.255.255.192/0/0)
     local crypto endpt.: 192.0.2.1/4500, remote crypto endpt.: 198.51.100.77/4500
     inbound esp sas:
      spi: 0x3(3)
        transform: esp-aes 256 esp-sha-hmac ,
        in use settings ={Tunnel, }
   protected vrf: (none)
   local  ident (addr/mask/prot/port): (192.0.2.0/255.255.255.0/0/0)
   remote ident (addr/mask/prot/port): (203.0.113.64/255.255.255.192/0/0)
   current_peer 203.0.113.99 port 500
     inbound esp sas:
     outbound esp sas:
`
	assertCiscoSAs(t, (&ciscoSSHClient{}).parseIPSecSA(output), []ciscoCryptoConfig{
		{Interface: "GigabitEthernet0/0", Name: "CMAP", LocalAddress: "192.0.2.1", PeerAddress: "198.51.100.1", Port: 4500, NATTraversal: true, Mode: "tunnel", CipherSuite: "AES-128-CBC", KeySize: 128, HashAlg: "SHA256"},
		// A second flow under the same crypto map tag is its own row.
		{Interface: "GigabitEthernet0/0", Name: "CMAP", LocalAddress: "192.0.2.1", PeerAddress: "203.0.113.1", Port: 500, Mode: "tunnel", CipherSuite: "AES-256-GCM", KeySize: 256},
		// No current_peer line: the peer and the NAT-T port come from the
		// crypto endpoints.
		{Interface: "GigabitEthernet0/0", Name: "CMAP", LocalAddress: "192.0.2.1", PeerAddress: "198.51.100.77", Port: 4500, NATTraversal: true, Mode: "tunnel", CipherSuite: "AES-256-CBC", KeySize: 256, HashAlg: "SHA1"},
		// The fourth flow has no SA (no transform): a configured tunnel that
		// is not up, which the crypto map row reports — no row here.
	})
}

// scriptedStdin answers each command written to a shell with a canned reply,
// as the device would, so ciscoShell.run can be driven without a network.
type scriptedStdin struct {
	out     *ciscoShellBuffer
	replies map[string]string
}

func (s *scriptedStdin) Write(p []byte) (int, error) {
	command := strings.TrimSpace(string(p))
	if reply, ok := s.replies[command]; ok {
		go func() {
			time.Sleep(5 * time.Millisecond)
			_, _ = s.out.Write([]byte(reply))
		}()
	}
	return len(p), nil
}

func (s *scriptedStdin) Close() error { return nil }

var _ io.WriteCloser = (*scriptedStdin)(nil)

// A device that echoes what was typed at a password prompt puts the secret on
// a line of its own; that line is dropped. Nothing else is touched: masking
// every occurrence turned an enable secret of "C9300" into a chassis model of
// "[REDACTED]-48P" — corrupting the data and revealing the secret through it.
func TestCiscoShellRun_DropsOnlyEchoedSecretLines(t *testing.T) {
	out := newCiscoShellBuffer(ciscoMaxCommandBytes)
	s := &ciscoShell{
		out:     out,
		prompt:  "r1",
		secrets: []string{"C9300", "cisco"},
		stdin: &scriptedStdin{out: out, replies: map[string]string{
			"show inventory": "show inventory\r\nC9300\r\nNAME: \"Chassis\", DESCR: \"Cisco Catalyst 9300 48-port\"\r\n" +
				"PID: C9300-48P         , VID: V02  , SN: FOC2233X0AB\r\n  cisco  \r\nr1#",
		}},
	}
	text, truncated, err := s.run(context.Background(), "show inventory")
	if err != nil || truncated {
		t.Fatalf("run = %v truncated=%v", err, truncated)
	}
	for _, line := range strings.Split(text, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed == "C9300" || trimmed == "cisco" {
			t.Errorf("an echoed secret line survived: %q", text)
		}
	}
	if got := ciscoParseInventory(text); got.PID != "C9300-48P" || got.Serial != "FOC2233X0AB" {
		t.Errorf("chassis = %+v, want the PID and serial untouched by a secret that is a substring of them", got)
	}
	if strings.Contains(text, "REDACTED") || !strings.Contains(text, "Cisco Catalyst 9300") {
		t.Errorf("output was altered beyond the echoed line: %q", text)
	}
}
