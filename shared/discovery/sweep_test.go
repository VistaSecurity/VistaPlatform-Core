package discovery

import "testing"

func TestIsNetworkRange(t *testing.T) {
	cases := map[string]bool{
		"10.0.0.0/24":        true,
		"10.0.0.1-10.0.0.10": true,
		"10.0.0.5":           false,
		"example.com":        false,
		"host-name":          false, // hyphen but not an IP range
	}
	for in, want := range cases {
		if got := IsNetworkRange(in); got != want {
			t.Errorf("IsNetworkRange(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestExpandTargets_CIDR(t *testing.T) {
	hosts := ExpandTargets([]string{"192.0.2.0/30"})
	// /30 = .0 .1 .2 .3
	if len(hosts) != 4 {
		t.Fatalf("expected 4 hosts from /30, got %d: %v", len(hosts), hosts)
	}
	if hosts[0] != "192.0.2.0" || hosts[3] != "192.0.2.3" {
		t.Errorf("unexpected expansion: %v", hosts)
	}
}

func TestExpandTargets_Range(t *testing.T) {
	hosts := ExpandTargets([]string{"192.0.2.1-192.0.2.3"})
	if len(hosts) != 3 || hosts[0] != "192.0.2.1" || hosts[2] != "192.0.2.3" {
		t.Errorf("unexpected range expansion: %v", hosts)
	}
}

func TestExpandTargets_PlainIPAndDedup(t *testing.T) {
	hosts := ExpandTargets([]string{"192.0.2.5", "192.0.2.5"})
	if len(hosts) != 1 || hosts[0] != "192.0.2.5" {
		t.Errorf("expected single deduped host, got %v", hosts)
	}
}

func TestProtocolsForPort(t *testing.T) {
	cases := map[int]string{443: "TLS", 22: "SSH", 445: "SMB", 502: "Modbus", 4840: "OPC_UA"}
	for port, want := range cases {
		got := ProtocolsForPort(port)
		if len(got) == 0 || got[0] != want {
			t.Errorf("ProtocolsForPort(%d) = %v, want first=%q", port, got, want)
		}
	}
	// Unknown port falls back to TLS.
	if got := ProtocolsForPort(12345); len(got) != 1 || got[0] != "TLS" {
		t.Errorf("ProtocolsForPort(unknown) = %v, want [TLS]", got)
	}
}

func TestDefaultCryptoPortsNonEmpty(t *testing.T) {
	if len(DefaultCryptoPorts()) == 0 {
		t.Error("DefaultCryptoPorts() is empty")
	}
}
