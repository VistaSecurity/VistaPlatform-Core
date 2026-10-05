package discovery

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateJobProtocols(t *testing.T) {
	accepted := [][]string{
		nil,
		{},
		{"TLS"},
		{"SSH"},
		{"SMB"},
		{"TLS", "SSH"},
		{"tls", " Ssh ", "smb"}, // spelling variants fold the way the scanner folds them
		{"HTTPS", "SSL", "LDAPS", "SMTPS", "IMAPS", "POP3S", "FTPS"},
		{"ldaps", "Pop3s", "ftps"},
	}
	for _, in := range accepted {
		if err := ValidateJobProtocols(in); err != nil {
			t.Errorf("ValidateJobProtocols(%q) = %v, want accepted", in, err)
		}
	}

	refusedOT := []string{
		"Modbus", "MODBUS", "modbus", "Modbus/TCP", "Modbus-TCP",
		"OPC UA", "OPCUA", "OPC-UA", "opc_ua", "OPC_UA", "opc.ua",
		"EtherNet/IP", "EtherNet-IP", "ethernetip", "ENIP",
		"BACnet", "bacnet", "BACnet/IP", "BACnet_SC",
		"DNP3", "HART-IP", "HART_IP", "S7", "S7comm", "MMS", "ICCP", "IEC62351",
	}
	for _, name := range refusedOT {
		err := ValidateJobProtocols([]string{"TLS", name})
		var bad *ProtocolNotAllowedError
		if !errors.As(err, &bad) {
			t.Errorf("ValidateJobProtocols(TLS, %q) = %v, want *ProtocolNotAllowedError", name, err)
			continue
		}
		if len(bad.Rejected) != 1 || bad.Rejected[0] != name {
			t.Errorf("%q: Rejected = %q, want just the OT name (TLS is fine)", name, bad.Rejected)
		}
		if len(bad.OT) != 1 {
			t.Errorf("%q: OT = %q, want the name flagged as OT", name, bad.OT)
		}
		if !strings.Contains(err.Error(), "ot_probe_protocols") {
			t.Errorf("%q: message %q does not point at ot_probe_protocols", name, err.Error())
		}
	}

	refusedOther := []string{"", "  ", "garbage", "tcp", "udp", "unknown", "IPSec", "VPN", "Kerberos", "QUIC", "TLS;SSH", "TLSX"}
	for _, name := range refusedOther {
		err := ValidateJobProtocols([]string{name})
		var bad *ProtocolNotAllowedError
		if !errors.As(err, &bad) {
			t.Errorf("ValidateJobProtocols(%q) = %v, want refused", name, err)
			continue
		}
		if len(bad.OT) != 0 {
			t.Errorf("%q flagged as OT: %q", name, bad.OT)
		}
		if strings.Contains(err.Error(), "ot_probe_protocols") {
			t.Errorf("%q: a non-OT refusal should not talk about ot_probe_protocols: %s", name, err.Error())
		}
		for _, allowed := range JobProtocolNames() {
			if !strings.Contains(err.Error(), allowed) {
				t.Errorf("%q: message %q does not list %s", name, err.Error(), allowed)
			}
		}
	}
}

func TestValidateJobProtocols_ReportsEveryOffenderOnce(t *testing.T) {
	err := ValidateJobProtocols([]string{"TLS", "Modbus", "garbage", "Modbus", "SSH"})
	var bad *ProtocolNotAllowedError
	if !errors.As(err, &bad) {
		t.Fatalf("err = %v", err)
	}
	if got := strings.Join(bad.Rejected, ","); got != "Modbus,garbage" {
		t.Errorf("Rejected = %q, want Modbus,garbage", got)
	}
}

// The scanner's TLS-wrapped names and the allowlist are one list: a name the
// scanner treats as TLS must be requestable, and everything else requestable
// must be SSH or SMB. Without this, adding to one list silently leaves the other
// behind — the drift the shared definition exists to prevent.
func TestJobProtocolAllowlistAndTLSWrappedNamesAgree(t *testing.T) {
	for _, name := range JobProtocolNames() {
		switch name {
		case "SSH", "SMB":
			if IsTLSWrappedProtocol(name) {
				t.Errorf("%s is TLS-wrapped?", name)
			}
		default:
			if !IsTLSWrappedProtocol(name) {
				t.Errorf("%s is allowed in a job but the scanner would not probe it as TLS", name)
			}
		}
	}
	for _, name := range tlsWrappedJobProtocols {
		if !JobProtocolAllowed(name) {
			t.Errorf("%s is probed as TLS by the scanner but a job may not request it", name)
		}
	}
}

// No OT protocol may ever appear in the allowlist: it would reopen the path
// around ot_probe_protocols.
func TestJobProtocolAllowlistHoldsNoOTProtocol(t *testing.T) {
	for _, name := range JobProtocolNames() {
		if isOTProtocol(name) {
			t.Errorf("%s is an OT protocol and must not be allowed in a job's protocols", name)
		}
	}
}

// Entries are compared against the FOLDED request name, so an entry that is not
// its own fold ("Modbus", "OPC-UA") could never match — it would silently accept
// nothing while looking like it accepted something.
func TestJobProtocolAllowlistEntriesAreFolded(t *testing.T) {
	for _, list := range [][]string{jobProtocolNames, tlsWrappedJobProtocols} {
		for _, name := range list {
			if CanonicalProtocolName(name) != name {
				t.Errorf("allowlist entry %q is not its own folded form %q and would never match", name, CanonicalProtocolName(name))
			}
		}
	}
}
