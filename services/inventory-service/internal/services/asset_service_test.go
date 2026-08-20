package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveProtocol(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// IT protocols (pre-existing behavior)
		{"HTTPS", "TLS"},
		{"HTTP/2", "TLS"},
		{"TLS", "TLS"},
		{"SSL", "TLS"},
		{"ssh", "SSH"},
		{"IPSec", "IPSec"},
		{"ike", "IPSec"},
		{"IKEv2", "IPSec"},
		{"ikev2", "IPSec"},
		{"WireGuard", "VPN"},
		{"openvpn", "VPN"},
		{"SMB", "SMB"},
		{"Kerberos", "Kerberos"},
		{"db", "Database"},
		{"API", "API"},
		{"REST", "API"},

		// OT/ICS protocols — every alias must land on the canonical enum literal.
		{"Modbus", "Modbus"},
		{"MODBUS/TCP", "Modbus"},
		{"modbus_tcp", "Modbus"},
		{"modbus-tcp", "Modbus"},
		{"DNP3", "DNP3"},
		{"DNP3.0", "DNP3"},
		{"dnp3-sav5", "DNP3"},
		{"DNP3-SAv6", "DNP3"},
		{"OPC_UA", "OPC_UA"},
		{"OPC-UA", "OPC_UA"},
		{"opcua", "OPC_UA"},
		{"OPC UA", "OPC_UA"},
		{"EtherNet_IP", "EtherNet_IP"},
		{"ETHERNET-IP", "EtherNet_IP"},
		{"ethernet/ip", "EtherNet_IP"},
		{"ENIP", "EtherNet_IP"},
		{"CIP", "EtherNet_IP"},
		{"BACnet", "BACnet"},
		{"BACnet_SC", "BACnet_SC"},
		{"bacnet-sc", "BACnet_SC"},
		{"BACnet/SC", "BACnet_SC"},
		{"HART_IP", "HART_IP"},
		{"hart-ip", "HART_IP"},
		{"HARTIP", "HART_IP"},
		{"S7", "S7"},
		{"S7Comm", "S7"},
		{"S7-Plus", "S7"},
		{"s7plus", "S7"},
		{"MMS", "MMS"},
		{"IEC-61850-MMS", "MMS"},
		{"ICCP", "ICCP"},
		{"TASE.2", "ICCP"},
		{"IEC62351", "IEC62351"},
		{"iec-62351", "IEC62351"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, verdict := resolveProtocol(tc.in)
			assert.Equal(t, protocolEnum, verdict, "%q must resolve to a modelled protocol", tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestResolveProtocol_DoesNotFabricate is the negative polarity of the table
// above, and the whole point of the change: a string the enum does not model
// must come back with NO protocol, never with "TLS". Every case here used to
// return "TLS" and only log a warning, which is how a scanned-but-silent port,
// a database with SSL switched OFF, and a vendor string nobody had wired up all
// arrived in inventory as negotiated-TLS endpoints.
func TestResolveProtocol_DoesNotFabricate(t *testing.T) {
	cases := []struct {
		in   string
		want protocolVerdict
	}{
		// Transports. "The port completed a TCP handshake" is not crypto.
		{"tcp", protocolTransport},
		{"TCP", protocolTransport},
		{"udp", protocolTransport},

		// Explicitly unencrypted — the inverse of a TLS observation.
		{"NONE", protocolPlaintext},
		{"none", protocolPlaintext},
		{"HTTP", protocolPlaintext},
		{"http", protocolPlaintext},

		// Real protocols with no enum home. Named here so the list is visible
		// in code: they are a MODELLING gap, not a normalization bug, and they
		// must not be quietly filed as something they are not while it is open.
		{"QUIC", protocolUnrecognized},
		{"SNMP", protocolUnrecognized},
		{"SSL VPN", protocolUnrecognized},
		{"PPTP", protocolUnrecognized},
		{"L2TP/IPSec", protocolUnrecognized},
		{"STARTTLS", protocolUnrecognized},

		// Genuinely unknown, and empty.
		{"Custom-Vendor-Thing", protocolUnrecognized},
		{"", protocolUnrecognized},
		{"   ", protocolUnrecognized},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, verdict := resolveProtocol(tc.in)
			assert.Equal(t, tc.want, verdict)
			assert.Empty(t, got, "an unmodelled protocol must yield no enum value, got %q", got)
			assert.NotEqual(t, "TLS", got)
		})
	}
}
