package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeProtocol(t *testing.T) {
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

		// Unknown protocols still default to TLS (with warning log).
		{"Custom-Vendor-Thing", "TLS"},
		{"", "TLS"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, normalizeProtocol(tc.in))
		})
	}
}
