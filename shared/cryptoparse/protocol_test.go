package cryptoparse

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every case below is a spelling some producer in this tree actually emits, or
// an enum value in its own canonical spelling. The point of the table is that
// the LEFT column is what the wire/vendor/collector gave us and the RIGHT column
// is the single form that reaches the database, no matter which path wrote it.
func TestNormalizeProtocol(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// --- enum values normalize to themselves (identity) ---
		{"TLS", "TLS"},
		{"SSH", "SSH"},
		{"IPSec", "IPSec"},
		{"VPN", "VPN"},
		{"Database", "Database"},
		{"API", "API"},
		{"SMB", "SMB"},
		{"Kerberos", "Kerberos"},
		{"Modbus", "Modbus"},
		{"DNP3", "DNP3"},
		{"MMS", "MMS"},
		{"ICCP", "ICCP"},
		{"IEC62351", "IEC62351"},
		{"OPC_UA", "OPC_UA"},
		{"EtherNet_IP", "EtherNet_IP"},
		{"BACnet", "BACnet"},
		{"BACnet_SC", "BACnet_SC"},
		{"HART_IP", "HART_IP"},
		{"S7", "S7"},

		// --- case variants producers emit (qa-platform, sensor, cloud paths) ---
		{"tls", "TLS"},
		{"ssh", "SSH"},
		{"MODBUS", "Modbus"},
		{"BACNET", "BACnet"},
		{"ipsec", "IPSec"},
		{"kerberos", "Kerberos"},

		// --- the separator variants that started this: these upper-case to
		// something no service_identification_rules row can match ---
		{"EtherNet/IP", "EtherNet_IP"},
		{"EtherNet_IP", "EtherNet_IP"},
		{"ETHERNET-IP", "EtherNet_IP"},
		{"ethernet ip", "EtherNet_IP"},
		{"ENIP", "EtherNet_IP"},
		{"OPC UA", "OPC_UA"},
		{"OPC-UA", "OPC_UA"},
		{"OPCUA", "OPC_UA"},
		{"opc.ua", "OPC_UA"},
		{"ModbusTCP", "Modbus"},
		{"Modbus/TCP", "Modbus"},
		{"MODBUS_TCP", "Modbus"},
		{"BACnet.SC", "BACnet_SC"},
		{"BACNET_SC", "BACnet_SC"}, // the sensor's TLS assembler ALPN path
		{"BACnet/SC", "BACnet_SC"},
		{"BACNET-SC", "BACnet_SC"},
		{"BACnet/IP", "BACnet"},
		{"HART-IP", "HART_IP"},
		{"HARTIP", "HART_IP"},
		{"DNP3.0", "DNP3"},
		{"DNP3-SAv5", "DNP3"},
		{"DNP3_SAv6", "DNP3"},
		{"S7comm", "S7"},
		{"S7-PLUS", "S7"},
		{"TASE.2", "ICCP"},
		{"TASE-2", "ICCP"},
		{"IEC61850-MMS", "MMS"},
		{"IEC-62351", "IEC62351"},
		{"IP-SEC", "IPSec"},

		// --- whitespace is trimmed ---
		{"  TLS  ", "TLS"},
		{"\tEtherNet/IP\n", "EtherNet_IP"},

		// --- UNRECOGNISED VALUES SURVIVE. Each of these is emitted somewhere in
		// the tree and is genuinely not a protocol_type value. Losing the string
		// is worse than storing it un-normalised — it is the only record the
		// observation happened. And none of them may be coerced to a default.
		{"QUIC", "QUIC"},
		{"SNMP", "SNMP"},
		{"STARTTLS", "STARTTLS"},
		{"WireGuard", "WireGuard"},
		{"OpenVPN", "OpenVPN"},
		{"PPTP", "PPTP"},
		{"L2TP/IPSec", "L2TP/IPSec"},
		{"IKEv2", "IKEv2"},
		{"IKE", "IKE"},
		{"SSL VPN", "SSL VPN"},
		// nmap names the cluster port-scanner passes through verbatim.
		{"tcp", "tcp"},
		{"udp", "udp"},
		{"ftp", "ftp"},
		// SENTINELS. "AT-REST" marks a cloud resource that is not a network
		// endpoint at all and "NONE" means a database with SSL switched off;
		// both are matched downstream by exact/EqualFold comparison, so
		// rewriting either would silently break the check that keeps a bucket
		// out of Inventory as a phantom TLS endpoint.
		{"AT-REST", "AT-REST"},
		{"NONE", "NONE"},

		// --- cross-protocol relabelling is NOT this function's job. HTTPS and
		// SSL stay as observed; mapping them onto TLS is a semantic decision made
		// later, where a row crosses into the enum-typed column.
		{"HTTPS", "HTTPS"},
		{"SSL", "SSL"},
		{"DoT", "DoT"},

		// --- empty stays empty (callers treat "" as "not observed") ---
		{"", ""},
		{"   ", ""},
	}

	for _, c := range cases {
		got := NormalizeProtocol(c.in)
		if got != c.want {
			t.Errorf("NormalizeProtocol(%q) = %q, want %q", c.in, got, c.want)
		}
		// Idempotence: normalizing an already-stored value must be a no-op, or
		// a re-ingest of the same row would produce a different string than the
		// first write did.
		if again := NormalizeProtocol(got); again != got {
			t.Errorf("NormalizeProtocol is not idempotent for %q: %q -> %q", c.in, got, again)
		}
	}
}

// enumRe pulls the protocol_type value list out of the CREATE TYPE statement.
var enumRe = regexp.MustCompile(`(?s)CREATE TYPE public\.protocol_type AS ENUM\s*\((.*?)\)`)

// TestNormalizeProtocol_MatchesSchemaEnum is what makes canonicalProtocols a
// copy rather than a second opinion. The `protocol_type` enum in
// scripts/database/schema.sql is the vocabulary; if a value is added there and
// not here, this function would pass the new protocol through un-normalised
// while the enum column happily accepts it — exactly the drift this whole change
// exists to remove.
func TestNormalizeProtocol_MatchesSchemaEnum(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "database", "schema.sql")
	body, err := os.ReadFile(path) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read %s: %v (the schema is the source of truth for protocol_type; "+
			"if it moved, update this test rather than deleting it)", path, err)
	}

	m := enumRe.FindSubmatch(body)
	if m == nil {
		t.Fatalf("no `CREATE TYPE public.protocol_type AS ENUM (...)` found in %s", path)
	}

	// Strip the SQL comment lines the enum body carries BEFORE splitting on
	// commas — a comment sits on its own line between two values, so a naive
	// comma split leaves it glued to the value that follows it.
	var stripped []string
	for _, line := range strings.Split(string(m[1]), "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		stripped = append(stripped, line)
	}

	var fromSchema []string
	for _, tok := range strings.Split(strings.Join(stripped, "\n"), ",") {
		tok = strings.Trim(strings.TrimSpace(tok), "'")
		if tok == "" {
			continue
		}
		fromSchema = append(fromSchema, tok)
	}
	if len(fromSchema) == 0 {
		t.Fatalf("parsed 0 values out of the protocol_type enum — the parser broke, "+
			"not the schema: %q", m[1])
	}

	inGo := make(map[string]bool, len(canonicalProtocols))
	for _, p := range canonicalProtocols {
		inGo[p] = true
	}
	inSchema := make(map[string]bool, len(fromSchema))
	for _, p := range fromSchema {
		inSchema[p] = true
		if !inGo[p] {
			t.Errorf("protocol_type enum has %q but cryptoparse.canonicalProtocols does not — "+
				"that protocol will be stored with whatever spelling its producer used", p)
		}
	}
	for _, p := range canonicalProtocols {
		if !inSchema[p] {
			t.Errorf("cryptoparse.canonicalProtocols has %q but the protocol_type enum does not", p)
		}
	}
}

// TestFoldProtocol pins the comparison key shared/discovery's prober registry
// depends on.
func TestFoldProtocol(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"OPC UA", "OPCUA"},
		{"OPC-UA", "OPCUA"},
		{"OPC_UA", "OPCUA"},
		{"opc.ua", "OPCUA"},
		{"EtherNet/IP", "ETHERNETIP"},
		{"  TLS ", "TLS"},
		{"", ""},
	} {
		if got := FoldProtocol(c.in); got != c.want {
			t.Errorf("FoldProtocol(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
