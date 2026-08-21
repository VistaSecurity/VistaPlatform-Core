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

		// --- QUIC and PPTP are now enum values, so they normalise to
		// themselves for a different reason than the block below: they are
		// RECOGNISED, and their canonical spelling happens to be what producers
		// already emit. Kept explicit so a future spelling change to either
		// enum value fails here rather than silently in the free-text columns.
		{"QUIC", "QUIC"},
		{"quic", "QUIC"},
		{"PPTP", "PPTP"},
		{"pptp", "PPTP"},

		// --- UNRECOGNISED VALUES SURVIVE. Each of these is emitted somewhere in
		// the tree and is genuinely not a protocol_type value. Losing the string
		// is worse than storing it un-normalised — it is the only record the
		// observation happened. And none of them may be coerced to a default.
		//
		// NOTE the division of labour, which is the whole point of this file:
		// "SSL VPN", "L2TP/IPSec" and "STARTTLS" ARE mapped onto the enum by
		// inventory-service's resolveProtocol, on the way into
		// crypto_implementations. They are not mapped HERE, because this
		// function only respells and those are cross-protocol judgements — the
		// free-text columns keep what the producer actually observed.
		{"SNMP", "SNMP"},
		{"STARTTLS", "STARTTLS"},
		{"WireGuard", "WireGuard"},
		{"OpenVPN", "OpenVPN"},
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

// protocolEnumBaseline is the value list the `protocol_type` enum shipped with,
// frozen. It is history, not configuration: every database created before an
// ALTER was ever added to schema.sql has exactly these values and no others, so
// the list can never legitimately change. Do not "update" it when adding a
// protocol — add the value to CREATE TYPE and an ALTER, which is precisely what
// TestProtocolEnum_AdditionsCarryAnAlterType checks.
var protocolEnumBaseline = []string{
	"TLS", "SSH", "IPSec", "VPN", "Database", "API", "SMB", "Kerberos",
	"Modbus", "DNP3", "MMS", "ICCP", "IEC62351", "OPC_UA",
	"EtherNet_IP", "BACnet", "BACnet_SC", "HART_IP", "S7",
}

// alterEnumRe pulls the values out of the POST-MIGRATIONS
// `ALTER TYPE public.protocol_type ADD VALUE IF NOT EXISTS '<v>'` statements.
var alterEnumRe = regexp.MustCompile(`ALTER TYPE public\.protocol_type ADD VALUE IF NOT EXISTS '([^']+)'`)

// TestProtocolEnum_AdditionsCarryAnAlterType closes a failure mode that is
// SILENT in every other check, and that was demonstrated before this test was
// written: delete the ALTER statements, apply schema.sql to a database that
// already has the type, and psql exits 0 with zero errors — because the
// CREATE TYPE is wrapped in `EXCEPTION WHEN duplicate_object THEN NULL` and so
// no-ops. The enum keeps its old values, and the failure surfaces much later
// and somewhere else, as an "invalid input value for enum protocol_type" from
// an INSERT in the ingest path on every existing install.
//
// Nothing else can see it. The schema mirror compares two copies of the same
// file; TestNormalizeProtocol_MatchesSchemaEnum reads only CREATE TYPE; a
// double-apply against a FRESH database passes, because a fresh database got
// its values from the CREATE.
//
// So: every value in CREATE TYPE beyond the frozen baseline must also have an
// ALTER, and every ALTER must name a value CREATE TYPE declares (or a fresh
// install would be missing it).
func TestProtocolEnum_AdditionsCarryAnAlterType(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "database", "schema.sql")
	body, err := os.ReadFile(path) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	m := enumRe.FindSubmatch(body)
	if m == nil {
		t.Fatalf("no `CREATE TYPE public.protocol_type AS ENUM (...)` found in %s", path)
	}
	inCreate := map[string]bool{}
	var createOrder []string
	for _, line := range strings.Split(string(m[1]), "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		for _, tok := range strings.Split(line, ",") {
			tok = strings.Trim(strings.TrimSpace(tok), "'")
			if tok == "" {
				continue
			}
			inCreate[tok] = true
			createOrder = append(createOrder, tok)
		}
	}
	if len(createOrder) == 0 {
		t.Fatalf("parsed 0 values out of the protocol_type enum — the parser broke, not the schema")
	}

	// Strip `--` comment text before matching, or the ALTER statement quoted as
	// an EXAMPLE in schema.sql's own explanatory comment is read as a real one.
	// (It was — this test failed on its own documentation the first time it ran,
	// which is at least a cheap proof that the regex is live.)
	var sqlOnly []string
	for _, line := range strings.Split(string(body), "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		sqlOnly = append(sqlOnly, line)
	}
	altered := map[string]bool{}
	for _, mm := range alterEnumRe.FindAllStringSubmatch(strings.Join(sqlOnly, "\n"), -1) {
		altered[mm[1]] = true
	}

	baseline := map[string]bool{}
	for _, p := range protocolEnumBaseline {
		baseline[p] = true
		if !inCreate[p] {
			t.Errorf("baseline value %q is no longer in CREATE TYPE — a shipped enum value cannot be "+
				"removed (Postgres has no DROP VALUE, and existing rows may hold it). If it was "+
				"genuinely renamed, that is a data migration, not an edit to this list.", p)
		}
	}

	for _, p := range createOrder {
		if baseline[p] {
			continue
		}
		if !altered[p] {
			t.Errorf("protocol_type value %q is in CREATE TYPE but has no "+
				"`ALTER TYPE public.protocol_type ADD VALUE IF NOT EXISTS '%s'` in the POST-MIGRATIONS "+
				"block. Fresh installs would get it and EVERY EXISTING INSTALL WOULD NOT — silently, "+
				"because the CREATE TYPE no-ops there and psql still exits 0. Ingest would then fail "+
				"at INSERT time with \"invalid input value for enum protocol_type\".", p, p)
		}
	}

	for p := range altered {
		if !inCreate[p] {
			t.Errorf("`ALTER TYPE ... ADD VALUE '%s'` exists but %q is not in the CREATE TYPE list — "+
				"a fresh install would never get it. Both edits are required.", p, p)
		}
	}
}
