package services

// Guard for the built-in port-heuristic rules (`service_identification_rules`).
//
// GetPortHeuristic is the table's only reader and nothing in the product ever
// INSERTs into it, so the built-in rows are pure seed data — and they have
// already been lost once, when a `pg_dump --schema-only` regeneration of
// schema.sql dropped the data statements that carried them. Nothing errored:
// discovery simply started labelling every passively discovered TLS asset the
// literal "TLS Service", and left service_name/version/confidence/method NULL
// on every external connection and every EnrichAllAssets backfill.
//
// An empty table is therefore the failure mode this file exists to catch, and
// "empty" is indistinguishable from "working" at every other layer. The test
// asserts the floor, a sample of the specific mappings, and — through
// GetPortHeuristic itself, over a connection as the non-owner RLS app role —
// that a tenant can actually SEE the tenant_id IS NULL built-ins.
//
// Runs against the real schema + seed via the testdb harness (nightly
// test-backend and `make test-integration-db`); skips when TEST_DATABASE_URL is
// unset, so the plain unit path stays green.

import (
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// builtinRuleFloor is deliberately a floor, not an equality: adding a rule
// should not break the build, losing the set should. The shipped set is 39
// rows; anything below this means rows went missing rather than a rule being
// retired on purpose.
const builtinRuleFloor = 38

// mustIdentify are mappings whose absence is directly visible to a user — the
// Service row of the asset drawer for the most common secure listeners on an
// enterprise or OT network.
var mustIdentify = []struct {
	port     int
	protocol string
	want     string
}{
	{443, "TLS", "HTTPS"},
	{636, "TLS", "LDAPS"},
	{993, "TLS", "IMAPS"},
	{465, "TLS", "SMTPS"},
	{990, "TLS", "FTPS (implicit)"},
	{3389, "TLS", "RDP"},
	{5432, "TLS", "PostgreSQL"},
	{6443, "TLS", "Kubernetes API"},
	{22, "SSH", "SSH"},
	{445, "SMB", "SMB"},
	{502, "MODBUS", "Modbus/TCP"},
	{4840, "OPC_UA", "OPC UA"},
	// STARTTLS on the cleartext mail ports — TLS here can only be that port's
	// own protocol upgrading.
	{25, "TLS", "SMTP (STARTTLS)"},
	{143, "TLS", "IMAP (STARTTLS)"},
	{110, "TLS", "POP3 (STARTTLS)"},
}

// mustNotIdentify pins ports we decided NOT to name. A blank Service row is the
// correct answer for an ambiguous port; the risk being guarded against is
// someone adding a plausible-sounding rule back without reading why it was left
// out (see the 9090 note in scripts/database/seed.sql).
var mustNotIdentify = []struct {
	port     int
	protocol string
	why      string
}{
	{9090, "TLS", "ambiguous between Cockpit and TLS-enabled Prometheus"},
}

func TestIntegration_ServiceIdentificationRules_BuiltinsSeeded(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	var n int
	if err := db.QueryRow(
		`SELECT count(*) FROM service_identification_rules WHERE tenant_id IS NULL`).Scan(&n); err != nil {
		t.Fatalf("count built-in rules: %v", err)
	}
	if n < builtinRuleFloor {
		t.Fatalf("service_identification_rules holds %d built-in rows, want at least %d — "+
			"the port heuristic is dead and every port-only identification silently "+
			"produces no service name", n, builtinRuleFloor)
	}

	for _, c := range mustIdentify {
		var got string
		if err := db.QueryRow(
			`SELECT service_name FROM service_identification_rules
			 WHERE port = $1 AND protocol = $2 AND tenant_id IS NULL`,
			c.port, c.protocol).Scan(&got); err != nil {
			t.Errorf("no built-in rule for %d/%s: %v", c.port, c.protocol, err)
			continue
		}
		if got != c.want {
			t.Errorf("rule %d/%s names %q, want %q", c.port, c.protocol, got, c.want)
		}
	}
}

// TestIntegration_ServiceIdentificationRules_VisibleUnderRLS runs the real
// consumer as the non-owner app role. The built-ins carry tenant_id IS NULL,
// which the canonical per-tenant policy would hide outright; they survive only
// because service_identification_rules is one of the hybrid tables whose USING
// clause admits the global rows. Under the owner connection that distinction is
// invisible, so this is the assertion that proves the feature works in
// production rather than only in a test's privileged session.
func TestIntegration_ServiceIdentificationRules_VisibleUnderRLS(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenantID := testdb.NewTenant(t, owner)

	appDB := testdb.ConnectAsAppRole(t, owner)
	svc := NewServiceIdentificationService(&database.DB{DB: sqlx.NewDb(appDB, "postgres")})

	for _, c := range mustIdentify {
		if got := svc.GetPortHeuristic(tenantID, c.port, c.protocol); got != c.want {
			t.Errorf("GetPortHeuristic(%d, %q) = %q, want %q (built-in rules invisible to the app role?)",
				c.port, c.protocol, got, c.want)
		}
	}

	// Protocol normalization: callers report the protocol in whatever case and
	// alias the discovery path produced. All three of these must resolve to the
	// stored 'TLS'/'MODBUS' rows.
	for _, alias := range []struct {
		port     int
		protocol string
		want     string
	}{
		{443, "https", "HTTPS"},
		{443, "tls", "HTTPS"},
		{502, "Modbus", "Modbus/TCP"},
	} {
		if got := svc.GetPortHeuristic(tenantID, alias.port, alias.protocol); got != alias.want {
			t.Errorf("GetPortHeuristic(%d, %q) = %q, want %q — protocol normalization no longer "+
				"reaches the seeded rows", alias.port, alias.protocol, got, alias.want)
		}
	}

	// A port with no rule must stay empty rather than inventing a name.
	if got := svc.GetPortHeuristic(tenantID, 51234, "TLS"); got != "" {
		t.Errorf("GetPortHeuristic(51234, TLS) = %q, want \"\" for an unknown port", got)
	}

	for _, c := range mustNotIdentify {
		if got := svc.GetPortHeuristic(tenantID, c.port, c.protocol); got != "" {
			t.Errorf("GetPortHeuristic(%d, %q) = %q, want \"\" — %s. If naming it was "+
				"a deliberate decision, update the note in scripts/database/seed.sql "+
				"and this list together", c.port, c.protocol, got, c.why)
		}
	}

	// Protocols now arrive canonicalized from ingest (cryptoparse.NormalizeProtocol),
	// so the OT rows have to be reachable under the ENUM spelling, not only under
	// the uppercase form the rules are stored in. This is the assertion that the
	// two halves of the change meet.
	for _, c := range []struct {
		port     int
		protocol string
		want     string
	}{
		{502, "Modbus", "Modbus/TCP"},
		{4840, "OPC_UA", "OPC UA"},
		{44818, "EtherNet_IP", "EtherNet/IP"},
		{47808, "BACnet", "BACnet/IP"},
	} {
		if got := svc.GetPortHeuristic(tenantID, c.port, c.protocol); got != c.want {
			t.Errorf("GetPortHeuristic(%d, %q) = %q, want %q — the canonical protocol_type "+
				"spelling written at ingest no longer reaches the seeded rule",
				c.port, c.protocol, got, c.want)
		}
	}
}
