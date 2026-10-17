package services

// Traffic inference of a prefix's DHCP posture ( Phase 1a; DCIM row 1.6),
// through the real ingest path: a forwarded DHCP sighting goes in at
// IngestFindings and the answer is read off the prefix row, which is what
// identity reads.

import (
	"database/sql"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

func dhcpSighting(mac, addr, msgType string, at time.Time, extra map[string]interface{}) *hostobs.HostObservation {
	attrs := map[string]interface{}{"dhcp_message_type": msgType}
	for k, v := range extra {
		attrs[k] = v
	}
	return &hostobs.HostObservation{
		Source:     hostobs.SourceDHCP,
		MAC:        mac,
		Addresses:  []netip.Addr{netip.MustParseAddr(addr)},
		Hostnames:  []string{"lease-client"},
		Attributes: attrs,
		ObservedAt: at,
	}
}

// prefixDHCP is a prefix's stored DHCP posture: nil when nobody has said.
func prefixDHCP(t *testing.T, db *database.DB, tenant uuid.UUID, id uuid.UUID) *bool {
	t.Helper()
	var v sql.NullBool
	if err := db.QueryRow(`SELECT dhcp_managed FROM prefixes WHERE tenant_id = $1 AND id = $2`, tenant, id).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if !v.Valid {
		return nil
	}
	return &v.Bool
}

func TestIntegration_HostObservation_DHCPAckInfersThePrefixAndNothingElseDoes(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	mk := func(name, cidr string) uuid.UUID {
		return declarePrefix(t, db.DB.DB, tenant, map[string]any{"prefix": cidr, "description": name, "network_type": "private", "environment": "production"})
	}
	lan := mk("lan", "192.0.2.0/24")
	other := mk("other", "198.51.100.0/24")
	ingest := func(ho *hostobs.HostObservation) {
		t.Helper()
		if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, ho)}); err != nil {
			t.Fatalf("IngestFindings: %v", err)
		}
	}
	now := time.Now().UTC()

	// Everything that is NOT a server committing a lease says nothing about the prefix.
	for _, c := range []struct {
		name string
		ho   *hostobs.HostObservation
	}{
		{"a client REQUEST", dhcpSighting("28:cf:da:00:00:01", "192.0.2.20", "request", now.Add(-time.Minute), map[string]interface{}{"dhcp_address_requested_only": true})},
		{"a server OFFER", dhcpSighting("28:cf:da:00:00:02", "192.0.2.21", "offer", now.Add(-time.Minute), nil)},
		{"an ACK carrying only a requested address", dhcpSighting("28:cf:da:00:00:03", "192.0.2.22", "ack", now.Add(-time.Minute), map[string]interface{}{"dhcp_address_requested_only": true})},
		{"an ACK observed more than a day ago", dhcpSighting("28:cf:da:00:00:04", "192.0.2.23", "ack", now.Add(-48*time.Hour), nil)},
	} {
		ingest(c.ho)
		if v := prefixDHCP(t, db, tenant, lan); v != nil {
			t.Fatalf("%s marked the prefix: %v", c.name, *v)
		}
	}
	// An ACK that is not a DHCP source at all (an ARP frame that happens to carry the attribute).
	notDHCP := dhcpSighting("28:cf:da:00:00:05", "192.0.2.24", "ack", now.Add(-time.Minute), nil)
	notDHCP.Source, notDHCP.Sources = hostobs.SourceARP, []string{hostobs.SourceARP}
	ingest(notDHCP)
	if v := prefixDHCP(t, db, tenant, lan); v != nil {
		t.Fatalf("a non-DHCP source marked the prefix: %v", *v)
	}

	// An ACK assigning an address inside a prefix marks THAT prefix dynamic.
	ingest(dhcpSighting("28:cf:da:00:00:10", "192.0.2.30", "ack", now.Add(-2*time.Minute), nil))
	if v := prefixDHCP(t, db, tenant, lan); v == nil || !*v {
		t.Fatalf("an ACK did not mark the prefix dynamic: %v", v)
	}
	if v := prefixDHCP(t, db, tenant, other); v != nil {
		t.Fatalf("the ACK marked a prefix it did not assign into: %v", *v)
	}

	// A statement already made is not overwritten by later ACKs: the first
	// statement stands (shared/identity/postgres RecordPrefixPosture).
	if _, err := pgidentity.RecordPrefixPosture(t.Context(), db.DB.DB, tenant.String(), other.String(), false); err != nil {
		t.Fatal(err)
	}
	ingest(dhcpSighting("28:cf:da:00:00:12", "198.51.100.40", "ack", now.Add(-time.Minute), nil))
	if v := prefixDHCP(t, db, tenant, other); v == nil || *v {
		t.Fatalf("an ACK overwrote a stated static posture: %v", v)
	}

	// An ACK outside every prefix is simply not about a network we know.
	ingest(dhcpSighting("28:cf:da:00:00:13", "203.0.113.9", "ack", now.Add(-time.Minute), nil))
}

// The note about the prefix must never cost the observation it rode in on.
func TestIntegration_HostObservation_InferenceFailureDoesNotFailTheObservation(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	declarePrefix(t, db.DB.DB, tenant, map[string]any{"prefix": "192.0.2.0/24", "description": "lan", "network_type": "private", "environment": "production"})
	// Make every UPDATE of this tenant's prefixes fail. Scoped to the tenant and
	// removed afterwards: the database is shared with other tests.
	fn := "dhcp_inference_fail_" + strings.ReplaceAll(tenant.String(), "-", "")
	if _, err := db.Exec(`CREATE FUNCTION ` + fn + `() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.tenant_id = '` + tenant.String() + `'::uuid THEN RAISE EXCEPTION 'prefix writes are refused'; END IF; RETURN NEW; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER ` + fn + ` BEFORE UPDATE ON prefixes FOR EACH ROW EXECUTE FUNCTION ` + fn + `()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DROP TRIGGER IF EXISTS ` + fn + ` ON prefixes`)
		_, _ = db.Exec(`DROP FUNCTION IF EXISTS ` + fn + `()`)
	})

	imported, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t,
		dhcpSighting("28:cf:da:00:00:20", "192.0.2.50", "ack", time.Now().UTC().Add(-time.Minute), nil))})
	if err != nil || imported != 1 {
		t.Fatalf("a failed prefix note failed the observation: imported=%d err=%v", imported, err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).Scan(&n); err != nil || n != 1 {
		t.Fatalf("the asset was not created: n=%d err=%v", n, err)
	}
}
