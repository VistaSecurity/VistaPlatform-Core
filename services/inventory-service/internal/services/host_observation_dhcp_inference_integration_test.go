package services

// Traffic inference of a segment's DHCP posture ( Phase 1a), through the
// real ingest path: a forwarded DHCP sighting goes in at IngestFindings and the
// answer is read off the segment row, which is what identity reads.

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
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

func segmentMeta(t *testing.T, db *database.DB, tenant uuid.UUID, id uuid.UUID) map[string]any {
	t.Helper()
	var raw []byte
	if err := db.QueryRow(`SELECT metadata FROM network_segments WHERE tenant_id = $1 AND id = $2`, tenant, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestIntegration_HostObservation_DHCPAckInfersTheSegmentAndNothingElseDoes(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	mk := func(name, cidr string) *models.NetworkSegment {
		seg, err := svc.networkSegmentService.Create(tenant, models.NetworkSegmentInput{
			Name: name, SegmentType: "cidr", Value: cidr, NetworkType: "private", Environment: "production"})
		if err != nil {
			t.Fatal(err)
		}
		return seg
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

	// Everything that is NOT a server committing a lease says nothing about the segment.
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
		if m := segmentMeta(t, db, tenant, lan.ID); m["dynamic"] != nil {
			t.Fatalf("%s marked the segment: %v", c.name, m)
		}
	}
	// An ACK that is not a DHCP source at all (an ARP frame that happens to carry the attribute).
	notDHCP := dhcpSighting("28:cf:da:00:00:05", "192.0.2.24", "ack", now.Add(-time.Minute), nil)
	notDHCP.Source, notDHCP.Sources = hostobs.SourceARP, []string{hostobs.SourceARP}
	ingest(notDHCP)
	if m := segmentMeta(t, db, tenant, lan.ID); m["dynamic"] != nil {
		t.Fatalf("a non-DHCP source marked the segment: %v", m)
	}

	// An ACK assigning an address inside a segment marks THAT segment, inferred.
	first := now.Add(-2 * time.Minute)
	ingest(dhcpSighting("28:cf:da:00:00:10", "192.0.2.30", "ack", first, nil))
	m := segmentMeta(t, db, tenant, lan.ID)
	if m["dynamic"] != true || m["dynamic_source"] != "inferred" {
		t.Fatalf("an ACK did not mark the segment inferred-dynamic: %v", m)
	}
	if ev, _ := m["dynamic_evidence"].(map[string]any); ev["observed_at"] == nil {
		t.Fatalf("no evidence recorded: %v", m)
	}
	if o := segmentMeta(t, db, tenant, other.ID); o["dynamic"] != nil {
		t.Fatalf("the ACK marked a segment it did not assign into: %v", o)
	}
	evidenceAt := m["dynamic_evidence"].(map[string]any)["observed_at"]

	// The throttle: a second ACK inside 24h writes nothing (evidence is untouched).
	ingest(dhcpSighting("28:cf:da:00:00:11", "192.0.2.31", "ack", now.Add(-time.Minute), nil))
	if got := segmentMeta(t, db, tenant, lan.ID)["dynamic_evidence"].(map[string]any)["observed_at"]; got != evidenceAt {
		t.Fatalf("a second ACK inside the throttle window rewrote the evidence: %v -> %v", evidenceAt, got)
	}

	// A measured answer outranks the inference and is not overwritten by later ACKs.
	if _, err := pgidentity.RecordSegmentPosture(t.Context(), db.DB.DB, tenant.String(), other.ID.String(),
		pgidentity.PostureMeasured, false, pgidentity.PostureEvidence{}); err != nil {
		t.Fatal(err)
	}
	ingest(dhcpSighting("28:cf:da:00:00:12", "198.51.100.40", "ack", now.Add(-time.Minute), nil))
	if o := segmentMeta(t, db, tenant, other.ID); o["dynamic"] != false || o["dynamic_source"] != "measured" {
		t.Fatalf("an ACK overwrote a measurement: %v", o)
	}

	// An ACK outside every segment is simply not about a segment we know.
	ingest(dhcpSighting("28:cf:da:00:00:13", "203.0.113.9", "ack", now.Add(-time.Minute), nil))
}

// The note about the segment must never cost the observation it rode in on.
func TestIntegration_HostObservation_InferenceFailureDoesNotFailTheObservation(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	if _, err := svc.networkSegmentService.Create(tenant, models.NetworkSegmentInput{
		Name: "lan", SegmentType: "cidr", Value: "192.0.2.0/24", NetworkType: "private", Environment: "production"}); err != nil {
		t.Fatal(err)
	}
	// Make every UPDATE of this tenant's segments fail. Scoped to the tenant and
	// removed afterwards: the database is shared with other tests.
	fn := "dhcp_inference_fail_" + strings.ReplaceAll(tenant.String(), "-", "")
	if _, err := db.Exec(`CREATE FUNCTION ` + fn + `() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.tenant_id = '` + tenant.String() + `'::uuid THEN RAISE EXCEPTION 'segment writes are refused'; END IF; RETURN NEW; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER ` + fn + ` BEFORE UPDATE ON network_segments FOR EACH ROW EXECUTE FUNCTION ` + fn + `()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DROP TRIGGER IF EXISTS ` + fn + ` ON network_segments`)
		_, _ = db.Exec(`DROP FUNCTION IF EXISTS ` + fn + `()`)
	})

	imported, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t,
		dhcpSighting("28:cf:da:00:00:20", "192.0.2.50", "ack", time.Now().UTC().Add(-time.Minute), nil))})
	if err != nil || imported != 1 {
		t.Fatalf("a failed segment note failed the observation: imported=%d err=%v", imported, err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).Scan(&n); err != nil || n != 1 {
		t.Fatalf("the asset was not created: n=%d err=%v", n, err)
	}
}
