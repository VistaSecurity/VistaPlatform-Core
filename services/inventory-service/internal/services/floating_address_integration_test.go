package services

// The floating-address rule and decision memory, driven through the REAL host
// observation ingest against a real Postgres.
//
// "Test the wiring, not the helper": the engine tests in shared/identity prove
// the rules; these prove that an ARP-shaped finding arriving through
// IngestFindings reaches them — that the ARP decoder's evidence survives the
// builder, that the Postgres repository writes the `hosted_on` edge and reads
// back a reviewer's `kept_separate`, and that the approvals service's stamp is
// the shape the repository looks for. Deleting the floating branch from
// Engine.Resolve, or the priorDecision lookup, turns these red.
//
// The dev-cluster case that motivated it, in RFC 5737 addresses: MetalLB
// announces the ingress VIP from a node's real NIC by gratuitous ARP; the MAC resolves to
// the node's asset and the address to the asset at the VIP; the old walk
// proposed merging the two, three times, because the reviewer's "kept separate"
// was never read back.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
)

const (
	itNodeMAC = "e8:ff:1e:00:00:07"
	itVIPAddr = "192.0.2.230"
)

// seedNodeAndVIP ingests the node (ARP: its MAC at its own address) and the
// thing at the VIP (a named host at the floating address, no MAC — what an
// active scan or a certificate observation knows about it). Returns their ids.
func seedNodeAndVIP(t *testing.T, svc *AssetService, db *database.DB, tenant uuid.UUID) (node, vip uuid.UUID) {
	t.Helper()
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceARP, MAC: itNodeMAC,
		Addresses: addrsFor(t, "192.0.2.10"), ObservedAt: time.Now().UTC().Add(-time.Hour),
	})}); err != nil {
		t.Fatalf("seed the node: %v", err)
	}
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceMDNS, FQDNs: []string{"vista.example.test"},
		Addresses: addrsFor(t, itVIPAddr), ObservedAt: time.Now().UTC().Add(-time.Hour),
	})}); err != nil {
		t.Fatalf("seed the VIP's asset: %v", err)
	}
	node = assetOwning(t, db, tenant, "mac_address", itNodeMAC)
	vip = assetOwning(t, db, tenant, "ip_address", itVIPAddr)
	if node == vip {
		t.Fatal("fixture: the node and the VIP resolved to one asset")
	}
	return node, vip
}

func assetOwning(t *testing.T, db *database.DB, tenant uuid.UUID, kind, value string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(`
		SELECT asset_id FROM asset_identifiers
		 WHERE tenant_id = $1 AND kind = $2 AND value = $3`, tenant, kind, value).Scan(&id); err != nil {
		t.Fatalf("no asset owns %s=%s: %v", kind, value, err)
	}
	return id
}

// vipAnnouncement is what the sensor's ARP decoder emits for a gratuitous ARP
// of the VIP from the node's NIC: MAC, address, the gratuitous flag, nothing
// else.
func vipAnnouncement(t *testing.T, at time.Time) IngestFinding {
	t.Helper()
	ho := &hostobs.HostObservation{
		Source: hostobs.SourceARP, MAC: itNodeMAC,
		Addresses: addrsFor(t, itVIPAddr), ObservedAt: at,
		Attributes: map[string]any{"arp_gratuitous": true, "arp_operation": "request"},
	}
	return observationFinding(t, ho)
}

func countRows(t *testing.T, db *database.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func mergeProposalRows(t *testing.T, db *database.DB, tenant uuid.UUID) int {
	t.Helper()
	return countRows(t, db, `SELECT count(*) FROM asset_history WHERE tenant_id = $1 AND action = 'merge_proposed'`, tenant)
}

func TestIntegration_FloatingAddress_VIPAnnouncementDoesNotProposeAMerge(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	node, vip := seedNodeAndVIP(t, svc, db, tenant)
	var nodeSeenBefore time.Time
	if err := db.QueryRow(`SELECT last_seen_at FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, node).Scan(&nodeSeenBefore); err != nil {
		t.Fatal(err)
	}

	imported, err := svc.IngestFindings(tenant, []IngestFinding{vipAnnouncement(t, time.Now().UTC())})
	if err != nil {
		t.Fatalf("IngestFindings(announcement): %v", err)
	}
	if imported != 1 {
		t.Fatalf("imported = %d, want 1 — the announcement landed on the VIP's asset", imported)
	}

	if n := countRows(t, db, `SELECT count(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant); n != 2 {
		t.Errorf("%d assets, want 2: the node and the VIP, and nothing created for the announcement", n)
	}
	if n := mergeProposalRows(t, db, tenant); n != 0 {
		t.Errorf("%d merge_proposed rows; a node announcing a floating address is not a merge question", n)
	}
	// The node's MAC was NOT written onto the VIP's asset.
	if n := countRows(t, db, `SELECT count(*) FROM asset_identifiers WHERE tenant_id = $1 AND asset_id = $2 AND kind = 'mac_address'`, tenant, vip); n != 0 {
		t.Errorf("the VIP's asset carries %d mac_address identifier(s); the announcer's MAC must not be attached to it", n)
	}
	if owner := assetOwning(t, db, tenant, "mac_address", itNodeMAC); owner != node {
		t.Errorf("the node's MAC now belongs to %s, want the node %s", owner, node)
	}

	// The knowledge landed as a relationship: VIP hosted_on node, with the
	// evidence.
	var from, to uuid.UUID
	var status, sourceKind string
	var gratuitous bool
	var observations int
	if err := db.QueryRow(`
		SELECT from_asset_id, to_asset_id, status, source_kind,
		       (attributes -> 'floating_address' ->> 'gratuitous_arp')::bool, observation_count
		  FROM asset_relationships
		 WHERE tenant_id = $1 AND type = 'hosted_on' AND attributes ? 'floating_address'`, tenant).
		Scan(&from, &to, &status, &sourceKind, &gratuitous, &observations); err != nil {
		t.Fatalf("no hosted_on edge with floating_address evidence was written: %v", err)
	}
	if from != vip || to != node {
		t.Errorf("edge is %s → %s, want VIP %s hosted_on node %s", from, to, vip, node)
	}
	if sourceKind != "measured" {
		t.Errorf("edge source_kind = %q, want measured — a frame said so", sourceKind)
	}
	if !gratuitous {
		t.Error("the gratuitous-ARP evidence did not reach the edge's attributes")
	}
	if observations != 1 {
		t.Errorf("observation_count = %d, want 1", observations)
	}
	// Both assets pending, so the edge waits with them (ADR-0003 D3).
	if status != "pending" {
		t.Errorf("edge status = %q, want pending while both ends await approval", status)
	}

	// History on both, and the node was seen: its NIC sent the frame.
	if n := countRows(t, db, `SELECT count(*) FROM asset_history WHERE tenant_id = $1 AND asset_id = $2 AND action = 'updated' AND changes_json ? 'floating_address'`, tenant, vip); n != 1 {
		t.Errorf("the VIP's history has %d floating_address entries, want 1", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM asset_history WHERE tenant_id = $1 AND asset_id = $2 AND action = 'updated' AND changes_json ? 'announces'`, tenant, node); n != 1 {
		t.Errorf("the node's history has %d announces entries, want 1", n)
	}
	var nodeSeenAfter time.Time
	if err := db.QueryRow(`SELECT last_seen_at FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, node).Scan(&nodeSeenAfter); err != nil {
		t.Fatal(err)
	}
	if !nodeSeenAfter.After(nodeSeenBefore) {
		t.Error("the node's last_seen_at did not advance; the frame came from its NIC")
	}

	// Daily auto-scan plus passive capture means this fires continuously. A
	// second announcement is the same edge seen again — not a second row, and
	// still not a proposal.
	if _, err := svc.IngestFindings(tenant, []IngestFinding{vipAnnouncement(t, time.Now().UTC().Add(time.Minute))}); err != nil {
		t.Fatalf("IngestFindings(second announcement): %v", err)
	}
	if n := countRows(t, db, `SELECT count(*) FROM asset_relationships WHERE tenant_id = $1 AND type = 'hosted_on'`, tenant); n != 1 {
		t.Errorf("%d hosted_on edges after two announcements, want 1", n)
	}
	if err := db.QueryRow(`SELECT observation_count FROM asset_relationships WHERE tenant_id = $1 AND type = 'hosted_on'`, tenant).Scan(&observations); err != nil {
		t.Fatal(err)
	}
	if observations != 2 {
		t.Errorf("observation_count = %d after two announcements, want 2", observations)
	}
	if n := mergeProposalRows(t, db, tenant); n != 0 {
		t.Errorf("%d merge_proposed rows after the second announcement, want 0", n)
	}
	assertNoExternalConnections(t, db, tenant)
}

// THE QUALIFIER, through the wire: the node's MAC arriving WITH the VIP's name
// is a re-imaged or spoofed host, and that still gets a human.
func TestIntegration_FloatingAddress_NamedEvidenceStillProposes(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	_, vip := seedNodeAndVIP(t, svc, db, tenant)

	named := observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceMDNS, MAC: itNodeMAC,
		Addresses: addrsFor(t, itVIPAddr), FQDNs: []string{"vista.example.test"},
		ObservedAt: time.Now().UTC(),
		Attributes: map[string]any{"arp_gratuitous": true},
	})
	if _, err := svc.IngestFindings(tenant, []IngestFinding{named}); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}
	if n := mergeProposalRows(t, db, tenant); n == 0 {
		t.Error("no merge proposal for the node's MAC arriving with the VIP's name; that is a real contradiction")
	}
	if n := countRows(t, db, `SELECT count(*) FROM asset_relationships WHERE tenant_id = $1 AND type = 'hosted_on' AND attributes ? 'floating_address'`, tenant); n != 0 {
		t.Errorf("%d floating-address edges were written for a genuine conflict", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM asset_identifiers WHERE tenant_id = $1 AND asset_id = $2 AND kind = 'mac_address'`, tenant, vip); n != 0 {
		t.Errorf("the VIP's asset acquired %d MAC(s) on the conflict path", n)
	}
}

// A reviewer's "kept separate" sticks: the same conflict is not re-proposed,
// and the ingest can say why.
func TestIntegration_KeptSeparate_IsNotReproposed(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	ctx := context.Background()

	// A owns a MAC, B owns a name; an observation carrying both is the floor
	// conflict that opens a proposal and creates nothing.
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceARP, MAC: "28:cf:da:00:00:a1",
		Addresses: addrsFor(t, "192.0.2.20"), ObservedAt: time.Now().UTC().Add(-time.Hour),
	})}); err != nil {
		t.Fatalf("seed A: %v", err)
	}
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceMDNS, FQDNs: []string{"bee.example.test"},
		Addresses: addrsFor(t, "192.0.2.21"), ObservedAt: time.Now().UTC().Add(-time.Hour),
	})}); err != nil {
		t.Fatalf("seed B: %v", err)
	}
	a := assetOwning(t, db, tenant, "mac_address", "28:cf:da:00:00:a1")
	b := assetOwning(t, db, tenant, "fqdn", "bee.example.test")

	conflict := func(at time.Time) IngestFinding {
		return observationFinding(t, &hostobs.HostObservation{
			Source: hostobs.SourceMDNS, MAC: "28:cf:da:00:00:a1",
			FQDNs: []string{"bee.example.test"}, ObservedAt: at,
		})
	}
	if _, err := svc.IngestFindings(tenant, []IngestFinding{conflict(time.Now().UTC())}); err != nil {
		t.Fatalf("IngestFindings(conflict): %v", err)
	}
	var proposalID uuid.UUID
	if err := db.QueryRow(`
		SELECT id FROM asset_history
		 WHERE tenant_id = $1 AND action = 'merge_proposed'
		   AND changes_json ->> 'kind' = 'merge_proposal'
		   AND coalesce(changes_json ->> 'status', 'pending') = 'pending'`, tenant).Scan(&proposalID); err != nil {
		t.Fatalf("the conflict opened no pending proposal: %v", err)
	}
	rowsBefore := mergeProposalRows(t, db, tenant)

	// The reviewer looks and says these are different things — through the
	// PRODUCTION service, so the stamp it writes is the one the repository has
	// to read.
	if _, err := NewMergeProposalService(db).KeepSeparate(ctx, tenant, proposalID, seedUser(t, db, tenant)); err != nil {
		t.Fatalf("KeepSeparate: %v", err)
	}

	if _, err := svc.IngestFindings(tenant, []IngestFinding{conflict(time.Now().UTC().Add(time.Minute))}); err != nil {
		t.Fatalf("IngestFindings(conflict again): %v", err)
	}
	if n := mergeProposalRows(t, db, tenant); n != rowsBefore {
		t.Errorf("merge_proposed rows %d → %d; the pair was re-proposed after a reviewer kept it separate", rowsBefore, n)
	}
	if n := countRows(t, db, `
		SELECT count(*) FROM asset_history
		 WHERE tenant_id = $1 AND action = 'merge_proposed'
		   AND changes_json ->> 'kind' = 'merge_proposal'
		   AND coalesce(changes_json ->> 'status', 'pending') = 'pending'`, tenant); n != 0 {
		t.Errorf("%d pending proposal(s) after the decision; the queue refilled with a question already answered", n)
	}
	// The observation landed on the asset the WEAKER evidence names — the
	// reviewer set aside the MAC's claim — and its history says why.
	var suppressedOn uuid.UUID
	var recorded string
	if err := db.QueryRow(`
		SELECT asset_id, changes_json -> 'suppressed_proposal' ->> 'proposal_id'
		  FROM asset_history
		 WHERE tenant_id = $1 AND action = 'updated' AND changes_json ? 'suppressed_proposal'`, tenant).
		Scan(&suppressedOn, &recorded); err != nil {
		t.Fatalf("no history entry records the suppressed proposal: %v", err)
	}
	if suppressedOn != b {
		t.Errorf("the suppressed observation landed on %s, want B %s (the name's asset; A %s is the MAC's)", suppressedOn, b, a)
	}
	if recorded != proposalID.String() {
		t.Errorf("history names proposal %s, want the one the reviewer resolved, %s", recorded, proposalID)
	}
	// And A's MAC stayed A's.
	if owner := assetOwning(t, db, tenant, "mac_address", "28:cf:da:00:00:a1"); owner != a {
		t.Errorf("A's MAC now belongs to %s", owner)
	}
}

// A question already in the queue is noted once, not once per observation.
func TestIntegration_PendingProposal_IsNotRenotedPerObservation(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceARP, MAC: "28:cf:da:00:00:b1", ObservedAt: time.Now().UTC().Add(-time.Hour),
	})}); err != nil {
		t.Fatalf("seed A: %v", err)
	}
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceMDNS, FQDNs: []string{"cee.example.test"}, ObservedAt: time.Now().UTC().Add(-time.Hour),
	})}); err != nil {
		t.Fatalf("seed B: %v", err)
	}
	for i := 0; i < 3; i++ {
		f := observationFinding(t, &hostobs.HostObservation{
			Source: hostobs.SourceMDNS, MAC: "28:cf:da:00:00:b1",
			FQDNs: []string{"cee.example.test"}, ObservedAt: time.Now().UTC().Add(time.Duration(i) * time.Minute),
		})
		if _, err := svc.IngestFindings(tenant, []IngestFinding{f}); err != nil {
			t.Fatalf("IngestFindings(%d): %v", i, err)
		}
	}
	// One proposal row (kind: merge_proposal) plus ONE pointer entry on the
	// first candidate. Before the fix each re-observation appended another
	// pointer entry: 4 rows after three observations, 1,440 a day on a
	// one-minute coalescing window.
	if n := mergeProposalRows(t, db, tenant); n != 2 {
		t.Errorf("%d merge_proposed rows after three identical observations, want 2 (the proposal and one note about it)", n)
	}
	if n := countRows(t, db, `
		SELECT count(*) FROM asset_history
		 WHERE tenant_id = $1 AND action = 'merge_proposed' AND changes_json ->> 'kind' = 'merge_proposal'`, tenant); n != 1 {
		t.Errorf("%d proposals, want 1", n)
	}
}
