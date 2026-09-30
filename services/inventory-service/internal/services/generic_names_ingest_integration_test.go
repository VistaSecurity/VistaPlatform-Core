package services

// B2 (engine half) and B3 through the REAL inventory intake:
// IngestFindingsReport → ingestHostObservation → identity.GenericNames marking →
// the production engine (svc.identityEngine(): admission enforced, provisional
// inventory on) → the Postgres identity repository.
//
// The engine tests in shared/identity prove the rules against the in-memory
// store. These prove the mark reaches them from a sensor's frame and that no
// merge_proposed row is written in Postgres.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db). RFC 5737 addresses, RFC 7042 documentation MACs,
// invented names.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/identityenrichment"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const (
	genericPhoneOneMAC = "00:00:5e:00:53:81"
	genericPhoneTwoMAC = "00:00:5e:00:53:82"
	genericPhoneOneIP  = "203.0.113.81"
	genericPhoneTwoIP  = "203.0.113.82"
)

func (f *provisionalFixture) ingestHostObs(ho *hostobs.HostObservation) identity.IngestResult {
	f.t.Helper()
	report, err := f.svc.IngestFindingsReport(f.tenant, []IngestFinding{observationFinding(f.t, ho)}, "monitoring")
	if err != nil {
		f.t.Fatal(err)
	}
	if len(report.Results) != 1 {
		f.t.Fatalf("results = %+v, want one", report.Results)
	}
	return report.Results[0]
}

func (f *provisionalFixture) mergeProposals() int {
	f.t.Helper()
	var n int
	if err := f.raw.QueryRow(`SELECT count(*) FROM asset_history WHERE tenant_id=$1 AND action='merge_proposed'`, f.tenant).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *provisionalFixture) identifierCount(assetID string) int {
	f.t.Helper()
	var n int
	if err := f.raw.QueryRow(`SELECT count(*) FROM asset_identifiers WHERE tenant_id=$1 AND asset_id=$2`, f.tenant, assetID).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// TestIntegration_HostObservationIngest_GenericNameLinksNothing is the B2
// journey on a DHCP segment, with the default name every unrenamed phone
// announces.
//
//  1. Phone one is met by DHCP: its MAC, its lease, `iphone`.
//  2. Phone two is met by DHCP: ITS MAC, ITS lease, and the same `iphone`.
//     Before, the name decided a match on phone one and phone two's MAC was
//     written onto it. Now the name cannot decide: phone two is its own asset,
//     and the name stays phone one's (recorded, not moved).
//  3. An mDNS announcement — which establishes nothing — carries `iphone` and
//     phone two's lease. The name links phone one, the lease links phone two,
//     nothing may vote. Before, a proposal asking whether the two phones are
//     one. Now phone one is dropped (a generic-only link), phone two's link is
// a lease alone ( C1): unresolved, no asset, no proposal.
//
// Mutation checks: delete the `id.Generic` refusal in Engine.kindVotes → step 2
// matches phone one; delete the withoutGenericOnly pruning in
// Engine.resolveContested → step 3 writes a merge_proposed row.
func TestIntegration_HostObservationIngest_GenericNameLinksNothing(t *testing.T) {
	f := newProvisionalFixture(t)
	f.addDHCPSegment()
	t0 := f.now.Add(-3 * time.Hour)

	one := f.ingestHostObs(&hostobs.HostObservation{
		ObservedAt: t0, Source: hostobs.SourceDHCP, MAC: genericPhoneOneMAC,
		Addresses: addrsFor(t, genericPhoneOneIP), Hostnames: []string{"iphone"},
	})
	if one.AssetID == "" {
		t.Fatalf("step 1: phone one was not created: %+v", one)
	}
	nameOwner, _ := f.identifierOwner("hostname", "iphone")
	if nameOwner != one.AssetID {
		t.Fatalf("step 1: the name belongs to %s, want phone one %s", nameOwner, one.AssetID)
	}

	two := f.ingestHostObs(&hostobs.HostObservation{
		ObservedAt: t0.Add(time.Minute), Source: hostobs.SourceDHCP, MAC: genericPhoneTwoMAC,
		Addresses: addrsFor(t, genericPhoneTwoIP), Hostnames: []string{"iphone"},
	})
	if two.AssetID == "" || two.AssetID == one.AssetID {
		t.Fatalf("step 2: phone two resolved to %q (outcome %s); phone one is %s — a default name matched two phones",
			two.AssetID, two.Outcome, one.AssetID)
	}
	if owner, _ := f.identifierOwner("mac_address", genericPhoneTwoMAC); owner != two.AssetID {
		t.Errorf("step 2: phone two's MAC belongs to %s, want phone two %s", owner, two.AssetID)
	}
	if owner, _ := f.identifierOwner("hostname", "iphone"); owner != one.AssetID {
		t.Errorf("step 2: the name moved to %s; it is recorded where it was first seen, %s", owner, one.AssetID)
	}
	if n := f.mergeProposals(); n != 0 {
		t.Fatalf("step 2: %d merge proposals, want 0", n)
	}
	oneHeld, twoHeld := f.identifierCount(one.AssetID), f.identifierCount(two.AssetID)

	three := f.ingestHostObs(&hostobs.HostObservation{
		ObservedAt: t0.Add(time.Hour), Source: hostobs.SourceMDNS,
		Addresses: addrsFor(t, genericPhoneTwoIP), Hostnames: []string{"iphone"},
		Services: []string{"_companion-link._tcp"},
	})
	if n := f.mergeProposals(); n != 0 {
		t.Fatalf("step 3: %d merge proposals (outcome %s); a default name and a lease are no reason to ask whether two phones are one",
			n, three.Outcome)
	}
	if three.AssetID != "" || three.Outcome != string(identity.OutcomeUnresolved) {
		t.Errorf("step 3: outcome %s on %q, want unresolved with no asset", three.Outcome, three.AssetID)
	}
	if got := f.identifierCount(one.AssetID); got != oneHeld {
		t.Errorf("step 3: phone one holds %d identifiers, want %d", got, oneHeld)
	}
	if got := f.identifierCount(two.AssetID); got != twoHeld {
		t.Errorf("step 3: phone two holds %d identifiers, want %d", got, twoHeld)
	}
	if n := f.assetCount(); n != 2 {
		t.Errorf("%d assets, want 2", n)
	}
}

// TestIntegration_EnrichmentDNS_MarksAGenericName: the scoped DNS lookup the
// enrichment worker runs is measured context, and a generic name it looked up
// reaches the engine marked — the lookup cannot make `printer` decide what the
// sighting that carried it could not. Asserted on the evidence the engine
// stored for the DNS observation.
//
// Mutation check: delete the MarkAll call in pollDNS → the stored evidence
// carries the name unmarked and this fails.
func TestIntegration_EnrichmentDNS_MarksAGenericName(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	svc := NewAssetService(db)
	if _, err := svc.identityEngine(); err != nil {
		t.Fatal(err)
	}
	sensor, segment := uuid.New(), uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status,last_heartbeat,network_interfaces,reported_capabilities,reported_dns_interfaces) VALUES($1,$2,'Enrichment collector','linux','test-v1','datacenter_host','active',$3,ARRAY['eth0'],ARRAY['identity_dns_v1'],ARRAY['eth0'])`, []any{sensor, tenant, now}},
		{`INSERT INTO agent_addresses(sensor_id,interface_name,address,prefix_length) VALUES($1,'eth0','198.51.100.4',24)`, []any{sensor}},
		{`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment) VALUES($1,$2,'Enrichment network','cidr','198.51.100.0/24','production')`, []any{segment, tenant}},
		{`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"},"identity_enrichment":{"enabled":true}}') ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, []any{tenant}},
	} {
		if _, err := raw.Exec(q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	original := identity.Observation{
		TenantID: tenant.String(), Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:" + sensor.String()},
		ObservedAt: now.Add(-time.Minute), Network: identity.Network{SegmentID: segment.String()},
		Admission:   identity.AdmissionEvidence{ReceiptID: "generic-dns", CollectorVersion: "test-v1"},
		Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: "printer", Scope: segment.String()}},
	}
	first, err := svc.resolveObservationWith(ctx, original, nil)
	if err != nil {
		t.Fatal(err)
	}
	o := identityenrichment.Observation{ID: uuid.MustParse(first.ObservationID), Evidence: original, State: "unresolved"}
	store := &identityenrichment.Store{DB: db}
	scope, excluded, err := store.Scope(ctx, tenant, o, now)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := store.Policy(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	plan, reason := identityenrichment.NetworkPlan(o, policy, scope, nil, excluded)
	if reason != "" || plan.Action != "dns" {
		t.Fatalf("setup: plan %+v %s, want a DNS lookup", plan, reason)
	}
	job, err := store.Ensure(ctx, tenant, o, plan, now)
	if err != nil {
		t.Fatal(err)
	}
	backend := NewIdentityEnrichmentBackend(svc, &DiscoveryService{})
	queued, err := backend.Dispatch(ctx, job, o)
	if err != nil {
		t.Fatal(err)
	}
	job.RemoteID = queued.RemoteID
	answer, _ := json.Marshal(sensordispatch.IdentityDNSResult{
		RequestID: job.RequestID.String(), ObservationID: o.ID.String(), Hostname: plan.Hostname,
		NetworkScope: segment.String(), Addresses: []string{"198.51.100.20"}, ObservedAt: now, CollectorVersion: "test-v1",
	})
	if _, err := raw.Exec(`UPDATE sensor_commands SET status='completed',response_data=$2 WHERE id=$1`, job.RemoteID, string(answer)); err != nil {
		t.Fatal(err)
	}
	if done, err := backend.Poll(ctx, job, o); err != nil || done.State != "completed" {
		t.Fatalf("DNS poll %+v %v", done, err)
	}

	var evidence string
	if err := raw.QueryRow(`SELECT evidence::text FROM identity_observations WHERE tenant_id=$1 AND source_ref LIKE 'sensor:identity-dns:%'`, tenant).Scan(&evidence); err != nil {
		t.Fatalf("no evidence stored for the DNS observation: %v", err)
	}
	var stored identity.Observation
	if err := json.Unmarshal([]byte(evidence), &stored); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, id := range stored.Identifiers {
		if id.Kind == identity.KindHostname && id.Value == "printer" {
			found = true
			if !id.Generic || id.Confidence != identity.GenericConfidence {
				t.Errorf("the DNS observation's name = %+v, want it marked generic at %v", id, identity.GenericConfidence)
			}
		}
	}
	if !found {
		t.Fatalf("the DNS observation carries no `printer` hostname: %s", evidence)
	}
}

// TestIntegration_FloatingAddress_AnnouncersOwnAddressDoesNotProposeAMerge is
// B3 through the wire: the node's ARP frame carries its OWN address and the
// VIP. Before, the node's own address disqualified the floating shape and the
// frame proposed merging the node with the service. Now: the hosted_on edge is
// written, no proposal, and the node keeps its address.
//
// Mutation check: make an announcer-owned address disqualify the shape in
// Engine.floatingAddress → a merge_proposed row and no edge.
func TestIntegration_FloatingAddress_AnnouncersOwnAddressDoesNotProposeAMerge(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	node, vip := seedNodeAndVIP(t, svc, db, tenant)

	ho := &hostobs.HostObservation{
		Source: hostobs.SourceARP, MAC: itNodeMAC,
		Addresses: addrsFor(t, "192.0.2.10", itVIPAddr), ObservedAt: time.Now().UTC(),
		Attributes: map[string]any{"arp_gratuitous": true, "arp_operation": "request"},
	}
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, ho)}); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}

	if n := mergeProposalRows(t, db, tenant); n != 0 {
		t.Fatalf("%d merge_proposed rows; a node announcing its own address beside a VIP is not a merge question", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM asset_relationships WHERE tenant_id=$1 AND type='hosted_on' AND from_asset_id=$2 AND to_asset_id=$3`,
		tenant, vip, node); n != 1 {
		t.Errorf("%d hosted_on edges VIP → node, want 1", n)
	}
	if owner := assetOwning(t, db, tenant, "ip_address", "192.0.2.10"); owner != node {
		t.Errorf("the node's own address belongs to %s, want the node %s", owner, node)
	}
	if owner := assetOwning(t, db, tenant, "ip_address", itVIPAddr); owner != vip {
		t.Errorf("the VIP belongs to %s, want the VIP's asset %s", owner, vip)
	}
	if n := countRows(t, db, `SELECT count(*) FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL`, tenant); n != 2 {
		t.Errorf("%d assets, want 2", n)
	}
}
