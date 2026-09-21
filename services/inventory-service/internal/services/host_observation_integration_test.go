package services

// Host observations become assets, end to end, against a real Postgres
// (asset-inventory workstream 2.5, consumer half).
//
// These are the assertions a unit test cannot make. The builder tests next door
// prove the observation is SHAPED right; these prove it lands — that the asset,
// its identifiers and its facts are in the tables under RLS, that the same MAC
// seen twice is one asset rather than two, and that a second name on a known MAC
// attaches to the asset that already exists instead of minting another.
//
// They also hold the three refusals open, which is the half that matters most:
// the reason these rows were held back at discovery-processor's boundary for a
// whole release was that letting them through wrote connections that never
// happened and resolved names that exist only on the customer's LAN.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db). RFC 5737 documentation addresses throughout — the export
// leak gate rejects real lab ranges.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// newHostObsFixture builds the service with the collaborators the PRODUCTION
// ingest has, not the minimum these tests need.
//
// Both of them are load-bearing here, and leaving either out makes the refusal
// tests vacuous — which is exactly what the first draft of this file did:
//
//   - Without networkSegmentService, classifyAsset short-circuits to "unknown"
//     and nothing is ever third_party, so the external_connections route is
//     never on the table and a test asserting it was not taken asserts nothing.
//   - Without externalConnectionsSvc, IngestFindings skips the third-party
//     branch entirely (`&& s.externalConnectionsSvc != nil`), with the same
//     effect.
//
// With both wired and no segments defined for the tenant, an observation with
// no address — or with a public one — classifies third_party, which is the
// production condition that used to write a connection row and resolve a
// LAN-only name.
func newHostObsFixture(t *testing.T) (*AssetService, *database.DB, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	algorithms := NewAlgorithmService(db)
	svc := &AssetService{
		db:                    db,
		algorithmService:      algorithms,
		networkSegmentService: NewNetworkSegmentService(db, nil),
	}
	svc.SetExternalConnectionsService(NewExternalConnectionsService(db, algorithms))
	return svc, db, testdb.NewTenant(t, raw)
}

// observationFinding builds the finding discovery-processor forwards: the
// payload under `host_observation`, the kind on the finding, and the documented
// dest_ip of 0.0.0.0 when nothing was addressed.
func observationFinding(t *testing.T, ho *hostobs.HostObservation) IngestFinding {
	t.Helper()
	ho.Finalize()
	blob, err := json.Marshal(ho)
	if err != nil {
		t.Fatalf("marshal observation: %v", err)
	}
	var generic map[string]interface{}
	if err := json.Unmarshal(blob, &generic); err != nil {
		t.Fatalf("unmarshal observation: %v", err)
	}
	destIP := "0.0.0.0"
	if len(ho.Addresses) > 0 {
		destIP = ho.Addresses[0].String()
	}
	// sensor-manager fills sensor_discoveries.hostname from the observation's
	// best name, and the converter copies it onto the finding. Reproducing that
	// matters: `hostname` is half of what classifyAsset reads, and a fixture
	// that left it nil could never reach the third_party branch — so the
	// refusal tests below would be asserting against a path they never took.
	var hostname *string
	if n := hostObservationBestName(ho); n != nil {
		hostname = n
	}
	return IngestFinding{
		Kind:           KindHostObservation,
		Protocol:       "HOST",
		Hostname:       hostname,
		IPAddress:      &destIP,
		SourceSensorID: ptr("11111111-2222-3333-4444-555555555555"),
		RawData: map[string]interface{}{
			"host_observation": generic,
			"kind":             KindHostObservation,
			"source":           "sensor_discovery",
			"discovery_method": "passive_host_observation",
			"sensor_id":        "11111111-2222-3333-4444-555555555555",
			"batch_id":         "batch-hostobs-1",
			"confidence_score": hostobs.Confidence(ho),
		},
	}
}

func addrsFor(t *testing.T, ss ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("bad test address %q: %v", s, err)
		}
		out = append(out, a)
	}
	return out
}

// The whole path: a forwarded host observation becomes an asset with its
// identifiers and its facts, under RLS, and lands pending approval.
func TestIntegration_HostObservation_BecomesAnAssetWithIdentifiersAndFacts(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)

	f := observationFinding(t, &hostobs.HostObservation{
		Source:     hostobs.SourceMDNS,
		Sources:    []string{hostobs.SourceARP, hostobs.SourceMDNS},
		MAC:        "28:cf:da:11:22:33",
		Addresses:  addrsFor(t, "192.0.2.50"),
		FQDNs:      []string{"hp-printer.local"},
		Hostnames:  []string{"hp-printer"},
		Services:   []string{"_ipp._tcp"},
		ObservedAt: time.Now().UTC().Add(-time.Minute),
	})

	imported, err := svc.IngestFindings(tenant, []IngestFinding{f})
	if err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}
	if imported != 1 {
		t.Fatalf("imported = %d, want 1", imported)
	}

	var assetID uuid.UUID
	var classKey, status, ownership, primaryAddress string
	if err := db.QueryRow(`
		SELECT id, class_key, asset_status, asset_ownership, host(primary_address)
		  FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).
		Scan(&assetID, &classKey, &status, &ownership, &primaryAddress); err != nil {
		t.Fatalf("read the asset back: %v", err)
	}

	// A device advertising `_ipp._tcp` is a printer, and saying so is a
	// classification RULE's conclusion — which is why this assertion changed in
	// workstream 2.10b.
	//
	// It read `unknown_host` for one release, and the comment beside it said
	// "the engine is not allowed to guess one". That was right, and the reason
	// was never that the conclusion is wrong: it was that `class_source_kind`
	// had no honest value for a class argued from a curated rule, so recording
	// the answer would have meant claiming we measured the service-to-class
	// mapping. 2.10b added `rule`, and the class now lands with the id of the
	// row that argued it. The refusal that still stands is the one the
	// class_proposal tests hold: nothing is DECIDED here, the asset waits in
	// Approvals, and a rule never overwrites a class somebody already set.
	if classKey != "printer" {
		t.Errorf("class_key = %q, want printer — the `_ipp._tcp` mdns_service rule decides it (workstream 2.10b)", classKey)
	}
	// A host observation proposes an asset like any other discovery, and is not
	// exempt from approval.
	if status != "pending_approval" {
		t.Errorf("asset_status = %q, want pending_approval", status)
	}
	if ownership == "third_party" {
		t.Error("a passively observed host was recorded as a third party")
	}
	// The engine takes primary_address from the ip_address identifier, so the
	// asset shows its address without any endpoint row existing.
	if primaryAddress != "192.0.2.50" {
		t.Errorf("primary_address = %q, want 192.0.2.50", primaryAddress)
	}

	// kind|value → scope. A kind can hold several rows (the mDNS name is filed
	// twice: whole and short), so the map is keyed on both.
	identifiers := map[string]string{}
	rows, err := db.Query(`SELECT kind, value, coalesce(scope, '') FROM asset_identifiers WHERE tenant_id = $1 AND asset_id = $2`, tenant, assetID)
	if err != nil {
		t.Fatalf("read identifiers: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var kind, value, scope string
		if err := rows.Scan(&kind, &value, &scope); err != nil {
			t.Fatal(err)
		}
		identifiers[kind+"|"+value] = scope
	}
	for _, want := range []string{
		"mac_address|28:cf:da:11:22:33",
		// The `.local` name is link-scoped (RFC 6762 §3) and is filed as a
		// SCOPED hostname, whole, never as a globally unique fqdn — an
		// unscoped `.local` fqdn is what let a reflector's copy of one host's
		// name absorb the host itself from another segment.
		"hostname|hp-printer.local",
		"hostname|hp-printer",
		"ip_address|192.0.2.50",
	} {
		if _, ok := identifiers[want]; !ok {
			t.Errorf("%s identifier missing (all: %v)", want, identifiers)
		}
	}
	if scope := identifiers["hostname|hp-printer.local"]; scope == "" {
		t.Errorf("the .local name was stored without a scope; it must identify only within the segment it was heard in (all: %v)", identifiers)
	}
	if scope, ok := identifiers["fqdn|hp-printer.local"]; ok {
		t.Errorf("the .local name was stored as a globally unique fqdn (scope %q); a link-scoped name must not decide matches across segments", scope)
	}

	facts := map[string]string{}
	fRows, err := db.Query(`SELECT key, value::text, source_kind, source_ref FROM asset_facts WHERE tenant_id = $1 AND asset_id = $2`, tenant, assetID)
	if err != nil {
		t.Fatalf("read facts: %v", err)
	}
	defer func() { _ = fRows.Close() }()
	for fRows.Next() {
		var key, value, sourceKind, sourceRef string
		if err := fRows.Scan(&key, &value, &sourceKind, &sourceRef); err != nil {
			t.Fatal(err)
		}
		facts[key] = value
		if sourceKind != "measured" {
			t.Errorf("fact %s is %q; a frame stated it, so it is measured", key, sourceKind)
		}
		if sourceRef == "" {
			t.Errorf("fact %s has no source_ref — provenance is what makes it reconcilable", key)
		}
	}
	if facts["hw.vendor"] == "" {
		t.Errorf("hw.vendor was not written; facts = %v", facts)
	}
	if facts["net.mdns_services"] == "" {
		t.Errorf("net.mdns_services was not written; facts = %v", facts)
	}
	// Neither may be synthesised from a passive capture: an advertisement
	// identifies its ADVERTISER, not an adjacency to the capture point, and
	// capture_interface names the SENSOR's interface.
	for _, forbidden := range []string{"net.neighbors", "net.interfaces"} {
		if _, ok := facts[forbidden]; ok {
			t.Errorf("%s was synthesised from a passive capture", forbidden)
		}
	}

	// Nothing crypto-shaped was invented. A host observation measured no
	// cryptography, and a row saying otherwise with zero values reads downstream
	// as "we looked and found nothing".
	assertNoCryptoResidue(t, db, tenant)
}

// The same MAC seen again is the SAME asset. Without this every coalescing
// window — one a minute, per host — would add another row to Approvals.
func TestIntegration_HostObservation_SameMACMatchesTheSameAsset(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)

	first := observationFinding(t, &hostobs.HostObservation{
		Source:     hostobs.SourceARP,
		MAC:        "28:cf:da:44:55:66",
		Addresses:  addrsFor(t, "192.0.2.51"),
		ObservedAt: time.Now().UTC().Add(-2 * time.Minute),
	})
	if _, err := svc.IngestFindings(tenant, []IngestFinding{first}); err != nil {
		t.Fatalf("first ingest: %v", err)
	}

	// A later window: same device, same MAC, and this time the DHCP exchange
	// gave us its name too.
	second := observationFinding(t, &hostobs.HostObservation{
		Source:     hostobs.SourceDHCP,
		MAC:        "28:cf:da:44:55:66",
		Addresses:  addrsFor(t, "192.0.2.51"),
		Hostnames:  []string{"acct-ws-14"},
		ObservedAt: time.Now().UTC(),
	})
	if _, err := svc.IngestFindings(tenant, []IngestFinding{second}); err != nil {
		t.Fatalf("second ingest: %v", err)
	}

	var assets int
	if err := db.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).Scan(&assets); err != nil {
		t.Fatal(err)
	}
	if assets != 1 {
		t.Fatalf("%d assets for one MAC seen twice, want 1", assets)
	}

	// The name the second observation carried attaches to the asset that
	// already existed — a NEW identifier on the SAME asset, not a new asset.
	var hostnames int
	if err := db.QueryRow(`
		SELECT count(*) FROM asset_identifiers
		 WHERE tenant_id = $1 AND kind = 'hostname' AND value = 'acct-ws-14'`, tenant).Scan(&hostnames); err != nil {
		t.Fatal(err)
	}
	if hostnames != 1 {
		t.Errorf("%d hostname identifiers for the name the second window learned, want 1", hostnames)
	}
}

// A different name on a known MAC attaches a SECOND identifier rather than
// creating a second asset.
//
// This is the shape the coalescer produces in the ordinary course: a laptop that
// answers to a NetBIOS name and an mDNS .local name is one device with two
// names, and the MAC is what says so.
func TestIntegration_HostObservation_ASecondNameOnAKnownMACDoesNotDuplicate(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)

	mac := "28:cf:da:77:88:99"
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source:     hostobs.SourceNBNS,
		MAC:        mac,
		Addresses:  addrsFor(t, "192.0.2.52"),
		Hostnames:  []string{"ws1"},
		ObservedAt: time.Now().UTC().Add(-2 * time.Minute),
	})}); err != nil {
		t.Fatalf("first ingest: %v", err)
	}

	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source:     hostobs.SourceMDNS,
		MAC:        mac,
		Addresses:  addrsFor(t, "192.0.2.52"),
		FQDNs:      []string{"ws1-laptop.local"},
		Hostnames:  []string{"ws1-laptop"},
		ObservedAt: time.Now().UTC(),
	})}); err != nil {
		t.Fatalf("second ingest: %v", err)
	}

	var assets int
	if err := db.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).Scan(&assets); err != nil {
		t.Fatal(err)
	}
	if assets != 1 {
		t.Fatalf("%d assets for one MAC answering to two names, want 1", assets)
	}

	var names int
	if err := db.QueryRow(`
		SELECT count(*) FROM asset_identifiers
		 WHERE tenant_id = $1 AND kind IN ('hostname', 'fqdn')`, tenant).Scan(&names); err != nil {
		t.Fatal(err)
	}
	// ws1, ws1-laptop, ws1-laptop.local — every name the device answered to,
	// all on the one asset.
	if names != 3 {
		t.Errorf("%d name identifiers, want 3 (both short names and the fqdn) on the one asset", names)
	}
}

// A MAC-only observation still becomes an asset. This is the case the whole
// path exists for: a device that answers no name and holds no address is still
// a thing on the segment.
func TestIntegration_HostObservation_MACOnlyBecomesAnAsset(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)

	f := observationFinding(t, &hostobs.HostObservation{
		Source:     hostobs.SourceLLDP,
		MAC:        "00:1a:2f:aa:bb:cc",
		ObservedAt: time.Now().UTC(),
	})
	// The documented column compromise: no address observed.
	if *f.IPAddress != "0.0.0.0" {
		t.Fatalf("the fixture should carry the unspecified address, got %q", *f.IPAddress)
	}

	if _, err := svc.IngestFindings(tenant, []IngestFinding{f}); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}

	var assetID uuid.UUID
	var primaryAddress *string
	if err := db.QueryRow(`
		SELECT id, host(primary_address) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).
		Scan(&assetID, &primaryAddress); err != nil {
		t.Fatalf("a MAC-only observation produced no asset: %v", err)
	}
	if primaryAddress != nil {
		t.Errorf("primary_address = %q; 0.0.0.0 means NO address was observed and must not be stored as one", *primaryAddress)
	}

	var macs int
	if err := db.QueryRow(`
		SELECT count(*) FROM asset_identifiers
		 WHERE tenant_id = $1 AND asset_id = $2 AND kind = 'mac_address'`, tenant, assetID).Scan(&macs); err != nil {
		t.Fatal(err)
	}
	if macs != 1 {
		t.Errorf("%d mac_address identifiers, want 1 — the MAC is the whole identity here", macs)
	}

	// And, critically, nothing went to external_connections. An addressless
	// observation has no RFC-1918 address, which is exactly how the ownership
	// classifier used to call it third_party and write it there.
	assertNoExternalConnections(t, db, tenant)
}

// NOTHING a host observation produces may be DIVERTED to external_connections.
//
// That table records a CONNECTION between two endpoints with a protocol and a
// cipher. A host observation has no flow, no far end and no cryptography.
//
// The assertion is in two halves, and the second is the one that bites. A
// diverted observation does not merely write a wrong row — `continue` follows
// the route, so the observation never becomes an asset at all. And in fact no
// row lands either way today, because Upsert requires a non-zero dest_port and
// a host observation has none (`port = 0` means "not an endpoint"); the
// diversion presents as a pair of "ERROR routing third-party" log lines and a
// device that silently never appeared in Approvals. So counting rows alone
// would pass while every observation in the batch was being thrown away —
// which is precisely what the first draft of this test did.
func TestIntegration_HostObservation_IsNeverDivertedToExternalConnections(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)

	findings := []IngestFinding{
		// No address at all: the classifier's third_party answer, because
		// 0.0.0.0 is not RFC 1918.
		observationFinding(t, &hostobs.HostObservation{
			Source: hostobs.SourceLLDP, MAC: "00:1a:2f:00:00:01", ObservedAt: time.Now().UTC(),
		}),
		// A PUBLIC address: also third_party to the classifier, and also a
		// device on a segment we are watching rather than something we
		// connected out to.
		observationFinding(t, &hostobs.HostObservation{
			Source: hostobs.SourceARP, MAC: "00:1a:2f:00:00:02",
			Addresses: addrsFor(t, "203.0.113.10"), ObservedAt: time.Now().UTC(),
		}),
		// Names only, no MAC and no address.
		observationFinding(t, &hostobs.HostObservation{
			Source: hostobs.SourceMDNS, Hostnames: []string{"lan-only-host"},
			FQDNs: []string{"lan-only-host.local"}, ObservedAt: time.Now().UTC(),
		}),
	}

	imported, err := svc.IngestFindings(tenant, findings)
	if err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}
	if imported != len(findings) {
		t.Errorf("imported = %d, want %d — a diverted observation is a device that never reached Approvals", imported, len(findings))
	}

	var assets int
	if err := db.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).Scan(&assets); err != nil {
		t.Fatal(err)
	}
	if assets != len(findings) {
		t.Errorf("%d assets from %d host observations; the rest were routed away and lost", assets, len(findings))
	}

	assertNoExternalConnections(t, db, tenant)
	assertNoCryptoResidue(t, db, tenant)
}

// The resolver ban, driven through the REAL ingest.
//
// A unit test on a helper cannot make this claim: the resolver call lives at a
// CALL SITE (routeToExternalConnection's hostname fallback), reached from
// IngestFindings, and the thing that must never happen is that a passive
// observation gets there at all. So this drives IngestFindings with lookupHost
// swapped for a recorder.
//
// # Why one of these findings carries no ip_address
//
// The fallback only fires when the finding's ip_address is EMPTY, and the
// discovery-processor converter always fills it — with the documented 0.0.0.0
// when nothing was observed. So through today's pipeline the lookup is latent
// rather than live, and a test built only from converter-shaped fixtures would
// pass with both guards deleted. That is a property of one line
// (`if destIP == "" && f.Hostname != nil`) in a routine that neither side of
// this contract owns, and it is not something to rest a privacy guarantee on:
// `effectiveIP` two hundred lines away ALREADY normalises 0.0.0.0 to nil for
// the managed path, and the day somebody does the same for the external path —
// a reasonable tidy-up — the lookup goes live for every addressless
// observation in the fleet.
//
// So the batch carries that shape deliberately: a names-only finding with a nil
// ip_address, which is also exactly what an internal caller POSTing the ingest
// endpoint by hand produces. Mutation check: delete BOTH the branch at the top
// of IngestFindings' loop and the refusal in routeToExternalConnection, and
// this fails with "lan-only-host.local" in the recorder — a customer's internal
// host name going to whatever resolver the pod is configured with, from a
// feature whose entire premise is that it sends nothing onto the wire.
func TestIntegration_HostObservation_IngestNeverResolves(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)

	var resolved []string
	original := lookupHost
	lookupHost = func(_ context.Context, host string) ([]string, error) {
		resolved = append(resolved, host)
		return nil, nil
	}
	t.Cleanup(func() { lookupHost = original })

	namesOnly := observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceMDNS, Hostnames: []string{"lan-only-host"},
		FQDNs: []string{"lan-only-host.local"}, ObservedAt: time.Now().UTC(),
	})
	namesOnly.IPAddress = nil

	findings := []IngestFinding{
		namesOnly,
		observationFinding(t, &hostobs.HostObservation{
			Source: hostobs.SourceNBNS, MAC: "00:1a:2f:00:00:03",
			Hostnames: []string{"ws-accounting"}, ObservedAt: time.Now().UTC(),
		}),
	}
	if _, err := svc.IngestFindings(tenant, findings); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}

	if len(resolved) > 0 {
		t.Fatalf("host observation ingest resolved %v — those names exist only on the customer's LAN", resolved)
	}
	assertNoExternalConnections(t, db, tenant)
}

// A contested MAC opens a merge proposal AND the batch continues.
//
// One contested host in a thousand-observation sensor run must not discard every
// observation after it — which is what the ingest did before the Zero() check,
// aborting the whole batch with a parse error naming no asset.
func TestIntegration_HostObservation_ContestedMACProposesAndTheBatchContinues(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)

	mac := "28:cf:da:ab:cd:ef"

	// Two existing assets, each already owning one of the identifiers the
	// contested observation will carry. Neither can decide, so the engine has
	// to ask a human.
	first := observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceARP, MAC: mac, ObservedAt: time.Now().UTC().Add(-time.Hour),
	})
	if _, err := svc.IngestFindings(tenant, []IngestFinding{first}); err != nil {
		t.Fatalf("seed the MAC's owner: %v", err)
	}
	named := observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceMDNS, FQDNs: []string{"contested.local"},
		Hostnames: []string{"contested"}, ObservedAt: time.Now().UTC().Add(-time.Hour),
	})
	if _, err := svc.IngestFindings(tenant, []IngestFinding{named}); err != nil {
		t.Fatalf("seed the name's owner: %v", err)
	}

	var before int
	if err := db.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if before != 2 {
		t.Fatalf("the fixture produced %d assets, want 2 distinct ones to contest", before)
	}

	// Now an observation carrying BOTH: the MAC one asset owns and the name the
	// other does. Followed by an ordinary one, which must still land.
	contested := observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceDHCP, MAC: mac, FQDNs: []string{"contested.local"},
		Hostnames: []string{"contested"}, ObservedAt: time.Now().UTC(),
	})
	after := observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceARP, MAC: "28:cf:da:ff:ee:dd",
		Addresses: addrsFor(t, "192.0.2.77"), ObservedAt: time.Now().UTC(),
	})

	if _, err := svc.IngestFindings(tenant, []IngestFinding{contested, after}); err != nil {
		t.Fatalf("a contested observation aborted the batch: %v", err)
	}

	// A merge proposal is an asset_history row, not a table of its own — see
	// idx_asset_history_pending_merge_proposal.
	var proposals int
	if err := db.QueryRow(`
		SELECT count(*) FROM asset_history
		 WHERE tenant_id = $1 AND action = 'merge_proposed'`, tenant).Scan(&proposals); err != nil {
		t.Fatalf("read merge proposals: %v", err)
	}
	if proposals == 0 {
		t.Error("no merge proposal was opened for an observation whose identifiers belong to two assets")
	}

	// The observation AFTER the contested one still became an asset. This is
	// the half that regressed before: the batch aborted and everything behind
	// the contested row was lost.
	var landed int
	if err := db.QueryRow(`
		SELECT count(*) FROM asset_identifiers
		 WHERE tenant_id = $1 AND kind = 'mac_address' AND value = '28:cf:da:ff:ee:dd'`, tenant).Scan(&landed); err != nil {
		t.Fatal(err)
	}
	if landed != 1 {
		t.Errorf("the observation after the contested one did not land; the batch stopped early")
	}
}

func assertNoExternalConnections(t *testing.T, db *database.DB, tenant uuid.UUID) {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM external_connections WHERE tenant_id = $1`, tenant).Scan(&n); err != nil {
		t.Fatalf("read external_connections: %v", err)
	}
	if n != 0 {
		t.Errorf("%d external_connections row(s) from host observations; that table records connections, and there were none", n)
	}
}

func assertNoCryptoResidue(t *testing.T, db *database.DB, tenant uuid.UUID) {
	t.Helper()
	for _, table := range []string{"crypto_implementations", "certificates"} {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM `+table+` WHERE tenant_id = $1`, tenant).Scan(&n); err != nil {
			t.Fatalf("read %s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%d %s row(s) from a host observation, which measured no cryptography", n, table)
		}
	}
}

// The whole ingest runs under RLS, as the non-owner app role, and one tenant's
// observations are invisible to the other.
//
// The fixture above connects as the table OWNER, for which RLS is INERT unless
// the table declares FORCE ROW LEVEL SECURITY — and none here does. So every
// other test in this file proves the rows land and nothing about whether they
// land isolated: take away the `app.tenant_id` the engine's transaction sets
// and they would all still pass. That is the shape that shipped a release where
// `serviceRls` default-ON broke every plain-pool query silently.
//
// So this one opens the app role and drives the real ingest through it. With
// RLS live, a write that reaches the database OUTSIDE the tenant transaction
// fails closed instead of succeeding invisibly — so the asset, its identifiers
// AND its facts all landing is itself the assertion that the whole unit ran
// inside one tenant session. `UpsertFacts` is the one most at risk: it runs on
// the ENGINE's transaction deliberately, and on the service's own repository it
// would take a second connection off the pool with no tenant set.
//
// The tenant contract is the wire contract's §3 — a MAC seen on two customers'
// segments is two assets, and there is no cross-tenant sharing of host identity
// — so both observations below carry the SAME MAC, which is what makes the
// isolation assertion able to fail.
func TestIntegration_HostObservation_IngestIsTenantIsolatedUnderRLS(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenantA := testdb.NewTenant(t, owner)
	tenantB := testdb.NewTenant(t, owner)

	app := testdb.ConnectAsAppRole(t, owner)
	db := &database.DB{DB: sqlx.NewDb(app, "postgres")}
	algorithms := NewAlgorithmService(db)
	svc := &AssetService{
		db:                    db,
		algorithmService:      algorithms,
		networkSegmentService: NewNetworkSegmentService(db, nil),
	}
	svc.SetExternalConnectionsService(NewExternalConnectionsService(db, algorithms))

	const mac = "28:cf:da:be:ef:01"
	for _, tc := range []struct {
		tenant uuid.UUID
		name   string
	}{
		{tenantA, "a-printer"},
		{tenantB, "b-printer"},
	} {
		f := observationFinding(t, &hostobs.HostObservation{
			Source: hostobs.SourceMDNS, MAC: mac,
			Hostnames: []string{tc.name}, FQDNs: []string{tc.name + ".local"},
			Services:   []string{"_ipp._tcp"},
			ObservedAt: time.Now().UTC(),
		})
		imported, err := svc.IngestFindings(tc.tenant, []IngestFinding{f})
		if err != nil {
			t.Fatalf("IngestFindings for %s: %v", tc.name, err)
		}
		if imported != 1 {
			t.Fatalf("%s: imported = %d, want 1 — the write did not survive RLS", tc.name, imported)
		}
	}

	// Read back AS EACH TENANT, on the app role, so the policy narrows the
	// query rather than a WHERE clause this test wrote.
	for name, tenant := range map[string]uuid.UUID{"A": tenantA, "B": tenantB} {
		var hostname string
		var assetID uuid.UUID
		var identifiers, facts int

		asTenant(t, app, tenant, func(tx *sql.Tx) {
			if err := tx.QueryRow(`
				SELECT a.id, a.hostname
				  FROM assets a
				  JOIN asset_identifiers i ON i.asset_id = a.id AND i.tenant_id = a.tenant_id
				 WHERE i.kind = 'mac_address' AND i.value = $1 AND a.deleted_at IS NULL`, mac).
				Scan(&assetID, &hostname); err != nil {
				t.Fatalf("tenant %s: reading its own asset back under RLS: %v", name, err)
			}
			// Exactly one. Were RLS inert here, one MAC would return TWO rows
			// and the Scan above would have silently taken whichever came
			// first — which is how an isolation test ends up proving that two
			// tenants have one asset each and nothing more.
			if err := tx.QueryRow(`SELECT count(*) FROM asset_identifiers WHERE kind = 'mac_address' AND value = $1`, mac).
				Scan(&identifiers); err != nil {
				t.Fatalf("tenant %s: counting identifiers: %v", name, err)
			}
			if err := tx.QueryRow(`SELECT count(*) FROM asset_facts WHERE asset_id = $1`, assetID).
				Scan(&facts); err != nil {
				t.Fatalf("tenant %s: counting facts: %v", name, err)
			}
		})

		// The short hostname, because hostObservationBestName ranks a DHCP-style
		// name above a human `.local` (hex `.local` is even lower).
		if want := strings.ToLower(name) + "-printer"; hostname != want {
			t.Errorf("tenant %s sees hostname %q, want %q — one MAC on two segments is two assets", name, hostname, want)
		}
		if identifiers != 1 {
			t.Errorf("tenant %s can see %d mac_address identifiers for one MAC, want 1 — RLS did not narrow the read", name, identifiers)
		}
		if facts == 0 {
			t.Errorf("tenant %s: the asset has no facts; hw.vendor and net.mdns_services did not survive the tenant session", name)
		}
	}
}

// asTenant runs fn inside a transaction with `app.tenant_id` set for its
// duration, which is what the RLS policies read.
//
// A transaction and SET LOCAL rather than a session `set_config` on the *sql.DB:
// that is a POOL, so a session-scoped setting applies to whichever connection
// happened to serve the statement that set it, and the next query can land on a
// different one with nothing set — which fails closed, reads as "the row is not
// there", and would look exactly like the isolation this test is asserting.
func asTenant(t *testing.T, db *sql.DB, tenant uuid.UUID, fn func(tx *sql.Tx)) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.tenant_id', $1, true)`, tenant.String()); err != nil {
		t.Fatalf("set app.tenant_id: %v", err)
	}
	fn(tx)
}

func TestIntegration_HostObservation_ProjectsSiteWithoutListeners(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	location, segment := uuid.New(), uuid.New()
	if _, err := db.Exec(`INSERT INTO locations(id,tenant_id,name,location_type) VALUES($1,$2,'North','site')`, location, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment,location_id) VALUES($1,$2,'North','cidr','192.0.2.0/24','production',$3)`, segment, tenant, location); err != nil {
		t.Fatal(err)
	}
	ho := &hostobs.HostObservation{Source: hostobs.SourceARP, MAC: "00:1a:2b:11:22:33", Addresses: addrsFor(t, "192.0.2.50"), ObservedAt: time.Now().UTC()}
	var firstID uuid.UUID
	for i := 0; i < 2; i++ {
		if i == 1 {
			ho.Source = hostobs.SourceMDNS
			ho.FQDNs = []string{"improved.example.test"}
		}
		if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, ho)}); err != nil {
			t.Fatal(err)
		}
		var id uuid.UUID
		var site, loc, class, name string
		if err := db.QueryRow(`SELECT id,site,location_id::text,class_key,coalesce(hostname,'') FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL`, tenant).Scan(&id, &site, &loc, &class, &name); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstID = id
		} else if firstID != id {
			t.Fatal("name changed identity")
		}
		if i == 1 && name != "improved.example.test" {
			t.Fatalf("name promotion=%q", name)
		}

		if site != "North" || loc != location.String() || class != "unknown_host" {
			t.Fatalf("placement/class=%s %s %s", site, loc, class)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM asset_history WHERE asset_id=$1 AND changes_json ? 'location_id'`, firstID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("placement histories=%d", n)
	}
}

func TestIntegration_HostObservation_RetainsTypedEvidenceBeforeResolution(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	if _, err := svc.identityEngine(); err != nil {
		t.Fatal(err)
	}
	var err error
	svc.identityEng, err = identity.New(identity.Config{Repo: svc.identityRepo, AdmissionEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"}}')
 ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
		t.Fatal(err)
	}
	seen := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Microsecond)
	ho := &hostobs.HostObservation{ObservedAt: seen, Source: hostobs.SourceMDNS, FQDNs: []string{uuid.NewString() + ".local"},
		Services: []string{"_ipp._tcp"}, Attributes: map[string]interface{}{"password": "must-not-persist", "mdns_service_port": 631}}
	finding := observationFinding(t, ho)
	finding.RawData["password"] = "must-not-persist"
	finding.RawData["discovery_method"] = "pcap_upload"
	finding.RawData["confidence_score"] = 0.45
	res, err := svc.ingestHostObservation(context.Background(), tenant, finding, "monitoring")
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != identity.OutcomeUnresolved || res.ObservationID == "" || !res.Asset.Zero() {
		t.Fatalf("weak host created asset: %+v", res)
	}
	var payload []byte
	if err := db.QueryRow(`SELECT payload FROM identity_observation_payloads WHERE tenant_id=$1 AND observation_id=$2`, tenant, res.ObservationID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "must-not-persist") {
		t.Fatal("retained arbitrary secret metadata")
	}
	var retained IngestFinding
	if err := json.Unmarshal(payload, &retained); err != nil {
		t.Fatal(err)
	}
	if hostObservationSource(retained) != hostObservationSource(finding) || hostObservationFactProducer(retained) != hostObservationFactProducer(finding) || findingConfidence(retained) != 0.45 {
		t.Fatal("retention changed source or confidence")
	}
	asset := seedAsset(t, db, tenant, "Operator selected host", "server", "hardware.computer.server", "production", 0, 0)
	if err := svc.materializeRetainedHostObservation(context.Background(), tenant, asset, retained); err != nil {
		t.Fatal(err)
	}
	if err := svc.materializeRetainedHostObservation(context.Background(), tenant, asset, retained); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM asset_facts WHERE tenant_id=$1 AND asset_id=$2 AND key='net.mdns_services'`, tenant, asset).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("typed retained service facts=%d want 1", count)
	}
}

func TestIntegration_HostObservation_RetainedUnverifiedAgentCannotLinkSensor(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	sensor := uuid.New()
	if _, err := db.Exec(`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status)
 VALUES($1,$2,'Real sensor','linux','1.0','datacenter_host','active')`, sensor, tenant); err != nil {
		t.Fatal(err)
	}
	asset := seedAsset(t, db, tenant, "Operator selected host", "unknown_host", "unknown_host", "production", 0, 0)
	for _, sourceSensor := range []string{"", uuid.NewString()} {
		finding := observationFinding(t, &hostobs.HostObservation{ObservedAt: time.Now().UTC().Add(-time.Hour), Source: hostobs.SourceMDNS,
			AgentID: sensor.String(), Platform: "linux", Profile: "datacenter_host", FQDNs: []string{"unverified.local"}})
		finding.SourceSensorID = &sourceSensor
		finding.RawData["discovery_method"] = "sensor_self_report"
		if err := svc.materializeRetainedHostObservation(context.Background(), tenant, asset, finding); err != nil {
			t.Fatal(err)
		}
	}
	var linked sql.NullString
	var class string
	if err := db.QueryRow(`SELECT asset_id FROM sensors WHERE tenant_id=$1 AND id=$2`, tenant, sensor).Scan(&linked); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT class_key FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, asset).Scan(&class); err != nil {
		t.Fatal(err)
	}
	if linked.Valid || class != "unknown_host" {
		t.Fatalf("unverified agent changed association/class: %v %s", linked, class)
	}
}

func TestIntegration_HostObservation_SelfReportUsesSensorNamespace(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	sensor := uuid.New()
	if _, err := db.Exec(`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status)
 VALUES($1,$2,'Sensor','windows','1.0','datacenter_host','active')`, sensor, tenant); err != nil {
		t.Fatal(err)
	}
	finding := observationFinding(t, &hostobs.HostObservation{
		AgentID: sensor.String(), Platform: "windows", Hostnames: []string{"same-host"}, ObservedAt: time.Now().UTC(),
		MAC: "00:11:22:33:44:55", Addresses: addrsFor(t, "192.0.2.10"),
	})
	finding.SourceSensorID = ptr(sensor.String())
	finding.RawData["discovery_method"] = "sensor_self_report"
	ho, ok := hostObservationPayload(finding)
	if !ok {
		t.Fatal("missing payload")
	}
	observation, err := svc.hostObservationObservation(tenant, finding, ho)
	if err != nil {
		t.Fatal(err)
	}
	if !observation.Admission.Authoritative {
		t.Fatal("verified self-report lost authority")
	}
	found := false
	for _, id := range observation.Identifiers {
		if id.Kind == identity.KindAgentID {
			t.Fatal("sensor still uses device-agent namespace")
		}
		found = found || (id.Kind == identity.KindSensorID && id.Value == sensor.String())
	}
	if !found {
		t.Fatal("sensor identifier missing")
	}
	if _, err := db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"}}') ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason) SELECT $1,id,'{"quantity":10}'::jsonb,'collector identity regression' FROM billable_items WHERE key='max_assets'`, tenant); err != nil {
		t.Fatal(err)
	}
	repo := pgidentity.New(db.DB.DB)
	engine, err := identity.New(identity.Config{Repo: repo, AdmissionEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(obs identity.Observation) (identity.Resolution, error) {
		var result identity.Resolution
		err := repo.RunInTx(context.Background(), tenant.String(), func(bound *pgidentity.Repository) error {
			var resolveErr error
			result, resolveErr = engine.WithRepository(bound).Resolve(context.Background(), obs)
			return resolveErr
		})
		return result, err
	}
	sensorResult, err := resolve(observation)
	if err != nil {
		t.Fatal(err)
	}
	agent := identity.Observation{
		TenantID: tenant.String(), ClassHint: "computer", ObservedAt: time.Now().UTC(),
		Source:    identity.Source{Kind: identity.SourceMeasured, Ref: "agent:installation"},
		Admission: identity.AdmissionEvidence{Authoritative: true},
		Identifiers: []identity.Identifier{
			{Kind: identity.KindAgentID, Value: "installation"},
			{Kind: identity.KindSerialNumber, Value: "TEST-SERIAL"},
			{Kind: identity.KindMACAddress, Value: "00:11:22:33:44:55"},
			{Kind: identity.KindMACAddress, Value: "00:11:22:33:44:66"},
		},
	}
	agentResult, err := resolve(agent)
	if err != nil {
		t.Fatal(err)
	}
	if agentResult.Outcome != identity.OutcomeMatched || agentResult.Asset != sensorResult.Asset {
		t.Fatalf("same host separated under enforcement: sensor=%+v agent=%+v", sensorResult, agentResult)
	}
	var status string
	if err := db.QueryRow(`SELECT identity_status FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, agentResult.Asset.ID).Scan(&status); err != nil || status != "established" {
		t.Fatalf("identity status=%s err=%v", status, err)
	}
}

func TestIntegration_HostObservation_UpgradePreservesSensorIdentifierOwnership(t *testing.T) {
	_, db, tenant := newHostObsFixture(t)
	sensor := uuid.New()
	asset := seedAsset(t, db, tenant, "Existing sensor host", "workstation", "hardware.computer.workstation", "production", 0, 0)
	seen := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	if _, err := db.Exec(`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status)
 VALUES($1,$2,'Sensor','windows','1.0','datacenter_host','active')`, sensor, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO asset_identifiers(tenant_id,asset_id,kind,value,source_kind,source_ref,confidence,first_seen_at,last_seen_at)
 VALUES($1,$2,'agent_id',$3,'measured',$4,1,$5,$5),
       ($1,$2,'agent_id','device-agent-installation','measured','agent:device-agent-installation',1,$5,$5)`, tenant, asset, sensor.String(), "sensor:"+sensor.String(), seen); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		testdb.ForceApplySchema(t, db.DB.DB)
		var owner uuid.UUID
		var firstSeen, lastSeen time.Time
		if err := db.QueryRow(`SELECT asset_id,first_seen_at,last_seen_at FROM asset_identifiers WHERE tenant_id=$1 AND kind='sensor_id' AND value=$2`, tenant, sensor.String()).Scan(&owner, &firstSeen, &lastSeen); err != nil {
			t.Fatal(err)
		}
		if owner != asset || !firstSeen.Equal(seen) || !lastSeen.Equal(seen) {
			t.Fatalf("upgrade changed ownership or clocks: %v %v %v", owner, firstSeen, lastSeen)
		}
		var agents int
		if err := db.QueryRow(`SELECT count(*) FROM asset_identifiers WHERE tenant_id=$1 AND asset_id=$2 AND kind='agent_id'`, tenant, asset).Scan(&agents); err != nil || agents != 1 {
			t.Fatalf("device-agent identity changed: count=%d err=%v", agents, err)
		}
	}
}
