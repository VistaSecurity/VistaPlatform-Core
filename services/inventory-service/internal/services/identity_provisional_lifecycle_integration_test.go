package services

// The cross-VLAN provisional lifecycle, end to end against a real Postgres
// (spec docsv4/internal/developer/standards/features/cross-vlan-provisional-inventory.md).
//
// The scenario every sub-test here is about: a sensor on VLAN A hears a
// REFLECTED mDNS advert for a printer that lives on VLAN B. Before that
// evidence became an `identity_observation` no inventory surface could show,
// enrichment could never reach it (the only candidate collector was the one
// that by construction had no interface on VLAN B), and when a sensor was later
// deployed on VLAN B the two halves of the story had no way to become one item.
//
// These tests drive the PRODUCTION engine constructor — `svc.identityEngine()`,
// not a hand-built one — because the flag that turns the whole feature on lives
// there. Building an engine here with `ProvisionalInventory: true` would keep
// every assertion below green while the shipped binary did nothing.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/identityenrichment"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// RFC 5737 documentation networks, one per VLAN, and an RFC 7042
// universally-administered documentation MAC. A locally-administered MAC would
// be dropped as an identifier before it ever reached the engine, which would
// make the corroboration half of these tests pass for the wrong reason.
const (
	provSegmentACIDR = "192.0.2.0/24"
	provSegmentBCIDR = "198.51.100.0/24"
	provSensorAAddr  = "192.0.2.10"
	provSensorBAddr  = "198.51.100.9"
	provPrinterAddr  = "198.51.100.7"
	provPrinterMAC   = "00:00:5e:00:53:07"
	provPrinterName  = "crossvlan-printer"
)

type provisionalFixture struct {
	t       *testing.T
	raw     *sql.DB
	db      *database.DB
	svc     *AssetService
	tenant  uuid.UUID
	segA    uuid.UUID
	segB    uuid.UUID
	sensorA uuid.UUID
	sensorB uuid.UUID
	now     time.Time
}

func newProvisionalFixture(t *testing.T) *provisionalFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	svc := NewAssetService(db)
	if _, err := svc.identityEngine(); err != nil {
		t.Fatal(err)
	}
	f := &provisionalFixture{
		t: t, raw: raw, db: db, svc: svc, tenant: tenant,
		segA: uuid.New(), segB: uuid.New(), sensorA: uuid.New(), sensorB: uuid.New(),
		now: time.Now().UTC().Truncate(time.Microsecond),
	}
	f.exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,is_active,environment) VALUES($1,$2,'VLAN A','cidr',$3,true,'production')`, f.segA, tenant, provSegmentACIDR)
	f.exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,is_active,environment) VALUES($1,$2,'VLAN B','cidr',$3,true,'production')`, f.segB, tenant, provSegmentBCIDR)
	f.enrollSensor(f.sensorA, tenant, "sensor-a", provSensorAAddr)
	f.enrollSensor(f.sensorB, tenant, "sensor-b", provSensorBAddr)
	f.exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"},"identity_enrichment":{"enabled":true}}') ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant)
	f.exec(`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason) SELECT $1,id,'{"quantity":10}','provisional lifecycle regression' FROM billable_items WHERE key='max_assets'`, tenant)
	return f
}

// actor creates a tenant user to attribute a decision to. asset_history's
// actor_user_id is a real foreign key, so an operator action needs a real
// operator.
func (f *provisionalFixture) actor() uuid.UUID {
	f.t.Helper()
	id := uuid.New()
	f.exec(`INSERT INTO users(id,tenant_id,email,is_active) VALUES($1,$2,$3,true)`, id, f.tenant, "op-"+id.String()[:8]+"@example.test")
	return id
}

// retainBlockedObservation writes the row shape a pre- deployment left
// behind: unresolved, no asset, and blocked on a collector reason that no
// longer exists as a producer. The fingerprint is computed the way
// StoreObservation computes it, so when the engine re-stores this evidence it
// upserts THIS row rather than inserting a second one.
func (f *provisionalFixture) retainBlockedObservation(evidence identity.Observation) uuid.UUID {
	f.t.Helper()
	id := uuid.New()
	raw, err := json.Marshal(evidence)
	if err != nil {
		f.t.Fatal(err)
	}
	f.exec(`INSERT INTO identity_observations(tenant_id,id,fingerprint,source_kind,source_ref,collector_version,network_scope,evidence,admission_reasons,state,enrichment_state,enrichment_reason,first_seen_at,last_seen_at)
	 VALUES($1,$2,$3,'measured',$4,'test-v1',$5,$6,ARRAY['unverified_relayed_advertisement'],'unresolved','blocked','observing_collector_unreachable',$7,$7)`,
		f.tenant, id, identity.ObservationFingerprint(evidence), evidence.Source.Ref, evidence.Network.SegmentID, string(raw), evidence.ObservedAt)
	return id
}

// retainObservation writes an identity_observations row for evidence that has
// not been through the engine, which the enrichment job tables have a foreign
// key to.
func (f *provisionalFixture) retainObservation(evidence identity.Observation) uuid.UUID {
	f.t.Helper()
	id := uuid.New()
	raw, err := json.Marshal(evidence)
	if err != nil {
		f.t.Fatal(err)
	}
	f.exec(`INSERT INTO identity_observations(tenant_id,id,fingerprint,source_kind,source_ref,network_scope,evidence,first_seen_at,last_seen_at)
	 VALUES($1,$2,$3,'measured',$4,$5,$6,$7,$7)`, f.tenant, id, identity.ObservationFingerprint(evidence), evidence.Source.Ref, evidence.Network.SegmentID, string(raw), evidence.ObservedAt)
	return id
}

func (f *provisionalFixture) exec(query string, args ...any) {
	f.t.Helper()
	if _, err := f.raw.Exec(query, args...); err != nil {
		f.t.Fatalf("%s: %v", query, err)
	}
}

// enrollSensor creates a live, DNS-capable sensor with one reported interface
// address. Everything the executor rule reads — heartbeat, profile, tags,
// air-gap, the reported DNS interface allowlist, the address's own freshness —
// is set here, so each sub-test only has to break the one it is about.
func (f *provisionalFixture) enrollSensor(id, tenant uuid.UUID, name, address string) {
	f.t.Helper()
	f.exec(`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status,last_heartbeat,network_interfaces,reported_capabilities,reported_dns_interfaces)
	 VALUES($1,$2,$3,'linux','test-v1','datacenter_host','active',$4,ARRAY['eth0'],ARRAY['identity_dns_v1'],ARRAY['eth0'])`, id, tenant, name, f.now)
	f.exec(`INSERT INTO agent_addresses(sensor_id,interface_name,address,prefix_length,last_seen_at) VALUES($1,'eth0',$2::inet,24,$3)`, id, address, f.now)
}

// relayedAdvert is the reflected mDNS advertisement: a sensor repeating what it
// overheard, never having touched the device. `Relayed` is what makes
// AssessAdmission refuse to establish anything from it.
func (f *provisionalFixture) relayedAdvert(sensor uuid.UUID, receipt string, at time.Time, extra ...identity.Identifier) identity.Observation {
	return f.relayedAdvertOn(f.segB, provPrinterName, provPrinterAddr, sensor, receipt, at, extra...)
}

func (f *provisionalFixture) relayedAdvertOn(segment uuid.UUID, hostname, address string, sensor uuid.UUID, receipt string, at time.Time, extra ...identity.Identifier) identity.Observation {
	ids := []identity.Identifier{
		{Kind: identity.KindHostname, Value: hostname, Scope: segment.String()},
		{Kind: identity.KindIPAddress, Value: address, Scope: segment.String()},
	}
	return identity.Observation{
		TenantID:    f.tenant.String(),
		Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:" + sensor.String()},
		ObservedAt:  at,
		Network:     identity.Network{SegmentID: segment.String(), Ownership: identity.OwnershipInternal},
		Admission:   identity.AdmissionEvidence{Relayed: true, ReceiptID: receipt, CollectorVersion: "test-v1"},
		Confidence:  0.5,
		Hostname:    hostname,
		Identifiers: append(ids, extra...),
	}
}

// directSighting is the collector that actually met the printer: an ARP
// observation from a sensor on the printer's own segment, carrying the one
// thing hearsay can never carry — the interface's hardware address.
func (f *provisionalFixture) directSighting(sensor uuid.UUID, receipt string, at time.Time) identity.Observation {
	return identity.Observation{
		TenantID:   f.tenant.String(),
		Source:     identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:" + sensor.String()},
		ObservedAt: at,
		Network:    identity.Network{SegmentID: f.segB.String(), Ownership: identity.OwnershipInternal},
		Admission:  identity.AdmissionEvidence{Direct: true, ReceiptID: receipt, CollectorVersion: "test-v1"},
		Confidence: 1,
		Hostname:   provPrinterName,
		Identifiers: []identity.Identifier{
			{Kind: identity.KindHostname, Value: provPrinterName, Scope: f.segB.String()},
			{Kind: identity.KindIPAddress, Value: provPrinterAddr, Scope: f.segB.String()},
			{Kind: identity.KindMACAddress, Value: provPrinterMAC},
		},
	}
}

func (f *provisionalFixture) assetCount() int {
	f.t.Helper()
	var n int
	if err := f.raw.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL`, f.tenant).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *provisionalFixture) assetStatuses(assetID string) (identityStatus, assetStatus, segment string) {
	f.t.Helper()
	var seg sql.NullString
	if err := f.raw.QueryRow(`SELECT identity_status,asset_status,network_segment_id::text FROM assets WHERE tenant_id=$1 AND id=$2`, f.tenant, assetID).
		Scan(&identityStatus, &assetStatus, &seg); err != nil {
		f.t.Fatal(err)
	}
	return identityStatus, assetStatus, seg.String
}

func (f *provisionalFixture) observationRow(id string) (state string, assetID string, firstSeen time.Time, materializedAt sql.NullTime) {
	f.t.Helper()
	var linked sql.NullString
	if err := f.raw.QueryRow(`SELECT state,asset_id::text,first_seen_at,materialized_at FROM identity_observations WHERE tenant_id=$1 AND id=$2`, f.tenant, id).
		Scan(&state, &linked, &firstSeen, &materializedAt); err != nil {
		f.t.Fatal(err)
	}
	return state, linked.String, firstSeen, materializedAt
}

func (f *provisionalFixture) historyActions(assetID string) []string {
	f.t.Helper()
	rows, err := f.raw.Query(`SELECT action,COALESCE(changes_json::text,'{}') FROM asset_history WHERE tenant_id=$1 AND asset_id=$2 ORDER BY created_at,id`, f.tenant, assetID)
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var action, changes string
		if err := rows.Scan(&action, &changes); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, action+" "+changes)
	}
	if err := rows.Err(); err != nil {
		f.t.Fatal(err)
	}
	return out
}

func containsAll(entries []string, needles ...string) bool {
	for _, needle := range needles {
		found := false
		for _, entry := range entries {
			if strings.Contains(entry, needle) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func TestIntegration_CrossVLANProvisionalLifecycle(t *testing.T) {
	t.Run("advert_first", testProvisionalAdvertFirst)
	t.Run("direct_first", testProvisionalDirectFirst)
	t.Run("existing_retained_observation_backfill", testProvisionalBackfill)
	t.Run("executor_selection", testProvisionalExecutorSelection)
	t.Run("no_duplicate_in_flight_work", testProvisionalNoDuplicateInFlightWork)
	t.Run("actions", testProvisionalObservationActions)
	t.Run("retention", testProvisionalRetention)
	t.Run("api", testProvisionalAPI)
}

// testProvisionalAdvertFirst is the headline journey: hearsay becomes a visible
// inventory item, and the collector that later MEETS the device corroborates
// that same item rather than creating a second one.
func testProvisionalAdvertFirst(t *testing.T) {
	f := newProvisionalFixture(t)
	ctx := context.Background()

	advertAt := f.now.Add(-time.Hour)
	advert, err := f.svc.resolveObservationWith(ctx, f.relayedAdvert(f.sensorA, "advert-1", advertAt), nil)
	if err != nil {
		t.Fatal(err)
	}
	if advert.Outcome != identity.OutcomeProvisional || advert.Asset.Zero() {
		t.Fatalf("relayed advert on a configured segment did not become a provisional item: %+v", advert)
	}
	identityStatus, assetStatus, segment := f.assetStatuses(advert.Asset.ID)
	if identityStatus != "provisional" || assetStatus != "pending_approval" || segment != f.segB.String() {
		t.Fatalf("provisional asset wrong: identity=%s status=%s segment=%s (want segment B %s)", identityStatus, assetStatus, segment, f.segB)
	}
	state, linked, firstSeen, _ := f.observationRow(advert.ObservationID)
	if state != "unresolved" || linked != advert.Asset.ID {
		t.Fatalf("observation must stay unresolved WITH its asset so enrichment keeps working: state=%s asset=%s", state, linked)
	}

	// A provisional guess must not spend the tenant's paid inventory.
	if err := f.svc.identityRepo.RunInTx(ctx, f.tenant.String(), func(repo *pgidentity.Repository) error {
		allowed, err := repo.CheckAdmissionAllowance(ctx, f.tenant.String())
		if err != nil {
			return err
		}
		var counted int
		if err := repo.Tx().QueryRowContext(ctx, `SELECT count(*) FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL AND identity_status<>'provisional'`, f.tenant).Scan(&counted); err != nil {
			return err
		}
		if !allowed || counted != 0 {
			return fmt.Errorf("provisional asset consumed allowance: allowed=%v counted=%d", allowed, counted)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	directAt := f.now.Add(-time.Minute)
	direct, err := f.svc.resolveObservationWith(ctx, f.directSighting(f.sensorB, "arp-1", directAt), nil)
	if err != nil {
		t.Fatal(err)
	}
	if direct.Asset.ID != advert.Asset.ID {
		t.Fatalf("direct evidence created a SECOND asset (%s) instead of corroborating %s", direct.Asset.ID, advert.Asset.ID)
	}
	identityStatus, _, _ = f.assetStatuses(advert.Asset.ID)
	if identityStatus != "established" {
		t.Fatalf("corroboration did not promote the provisional item: identity_status=%s", identityStatus)
	}
	var macs int
	if err := f.raw.QueryRow(`SELECT count(*) FROM asset_identifiers WHERE tenant_id=$1 AND asset_id=$2 AND kind='mac_address' AND value=$3`, f.tenant, advert.Asset.ID, provPrinterMAC).Scan(&macs); err != nil || macs != 1 {
		t.Fatalf("the MAC the collector actually measured was not attached: %d %v", macs, err)
	}

	history := f.historyActions(advert.Asset.ID)
	if !containsAll(history, `"identity_status": "provisional"`) {
		t.Fatalf("history does not record the item being CREATED provisional: %v", history)
	}
	if !containsAll(history, `"corroborated_provisional": true`) {
		t.Fatalf("history does not record the corroboration: %v", history)
	}
	if !containsAll(history, `"from": "provisional"`, `"to": "established"`) {
		t.Fatalf("history does not record the identity_status promotion: %v", history)
	}

	// The advert's own clock is evidence about when it was heard. Promotion
	// must not rewrite it.
	promotedState, linked, refreshedFirstSeen, _ := f.observationRow(advert.ObservationID)
	if promotedState != "unresolved" || linked != advert.Asset.ID || !refreshedFirstSeen.Equal(firstSeen) {
		t.Fatalf("promotion changed the advert observation: state=%s asset=%s first_seen=%s (was %s)", promotedState, linked, refreshedFirstSeen, firstSeen)
	}
	directState, directLinked, _, _ := f.observationRow(direct.ObservationID)
	if directLinked != advert.Asset.ID || directState != "linked" {
		t.Fatalf("direct observation not linked to the same item: state=%s asset=%s", directState, directLinked)
	}
	if n := f.assetCount(); n != 1 {
		t.Fatalf("assets=%d, want exactly one — the whole point is that no duplicate exists", n)
	}
}

// testProvisionalDirectFirst is the same two pieces of evidence in the other
// order. A later advert about an ESTABLISHED asset is supporting evidence: it
// links, it moves last-seen to the moment it was HEARD, and it attaches
// nothing — an alias nobody checked must not become part of an identity
// somebody did.
func testProvisionalDirectFirst(t *testing.T) {
	f := newProvisionalFixture(t)
	ctx := context.Background()

	directAt := f.now.Add(-time.Hour)
	direct, err := f.svc.resolveObservationWith(ctx, f.directSighting(f.sensorB, "arp-1", directAt), nil)
	if err != nil {
		t.Fatal(err)
	}
	if direct.Asset.Zero() || direct.Outcome != identity.OutcomeCreated {
		t.Fatalf("direct sighting did not create an asset: %+v", direct)
	}
	established, _, _ := f.assetStatuses(direct.Asset.ID)
	if established != "established" {
		t.Fatalf("identity_status=%s, want established", established)
	}

	// Later than the direct sighting, so "last_seen_at == the advert's own
	// observed time" is a claim only a correct Touch can satisfy.
	advertAt := f.now.Add(-time.Minute)
	alias := identity.Identifier{Kind: identity.KindHostname, Value: provPrinterName + "-alias", Scope: f.segB.String()}
	advert, err := f.svc.resolveObservationWith(ctx, f.relayedAdvert(f.sensorA, "advert-1", advertAt, alias), nil)
	if err != nil {
		t.Fatal(err)
	}
	if advert.Outcome != identity.OutcomeSupporting || advert.Asset.ID != direct.Asset.ID {
		t.Fatalf("advert about a known asset should be supporting evidence for it: %+v", advert)
	}
	var aliases int
	if err := f.raw.QueryRow(`SELECT count(*) FROM asset_identifiers WHERE tenant_id=$1 AND value=$2`, f.tenant, alias.Value).Scan(&aliases); err != nil || aliases != 0 {
		t.Fatalf("an unverified alias was written onto an established asset: %d %v", aliases, err)
	}
	var lastSeen time.Time
	if err := f.raw.QueryRow(`SELECT last_seen_at FROM assets WHERE tenant_id=$1 AND id=$2`, f.tenant, direct.Asset.ID).Scan(&lastSeen); err != nil {
		t.Fatal(err)
	}
	if !lastSeen.Equal(advertAt) {
		t.Fatalf("last_seen_at=%s, want the advert's OWN observed time %s — not now(), not the earlier direct sighting", lastSeen, advertAt)
	}
	state, linked, _, _ := f.observationRow(advert.ObservationID)
	if state != "linked" || linked != direct.Asset.ID {
		t.Fatalf("supporting evidence for an established asset must resolve as linked: state=%s asset=%s", state, linked)
	}
	if n := f.assetCount(); n != 1 {
		t.Fatalf("assets=%d, want one", n)
	}
}

// testProvisionalBackfill is D5: evidence already sitting in the database
// under the OLD rule becomes a provisional item without anybody re-registering
// a sensor or deleting a row — and it does so with enrichment DISABLED, which
// is the state an existing deployment's blocked observations are actually in.
//
// It also pins the part of D5 that is easy to get wrong: the pass is bounded by
// a CLOCK, not by the evidence. An observation refused because two of the
// tenant's segments overlap has to be reconsidered once the operator fixes the
// overlap — and nothing about the stored evidence changes when they do, so a
// guard keyed on the evidence would never look at it again.
func testProvisionalBackfill(t *testing.T) {
	f := newProvisionalFixture(t)
	ctx := context.Background()
	f.exec(`UPDATE tenant_admin_settings SET config=jsonb_set(config,'{identity_enrichment,enabled}','false') WHERE tenant_id=$1`, f.tenant)

	// One retained observation on an unambiguous segment, and one on a segment
	// a second active segment overlaps.
	eligible := f.retainBlockedObservation(f.relayedAdvert(f.sensorA, "legacy-advert", f.now.Add(-2*time.Hour)))
	contestedSegment, overlapping := uuid.New(), uuid.New()
	f.exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,is_active,environment) VALUES($1,$2,'VLAN C','cidr','203.0.113.0/24',true,'production')`, contestedSegment, f.tenant)
	f.exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,is_active,environment) VALUES($1,$2,'VLAN C overlap','cidr','203.0.113.0/25',true,'production')`, overlapping, f.tenant)
	contested := f.retainBlockedObservation(f.relayedAdvertOn(contestedSegment, "contested-printer", "203.0.113.7", f.sensorA, "contested-advert", f.now.Add(-2*time.Hour)))

	coordinator := &identityenrichment.Coordinator{
		Store:   &identityenrichment.Store{DB: f.db},
		Backend: NewIdentityEnrichmentBackend(f.svc, &DiscoveryService{}),
		Enabled: true,
		Now:     func() time.Time { return f.now },
	}
	if err := coordinator.Sweep(ctx, f.tenant); err != nil {
		t.Fatal(err)
	}

	state, linked, _, materialized := f.observationRow(eligible.String())
	if linked == "" {
		t.Fatalf("the retained observation was not materialized: state=%s", state)
	}
	if !materialized.Valid {
		t.Fatal("materialized_at was not recorded; the next sweep would re-resolve this row every minute for ever")
	}
	identityStatus, assetStatus, _ := f.assetStatuses(linked)
	if identityStatus != "provisional" || assetStatus != "pending_approval" {
		t.Fatalf("backfilled item wrong: identity=%s status=%s", identityStatus, assetStatus)
	}

	// The contested one was looked at and refused, with the reason recorded
	// where the tenant can read it.
	_, contestedAsset, _, contestedMaterialized := f.observationRow(contested.String())
	if contestedAsset != "" || !contestedMaterialized.Valid {
		t.Fatalf("overlapping-scope observation: asset=%q materialized=%v", contestedAsset, contestedMaterialized.Valid)
	}
	var reasons pq.StringArray
	if err := f.raw.QueryRow(`SELECT admission_reasons FROM identity_observations WHERE tenant_id=$1 AND id=$2`, f.tenant, contested).Scan(&reasons); err != nil {
		t.Fatal(err)
	}
	if !containsAll([]string{strings.Join(reasons, " ")}, "overlapping_network_scope_requires_source_resolution") {
		t.Fatalf("refusal reason not recorded: %v", reasons)
	}
	if n := f.assetCount(); n != 1 {
		t.Fatalf("assets=%d, want one", n)
	}

	// Restart-safe: a second sweep straight away must be a no-op. Nothing is
	// re-resolved, which is visible as both stamps standing still.
	if err := coordinator.Sweep(ctx, f.tenant); err != nil {
		t.Fatal(err)
	}
	if n := f.assetCount(); n != 1 {
		t.Fatalf("a repeated sweep duplicated the item: assets=%d", n)
	}
	_, relinked, _, stillMaterialized := f.observationRow(eligible.String())
	if relinked != linked || !stillMaterialized.Time.Equal(materialized.Time) {
		t.Fatalf("a repeated sweep re-resolved a settled row: asset %s→%s stamp %v→%v", linked, relinked, materialized.Time, stillMaterialized.Time)
	}
	_, _, _, contestedUnchanged := f.observationRow(contested.String())
	if !contestedUnchanged.Time.Equal(contestedMaterialized.Time) {
		t.Fatalf("a repeated sweep re-resolved the refused row inside its interval: %v→%v", contestedMaterialized.Time, contestedUnchanged.Time)
	}

	// The operator resolves the overlap, and the re-check interval elapses. The
	// evidence has not changed by one byte; the ANSWER has.
	f.exec(`UPDATE network_segments SET is_active=false WHERE tenant_id=$1 AND id=$2`, f.tenant, overlapping)
	f.exec(`UPDATE identity_observations SET materialized_at=now()-interval '7 hours' WHERE tenant_id=$1 AND id=$2`, f.tenant, contested)
	if err := coordinator.Sweep(ctx, f.tenant); err != nil {
		t.Fatal(err)
	}
	_, resolved, _, _ := f.observationRow(contested.String())
	if resolved == "" {
		t.Fatal("an observation refused for an overlapping scope was never reconsidered after the operator fixed the overlap")
	}
	contestedIdentity, _, contestedSegmentID := f.assetStatuses(resolved)
	if contestedIdentity != "provisional" || contestedSegmentID != contestedSegment.String() {
		t.Fatalf("reconsidered item wrong: identity=%s segment=%s", contestedIdentity, contestedSegmentID)
	}
	if n := f.assetCount(); n != 2 {
		t.Fatalf("assets=%d, want two", n)
	}
}

// testProvisionalExecutorSelection is D4: the collector that HEARD the
// advert and the collector that can ACT on it are two different questions, and
// the enrichment job goes to the one that can act.
func testProvisionalExecutorSelection(t *testing.T) {
	f := newProvisionalFixture(t)
	ctx := context.Background()
	store := &identityenrichment.Store{DB: f.db}
	evidence := f.relayedAdvert(f.sensorA, "advert-1", f.now.Add(-time.Hour))
	o := identityenrichment.Observation{ID: f.retainObservation(evidence), State: "unresolved", Evidence: evidence}

	scope, excluded, err := store.Scope(ctx, f.tenant, o, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if scope.SensorID != f.sensorB || !scope.Reachable || scope.BlockReason != "" {
		t.Fatalf("executor should be sensor B (%s): %+v", f.sensorB, scope)
	}
	if scope.ObserverSensorID != f.sensorA || scope.ObserverReachable || scope.ObserverReason != "collector_has_no_interface_in_target_network" {
		t.Fatalf("observer provenance lost or wrong: %+v", scope)
	}
	policy, err := store.Policy(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	plan, reason := identityenrichment.NetworkPlan(o, policy, scope, nil, excluded)
	if reason != "" || plan.Action != "probe" || plan.Executor != "sensor:"+f.sensorB.String() || plan.ObserverSensorID != f.sensorA {
		t.Fatalf("plan=%+v reason=%s", plan, reason)
	}

	// The probe actually dispatched: cluster-sensor-service is the thing that
	// would receive it, and the sensor it names is the executor.
	var preferred []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			PreferredSensorIDs []string `json:"preferred_sensor_ids"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		preferred = body.PreferredSensorIDs
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"job":{"id":"` + uuid.NewString() + `"}}`))
	}))
	defer server.Close()
	backend := NewIdentityEnrichmentBackend(f.svc, &DiscoveryService{httpClient: server.Client(), clusterSensorURL: server.URL})
	job, err := store.Ensure(ctx, f.tenant, o, plan, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Dispatch(ctx, job, o); err != nil {
		t.Fatal(err)
	}
	if len(preferred) != 1 || preferred[0] != f.sensorB.String() {
		t.Fatalf("probe dispatched to %v, want the executor [%s]", preferred, f.sensorB)
	}

	// Each of these is a separate way to be ineligible, and each must produce
	// the honest "no collector reaches this network" rather than a silent
	// fallback to the observer.
	for _, tc := range []struct {
		name   string
		break_ func()
	}{
		{"stale interface report", func() {
			f.exec(`UPDATE agent_addresses SET last_seen_at=$2 WHERE sensor_id=$1`, f.sensorB, f.now.Add(-10*time.Minute))
		}},
		{"offline collector", func() {
			f.exec(`UPDATE sensors SET last_heartbeat=$2 WHERE id=$1`, f.sensorB, f.now.Add(-time.Hour))
		}},
		{"platform collector", func() {
			f.exec(`UPDATE sensors SET tags=ARRAY['system'] WHERE id=$1`, f.sensorB)
		}},
		{"air-gapped collector", func() {
			f.exec(`UPDATE sensors SET air_gapped=true WHERE id=$1`, f.sensorB)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.exec(`UPDATE sensors SET last_heartbeat=$2,tags=ARRAY[]::text[],air_gapped=false WHERE id=$1`, f.sensorB, f.now)
			f.exec(`UPDATE agent_addresses SET last_seen_at=$2 WHERE sensor_id=$1`, f.sensorB, f.now)
			tc.break_()
			scope, _, err := store.Scope(ctx, f.tenant, o, f.now)
			if err != nil {
				t.Fatal(err)
			}
			if scope.SensorID != uuid.Nil || scope.Reachable || scope.BlockReason != identityenrichment.ReasonNoEligibleCollector {
				t.Fatalf("an ineligible collector was selected anyway: %+v", scope)
			}
		})
	}
	f.exec(`UPDATE sensors SET last_heartbeat=$2,tags=ARRAY[]::text[],air_gapped=false WHERE id=$1`, f.sensorB, f.now)
	f.exec(`UPDATE agent_addresses SET last_seen_at=$2 WHERE sensor_id=$1`, f.sensorB, f.now)

	t.Run("another tenant's collector is never selected", func(t *testing.T) {
		foreign := testdb.NewTenant(t, f.raw)
		foreignSensor := uuid.New()
		f.enrollSensor(foreignSensor, foreign, "foreign-sensor", provPrinterAddr)
		f.exec(`DELETE FROM agent_addresses WHERE sensor_id=$1`, f.sensorB)
		scope, _, err := store.Scope(ctx, f.tenant, o, f.now)
		if err != nil {
			t.Fatal(err)
		}
		if scope.SensorID != uuid.Nil || scope.BlockReason != identityenrichment.ReasonNoEligibleCollector {
			t.Fatalf("a collector belonging to another tenant was selected: %+v", scope)
		}
		f.exec(`INSERT INTO agent_addresses(sensor_id,interface_name,address,prefix_length,last_seen_at) VALUES($1,'eth0',$2::inet,24,$3)`, f.sensorB, provSensorBAddr, f.now)
	})

	t.Run("the observer is preferred when it is eligible", func(t *testing.T) {
		f.exec(`INSERT INTO agent_addresses(sensor_id,interface_name,address,prefix_length,last_seen_at) VALUES($1,'eth0','198.51.100.11'::inet,24,$2)`, f.sensorA, f.now)
		scope, _, err := store.Scope(ctx, f.tenant, o, f.now)
		if err != nil {
			t.Fatal(err)
		}
		if scope.SensorID != f.sensorA || !scope.ObserverReachable {
			t.Fatalf("an eligible observer should execute its own work: %+v", scope)
		}
		f.exec(`DELETE FROM agent_addresses WHERE sensor_id=$1 AND host(address)='198.51.100.11'`, f.sensorA)
	})

	t.Run("paused admission plans nothing", func(t *testing.T) {
		f.exec(`UPDATE tenant_admin_settings SET config=jsonb_set(config,'{identity_admission,mode}','"paused"') WHERE tenant_id=$1`, f.tenant)
		paused, err := store.Policy(ctx, f.tenant)
		if err != nil {
			t.Fatal(err)
		}
		scope, excluded, err := store.Scope(ctx, f.tenant, o, f.now)
		if err != nil {
			t.Fatal(err)
		}
		if _, reason := identityenrichment.NetworkPlan(o, paused, scope, nil, excluded); reason != "admission_or_enrichment_paused" {
			t.Fatalf("reason=%s", reason)
		}
		f.exec(`UPDATE tenant_admin_settings SET config=jsonb_set(config,'{identity_admission,mode}','"enforce"') WHERE tenant_id=$1`, f.tenant)
	})
}

// testProvisionalNoDuplicateInFlightWork pins the idempotency half of D4: a
// collector becoming eligible must not start a SECOND request for work another
// collector is still running.
func testProvisionalNoDuplicateInFlightWork(t *testing.T) {
	f := newProvisionalFixture(t)
	ctx := context.Background()
	store := &identityenrichment.Store{DB: f.db}
	evidence := f.relayedAdvert(f.sensorA, "advert-1", f.now.Add(-time.Hour))
	observationID := f.retainObservation(evidence)
	o := identityenrichment.Observation{ID: observationID, State: "unresolved", Evidence: evidence}

	viaA := identityenrichment.Plan{Action: "probe", Executor: "sensor:" + f.sensorA.String(), SensorID: f.sensorA, ObserverSensorID: f.sensorA,
		SegmentID: f.segB, SegmentCIDR: provSegmentBCIDR, Addresses: []string{provPrinterAddr}}
	first, err := store.Ensure(ctx, f.tenant, o, viaA, f.now)
	if err != nil {
		t.Fatal(err)
	}
	// In flight: the remote request is committed and the collector is working.
	f.exec(`UPDATE identity_enrichment_jobs SET state='running',remote_id=$3 WHERE tenant_id=$1 AND id=$2`, f.tenant, first.ID, uuid.NewString())

	viaB := viaA
	viaB.Executor = "sensor:" + f.sensorB.String()
	viaB.SensorID = f.sensorB
	second, err := store.Ensure(ctx, f.tenant, o, viaB, f.now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID {
		t.Fatalf("a newly eligible collector started a second in-flight probe: %s vs %s", second.ID, first.ID)
	}
	var jobs int
	if err := f.raw.QueryRow(`SELECT count(*) FROM identity_enrichment_jobs WHERE tenant_id=$1 AND observation_id=$2 AND action='probe'`, f.tenant, observationID).Scan(&jobs); err != nil || jobs != 1 {
		t.Fatalf("probe jobs=%d %v, want one", jobs, err)
	}
}

// testProvisionalObservationActions is D6: what confirm, link and dismiss
// mean once an observation has already produced an inventory item.
func testProvisionalObservationActions(t *testing.T) {
	t.Run("confirm promotes in place", func(t *testing.T) {
		f := newProvisionalFixture(t)
		ctx := context.Background()
		advert, err := f.svc.resolveObservationWith(ctx, f.relayedAdvert(f.sensorA, "advert-1", f.now.Add(-time.Hour)), nil)
		if err != nil {
			t.Fatal(err)
		}
		actor := f.actor()
		result, err := f.svc.DecideIdentityObservation(ctx, f.tenant, uuid.MustParse(advert.ObservationID), actor, "confirmed",
			ObservationDecisionInput{Reason: "Operator walked to the printer and read its label"})
		if err != nil {
			t.Fatal(err)
		}
		if result.AssetID != advert.Asset.ID {
			t.Fatalf("confirmation produced a different asset (%s) from the item the operator was looking at (%s)", result.AssetID, advert.Asset.ID)
		}
		if n := f.assetCount(); n != 1 {
			t.Fatalf("assets=%d, want one — confirming must never create a second item", n)
		}
		identityStatus, _, _ := f.assetStatuses(advert.Asset.ID)
		if identityStatus != "operator_confirmed" {
			t.Fatalf("identity_status=%s, want operator_confirmed", identityStatus)
		}
		var declarations int
		if err := f.raw.QueryRow(`SELECT count(*) FROM asset_identifiers WHERE tenant_id=$1 AND asset_id=$2 AND kind='declaration_id' AND value=$3`, f.tenant, advert.Asset.ID, advert.ObservationID).Scan(&declarations); err != nil || declarations != 1 {
			t.Fatalf("declaration identifier missing: %d %v", declarations, err)
		}
		var confirmedBy uuid.UUID
		if err := f.raw.QueryRow(`SELECT confirmed_by FROM identity_observations WHERE tenant_id=$1 AND id=$2`, f.tenant, advert.ObservationID).Scan(&confirmedBy); err != nil || confirmedBy != actor {
			t.Fatalf("confirmation not recorded on the observation: %v %v", confirmedBy, err)
		}
		var decisions int
		if err := f.raw.QueryRow(`SELECT count(*) FROM identity_observation_decisions WHERE tenant_id=$1 AND observation_id=$2 AND action='confirmed'`, f.tenant, advert.ObservationID).Scan(&decisions); err != nil || decisions != 1 {
			t.Fatalf("decision rows=%d %v", decisions, err)
		}
	})

	t.Run("link is refused in favour of merge review", func(t *testing.T) {
		f := newProvisionalFixture(t)
		ctx := context.Background()
		advert, err := f.svc.resolveObservationWith(ctx, f.relayedAdvert(f.sensorA, "advert-1", f.now.Add(-time.Hour)), nil)
		if err != nil {
			t.Fatal(err)
		}
		other, err := f.svc.resolveObservationWith(ctx, identity.Observation{
			TenantID: f.tenant.String(), Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:" + f.sensorB.String()},
			ObservedAt: f.now.Add(-time.Minute), Network: identity.Network{SegmentID: f.segB.String()},
			Admission: identity.AdmissionEvidence{Direct: true, ReceiptID: "other-device"},
			Identifiers: []identity.Identifier{
				{Kind: identity.KindIPAddress, Value: "198.51.100.42", Scope: f.segB.String()},
				{Kind: identity.KindMACAddress, Value: "00:00:5e:00:53:42"},
			}}, nil)
		if err != nil || other.Asset.Zero() {
			t.Fatalf("second asset fixture: %+v %v", other, err)
		}
		target := uuid.MustParse(other.Asset.ID)
		_, err = f.svc.DecideIdentityObservation(ctx, f.tenant, uuid.MustParse(advert.ObservationID), f.actor(), "linked",
			ObservationDecisionInput{Reason: "Same printer, surely", AssetID: &target})
		if err == nil || err.Error() != "provisional_item_requires_merge_review" {
			t.Fatalf("linking a provisional item must be refused with the merge-review code, got %v", err)
		}
	})

	t.Run("dismiss archives an item nothing else vouches for", func(t *testing.T) {
		f := newProvisionalFixture(t)
		ctx := context.Background()
		advert, err := f.svc.resolveObservationWith(ctx, f.relayedAdvert(f.sensorA, "advert-1", f.now.Add(-time.Hour)), nil)
		if err != nil {
			t.Fatal(err)
		}
		// A second relayed advert, from a different collector, about the same
		// name: supporting evidence that keeps the item vouched for.
		second, err := f.svc.resolveObservationWith(ctx, f.relayedAdvert(f.sensorB, "advert-2", f.now.Add(-30*time.Minute)), nil)
		if err != nil {
			t.Fatal(err)
		}
		if second.Asset.ID != advert.Asset.ID || second.ObservationID == advert.ObservationID {
			t.Fatalf("second advert did not become separate supporting evidence for the same item: %+v", second)
		}
		if _, err := f.svc.DecideIdentityObservation(ctx, f.tenant, uuid.MustParse(advert.ObservationID), f.actor(), "dismissed",
			ObservationDecisionInput{Reason: "Reflected from a neighbouring VLAN"}); err != nil {
			t.Fatal(err)
		}
		_, assetStatus, _ := f.assetStatuses(advert.Asset.ID)
		if assetStatus == "archived" {
			t.Fatal("the item was archived while another observation still links to it")
		}
		if _, err := f.svc.DecideIdentityObservation(ctx, f.tenant, uuid.MustParse(second.ObservationID), f.actor(), "dismissed",
			ObservationDecisionInput{Reason: "Same reflection, second collector"}); err != nil {
			t.Fatal(err)
		}
		_, assetStatus, _ = f.assetStatuses(advert.Asset.ID)
		if assetStatus != "archived" {
			t.Fatalf("asset_status=%s, want archived once nothing vouches for the item", assetStatus)
		}
		if !containsAll(f.historyActions(advert.Asset.ID), `"reason": "dismissed_provisional"`) {
			t.Fatalf("archival reason missing from history: %v", f.historyActions(advert.Asset.ID))
		}
		// The link survives the dismissal so the timeline stays navigable.
		state, linked, _, _ := f.observationRow(advert.ObservationID)
		if state != "dismissed" || linked != advert.Asset.ID {
			t.Fatalf("dismissal detached the observation from its item: state=%s asset=%s", state, linked)
		}
	})
}

// testProvisionalRetention: an observation that produced an inventory item is
// not expiring evidence. Deleting it would leave an asset whose only
// explanation is gone.
func testProvisionalRetention(t *testing.T) {
	f := newProvisionalFixture(t)
	ctx := context.Background()
	advert, err := f.svc.resolveObservationWith(ctx, f.relayedAdvert(f.sensorA, "advert-1", f.now.Add(-time.Hour)), nil)
	if err != nil {
		t.Fatal(err)
	}
	repo := pgidentity.New(f.raw)
	if err := repo.ExpireObservations(ctx, f.tenant.String(), f.now.Add(91*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	state, linked, _, _ := f.observationRow(advert.ObservationID)
	if state != "unresolved" || linked != advert.Asset.ID {
		t.Fatalf("the retention sweep expired or detached a provisional-linked observation: state=%s asset=%s", state, linked)
	}
	if n := f.assetCount(); n != 1 {
		t.Fatalf("assets=%d", n)
	}
}

// testProvisionalAPI is D7: what the tenant's browser actually receives.
func testProvisionalAPI(t *testing.T) {
	f := newProvisionalFixture(t)
	ctx := context.Background()
	advert, err := f.svc.resolveObservationWith(ctx, f.relayedAdvert(f.sensorA, "advert-1", f.now.Add(-time.Hour)), nil)
	if err != nil {
		t.Fatal(err)
	}

	detail, err := f.svc.GetIdentityObservation(ctx, f.tenant, uuid.MustParse(advert.ObservationID))
	if err != nil {
		t.Fatal(err)
	}
	assertCollector := func(label string, block *IdentityObservationCollector) {
		t.Helper()
		if block == nil {
			t.Fatalf("%s: collector block missing", label)
		}
		if block.Observer.SensorID == nil || *block.Observer.SensorID != f.sensorA || block.Observer.Name != "sensor-a" {
			t.Fatalf("%s: observer wrong: %+v", label, block.Observer)
		}
		if block.Observer.Reachable || block.Observer.Reason != "collector_has_no_interface_in_target_network" {
			t.Fatalf("%s: observer reachability wrong: %+v", label, block.Observer)
		}
		if block.Executor == nil || block.Executor.SensorID != f.sensorB || block.Executor.Name != "sensor-b" {
			t.Fatalf("%s: executor wrong: %+v", label, block.Executor)
		}
		if block.Reason != "" {
			t.Fatalf("%s: reason=%q, want empty while an executor exists", label, block.Reason)
		}
	}
	assertCollector("detail", detail.Collector)

	page, err := f.svc.ListIdentityObservations(ctx, f.tenant, "unresolved", 1, 50, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Observations) != 1 {
		t.Fatalf("observations=%d, want one", len(page.Observations))
	}
	assertCollector("list", page.Observations[0].Collector)

	summary, err := f.svc.IdentitySummary(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Provisional != 1 || summary.Established != 0 {
		t.Fatalf("summary=%+v, want exactly one provisional item and no monitored identity", summary)
	}

	// With every eligible collector gone, the block reason is the one the UI
	// renders as "deploy a sensor on this network".
	f.exec(`DELETE FROM agent_addresses WHERE sensor_id=$1`, f.sensorB)
	blocked, err := f.svc.GetIdentityObservation(ctx, f.tenant, uuid.MustParse(advert.ObservationID))
	if err != nil {
		t.Fatal(err)
	}
	if blocked.Collector == nil || blocked.Collector.Executor != nil || blocked.Collector.Reason != identityenrichment.ReasonNoEligibleCollector {
		t.Fatalf("collector block with no eligible executor: %+v", blocked.Collector)
	}

	// An observation the tenant has no segment for gets no collector answer at
	// all, rather than a sentence naming a network they never configured.
	unplaced, err := f.svc.resolveObservationWith(ctx, identity.Observation{
		TenantID: f.tenant.String(), Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:" + f.sensorA.String()},
		ObservedAt: f.now.Add(-time.Hour), Admission: identity.AdmissionEvidence{Relayed: true, ReceiptID: "unplaced"},
		Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: "nowhere-in-particular"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	nowhere, err := f.svc.GetIdentityObservation(ctx, f.tenant, uuid.MustParse(unplaced.ObservationID))
	if err != nil {
		t.Fatal(err)
	}
	if nowhere.Collector != nil {
		t.Fatalf("an unplaced observation should carry no collector block: %+v", nowhere.Collector)
	}
}
