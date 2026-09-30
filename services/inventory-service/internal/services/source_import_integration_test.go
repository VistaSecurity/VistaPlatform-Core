package services

// The internal source-import service (platform ADR-0002 D3) against a real
// Postgres: what a connector running OUTSIDE this service can and cannot do to
// the inventory.
//
// The connector-level behaviour (a NetBox estate imported twice is one set of
// assets, and so on) is pinned end to end in the connector's own service,
// through the real HTTP path. What is pinned HERE is the inventory's half:
// the tenant-wins rules on a segment the tenant drew, cloud segments not
// absorbing on-prem prefixes, the too-broad rule, admission, the discovery
// source claim, facts with provenance, the hardware read — and that every one
// of them is scoped to the ONE tenant named in the call.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type sourceFixture struct {
	db  *database.DB
	svc *SourceImportService
}

func newSourceFixture(t *testing.T) *sourceFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	assets := NewAssetService(db)
	assets.SetEnrichmentServices(NewNetworkSegmentService(db, NewLocationService(db)), nil)
	return &sourceFixture{db: db, svc: NewSourceImportService(db, assets)}
}

func (f *sourceFixture) tenant(t *testing.T) uuid.UUID {
	t.Helper()
	id := testdb.NewTenant(t, f.db.DB.DB)
	if _, err := f.db.Exec(`UPDATE tenants SET subscription_tier_id = (SELECT id FROM subscription_tiers WHERE name = 'enterprise') WHERE id = $1`, id); err != nil {
		t.Fatalf("assign tier: %v", err)
	}
	return id
}

type segmentRow struct {
	Name, Environment, SourceKind, SourceRef string
	AutoApprove                              bool
	Tags, Metadata                           map[string]any
}

func (f *sourceFixture) segment(t *testing.T, tenant, id uuid.UUID) segmentRow {
	t.Helper()
	var r segmentRow
	var tags, meta []byte
	err := database.WithTenantTx(context.Background(), f.db, tenant, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`
			SELECT name, environment::text, COALESCE(source_kind,''), COALESCE(source_ref,''),
			       COALESCE(auto_approve_discoveries,false), COALESCE(tags,'{}'::jsonb), COALESCE(metadata,'{}'::jsonb)
			FROM network_segments WHERE tenant_id = $1 AND id = $2`, tenant, id).
			Scan(&r.Name, &r.Environment, &r.SourceKind, &r.SourceRef, &r.AutoApprove, &tags, &meta)
	})
	if err != nil {
		t.Fatalf("read segment: %v", err)
	}
	_ = json.Unmarshal(tags, &r.Tags)
	_ = json.Unmarshal(meta, &r.Metadata)
	return r
}

func (f *sourceFixture) insertSegment(t *testing.T, tenant uuid.UUID, name, value, cloudRef string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	var ref any
	if cloudRef != "" {
		ref = cloudRef
	}
	err := database.WithTenantTx(context.Background(), f.db, tenant, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`
			INSERT INTO network_segments (tenant_id, name, segment_type, value, network_type, environment,
			                              auto_approve_discoveries, tags, metadata, cloud_network_ref)
			VALUES ($1, $2, 'cidr', $3, 'private', 'staging'::environment_type, true,
			        '{"owner":"netops"}'::jsonb, '{"note":"hand-drawn"}'::jsonb, $4)
			RETURNING id`, tenant, name, value, ref).Scan(&id)
	})
	if err != nil {
		t.Fatalf("insert segment: %v", err)
	}
	return id
}

func (f *sourceFixture) segmentCount(t *testing.T, tenant uuid.UUID) int {
	t.Helper()
	var n int
	if err := database.WithTenantTx(context.Background(), f.db, tenant, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`SELECT count(*) FROM network_segments WHERE tenant_id = $1`, tenant).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func seg(cidr, ref string) SourceSegment {
	return SourceSegment{
		CIDR: cidr, Name: "Imported " + cidr, Environment: "production", SourceRef: ref,
		Metadata:      map[string]any{"imported_from": "test", "role": "servers"},
		MatchMetadata: map[string]any{"imported_from": "test"},
	}
}

// A segment the tenant already drew is MATCHED by masked CIDR, stamped with
// the source's provenance, and otherwise left exactly as the tenant set it.
// MUTATION: make markSegmentImported also SET name/environment/auto-approve
// (or replace metadata instead of merging) and this goes red.
func TestIntegration_SourceImport_ExistingSegmentKeepsTheTenantsSettings(t *testing.T) {
	f := newSourceFixture(t)
	tenant := f.tenant(t)
	ctx := context.Background()
	drawn := f.insertSegment(t, tenant, "Hand-drawn server LAN", "192.0.2.5/24", "")

	res, err := f.svc.UpsertSegments(ctx, tenant, []SourceSegment{
		seg("192.0.2.0/24", "src:conn:prefix:1"),
		seg("198.51.100.0/24", "src:conn:prefix:2"),
	})
	if err != nil {
		t.Fatalf("UpsertSegments: %v", err)
	}
	if res[0].Outcome != SourceSegmentMatched || res[1].Outcome != SourceSegmentCreated {
		t.Fatalf("outcomes = %+v, want matched then created", res)
	}
	got := f.segment(t, tenant, drawn)
	if got.SourceKind != "imported" || got.SourceRef != "src:conn:prefix:1" {
		t.Errorf("provenance = %q / %q, want imported / src:conn:prefix:1", got.SourceKind, got.SourceRef)
	}
	if got.Name != "Hand-drawn server LAN" || got.Environment != "staging" || !got.AutoApprove {
		t.Errorf("the tenant's settings were overwritten: %+v", got)
	}
	if got.Tags["owner"] != "netops" {
		t.Errorf("tags were overwritten: %v", got.Tags)
	}
	if got.Metadata["note"] != "hand-drawn" || got.Metadata["imported_from"] != "test" {
		t.Errorf("metadata was not MERGED: %v", got.Metadata)
	}
	if _, leaked := got.Metadata["role"]; leaked {
		t.Errorf("create-only metadata reached a matched segment: %v", got.Metadata)
	}
	if n := f.segmentCount(t, tenant); n != 2 {
		t.Errorf("%d segments, want 2 — the overlapping prefix was duplicated", n)
	}
}

// A cloud segment with the same CIDR is a different address space and is not
// matched. MUTATION: drop `cloud_network_ref IS NULL` from onPremSegments.
func TestIntegration_SourceImport_CloudSegmentIsNotMatched(t *testing.T) {
	f := newSourceFixture(t)
	tenant := f.tenant(t)
	cloud := f.insertSegment(t, tenant, "VPC prod", "192.0.2.0/24", "vpc-0abc123")

	res, err := f.svc.UpsertSegments(context.Background(), tenant, []SourceSegment{seg("192.0.2.0/24", "src:c:prefix:1")})
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Outcome != SourceSegmentCreated {
		t.Errorf("outcome = %q, want created — a VPC segment must not absorb an on-premises prefix", res[0].Outcome)
	}
	if got := f.segment(t, tenant, cloud); got.SourceKind != "" {
		t.Errorf("the cloud segment was stamped %q", got.SourceKind)
	}
}

// Too broad to be anybody's segment: refused when new, but an EXISTING one it
// matches is still matched. MUTATION: move the too-broad check above the match.
func TestIntegration_SourceImport_TooBroadPrefix(t *testing.T) {
	f := newSourceFixture(t)
	tenant := f.tenant(t)
	res, err := f.svc.UpsertSegments(context.Background(), tenant, []SourceSegment{seg("0.0.0.0/0", "src:c:prefix:9")})
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Outcome != SourceSegmentTooBroad {
		t.Errorf("0.0.0.0/0 outcome = %q, want too_broad", res[0].Outcome)
	}
	if n := f.segmentCount(t, tenant); n != 0 {
		t.Errorf("%d segments written for a too-broad prefix", n)
	}
}

// The tenant named in the call is the only tenant touched. Tenant B has the
// same CIDR drawn; tenant A's import creates A's own and leaves B's alone.
// MUTATION: run onPremSegments without the tenant (or on a bypass pool) and
// tenant A's call matches — and stamps — tenant B's segment.
func TestIntegration_SourceImport_SegmentsAreTenantScoped(t *testing.T) {
	f := newSourceFixture(t)
	a, b := f.tenant(t), f.tenant(t)
	bSeg := f.insertSegment(t, b, "B's LAN", "192.0.2.0/24", "")

	res, err := f.svc.UpsertSegments(context.Background(), a, []SourceSegment{seg("192.0.2.0/24", "src:a:prefix:1")})
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Outcome != SourceSegmentCreated {
		t.Errorf("tenant A's outcome = %q, want created (B's segment is not A's)", res[0].Outcome)
	}
	if got := f.segment(t, b, bSeg); got.SourceKind != "" || got.SourceRef != "" {
		t.Errorf("tenant A's import stamped tenant B's segment: %+v", got)
	}
	if f.segmentCount(t, a) != 1 || f.segmentCount(t, b) != 1 {
		t.Errorf("segment counts A=%d B=%d, want 1 and 1", f.segmentCount(t, a), f.segmentCount(t, b))
	}
}

// Per-item validation is a result, not a failed call: one bad item does not
// cost the others.
func TestIntegration_SourceImport_BadItemsFailAlone(t *testing.T) {
	f := newSourceFixture(t)
	tenant := f.tenant(t)
	bad := seg("10.9.0.0/16", "src:c:prefix:1")
	bad.Environment = "prod-ish"
	res, err := f.svc.UpsertSegments(context.Background(), tenant, []SourceSegment{
		{CIDR: "not-a-cidr", Name: "x", Environment: "production", SourceRef: "r"},
		bad,
		{CIDR: "10.8.0.0/16", Name: "no ref", Environment: "production"},
		seg("10.7.0.0/16", "src:c:prefix:4"),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{SourceSegmentError, SourceSegmentError, SourceSegmentError, SourceSegmentCreated}
	for i, w := range want {
		if res[i].Outcome != w {
			t.Errorf("item %d outcome = %q (%s), want %q", i, res[i].Outcome, res[i].Error, w)
		}
	}
}

func sourceHost(serial, ip, host string) SourceAssetItem {
	in := models.AssetInput{
		ClassKey:    assetclass.KeySwitch,
		Identifiers: []models.AssetIdentifierInput{{Kind: string(identity.KindSerialNumber), Value: serial}},
		IPAddress:   &ip,
		Hostname:    &host,
		DisplayName: &host,
	}
	return SourceAssetItem{
		Input:                in,
		Facts:                []SourceFact{{Key: "hw.vendor", Value: "Cisco"}, {Key: "hw.model", Value: ""}},
		ClaimDiscoverySource: "testsrc",
	}
}

var testSource = identity.Source{Kind: identity.SourceImported, Ref: "testsrc:conn-1"}

// Two submissions of the same host resolve to ONE asset, through the engine:
// created, then matched. The facts land with the source's provenance, empty
// values are dropped, and the asset waits for approval.
func TestIntegration_SourceImport_AssetsResolveThroughTheEngine(t *testing.T) {
	f := newSourceFixture(t)
	tenant := f.tenant(t)
	ctx := context.Background()
	item := sourceHost("SRC-SERIAL-1", "192.0.2.11", "core-sw-01")

	first := f.svc.ResolveAssets(ctx, tenant, testSource, []SourceAssetItem{item})
	second := f.svc.ResolveAssets(ctx, tenant, testSource, []SourceAssetItem{item})
	if first[0].Outcome != string(identity.OutcomeCreated) || second[0].Outcome != string(identity.OutcomeMatched) {
		t.Fatalf("outcomes = %+v then %+v, want created then matched", first[0], second[0])
	}
	if first[0].AssetID == nil || second[0].AssetID == nil || *first[0].AssetID != *second[0].AssetID {
		t.Fatalf("the two submissions resolved to different assets: %v / %v", first[0].AssetID, second[0].AssetID)
	}
	if first[0].FactsError != "" || first[0].DiscoverySourceError != "" {
		t.Fatalf("follow-up writes failed: %+v", first[0])
	}

	var status, discovery string
	var facts int
	var factRef string
	err := database.WithTenantTx(ctx, f.db, tenant, func(tx *sqlx.Tx) error {
		if err := tx.QueryRow(`SELECT asset_status, COALESCE(metadata->>'discovery_source','') FROM assets WHERE tenant_id=$1 AND id=$2`,
			tenant, *first[0].AssetID).Scan(&status, &discovery); err != nil {
			return err
		}
		return tx.QueryRow(`SELECT count(*), COALESCE(min(source_ref),'') FROM asset_facts WHERE tenant_id=$1 AND asset_id=$2 AND source_kind='imported'`,
			tenant, *first[0].AssetID).Scan(&facts, &factRef)
	})
	if err != nil {
		t.Fatal(err)
	}
	if status != "pending_approval" {
		t.Errorf("asset_status = %q; a source import must not bypass the approval queue", status)
	}
	if discovery != "testsrc" {
		t.Errorf("discovery_source = %q, want testsrc (nothing had claimed it)", discovery)
	}
	if facts != 1 || factRef != testSource.Ref {
		t.Errorf("%d imported facts under %q, want 1 (hw.vendor; the empty hw.model dropped) under %q", facts, factRef, testSource.Ref)
	}
}

// A discovery source already claimed is not displaced.
// MUTATION: drop the "no discovery_source yet" predicate from claimDiscoverySource.
func TestIntegration_SourceImport_DiscoverySourceIsNotDisplaced(t *testing.T) {
	f := newSourceFixture(t)
	tenant := f.tenant(t)
	ctx := context.Background()
	res := f.svc.ResolveAssets(ctx, tenant, testSource, []SourceAssetItem{sourceHost("SRC-SERIAL-2", "192.0.2.12", "core-sw-02")})
	id := *res[0].AssetID
	if _, err := f.db.Exec(`UPDATE assets SET metadata = metadata || '{"discovery_source":"sensor"}'::jsonb WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	again := f.svc.ResolveAssets(ctx, tenant, testSource, []SourceAssetItem{sourceHost("SRC-SERIAL-2", "192.0.2.12", "core-sw-02")})
	if again[0].Outcome != string(identity.OutcomeMatched) {
		t.Fatalf("outcome %q, want matched", again[0].Outcome)
	}
	var discovery string
	if err := f.db.QueryRow(`SELECT metadata->>'discovery_source' FROM assets WHERE id=$1`, id).Scan(&discovery); err != nil {
		t.Fatal(err)
	}
	if discovery != "sensor" {
		t.Errorf("discovery_source = %q; a source displaced the sensor that found the host", discovery)
	}
}

// Assets land in the named tenant only, and an identical host in another
// tenant is never matched across the boundary.
func TestIntegration_SourceImport_AssetsAreTenantScoped(t *testing.T) {
	f := newSourceFixture(t)
	a, b := f.tenant(t), f.tenant(t)
	ctx := context.Background()
	item := sourceHost("SRC-SERIAL-3", "192.0.2.13", "core-sw-03")
	ra := f.svc.ResolveAssets(ctx, a, testSource, []SourceAssetItem{item})
	rb := f.svc.ResolveAssets(ctx, b, testSource, []SourceAssetItem{item})
	if ra[0].Outcome != string(identity.OutcomeCreated) || rb[0].Outcome != string(identity.OutcomeCreated) {
		t.Fatalf("outcomes A=%q B=%q, want created in both — B's host is not A's", ra[0].Outcome, rb[0].Outcome)
	}
	var owner uuid.UUID
	if err := f.db.QueryRow(`SELECT tenant_id FROM assets WHERE id=$1`, *ra[0].AssetID).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if owner != a {
		t.Errorf("tenant A's asset belongs to %s", owner)
	}
}

// A per-item failure is a result naming the problem, and the others proceed.
func TestIntegration_SourceImport_AssetErrorsFailAlone(t *testing.T) {
	f := newSourceFixture(t)
	tenant := f.tenant(t)
	bad := sourceHost("SRC-SERIAL-4", "192.0.2.14", "core-sw-04")
	bad.Input.ClassKey = "not-a-class"
	good := sourceHost("SRC-SERIAL-5", "192.0.2.15", "core-sw-05")
	res := f.svc.ResolveAssets(context.Background(), tenant, testSource, []SourceAssetItem{bad, good})
	if res[0].Outcome != SourceOutcomeError || res[0].Error == "" {
		t.Errorf("bad item = %+v, want an error with a reason", res[0])
	}
	if res[1].Outcome != string(identity.OutcomeCreated) {
		t.Errorf("good item = %+v, want created", res[1])
	}
}

// Admission: an ordinary tenant under its cap is allowed; one with no tier
// (every cap zero) is refused with the cap's sentence, before anything is
// written.
func TestIntegration_SourceImport_Admission(t *testing.T) {
	f := newSourceFixture(t)
	ctx := context.Background()
	ok, err := f.svc.Admission(ctx, f.tenant(t), 3)
	if err != nil || !ok.Allowed || ok.Prospective {
		t.Errorf("tiered tenant: %+v err %v, want allowed, not prospective", ok, err)
	}
	tierless := testdb.NewTenant(t, f.db.DB.DB)
	refused, err := f.svc.Admission(ctx, tierless, 3)
	if err != nil {
		t.Fatalf("tierless tenant: %v", err)
	}
	if refused.Allowed || refused.Message == "" {
		t.Errorf("tierless tenant: %+v, want refused with a message", refused)
	}
}

// The hardware read: live hardware and unknown hosts, first serial, paged in
// id order, one tenant only.
func TestIntegration_SourceImport_HardwareAssets(t *testing.T) {
	f := newSourceFixture(t)
	a, b := f.tenant(t), f.tenant(t)
	ctx := context.Background()
	for i, serial := range []string{"HW-1", "HW-2", "HW-3"} {
		ip := "192.0.2." + string(rune('1'+i)) + "0"
		f.svc.ResolveAssets(ctx, a, testSource, []SourceAssetItem{sourceHost(serial, ip, "hw-"+serial)})
	}
	f.svc.ResolveAssets(ctx, b, testSource, []SourceAssetItem{sourceHost("HW-B", "192.0.2.99", "hw-b")})

	page1, err := f.svc.HardwareAssets(ctx, a, uuid.Nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	page2, err := f.svc.HardwareAssets(ctx, a, page1[len(page1)-1].ID, 2)
	if err != nil {
		t.Fatal(err)
	}
	all := append(page1, page2...)
	if len(page1) != 2 || len(all) != 3 {
		t.Fatalf("pages of %d then %d, want 2 then 1", len(page1), len(page2))
	}
	seen := map[string]bool{}
	for _, h := range all {
		seen[h.Serial] = true
		if h.ClassKey != assetclass.KeySwitch || h.Address == "" {
			t.Errorf("row = %+v, want a switch with its address", h)
		}
	}
	if !seen["HW-1"] || !seen["HW-2"] || !seen["HW-3"] || seen["HW-B"] {
		t.Errorf("serials seen = %v, want tenant A's three and not B's", seen)
	}
}

// Class check: compiled classes and the tenant's own leaf subclasses exist;
// another tenant's leaf does not.
func TestIntegration_SourceImport_ClassKeyExists(t *testing.T) {
	f := newSourceFixture(t)
	a, b := f.tenant(t), f.tenant(t)
	ctx := context.Background()
	key := "src-leaf-" + uuid.NewString()[:8]
	if _, err := f.db.Exec(`
		INSERT INTO asset_classes (tenant_id, key, parent_key, path, label, cyclonedx_type)
		SELECT $1, $2, 'switch', path || '/' || $2, 'Leaf', cyclonedx_type FROM asset_classes WHERE key = 'switch' AND tenant_id IS NULL`, a, key); err != nil {
		t.Fatalf("create a tenant leaf class: %v", err)
	}
	for _, tc := range []struct {
		tenant uuid.UUID
		key    string
		want   bool
	}{
		{a, assetclass.KeySwitch, true},
		{a, key, true},
		{b, key, false},
		{a, "no-such-class", false},
	} {
		got, err := f.svc.ClassKeyExists(ctx, tc.tenant, tc.key)
		if err != nil || got != tc.want {
			t.Errorf("ClassKeyExists(%s) = %t, %v; want %t", tc.key, got, err, tc.want)
		}
	}
}

// ObservationTime and the receipt id travel with the item, so a replay of one
// run is one sighting and the next run is a second.
func TestIntegration_SourceImport_ReceiptsSeparateReplayFromNewSightings(t *testing.T) {
	f := newSourceFixture(t)
	tenant := f.tenant(t)
	ctx := context.Background()
	if _, err := f.db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"observe"}}')
		ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
		t.Fatal(err)
	}
	observed := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Microsecond)
	for _, run := range []struct {
		id string
		at time.Time
	}{{"run-1:7", observed}, {"run-1:7", observed}, {"run-2:7", observed.Add(time.Hour)}} {
		item := sourceHost("SRC-RECEIPT-7", "192.0.2.77", "receipt-host.example.test")
		item.Input.ObservationReceiptID = run.id
		item.Input.ObservationTime = run.at
		if res := f.svc.ResolveAssets(ctx, tenant, testSource, []SourceAssetItem{item}); res[0].Outcome == SourceOutcomeError {
			t.Fatalf("resolve %s: %+v", run.id, res[0])
		}
	}
	var sightings int
	var first, last time.Time
	if err := f.db.QueryRow(`SELECT occurrence_count, first_seen_at, last_seen_at FROM identity_observations WHERE tenant_id=$1`, tenant).
		Scan(&sightings, &first, &last); err != nil {
		t.Fatal(err)
	}
	if sightings != 2 || !first.Equal(observed) || !last.Equal(observed.Add(time.Hour)) {
		t.Fatalf("sightings=%d first=%s last=%s; want 2, %s, %s", sightings, first, last, observed, observed.Add(time.Hour))
	}
}
