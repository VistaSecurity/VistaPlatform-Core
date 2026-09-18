package services

// Re-classification when a host inventory lands on an asset something else
// created.
//
// # What was broken
//
// Classification ran exactly ONCE, at the moment an asset was created, from
// whatever the creating observation happened to carry — and nothing re-asked the
// question when better evidence turned up minutes later.
//
// On a dev cluster that produced this: a passive sensor saw a host at 20:18:54
// and created an asset from an address and a MAC, which decides nothing, so it
// was born `unknown_host` and displayed as the bare IP. At 20:21:44 a device
// agent delivered the host's full inventory for the same asset — Windows 11
// Pro, Dell Inc., XPS 16 9640, serial 5SDH994, 106 software installs, 69
// certificate stores, 83 listening sockets. The asset stayed `unknown_host` and
// stayed labelled with its bare address. `asset_class_history` held exactly one row
// for it, written at creation, and three of that tenant's four assets were in
// the same state.
//
// Two separate causes, and both had to be fixed for either to matter:
//
//  1. The host-inventory path asked the rules and then dropped the answer on
//     the job row, because when it was written this service had no proposal
//     writer (see the header of host_inventory_ingest.go).
//  2. Even asked, the rules could not answer: the only inputs a general-purpose
//     computer offers are its OS and its model, and there was no `os_name` rule
//     kind. A Dell OUI is vendor-only by design and "XPS 16 9640" is a consumer
//     product line no catalogue enumerates.
//
// # What these pin
//
//  1. A host inventory PROMOTES an existing asset off the `unknown_host` floor,
//     writes `asset_class_history`, and names it.
//  2. A DECLARED class is never touched — not the class, not the history.
//  3. An asset holding a real MEASURED class is not restomped: it gets a
//     proposal in Approvals, which is what stops two classes flapping.
//  4. A second identical collection changes nothing and writes no second row.
//
// Every one of these fails silently in production if it regresses: a wrong
// class shows as a fact, and a class that quietly stops moving looks exactly
// like an inventory nobody has looked at.
//
// Skips without TEST_DATABASE_URL (`make test-integration-db`).

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/classify"
	"github.com/vistasecurity/vistaplatform/shared/hostinventory"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/classproposal"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The physical NIC the passive sighting and the host inventory share. Its OUI
// (00:1A:2B) carries no rule, so the class in these tests can only have come
// from the OS — which is the whole point.
const reclassifyMAC = "00:1a:2b:3c:4d:5e"

// windowsHostReport is the reported asset, as the collector would report it.
func windowsHostReport(agentID, serial string) *hostinventory.Report {
	return &hostinventory.Report{
		Collected: time.Date(2026, 9, 17, 20, 21, 44, 0, time.UTC),
		Mode:      hostinventory.ModeLocal,
		Platform:  hostinventory.PlatformWindows,
		AgentID:   agentID,
		Host: hostinventory.Host{
			OS: "Microsoft Windows 11 Pro", OSVersion: "10.0.26200",
			Hostname: "xps16", FQDN: "xps16.example.net",
		},
		Hardware: hostinventory.Hardware{
			Vendor: "Dell Inc.", Model: "XPS 16 9640", Serial: serial,
			UUID: "4C4C4544-0053-4410-8048-B5C04F393934", Firmware: "1.24.0",
		},
		Interfaces: []hostinventory.Interface{
			{Name: "eth0", MAC: reclassifyMAC, Addresses: []string{"198.51.100.73/24"}, State: "up"},
		},
		Listeners: []hostinventory.Listener{
			{Proto: "tcp", Address: "0.0.0.0", Port: 445, Process: "System"},
		},
		Sections: map[string]string{
			hostinventory.SectionHost:       hostinventory.SectionOK,
			hostinventory.SectionHardware:   hostinventory.SectionOK,
			hostinventory.SectionInterfaces: hostinventory.SectionOK,
			hostinventory.SectionListeners:  hostinventory.SectionOK,
		},
	}
}

// passiveSighting creates the asset a passive sensor would: a MAC, an address,
// and no opinion at all about what the thing is.
//
// Through the REAL identification engine rather than an INSERT, because the
// asset the fix has to repair is one the engine created — its class_source_kind,
// its confidence and its display-name fallback are all the engine's doing, and a
// hand-written row would let the test pass against a shape production never
// produces.
func passiveSighting(t *testing.T, db *sql.DB, tenantID uuid.UUID, address string) uuid.UUID {
	t.Helper()
	repo := pgidentity.New(db)
	engine, err := identity.New(identity.Config{Repo: repo})
	if err != nil {
		t.Fatalf("build the identification engine: %v", err)
	}

	obs := identity.Observation{
		TenantID: tenantID.String(),
		// The floor. A MAC and an address decide nothing.
		ClassHint:  string(assetclass.KeyUnknownHost),
		Source:     identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:reclassify-test", Mode: identity.ModePassive},
		ObservedAt: time.Date(2026, 9, 17, 20, 18, 54, 0, time.UTC),
		Confidence: 0.85,
		Network:    identity.Network{Ownership: identity.OwnershipInternal},
		Identifiers: []identity.Identifier{
			{Kind: identity.KindMACAddress, Value: reclassifyMAC, Confidence: 0.85},
			{Kind: identity.KindIPAddress, Value: address, Confidence: 0.6},
		},
	}
	clean, _ := obs.Sanitize()

	var assetID uuid.UUID
	err = repo.RunInTx(context.Background(), tenantID.String(), func(r *pgidentity.Repository) error {
		res, rErr := engine.WithRepository(r).Resolve(context.Background(), clean)
		if rErr != nil {
			return rErr
		}
		if res.Asset.Zero() {
			t.Fatalf("the passive sighting created no asset")
		}
		assetID = uuid.MustParse(res.Asset.ID)
		return nil
	})
	if err != nil {
		t.Fatalf("seed the passive sighting: %v", err)
	}
	return assetID
}

type assetClassRow struct {
	Class       string
	SourceKind  string
	SourceRef   string
	Confidence  sql.NullFloat64
	DisplayName string
	Hostname    string
	Path        string
}

func readAssetClass(t *testing.T, db *sql.DB, tenantID, assetID uuid.UUID) assetClassRow {
	t.Helper()
	var r assetClassRow
	if err := db.QueryRow(`
		SELECT class_key, COALESCE(class_source_kind, ''), COALESCE(class_source_ref, ''),
		       class_confidence, COALESCE(display_name, ''), COALESCE(hostname, ''), class_path
		  FROM assets WHERE tenant_id = $1 AND id = $2`,
		tenantID, assetID).Scan(&r.Class, &r.SourceKind, &r.SourceRef, &r.Confidence,
		&r.DisplayName, &r.Hostname, &r.Path); err != nil {
		t.Fatalf("read the asset: %v", err)
	}
	return r
}

type classHistoryRow struct {
	From   sql.NullString
	To     string
	Source string
	Actor  sql.NullString
}

func readClassHistory(t *testing.T, db *sql.DB, tenantID, assetID uuid.UUID) []classHistoryRow {
	t.Helper()
	rows, err := db.Query(`
		SELECT from_class_key, to_class_key, source, actor_user_id::text
		  FROM asset_class_history
		 WHERE tenant_id = $1 AND asset_id = $2
		 ORDER BY created_at, id`, tenantID, assetID)
	if err != nil {
		t.Fatalf("read the class history: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []classHistoryRow
	for rows.Next() {
		var r classHistoryRow
		if err := rows.Scan(&r.From, &r.To, &r.Source, &r.Actor); err != nil {
			t.Fatalf("scan the class history: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate the class history: %v", err)
	}
	return out
}

// reclassifyDB opens the test database WITH the seed.
//
// Not optional: the sink classifies through the CURATED `classification_rules`
// table, so on a schema-only database the rule set is empty, nothing is
// classified, no promotion happens — and every test here would pass or fail on
// whether some other package seeded the shared container first.
func reclassifyDB(t *testing.T) *sql.DB {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	return db
}

// assertOSRulesAreCurated checks the fixture against the engine the INGEST will
// actually use, not the compiled-in copy.
//
// The two are generated from the same YAML and agree today. They are still
// different objects, and the one that decides here is the table — so an
// `os_name` row that never reached seed.sql, or a CHECK constraint that refused
// it, fails loudly here rather than looking like a broken writer.
func assertOSRulesAreCurated(t *testing.T, ingest *HostInventoryIngest) {
	t.Helper()
	e := ingest.sink.classifier().Engine()
	if e.Len() == 0 {
		t.Fatal("the curated classification_rules table is empty; the database needs its seed")
	}
	got := e.Classify(context.Background(), classify.ClassifyInput{OS: "Microsoft Windows 11 Pro"})
	if got.Class != string(assetclass.KeyComputer) {
		t.Fatalf("the CURATED rules class Windows 11 as %q, want computer — the os_name rows did not reach "+
			"classification_rules, so nothing below would be testing the fix", got.Class)
	}
	if bare := e.Classify(context.Background(), classify.ClassifyInput{MACs: []string{reclassifyMAC}}); bare.Class != "" {
		t.Fatalf("the MAC %s now carries class %q; these tests could no longer tell an OS-derived class "+
			"from an OUI-derived one", reclassifyMAC, bare.Class)
	}
}

// ---------------------------------------------------------------------------

// TestIntegration_HostInventory_ReclassifiesAnAssetSeenPassivelyFirst is the
// reported bug, end to end.
//
// MUTATION LOG (each reverted after confirming red):
//   - delete the `facts.KeyOSName` case in hostInventoryClassEvidence → red
//     (class stays unknown_host)
//   - delete the classproposal.Promote call in recordClassOutcome → red
//   - drop `intent.FirstHand &&` so the peer path promotes too → the peer
//     suite's "a proposal must not change the asset" goes red
//   - delete the os_name rows from standards/classification-rules.yaml and
//     regenerate → red at assertOSRulesAreCurated
//   - delete the assetclasshistory.Record call in Promote → red (no history row)
//   - delete the nameAsset call → red (display_name stays the bare IP)
func TestIntegration_HostInventory_ReclassifiesAnAssetSeenPassivelyFirst(t *testing.T) {
	owner := reclassifyDB(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	jobID := newHostInventoryJob(t, appDB, owner, tenantID, agentID)

	// 20:18:54 — the passive sighting.
	assetID := passiveSighting(t, appDB, tenantID, "198.51.100.73")
	before := readAssetClass(t, owner, tenantID, assetID)
	if before.Class != string(assetclass.KeyUnknownHost) {
		t.Fatalf("the passive sighting was classed %q, want unknown_host: the premise of this test is gone", before.Class)
	}
	if before.DisplayName != "198.51.100.73" {
		t.Fatalf("display_name = %q, want the bare address the engine falls back to", before.DisplayName)
	}
	if got := readClassHistory(t, owner, tenantID, assetID); len(got) != 1 {
		t.Fatalf("%d class-history rows after creation, want 1", len(got))
	}

	// 20:21:44 — the host inventory, for the same machine.
	ingest := NewHostInventoryIngest(appDB, owner)
	assertOSRulesAreCurated(t, ingest)

	rep := windowsHostReport(agentID.String(), "5SDH994")
	counts, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentID, jobID, observationsFor(t, rep))
	if err != nil {
		t.Fatalf("MaterialiseAndRecord: %v", err)
	}
	if counts.Contested {
		t.Fatalf("the collection was contested: %s", counts.ContestedReason)
	}
	if counts.AssetID != assetID.String() {
		t.Fatalf("the inventory landed on asset %s, want the passively-seen %s — it must MATCH, not create",
			counts.AssetID, assetID)
	}
	if counts.AssetCreated {
		t.Fatal("asset_created = true; the inventory minted a second asset for one machine")
	}

	// --- the class ----------------------------------------------------------
	after := readAssetClass(t, owner, tenantID, assetID)
	if after.Class != string(assetclass.KeyComputer) {
		t.Errorf("class_key = %q, want computer — a fully inventoried Windows laptop is not an unknown host", after.Class)
	}
	if after.SourceKind != string(identity.ClassSourceRule) {
		t.Errorf("class_source_kind = %q, want rule: a rule argued this, nothing measured it", after.SourceKind)
	}
	if after.SourceRef == "" || after.SourceRef == "rule" {
		t.Errorf("class_source_ref = %q; it must cite the row a reviewer can go and read", after.SourceRef)
	}
	if after.Path == "" || after.Path == string(assetclass.KeyUnknownHost) {
		t.Errorf("class_path = %q; it must move with class_key or every facet puts the asset under its old branch", after.Path)
	}
	if !after.Confidence.Valid || after.Confidence.Float64 <= 0 {
		t.Errorf("class_confidence = %v, want the rule's own number", after.Confidence)
	}
	if !counts.ClassApplied {
		t.Error("class_applied = false on the job row while the class moved; the Job Logs line would be a lie")
	}
	if counts.ClassProposal != string(assetclass.KeyComputer) {
		t.Errorf("class_proposal = %q on the job row", counts.ClassProposal)
	}

	// --- the history --------------------------------------------------------
	hist := readClassHistory(t, owner, tenantID, assetID)
	if len(hist) != 2 {
		t.Fatalf("%d class-history rows after the class moved, want 2 (creation, then the promotion)", len(hist))
	}
	move := hist[1]
	if !move.From.Valid || move.From.String != string(assetclass.KeyUnknownHost) {
		t.Errorf("from_class_key = %v, want unknown_host", move.From)
	}
	if move.To != string(assetclass.KeyComputer) {
		t.Errorf("to_class_key = %q, want computer", move.To)
	}
	if move.Source != "classifier" {
		t.Errorf("source = %q, want classifier", move.Source)
	}
	if move.Actor.Valid {
		t.Errorf("actor_user_id = %v; a machine did this and NULL means 'no person'", move.Actor)
	}

	// --- the label ----------------------------------------------------------
	if after.Hostname != "xps16.example.net" {
		t.Errorf("hostname = %q, want xps16.example.net — prefer the measured canonical name", after.Hostname)
	}
	if after.DisplayName != "xps16.example.net" {
		t.Errorf("display_name = %q, want xps16.example.net: a bare address is not a name, and the platform knew the hostname",
			after.DisplayName)
	}

	// --- and no proposal ----------------------------------------------------
	//
	// A promotion and a proposal for the same answer would leave a pending
	// question in Approvals whose answer is already on the asset.
	if n := countRows(t, owner,
		`SELECT count(*) FROM asset_history WHERE tenant_id = $1 AND asset_id = $2 AND action = 'class_proposed'`,
		tenantID, assetID); n != 0 {
		t.Errorf("%d class proposals raised beside the promotion, want 0", n)
	}

	// --- and it is stable ---------------------------------------------------
	//
	// A second identical collection must change nothing. An intake that
	// re-proposed or re-wrote on unchanged evidence is how asset_class_history
	// and the approval queue become unreadable.
	job2 := newHostInventoryJob(t, appDB, owner, tenantID, agentID)
	if _, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentID, job2, observationsFor(t, rep)); err != nil {
		t.Fatalf("second MaterialiseAndRecord: %v", err)
	}
	if got := readClassHistory(t, owner, tenantID, assetID); len(got) != 2 {
		t.Errorf("%d class-history rows after an identical second collection, want 2", len(got))
	}
	if n := countRows(t, owner,
		`SELECT count(*) FROM asset_history WHERE tenant_id = $1 AND asset_id = $2 AND action = 'class_proposed'`,
		tenantID, assetID); n != 0 {
		t.Errorf("%d class proposals after an identical second collection, want 0", n)
	}
}

// TestIntegration_HostInventory_NeverStompsADeclaredClass is the polarity that
// matters most.
//
// A person who has said what a thing is has answered, and no measurement
// reopens that (ADR-0008 D4.2) — INCLUDING when what they declared is
// `unknown_host`, which is the case an "is it still the floor?" check alone
// would walk straight past. The class stays, the history stays at one row, and
// the answer goes to Approvals where a person can look at it.
//
// MUTATION: delete the `sourceKind == declared` guard in classproposal.Promote
// and this fails while every other test in the package stays green.
func TestIntegration_HostInventory_NeverStompsADeclaredClass(t *testing.T) {
	owner := reclassifyDB(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	jobID := newHostInventoryJob(t, appDB, owner, tenantID, agentID)

	assetID := passiveSighting(t, appDB, tenantID, "198.51.100.74")

	// A person opens the asset and says: I do not know what this is, leave it.
	if _, err := owner.Exec(`
		UPDATE assets SET class_source_kind = 'declared', class_source_ref = 'user:someone'
		 WHERE tenant_id = $1 AND id = $2`, tenantID, assetID); err != nil {
		t.Fatalf("declare the class: %v", err)
	}

	ingest := NewHostInventoryIngest(appDB, owner)
	assertOSRulesAreCurated(t, ingest)
	rep := windowsHostReport(agentID.String(), "5SDH995")
	counts, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentID, jobID, observationsFor(t, rep))
	if err != nil {
		t.Fatalf("MaterialiseAndRecord: %v", err)
	}
	if counts.AssetID != assetID.String() {
		t.Fatalf("the inventory landed on %s, want %s", counts.AssetID, assetID)
	}

	after := readAssetClass(t, owner, tenantID, assetID)
	if after.Class != string(assetclass.KeyUnknownHost) {
		t.Errorf("class_key = %q; a declared class was overwritten by a rule", after.Class)
	}
	if after.SourceKind != string(identity.ClassSourceDeclared) {
		t.Errorf("class_source_kind = %q, want declared", after.SourceKind)
	}
	if counts.ClassApplied {
		t.Error("class_applied = true while the class did not move")
	}
	if got := readClassHistory(t, owner, tenantID, assetID); len(got) != 1 {
		t.Errorf("%d class-history rows, want 1: nothing moved, so nothing is a move", len(got))
	}
}

// TestIntegration_HostInventory_ProposesRatherThanRestompsARealClass is the
// other polarity, and the anti-flapping one.
//
// An asset that already holds a real class holds an ANSWER, whoever gave it.
// The rules disagreeing with it is a question for a person, not a licence to
// overwrite — and an intake that did overwrite would churn the class (and
// therefore asset_class_history, and therefore any alerting built on class
// changes) on every single collection.
//
// MUTATION: drop the `!IsFallbackClassHint(current)` guard in
// classproposal.Promote and this fails.
func TestIntegration_HostInventory_ProposesRatherThanRestompsARealClass(t *testing.T) {
	owner := reclassifyDB(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	jobID := newHostInventoryJob(t, appDB, owner, tenantID, agentID)

	assetID := passiveSighting(t, appDB, tenantID, "198.51.100.75")

	// Something classified it a storage device — measured, not declared.
	if _, err := owner.Exec(`
		UPDATE assets
		   SET class_key = 'storage_device', class_path = 'hardware.storage_device',
		       class_source_kind = 'measured', class_source_ref = 'cmdb:import'
		 WHERE tenant_id = $1 AND id = $2`, tenantID, assetID); err != nil {
		t.Fatalf("set the prior class: %v", err)
	}

	ingest := NewHostInventoryIngest(appDB, owner)
	assertOSRulesAreCurated(t, ingest)
	rep := windowsHostReport(agentID.String(), "5SDH996")
	counts, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentID, jobID, observationsFor(t, rep))
	if err != nil {
		t.Fatalf("MaterialiseAndRecord: %v", err)
	}
	if counts.AssetID != assetID.String() {
		t.Fatalf("the inventory landed on %s, want %s", counts.AssetID, assetID)
	}

	after := readAssetClass(t, owner, tenantID, assetID)
	if after.Class != "storage_device" {
		t.Errorf("class_key = %q; a rule overwrote a class that had already been decided", after.Class)
	}
	if counts.ClassApplied {
		t.Error("class_applied = true while the class did not move")
	}
	if got := readClassHistory(t, owner, tenantID, assetID); len(got) != 1 {
		t.Errorf("%d class-history rows, want 1", len(got))
	}

	// The disagreement is not swallowed either: it is a question, and it goes
	// where questions go.
	props := classProposalsFor(t, owner, tenantID)
	if len(props) != 1 {
		t.Fatalf("%d class proposals, want 1 — a rule disagreeing with a decided class is for Approvals", len(props))
	}
	if props[0].Payload.ProposedClassKey != string(assetclass.KeyComputer) {
		t.Errorf("proposed_class_key = %q, want computer", props[0].Payload.ProposedClassKey)
	}
	if props[0].Payload.CurrentClassKey != "storage_device" {
		t.Errorf("current_class_key = %q; the proposal must read as a comparison", props[0].Payload.CurrentClassKey)
	}
}

// TestIntegration_HostInventory_CreatesANewAssetWithTheRulesClass covers the
// half that does NOT go through Promote: a machine nothing has seen before.
//
// The class is applied at creation with `rule` provenance and ONE history row,
// and the asset lands in `pending_approval` like every other discovery — so
// approving the asset approves the class, and nothing is asked twice.
//
// MUTATION: delete the classproposal.Apply call in Materialise and this fails
// (the asset is created `unknown_host` and nothing promotes it, because a
// create is deliberately not a promotion).
func TestIntegration_HostInventory_CreatesANewAssetWithTheRulesClass(t *testing.T) {
	owner := reclassifyDB(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	jobID := newHostInventoryJob(t, appDB, owner, tenantID, agentID)

	ingest := NewHostInventoryIngest(appDB, owner)
	assertOSRulesAreCurated(t, ingest)

	rep := windowsHostReport(agentID.String(), "5SDH997")
	counts, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentID, jobID, observationsFor(t, rep))
	if err != nil {
		t.Fatalf("MaterialiseAndRecord: %v", err)
	}
	if !counts.AssetCreated {
		t.Fatalf("asset_created = false for a host nothing had seen: %+v", counts)
	}
	assetID := uuid.MustParse(counts.AssetID)

	after := readAssetClass(t, owner, tenantID, assetID)
	if after.Class != string(assetclass.KeyComputer) {
		t.Errorf("class_key = %q, want computer", after.Class)
	}
	if after.SourceKind != string(identity.ClassSourceRule) {
		t.Errorf("class_source_kind = %q, want rule", after.SourceKind)
	}
	if !counts.ClassApplied {
		t.Error("class_applied = false while the asset was created with the rules' class")
	}

	var status string
	if err := owner.QueryRow(`SELECT asset_status FROM assets WHERE tenant_id = $1 AND id = $2`,
		tenantID, assetID).Scan(&status); err != nil {
		t.Fatalf("read the status: %v", err)
	}
	if status != "pending_approval" {
		t.Errorf("asset_status = %q, want pending_approval — the asset's own approval is what covers the class", status)
	}

	// ONE row. A create that also promoted would write a second, claiming a
	// move from a class the asset never held.
	hist := readClassHistory(t, owner, tenantID, assetID)
	if len(hist) != 1 {
		t.Fatalf("%d class-history rows for a created asset, want 1", len(hist))
	}
	if hist[0].From.Valid {
		t.Errorf("from_class_key = %v on a creation row, want NULL", hist[0].From)
	}
	if hist[0].To != string(assetclass.KeyComputer) {
		t.Errorf("to_class_key = %q, want computer", hist[0].To)
	}

	if n := countRows(t, owner,
		`SELECT count(*) FROM asset_history WHERE tenant_id = $1 AND asset_id = $2 AND action = 'class_proposed'`,
		tenantID, assetID); n != 0 {
		t.Errorf("%d class proposals for an asset created WITH the class, want 0", n)
	}

	// A guard against the payload drifting out from under this file: the class
	// must have come from the OS and nothing else.
	ev := hostInventoryClassEvidence(observationsFor(t, rep))
	if ev.OS != "Microsoft Windows 11 Pro" {
		t.Errorf("the collector projection no longer carries os.name: %+v", ev)
	}
}

// Interleave a human declaration after Promote reads the floor but before its
// UPDATE. The class key stays unknown_host, so comparing that key alone cannot
// protect the person's decision.
type declarationBeforePromotion struct {
	*sql.DB
	tenant, asset uuid.UUID
}

func (d declarationBeforePromotion) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if strings.Contains(query, "UPDATE assets") {
		if _, err := d.DB.ExecContext(ctx, `UPDATE assets SET class_source_kind = 'declared' WHERE tenant_id = $1 AND id = $2`, d.tenant, d.asset); err != nil {
			return nil, err
		}
	}
	return d.DB.ExecContext(ctx, query, args...)
}
func TestIntegration_HostInventory_ConcurrentDeclarationWinsPromotion(t *testing.T) {
	owner := reclassifyDB(t)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	asset := passiveSighting(t, app, tenant, "198.51.100.77")
	promoted, err := classproposal.Promote(context.Background(), declarationBeforePromotion{owner, tenant, asset}, tenant, asset, classify.ClassProposal{Class: "computer", Confidence: 0.75})
	if err != nil {
		t.Fatal(err)
	}
	if promoted {
		t.Fatal("promotion overwrote a concurrent declaration")
	}
	after := readAssetClass(t, owner, tenant, asset)
	if after.Class != "unknown_host" || after.SourceKind != "declared" {
		t.Fatalf("declaration lost: %+v", after)
	}
}

func TestIntegration_HostInventory_SplitWindowsProjectsSiteWithoutListeners(t *testing.T) {
	owner := reclassifyDB(t)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	agent := seedHostInventoryAgent(t, owner, tenant)
	location, segment := uuid.New(), uuid.New()
	if _, err := owner.Exec(`INSERT INTO locations(id,tenant_id,name,location_type) VALUES($1,$2,'North','site')`, location, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment,location_id) VALUES($1,$2,'North','cidr','198.51.100.0/24','production',$3)`, segment, tenant, location); err != nil {
		t.Fatal(err)
	}
	report := windowsHostReport(agent.String(), "SPLIT-WINDOWS")
	report.Host.OS = "Windows"
	report.Host.OSVersion = "11 Enterprise"
	report.Listeners = nil
	ingest := NewHostInventoryIngest(app, owner)
	var assetID string
	for i := 0; i < 2; i++ {
		job := newHostInventoryJob(t, app, owner, tenant, agent)
		counts, err := ingest.MaterialiseAndRecord(context.Background(), tenant, agent, job, observationsFor(t, report))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			assetID = counts.AssetID
		} else if assetID != counts.AssetID {
			t.Fatal("inventory changed identity")
		}
		var site, class, loc string
		if err = owner.QueryRow(`SELECT site,location_id::text,class_key FROM assets WHERE id=$1 AND tenant_id=$2`, assetID, tenant).Scan(&site, &loc, &class); err != nil {
			t.Fatal(err)
		}
		if site != "North" || loc != location.String() || class != "computer" {
			t.Fatalf("placement/class=%s %s %s", site, loc, class)
		}
	}
	var n int
	if err := owner.QueryRow(`SELECT count(*) FROM asset_history WHERE asset_id=$1 AND changes_json ? 'location_id'`, assetID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("placement histories=%d", n)
	}
}
