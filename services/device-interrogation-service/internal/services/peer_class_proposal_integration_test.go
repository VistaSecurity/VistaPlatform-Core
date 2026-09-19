package services

// Class proposals for an interrogated PEER (workstream 4.6a, closing a
// 2.10b/4.2 limit).
//
// # What was broken
//
// ObservationSink has always run the classifier over what a peer reference
// carries, and could do only one thing with the answer: put a RULE's class onto
// a peer it was about to CREATE. Everything else was computed and thrown away —
// a class for an EXISTING peer, and any class the learned classifier proposed —
// because this service had no proposal writer. The code said so in a comment and
// called it follow-up work.
//
// The consequence was invisible and one-directional: a switch's LLDP neighbour
// that the inventory already knew as `unknown_host` stayed `unknown_host` for
// ever, however clearly the curated rules identified it, and nothing anywhere
// recorded that an answer had been discarded.
//
// # What these pin
//
//  1. A rule class for an EXISTING peer becomes a proposal, citing the rule.
//  2. It never changes the asset's class. A class is not overwritten, ever.
//  3. A MODEL's class never reaches an asset — on create or on match — and lands
//     as a proposal stamped `inferred` + `model:<id>`, not `rule`.
//  4. A rule and a model both having an answer means the RULE's answer, with
//     rule provenance: a model never overrules a deterministic, citable rule.
//  5. With the model half off, a peer the rules cannot class produces NOTHING —
//     no proposal, no guess.
//
// Every one of these guards a failure that produces no error anywhere. A model
// proposal stamped `rule` passes every database constraint and is only
// detectable by somebody auditing provenance six months later.
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/classify"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/identityaudit"
	"github.com/vistasecurity/vistaplatform/shared/relationships"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// MAC fixtures. The OUI table is generated from IEEE's registry, so these are
// asserted rather than assumed: a catalogue change that gave the vendor-only one
// a class would turn the model tests into rule tests, silently and while still
// passing.
const (
	// cisco: OUI 00:00:0C, which the shipped rules class as network_device.
	macClassedByRule = "00:00:0c:11:22:33"
	// xerox: OUI 00:00:01, a VENDOR-only row — Xerox sells printers, servers
	// and network gear, so the rule names no class.
	macUnclassedByRule = "00:00:01:44:55:66"
	// a second unclassed MAC, so a peer can be re-observed carrying one MAC it
	// is already known by plus one that carries new evidence.
	macUnclassedByRuleB = "00:00:0e:77:88:99"
)

func assertRuleFixtures(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	classed := classify.Default().Classify(ctx, classify.ClassifyInput{MACs: []string{macClassedByRule}})
	if classed.Class != string(assetclass.KeyNetworkDevice) {
		t.Fatalf("the shipped rules class %s as %q, want network_device: the fixtures no longer say what they claim",
			macClassedByRule, classed.Class)
	}
	for _, mac := range []string{macUnclassedByRule, macUnclassedByRuleB} {
		out := classify.Default().Classify(ctx, classify.ClassifyInput{MACs: []string{mac}})
		if out.Class != "" || out.Conflict {
			t.Fatalf("the shipped rules now decide %s (%+v); the model tests below would become rule tests", mac, out)
		}
	}
}

// stubModelClassifier answers with a MODEL's voice where the curated rules
// cannot.
//
// It is the chain in miniature, and it is the chain's CONTRACT that matters
// here: rules first and decisive, model only where they were silent, and the
// model's answer always carrying a ModelID. The shipped weights decline on a
// MAC alone, so this is the only way to reach the branch at all.
type stubModelClassifier struct {
	rules seams.RuleClassifier
	class string
	model string
}

func (s stubModelClassifier) Classify(ctx context.Context, facts seams.AssetFacts) (seams.ClassProposal, error) {
	return s.rules.Classify(ctx, facts)
}

func (s stubModelClassifier) Explain(ctx context.Context, facts seams.AssetFacts) classify.ClassProposal {
	out := seams.Explain(ctx, s.rules, facts)
	if out.Class != "" || out.Conflict {
		// The rules decided. A model never overrules them (ADR-0008 D3), and a
		// stub that did would be testing a product that does not exist.
		return out
	}
	return classify.ClassProposal{
		Class:            s.class,
		Confidence:       0.91,
		ModelID:          s.model,
		ModelProbability: 0.91,
		ModelReasons:     []classify.ModelReason{{Feature: "oui/stub", Label: "the MAC prefix is registered to a stub vendor", Contribution: 1}},
	}
}

// sinkWithClassifier builds an ObservationSink whose peers are classified
// through `set`.
func sinkWithClassifier(db *sql.DB, set func() seams.Set) *ObservationSink {
	s := NewObservationSink(db)
	s.classifierSet = set
	return s
}

// modelSet is the seam default with the classifier replaced by the stub chain.
func modelSet(class, model string) func() seams.Set {
	return func() seams.Set {
		out := seams.Default()
		out.Classifier = stubModelClassifier{class: class, model: model}
		return out
	}
}

// rulesOnlySet is what `CLASSIFIER_MODEL_ENABLED=false` makes the default
// behave as: the curated rules, and no model at all.
func rulesOnlySet() seams.Set {
	out := seams.Default()
	out.Classifier = seams.RuleClassifier{}
	return out
}

// peerWith builds the relationship observation a collector emits for a
// neighbour described only by MAC addresses.
func peerWith(name string, macs ...string) InterrogationObservations {
	peer := di.PeerRef{DisplayName: name}
	for _, m := range macs {
		peer.Identifiers = append(peer.Identifiers, di.PeerIdentifier{Kind: di.IdentifierMACAddress, Value: m})
	}
	return InterrogationObservations{
		Relationships: []di.RelationshipObservation{{
			Type:      string(relationships.ConnectsTo),
			Peer:      peer,
			Direction: di.SubjectToPeer,
		}},
	}
}

// subjectAsset creates the asset an interrogation is ABOUT, so the sink has a
// self to hang the edge on.
func subjectAsset(t *testing.T, db *sql.DB, tenant uuid.UUID, name string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status)
		VALUES ($1, $2, $3, 'network_device', 'hardware.network_device', 'monitoring')`,
		id, tenant, name); err != nil {
		t.Fatalf("seed the subject asset: %v", err)
	}
	return id
}

// classProposals reads every class proposal a tenant has, newest first.
type classProposalRow struct {
	AssetID uuid.UUID
	Source  string
	Payload struct {
		Kind             string   `json:"kind"`
		ProposedClassKey string   `json:"proposed_class_key"`
		CurrentClassKey  string   `json:"current_class_key"`
		SourceKind       string   `json:"class_source_kind"`
		SourceRef        string   `json:"class_source_ref"`
		ModelID          string   `json:"model_id"`
		RuleIDs          []string `json:"rule_ids"`
		Status           string   `json:"status"`
	}
}

func classProposalsFor(t *testing.T, db *sql.DB, tenant uuid.UUID) []classProposalRow {
	t.Helper()
	rows, err := db.Query(`
		SELECT asset_id, source, changes_json::text FROM asset_history
		 WHERE tenant_id = $1 AND action = 'class_proposed'
		   AND changes_json->>'kind' = 'class_proposal'
		 ORDER BY created_at DESC, seq DESC`, tenant)
	if err != nil {
		t.Fatalf("read class proposals: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []classProposalRow
	for rows.Next() {
		var r classProposalRow
		var payload string
		if err := rows.Scan(&r.AssetID, &r.Source, &payload); err != nil {
			t.Fatalf("scan class proposal: %v", err)
		}
		if err := json.Unmarshal([]byte(payload), &r.Payload); err != nil {
			t.Fatalf("decode class proposal: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate class proposals: %v", err)
	}
	return out
}

func classOfAsset(t *testing.T, db *sql.DB, tenant, asset uuid.UUID) (class, sourceKind string) {
	t.Helper()
	if err := db.QueryRow(
		`SELECT class_key, COALESCE(class_source_kind, '') FROM assets WHERE tenant_id = $1 AND id = $2`,
		tenant, asset).Scan(&class, &sourceKind); err != nil {
		t.Fatalf("read the asset's class: %v", err)
	}
	return class, sourceKind
}

// connectPeerTestDB opens the test database with the SEED applied.
//
// The seed is not optional here and the reason is the shape this repo keeps
// hitting. ObservationSink classifies through the CURATED table
// (`classification_rules`), loaded once at first use — so on a database with the
// schema but no seed the rule set is EMPTY, nothing classifies, no proposal is
// raised, and every test in this file passes or fails on whether some OTHER
// package happened to seed the shared container first. It did, which is why
// these were green before they were run on a fresh one.
//
// assertCuratedRules below is the other half: it asks the engine the sink will
// actually use, so "the table is empty" fails loudly instead of looking like
// "the writer is broken".
func connectPeerTestDB(t *testing.T) *sql.DB {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	return db
}

// assertCuratedRules checks the fixtures against the engine the SINK will use —
// the curated table, not the compiled-in copy.
//
// The two are generated from the same source and agree today. They are still
// different objects, and it is the curated one that decides here.
func assertCuratedRules(t *testing.T, sink *ObservationSink) {
	t.Helper()
	e := sink.classifier().Engine()
	if e.Len() == 0 {
		t.Fatal("the curated classification_rules table is empty, so nothing can be classified and these tests " +
			"would pass for the wrong reason; the database needs its seed")
	}
	ctx := context.Background()
	if got := e.Classify(ctx, classify.ClassifyInput{MACs: []string{macClassedByRule}}); got.Class != string(assetclass.KeyNetworkDevice) {
		t.Fatalf("the curated rules class %s as %q, want network_device", macClassedByRule, got.Class)
	}
	for _, mac := range []string{macUnclassedByRule, macUnclassedByRuleB} {
		if got := e.Classify(ctx, classify.ClassifyInput{MACs: []string{mac}}); got.Class != "" || got.Conflict {
			t.Fatalf("the curated rules now decide %s (%+v); the model tests would become rule tests", mac, got)
		}
	}
}

func newPeerTenant(t *testing.T, db *sql.DB) uuid.UUID { return testdb.NewTenant(t, db) }

func peerSource(ref string) identity.Source {
	return identity.Source{Kind: identity.SourceMeasured, Ref: ref}
}

// ---------------------------------------------------------------------------

// TestIntegration_ObservationSink_RuleProposalForAnExistingPeer: the rules
// identify a peer the inventory already holds, and that becomes a PROPOSAL
// rather than nothing.
//
// MUTATION: delete the recordClassOutcome call in resolveObservationWith and
// this fails while every other test in the package stays green — which is
// exactly how the gap survived from 2.10b to here.
func TestIntegration_ObservationSink_RuleProposalForAnExistingPeer(t *testing.T) {
	db := connectPeerTestDB(t)
	assertRuleFixtures(t)
	tenant := newPeerTenant(t, db)
	sink := NewObservationSink(db)
	assertCuratedRules(t, sink)
	ctx := context.Background()
	self := subjectAsset(t, db, tenant, "switch-peerclass-rule")

	// First sighting: one MAC the rules cannot class. The peer is created, and
	// `unknown_host` is the honest answer — nothing classified it.
	if err := sink.Persist(ctx, tenant, self, peerSource("interrogation:peerclass-1"),
		peerWith("neighbour-a", macUnclassedByRule)); err != nil {
		t.Fatalf("first Persist: %v", err)
	}
	if got := classProposalsFor(t, db, tenant); len(got) != 0 {
		t.Fatalf("%d class proposals for a peer nothing classified; silence is the right answer", len(got))
	}
	peer := peerAssetByMAC(t, db, tenant, macUnclassedByRule)
	if class, _ := classOfAsset(t, db, tenant, peer); class != string(assetclass.KeyUnknownHost) {
		t.Fatalf("the created peer is classed %q, want unknown_host", class)
	}

	// Second sighting: the same peer, now also reporting a MAC whose OUI the
	// curated rules DO class. It matches the existing asset, so the class
	// cannot be written onto it — it is a question for Approvals.
	if err := sink.Persist(ctx, tenant, self, peerSource("interrogation:peerclass-2"),
		peerWith("neighbour-a", macUnclassedByRule, macClassedByRule)); err != nil {
		t.Fatalf("second Persist: %v", err)
	}

	props := classProposalsFor(t, db, tenant)
	if len(props) != 1 {
		t.Fatalf("%d class proposals after the rules identified an existing peer, want 1", len(props))
	}
	p := props[0]
	if p.AssetID != peer {
		t.Errorf("the proposal is about asset %s, want the peer %s", p.AssetID, peer)
	}
	if p.Payload.ProposedClassKey != string(assetclass.KeyNetworkDevice) {
		t.Errorf("proposed_class_key = %q, want network_device", p.Payload.ProposedClassKey)
	}
	if p.Payload.CurrentClassKey != string(assetclass.KeyUnknownHost) {
		t.Errorf("current_class_key = %q, want unknown_host — the proposal must read as a comparison", p.Payload.CurrentClassKey)
	}
	if p.Payload.SourceKind != string(identity.ClassSourceRule) {
		t.Errorf("class_source_kind = %q, want rule", p.Payload.SourceKind)
	}
	if p.Payload.SourceRef == "" || p.Payload.SourceRef == "rule" {
		t.Errorf("class_source_ref = %q; a rule proposal must cite the rule a reviewer can go and read", p.Payload.SourceRef)
	}
	if p.Source != "classifier:rules" {
		t.Errorf("source = %q, want classifier:rules so the Approvals facet says who is asking", p.Source)
	}
	if p.Payload.Status != "pending" {
		t.Errorf("status = %q, want pending", p.Payload.Status)
	}

	// And the asset itself is untouched. A class is not overwritten, ever.
	if class, _ := classOfAsset(t, db, tenant, peer); class != string(assetclass.KeyUnknownHost) {
		t.Errorf("the peer's class became %q; a proposal must not change the asset", class)
	}
}

// TestIntegration_ObservationSink_ModelNeverSetsAClass: a model's answer goes to
// Approvals, on a NEW peer and on an existing one, stamped `inferred`.
func TestIntegration_ObservationSink_ModelNeverSetsAClass(t *testing.T) {
	db := connectPeerTestDB(t)
	assertRuleFixtures(t)
	tenant := newPeerTenant(t, db)
	sink := sinkWithClassifier(db, modelSet(string(assetclass.KeyPrinter), "classifier-stub-v1"))
	assertCuratedRules(t, sink)
	ctx := context.Background()
	self := subjectAsset(t, db, tenant, "switch-peerclass-model")

	if err := sink.Persist(ctx, tenant, self, peerSource("interrogation:peerclass-model"),
		peerWith("neighbour-m", macUnclassedByRule)); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	peer := peerAssetByMAC(t, db, tenant, macUnclassedByRule)
	class, sourceKind := classOfAsset(t, db, tenant, peer)
	if class != string(assetclass.KeyUnknownHost) {
		t.Errorf("a NEW peer was created classed %q from a model's answer; a machine's guess must not enter the "+
			"inventory with nobody having read it (ADR-0008 D3)", class)
	}
	if sourceKind == string(identity.ClassSourceInferred) {
		t.Errorf("class_source_kind = %q on the asset; the model never stamps a class", sourceKind)
	}

	props := classProposalsFor(t, db, tenant)
	if len(props) != 1 {
		t.Fatalf("%d class proposals for a peer only the model could class, want 1 — the answer was dropped", len(props))
	}
	p := props[0]
	if p.Payload.ProposedClassKey != string(assetclass.KeyPrinter) {
		t.Errorf("proposed_class_key = %q, want printer", p.Payload.ProposedClassKey)
	}
	if p.Payload.SourceKind != string(identity.ClassSourceInferred) {
		t.Errorf("class_source_kind = %q, want inferred — `rule` would claim a citable source the model does not have",
			p.Payload.SourceKind)
	}
	if p.Payload.SourceRef != "model:classifier-stub-v1" {
		t.Errorf("class_source_ref = %q, want model:classifier-stub-v1", p.Payload.SourceRef)
	}
	if p.Payload.ModelID != "classifier-stub-v1" {
		t.Errorf("model_id = %q, want classifier-stub-v1", p.Payload.ModelID)
	}
	if p.Source != "classifier:model" {
		t.Errorf("source = %q, want classifier:model", p.Source)
	}
}

// TestIntegration_ObservationSink_RuleBeatsModel: where the curated rules have
// an answer, the model's is not consulted and the provenance says `rule`.
func TestIntegration_ObservationSink_RuleBeatsModel(t *testing.T) {
	db := connectPeerTestDB(t)
	assertRuleFixtures(t)
	tenant := newPeerTenant(t, db)
	sink := sinkWithClassifier(db, modelSet(string(assetclass.KeyPrinter), "classifier-stub-v1"))
	assertCuratedRules(t, sink)
	ctx := context.Background()
	self := subjectAsset(t, db, tenant, "switch-peerclass-precedence")

	if err := sink.Persist(ctx, tenant, self, peerSource("interrogation:peerclass-precedence"),
		peerWith("neighbour-r", macClassedByRule)); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	peer := peerAssetByMAC(t, db, tenant, macClassedByRule)
	class, sourceKind := classOfAsset(t, db, tenant, peer)
	if class != string(assetclass.KeyNetworkDevice) {
		t.Errorf("the created peer is classed %q, want network_device: a RULE's class IS written at creation, "+
			"because it is deterministic and cites a source and the asset's own approval covers it", class)
	}
	if sourceKind != string(identity.ClassSourceRule) {
		t.Errorf("class_source_kind = %q, want rule", sourceKind)
	}
	if got := classProposalsFor(t, db, tenant); len(got) != 0 {
		t.Fatalf("%d class proposals for a peer the rules classed at creation: approving the asset approves the "+
			"class, and proposing it as well asks one question twice", len(got))
	}
}

// TestIntegration_ObservationSink_ModelOffProposesNothing: with the model half
// off, a peer the rules cannot class produces no proposal and no guess.
//
// This is the polarity that must not be assumed. `CLASSIFIER_MODEL_ENABLED=false`
// is documented to leave the rules running and nothing else, and a wiring that
// ignored it would look identical in every other test here.
func TestIntegration_ObservationSink_ModelOffProposesNothing(t *testing.T) {
	db := connectPeerTestDB(t)
	assertRuleFixtures(t)
	tenant := newPeerTenant(t, db)
	sink := sinkWithClassifier(db, rulesOnlySet)
	assertCuratedRules(t, sink)
	ctx := context.Background()
	self := subjectAsset(t, db, tenant, "switch-peerclass-modeloff")

	if err := sink.Persist(ctx, tenant, self, peerSource("interrogation:peerclass-modeloff"),
		peerWith("neighbour-off", macUnclassedByRule)); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if got := classProposalsFor(t, db, tenant); len(got) != 0 {
		t.Fatalf("%d class proposals with the model half off", len(got))
	}
	peer := peerAssetByMAC(t, db, tenant, macUnclassedByRule)
	if class, _ := classOfAsset(t, db, tenant, peer); class != string(assetclass.KeyUnknownHost) {
		t.Errorf("the peer is classed %q with the model off, want unknown_host", class)
	}
}

// TestObservationSink_DefaultsToTheShippedSeams: production wiring resolves the
// classifier through [seams.Default], and the stub seam above is a test-only
// override that no constructor sets.
//
// Without this, a future edit that left `classifierSet` pointing at something
// else would be invisible: every test in this file installs its own.
func TestObservationSink_DefaultsToTheShippedSeams(t *testing.T) {
	for name, s := range map[string]*ObservationSink{
		"NewObservationSink": NewObservationSink(nil),
	} {
		if s.classifierSet != nil {
			t.Errorf("%s set a classifier override; production must resolve through seams.Default", name)
		}
	}
	if _, ok := seams.Default().Classifier.(seams.ChainClassifier); !ok {
		t.Errorf("the seam default is %T, not the rules+model chain; peers would stop being classified as "+
			"inventory-service classifies them", seams.Default().Classifier)
	}
}

// peerAssetByMAC finds the asset a peer's MAC identifier resolved to.
func peerAssetByMAC(t *testing.T, db *sql.DB, tenant uuid.UUID, mac string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := db.QueryRow(`
		SELECT asset_id FROM asset_identifiers
		 WHERE tenant_id = $1 AND kind = 'mac_address' AND value = $2`,
		tenant, normaliseMACForLookup(mac)).Scan(&id)
	if err != nil {
		t.Fatalf("find the peer asset by %s: %v", mac, err)
	}
	return id
}

// normaliseMACForLookup mirrors identity.Identifier.Normalized for MACs, so the
// test looks the row up the way it was stored rather than the way it was typed.
func normaliseMACForLookup(mac string) string {
	id, err := identity.Identifier{Kind: identity.KindMACAddress, Value: mac, SeenAt: time.Now()}.Normalized()
	if err != nil {
		return mac
	}
	return id.Value
}

// ---------------------------------------------------------------------------
// the tenant's auto-accept threshold, on the SINK's engine
// ---------------------------------------------------------------------------

// TestIntegration_ObservationSink_AutoAcceptThresholdReachesTheEngine: the
// second of this service's two identity engines honours the tenant's setting
// too (workstream 4.6a).
//
// DeviceService's engine and this one are built separately and neither owns the
// other — ObservationSink says so in its own doc comment — so wiring one proves
// nothing about the other. A collector's LLDP neighbour and an operator's
// manually added device are the same question asked twice, and a tenant whose
// answer applied to one of them and not the other would have no way to tell
// which.
//
// MUTATION: drop WithAutoAcceptThreshold from resolveObservationWith and this
// goes red while every DeviceService test stays green.
func TestIntegration_ObservationSink_AutoAcceptThresholdReachesTheEngine(t *testing.T) {
	db := connectPeerTestDB(t)
	audit := installCaptureAudit(t)
	sink := NewObservationSink(db)

	// ── the control: the default threshold never accepts ────────────────────
	def := newPeerTenant(t, db)
	defSelf := subjectAsset(t, db, def, "switch-peer-autoaccept-a")
	stagePeerConflict(t, sink, db, def, defSelf, "a")
	if n := autoAcceptedHistoryCount(t, db, def); n != 0 {
		t.Fatalf("a tenant that has set NOTHING auto-accepted %d peer merge(s)", n)
	}
	if n := len(audit.all()); n != 0 {
		t.Fatalf("%d audit events on a tenant that auto-accepted nothing", n)
	}

	score := topProposalScore(t, db, def)
	t.Logf("the shipped model scored the contested peer %.4f", score)
	if score < 0.1 {
		t.Fatalf("the contested peer scored %.4f: nothing is scoring it, so this test cannot distinguish "+
			"a wired threshold from an unwired one", score)
	}
	threshold := math.Floor(score*100) / 100
	if threshold <= 0 {
		t.Fatalf("derived threshold %v is not above zero", threshold)
	}

	// ── the subject ─────────────────────────────────────────────────────────
	set := newPeerTenant(t, db)
	writeAutoAcceptThreshold(t, db, set, threshold)
	audit.reset()
	setSelf := subjectAsset(t, db, set, "switch-peer-autoaccept-b")
	stagePeerConflict(t, sink, db, set, setSelf, "a")
	if n := autoAcceptedHistoryCount(t, db, set); n != 1 {
		t.Fatalf("a tenant whose stored threshold is %v got %d auto-accepted peer merges on a candidate scoring %.4f, "+
			"want 1: the setting is not reaching the ObservationSink's engine", threshold, n, score)
	}

	// The SAME audit event DeviceService writes. A tenant asking what the
	// matcher has done to their inventory is asking one question.
	events := audit.all()
	if len(events) != 1 {
		t.Fatalf("%d audit events for one auto-accepted peer merge, want 1", len(events))
	}
	if got, _ := events[0].Metadata["actor"].(string); got != identityaudit.ActorMatcher {
		t.Errorf("actor = %q, want %q", got, identityaudit.ActorMatcher)
	}
	if events[0].EventType != identityaudit.EventType {
		t.Errorf("event_type = %q, want %q", events[0].EventType, identityaudit.EventType)
	}

	// ── per tenant, read fresh ──────────────────────────────────────────────
	stagePeerConflict(t, sink, db, def, defSelf, "b")
	if n := autoAcceptedHistoryCount(t, db, def); n != 0 {
		t.Fatalf("the default-threshold tenant auto-accepted %d peer merge(s) after ANOTHER tenant set a threshold", n)
	}
}

// stagePeerConflict observes a peer whose every identifier already belongs to a
// different in-service asset: the identity floor's contested shape, which is
// where a peer merge can be auto-accepted at all.
//
// Both owners are promoted to `monitoring` because the auto-accept refuses to
// merge into anything still in Approvals — leaving them pending would make this
// pass for the wrong reason.
func stagePeerConflict(t *testing.T, sink *ObservationSink, db *sql.DB, tenant, self uuid.UUID, run string) {
	t.Helper()
	ctx := context.Background()
	mac := "02:00:5e:10:00:" + run + "1"
	host := "peer-conflict-" + run
	src := peerSource("interrogation:peer-conflict-" + run)

	if err := sink.Persist(ctx, tenant, self, src, peerWith("owner-mac-"+run, mac)); err != nil {
		t.Fatalf("stage the MAC owner: %v", err)
	}
	if err := sink.Persist(ctx, tenant, self, src, peerNamed("owner-host-"+run, host)); err != nil {
		t.Fatalf("stage the hostname owner: %v", err)
	}
	byMAC := peerAssetByMAC(t, db, tenant, mac)
	byHost := peerAssetByHostname(t, db, tenant, host)
	if byMAC == byHost {
		t.Fatal("the two staged peers resolved to ONE asset; the fixture is not contested")
	}
	promoteAssetToMonitoring(t, db, tenant, byMAC)
	promoteAssetToMonitoring(t, db, tenant, byHost)

	// Carries both: the MAC belongs to one asset, the hostname to another, and
	// neither may decide — so the engine ranks them and either opens a proposal
	// or accepts the winner.
	peer := di.PeerRef{DisplayName: "contested-" + run}
	peer.Identifiers = []di.PeerIdentifier{
		{Kind: di.IdentifierMACAddress, Value: mac},
		{Kind: di.IdentifierHostname, Value: host},
	}
	obs := InterrogationObservations{Relationships: []di.RelationshipObservation{{
		Type:      string(relationships.ConnectsTo),
		Peer:      peer,
		Direction: di.SubjectToPeer,
	}}}
	// A contested peer is reported by Persist as a skipped EDGE, not as a
	// failure of the interrogation, so an error here would be a real one.
	if err := sink.Persist(ctx, tenant, self, src, obs); err != nil {
		t.Fatalf("observe the contested peer: %v", err)
	}
}

// peerNamed is a peer described only by a bare hostname.
func peerNamed(display, hostname string) InterrogationObservations {
	return InterrogationObservations{Relationships: []di.RelationshipObservation{{
		Type: string(relationships.ConnectsTo),
		Peer: di.PeerRef{
			DisplayName: display,
			Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierHostname, Value: hostname}},
		},
		Direction: di.SubjectToPeer,
	}}}
}

func peerAssetByHostname(t *testing.T, db *sql.DB, tenant uuid.UUID, hostname string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(`
		SELECT asset_id FROM asset_identifiers
		 WHERE tenant_id = $1 AND kind = 'hostname' AND value = $2`,
		tenant, hostname).Scan(&id); err != nil {
		t.Fatalf("find the peer asset by hostname %s: %v", hostname, err)
	}
	return id
}

func TestIntegration_ObservationSink_RetainsWeakPeerFactsAndEdges(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenant, other := testdb.NewTenant(t, owner), testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	app.SetMaxOpenConns(1)
	self := subjectAsset(t, owner, tenant, "controller")
	target := subjectAsset(t, owner, tenant, "verified-target")
	oldSeen := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Microsecond)
	if _, err := owner.Exec(`UPDATE assets SET last_seen_at=$3,class_key='unknown_host',class_source_kind='declared',site='Operator site' WHERE tenant_id=$1 AND id=$2`, tenant, target, oldSeen); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"}}')`, tenant); err != nil {
		t.Fatal(err)
	}
	enable := func(s *ObservationSink) {
		t.Helper()
		_, repo, err := s.engine()
		if err != nil {
			t.Fatal(err)
		}
		s.eng, err = identity.New(identity.Config{Repo: repo, AdmissionEnabled: true})
		if err != nil {
			t.Fatal(err)
		}
	}
	sink := NewObservationSink(app)
	enable(sink)
	seen := oldSeen.Add(time.Hour)
	peer := di.PeerRef{DisplayName: "mystery.local", Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierHostname, Value: "mystery.local"}}}
	obs := InterrogationObservations{ObservedAt: seen,
		Facts:         []di.FactObservation{{Subject: peer, Key: "hw.model", Value: "Access point", Confidence: .8}},
		Relationships: []di.RelationshipObservation{{Type: string(relationships.ConnectsTo), Direction: di.SubjectToPeer, Peer: peer, Attributes: map[string]interface{}{"port": "4", "auth_key": "must-not-retain-this-secret"}}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for range 2 {
		if err := sink.Persist(ctx, tenant, self, peerSource("interrogation:retained-peer"), obs); err != nil {
			t.Fatal(err)
		}
	}
	if n := countRows(t, owner, `SELECT count(*) FROM assets WHERE tenant_id=$1`, tenant); n != 2 {
		t.Fatalf("weak peer created asset: %d", n)
	}
	var observation uuid.UUID
	var body string
	if err := owner.QueryRow(`SELECT observation_id,payload::text FROM identity_observation_peer_contexts WHERE tenant_id=$1`, tenant).Scan(&observation, &body); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, "must-not-retain-this-secret") || !strings.Contains(body, "Access point") {
		t.Fatalf("retained payload lost typed context or kept secrets")
	}
	if n := countRows(t, owner, `SELECT occurrence_count FROM identity_observations WHERE tenant_id=$1 AND id=$2`, tenant, observation); n != 1 {
		t.Fatalf("repeated delivery counted as corroboration: %d", n)
	}
	if _, err := owner.Exec(`UPDATE identity_observations SET state='linked',asset_id=$3,confirmed_by=$4 WHERE tenant_id=$1 AND id=$2`, tenant, observation, target, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`UPDATE assets SET asset_status='pending_approval' WHERE tenant_id=$1 AND id=$2`, tenant, target); err != nil {
		t.Fatal(err)
	}
	restarted := NewObservationSink(app)
	enable(restarted)
	if err := restarted.ReplayRetainedPeers(ctx, other); err != nil {
		t.Fatal(err)
	}
	if err := restarted.ReplayRetainedPeers(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, owner, `SELECT count(*) FROM asset_facts WHERE tenant_id=$1 AND asset_id=$2 AND key='hw.model'`, tenant, target); n != 0 {
		t.Fatal("unapproved linked peer materialized")
	}
	survivor := subjectAsset(t, owner, tenant, "controller-survivor")
	if _, err := owner.Exec(`UPDATE assets SET asset_status='archived',metadata=jsonb_build_object('merged_into',$3::text) WHERE tenant_id=$1 AND id=$2`, tenant, self, survivor); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`UPDATE assets SET asset_status='monitoring' WHERE tenant_id=$1 AND id=$2`, tenant, target); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`UPDATE identity_observation_peer_contexts SET next_attempt_at=now() WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := restarted.ReplayRetainedPeers(ctx, tenant); err != nil {
			t.Fatal(err)
		}
	}
	if n := countRows(t, owner, `SELECT count(*) FROM identity_observation_peer_contexts WHERE tenant_id=$1 AND materialized_at IS NOT NULL`, tenant); n != 1 {
		t.Fatalf("context not acknowledged exactly once: %d", n)
	}
	var factTime, assetSeen time.Time
	var class, site string
	if err := owner.QueryRow(`SELECT observed_at FROM asset_facts WHERE tenant_id=$1 AND asset_id=$2 AND key='hw.model'`, tenant, target).Scan(&factTime); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRow(`SELECT last_seen_at,class_key,site FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, target).Scan(&assetSeen, &class, &site); err != nil {
		t.Fatal(err)
	}
	if !factTime.Equal(seen) || !assetSeen.Equal(oldSeen) || class != "unknown_host" || site != "Operator site" {
		t.Fatalf("replay changed clocks/safeguards: %v %v %s %s", factTime, assetSeen, class, site)
	}
	if n := countRows(t, owner, `SELECT count(*) FROM asset_relationships WHERE tenant_id=$1 AND from_asset_id=$2 AND to_asset_id=$3`, tenant, survivor, target); n != 1 {
		t.Fatalf("retained relationship did not follow controller redirect: %d", n)
	}
	if n := countRows(t, owner, `SELECT count(*) FROM asset_identifiers WHERE tenant_id=$1 AND asset_id=$2 AND value='mystery.local'`, tenant, target); n != 0 {
		t.Fatal("operator linkage promoted weak alias")
	}
}

func TestIntegration_ObservationSink_UsesControllerProofWithoutTrustingAdvertisements(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenant := testdb.NewTenant(t, owner)
	if _, err := owner.Exec(`INSERT INTO network_segments(tenant_id,name,segment_type,value,network_type,environment,is_active,metadata) VALUES($1,'DHCP LAN','cidr','192.0.2.0/24','private','production',true,'{"dynamic":true}')`, tenant); err != nil {
		t.Fatal(err)
	}
	sink := NewObservationSink(testdb.ConnectAsAppRole(t, owner))
	source := peerSource("interrogation:controller-proof")
	for _, tc := range []struct {
		name string
		peer di.PeerRef
		want bool
	}{
		{"active interface", di.PeerRef{IdentityEvidence: di.PeerIdentityEvidence{ConnectedInterface: true}, Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierMACAddress, Value: "00:1a:2b:3c:4d:5e"}, {Kind: di.IdentifierIPAddress, Value: "192.0.2.20"}}}, true},
		{"dynamic address only", di.PeerRef{IdentityEvidence: di.PeerIdentityEvidence{ConnectedInterface: true}, Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierIPAddress, Value: "192.0.2.20"}}}, false},
		{"advertised interface", di.PeerRef{Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierMACAddress, Value: "00:1a:2b:3c:4d:5e"}, {Kind: di.IdentifierIPAddress, Value: "192.0.2.20"}}}, false},
		{"offline inventory serial", di.PeerRef{IdentityEvidence: di.PeerIdentityEvidence{ControllerInventory: true}, Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierSerialNumber, Value: "DEVICE-SERIAL"}}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs, _, err := sink.peerObservation(context.Background(), tenant, tc.peer, source, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if got := identity.AssessAdmission(obs); got.Established != tc.want {
				t.Fatalf("admission=%+v want established=%t", got, tc.want)
			}
		})
	}
}

func TestIntegration_ObservationSink_SegmentPreparationFailureStopsPeers(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenant := testdb.NewTenant(t, owner)
	self := subjectAsset(t, owner, tenant, "controller")
	name := "reject_test_segment_" + strings.ReplaceAll(tenant.String(), "-", "")
	if _, err := owner.Exec(`CREATE FUNCTION ` + name + `() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id='` + tenant.String() + `'::uuid THEN RAISE EXCEPTION 'test segment preparation failure'; END IF; RETURN NEW; END $$`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = owner.Exec(`DROP FUNCTION IF EXISTS ` + name + `() CASCADE`) })
	if _, err := owner.Exec(`CREATE TRIGGER ` + name + ` BEFORE INSERT ON network_segments FOR EACH ROW EXECUTE FUNCTION ` + name + `() `); err != nil {
		t.Fatal(err)
	}
	peer := di.PeerRef{Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierMACAddress, Value: "00:1a:2b:3c:4d:5e"}, {Kind: di.IdentifierIPAddress, Value: "192.0.2.20"}}}
	sink := NewObservationSink(testdb.ConnectAsAppRole(t, owner))
	err := sink.Persist(context.Background(), tenant, self, peerSource("interrogation:preparation-failure"), InterrogationObservations{Facts: []di.FactObservation{
		{Key: "net.vlans", Value: []map[string]interface{}{{"subnet": "192.0.2.0/24", "dhcp_enabled": true}}},
		{Subject: peer, Key: "hw.vendor", Value: "Example", Confidence: 1},
	}})
	if err == nil || !strings.Contains(err.Error(), "vlan segments") {
		t.Fatalf("preparation failure not reported: %v", err)
	}
	if n := countRows(t, owner, `SELECT count(*) FROM assets WHERE tenant_id=$1`, tenant); n != 1 {
		t.Fatalf("peer resolved after segment failure: %d", n)
	}
}
