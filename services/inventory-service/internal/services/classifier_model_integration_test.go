package services

// The learned classifier reaching an asset — and the four ways it must not
// (asset-inventory workstream 4.2, ADR-0008 D1/D3/D4).
//
// The unit tests next door prove the CHAIN decides correctly. These prove what
// lands: that a model's answer becomes a row in Approvals and never a class on
// an asset, that accepting one stamps `inferred` rather than `rule`, that a
// rejection sticks, and that the rules still win where they have an answer.
//
// Every one of these guards a failure that produces no error anywhere. A model
// class written straight onto a new asset looks exactly like a rule class; a
// model proposal stamped `rule` passes every database constraint; a re-proposed
// rejection just makes the queue longer. None of them would be noticed except
// by somebody auditing provenance six months later, which is the point at which
// it is too late.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).
//
// RFC 1918 addresses in 10.77/16, not the RFC 5737 documentation range the
// host-observation tests use. The difference is load-bearing here: these go in
// as ordinary discovery findings, and ClassifyAsset routes a PUBLIC address to
// external_connections rather than creating a managed asset — so a 192.0.2.x
// fixture never reaches the classifier at all. 10.77/16 is neither lab subnet,
// which is what the export's lab-identity gate rejects.

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/classify"
	classmodel "github.com/vistasecurity/vistaplatform/shared/classify/model"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// modelPrinterFinding is evidence the RULES cannot decide and the MODEL can: an
// HP OUI (a vendor-only rule — HP sells printers, servers and switches, so it
// names no class), a print port, and an embedded web server whose banner
// matches none of the eight shipped banner rules.
//
// Every part of that is load-bearing, so the helper asserts it rather than
// assuming it: a catalogue change that gave one of these a class would turn
// every test in this file into a test of the RULES, silently and while still
// passing.
func modelPrinterFinding(t *testing.T, hostname, address, mac string) IngestFinding {
	t.Helper()
	port := 9100
	f := IngestFinding{
		Hostname:  &hostname,
		IPAddress: &address,
		Port:      &port,
		RawData: map[string]interface{}{
			"mac_address":   mac,
			"open_ports":    []any{float64(80), float64(9100)},
			"server_header": "HP HTTP Server",
		},
	}
	rules := classify.Default().Classify(context.Background(), findingClassEvidence(f))
	if rules.Class != "" || rules.Conflict {
		t.Fatalf("the shipped rules now decide this fixture (%+v); it no longer exercises the model "+
			"and these tests would silently become tests of the rule engine", rules)
	}
	return f
}

// embeddedClassifierModel is the shipped model, or a skip.
func embeddedClassifierModel(t *testing.T) *classmodel.Model {
	t.Helper()
	m, err := classmodel.Default()
	if err != nil {
		t.Skipf("the embedded classifier weights did not load: %v", err)
	}
	return m
}

// classProposalRow reads the one pending proposal, with the columns the view
// does not carry.
func classProposalRow(t *testing.T, db *database.DB, tenant uuid.UUID) (view ClassProposalView, source, payload string) {
	t.Helper()
	views := listClassProposals(t, db, tenant)
	if len(views) != 1 {
		t.Fatalf("%d pending class proposals, want exactly 1", len(views))
	}
	err := database.WithTenantTx(context.Background(), db, tenant, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`SELECT source, changes_json::text FROM asset_history
			WHERE tenant_id = $1 AND id = $2`, tenant, views[0].ID).Scan(&source, &payload)
	})
	if err != nil {
		t.Fatalf("read the proposal row: %v", err)
	}
	return views[0], source, payload
}

// --- the model never SETS a class --------------------------------------------

// A NEW asset the model can classify is created UNCLASSIFIED, with a proposal
// beside it.
//
// This is the pair of behaviours that has to move together, and either half
// alone is a bug that looks like a feature. A rule-derived class IS set at
// creation — the asset lands in `pending_approval` and approving it approves
// the class, which is honest because a rule is deterministic and cites a
// source. A model's answer is neither, so it gets the queue instead: a machine
// guess entering the inventory with nobody having read it is exactly what
// ADR-0008 D3 forbids.
//
// Delete either the `prop.ModelID != ""` guard in applyClassProposal or the one
// in recordClassOutcome and this fails: the first lets the class onto the
// asset, the second drops the proposal on the floor.
func TestIntegration_ClassifierModel_NeverSetsAClassOnANewAsset(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	model := embeddedClassifierModel(t)

	f := modelPrinterFinding(t, "model-proposed-printer", "10.77.0.90", "00:01:e6:aa:bb:01")
	if _, err := svc.IngestFindings(tenant, []IngestFinding{f}); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}

	var classKey, sourceKind, sourceRef, status string
	readAsset(t, db, tenant, "model-proposed-printer", &classKey, &sourceKind, &sourceRef, &status)

	if classKey != string(assetclass.KeyUnknownHost) {
		t.Errorf("class_key = %q on a newly created asset; a MODEL proposed that class and a model "+
			"never sets one — it proposes, and a person accepts", classKey)
	}
	if sourceKind == string(identity.ClassSourceInferred) || strings.HasPrefix(sourceRef, "model:") {
		t.Errorf("the asset carries model provenance (%q / %q) without anybody having accepted it", sourceKind, sourceRef)
	}

	// And the answer was not thrown away: it is in the queue, attributed.
	view, source, payload := classProposalRow(t, db, tenant)
	if view.ProposedClassKey != string(assetclass.KeyPrinter) {
		t.Errorf("proposed class = %q, want printer", view.ProposedClassKey)
	}
	if view.ModelID != model.ModelID {
		t.Errorf("model_id = %q, want %q — a proposal that cannot name the weights behind it "+
			"cannot be traced when it turns out wrong", view.ModelID, model.ModelID)
	}
	if view.ModelProbability < classmodel.ModelProposalFloor {
		t.Errorf("model_probability = %v, below the %.2f floor; nothing under it should have been proposed",
			view.ModelProbability, classmodel.ModelProposalFloor)
	}
	if view.ProposedClassSourceKind != string(identity.ClassSourceInferred) {
		t.Errorf("proposed_class_source_kind = %q, want inferred. `rule` would say a deterministic, "+
			"citable rule argued it — ADR-0008 D4.2 defines `inferred` as what a model proposed and "+
			"prices it accordingly, and both spellings satisfy every database constraint",
			view.ProposedClassSourceKind)
	}
	if want := "model:" + model.ModelID; view.ProposedClassSourceRef != want {
		t.Errorf("class_source_ref = %q, want %q", view.ProposedClassSourceRef, want)
	}
	if source != "classifier:model" {
		t.Errorf("asset_history.source = %q, want classifier:model — the Approvals facet reads it "+
			"to say who is asking, and `classifier:rules` would name the wrong producer", source)
	}
	if len(view.ModelReasons) == 0 {
		t.Fatalf("the proposal carries no reasons; a model cannot cite a source URL the way a rule "+
			"can, so the feature contributions are the whole of its argument. Payload: %s", payload)
	}
	for _, r := range view.ModelReasons {
		if strings.TrimSpace(r.Label) == "" {
			t.Errorf("reason %q has no readable phrase", r.Feature)
		}
	}
	// No identifier crossed into the stored argument. The payload is read back
	// by the API and rendered in a browser; a MAC in it is an identifier
	// leaving the tenant's own screen for no benefit.
	for _, needle := range []string{"00:01:e6:aa:bb:01", "0001e6aabb01", "aa:bb:01", "10.77.0.90"} {
		for _, r := range view.ModelReasons {
			if strings.Contains(strings.ToLower(r.Feature+r.Label), strings.ToLower(needle)) {
				t.Errorf("a stored reason contains %q: %+v", needle, r)
			}
		}
	}
}

// The same, on an asset that already exists: a class is never overwritten.
func TestIntegration_ClassifierModel_NeverSetsAClassOnAnExistingAsset(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	embeddedClassifierModel(t)

	// First sighting: nothing classifies it, and the asset is created.
	mac := "00:01:e6:aa:bb:02"
	bare := IngestFinding{
		Hostname:  ptr("model-existing-printer"),
		IPAddress: ptr("10.77.0.91"),
		RawData:   map[string]interface{}{"mac_address": mac},
	}
	if _, err := svc.IngestFindings(tenant, []IngestFinding{bare}); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}
	var classKey, sourceKind, sourceRef, status string
	readAsset(t, db, tenant, "model-existing-printer", &classKey, &sourceKind, &sourceRef, &status)
	if classKey != string(assetclass.KeyUnknownHost) {
		t.Fatalf("the first sighting classed it %q; the fixture no longer starts unclassified", classKey)
	}
	if n := countClassProposals(t, db, tenant); n != 0 {
		t.Fatalf("%d proposals from evidence nothing can classify, want 0", n)
	}

	// Second sighting, with the evidence the model can read.
	if _, err := svc.IngestFindings(tenant, []IngestFinding{
		modelPrinterFinding(t, "model-existing-printer", "10.77.0.91", mac),
	}); err != nil {
		t.Fatalf("re-ingest: %v", err)
	}

	readAsset(t, db, tenant, "model-existing-printer", &classKey, &sourceKind, &sourceRef, &status)
	if classKey != string(assetclass.KeyUnknownHost) {
		t.Errorf("class_key = %q; an existing asset's class was REWRITTEN by a model", classKey)
	}
	view, _, _ := classProposalRow(t, db, tenant)
	if view.ProposedClassKey != string(assetclass.KeyPrinter) || view.ModelID == "" {
		t.Errorf("got %+v, want a printer proposal attributed to the model", view)
	}
	if view.CurrentClassKey != string(assetclass.KeyUnknownHost) {
		t.Errorf("current_class_key = %q; a proposal is a COMPARISON and one half of it is missing",
			view.CurrentClassKey)
	}
}

// The other polarity: where the RULES decide, nothing changes. The class is on
// the asset at creation with `rule` provenance and no proposal is raised.
//
// Without this, every assertion above would pass just as well against a build
// whose classifier had stopped working entirely.
func TestIntegration_ClassifierModel_TheRulesStillDecideAndStillSetTheClass(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)

	// An advertised `_ipp._tcp`: a shipped mdns_service rule, printer at 0.75.
	f := IngestFinding{
		Hostname:  ptr("rule-classed-printer"),
		IPAddress: ptr("10.77.0.92"),
		RawData: map[string]interface{}{
			"mac_address":   "00:01:e6:aa:bb:03",
			"mdns_services": []any{"_ipp._tcp"},
		},
	}
	if _, err := svc.IngestFindings(tenant, []IngestFinding{f}); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}

	var classKey, sourceKind, sourceRef, status string
	readAsset(t, db, tenant, "rule-classed-printer", &classKey, &sourceKind, &sourceRef, &status)
	if classKey != string(assetclass.KeyPrinter) {
		t.Errorf("class_key = %q, want printer from the rule", classKey)
	}
	if sourceKind != string(identity.ClassSourceRule) {
		t.Errorf("class_source_kind = %q, want rule — the model must not relabel a rule's answer", sourceKind)
	}
	if !strings.HasPrefix(sourceRef, "rule:") {
		t.Errorf("class_source_ref = %q, want a rule reference", sourceRef)
	}
	if n := countClassProposals(t, db, tenant); n != 0 {
		t.Errorf("%d proposals for an asset the rules classified at creation, want 0 — approving "+
			"the asset approves its class, and asking twice lets a reviewer answer twice", n)
	}
}

// --- accepting and rejecting -------------------------------------------------

// ACCEPTING a model proposal stamps `inferred` and the model ref, not `rule`.
func TestIntegration_ClassifierModel_AcceptingStampsInferredProvenance(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	model := embeddedClassifierModel(t)

	if _, err := svc.IngestFindings(tenant, []IngestFinding{
		modelPrinterFinding(t, "accepted-model-printer", "10.77.0.93", "00:01:e6:aa:bb:04"),
	}); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}
	view, _, _ := classProposalRow(t, db, tenant)

	if _, err := NewClassProposalService(db).Decide(context.Background(), tenant, view.ID,
		seedClassReviewer(t, db, tenant), true, ""); err != nil {
		t.Fatalf("accept: %v", err)
	}

	var classKey, sourceKind, sourceRef, status string
	readAsset(t, db, tenant, "accepted-model-printer", &classKey, &sourceKind, &sourceRef, &status)
	if classKey != string(assetclass.KeyPrinter) {
		t.Errorf("class_key = %q after accepting, want printer", classKey)
	}
	if sourceKind != string(identity.ClassSourceInferred) {
		t.Errorf("class_source_kind = %q, want inferred. applyProposedClass used to write the "+
			"literal `rule` for every acceptance; against a model's answer that is false provenance "+
			"on the one column a reviewer audits, and the database would accept it silently", sourceKind)
	}
	if want := "model:" + model.ModelID; sourceRef != want {
		t.Errorf("class_source_ref = %q, want %q", sourceRef, want)
	}
	if n := countClassProposals(t, db, tenant); n != 0 {
		t.Errorf("%d proposals still pending after the accept", n)
	}
}

// REJECTING one is remembered, and the same class is not proposed again on the
// next sighting of the same unchanged evidence.
//
// The rejection guard is the same one the rules use — `class_rejected` read
// before proposing — and this is the assertion that it covers the model's
// proposals too. Without it a reviewer who says "no, that is not a printer" is
// asked again within the hour, for ever, by a producer that will never change
// its mind because the evidence does not change.
func TestIntegration_ClassifierModel_ARejectedClassIsNotProposedAgain(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	embeddedClassifierModel(t)

	sighting := func() IngestFinding {
		return modelPrinterFinding(t, "rejected-model-printer", "10.77.0.94", "00:01:e6:aa:bb:05")
	}
	if _, err := svc.IngestFindings(tenant, []IngestFinding{sighting()}); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}
	view, _, _ := classProposalRow(t, db, tenant)
	if _, err := NewClassProposalService(db).Decide(context.Background(), tenant, view.ID,
		seedClassReviewer(t, db, tenant), false, ""); err != nil {
		t.Fatalf("reject: %v", err)
	}

	// The same evidence again. The model has not changed its mind — it cannot.
	if _, err := svc.IngestFindings(tenant, []IngestFinding{sighting()}); err != nil {
		t.Fatalf("re-ingest: %v", err)
	}
	if n := countClassProposals(t, db, tenant); n != 0 {
		t.Errorf("%d pending class proposals after the reviewer rejected exactly this class, want 0", n)
	}

	var classKey, sourceKind, sourceRef, status string
	readAsset(t, db, tenant, "rejected-model-printer", &classKey, &sourceKind, &sourceRef, &status)
	if classKey != string(assetclass.KeyUnknownHost) {
		t.Errorf("class_key = %q; rejecting must leave the asset exactly as it was", classKey)
	}
}

// --- tenant isolation --------------------------------------------------------

// A model proposal is a tenant's own. RLS is what enforces it, and a proposal
// stored in `asset_history` inherits that — but "inherits" is an assumption
// until something reads it from the other side.
func TestIntegration_ClassifierModel_ProposalsAreTenantIsolated(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	embeddedClassifierModel(t)

	if _, err := svc.IngestFindings(tenant, []IngestFinding{
		modelPrinterFinding(t, "isolated-model-printer", "10.77.0.95", "00:01:e6:aa:bb:06"),
	}); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}
	mine, _, _ := classProposalRow(t, db, tenant)

	other := uuid.New()
	views, total, err := NewClassProposalService(db).ListPending(context.Background(), other, 0, 0)
	if err != nil {
		t.Fatalf("ListPending for another tenant: %v", err)
	}
	if len(views) != 0 || total != 0 {
		t.Errorf("another tenant sees %d of this tenant's class proposals (total %d)", len(views), total)
	}
	if _, err := NewClassProposalService(db).Decide(context.Background(), other, mine.ID,
		uuid.Nil, true, ""); err == nil {
		t.Error("another tenant decided this tenant's class proposal")
	}
}
