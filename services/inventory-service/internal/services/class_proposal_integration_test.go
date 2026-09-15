package services

// Rule-derived classes reaching assets, end to end, against a real Postgres
// (asset-inventory workstream 2.10b, ADR-0004 D6 + ADR-0008 D3).
//
// These are the assertions the unit tests next door cannot make. The engine's
// tests prove the RULES decide correctly; these prove the decision lands — that
// a new asset carries `class_source_kind = 'rule'` and the rule's id, that an
// existing asset gets a PROPOSAL rather than a rewrite, that a declared class is
// never touched, and that a rejection is remembered.
//
// Three of them exist because the failure they guard is invisible. A class that
// silently overwrote a declared one, or a proposal re-raised on every coalescing
// window, or a rejection that did not stick — none of those produce an error
// anywhere. They produce a queue nobody can clear and an inventory nobody
// trusts.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db). RFC 5737 documentation addresses throughout — the export
// leak gate rejects real lab ranges.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// --- the class on a NEW asset ------------------------------------------------

// A passively observed printer is classed BY THE RULES and still waits in
// Approvals.
//
// Both halves matter and they are easy to get half-right. Setting the class and
// auto-approving would be the auto-decide ADR-0002 D5 forbids; leaving the class
// as `unknown_host` is where row 7 of the 2.5 note was stuck for a release.
func TestIntegration_ClassProposal_NewAssetCarriesTheRuleClassAndStaysPending(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)

	f := observationFinding(t, &hostobs.HostObservation{
		Source:     hostobs.SourceMDNS,
		MAC:        "28:cf:da:aa:bb:01",
		Addresses:  addrsFor(t, "192.0.2.61"),
		Hostnames:  []string{"floor2-printer"},
		Services:   []string{"_ipp._tcp"},
		ObservedAt: time.Now().UTC(),
	})
	if _, err := svc.IngestFindings(tenant, []IngestFinding{f}); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}

	var classKey, sourceKind, sourceRef, status string
	readAsset(t, db, tenant, "floor2-printer", &classKey, &sourceKind, &sourceRef, &status)

	if classKey != "printer" {
		t.Errorf("class_key = %q, want printer — the `_ipp._tcp` mdns_service rule should have decided it", classKey)
	}
	if sourceKind != string(identity.ClassSourceRule) {
		t.Errorf("class_source_kind = %q, want rule. `measured` would claim we measured the service-to-class mapping; "+
			"`inferred` would call a deterministic rule a model. Both are false provenance on the field a reviewer audits.", sourceKind)
	}
	if !strings.HasPrefix(sourceRef, "rule:") {
		t.Errorf("class_source_ref = %q, want a rule:<id> reference — a proposal that cannot name its rule is not reviewable", sourceRef)
	}
	if status != identity.StatusPendingApproval {
		t.Errorf("asset_status = %q, want pending_approval — classifying an asset is not approving it", status)
	}

	// And NO proposal was raised: the asset itself is the question, and asking
	// twice would let a reviewer answer it two ways.
	if n := countClassProposals(t, db, tenant); n != 0 {
		t.Errorf("%d class proposals were raised for a newly created asset, want 0 — approving the asset approves its class", n)
	}
}

// The rules deciding NOTHING leaves the asset coarse and true, with no proposal.
func TestIntegration_ClassProposal_UnknownStaysUnknown(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)

	// A MAC from a prefix no rule covers, no services, no capabilities.
	f := observationFinding(t, &hostobs.HostObservation{
		Source:     hostobs.SourceARP,
		MAC:        "98:3b:7c:00:11:22",
		Addresses:  addrsFor(t, "192.0.2.62"),
		Hostnames:  []string{"mystery-box"},
		ObservedAt: time.Now().UTC(),
	})
	if _, err := svc.IngestFindings(tenant, []IngestFinding{f}); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}

	var classKey, sourceKind, sourceRef, status string
	readAsset(t, db, tenant, "mystery-box", &classKey, &sourceKind, &sourceRef, &status)
	if classKey != "unknown_host" {
		t.Errorf("class_key = %q, want unknown_host", classKey)
	}
	if sourceKind == string(identity.ClassSourceRule) {
		t.Error("the fallback class was stamped `rule`; no rule argued for not knowing")
	}
	if n := countClassProposals(t, db, tenant); n != 0 {
		t.Errorf("%d class proposals for an asset nothing classified, want 0", n)
	}
}

// --- the PROPOSAL on an existing asset ---------------------------------------

// An asset that already exists gets a proposal, not a rewrite.
func TestIntegration_ClassProposal_ExistingAssetIsProposedAgainstNotOverwritten(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)

	// First sighting: nothing classifies it.
	mac := "98:3b:7c:33:44:55"
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceARP, MAC: mac, Addresses: addrsFor(t, "192.0.2.63"),
		Hostnames: []string{"later-a-printer"}, ObservedAt: time.Now().UTC(),
	})}); err != nil {
		t.Fatalf("first ingest: %v", err)
	}

	// Second sighting of the SAME MAC, now advertising IPP.
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceMDNS, MAC: mac, Addresses: addrsFor(t, "192.0.2.63"),
		Hostnames: []string{"later-a-printer"}, Services: []string{"_ipp._tcp"},
		ObservedAt: time.Now().UTC(),
	})}); err != nil {
		t.Fatalf("second ingest: %v", err)
	}

	var classKey, sourceKind, sourceRef, status string
	readAsset(t, db, tenant, "later-a-printer", &classKey, &sourceKind, &sourceRef, &status)
	if classKey != "unknown_host" {
		t.Errorf("class_key = %q; an existing asset's class must not be rewritten by a rule", classKey)
	}

	proposals := listClassProposals(t, db, tenant)
	if len(proposals) != 1 {
		t.Fatalf("%d class proposals, want 1", len(proposals))
	}
	if proposals[0].ProposedClassKey != "printer" {
		t.Errorf("proposed class = %q, want printer", proposals[0].ProposedClassKey)
	}
	if proposals[0].CurrentClassKey != "unknown_host" {
		t.Errorf("current class on the proposal = %q, want unknown_host — a proposal is a comparison", proposals[0].CurrentClassKey)
	}
	if len(proposals[0].MatchedRules) == 0 {
		t.Error("the proposal carries no matched rules; a proposal a reviewer cannot audit is one they can only rubber-stamp")
	}
}

// The same evidence seen again does not refill the queue.
//
// A printer advertises `_ipp._tcp` on every coalescing window. Without the
// partial unique index this is a hundred identical rows a day that nobody can
// clear by deciding one of them — which is exactly what the merge queue did
// before its index was added.
func TestIntegration_ClassProposal_OnePendingProposalPerAssetAndClass(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)

	mac := "98:3b:7c:66:77:88"
	seed := func(services ...string) IngestFinding {
		return observationFinding(t, &hostobs.HostObservation{
			Source: hostobs.SourceMDNS, MAC: mac, Addresses: addrsFor(t, "192.0.2.64"),
			Hostnames: []string{"chatty-printer"}, Services: services, ObservedAt: time.Now().UTC(),
		})
	}
	if _, err := svc.IngestFindings(tenant, []IngestFinding{seed()}); err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	for i := 0; i < 4; i++ {
		if _, err := svc.IngestFindings(tenant, []IngestFinding{seed("_ipp._tcp")}); err != nil {
			t.Fatalf("ingest %d: %v", i, err)
		}
	}
	if n := countClassProposals(t, db, tenant); n != 1 {
		t.Errorf("%d pending class proposals after four identical observations, want 1", n)
	}
}

// A DECLARED class is never proposed against.
//
// A person said what this is. ADR-0008 D4.2's rule — an inference never
// overwrites a declared value at any confidence — applied to the class column,
// and the reason it is a test rather than a comment is that the failure is
// silent: the reviewer just finds the machine arguing with them.
//
// MUTATION: delete the `sourceKind == declared` guard in recordClassOutcome and
// this test fails; nothing else does.
func TestIntegration_ClassProposal_ADeclaredClassIsNeverProposedAgainst(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)

	mac := "98:3b:7c:99:aa:bb"
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceARP, MAC: mac, Addresses: addrsFor(t, "192.0.2.65"),
		Hostnames: []string{"the-users-call"}, ObservedAt: time.Now().UTC(),
	})}); err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	// A person classifies it.
	execTenant(t, db, tenant, `UPDATE assets SET class_key = 'server', class_path = 'hardware.computer.server',
		class_source_kind = 'declared', class_source_ref = 'user:someone' WHERE tenant_id = $1`)

	// The rules now argue printer.
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceMDNS, MAC: mac, Addresses: addrsFor(t, "192.0.2.65"),
		Hostnames: []string{"the-users-call"}, Services: []string{"_ipp._tcp"},
		ObservedAt: time.Now().UTC(),
	})}); err != nil {
		t.Fatalf("second ingest: %v", err)
	}

	if n := countClassProposals(t, db, tenant); n != 0 {
		t.Errorf("%d class proposals against a DECLARED class, want 0", n)
	}
	var classKey, sourceKind, sourceRef, status string
	readAsset(t, db, tenant, "the-users-call", &classKey, &sourceKind, &sourceRef, &status)
	if classKey != "server" || sourceKind != "declared" {
		t.Errorf("the declared class moved to %q/%q", classKey, sourceKind)
	}
}

// --- accepting and rejecting -------------------------------------------------

func TestIntegration_ClassProposal_AcceptAppliesTheClassAndWritesHistory(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	proposals := seedOneClassProposal(t, svc, db, tenant, "accept-me")
	actor := seedClassReviewer(t, db, tenant)

	decided, err := NewClassProposalService(db).Decide(context.Background(), tenant, proposals[0].ID, actor, true, "")
	if err != nil {
		t.Fatalf("Decide(accept): %v", err)
	}
	if decided.Status != "accepted" || decided.AcceptedClassKey != "printer" {
		t.Errorf("decided = %+v, want accepted/printer", decided)
	}

	var classKey, sourceKind, sourceRef, status string
	readAsset(t, db, tenant, "accept-me", &classKey, &sourceKind, &sourceRef, &status)
	if classKey != "printer" {
		t.Errorf("class_key = %q after accepting, want printer", classKey)
	}
	if sourceKind != string(identity.ClassSourceRule) {
		t.Errorf("class_source_kind = %q, want rule — the RULE decided the class, the person decided to take it", sourceKind)
	}
	if !strings.HasPrefix(sourceRef, "rule:") {
		t.Errorf("class_source_ref = %q, want rule:<id>", sourceRef)
	}
	// class_path moves with class_key, or every prefix facet keeps the asset
	// under its old branch while its badge says otherwise.
	var path string
	queryTenant(t, db, tenant, `SELECT class_path FROM assets WHERE tenant_id = $1`, &path)
	if path != "hardware.printer" {
		t.Errorf("class_path = %q, want hardware.printer", path)
	}

	var n int
	queryTenant(t, db, tenant,
		`SELECT count(*) FROM asset_history WHERE tenant_id = $1 AND action = 'class_accepted' AND actor_user_id = '`+actor.String()+`'`, &n)
	if n != 1 {
		t.Errorf("class_accepted history rows = %d, want 1", n)
	}
	// And the proposal is out of the queue.
	if got := countClassProposals(t, db, tenant); got != 0 {
		t.Errorf("%d pending proposals after accepting, want 0", got)
	}
}

// A rejection sticks, and the same class is not proposed again on the next
// observation of unchanged evidence.
//
// This is the one that makes the queue usable. Without the `class_rejected` row
// being CONSULTED, a reviewer who says "no, that is not a printer" is asked
// again within the hour, for ever.
func TestIntegration_ClassProposal_ARejectedClassIsNotProposedAgain(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	proposals := seedOneClassProposal(t, svc, db, tenant, "not-a-printer")

	if _, err := NewClassProposalService(db).Decide(context.Background(), tenant, proposals[0].ID, seedClassReviewer(t, db, tenant), false, ""); err != nil {
		t.Fatalf("Decide(reject): %v", err)
	}
	var classKey, sourceKind, sourceRef, status string
	readAsset(t, db, tenant, "not-a-printer", &classKey, &sourceKind, &sourceRef, &status)
	if classKey != "unknown_host" {
		t.Errorf("rejecting changed the class to %q; it must leave the asset exactly as it was", classKey)
	}

	// Same evidence again.
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceMDNS, MAC: "98:3b:7c:cc:dd:ee", Addresses: addrsFor(t, "192.0.2.66"),
		Hostnames: []string{"not-a-printer"}, Services: []string{"_ipp._tcp"},
		ObservedAt: time.Now().UTC(),
	})}); err != nil {
		t.Fatalf("re-ingest: %v", err)
	}
	if n := countClassProposals(t, db, tenant); n != 0 {
		t.Errorf("%d pending class proposals after a rejection, want 0 — the rejection must be consulted, not just recorded", n)
	}
}

// Deciding twice is a 409, not a second write.
func TestIntegration_ClassProposal_ASecondDecisionIsRefused(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	proposals := seedOneClassProposal(t, svc, db, tenant, "decided-once")
	s := NewClassProposalService(db)
	if _, err := s.Decide(context.Background(), tenant, proposals[0].ID, seedClassReviewer(t, db, tenant), true, ""); err != nil {
		t.Fatalf("first decision: %v", err)
	}
	_, err := s.Decide(context.Background(), tenant, proposals[0].ID, seedClassReviewer(t, db, tenant), false, "")
	if err == nil || !strings.Contains(err.Error(), "already been decided") {
		t.Fatalf("second decision returned %v, want the already-decided error", err)
	}
}

// RLS: one tenant cannot see or decide another's proposals.
func TestIntegration_ClassProposal_IsTenantIsolated(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	proposals := seedOneClassProposal(t, svc, db, tenant, "mine-only")

	raw := testdb.Connect(t)
	other := testdb.NewTenant(t, raw)
	s := NewClassProposalService(db)

	got, total, err := s.ListPending(context.Background(), other, 0, 0)
	if err != nil {
		t.Fatalf("ListPending for the other tenant: %v", err)
	}
	if len(got) != 0 || total != 0 {
		t.Errorf("the other tenant saw %d proposals (total %d); RLS must scope the queue", len(got), total)
	}
	if _, err := s.Decide(context.Background(), other, proposals[0].ID, seedClassReviewer(t, db, tenant), true, ""); err == nil {
		t.Error("the other tenant decided a proposal it cannot see")
	}
}

// --- helpers -----------------------------------------------------------------

// seedOneClassProposal drives the real ingest twice — once with no classifying
// evidence, once with it — so the proposal under test is the one production
// writes rather than a hand-built row.
func seedOneClassProposal(t *testing.T, svc *AssetService, db *database.DB, tenant uuid.UUID, hostname string) []ClassProposalView {
	t.Helper()
	mac := "98:3b:7c:cc:dd:ee"
	addr := "192.0.2.66"
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceARP, MAC: mac, Addresses: addrsFor(t, addr),
		Hostnames: []string{hostname}, ObservedAt: time.Now().UTC(),
	})}); err != nil {
		t.Fatalf("seed ingest 1: %v", err)
	}
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceMDNS, MAC: mac, Addresses: addrsFor(t, addr),
		Hostnames: []string{hostname}, Services: []string{"_ipp._tcp"}, ObservedAt: time.Now().UTC(),
	})}); err != nil {
		t.Fatalf("seed ingest 2: %v", err)
	}
	out := listClassProposals(t, db, tenant)
	if len(out) != 1 {
		t.Fatalf("seeded %d proposals, want 1", len(out))
	}
	return out
}

// seedClassReviewer creates the person whose decision the history records.
// asset_history.actor_user_id is an FK to users, so a bare uuid.New() is a
// constraint violation rather than an anonymous actor.
func seedClassReviewer(t *testing.T, db *database.DB, tenant uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO users (id, tenant_id, email, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, true, NOW(), NOW())`,
		id, tenant, "class-reviewer-"+id.String()[:8]+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

func listClassProposals(t *testing.T, db *database.DB, tenant uuid.UUID) []ClassProposalView {
	t.Helper()
	out, _, err := NewClassProposalService(db).ListPending(context.Background(), tenant, 0, 0)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	return out
}

func countClassProposals(t *testing.T, db *database.DB, tenant uuid.UUID) int {
	t.Helper()
	var n int
	queryTenant(t, db, tenant, `SELECT count(*) FROM asset_history
		WHERE tenant_id = $1 AND action = 'class_proposed'
		  AND COALESCE(changes_json->>'status', 'pending') = 'pending'`, &n)
	return n
}

func readAsset(t *testing.T, db *database.DB, tenant uuid.UUID, hostname string, classKey, sourceKind, sourceRef, status *string) {
	t.Helper()
	err := database.WithTenantTx(context.Background(), db, tenant, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`SELECT class_key, class_source_kind, COALESCE(class_source_ref, ''), asset_status
			FROM assets WHERE tenant_id = $1 AND hostname = $2`, tenant, hostname).
			Scan(classKey, sourceKind, sourceRef, status)
	})
	if err != nil {
		t.Fatalf("read asset %q: %v", hostname, err)
	}
}

func queryTenant(t *testing.T, db *database.DB, tenant uuid.UUID, query string, dest any) {
	t.Helper()
	if err := database.WithTenantTx(context.Background(), db, tenant, func(tx *sqlx.Tx) error {
		return tx.QueryRow(query, tenant).Scan(dest)
	}); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
}

func execTenant(t *testing.T, db *database.DB, tenant uuid.UUID, query string) {
	t.Helper()
	if err := database.WithTenantTx(context.Background(), db, tenant, func(tx *sqlx.Tx) error {
		_, err := tx.Exec(query, tenant)
		return err
	}); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

// Two rules disagreeing leaves the asset unclassified AND raises a proposal
// that names both.
//
// This is the one outcome that is easy to implement as a silent nothing. The
// engine already refuses to choose (that is its own test); what this pins is the
// half intake owns — that the refusal REACHES somebody. A conflict is a curation
// bug, and a curation bug nobody is shown is a rule that stays wrong.
//
// The fixture is a real conflict from the shipped table: a Cisco OUI proposes
// `network_device` at 0.70 and an advertised `_ipp._tcp` proposes `printer` at
// 0.75. They are unrelated classes 0.05 apart, which is inside ConflictEpsilon.
func TestIntegration_ClassProposal_AConflictProposesNothingAndNamesBoth(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)

	f := observationFinding(t, &hostobs.HostObservation{
		Source:     hostobs.SourceMDNS,
		MAC:        "00:00:0c:12:34:56", // Cisco Systems
		Addresses:  addrsFor(t, "192.0.2.67"),
		Hostnames:  []string{"argued-over"},
		Services:   []string{"_ipp._tcp"},
		ObservedAt: time.Now().UTC(),
	})
	if _, err := svc.IngestFindings(tenant, []IngestFinding{f}); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}

	var classKey, sourceKind, sourceRef, status string
	readAsset(t, db, tenant, "argued-over", &classKey, &sourceKind, &sourceRef, &status)
	if classKey != "unknown_host" {
		t.Errorf("class_key = %q; two rules disagreeing must leave the asset unclassified, not pick one", classKey)
	}

	proposals := listClassProposals(t, db, tenant)
	if len(proposals) != 1 {
		t.Fatalf("%d class proposals for a conflict, want 1 — a conflict nobody is shown is a rule that stays wrong", len(proposals))
	}
	p := proposals[0]
	if p.ProposedClassKey != "" {
		t.Errorf("proposed class = %q; a conflict proposes NO class and offers a choice", p.ProposedClassKey)
	}
	keys := map[string]bool{}
	for _, c := range p.ConflictingClasses {
		keys[c.Key] = true
	}
	if !keys["printer"] || !keys["network_device"] {
		t.Errorf("conflicting_classes = %+v, want both printer and network_device", p.ConflictingClasses)
	}

	// A reviewer settles it by picking one — and only one the proposal offered.
	s := NewClassProposalService(db)
	if _, err := s.Decide(context.Background(), tenant, p.ID, seedClassReviewer(t, db, tenant), true, "plc"); err == nil {
		t.Error("accepting a class the proposal never offered succeeded; that would reclassify an asset as something no rule argued for")
	}
	if _, err := s.Decide(context.Background(), tenant, p.ID, seedClassReviewer(t, db, tenant), true, "printer"); err != nil {
		t.Fatalf("accepting one of the conflicting classes: %v", err)
	}
	readAsset(t, db, tenant, "argued-over", &classKey, &sourceKind, &sourceRef, &status)
	if classKey != "printer" {
		t.Errorf("class_key = %q after the reviewer chose printer", classKey)
	}
}

// Settling a conflict by CHOOSING one of its classes is remembered, and the
// same argument is not put back in the queue on the next observation.
//
// The rejection path had this guard from the start and the acceptance path did
// not, because the two suppressions work differently and only one of them is
// visible. An ordinary proposal that is accepted goes quiet by itself: the
// asset's class becomes the proposed class, and `prop.Class == current` says
// nothing to propose. A CONFLICT proposes no class at all, so that comparison
// can never fire — the accepted row drops out of the partial unique index, no
// `class_rejected` row was written because nobody rejected anything, and the
// same unchanged evidence raises a fresh conflict every coalescing window.
//
// Which is the exact complaint the `class_rejected` read exists to answer,
// arriving through the door nobody had checked. A reviewer who settles "printer
// or network device?" would be asked again within the hour, for ever, having
// answered it.
func TestIntegration_ClassProposal_ASettledConflictIsNotArguedAgain(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)

	// Cisco OUI (network_device, 0.70) against an advertised _ipp._tcp
	// (printer, 0.75): unrelated classes 0.05 apart, inside ConflictEpsilon.
	obs := func() IngestFinding {
		return observationFinding(t, &hostobs.HostObservation{
			Source: hostobs.SourceMDNS, MAC: "00:00:0c:ab:cd:ef",
			Addresses: addrsFor(t, "192.0.2.69"), Hostnames: []string{"settled-argument"},
			Services: []string{"_ipp._tcp"}, ObservedAt: time.Now().UTC(),
		})
	}
	if _, err := svc.IngestFindings(tenant, []IngestFinding{obs()}); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}
	proposals := listClassProposals(t, db, tenant)
	if len(proposals) != 1 {
		t.Fatalf("%d class proposals, want 1", len(proposals))
	}
	if _, err := NewClassProposalService(db).Decide(context.Background(), tenant,
		proposals[0].ID, seedClassReviewer(t, db, tenant), true, "printer"); err != nil {
		t.Fatalf("settling the conflict: %v", err)
	}

	// The same evidence, and the same disagreement in the catalogue.
	if _, err := svc.IngestFindings(tenant, []IngestFinding{obs()}); err != nil {
		t.Fatalf("re-ingest: %v", err)
	}
	if n := countClassProposals(t, db, tenant); n != 0 {
		t.Errorf("%d pending class proposals after the reviewer settled the conflict, want 0 — "+
			"the asset already holds one of the classes being argued over", n)
	}
	var classKey, sourceKind, sourceRef, status string
	readAsset(t, db, tenant, "settled-argument", &classKey, &sourceKind, &sourceRef, &status)
	if classKey != "printer" {
		t.Errorf("class_key = %q, want the class the reviewer chose", classKey)
	}
}

// A conflict accepted with NO class named is refused rather than guessed at.
func TestIntegration_ClassProposal_AConflictCannotBeAcceptedWithoutAChoice(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)

	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, &hostobs.HostObservation{
		Source: hostobs.SourceMDNS, MAC: "00:00:0c:65:43:21", Addresses: addrsFor(t, "192.0.2.68"),
		Hostnames: []string{"still-argued-over"}, Services: []string{"_ipp._tcp"},
		ObservedAt: time.Now().UTC(),
	})}); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}
	proposals := listClassProposals(t, db, tenant)
	if len(proposals) != 1 {
		t.Fatalf("%d proposals, want 1", len(proposals))
	}
	_, err := NewClassProposalService(db).Decide(context.Background(), tenant,
		proposals[0].ID, seedClassReviewer(t, db, tenant), true, "")
	if err == nil || !strings.Contains(err.Error(), "no single class") {
		t.Fatalf("accepting a conflict with no class returned %v, want a refusal naming the choices", err)
	}
}
