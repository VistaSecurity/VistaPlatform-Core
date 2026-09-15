package catalogs

// Real-Postgres assertions the stub store cannot make: that the ON CONFLICT
// targets match the tables' actual indexes (including the PARTIAL one, whose
// predicate has to be inferred exactly), that the CHECK constraints hold, that
// accept is genuinely atomic, and that a second accept loses.
//
// Skips unless TEST_DATABASE_URL is set — run `make test-integration-db`.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func integrationStore(t *testing.T) (*SQLStore, *sql.DB) {
	t.Helper()
	db := testdb.Connect(t)
	testdb.ApplySchema(t, db)
	return NewSQLStore(db), db
}

// uniqueProduct keeps parallel package binaries from colliding on the natural
// keys — these tables are platform-scoped, so there is no tenant to isolate by.
func uniqueProduct(t *testing.T, prefix string) string {
	t.Helper()
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func cleanupProduct(t *testing.T, db *sql.DB, product string) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.eol_catalogue_proposals WHERE subject_product = $1`, product)
		_, _ = db.Exec(`DELETE FROM public.catalog_lookup_misses WHERE product = $1`, product)
		_, _ = db.Exec(`DELETE FROM public.eol_catalogue WHERE product = $1`, product)
	})
}

func newProposal(product string) NewProposal {
	release := time.Date(2022, time.November, 14, 0, 0, 0, 0, time.UTC)
	eol := time.Date(2027, time.April, 30, 0, 0, 0, 0, time.UTC)
	return NewProposal{
		ProductKind: KindOS, Vendor: "Cisco", Product: product, Version: "17.9.4a",
		Cycle: "17.9", ReleaseDate: &release, EOLDate: &eol,
		SourceURL: "https://www.cisco.com/eol", ModelID: "test-model-1",
	}
}

func TestIntegration_RecordMiss_CountsRatherThanDuplicating(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	product := uniqueProduct(t, "it-miss")
	cleanupProduct(t, db, product)

	subject := MissSubject{Kind: KindOS, Vendor: "Cisco", Product: product, Version: "17.9.4a"}
	for i := 0; i < 3; i++ {
		if err := store.RecordMiss(ctx, subject); err != nil {
			t.Fatalf("RecordMiss %d: %v", i, err)
		}
	}
	// A differently-cased spelling of the same subject aggregates onto the same
	// row: the identity index folds case, which is the only way a count means
	// anything when the subject comes from whatever a device reported.
	if err := store.RecordMiss(ctx, MissSubject{
		Kind: KindOS, Vendor: "CISCO", Product: product, Version: "17.9.4a",
	}); err != nil {
		t.Fatalf("RecordMiss cased: %v", err)
	}

	var rows int
	var count int64
	var storedVendor string
	if err := db.QueryRow(`SELECT count(*), max(miss_count), max(vendor)
		FROM public.catalog_lookup_misses WHERE product = $1`, product).
		Scan(&rows, &count, &storedVendor); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 1 {
		t.Fatalf("rows = %d, want 1 — the identity index must fold case", rows)
	}
	if count != 4 {
		t.Fatalf("miss_count = %d, want 4", count)
	}
	// The first spelling is kept verbatim. A gap list that displayed its own
	// normalised form would hide a vendor-name mismatch, which is one of the
	// commonest causes of a miss.
	if storedVendor != "Cisco" {
		t.Errorf("vendor = %q, want the spelling first seen", storedVendor)
	}

	// The VERSION folds case too. It is a name here — whatever a device
	// reported — so "17.9.4A" is the same gap as "17.9.4a". Two rows would
	// split the count this list is ORDERED BY, sinking the product that costs
	// the most answers below one asked about half as often.
	if err := store.RecordMiss(ctx, MissSubject{
		Kind: KindOS, Vendor: "Cisco", Product: product, Version: "17.9.4A",
	}); err != nil {
		t.Fatalf("RecordMiss cased version: %v", err)
	}
	var storedVersion string
	if err := db.QueryRow(`SELECT count(*), max(miss_count), max(version)
		FROM public.catalog_lookup_misses WHERE product = $1`, product).
		Scan(&rows, &count, &storedVersion); err != nil {
		t.Fatalf("count after cased version: %v", err)
	}
	if rows != 1 {
		t.Fatalf("rows = %d, want 1 — the identity index must fold the version's case too", rows)
	}
	if count != 5 {
		t.Fatalf("miss_count = %d, want 5", count)
	}
	// Still verbatim: the identity folds, the display does not.
	if storedVersion != "17.9.4a" {
		t.Errorf("version = %q, want the spelling first seen", storedVersion)
	}

	// A version-less miss for the same product is a DIFFERENT gap: the index
	// coalesces version to '' rather than treating NULL as a wildcard.
	if err := store.RecordMiss(ctx, MissSubject{Kind: KindOS, Vendor: "Cisco", Product: product}); err != nil {
		t.Fatalf("RecordMiss no version: %v", err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM public.catalog_lookup_misses WHERE product = $1`, product).
		Scan(&rows); err != nil {
		t.Fatalf("recount: %v", err)
	}
	if rows != 2 {
		t.Fatalf("rows = %d, want 2", rows)
	}
}

// A subject nothing upstream vouched for cannot grow the gap list without
// bound. The row that lands is bounded and still readable.
func TestIntegration_RecordMiss_BoundsTheSubject(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	product := uniqueProduct(t, "it-long")
	cleanupProduct(t, db, product)

	padded := product + strings.Repeat("x", 5000)
	if err := store.RecordMiss(ctx, MissSubject{
		Kind: KindSoftware, Vendor: strings.Repeat("v", 5000), Product: padded, Version: strings.Repeat("9", 5000),
	}); err != nil {
		t.Fatalf("RecordMiss: %v", err)
	}

	var gotProduct, gotVendor, gotVersion string
	if err := db.QueryRow(`SELECT product, coalesce(vendor,''), coalesce(version,'')
		FROM public.catalog_lookup_misses WHERE product LIKE $1`, product+"%").
		Scan(&gotProduct, &gotVendor, &gotVersion); err != nil {
		t.Fatalf("select: %v", err)
	}
	for name, v := range map[string]string{"product": gotProduct, "vendor": gotVendor, "version": gotVersion} {
		if len(v) > MaxSubjectField {
			t.Errorf("%s stored %d bytes, past the %d-byte bound", name, len(v), MaxSubjectField)
		}
	}
	// Still the subject that was asked about, not a hash or an ellipsis: the
	// reviewer has to recognise it.
	if !strings.HasPrefix(gotProduct, product[:20]) {
		t.Errorf("product = %q, want the head of what was asked", gotProduct)
	}
}

func TestIntegration_TopMisses_RanksAndHonoursTheCooldown(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	hot := uniqueProduct(t, "it-hot")
	cold := uniqueProduct(t, "it-cold")
	cleanupProduct(t, db, hot)
	cleanupProduct(t, db, cold)

	for i := 0; i < 5; i++ {
		if err := store.RecordMiss(ctx, MissSubject{Kind: KindSoftware, Product: hot}); err != nil {
			t.Fatalf("RecordMiss hot: %v", err)
		}
	}
	if err := store.RecordMiss(ctx, MissSubject{Kind: KindSoftware, Product: cold}); err != nil {
		t.Fatalf("RecordMiss cold: %v", err)
	}

	top, err := store.TopMisses(ctx, 100, time.Hour)
	if err != nil {
		t.Fatalf("TopMisses: %v", err)
	}
	posHot, posCold := -1, -1
	for i, m := range top {
		switch m.Product {
		case hot:
			posHot = i
		case cold:
			posCold = i
		}
	}
	if posHot < 0 || posCold < 0 {
		t.Fatalf("both gaps should be selectable; got hot=%d cold=%d", posHot, posCold)
	}
	if posHot > posCold {
		t.Errorf("the gap hit 5 times must rank above the one hit once")
	}

	// Stamping it takes it out of the next pass — this is what stops a nightly
	// run re-asking the same question forever.
	var hotID string
	if err := db.QueryRow(`SELECT id FROM public.catalog_lookup_misses WHERE product = $1`, hot).Scan(&hotID); err != nil {
		t.Fatalf("select hot id: %v", err)
	}
	if err := store.MarkMissProposed(ctx, hotID); err != nil {
		t.Fatalf("MarkMissProposed: %v", err)
	}
	top, err = store.TopMisses(ctx, 100, time.Hour)
	if err != nil {
		t.Fatalf("TopMisses after stamp: %v", err)
	}
	for _, m := range top {
		if m.Product == hot {
			t.Fatalf("a gap asked about within the cooldown must not be reselected")
		}
	}

	// A cooldown of zero brings it back, which is the inverse polarity: a
	// filter that excluded everything would pass the test above just as well.
	top, err = store.TopMisses(ctx, 100, 0)
	if err != nil {
		t.Fatalf("TopMisses cooldown 0: %v", err)
	}
	found := false
	for _, m := range top {
		if m.Product == hot {
			found = true
		}
	}
	if !found {
		t.Fatal("with no cooldown the stamped gap must be selectable again")
	}
}

func TestIntegration_InsertProposal_AtMostOnePendingPerSubject(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	product := uniqueProduct(t, "it-prop")
	cleanupProduct(t, db, product)

	first, err := store.InsertProposal(ctx, newProposal(product))
	if err != nil {
		t.Fatalf("first InsertProposal: %v", err)
	}
	if first == nil {
		t.Fatal("first InsertProposal returned no row")
	}
	if first.Status != StatusPending || first.SourceKind != "inferred" || first.Confidence != 0 {
		t.Errorf("stored defaults = status %q source_kind %q confidence %v",
			first.Status, first.SourceKind, first.Confidence)
	}

	// The DO NOTHING path: (nil, nil), not an error. A caller that treated it
	// as failure would log an error every night for as long as a proposal sat
	// unreviewed.
	second, err := store.InsertProposal(ctx, newProposal(product))
	if err != nil {
		t.Fatalf("second InsertProposal: %v", err)
	}
	if second != nil {
		t.Fatalf("a second pending proposal for the same subject was stored: %+v", second)
	}

	// Rejecting the first frees the subject: the uniqueness index is PARTIAL on
	// status='pending', so history does not block a fresh question.
	if _, err := store.RejectProposal(ctx, first.ID, Reviewer{ID: testReviewerID, Email: "a@b.c"}); err != nil {
		t.Fatalf("RejectProposal: %v", err)
	}
	third, err := store.InsertProposal(ctx, newProposal(product))
	if err != nil {
		t.Fatalf("third InsertProposal: %v", err)
	}
	if third == nil {
		t.Fatal("a rejected proposal must not block a new pending one")
	}
}

// The table's constraints, restated in Go, actually hold.
func TestIntegration_InsertProposal_RefusesAnUncitedOrUnattributedProposal(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	product := uniqueProduct(t, "it-bad")
	cleanupProduct(t, db, product)

	uncited := newProposal(product)
	uncited.SourceURL = ""
	if _, err := store.InsertProposal(ctx, uncited); err == nil {
		t.Error("an uncited proposal must be refused (ADR-0008 D4.4)")
	}

	unattributed := newProposal(product)
	unattributed.ModelID = ""
	if _, err := store.InsertProposal(ctx, unattributed); err == nil {
		t.Error("a proposal naming no model must be refused (D4.1)")
	}

	badKind := newProposal(product)
	badKind.ProductKind = "firmware"
	if _, err := store.InsertProposal(ctx, badKind); err == nil {
		t.Error("an unknown product_kind must be refused")
	}

	var stored int
	if err := db.QueryRow(`SELECT count(*) FROM public.eol_catalogue_proposals WHERE subject_product = $1`,
		product).Scan(&stored); err != nil {
		t.Fatalf("count: %v", err)
	}
	if stored != 0 {
		t.Fatalf("stored %d refused proposals", stored)
	}
}

// Accept is the only route into the catalogue, and it writes BOTH halves or
// neither.
func TestIntegration_AcceptProposal_WritesTheCatalogueRowWithProvenance(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	product := uniqueProduct(t, "it-accept")
	cleanupProduct(t, db, product)

	proposal, err := store.InsertProposal(ctx, newProposal(product))
	if err != nil || proposal == nil {
		t.Fatalf("InsertProposal: %v", err)
	}

	accepted, eolID, err := store.AcceptProposal(ctx, proposal.ID,
		Reviewer{ID: testReviewerID, Email: "reviewer@example.com"})
	if err != nil {
		t.Fatalf("AcceptProposal: %v", err)
	}
	if accepted.Status != StatusAccepted {
		t.Errorf("status = %q", accepted.Status)
	}
	if accepted.ReviewedAt == nil || accepted.ReviewerID == nil || *accepted.ReviewerID != testReviewerID {
		t.Errorf("reviewer not recorded: %+v", accepted)
	}
	if eolID == "" {
		t.Fatal("no catalogue row id returned")
	}

	var kind, vendor, cycle, sourceKind, sourceURL string
	var eolDate time.Time
	if err := db.QueryRow(`SELECT product_kind, vendor, cycle, source_kind, source_url, eol_date
		FROM public.eol_catalogue WHERE id = $1`, eolID).
		Scan(&kind, &vendor, &cycle, &sourceKind, &sourceURL, &eolDate); err != nil {
		t.Fatalf("select catalogue row: %v", err)
	}
	// The row says forever where it came from. This is what the End-of-life
	// page badges, and what stops an accepted proposal becoming indistinguishable
	// from a mirrored one.
	if sourceKind != "inferred" {
		t.Errorf("source_kind = %q, want inferred", sourceKind)
	}
	if sourceURL != "https://www.cisco.com/eol" {
		t.Errorf("source_url = %q, want the cited page", sourceURL)
	}
	if kind != KindOS || vendor != "Cisco" || cycle != "17.9" {
		t.Errorf("row = %s/%s/%s", kind, vendor, cycle)
	}
	if eolDate.UTC().Format("2006-01-02") != "2027-04-30" {
		t.Errorf("eol_date = %s", eolDate)
	}

	// A second accept loses. Reviewing is deliberately not idempotent: a second
	// accept would write a second catalogue row, and answering success would
	// tell two reviewers they each made the decision.
	if _, _, err := store.AcceptProposal(ctx, proposal.ID, Reviewer{ID: testReviewerID}); err == nil {
		t.Error("a second accept must fail")
	}
}

// An accepted proposal for a cycle a feed has since filled UPDATES that row
// rather than failing — and the update carries the honest source_kind.
func TestIntegration_AcceptProposal_UpdatesAnExistingCatalogueRow(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	product := uniqueProduct(t, "it-collide")
	cleanupProduct(t, db, product)

	if _, err := db.Exec(`INSERT INTO public.eol_catalogue
		(product_kind, vendor, product, cycle, eol_date, source_url, source_kind)
		VALUES ($1, 'Cisco', $2, '17.9', '2026-01-01', 'https://endoflife.date/x', 'imported')`,
		KindOS, product); err != nil {
		t.Fatalf("seed catalogue row: %v", err)
	}

	proposal, err := store.InsertProposal(ctx, newProposal(product))
	if err != nil || proposal == nil {
		t.Fatalf("InsertProposal: %v", err)
	}
	_, eolID, err := store.AcceptProposal(ctx, proposal.ID, Reviewer{ID: testReviewerID})
	if err != nil {
		t.Fatalf("AcceptProposal: %v", err)
	}

	var rows int
	var sourceKind string
	if err := db.QueryRow(`SELECT count(*) FROM public.eol_catalogue WHERE product = $1`, product).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 1 {
		t.Fatalf("rows = %d, want the existing row updated rather than a duplicate", rows)
	}
	if err := db.QueryRow(`SELECT source_kind FROM public.eol_catalogue WHERE id = $1`, eolID).Scan(&sourceKind); err != nil {
		t.Fatalf("select: %v", err)
	}
	if sourceKind != "inferred" {
		t.Errorf("source_kind = %q, want the row to say it now carries an inferred date", sourceKind)
	}
}

// A rejection writes nothing to the catalogue and keeps the row as evidence.
func TestIntegration_RejectProposal_WritesNothingToTheCatalogue(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	product := uniqueProduct(t, "it-reject")
	cleanupProduct(t, db, product)

	proposal, err := store.InsertProposal(ctx, newProposal(product))
	if err != nil || proposal == nil {
		t.Fatalf("InsertProposal: %v", err)
	}
	rejected, err := store.RejectProposal(ctx, proposal.ID, Reviewer{ID: testReviewerID, Email: "r@e.com"})
	if err != nil {
		t.Fatalf("RejectProposal: %v", err)
	}
	if rejected.Status != StatusRejected || rejected.ReviewedAt == nil {
		t.Fatalf("rejected = %+v", rejected)
	}

	var rows int
	if err := db.QueryRow(`SELECT count(*) FROM public.eol_catalogue WHERE product = $1`, product).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 0 {
		t.Fatalf("a rejection wrote %d catalogue rows", rows)
	}
	// The proposal survives: it is the record of a model having been wrong.
	if err := db.QueryRow(`SELECT count(*) FROM public.eol_catalogue_proposals WHERE subject_product = $1`,
		product).Scan(&rows); err != nil {
		t.Fatalf("count proposals: %v", err)
	}
	if rows != 1 {
		t.Fatalf("proposal rows = %d, want the rejection kept", rows)
	}
}

// Accept RE-VALIDATES the citation rather than trusting it from write time.
//
// The generative proposer cannot produce such a row, so the only way to reach
// this is the way a future second proposal source would: a direct INSERT. That
// is exactly why the check is here — accept is where a claim becomes a row every
// tenant is evaluated against, and "it was checked when it was stored" is a
// promise about a writer that may not have existed when accept was written.
func TestIntegration_AcceptProposal_RefusesAnUncheckableCitation(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	product := uniqueProduct(t, "it-badcite")
	cleanupProduct(t, db, product)

	var id string
	if err := db.QueryRow(`INSERT INTO public.eol_catalogue_proposals
		(product_kind, subject_vendor, subject_product, proposed_cycle, proposed_eol_date, source_url, model_id)
		VALUES ('software', 'Acme', $1, '1.0', '2028-01-01', 'https://169.254.169.254/eol', 'm-1')
		RETURNING id`, product).Scan(&id); err != nil {
		t.Fatalf("seed proposal: %v", err)
	}

	_, _, err := store.AcceptProposal(ctx, id, Reviewer{ID: testReviewerID, Email: "r@e.com"})
	if !errors.Is(err, ErrProposalUncitable) {
		t.Fatalf("accept err = %v, want ErrProposalUncitable", err)
	}

	// Neither half of the decision happened: no catalogue row, and the
	// proposal is still pending rather than marked accepted.
	var rows int
	if err := db.QueryRow(`SELECT count(*) FROM public.eol_catalogue WHERE product = $1`, product).Scan(&rows); err != nil {
		t.Fatalf("count catalogue: %v", err)
	}
	if rows != 0 {
		t.Fatalf("a refused accept wrote %d catalogue rows", rows)
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM public.eol_catalogue_proposals WHERE id = $1`, id).Scan(&status); err != nil {
		t.Fatalf("read status: %v", err)
	}
	if status != StatusPending {
		t.Fatalf("status = %q, want the proposal left pending", status)
	}

	// The inverse polarity: the same row with a checkable citation accepts, so
	// the guard is refusing the URL and not accept itself.
	if _, err := db.Exec(`UPDATE public.eol_catalogue_proposals SET source_url = 'https://acme.example/eol' WHERE id = $1`, id); err != nil {
		t.Fatalf("fix citation: %v", err)
	}
	if _, eolID, err := store.AcceptProposal(ctx, id, Reviewer{ID: testReviewerID, Email: "r@e.com"}); err != nil || eolID == "" {
		t.Fatalf("accept with a good citation: err=%v id=%q", err, eolID)
	}
}

// The same rule at the other door: a direct InsertProposal cannot store an
// uncheckable citation either, so the queue never fills with proposals accept
// will later refuse.
func TestIntegration_InsertProposal_RefusesAnUncheckableCitation(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	product := uniqueProduct(t, "it-badcite2")
	cleanupProduct(t, db, product)

	for _, bad := range []string{"x", "http://www.cisco.com/eol", "https://10.0.0.1/eol", "https://wiki.internal/eol"} {
		p := newProposal(product)
		p.SourceURL = bad
		if _, err := store.InsertProposal(ctx, p); err == nil {
			t.Errorf("InsertProposal stored source_url %q", bad)
		}
	}
	var rows int
	if err := db.QueryRow(`SELECT count(*) FROM public.eol_catalogue_proposals WHERE subject_product = $1`,
		product).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 0 {
		t.Fatalf("stored %d proposals with an uncheckable citation", rows)
	}
}

func TestIntegration_ReviewingAMissingProposalIsNotFound(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	missing := "00000000-0000-4000-8000-00000000dead"
	if _, _, err := store.AcceptProposal(ctx, missing, Reviewer{ID: testReviewerID}); err != ErrProposalNotFound {
		t.Errorf("accept err = %v, want ErrProposalNotFound", err)
	}
	if _, err := store.RejectProposal(ctx, missing, Reviewer{ID: testReviewerID}); err != ErrProposalNotFound {
		t.Errorf("reject err = %v, want ErrProposalNotFound", err)
	}
}

// The status-filtered list and its count use the same predicate.
func TestIntegration_ListProposals_FiltersByStatus(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	product := uniqueProduct(t, "it-list")
	cleanupProduct(t, db, product)

	p, err := store.InsertProposal(ctx, newProposal(product))
	if err != nil || p == nil {
		t.Fatalf("InsertProposal: %v", err)
	}

	pending, _, err := store.ListProposals(ctx, ProposalQuery{Status: StatusPending, PageSize: MaxPageSize})
	if err != nil {
		t.Fatalf("ListProposals pending: %v", err)
	}
	if !containsProposal(pending, p.ID) {
		t.Fatal("the pending proposal is missing from the pending list")
	}
	accepted, _, err := store.ListProposals(ctx, ProposalQuery{Status: StatusAccepted, PageSize: MaxPageSize})
	if err != nil {
		t.Fatalf("ListProposals accepted: %v", err)
	}
	if containsProposal(accepted, p.ID) {
		t.Fatal("a pending proposal appeared in the accepted list")
	}

	if _, _, err := store.AcceptProposal(ctx, p.ID, Reviewer{ID: testReviewerID}); err != nil {
		t.Fatalf("AcceptProposal: %v", err)
	}
	accepted, _, err = store.ListProposals(ctx, ProposalQuery{Status: StatusAccepted, PageSize: MaxPageSize})
	if err != nil {
		t.Fatalf("ListProposals accepted 2: %v", err)
	}
	if !containsProposal(accepted, p.ID) {
		t.Fatal("the accepted proposal is missing from the accepted list")
	}
}

// The candidate query's LIKE metacharacters are escaped, so a product name
// containing '%' does not silently return ten arbitrary rows presented to a
// model as "the nearest ones".
func TestIntegration_Candidates_EscapesLikeMetacharacters(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	product := uniqueProduct(t, "it-cand")
	cleanupProduct(t, db, product)

	if _, err := db.Exec(`INSERT INTO public.eol_catalogue
		(product_kind, vendor, product, cycle, eol_date, source_url, source_kind)
		VALUES ($1, 'Acme', $2, '1', '2030-01-01', 'https://x/1', 'imported')`,
		KindSoftware, product); err != nil {
		t.Fatalf("seed: %v", err)
	}

	hits, err := store.Candidates(ctx, "", product, 10)
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("the seeded row should be its own nearest candidate")
	}

	// A bare '%' must match nothing here rather than everything.
	wild, err := store.Candidates(ctx, "", "%", 10)
	if err != nil {
		t.Fatalf("Candidates wildcard: %v", err)
	}
	for _, h := range wild {
		if h.Product == product {
			t.Fatal("a literal '%' product name matched the catalogue as a wildcard")
		}
	}
}

// The CPE lookup only ever returns a name an advisory already uses, and only a
// product-level one.
func TestIntegration_LookupCPE_OnlyReturnsAProductLevelNameFromAMatchRule(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	cve := fmt.Sprintf("CVE-2099-%d", time.Now().UnixNano()%100000)
	vendor := fmt.Sprintf("acmeco%d", time.Now().UnixNano()%100000)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.vulnerability_catalogue WHERE cve_id = $1`, cve) })

	if _, err := db.Exec(`INSERT INTO public.vulnerability_catalogue (cve_id, source_kind)
		VALUES ($1, 'imported')`, cve); err != nil {
		t.Fatalf("seed cve: %v", err)
	}
	// A version-pinned rule first, then the product-level one. Only the second
	// is a name for the PRODUCT; the first belongs to this CVE's range bounds.
	pinned := fmt.Sprintf(`{"cpe":"cpe:2.3:a:%s:widget:1.2.3:*:*:*:*:*:*:*"}`, vendor)
	productLevel := fmt.Sprintf(`{"cpe":"cpe:2.3:a:%s:widget:*:*:*:*:*:*:*:*"}`, vendor)
	for _, m := range []string{pinned, productLevel} {
		if _, err := db.Exec(`INSERT INTO public.vulnerability_matches (cve_id, cpe_match_string)
			VALUES ($1, $2)`, cve, m); err != nil {
			t.Fatalf("seed match: %v", err)
		}
	}

	cpe, gotCVE, err := store.LookupCPE(ctx, vendor, "widget")
	if err != nil {
		t.Fatalf("LookupCPE: %v", err)
	}
	if cpe != fmt.Sprintf("cpe:2.3:a:%s:widget:*:*:*:*:*:*:*:*", vendor) {
		t.Errorf("cpe = %q, want the product-level name", cpe)
	}
	if gotCVE != cve {
		t.Errorf("cve = %q, want %q", gotCVE, cve)
	}

	// A vendor that does not appear in any match rule gets nothing, not a
	// constructed name.
	if cpe, _, err := store.LookupCPE(ctx, "nobody-ltd", "widget"); err != nil || cpe != "" {
		t.Errorf("cpe = %q err = %v, want nothing", cpe, err)
	}
	// And with no vendor there is nothing to anchor the component pair, so the
	// lookup refuses rather than widening.
	if cpe, _, err := store.LookupCPE(ctx, "", "widget"); err != nil || cpe != "" {
		t.Errorf("cpe = %q err = %v, want nothing without a vendor", cpe, err)
	}
}

const testReviewerID = "11111111-2222-3333-4444-555555555555"

func containsProposal(list []Proposal, id string) bool {
	for _, p := range list {
		if p.ID == id {
			return true
		}
	}
	return false
}
