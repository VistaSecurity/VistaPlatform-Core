package producers

// The eol producer's resolve phase, against in-memory catalogue rows.
//
// The read and write phases need a database and are covered by
// eol_producer_integration_test.go. What is testable here is the decision:
// which catalogue row answers a subject, whether the date warrants a finding,
// and what the finding then carries — including the citation, which is the
// whole reason a person can check the claim.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/catalogs"
	"github.com/vistasecurity/vistaplatform/shared/catalogs/catalogstest"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
)

// fixedNow is the clock every case here runs against, so "90 days from now" is
// a date rather than a moving target.
var fixedNow = time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)

func at(days int) *time.Time {
	t := fixedNow.AddDate(0, 0, days)
	return &t
}

func testProducer(t *testing.T, store catalogs.LookupStore) *EOLProducer {
	t.Helper()
	p, err := newEOLProducerWithStore(nil, store)
	if err != nil {
		t.Fatalf("newEOLProducerWithStore: %v", err)
	}
	p.now = func() time.Time { return fixedNow }
	return p
}

func ubuntuRow(eol *time.Time) catalogs.EOLRow {
	return catalogs.EOLRow{
		ID:          "11111111-1111-1111-1111-111111111111",
		ProductKind: catalogs.KindOS,
		Vendor:      "Canonical",
		Product:     "Ubuntu",
		Cycle:       "18.04",
		EOLDate:     eol,
		SourceURL:   "https://endoflife.date/ubuntu",
	}
}

func resolveOS(t *testing.T, p *EOLProducer, run *Run, name, version string) *plannedFinding {
	t.Helper()
	assetID := uuid.New()
	plan, _, err := p.resolveOne(context.Background(), run, catalogs.KindOS, findings.KindOSEndOfLife,
		assetID, "web-01", producer.Subject{Type: findings.SubjectAsset, ID: assetID},
		"", name, version, nil)
	if err != nil {
		t.Fatalf("resolveOne: %v", err)
	}
	return plan
}

func TestEOLResolve_PastDateRaisesAFindingWithItsCitation(t *testing.T) {
	store := &catalogstest.Store{Rows: []catalogs.EOLRow{ubuntuRow(at(-30))}}
	p := testProducer(t, store)

	var run Run
	plan := resolveOS(t, p, &run, "Ubuntu", "18.04.6 LTS")
	if plan == nil || plan.finding.Kind == "" {
		t.Fatal("a catalogue row 30 days past its end-of-life date raised no finding")
	}

	f := plan.finding
	if f.Kind != findings.KindOSEndOfLife || f.Subject.Type != findings.SubjectAsset {
		t.Errorf("finding is %s on a %s, want os_end_of_life on an asset", f.Kind, f.Subject.Type)
	}
	// 30 days past, inside the year → the middle rung.
	k, _ := findings.Get(findings.ProducerEOL, findings.KindOSEndOfLife)
	if f.Severity != k.Rungs[rungPast].Severity || f.Score != k.Rungs[rungPast].Score {
		t.Errorf("severity/score = %s/%d, want the registry's 'past end of life' rung %s/%d",
			f.Severity, f.Score, k.Rungs[rungPast].Severity, k.Rungs[rungPast].Score)
	}
	if f.Summary != "web-01 runs an end-of-life operating system (30 days ago)" {
		t.Errorf("summary = %q", f.Summary)
	}

	// The citation is the point. Both halves: the row id so a disputed date
	// leads to the exact thing that said it, and the URL so a person can check
	// it without database access.
	if got := f.Evidence["catalogue_id"]; got != store.Rows[0].ID {
		t.Errorf("evidence.catalogue_id = %v, want the row that answered (%s)", got, store.Rows[0].ID)
	}
	if got := f.Evidence["catalogue_source_url"]; got != "https://endoflife.date/ubuntu" {
		t.Errorf("evidence.catalogue_source_url = %v; without it the finding cannot be checked", got)
	}
	if got := f.Evidence["eol_date"]; got != at(-30).UTC().Format("2006-01-02") {
		t.Errorf("evidence.eol_date = %v", got)
	}
	if got := f.Evidence["observed_version"]; got != "18.04.6 LTS" {
		t.Errorf("evidence.observed_version = %v, want the version as reported", got)
	}
	if f.SourceKind != producer.SourceImported {
		t.Errorf("source_kind = %q, want imported — the date came out of a mirrored catalogue, we did not measure it", f.SourceKind)
	}

	// The fact travels alongside, from the same row.
	if plan.fact == nil {
		t.Fatal("no eol.os.date fact was planned")
	}
	if plan.fact.Key != "eol.os.date" {
		t.Errorf("fact key = %q, want eol.os.date", plan.fact.Key)
	}
	if plan.fact.SourceRef != "catalog:eol:"+store.Rows[0].ID {
		t.Errorf("fact source_ref = %q, want catalog:eol:<row id>", plan.fact.SourceRef)
	}
	if run.Matched != 1 || run.FactsWritten != 1 || run.Misses != 0 {
		t.Errorf("run = %+v, want one match, one fact, no gap", run)
	}
}

func TestEOLResolve_FutureDateWritesTheFactAndNoFinding(t *testing.T) {
	// Support ends in two years. The asset page still shows the date — that is
	// how somebody plans an upgrade before it becomes a problem — but a finding
	// would be noise that trains people to ignore the real ones.
	store := &catalogstest.Store{Rows: []catalogs.EOLRow{ubuntuRow(at(800))}}
	p := testProducer(t, store)

	var run Run
	plan := resolveOS(t, p, &run, "Ubuntu", "18.04")
	if plan == nil {
		t.Fatal("nothing was planned at all; the fact should still be written")
	}
	if plan.finding.Kind != "" {
		t.Errorf("a date 800 days out raised a finding (%s/%d)", plan.finding.Severity, plan.finding.Score)
	}
	if plan.fact == nil {
		t.Error("the eol.os.date fact was not planned; the date is known whether or not it is a problem yet")
	}
	if run.Matched != 1 {
		t.Errorf("run.Matched = %d, want 1 — the row matched even though nothing was raised", run.Matched)
	}
}

func TestEOLResolve_NullEOLDateIsAMatchWithNoFindingAndNoGap(t *testing.T) {
	// endoflife.date publishes `true` for "support has ended, date unknown" and
	// `false` for "not announced"; the mirror stores both as NULL rather than
	// inventing a date. There is nothing to judge — and it is NOT a gap: "the
	// catalogue has never heard of this" and "the catalogue has it and
	// publishes no date" are different problems with different fixes, and only
	// the first belongs on the list the enrichment pass works from.
	store := &catalogstest.Store{Rows: []catalogs.EOLRow{ubuntuRow(nil)}}
	p := testProducer(t, store)

	var run Run
	plan := resolveOS(t, p, &run, "Ubuntu", "18.04")
	if plan != nil && plan.finding.Kind != "" {
		t.Error("a catalogue row with a NULL eol_date raised a finding")
	}
	if plan != nil && plan.fact != nil {
		t.Error("a catalogue row with a NULL eol_date produced a fact; there is no date to state")
	}
	if run.Matched != 1 {
		t.Errorf("run.Matched = %d, want 1 — the row matched", run.Matched)
	}
	if run.Misses != 0 || len(store.Misses) != 0 {
		t.Errorf("a matched row was recorded as a gap (%d); the gap list is for products the catalogue does not have", run.Misses)
	}
}

func TestEOLResolve_UncitedRowProducesNoFact(t *testing.T) {
	// ADR-0008 D4.4 is cite or refuse, and it binds the lookup exactly as it
	// binds a model. A catalogue row with no source_url is one an operator
	// hand-entered without one, and it is not evidence.
	row := ubuntuRow(at(-30))
	row.SourceURL = ""
	p := testProducer(t, &catalogstest.Store{Rows: []catalogs.EOLRow{row}})

	var run Run
	plan := resolveOS(t, p, &run, "Ubuntu", "18.04")
	if plan == nil {
		t.Fatal("nothing planned")
	}
	if plan.fact != nil {
		t.Error("an uncited catalogue row produced a fact")
	}
	// The FINDING is still raised — the date is in the catalogue, the row id is
	// in the evidence, and suppressing a real end-of-life finding because
	// somebody forgot a URL would be the cure worse than the disease.
	if plan.finding.Kind == "" {
		t.Error("an uncited row raised no finding; the row id is still a citation")
	}
	if plan.finding.Evidence["catalogue_source_url"] != "" {
		t.Errorf("evidence claims a source URL the row does not have: %v", plan.finding.Evidence["catalogue_source_url"])
	}
}

func TestEOLResolve_MissIsRecordedOnTheGapList(t *testing.T) {
	store := &catalogstest.Store{} // catalogue knows nothing
	p := testProducer(t, store)

	var run Run
	plan := resolveOS(t, p, &run, "Cisco IOS-XE", "17.9.4a")
	if plan != nil {
		t.Error("an unresolvable subject produced a plan")
	}
	if run.Misses != 1 || len(store.Misses) != 1 {
		t.Fatalf("run.Misses=%d store.Misses=%d, want one gap recorded", run.Misses, len(store.Misses))
	}
	m := store.Misses[0]
	if m.Product != "Cisco IOS-XE" || m.Version != "17.9.4a" {
		t.Errorf("the gap was recorded as %+v; the subject is stored verbatim so a reviewer sees what was asked", m)
	}
	if m.Kind != catalogs.KindOS {
		t.Errorf("gap kind = %q, want os", m.Kind)
	}
}

func TestEOLResolve_GapListIsBoundedPerRun(t *testing.T) {
	// A tenant with fifty thousand unrecognised npm packages must not bury the
	// row the enrichment pass should actually work on. The LOOKUP still runs
	// once the budget is spent — only the bookkeeping stops.
	store := &catalogstest.Store{}
	p := testProducer(t, store)
	p.maxMisses = 2

	var run Run
	for i := 0; i < 5; i++ {
		resolveOS(t, p, &run, "unknown-product", "1.0")
	}
	if run.Misses != 2 {
		t.Errorf("run.Misses = %d, want the bound of 2", run.Misses)
	}
	if run.MissesDropped != 3 {
		t.Errorf("run.MissesDropped = %d, want 3 — a run that recorded a subset has to say so", run.MissesDropped)
	}
	if len(store.Misses) != 2 {
		t.Errorf("%d gaps reached the store, want 2", len(store.Misses))
	}
	// And the lookups kept happening, so a finding after the bound is still
	// found.
	if len(store.Asked) != 5 {
		t.Errorf("%d lookups, want 5 — the bound stops the bookkeeping, not the matching", len(store.Asked))
	}
}

func TestEOLResolve_NoProductNameIsSkippedNotRecorded(t *testing.T) {
	// An asset with no os.name fact is a caller with nothing to ask, not a gap
	// in the catalogue. Counting it would put noise at the top of the list.
	store := &catalogstest.Store{}
	p := testProducer(t, store)

	var run Run
	if plan := resolveOS(t, p, &run, "", "18.04"); plan != nil {
		t.Error("a subject with no product name produced a plan")
	}
	if run.Skipped != 1 {
		t.Errorf("run.Skipped = %d, want 1", run.Skipped)
	}
	if run.Misses != 0 || len(store.Misses) != 0 {
		t.Error("a subject with no product name was recorded on the gap list")
	}
	if len(store.Asked) != 0 {
		t.Error("a subject with no product name reached the catalogue")
	}
}

func TestEOLResolve_SoftwareSubjectIsTheInstall(t *testing.T) {
	// The identity index allows one open row per (producer, kind, subject).
	// On an ASSET subject, forty end-of-life packages would collapse into one
	// finding and lose thirty-nine.
	row := ubuntuRow(at(-10))
	row.ProductKind = catalogs.KindSoftware
	row.Product = "nginx"
	row.Vendor = ""
	row.Cycle = "1.20"
	p := testProducer(t, &catalogstest.Store{Rows: []catalogs.EOLRow{row}})

	assetID, installID, productID := uuid.New(), uuid.New(), uuid.New()
	var run Run
	plan, _, err := p.resolveOne(context.Background(), &run, catalogs.KindSoftware, findings.KindSoftwareEndOfLife,
		assetID, "nginx 1.20.0", producer.Subject{Type: findings.SubjectSoftwareInstall, ID: installID},
		"", "nginx", "1.20.0",
		map[string]any{
			"asset_id":   assetID.String(),
			"product_id": productID.String(),
			"install_id": installID.String(),
		})
	if err != nil {
		t.Fatalf("resolveOne: %v", err)
	}
	if plan == nil || plan.finding.Kind == "" {
		t.Fatal("no software end-of-life finding")
	}
	if plan.finding.Subject.Type != findings.SubjectSoftwareInstall || plan.finding.Subject.ID != installID {
		t.Errorf("subject = %s/%s, want the software install %s",
			plan.finding.Subject.Type, plan.finding.Subject.ID, installID)
	}
	// The asset and product still travel, so the inspector can drill either way.
	if plan.finding.Evidence["asset_id"] != assetID.String() {
		t.Error("evidence does not name the asset the install is on")
	}
	if plan.finding.Evidence["product_id"] != productID.String() {
		t.Error("evidence does not name the product")
	}
	// The fact is written on the ASSET — asset_facts is keyed by asset.
	if plan.assetID != assetID {
		t.Errorf("the fact is planned for %s, want the asset %s", plan.assetID, assetID)
	}
}

// Every finding this producer plans has to be one the shared writer will accept.
// Without this, a severity/score pair that drifts from the registry would only
// fail at the database, inside a transaction, with the whole run lost.
func TestEOLResolve_EveryPlannedFindingPassesTheWriterContract(t *testing.T) {
	w, err := producer.New(findings.ProducerEOL)
	if err != nil {
		t.Fatalf("producer.New: %v", err)
	}
	for _, days := range []int{-2000, -400, -365, -1, 0, 45, 89, 90} {
		store := &catalogstest.Store{Rows: []catalogs.EOLRow{ubuntuRow(at(days))}}
		p := testProducer(t, store)
		var run Run
		plan := resolveOS(t, p, &run, "Ubuntu", "18.04")
		if plan == nil || plan.finding.Kind == "" {
			continue
		}
		if err := w.Validate(plan.finding); err != nil {
			t.Errorf("a finding planned at %d days was refused by the writer: %v", days, err)
		}
	}
}
