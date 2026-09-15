package producers

// The per-install lifecycle record — what the resolve phase concludes for a
// software install, and how that becomes the row the write phase records.
//
// Each outcome maps onto exactly one recorded word, or onto no row at all, and
// the mapping is what the Software surfaces read: a wrong word here is a wrong
// cell there. These cases run against in-memory catalogue rows; the database
// half (the transaction, the sweep, the RLS) is in
// eol_lifecycle_integration_test.go.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/catalogs"
	"github.com/vistasecurity/vistaplatform/shared/catalogs/catalogstest"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
	"github.com/vistasecurity/vistaplatform/shared/software"
)

func nginxRow(eol *time.Time) catalogs.EOLRow {
	return catalogs.EOLRow{
		ID:          "22222222-2222-2222-2222-222222222222",
		ProductKind: catalogs.KindSoftware,
		Product:     "nginx",
		Cycle:       "1.20",
		EOLDate:     eol,
		SourceURL:   "https://endoflife.date/nginx",
	}
}

// resolveInstall resolves one software install and returns what the write
// phase would record for it.
func resolveInstall(t *testing.T, p *EOLProducer, run *Run, installID uuid.UUID, product, version string) (resolution, *plannedFinding) {
	t.Helper()
	assetID := uuid.New()
	plan, res, err := p.resolveOne(context.Background(), run, catalogs.KindSoftware, findings.KindSoftwareEndOfLife,
		assetID, product+" "+version, producer.Subject{Type: findings.SubjectSoftwareInstall, ID: installID},
		"", product, version, nil)
	if err != nil {
		t.Fatalf("resolveOne: %v", err)
	}
	return res, plan
}

func TestEOLLifecycle_EachOutcomeRecordsOneWord(t *testing.T) {
	installID := uuid.New()
	cases := []struct {
		name    string
		rows    []catalogs.EOLRow
		product string

		wantRecorded bool
		wantWord     string
		wantCitation bool
		wantDate     bool
		wantFinding  bool
	}{
		{
			name: "a past date is end_of_life, with the finding",
			rows: []catalogs.EOLRow{nginxRow(at(-10))}, product: "nginx",
			wantRecorded: true, wantWord: software.LifecycleEndOfLife, wantCitation: true, wantDate: true, wantFinding: true,
		},
		{
			name: "a date inside the warning window is end_of_life too",
			rows: []catalogs.EOLRow{nginxRow(at(30))}, product: "nginx",
			wantRecorded: true, wantWord: software.LifecycleEndOfLife, wantCitation: true, wantDate: true, wantFinding: true,
		},
		{
			// The case this whole record exists for: a supported package used
			// to be indistinguishable from one the catalogue had never seen.
			name: "a date beyond the window is supported, with no finding",
			rows: []catalogs.EOLRow{nginxRow(at(800))}, product: "nginx",
			wantRecorded: true, wantWord: software.LifecycleSupported, wantCitation: true, wantDate: true, wantFinding: false,
		},
		{
			name: "a matched row with no date is no_date, cited, undated",
			rows: []catalogs.EOLRow{nginxRow(nil)}, product: "nginx",
			wantRecorded: true, wantWord: software.LifecycleNoDate, wantCitation: true, wantDate: false, wantFinding: false,
		},
		{
			name: "a miss is not_in_catalogue, citing nothing",
			rows: nil, product: "nginx",
			wantRecorded: true, wantWord: software.LifecycleNotInCatalogue, wantCitation: false, wantDate: false, wantFinding: false,
		},
		{
			// Not a gap and not coverage, so not a record either: "no
			// completed pass has assessed this" is the honest state for an
			// install the producer had nothing to ask about.
			name: "no product name records nothing",
			rows: nil, product: "   ",
			wantRecorded: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testProducer(t, &catalogstest.Store{Rows: tc.rows})
			var run Run
			res, plan := resolveInstall(t, p, &run, installID, tc.product, "1.20.0")

			row, ok, err := lifecycleFor(installID, res)
			if err != nil {
				t.Fatalf("lifecycleFor: %v", err)
			}
			if ok != tc.wantRecorded {
				t.Fatalf("recorded = %v, want %v", ok, tc.wantRecorded)
			}
			if !ok {
				if res.asked() {
					t.Error("an install with nothing to record was still counted as asked; coverage would be over-claimed")
				}
				return
			}
			if row.InstallID != installID {
				t.Errorf("the record is keyed on %s, want the install %s", row.InstallID, installID)
			}
			if row.Assessment != tc.wantWord {
				t.Errorf("assessment = %q, want %q", row.Assessment, tc.wantWord)
			}
			if got := row.CatalogueID != nil; got != tc.wantCitation {
				t.Errorf("catalogue_id present = %v, want %v", got, tc.wantCitation)
			}
			if tc.wantCitation && row.CatalogueID.String() != tc.rows[0].ID {
				t.Errorf("catalogue_id = %s, want the row that answered (%s)", row.CatalogueID, tc.rows[0].ID)
			}
			if got := row.EOLDate != nil; got != tc.wantDate {
				t.Errorf("eol_date present = %v, want %v", got, tc.wantDate)
			}
			if tc.wantDate && !row.EOLDate.Equal(tc.rows[0].EOLDate.UTC()) {
				t.Errorf("eol_date = %v, want the catalogue's %v", row.EOLDate, tc.rows[0].EOLDate)
			}
			if got := plan != nil && plan.finding.Kind != ""; got != tc.wantFinding {
				t.Errorf("finding planned = %v, want %v — the record and the finding must agree", got, tc.wantFinding)
			}
			// Every recorded outcome is also coverage: the catalogue was asked.
			if !res.asked() {
				t.Error("a recorded outcome was not counted as asked")
			}
		})
	}
}

// Exhausting the per-run gap budget suppresses only the operator-facing gap
// row. The lookup still happened, so Software must still show the install as
// assessed and not_in_catalogue rather than falling back to "never assessed".
func TestEOLLifecycle_SuppressedMissStillRecordsNotInCatalogue(t *testing.T) {
	store := &catalogstest.Store{}
	p := testProducer(t, store)
	p.maxMisses = 1

	run := Run{Misses: 1}
	installID := uuid.New()
	res, plan := resolveInstall(t, p, &run, installID, "unrecognised-package", "9.9.9")

	if run.Misses != 1 {
		t.Errorf("run.Misses = %d, want the already-spent budget to stay unchanged", run.Misses)
	}
	if run.MissesDropped != 1 {
		t.Errorf("run.MissesDropped = %d, want the suppressed gap counted", run.MissesDropped)
	}
	if len(store.Misses) != 0 {
		t.Errorf("%d gaps reached the store after the budget was exhausted, want 0", len(store.Misses))
	}
	if len(store.Asked) != 1 {
		t.Fatalf("%d catalogue lookups, want 1 — the budget must not skip the assessment", len(store.Asked))
	}

	row, ok, err := lifecycleFor(installID, res)
	if err != nil {
		t.Fatalf("lifecycleFor: %v", err)
	}
	if !ok {
		t.Fatal("suppressed catalogue miss recorded no lifecycle row")
	}
	if row.Assessment != software.LifecycleNotInCatalogue {
		t.Errorf("assessment = %q, want %q", row.Assessment, software.LifecycleNotInCatalogue)
	}
	if row.CatalogueID != nil || row.EOLDate != nil {
		t.Errorf("a catalogue miss should not cite a row/date: catalogue_id=%v eol_date=%v", row.CatalogueID, row.EOLDate)
	}
	if !res.asked() {
		t.Error("a suppressed miss was not counted as an answered catalogue question")
	}
	if plan != nil && plan.finding.Kind != "" {
		t.Errorf("catalogue miss planned a finding: %+v", plan.finding)
	}
}

// The record and the finding cite the SAME catalogue row. A disputed date has
// to lead to one thing that said it, whichever of the two the reader starts
// from.
func TestEOLLifecycle_RecordAndFindingCiteTheSameRow(t *testing.T) {
	store := &catalogstest.Store{Rows: []catalogs.EOLRow{nginxRow(at(-10))}}
	p := testProducer(t, store)
	installID := uuid.New()
	var run Run
	res, plan := resolveInstall(t, p, &run, installID, "nginx", "1.20.0")
	row, ok, err := lifecycleFor(installID, res)
	if err != nil || !ok {
		t.Fatalf("lifecycleFor: ok=%v err=%v", ok, err)
	}
	if plan == nil || plan.finding.Kind == "" {
		t.Fatal("no finding planned for a past date")
	}
	if got := plan.finding.Evidence["catalogue_id"]; got != row.CatalogueID.String() {
		t.Errorf("finding cites %v, record cites %s", got, row.CatalogueID)
	}
	if got := plan.finding.Evidence["eol_date"]; got != row.EOLDate.Format("2006-01-02") {
		t.Errorf("finding says %v, record says %s", got, row.EOLDate.Format("2006-01-02"))
	}
}

// A catalogue row whose id cannot be a citation fails the pass rather than
// recording an answer nobody can trace. The column is a uuid in the database,
// so this cannot happen with the SQL store — the guard is for the in-memory
// one and for whatever store comes next.
func TestEOLLifecycle_RefusesAnUncitableRow(t *testing.T) {
	row := nginxRow(at(800))
	row.ID = "not-a-uuid"
	installID := uuid.New()
	if _, _, err := lifecycleFor(installID, resolution{outcome: outcomeSupported, row: &row}); err == nil {
		t.Fatal("a catalogue row with a non-uuid id was recorded as a citation")
	}
	// And an outcome that needs a row but has none is refused the same way,
	// rather than becoming a `supported` row with nothing behind it.
	if _, _, err := lifecycleFor(installID, resolution{outcome: outcomeSupported}); err == nil {
		t.Fatal("a supported outcome with no catalogue row was recorded")
	}
	dateless := nginxRow(nil)
	if _, _, err := lifecycleFor(installID, resolution{outcome: outcomeSupported, row: &dateless}); err == nil {
		t.Fatal("a supported outcome with no date was recorded")
	}
}

// Only software subjects have a record. An asset's OS and hardware answers are
// legible from the asset-keyed facts and findings already; recording them here
// would be a second place for the same fact.
func TestEOLLifecycle_OnlyInstallsAreRecorded(t *testing.T) {
	store := &catalogstest.Store{Rows: []catalogs.EOLRow{ubuntuRow(at(800))}}
	p := testProducer(t, store)

	subjects := []assetSubject{{
		id: uuid.New(), label: "web-01", osName: "Ubuntu", osVer: "18.04",
	}}
	var run Run
	_, assessed, lifecycle, _, err := p.resolve(context.Background(), subjects, &run)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(assessed) != 1 {
		t.Errorf("%d assets assessed, want 1 — the OS was resolved", len(assessed))
	}
	if len(lifecycle) != 0 {
		t.Errorf("%d lifecycle rows for an asset with no installs, want 0", len(lifecycle))
	}
}
