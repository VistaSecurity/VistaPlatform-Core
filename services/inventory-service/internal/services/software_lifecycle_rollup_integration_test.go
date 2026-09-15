package services

// The end-of-life column reading the `eol` producer's per-install record,
// against a real Postgres.
//
// Before the record existed the column was two-valued in practice: an open
// finding, or "not assessed" for everything else. These tests are the READ
// side of the record — the rows are written straight into the table, because
// what is under test is the SQL that turns a recorded word into a state, on
// both surfaces (the per-asset LATERAL list and the catalogue aggregate), and
// the one corner where the record and the finding disagree.
//
// There is deliberately no cross-tenant case here. The record's composite
// foreign key makes "tenant B's row naming tenant A's install" unwritable, so
// a test of that shape could not fail and would prove nothing; tenant
// isolation of the record is RLS, pinned by
// TestIntegration_EOLProducer_LifecycleRecordIsTenantIsolated and the
// shared/database RLS guard over every tenant-scoped table.
//
// Skips without TEST_DATABASE_URL (`make test-integration-db`).

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	sharedfindings "github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/software"
)

// writeLifecycle records one install's answer directly, shaped as the
// producer would write it. `date` is YYYY-MM-DD or "" for none.
func writeLifecycle(t *testing.T, svc *SBOMIngestService, tenant, install uuid.UUID, assessment string, catalogue *uuid.UUID, date string) {
	t.Helper()
	var cid any
	if catalogue != nil {
		cid = *catalogue
	}
	var d any
	if date != "" {
		d = date
	}
	if _, err := svc.db.Exec(`
		INSERT INTO software_install_lifecycle (tenant_id, install_id, assessment, catalogue_id, eol_date, assessed_at)
		VALUES ($1, $2, $3, $4, $5::date, now())
		ON CONFLICT (tenant_id, install_id) DO UPDATE
		   SET assessment = EXCLUDED.assessment, catalogue_id = EXCLUDED.catalogue_id,
		       eol_date = EXCLUDED.eol_date, assessed_at = EXCLUDED.assessed_at`,
		tenant, install, assessment, cid, d); err != nil {
		t.Fatalf("write lifecycle %s for %s: %v", assessment, install, err)
	}
}

func productByName(t *testing.T, rows []SoftwareProductRow, name string) SoftwareProductRow {
	t.Helper()
	for _, r := range rows {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no product named %q in %d rows", name, len(rows))
	return SoftwareProductRow{}
}

func TestIntegration_SoftwareRollup_ReadsTheProducersLifecycleRecord(t *testing.T) {
	svc, _, tenant := newSBOMFixture(t)
	asset := hostAsset(t, svc.assets, tenant, "lifecycle.example.test")
	ingest(t, svc, tenant, asset, cycloneDX(t, "",
		comp("openssl", map[string]any{"version": "1.1.1", "purl": "pkg:generic/openssl@1.1.1"}),
		comp("zlib", map[string]any{"version": "1.3.1", "purl": "pkg:generic/zlib@1.3.1"}),
		comp("libfoo", map[string]any{"version": "2.1.0", "purl": "pkg:generic/libfoo@2.1.0"}),
		comp("in-house-shim", map[string]any{"version": "0.1.0"}),
		comp("fresh", map[string]any{"version": "9.9.9", "purl": "pkg:generic/fresh@9.9.9"}),
	))
	rows, _, err := svc.ListAssetSoftware(context.Background(), tenant, asset, "", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	openssl := installByName(t, rows, "openssl")
	zlib := installByName(t, rows, "zlib")
	libfoo := installByName(t, rows, "libfoo")
	shim := installByName(t, rows, "in-house-shim")

	// Before anything is recorded every install is `not_assessed` — the
	// honest state for "no completed pass has looked", with no date and no
	// timestamp to explain.
	for _, r := range rows {
		if r.EOLState != SoftwareEOLNotAssessed || r.EOLDate != nil || r.EOLAssessedAt != nil {
			t.Errorf("%s before any record: state=%q date=%v assessed_at=%v, want not_assessed/nil/nil",
				r.Name, r.EOLState, r.EOLDate, r.EOLAssessedAt)
		}
	}

	// The producer's four words, one per install; `fresh` gets no record.
	cat1, cat2, cat3 := uuid.New(), uuid.New(), uuid.New()
	writeLifecycle(t, svc, tenant, openssl.InstallID, software.LifecycleEndOfLife, &cat1, "2023-09-11")
	writeFinding(t, svc, tenant, sharedfindings.ProducerEOL, sharedfindings.KindSoftwareEndOfLife,
		openssl.InstallID, "medium", 50, `{"eol_date":"2023-09-11","days_remaining":-731,"catalogue_id":"`+cat1.String()+`"}`)
	writeLifecycle(t, svc, tenant, zlib.InstallID, software.LifecycleSupported, &cat2, "2028-04-01")
	writeLifecycle(t, svc, tenant, libfoo.InstallID, software.LifecycleNoDate, &cat3, "")
	writeLifecycle(t, svc, tenant, shim.InstallID, software.LifecycleNotInCatalogue, nil, "")

	rows, _, err = svc.ListAssetSoftware(context.Background(), tenant, asset, "", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 5 {
		t.Fatalf("%d rows, want 5 — the lifecycle join multiplied an install", len(rows))
	}
	openssl = installByName(t, rows, "openssl")
	zlib = installByName(t, rows, "zlib")
	libfoo = installByName(t, rows, "libfoo")
	shim = installByName(t, rows, "in-house-shim")
	fresh := installByName(t, rows, "fresh")

	if openssl.EOLState != SoftwareEOLEndOfLife || openssl.EOLDate == nil || *openssl.EOLDate != "2023-09-11" {
		t.Errorf("openssl = %q / %v, want end_of_life / 2023-09-11 (the finding's date)", openssl.EOLState, openssl.EOLDate)
	}
	// The one that used to get no credit.
	if zlib.EOLState != SoftwareEOLSupported {
		t.Errorf("zlib = %q, want %q — a recorded supported answer is earned and must be shown", zlib.EOLState, SoftwareEOLSupported)
	}
	if zlib.EOLDate == nil || *zlib.EOLDate != "2028-04-01" {
		t.Errorf("zlib eol_date = %v, want 2028-04-01 from the record", zlib.EOLDate)
	}
	if zlib.EOLAssessedAt == nil || time.Since(*zlib.EOLAssessedAt) > time.Hour {
		t.Errorf("zlib eol_assessed_at = %v, want the record's timestamp", zlib.EOLAssessedAt)
	}
	if zlib.EOLFindingID != nil || zlib.EOLSeverity != nil {
		t.Error("a supported install carries a finding id or severity; there is no finding")
	}
	if libfoo.EOLState != SoftwareEOLNoDate || libfoo.EOLDate != nil {
		t.Errorf("libfoo = %q / %v, want no_date with no date", libfoo.EOLState, libfoo.EOLDate)
	}
	if shim.EOLState != SoftwareEOLNotInCatalogue || shim.EOLDate != nil {
		t.Errorf("in-house-shim = %q / %v, want not_in_catalogue with no date", shim.EOLState, shim.EOLDate)
	}
	if fresh.EOLState != SoftwareEOLNotAssessed || fresh.EOLAssessedAt != nil {
		t.Errorf("fresh (no record) = %q / %v, want not_assessed with no timestamp", fresh.EOLState, fresh.EOLAssessedAt)
	}

	// The catalogue aggregate answers the same way for each product.
	products, _, err := svc.ListProducts(context.Background(), tenant, "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct{ name, state string }{
		{"openssl", SoftwareEOLEndOfLife},
		{"zlib", SoftwareEOLSupported},
		{"libfoo", SoftwareEOLNoDate},
		{"in-house-shim", SoftwareEOLNotInCatalogue},
		{"fresh", SoftwareEOLNotAssessed},
	} {
		if got := productByName(t, products, want.name); got.EOLState != want.state {
			t.Errorf("catalogue row %s = %q, want %q", want.name, got.EOLState, want.state)
		}
	}
	pz := productByName(t, products, "zlib")
	if pz.EOLDate == nil || *pz.EOLDate != "2028-04-01" || pz.EOLAssessedAt == nil {
		t.Errorf("catalogue row zlib: date=%v assessed_at=%v, want 2028-04-01 and a timestamp", pz.EOLDate, pz.EOLAssessedAt)
	}
	if po := productByName(t, products, "openssl"); po.EOLInstallCount != 1 || po.EOLDate == nil || *po.EOLDate != "2023-09-11" {
		t.Errorf("catalogue row openssl: eol_install_count=%d date=%v", po.EOLInstallCount, po.EOLDate)
	}
}

// The corner where the record and the finding disagree: the record says
// `end_of_life`, and a person has since closed the finding.
//
// Neither neighbour is right. "Supported" would credit a package whose date
// has passed; "end of life" would report a finding somebody closed, which is
// what `ClosedFindingsDoNotShow` pins for the vulnerability column. So it
// reads as the honest third thing, with no date it would then have to
// explain. Pinned so a later "simplification" that maps the recorded word
// straight onto the state cannot quietly turn a suppressed finding into a
// green cell.
func TestIntegration_SoftwareRollup_AClosedFindingDoesNotBecomeSupported(t *testing.T) {
	svc, _, tenant := newSBOMFixture(t)
	asset := hostAsset(t, svc.assets, tenant, "closed-eol.example.test")
	ingest(t, svc, tenant, asset, cycloneDX(t, "",
		comp("libold", map[string]any{"version": "1.0.0", "purl": "pkg:generic/libold@1.0.0"}),
	))
	rows, _, err := svc.ListAssetSoftware(context.Background(), tenant, asset, "", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	install := rows[0].InstallID
	cat := uuid.New()
	writeLifecycle(t, svc, tenant, install, software.LifecycleEndOfLife, &cat, "2023-09-11")
	id := writeFinding(t, svc, tenant, sharedfindings.ProducerEOL, sharedfindings.KindSoftwareEndOfLife,
		install, "medium", 50, `{"eol_date":"2023-09-11","days_remaining":-731}`)

	rows, _, _ = svc.ListAssetSoftware(context.Background(), tenant, asset, "", "", "", 50, 0)
	if rows[0].EOLState != SoftwareEOLEndOfLife {
		t.Fatalf("state = %q before closing, want end_of_life — the rest of this test proves nothing otherwise", rows[0].EOLState)
	}

	for _, closed := range []struct{ col, val string }{
		{"workflow_status", "RESOLVED"},
		{"workflow_status", "SUPPRESSED"},
		{"detection_state", "INACTIVE"},
	} {
		if _, err := svc.db.Exec(`UPDATE findings SET workflow_status = 'NEW', detection_state = 'ACTIVE' WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.db.Exec(`UPDATE findings SET `+closed.col+` = $1 WHERE id = $2`, closed.val, id); err != nil {
			t.Fatal(err)
		}
		rows, _, err = svc.ListAssetSoftware(context.Background(), tenant, asset, "", "", "", 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		r := rows[0]
		if r.EOLState == SoftwareEOLSupported {
			t.Errorf("%s=%s reads SUPPORTED; a closed finding does not make a past date future", closed.col, closed.val)
		}
		if r.EOLState == SoftwareEOLEndOfLife {
			t.Errorf("%s=%s still reads end_of_life; the column would report a problem somebody closed", closed.col, closed.val)
		}
		if r.EOLState != SoftwareEOLNotAssessed {
			t.Errorf("%s=%s reads %q, want %q", closed.col, closed.val, r.EOLState, SoftwareEOLNotAssessed)
		}
		if r.EOLDate != nil {
			t.Errorf("%s=%s carries a date %v beside not_assessed", closed.col, closed.val, *r.EOLDate)
		}

		products, _, perr := svc.ListProducts(context.Background(), tenant, "", "", 50, 0)
		if perr != nil {
			t.Fatal(perr)
		}
		if p := productByName(t, products, "libold"); p.EOLState != SoftwareEOLNotAssessed || p.EOLInstallCount != 0 {
			t.Errorf("catalogue row with %s=%s reads %q on %d installs, want not_assessed on 0",
				closed.col, closed.val, p.EOLState, p.EOLInstallCount)
		}
	}
}

// A product's installs resolve identically, so a mixed set only arises across
// pass boundaries — an install added since the last pass has no record yet.
// The catalogue row then takes the most informative recorded answer, and an
// open finding on ANY install outranks it.
func TestIntegration_SoftwareRollup_ProductTakesTheMostInformativeRecordedAnswer(t *testing.T) {
	svc, _, tenant := newSBOMFixture(t)
	a1 := hostAsset(t, svc.assets, tenant, "mixed-1.example.test")
	a2 := hostAsset(t, svc.assets, tenant, "mixed-2.example.test")
	doc := cycloneDX(t, "", comp("libmix", map[string]any{"version": "3.0.0", "purl": "pkg:generic/libmix@3.0.0"}))
	ingest(t, svc, tenant, a1, doc)
	ingest(t, svc, tenant, a2, doc)
	i1, _, err := svc.ListAssetSoftware(context.Background(), tenant, a1, "", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	i2, _, err := svc.ListAssetSoftware(context.Background(), tenant, a2, "", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}

	// One install recorded supported, the other not yet assessed.
	cat := uuid.New()
	writeLifecycle(t, svc, tenant, i1[0].InstallID, software.LifecycleSupported, &cat, "2028-04-01")
	products, _, err := svc.ListProducts(context.Background(), tenant, "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if p := productByName(t, products, "libmix"); p.EOLState != SoftwareEOLSupported || p.EOLDate == nil || *p.EOLDate != "2028-04-01" {
		t.Errorf("supported + unassessed = %q / %v, want supported / 2028-04-01", p.EOLState, p.EOLDate)
	}

	// Each STEP of the recorded ladder, not just its top. Every other case in
	// this file gives a product one recorded word, so the order of the three
	// non-finding branches is invisible to them: inverting the ladder to
	// least-informative-first leaves them all green while the Software lens
	// reports "Not in catalogue" for a product an install of which the
	// catalogue answered. These two pairs are what makes the order fail if it
	// moves.
	for _, step := range []struct {
		name              string
		first, second     string
		firstCat, secCat  *uuid.UUID
		firstDate, secDte string
		want              string
	}{
		// supported beats a recorded miss: the catalogue answered for one of
		// them, and that answer is the product's.
		{"supported + not_in_catalogue", software.LifecycleSupported, software.LifecycleNotInCatalogue,
			&cat, nil, "2028-04-01", "", SoftwareEOLSupported},
		// and a dateless entry beats a miss: "we have this version, the vendor
		// published no date" is a different problem from "never heard of it",
		// and only the first is answerable by the vendor.
		{"no_date + not_in_catalogue", software.LifecycleNoDate, software.LifecycleNotInCatalogue,
			&cat, nil, "", "", SoftwareEOLNoDate},
	} {
		writeLifecycle(t, svc, tenant, i1[0].InstallID, step.first, step.firstCat, step.firstDate)
		writeLifecycle(t, svc, tenant, i2[0].InstallID, step.second, step.secCat, step.secDte)
		mixed, _, merr := svc.ListProducts(context.Background(), tenant, "", "", 50, 0)
		if merr != nil {
			t.Fatal(merr)
		}
		if p := productByName(t, mixed, "libmix"); p.EOLState != step.want {
			t.Errorf("%s = %q, want %q — the catalogue row takes the most informative recorded answer",
				step.name, p.EOLState, step.want)
		}
	}

	// Back to the state the rest of this test continues from.
	writeLifecycle(t, svc, tenant, i1[0].InstallID, software.LifecycleSupported, &cat, "2028-04-01")
	if _, err := svc.db.Exec(`DELETE FROM software_install_lifecycle WHERE tenant_id = $1 AND install_id = $2`,
		tenant, i2[0].InstallID); err != nil {
		t.Fatal(err)
	}

	// Now the other install's pass lands with an open finding: worst wins,
	// and the date shown is the finding's, not the supported install's.
	writeLifecycle(t, svc, tenant, i2[0].InstallID, software.LifecycleEndOfLife, &cat, "2026-01-01")
	writeFinding(t, svc, tenant, sharedfindings.ProducerEOL, sharedfindings.KindSoftwareEndOfLife,
		i2[0].InstallID, "medium", 50, `{"eol_date":"2026-01-01","days_remaining":-254}`)
	products, _, err = svc.ListProducts(context.Background(), tenant, "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	p := productByName(t, products, "libmix")
	if p.EOLState != SoftwareEOLEndOfLife || p.EOLInstallCount != 1 {
		t.Errorf("supported + end_of_life = %q on %d installs, want end_of_life on 1", p.EOLState, p.EOLInstallCount)
	}
	if p.EOLDate == nil || *p.EOLDate != "2026-01-01" {
		t.Errorf("eol_date = %v, want the finding's 2026-01-01, not the supported install's", p.EOLDate)
	}

	// A REMOVED install's record must not count: the aggregate is over
	// active installs, and the producer sweeps the record anyway.
	if _, err := svc.db.Exec(`UPDATE software_installs SET status = 'removed' WHERE id = $1`, i2[0].InstallID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.db.Exec(`UPDATE findings SET detection_state = 'INACTIVE' WHERE subject_id = $1`, i2[0].InstallID); err != nil {
		t.Fatal(err)
	}
	products, _, err = svc.ListProducts(context.Background(), tenant, "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if p := productByName(t, products, "libmix"); p.EOLState != SoftwareEOLSupported {
		t.Errorf("after removing the end-of-life install the row reads %q, want supported from the remaining active one", p.EOLState)
	}
}
