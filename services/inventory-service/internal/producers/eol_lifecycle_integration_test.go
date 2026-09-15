package producers

// The per-install lifecycle record against a real Postgres under RLS.
//
// The unit tests cover which word each outcome becomes. What only a database
// can show is the LIFECYCLE of the record: that every install the pass assessed
// gets a row, that a converged re-run moves the timestamp and nothing else,
// that a changed catalogue changes the word, that a removed install loses its
// row — and, most of all, that a pass whose write phase fails records NOTHING,
// because a `supported` row that outlived a rolled-back pass is exactly the
// unearned credit the record exists to prevent.

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/software"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// lifecycleRecord is one software_install_lifecycle row as the tests read it.
type lifecycleRecord struct {
	assessment  string
	catalogueID *uuid.UUID
	eolDate     *time.Time
	assessedAt  time.Time
}

// lifecycle reads every record for the fixture tenant, keyed by install.
func (f *eolFixture) lifecycle(t *testing.T) map[uuid.UUID]lifecycleRecord {
	t.Helper()
	out := map[uuid.UUID]lifecycleRecord{}
	testdb.RetryTransient(t, func() error {
		clear(out)
		rows, err := f.owner.Query(`
			SELECT install_id, assessment, catalogue_id, eol_date, assessed_at
			  FROM software_install_lifecycle WHERE tenant_id = $1`, f.tenant)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id uuid.UUID
			var r lifecycleRecord
			var cid uuid.NullUUID
			var date sql.NullTime
			if err := rows.Scan(&id, &r.assessment, &cid, &date, &r.assessedAt); err != nil {
				return err
			}
			if cid.Valid {
				c := cid.UUID
				r.catalogueID = &c
			}
			if date.Valid {
				d := date.Time
				r.eolDate = &d
			}
			out[id] = r
		}
		return rows.Err()
	})
	return out
}

// install adds one product and one install of it to the fixture asset.
func (f *eolFixture) install(t *testing.T, name, vendor, version, status string) uuid.UUID {
	t.Helper()
	product := uuid.New()
	exec(t, f.owner, `INSERT INTO software_products (id, tenant_id, name, vendor, version)
	                  VALUES ($1, $2, $3, NULLIF($4, ''), $5)`, product, f.tenant, name, vendor, version)
	id := uuid.New()
	exec(t, f.owner, `INSERT INTO software_installs (id, tenant_id, asset_id, product_id, status)
	                  VALUES ($1, $2, $3, $4, $5)`, id, f.tenant, f.assetID, product, status)
	return id
}

// catalogueRowNoDate is a catalogue entry that publishes no date — what the
// mirror writes for endoflife.date's "support ended, date unknown" and "not
// announced" alike.
func catalogueRowNoDate(t *testing.T, db *sql.DB, kind, vendor, product, cycle string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	exec(t, db, `INSERT INTO eol_catalogue (id, product_kind, vendor, product, cycle, eol_date, source_url)
	             VALUES ($1, $2, $3, $4, $5, NULL, $6)`,
		id, kind, vendor, product, cycle, "https://endoflife.date/"+product)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM eol_catalogue WHERE id = $1`, id) })
	return id
}

func sameDay(a, b time.Time) bool {
	return a.UTC().Format("2006-01-02") == b.UTC().Format("2006-01-02")
}

func TestIntegration_EOLProducer_RecordsWhatEachInstallResolvedTo(t *testing.T) {
	f := newEOLFixture(t)
	ctx := context.Background()

	// The fixture's nginx is 10 days past its date. Four more installs, one
	// per answer the catalogue can give, plus one the producer must skip.
	supportedUntil := daysFromNow(900)
	supported := f.install(t, "postgresql", "PostgreSQL", "16.2", "active")
	supportedCat := catalogueRow(t, f.owner, "software", "PostgreSQL", "postgresql", "16", supportedUntil)
	noDate := f.install(t, "libfoo", "", "2.1.0", "active")
	noDateCat := catalogueRowNoDate(t, f.owner, "software", "", "libfoo", "2.1")
	unknown := f.install(t, "acme-internal-tool", "Acme", "1.0.0", "active")
	removed := f.install(t, "oldtool", "", "0.9", "removed")
	t.Cleanup(func() {
		_, _ = f.owner.Exec(`DELETE FROM catalog_lookup_misses WHERE lower(product) = 'acme-internal-tool'`)
	})

	run, err := f.producer.Run(ctx, f.tenant)
	if err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if run.Lifecycle != 4 {
		t.Errorf("run.Lifecycle = %d, want 4 — one record per ACTIVE install, none for the removed one", run.Lifecycle)
	}

	recs := f.lifecycle(t)
	if len(recs) != 4 {
		t.Fatalf("%d lifecycle records, want 4: %+v", len(recs), recs)
	}
	if _, ok := recs[removed]; ok {
		t.Error("the removed install has a record; the producer skipped it, so it must have none")
	}

	// nginx: end_of_life, citing the same row as its finding.
	nginx := recs[f.installID]
	if nginx.assessment != software.LifecycleEndOfLife {
		t.Errorf("nginx = %q, want end_of_life", nginx.assessment)
	}
	if nginx.catalogueID == nil || *nginx.catalogueID != f.swCatalogueID {
		t.Errorf("nginx cites %v, want the catalogue row %s the finding cites", nginx.catalogueID, f.swCatalogueID)
	}
	if fnd := f.finding(t, findings.KindSoftwareEndOfLife, findings.SubjectSoftwareInstall, f.installID); fnd == nil {
		t.Error("nginx has an end_of_life record and no finding; the two must land together")
	}

	// postgresql: supported, with the catalogue's date — the answer that used
	// to get no credit.
	pg := recs[supported]
	if pg.assessment != software.LifecycleSupported {
		t.Errorf("postgresql = %q, want supported", pg.assessment)
	}
	if pg.catalogueID == nil || *pg.catalogueID != supportedCat {
		t.Errorf("postgresql cites %v, want %s", pg.catalogueID, supportedCat)
	}
	if pg.eolDate == nil || !sameDay(*pg.eolDate, supportedUntil) {
		t.Errorf("postgresql eol_date = %v, want the catalogue's %s", pg.eolDate, supportedUntil.Format("2006-01-02"))
	}
	if fnd := f.finding(t, findings.KindSoftwareEndOfLife, findings.SubjectSoftwareInstall, supported); fnd != nil {
		t.Error("a supported install has a finding")
	}

	// libfoo: in the catalogue, no date.
	lf := recs[noDate]
	if lf.assessment != software.LifecycleNoDate {
		t.Errorf("libfoo = %q, want no_date", lf.assessment)
	}
	if lf.catalogueID == nil || *lf.catalogueID != noDateCat {
		t.Errorf("libfoo cites %v, want %s — a no_date record still says WHICH row has no date", lf.catalogueID, noDateCat)
	}
	if lf.eolDate != nil {
		t.Errorf("libfoo carries a date %v; the catalogue published none", lf.eolDate)
	}

	// acme-internal-tool: not in the catalogue, citing nothing.
	ac := recs[unknown]
	if ac.assessment != software.LifecycleNotInCatalogue {
		t.Errorf("acme-internal-tool = %q, want not_in_catalogue", ac.assessment)
	}
	if ac.catalogueID != nil || ac.eolDate != nil {
		t.Errorf("a miss cites %v / %v; it has nothing to cite", ac.catalogueID, ac.eolDate)
	}

	// --- a converged re-run moves only the timestamp.
	run2, err := f.producer.Run(ctx, f.tenant)
	if err != nil {
		t.Fatalf("run 2: %v", err)
	}
	if run2.LifecycleSwept != 0 {
		t.Errorf("a converged re-run swept %d records; nothing changed", run2.LifecycleSwept)
	}
	again := f.lifecycle(t)
	for id, before := range recs {
		after, ok := again[id]
		if !ok {
			t.Errorf("install %s lost its record on a converged re-run", id)
			continue
		}
		if after.assessment != before.assessment {
			t.Errorf("install %s moved from %q to %q with nothing changed", id, before.assessment, after.assessment)
		}
		if !after.assessedAt.After(before.assessedAt) {
			t.Errorf("install %s: assessed_at did not move (%v → %v); a producer broken for a month would look like one that ran an hour ago",
				id, before.assessedAt, after.assessedAt)
		}
	}

	// --- the catalogue changes: postgresql's support was cut short.
	exec(t, f.owner, `UPDATE eol_catalogue SET eol_date = $1 WHERE id = $2`, daysFromNow(-5), supportedCat)
	if _, err := f.producer.Run(ctx, f.tenant); err != nil {
		t.Fatalf("run 3: %v", err)
	}
	moved := f.lifecycle(t)[supported]
	if moved.assessment != software.LifecycleEndOfLife {
		t.Errorf("postgresql = %q after its date passed, want end_of_life", moved.assessment)
	}
	if fnd := f.finding(t, findings.KindSoftwareEndOfLife, findings.SubjectSoftwareInstall, supported); fnd == nil {
		t.Error("postgresql's record says end_of_life and there is no finding")
	}

	// --- the install is removed: its record is swept in the same pass.
	exec(t, f.owner, `UPDATE software_installs SET status = 'removed' WHERE id = $1`, supported)
	run4, err := f.producer.Run(ctx, f.tenant)
	if err != nil {
		t.Fatalf("run 4: %v", err)
	}
	if run4.LifecycleSwept != 1 {
		t.Errorf("run 4 swept %d records, want 1", run4.LifecycleSwept)
	}
	if _, ok := f.lifecycle(t)[supported]; ok {
		t.Error("a removed install kept its lifecycle record; 'no row' must keep meaning 'not assessed since last active'")
	}
}

// A pass whose WRITE phase fails must record nothing — the record is inside
// the pass's transaction, not beside it.
//
// The write phase is failed AFTER the lifecycle rows are written, by a trigger
// that refuses the findings sweep's UPDATE; a cancelled context would not
// prove anything, because it kills the read phase and the write never runs.
// Mutation-proven: move the UpsertLifecycle call out of RunInTx onto its own
// transaction and the first assertion goes red with 1 record surviving.
func TestIntegration_EOLProducer_AFailedWritePhaseRecordsNoLifecycle(t *testing.T) {
	f := newEOLFixture(t)
	ctx := context.Background()

	// A stale finding of a kind this pass will not re-assert, so the sweep
	// has a row to inactivate and therefore an UPDATE for the trigger to
	// refuse.
	exec(t, f.owner, `
		INSERT INTO findings (id, tenant_id, producer, kind, subject_type, subject_id,
		                      severity, score, summary, detection_state, workflow_status)
		VALUES ($1, $2, 'eol', 'hardware_end_of_support', 'asset', $3,
		        'medium', 50, 'stale, to be swept', 'ACTIVE', 'NEW')`,
		uuid.New(), f.tenant, f.assetID)

	trigger := "lc_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:12]
	dropTrigger := func() {
		_, _ = f.owner.Exec(`DROP TRIGGER IF EXISTS ` + trigger + ` ON findings`)
		_, _ = f.owner.Exec(`DROP FUNCTION IF EXISTS ` + trigger + `()`)
	}
	t.Cleanup(dropTrigger)

	// DDL on findings inside the shared schema lock, for the reason the crypto
	// producer's twin of this test gives: another package's schema apply
	// GRANTing over the table fails with "tuple concurrently updated".
	testdb.WithSchemaShareLock(t, f.owner, func() {
		exec(t, f.owner, `
			CREATE OR REPLACE FUNCTION `+trigger+`() RETURNS trigger AS $$
			BEGIN RAISE EXCEPTION 'sweep refused by the test'; END $$ LANGUAGE plpgsql`)
		exec(t, f.owner, `
			CREATE TRIGGER `+trigger+` BEFORE UPDATE ON findings
			FOR EACH ROW WHEN (NEW.detection_state = 'INACTIVE' AND NEW.tenant_id = '`+f.tenant.String()+`')
			EXECUTE FUNCTION `+trigger+`()`)

		if _, err := f.producer.Run(ctx, f.tenant); err == nil {
			t.Error("a pass whose write phase failed reported success")
		}
		dropTrigger()
	})
	if t.Failed() {
		t.FailNow()
	}

	if n := len(f.lifecycle(t)); n != 0 {
		t.Fatalf("a write phase that failed AFTER the lifecycle rows were written left %d of them, want 0 — "+
			"the record is not inside the pass's transaction, so an install reads 'supported' from a pass that never completed", n)
	}

	// The polarity: with the trigger gone the same pass completes and records
	// what it just refused to. Without this a producer that never wrote the
	// record would satisfy the assertion above.
	if _, err := f.producer.Run(ctx, f.tenant); err != nil {
		t.Fatalf("the pass failed with the trigger gone: %v", err)
	}
	recs := f.lifecycle(t)
	if len(recs) != 1 {
		t.Fatalf("a completed pass recorded %d installs, want 1", len(recs))
	}
	if recs[f.installID].assessment != software.LifecycleEndOfLife {
		t.Errorf("nginx = %q, want end_of_life", recs[f.installID].assessment)
	}
}

// The record is written on the RLS-subject handle and must be isolated by
// tenant like everything else the producer writes: a tenant reads its own
// rows, never another's, and nothing with no tenant context.
func TestIntegration_EOLProducer_LifecycleRecordIsTenantIsolated(t *testing.T) {
	f := newEOLFixture(t)
	if _, err := f.producer.Run(context.Background(), f.tenant); err != nil {
		t.Fatalf("run: %v", err)
	}
	other := testdb.NewTenant(t, f.owner)

	testdb.AsTenant(t, f.app, f.tenant, func(tx *sql.Tx) {
		var own int
		if err := tx.QueryRow(`SELECT count(*) FROM software_install_lifecycle WHERE tenant_id = $1`, f.tenant).Scan(&own); err != nil {
			t.Fatal(err)
		}
		if own != 1 {
			t.Errorf("the tenant sees %d of its own records, want 1", own)
		}
	})
	testdb.AsTenant(t, f.app, other, func(tx *sql.Tx) {
		var leaked int
		if err := tx.QueryRow(`SELECT count(*) FROM software_install_lifecycle WHERE tenant_id = $1`, f.tenant).Scan(&leaked); err != nil {
			t.Fatal(err)
		}
		if leaked != 0 {
			t.Errorf("another tenant sees %d of this tenant's records", leaked)
		}
	})
	testdb.AsRoleNoTenant(t, f.app, func(tx *sql.Tx) {
		var n int
		if err := tx.QueryRow(`SELECT count(*) FROM software_install_lifecycle`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%d records visible with no tenant context; the policy is not failing closed", n)
		}
	})
}

// The database refuses a record whose shape contradicts its word, so a bug in
// a future writer cannot store a `supported` row with no date or a miss that
// cites a row. Asserted here because the read side trusts the shape.
func TestIntegration_EOLProducer_LifecycleShapeIsEnforcedByTheSchema(t *testing.T) {
	f := newEOLFixture(t)
	cat := uuid.New()
	for _, bad := range []struct {
		name       string
		assessment string
		catalogue  any
		date       any
	}{
		{"supported without a date", software.LifecycleSupported, cat, nil},
		{"supported without a citation", software.LifecycleSupported, nil, "2028-04-01"},
		{"end_of_life without a date", software.LifecycleEndOfLife, cat, nil},
		{"no_date with a date", software.LifecycleNoDate, cat, "2028-04-01"},
		{"no_date without a citation", software.LifecycleNoDate, nil, nil},
		{"not_in_catalogue citing a row", software.LifecycleNotInCatalogue, cat, nil},
		{"a word that is not in the vocabulary", "probably_fine", cat, "2028-04-01"},
	} {
		_, err := f.owner.Exec(`
			INSERT INTO software_install_lifecycle (tenant_id, install_id, assessment, catalogue_id, eol_date)
			VALUES ($1, $2, $3, $4, $5::date)`, f.tenant, f.installID, bad.assessment, bad.catalogue, bad.date)
		if err == nil {
			t.Errorf("%s was accepted by the schema", bad.name)
			_, _ = f.owner.Exec(`DELETE FROM software_install_lifecycle WHERE tenant_id = $1`, f.tenant)
		}
	}
}
