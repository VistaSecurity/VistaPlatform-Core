package producers

// The `eol` producer end to end, against a real Postgres under RLS.
//
// The unit tests cover the decision — which catalogue row answers a subject and
// what rung the date lands on. What only a database can show is the LIFECYCLE:
// that a finding created by one pass is resolved by the next when the answer
// changes, and that the pass after THAT reuses the same row rather than
// starting a second history for the same condition.

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer/producertest"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// eolFixture is one tenant with an asset, its OS facts, and one software
// install — the smallest inventory the producer has anything to say about.
type eolFixture struct {
	owner  *sql.DB
	app    *sql.DB
	tenant uuid.UUID

	assetID   uuid.UUID
	installID uuid.UUID
	productID uuid.UUID

	// catalogueID is the eol_catalogue row the OS resolves to.
	catalogueID uuid.UUID
	// swCatalogueID is the row the software install resolves to.
	swCatalogueID uuid.UUID

	producer *EOLProducer
}

func newEOLFixture(t *testing.T) *eolFixture {
	t.Helper()
	owner := testdb.Connect(t)
	// No testdb.ApplySchema here: the runner applies scripts/database/schema.sql
	// once to the database, and re-applying it per fixture takes ACCESS
	// EXCLUSIVE locks across the whole schema while other package binaries of
	// the same `go test ./...` run are querying it. That is the documented
	// deadlock source and it made this package fail
	// intermittently with "could not complete operation in a failed
	// transaction". ApplySchema is for the re-apply/idempotency tests, which
	// these are not.
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)

	f := &eolFixture{owner: owner, app: app, tenant: tenant}

	f.assetID = uuid.New()
	exec(t, owner, `INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path, asset_status)
	                VALUES ($1, $2, $3, $4, 'server', 'hardware.computer.server', 'monitoring')`,
		f.assetID, tenant, "eol-host", "eol-host")

	// os.name / os.version, as a collector would write them.
	fact(t, owner, tenant, f.assetID, "os.name", `"Ubuntu"`)
	fact(t, owner, tenant, f.assetID, "os.version", `"18.04.6 LTS"`)

	f.productID = uuid.New()
	exec(t, owner, `INSERT INTO software_products (id, tenant_id, name, vendor, version)
	                VALUES ($1, $2, 'nginx', 'F5', '1.20.0')`, f.productID, tenant)
	f.installID = uuid.New()
	exec(t, owner, `INSERT INTO software_installs (id, tenant_id, asset_id, product_id, status)
	                VALUES ($1, $2, $3, $4, 'active')`, f.installID, tenant, f.assetID, f.productID)

	// The catalogue rows. Platform-scoped: no tenant_id, and every tenant reads
	// them — which is why they are cleaned up explicitly rather than by the
	// tenant CASCADE.
	f.catalogueID = catalogueRow(t, owner, "os", "Canonical", "Ubuntu", "18.04", daysFromNow(-30))
	f.swCatalogueID = catalogueRow(t, owner, "software", "F5", "nginx", "1.20", daysFromNow(-10))

	p, err := NewEOLProducer(app, owner)
	if err != nil {
		t.Fatalf("NewEOLProducer: %v", err)
	}
	f.producer = p
	return f
}

// run is one pass, taken under the schema share lock and retried past the
// cross-binary races the shared test database produces — see driftFixture.run
// for why both halves are needed, and
// TestIntegration_Producers_PassHelpersTakeTheSchemaShareLock for the proof
// that every helper here takes the lock.
//
// Used wherever a pass is EXPECTED to succeed. The cases that expect an error
// call Run directly, because a retry there would hide the thing under test.
func (f *eolFixture) run(t *testing.T, ctx context.Context) Run {
	t.Helper()
	var out Run
	testdb.WithSchemaShareLock(t, f.owner, func() {
		testdb.RetryTransient(t, func() error {
			var err error
			out, err = f.producer.Run(ctx, f.tenant)
			return err
		})
	})
	return out
}

func TestIntegration_EOLProducer_WriterContract(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)

	// The contract suite, run with THIS producer's key and kinds — so what it
	// proves is that eol findings obey the lifecycle, not that some example
	// producer's do.
	producertest.Run(t, producertest.Config{
		DB:          app,
		Owner:       owner,
		Producer:    findings.ProducerEOL,
		Kind:        findings.KindOSEndOfLife,
		OtherKind:   findings.KindHardwareEndOfSupport,
		SubjectType: findings.SubjectAsset,
	})
}

func TestIntegration_EOLProducer_RaisesResolvesAndReturns(t *testing.T) {
	f := newEOLFixture(t)
	ctx := context.Background()

	// --- pass 1: the OS is 30 days past its end of life.
	run := f.run(t, ctx)
	if run.Raised != 2 {
		t.Fatalf("run 1 raised %d findings, want 2 (the OS and the install)", run.Raised)
	}

	osFinding := f.finding(t, findings.KindOSEndOfLife, findings.SubjectAsset, f.assetID)
	if osFinding == nil {
		t.Fatal("no os_end_of_life finding for the asset")
	}
	if osFinding.state != producer.StateActive {
		t.Errorf("detection_state = %q, want ACTIVE", osFinding.state)
	}
	k, _ := findings.Get(findings.ProducerEOL, findings.KindOSEndOfLife)
	if osFinding.severity != k.Rungs[rungPast].Severity || osFinding.score != k.Rungs[rungPast].Score {
		t.Errorf("severity/score = %s/%d, want the registry's 'past end of life' rung",
			osFinding.severity, osFinding.score)
	}
	// The citation, which is what makes the claim checkable.
	if got := osFinding.evidence["catalogue_id"]; got != f.catalogueID.String() {
		t.Errorf("evidence.catalogue_id = %v, want %s", got, f.catalogueID)
	}
	if got, _ := osFinding.evidence["catalogue_source_url"].(string); got == "" {
		t.Error("the finding carries no source URL")
	}

	// The software finding is on the INSTALL, not the asset: one open row per
	// subject means an asset-subject software finding would collapse every
	// end-of-life package on the host into one.
	swFinding := f.finding(t, findings.KindSoftwareEndOfLife, findings.SubjectSoftwareInstall, f.installID)
	if swFinding == nil {
		t.Fatal("no software_end_of_life finding on the install")
	}
	if got := swFinding.evidence["asset_id"]; got != f.assetID.String() {
		t.Errorf("the software finding does not name its asset: %v", got)
	}

	// And the fact went with it, from the same catalogue row.
	if ref := f.factSourceRef(t, "eol.os.date"); ref != "catalog:eol:"+f.catalogueID.String() {
		t.Errorf("eol.os.date source_ref = %q, want catalog:eol:%s — the fact and the finding must cite the same row",
			ref, f.catalogueID)
	}

	// --- a converged re-run changes nothing but the counters.
	run2 := f.run(t, ctx)
	if run2.Resolved != 0 {
		t.Errorf("a converged re-run resolved %d findings; nothing changed", run2.Resolved)
	}
	again := f.finding(t, findings.KindOSEndOfLife, findings.SubjectAsset, f.assetID)
	if again.id != osFinding.id {
		t.Fatalf("the second pass wrote a NEW row (%s, was %s)", again.id, osFinding.id)
	}
	if again.occurrence != 2 {
		t.Errorf("occurrence_count = %d after two passes, want 2", again.occurrence)
	}

	// --- the catalogue changes: the vendor extended support into the future.
	exec(t, f.owner, `UPDATE eol_catalogue SET eol_date = $1 WHERE id = $2`, daysFromNow(900), f.catalogueID)
	run3 := f.run(t, ctx)
	if run3.Resolved < 1 {
		t.Errorf("run 3 resolved %d findings; the OS is no longer end of life", run3.Resolved)
	}
	resolved := f.finding(t, findings.KindOSEndOfLife, findings.SubjectAsset, f.assetID)
	if resolved.state != producer.StateInactive {
		t.Fatalf("detection_state = %q after the catalogue date moved, want INACTIVE", resolved.state)
	}
	if resolved.id != osFinding.id {
		t.Error("the resolved finding is a different row; a condition that went away keeps its row")
	}

	// --- and back: the extension was a data-entry error, corrected.
	exec(t, f.owner, `UPDATE eol_catalogue SET eol_date = $1 WHERE id = $2`, daysFromNow(-30), f.catalogueID)
	f.run(t, ctx)
	back := f.finding(t, findings.KindOSEndOfLife, findings.SubjectAsset, f.assetID)
	if back.id != osFinding.id {
		t.Fatalf("the returning condition got a NEW row %s instead of reusing %s — first_seen and occurrence_count would each describe one episode",
			back.id, osFinding.id)
	}
	if back.state != producer.StateActive {
		t.Errorf("detection_state = %q after the condition returned, want ACTIVE", back.state)
	}
	if !back.resurfaced {
		t.Error("resurfaced_at is NULL on a finding that came back")
	}
}

func TestIntegration_EOLProducer_RemovingTheInstallResolvesItsFinding(t *testing.T) {
	f := newEOLFixture(t)
	ctx := context.Background()

	f.run(t, ctx)
	before := f.finding(t, findings.KindSoftwareEndOfLife, findings.SubjectSoftwareInstall, f.installID)
	if before == nil || before.state != producer.StateActive {
		t.Fatal("no active software_end_of_life finding to start from")
	}

	// The package was uninstalled. The install row stays — the history is worth
	// keeping — and its status says it is gone.
	exec(t, f.owner, `UPDATE software_installs SET status = 'removed' WHERE id = $1`, f.installID)

	run := f.run(t, ctx)
	if run.Resolved != 1 {
		t.Errorf("run 2 resolved %d findings, want 1", run.Resolved)
	}
	after := f.finding(t, findings.KindSoftwareEndOfLife, findings.SubjectSoftwareInstall, f.installID)
	if after.state != producer.StateInactive {
		t.Errorf("detection_state = %q after the install was removed, want INACTIVE", after.state)
	}
	// The OS finding is untouched: a sweep is scoped to its own kind.
	os := f.finding(t, findings.KindOSEndOfLife, findings.SubjectAsset, f.assetID)
	if os.state != producer.StateActive {
		t.Errorf("the OS finding is %q; removing a package must not touch it", os.state)
	}
}

func TestIntegration_EOLProducer_UnknownProductLandsOnTheGapList(t *testing.T) {
	f := newEOLFixture(t)

	// An OS the catalogue has never heard of.
	exec(t, f.owner, `UPDATE asset_facts SET value = '"Frobnicator OS"' WHERE tenant_id = $1 AND key = 'os.name'`, f.tenant)

	run, err := f.producer.Run(context.Background(), f.tenant)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if run.Misses < 1 {
		t.Fatalf("run.Misses = %d; an unanswerable lookup has to be counted so the enrichment pass can work on it", run.Misses)
	}

	var n int
	if err := f.owner.QueryRow(
		`SELECT count(*) FROM catalog_lookup_misses WHERE lower(product) = 'frobnicator os'`).Scan(&n); err != nil {
		t.Fatalf("read gap list: %v", err)
	}
	if n != 1 {
		t.Errorf("%d gap rows for the unknown OS, want 1", n)
	}
	t.Cleanup(func() {
		_, _ = f.owner.Exec(`DELETE FROM catalog_lookup_misses WHERE lower(product) = 'frobnicator os'`)
	})
}

// The reachability check. A finding on a software INSTALL is still "on" the
// asset everywhere the product asks that question — `findings.AssetSubjects`
// walks software_installs.asset_id, and the query language's `finding:(…)`
// compiles through it. Without this the software findings would exist and be
// invisible from the inventory.
func TestIntegration_EOLProducer_FindingsAreReachableFromTheAsset(t *testing.T) {
	f := newEOLFixture(t)
	if _, err := f.producer.Run(context.Background(), f.tenant); err != nil {
		t.Fatalf("run: %v", err)
	}

	clause := findings.AssetSubjectClause("fnd", "a", aliasCounter(), func(s string) string {
		return "'" + s + "'"
	})
	q := `SELECT count(DISTINCT a.id) FROM assets a WHERE a.tenant_id = $1
	      AND EXISTS (SELECT 1 FROM findings fnd
	                  WHERE fnd.tenant_id = a.tenant_id
	                    AND fnd.producer = 'eol' AND fnd.kind = $2
	                    AND ` + findings.OpenSQL("fnd") + ` AND (` + clause + `))`

	for _, kind := range []string{findings.KindOSEndOfLife, findings.KindSoftwareEndOfLife} {
		var n int
		// Through the retry helper: this statement touches seven tables, and a
		// concurrent schema apply in another package's binary deadlocks against
		// it (see testdb.RetryTransient). The assertion below is the test; the
		// deadlock is the harness.
		testdb.RetryTransient(t, func() error {
			return f.owner.QueryRow(q, f.tenant, kind).Scan(&n)
		})
		if n != 1 {
			t.Errorf("%d assets reachable from an open %s finding, want 1 — the inventory's finding:(…) predicate cannot see it",
				n, kind)
		}
	}
}

// --- fixture helpers --------------------------------------------------------

type storedFinding struct {
	id         uuid.UUID
	state      string
	severity   string
	score      int
	occurrence int
	resurfaced bool
	summary    string
	evidence   map[string]any
}

func (f *eolFixture) finding(t *testing.T, kind, subjectType string, subjectID uuid.UUID) *storedFinding {
	t.Helper()
	var out storedFinding
	var raw []byte
	var resurfaced sql.NullTime
	var err error
	testdb.RetryTransient(t, func() error {
		err = f.owner.QueryRow(`
			SELECT id, detection_state, severity, score, occurrence_count, resurfaced_at, summary, evidence
			FROM findings
			WHERE tenant_id = $1 AND producer = 'eol' AND kind = $2
			  AND subject_type = $3 AND subject_id = $4`,
			f.tenant, kind, subjectType, subjectID).
			Scan(&out.id, &out.state, &out.severity, &out.score, &out.occurrence, &resurfaced, &out.summary, &raw)
		if err == sql.ErrNoRows {
			// Not an error: the caller reads "no such finding" as an answer.
			return nil
		}
		return err
	})
	if err == sql.ErrNoRows {
		return nil
	}
	out.resurfaced = resurfaced.Valid
	out.evidence = map[string]any{}
	if err := json.Unmarshal(raw, &out.evidence); err != nil {
		t.Fatalf("finding evidence is not an object: %v", err)
	}
	return &out
}

func (f *eolFixture) factSourceRef(t *testing.T, key string) string {
	t.Helper()
	var ref string
	err := f.owner.QueryRow(
		`SELECT source_ref FROM asset_facts WHERE tenant_id = $1 AND asset_id = $2 AND key = $3`,
		f.tenant, f.assetID, key).Scan(&ref)
	if err == sql.ErrNoRows {
		return ""
	}
	if err != nil {
		t.Fatalf("read fact %s: %v", key, err)
	}
	return ref
}

func exec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	testdb.RetryTransient(t, func() error {
		_, err := db.Exec(q, args...)
		return err
	})
}

func fact(t *testing.T, db *sql.DB, tenant, asset uuid.UUID, key, jsonValue string) {
	t.Helper()
	exec(t, db, `INSERT INTO asset_facts (tenant_id, asset_id, key, value, source_kind, source_ref)
	             VALUES ($1, $2, $3, $4::jsonb, 'measured', 'integration')`,
		tenant, asset, key, jsonValue)
}

// catalogueRow inserts a platform eol_catalogue row and registers its cleanup.
// The catalogue carries no tenant_id, so the tenant CASCADE does not reach it
// and a row left behind would answer a later test's lookup.
func catalogueRow(t *testing.T, db *sql.DB, kind, vendor, product, cycle string, eol time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	exec(t, db, `INSERT INTO eol_catalogue (id, product_kind, vendor, product, cycle, eol_date, source_url)
	             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, kind, vendor, product, cycle, eol, "https://endoflife.date/"+product)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM eol_catalogue WHERE id = $1`, id) })
	return id
}

func daysFromNow(days int) time.Time {
	return time.Now().UTC().AddDate(0, 0, days)
}

// aliasCounter mints the unique table aliases findings.AssetSubjects needs.
//
// strconv.Itoa, not `string(rune('0'+n))`. The latter is only a digit for n≤9,
// and past that it walks straight into ':', ';', '<' — so the tenth alias made
// the generated SQL a syntax error. It held for exactly as long as
// AssetSubjects had nine aliases or fewer; adding the `key` path took it to
// thirteen, and every test using this helper failed at once with
// `syntax error at or near ":"`, in a clause none of them wrote.
func aliasCounter() func(string) string {
	n := 0
	return func(prefix string) string {
		n++
		return "it_" + prefix + strconv.Itoa(n)
	}
}
