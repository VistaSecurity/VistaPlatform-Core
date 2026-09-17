package jobs

// The certificate compliance band scan, against a real Postgres.
//
// The bug this closes: `cert_expiration_days` is the platform's only purely
// time-dependent compliance measurement — it decreases every day with no
// inventory change — while materialization is event-driven by design. A
// certificate that crosses the 90-day threshold (cert-expiry-90-day / CE-90-001)
// with nothing else about it changing raises no event, is never re-evaluated, and
// keeps whatever verdict the last reconcile computed. `tenant_framework_scores`
// keeps reporting that verdict to the posture page indefinitely.
//
// These tests move a certificate's not_after across the line WITHOUT touching
// anything that raises an event — which is precisely the situation the clock
// creates — and assert the materialized rollup follows.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	sharedevents "github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// bandFixture is one tenant holding one asset that serves one leaf certificate,
// with the seeded cert-expiry frameworks and the job under test.
//
// Wired as cmd/main.go wires it: the tenant-scoped handle is the non-owner
// `crypto_app` role (RLS enforced, as in production) and the cross-tenant handle
// stands in for the BYPASSRLS pool. An owner-only test would prove nothing about
// the RLS-scoped reads the sweep depends on.
type bandFixture struct {
	owner    *sql.DB
	app      *sqlx.DB
	tenant   uuid.UUID
	asset    uuid.UUID
	cert     uuid.UUID
	findings *services.FindingsService
	job      *CertComplianceBandScanJob
}

func newBandFixture(t *testing.T, daysRemaining int) *bandFixture {
	t.Helper()
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	appRaw := testdb.ConnectAsAppRole(t, owner)
	app := sqlx.NewDb(appRaw, "postgres")
	bypass := sqlx.NewDb(owner, "postgres")
	tenant := testdb.NewTenant(t, owner)

	asset := uuid.New()
	if _, err := owner.Exec(`
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path)
		VALUES ($1, $2, 'cert-band.example.test', 'server', 'hardware.computer.server')`,
		asset, tenant); err != nil {
		t.Fatalf("seed asset: %v", err)
	}

	cert := uuid.New()
	fingerprint := strings.ReplaceAll(cert.String(), "-", "")
	if _, err := owner.Exec(fmt.Sprintf(`
		INSERT INTO certificates (id, tenant_id, subject_dn, issuer_dn, common_name,
			fingerprint_sha256, public_key_algorithm, public_key_size,
			signature_algorithm, not_before, not_after, is_ca_certificate)
		VALUES ($1, $2, 'CN=cert-band.example.test', 'CN=Fixture CA', 'cert-band.example.test',
			$3, 'RSA', 2048, 'SHA256withRSA',
			now() - interval '30 days', now() + interval '%d days', false)`,
		daysRemaining), cert, tenant, fingerprint+fingerprint); err != nil {
		t.Fatalf("seed certificate: %v", err)
	}

	// The binding an ordinary TLS discovery writes: the asset's configuration
	// names the leaf it presented.
	if _, err := owner.Exec(`
		INSERT INTO crypto_implementations_partitioned (tenant_id, asset_id, protocol, discovery_method, certificate_id)
		VALUES ($1, $2, 'TLS', 'passive', $3)`, tenant, asset, cert); err != nil {
		t.Fatalf("seed crypto implementation: %v", err)
	}

	extractor := services.NewMeasurementExtractor(app)
	evaluator := services.NewRuleEvaluator(app, extractor)
	findings := services.NewFindingsService(app, bypass, evaluator, nil,
		services.NewEvaluationService(app, evaluator), nil)

	return &bandFixture{
		owner: owner, app: app, tenant: tenant, asset: asset, cert: cert,
		findings: findings,
		job:      NewCertComplianceBandScanJob(app, bypass, findings, 0),
	}
}

// onAssetChanged drives the REAL event handler, establishing the materialized
// verdict the same way an ordinary discovery does.
func (f *bandFixture) onAssetChanged(t *testing.T) {
	t.Helper()
	testdb.RetryTransient(t, func() error {
		return f.findings.OnAssetChanged(context.Background(), sharedevents.AssetChangedEvent{
			EventID:    uuid.New(),
			EventType:  sharedevents.EventTypeAssetChanged,
			TenantID:   f.tenant,
			AssetID:    f.asset,
			ChangeType: sharedevents.ChangeTypeUpdated,
			Source:     "cert-band-regression-test",
		})
	})
}

// moveNotAfter rewrites the certificate's expiry directly, raising NO event —
// the whole point. This is what the passage of time does to the measurement:
// nothing in inventory changes, and nothing tells compliance to look again.
func (f *bandFixture) moveNotAfter(t *testing.T, daysRemaining int) {
	t.Helper()
	if _, err := f.owner.Exec(fmt.Sprintf(
		`UPDATE certificates SET not_after = now() + interval '%d days' WHERE id = $1`,
		daysRemaining), f.cert); err != nil {
		t.Fatalf("move not_after: %v", err)
	}
}

type bandRollup struct {
	Score       *float64 `db:"score"`
	Total       int      `db:"controls_total"`
	Passing     int      `db:"controls_passing"`
	Failing     int      `db:"controls_failing"`
	NotAssessed int      `db:"controls_not_assessed"`
}

// rollupFor reads the materialized rollup — the number the posture page and the
// framework card show. Read on the owner handle so the assertion itself is never
// the thing RLS hides.
func (f *bandFixture) rollupFor(t *testing.T, frameworkCode string) bandRollup {
	t.Helper()
	var out bandRollup
	if err := sqlx.NewDb(f.owner, "postgres").Get(&out, `
		SELECT s.score, s.controls_total, s.controls_passing, s.controls_failing, s.controls_not_assessed
		FROM tenant_framework_scores s
		JOIN platform_frameworks fw ON fw.id = s.platform_framework_id
		WHERE s.tenant_id = $1 AND fw.code = $2`, f.tenant, frameworkCode); err != nil {
		t.Fatalf("no tenant_framework_scores row for %s: %v", frameworkCode, err)
	}
	return out
}

func wantBandRollup(t *testing.T, got bandRollup, code string, wantPassing, wantFailing int, why string) {
	t.Helper()
	if got.Passing != wantPassing || got.Failing != wantFailing {
		score := "nil"
		if got.Score != nil {
			score = fmt.Sprint(*got.Score)
		}
		t.Errorf("%s rollup: score=%s total=%d passing=%d failing=%d not_assessed=%d; want passing=%d failing=%d — %s",
			code, score, got.Total, got.Passing, got.Failing, got.NotAssessed,
			wantPassing, wantFailing, why)
	}
}

// TestIntegration_CertBandScan_CrossingNinetyDaysFlipsTheRollup is the regression.
//
// A certificate with 120 days of validity legitimately passes "at least 90 days
// remaining". Time then takes it to 56 days — no discovery, no upsert, no event.
// Before this job, the stored finding and the rollup kept the 120-day verdict for
// as long as nothing else about the certificate changed, and the posture page
// reported a clean 100 for a certificate two months from expiry.
func TestIntegration_CertBandScan_CrossingNinetyDaysFlipsTheRollup(t *testing.T) {
	f := newBandFixture(t, 120)

	// 1. The honest starting verdict, established by the real event handler.
	f.onAssetChanged(t)
	wantBandRollup(t, f.rollupFor(t, "cert-expiry-90-day"), "cert-expiry-90-day", 1, 0,
		"a certificate with 120 days left genuinely satisfies >= 90")

	// 2. The clock moves it across the line. Nothing raises an event.
	f.moveNotAfter(t, 56)

	// 3. The staleness itself, asserted rather than assumed: with no sweep, the
	//    materialized verdict does not move. If this ever stops holding, some
	//    other path is re-evaluating certificates and this job's premise needs
	//    re-checking — so it is a real assertion, not scaffolding.
	wantBandRollup(t, f.rollupFor(t, "cert-expiry-90-day"), "cert-expiry-90-day", 1, 0,
		"nothing re-evaluates a certificate on the clock alone — this IS the bug")

	// 4. The sweep — the real job entry point, not a helper.
	f.job.ScanAll()

	wantBandRollup(t, f.rollupFor(t, "cert-expiry-90-day"), "cert-expiry-90-day", 0, 1,
		"56 days remaining violates >= 90; the band scan must re-materialize it")
}

// TestIntegration_CertBandScan_RungsStaySeparate pins that the sweep re-evaluates
// each threshold on its own terms rather than collapsing them: at 56 days the
// 90-day rung fails while the 30-day rung and not-expired still pass.
func TestIntegration_CertBandScan_RungsStaySeparate(t *testing.T) {
	f := newBandFixture(t, 120)
	f.onAssetChanged(t)
	f.moveNotAfter(t, 56)
	f.job.ScanAll()

	wantBandRollup(t, f.rollupFor(t, "cert-expiry-90-day"), "cert-expiry-90-day", 0, 1,
		"56 < 90")
	wantBandRollup(t, f.rollupFor(t, "cert-expiry-30-day"), "cert-expiry-30-day", 1, 0,
		"56 >= 30 — the 30-day rung must NOT fail")
	wantBandRollup(t, f.rollupFor(t, "cert-expiry-not-expired"), "cert-expiry-not-expired", 1, 0,
		"56 > 0 — the certificate is not expired")
}

// TestIntegration_CertBandScan_OutOfBandCertificateIsLeftAlone pins the other
// polarity: a certificate comfortably outside the widest threshold has no verdict
// that the clock can have moved, so the sweep must not touch it. A window that
// swept everything would pass this suite's other tests while doing per-tenant work
// proportional to the whole certificate inventory every interval.
func TestIntegration_CertBandScan_OutOfBandCertificateIsLeftAlone(t *testing.T) {
	f := newBandFixture(t, 300)
	f.onAssetChanged(t)
	wantBandRollup(t, f.rollupFor(t, "cert-expiry-90-day"), "cert-expiry-90-day", 1, 0,
		"300 days left satisfies every rung")

	band, err := f.job.bandDays(context.Background())
	if err != nil {
		t.Fatalf("bandDays: %v", err)
	}
	n, err := f.job.scanTenant(context.Background(), f.tenant, band)
	if err != nil {
		t.Fatalf("scanTenant: %v", err)
	}
	if n != 0 {
		t.Errorf("scanTenant reconciled %d certificate(s) at 300 days remaining with a %d-day band; want 0 — the window is not bounded", n, band)
	}

	f.job.ScanAll()
	wantBandRollup(t, f.rollupFor(t, "cert-expiry-90-day"), "cert-expiry-90-day", 1, 0,
		"an out-of-band certificate's verdict must be unchanged")
}

// TestIntegration_CertBandScan_BandComesFromTheCatalogue is the guard against
// hardcoding the window.
//
// Two halves, because a window can be wrong in two directions:
//
//   - the seeded rungs (> 0, >= 30, >= 90) must produce 90, read through the real
//     query rather than a constant; and
//   - `pf.status = 'published'` must be load-bearing — a 180-day threshold on an
//     UNPUBLISHED framework must NOT widen it, because evaluateSubjects folds only
//     published frameworks and a window wider than the thing being re-evaluated is
//     per-tenant work every interval for nothing.
//
// Deliberately NOT done by authoring a published 180-day control: that would add a
// control to a framework other test binaries assert exact rollup counts against
// (services/.../cert_expiry_rungs_integration_test.go reads cert-expiry-90-day's
// controls_total), and `go test ./...` runs those binaries concurrently against the
// same database. That is the seed-row-pollution class, and it reads as a flake
// in somebody else's package. The "a wider window actually reaches further"
// direction is covered below by handing scanTenant a wider band directly, and the
// max-selection itself is unit-tested in widestBandDays without a database.
func TestIntegration_CertBandScan_BandComesFromTheCatalogue(t *testing.T) {
	f := newBandFixture(t, 120)
	ctx := context.Background()

	band, err := f.job.bandDays(ctx)
	if err != nil {
		t.Fatalf("bandDays: %v", err)
	}
	if band != 90 {
		t.Fatalf("band from the seeded rungs (> 0, >= 30, >= 90) = %d, want 90", band)
	}

	// A 180-day threshold on a DRAFT framework. Inert: nothing folds it, so it
	// cannot perturb any other test, and it must not widen the window either.
	f.authorDraftThreshold(t, 180)

	band, err = f.job.bandDays(ctx)
	if err != nil {
		t.Fatalf("bandDays after the draft framework: %v", err)
	}
	if band != 90 {
		t.Errorf("a 180-day threshold on an UNPUBLISHED framework widened the band to %d; want 90 — the query must be scoped to published frameworks, which is the only set evaluateSubjects folds", band)
	}

	// The other direction: a genuinely PUBLISHED 180-day threshold must widen the
	// window to 180. Read inside an uncommitted transaction (see
	// bandInUncommittedTx) so the framework never becomes visible to another test
	// binary — a published framework IS folded by evaluateSubjects, and
	// `go test ./...` runs these binaries concurrently against one database.
	if got := f.bandInUncommittedTx(t, 180); got != 180 {
		t.Errorf("with a published 180-day threshold the band = %d, want 180 — the window is not derived from the catalogue (a hardcoded 90 reads exactly like this)", got)
	}

	// And the window is honoured end to end: at 120 days the certificate is
	// outside a 90-day window and inside a 180-day one, so a window clamped to any
	// constant cannot produce both of these answers.
	f.onAssetChanged(t)
	if n := f.mustScanTenant(t, 90); n != 0 {
		t.Errorf("a 90-day band reconciled %d certificate(s) at 120 days remaining; want 0", n)
	}
	if n := f.mustScanTenant(t, 180); n != 1 {
		t.Errorf("a 180-day band reconciled %d certificate(s) at 120 days remaining; want 1 — the window is not honoured", n)
	}
}

// bandInUncommittedTx authors a PUBLISHED framework carrying a cert_expiration_days
// threshold of `days`, reads the band back through the real query, and rolls the
// whole thing back.
//
// The isolation trick: a dedicated *sql.DB capped at ONE open connection, so the
// manual BEGIN, the inserts and bandDays' own SELECT all land on the same backend
// session and share the transaction. The rows are therefore visible to the query
// under test and to nothing else, ever — no other test binary can observe a
// published framework that never commits. Capping the pool is what makes this work;
// with the default pool, bandDays could be served by a second connection outside the
// transaction and would not see the fixture at all (the test would then fail rather
// than pass silently, which is the right way round).
//
// Authoring a published framework the ordinary way would be the seed-pollution
// hazard: services/.../cert_expiry_rungs_integration_test.go asserts exact rollup
// counts for the seeded cert-expiry frameworks, and a transient extra published
// control perturbs concurrent runs of it.
func (f *bandFixture) bandInUncommittedTx(t *testing.T, days int) int {
	t.Helper()
	raw := testdb.Connect(t)
	raw.SetMaxOpenConns(1)
	pinned := sqlx.NewDb(raw, "postgres")
	job := NewCertComplianceBandScanJob(pinned, pinned, f.findings, 0)

	if _, err := pinned.Exec("BEGIN"); err != nil {
		t.Fatalf("begin: %v", err)
	}
	rolledBack := false
	rollback := func() {
		if !rolledBack {
			rolledBack = true
			if _, err := pinned.Exec("ROLLBACK"); err != nil {
				t.Errorf("rollback: %v", err)
			}
		}
	}
	// Cleanup as well as the explicit call below: a t.Fatalf inside skips the rest
	// of the function, and this fixture must never be left committed.
	t.Cleanup(rollback)

	var measurementID uuid.UUID
	if err := pinned.QueryRow(
		`SELECT id FROM measurement_types WHERE code = 'cert_expiration_days'`).Scan(&measurementID); err != nil {
		t.Fatalf("cert_expiration_days measurement type missing — the assertion would be vacuous: %v", err)
	}

	var fwID, ctlID uuid.UUID
	if err := pinned.QueryRow(`
		INSERT INTO platform_frameworks (id, code, name, version, description, organization, status, published_at, created_by)
		SELECT gen_random_uuid(), $1, 'Band scan published fixture', '1.0',
		       'Rolled back; never committed.', 'Vista Platform', 'published', now(), pu.id
		FROM platform_users pu ORDER BY pu.created_at LIMIT 1
		RETURNING id`, "cert-band-published-"+uuid.NewString()).Scan(&fwID); err != nil {
		t.Fatalf("author published framework: %v", err)
	}
	if err := pinned.QueryRow(`
		INSERT INTO platform_framework_controls (id, framework_id, control_id, title, description, baseline_severity, crypto_relevant)
		VALUES (gen_random_uuid(), $1, 'CB-PUB-001', 'Published threshold', 'Fixture.', 'low', true)
		RETURNING id`, fwID).Scan(&ctlID); err != nil {
		t.Fatalf("author published control: %v", err)
	}
	if _, err := pinned.Exec(`
		INSERT INTO control_measurements (id, control_id, framework_type, measurement_type_id, rule_type, predicate, weight)
		VALUES (gen_random_uuid(), $1, 'platform', $2, 'threshold',
		        jsonb_build_object('operator', '>=', 'value', $3::int), 4)`,
		ctlID, measurementID, days); err != nil {
		t.Fatalf("author published measurement: %v", err)
	}

	band, err := job.bandDays(context.Background())
	if err != nil {
		t.Fatalf("bandDays inside the transaction: %v", err)
	}
	rollback()

	// The fixture must be gone for every other reader. Checked on the ORIGINAL
	// handle, not the pinned one, so this cannot be answered by the same session.
	var leaked int
	if err := f.owner.QueryRow(
		`SELECT COUNT(*) FROM platform_frameworks WHERE id = $1`, fwID).Scan(&leaked); err != nil {
		t.Fatalf("leak check: %v", err)
	}
	if leaked != 0 {
		t.Fatalf("the published fixture framework %s COMMITTED — it is visible to every concurrent test binary", fwID)
	}
	return band
}

// authorDraftThreshold adds a cert_expiration_days threshold to a framework this
// test owns and leaves UNPUBLISHED, cleaning it up afterwards. Its code is unique
// per test run so two concurrent runs cannot collide on it, and no seeded row is
// touched.
func (f *bandFixture) authorDraftThreshold(t *testing.T, days int) {
	t.Helper()
	code := "cert-band-draft-" + uuid.NewString()

	var fwID uuid.UUID
	if err := f.owner.QueryRow(`
		INSERT INTO platform_frameworks (id, code, name, version, description, organization, status, created_by)
		SELECT gen_random_uuid(), $1, 'Band scan draft fixture', '1.0',
		       'Unpublished fixture for the band-derivation test.', 'Vista Platform', 'draft', pu.id
		FROM platform_users pu ORDER BY pu.created_at LIMIT 1
		RETURNING id`, code).Scan(&fwID); err != nil {
		t.Fatalf("author draft framework: %v", err)
	}
	t.Cleanup(func() {
		_, _ = f.owner.Exec(`DELETE FROM platform_frameworks WHERE id = $1`, fwID)
	})

	var ctlID uuid.UUID
	if err := f.owner.QueryRow(`
		INSERT INTO platform_framework_controls (id, framework_id, control_id, title, description, baseline_severity, crypto_relevant)
		VALUES (gen_random_uuid(), $1, 'CB-DRAFT-001', 'Draft threshold', 'Fixture.', 'low', true)
		RETURNING id`, fwID).Scan(&ctlID); err != nil {
		t.Fatalf("author draft control: %v", err)
	}
	res, err := f.owner.Exec(`
		INSERT INTO control_measurements (id, control_id, framework_type, measurement_type_id, rule_type, predicate, weight)
		SELECT gen_random_uuid(), $1, 'platform', mt.id, 'threshold',
		       jsonb_build_object('operator', '>=', 'value', $2::int), 4
		FROM measurement_types mt WHERE mt.code = 'cert_expiration_days'`, ctlID, days)
	if err != nil {
		t.Fatalf("author draft measurement: %v", err)
	}
	// An INSERT ... SELECT whose subquery finds nothing succeeds with zero rows,
	// and the assertion above would then pass vacuously — "the draft did not widen
	// the band" is trivially true when no draft rule exists.
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("draft measurement inserted %d rows, want 1 — the cert_expiration_days measurement type is missing, so this test would pass vacuously", n)
	}
}

// mustScanTenant runs the sweep's per-tenant leg with an explicit band and returns
// how many certificates it reconciled.
func (f *bandFixture) mustScanTenant(t *testing.T, band int) int {
	t.Helper()
	n, err := f.job.scanTenant(context.Background(), f.tenant, band)
	if err != nil {
		t.Fatalf("scanTenant(band=%d): %v", band, err)
	}
	return n
}

// TestIntegration_CertBandScan_LeavesOtherSubjectsAlone pins the hazard M5 of
// exposed: a bounded pass must never retire findings about a subject it did
// not evaluate. The sweep hands certificate ids to evaluateSubjects, whose
// stale-finding sweep is scoped to `subject_id = ANY(subjects)`; if that scoping
// were ever widened, a band scan would silently erase the posture of every asset
// in the tenant.
func TestIntegration_CertBandScan_LeavesOtherSubjectsAlone(t *testing.T) {
	f := newBandFixture(t, 120)
	ctx := context.Background()

	// A second asset with weak crypto, carrying findings of its own and NO
	// certificate — so it is never a subject of the band scan.
	other := uuid.New()
	if _, err := f.owner.Exec(`
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path)
		VALUES ($1, $2, 'other.example.test', 'server', 'hardware.computer.server')`,
		other, f.tenant); err != nil {
		t.Fatalf("seed other asset: %v", err)
	}
	if _, err := f.owner.Exec(`
		INSERT INTO crypto_implementations_partitioned
			(tenant_id, asset_id, protocol, protocol_version, cipher_suite, key_size, discovery_method)
		VALUES ($1, $2, 'TLS', 'TLS 1.0', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 1024, 'passive')`,
		f.tenant, other); err != nil {
		t.Fatalf("seed other implementation: %v", err)
	}
	testdb.RetryTransient(t, func() error {
		_, err := f.findings.EvaluateAsset(ctx, f.tenant, other)
		return err
	})

	before := f.activeFindingCount(t, other)
	if before == 0 {
		t.Fatalf("fixture produced no findings for the unrelated asset — the test cannot detect erasure")
	}

	f.moveNotAfter(t, 56)
	f.job.ScanAll()

	if after := f.activeFindingCount(t, other); after != before {
		t.Errorf("the band scan changed the active-finding count of an unrelated asset %s: %d -> %d; a bounded pass must not retire findings about subjects it did not evaluate",
			other, before, after)
	}
}

func (f *bandFixture) activeFindingCount(t *testing.T, subject uuid.UUID) int {
	t.Helper()
	var n int
	if err := f.owner.QueryRow(
		`SELECT COUNT(*) FROM findings WHERE tenant_id = $1 AND subject_id = $2 AND detection_state = 'ACTIVE'`,
		f.tenant, subject).Scan(&n); err != nil {
		t.Fatalf("count active findings: %v", err)
	}
	return n
}

// Tenant discovery must use the same margin as the per-tenant selector. A
// tenant whose only certificate is just outside the threshold still needs a scan.
func TestIntegration_CertBandScan_TenantEnumerationIncludesBoundaryMargin(t *testing.T) {
	f := newBandFixture(t, 91)
	if _, err := f.owner.Exec(`UPDATE certificates SET not_after = now() + interval '90.5 days' WHERE id = $1`, f.cert); err != nil {
		t.Fatal(err)
	}
	ids, err := f.job.tenantsWithInBandCerts(context.Background(), 90)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if id == f.tenant {
			return
		}
	}
	t.Fatal("tenant with a certificate in the boundary margin was omitted")
}
