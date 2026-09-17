package services

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	sharedevents "github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// certExpiryFixture is one tenant holding one asset that serves one leaf
// certificate, with the seeded cert-expiry frameworks.
type certExpiryFixture struct {
	db       *sqlx.DB
	tenant   uuid.UUID
	asset    uuid.UUID
	cert     uuid.UUID
	findings *FindingsService
}

// newCertExpiryFixture reproduces the shape the bug was found in: an ordinary
// discovered host with one TLS configuration pointing at one leaf certificate.
// daysRemaining places the certificate's not_after relative to now.
func newCertExpiryFixture(t *testing.T, daysRemaining int) *certExpiryFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	asset := uuid.New()
	if _, err := raw.Exec(`
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path)
		VALUES ($1, $2, 'cert-expiry.example.test', 'server', 'hardware.computer.server')`,
		asset, tenant); err != nil {
		t.Fatalf("seed asset: %v", err)
	}

	cert := uuid.New()
	fingerprint := strings.ReplaceAll(cert.String(), "-", "")
	if _, err := raw.Exec(fmt.Sprintf(`
		INSERT INTO certificates (id, tenant_id, subject_dn, issuer_dn, common_name,
			fingerprint_sha256, public_key_algorithm, public_key_size,
			signature_algorithm, not_before, not_after, is_ca_certificate)
		VALUES ($1, $2, 'CN=cert-expiry.example.test', 'CN=Fixture CA', 'cert-expiry.example.test',
			$3, 'RSA', 2048, 'SHA256withRSA',
			now() - interval '%d days', now() + interval '%d days', false)`,
		90-daysRemaining, daysRemaining), cert, tenant, fingerprint+fingerprint); err != nil {
		t.Fatalf("seed certificate: %v", err)
	}

	// The binding an ordinary TLS discovery writes: the asset's configuration
	// names the leaf it presented. This is the edge the per-asset reconcile has
	// to walk to reach the certificate at all.
	if _, err := raw.Exec(`
		INSERT INTO crypto_implementations_partitioned (tenant_id, asset_id, protocol, discovery_method, certificate_id)
		VALUES ($1, $2, 'TLS', 'passive', $3)`, tenant, asset, cert); err != nil {
		t.Fatalf("seed crypto implementation: %v", err)
	}

	extractor := NewMeasurementExtractor(db)
	evaluator := NewRuleEvaluator(db, extractor)
	return &certExpiryFixture{
		db: db, tenant: tenant, asset: asset, cert: cert,
		findings: NewFindingsService(db, db, evaluator, nil, NewEvaluationService(db, evaluator), nil),
	}
}

// onAssetChanged drives the REAL wiring: the handler `compliance.asset.changed`
// dispatches to. Deliberately not EvaluateAsset (let alone the rule evaluator)
// — the bug was never in the predicate, it was in which subjects the reconcile
// behind this event covers, so a test that skips the handler cannot see it.
func (f *certExpiryFixture) onAssetChanged(t *testing.T) {
	t.Helper()
	testdb.RetryTransient(t, func() error {
		return f.findings.OnAssetChanged(context.Background(), sharedevents.AssetChangedEvent{
			EventID:    uuid.New(),
			EventType:  sharedevents.EventTypeAssetChanged,
			TenantID:   f.tenant,
			AssetID:    f.asset,
			ChangeType: sharedevents.ChangeTypeUpdated,
			Source:     "cert-expiry-regression-test",
		})
	})
}

// certRollup reads the materialized rollup for one cert-expiry framework — the
// number the posture page and the framework card show, and the one the live
// report was taken from.
func (f *certExpiryFixture) certRollup(t *testing.T, frameworkCode string) rollup {
	t.Helper()
	var out rollup
	if err := f.db.Get(&out, `
		SELECT s.score, s.controls_total, s.controls_passing, s.controls_failing, s.controls_not_assessed
		FROM tenant_framework_scores s
		JOIN platform_frameworks fw ON fw.id = s.platform_framework_id
		WHERE s.tenant_id = $1 AND fw.code = $2`, f.tenant, frameworkCode); err != nil {
		t.Fatalf("no tenant_framework_scores row for %s: %v", frameworkCode, err)
	}
	return out
}

func wantRollup(t *testing.T, got rollup, frameworkCode string, wantPassing, wantFailing int, why string) {
	t.Helper()
	if got.Passing != wantPassing || got.Failing != wantFailing {
		score := "nil"
		if got.Score != nil {
			score = fmt.Sprint(*got.Score)
		}
		t.Errorf("%s rollup: score=%s total=%d passing=%d failing=%d not_assessed=%d; want passing=%d failing=%d — %s",
			frameworkCode, score, got.Total, got.Passing, got.Failing, got.NotAssessed, wantPassing, wantFailing, why)
	}
}

// TestIntegration_CertExpiry56Days_FailsThe90DayRung is the regression.
//
// One tenant, one non-CA certificate with 56 days of validity left, reconciled
// by the event an ordinary discovery raises. Before the fix this produced
// `cert-expiry-90-day: score=100, controls_total=1, controls_passing=1` — a
// clean bill of health for a certificate that plainly violates "at least 90 days
// of validity remaining".
//
// The cause was not the predicate. The per-asset reconcile folded every
// published framework's controls against the ASSET id, and the `certificate`
// measurement shape filters `c.id = $2`, so an asset id matched no certificate,
// every certificate control produced no measurement and therefore no finding —
// and the score rollup, which derives a control's verdict from the ABSENCE of an
// active finding, read that as PASS. The pass published a verdict about a
// subject it had never looked at.
//
// Both halves are asserted together on purpose: the 30-day rung must still PASS
// for the same certificate. A "fix" that made every certificate control fail
// would satisfy the 90-day half and be just as wrong.
func TestIntegration_CertExpiry56Days_FailsThe90DayRung(t *testing.T) {
	f := newCertExpiryFixture(t, 56)
	f.onAssetChanged(t)

	wantRollup(t, f.certRollup(t, "cert-expiry-90-day"), "cert-expiry-90-day", 0, 1,
		"56 days of remaining validity does not satisfy `cert_expiration_days >= 90`")
	wantRollup(t, f.certRollup(t, "cert-expiry-30-day"), "cert-expiry-30-day", 1, 0,
		"56 days DOES satisfy `cert_expiration_days >= 30`; the fix must not flip this rung")
	wantRollup(t, f.certRollup(t, "cert-expiry-not-expired"), "cert-expiry-not-expired", 1, 0,
		"the certificate has not expired")
}

// TestIntegration_CertExpiryRungs_DoNotCollapse walks the bands across all three
// rungs through the real reconcile, so the ladder cannot quietly degenerate into
// an expired-vs-not check again.
//
// Each case is its own tenant (newCertExpiryFixture calls testdb.NewTenant), so
// the rollups read are that certificate's alone.
func TestIntegration_CertExpiryRungs_DoNotCollapse(t *testing.T) {
	cases := []struct {
		name          string
		daysRemaining int
		// passing/failing per framework, in rung order.
		notExpiredPasses bool
		thirtyPasses     bool
		ninetyPasses     bool
	}{
		{"expired", -31, false, false, false},
		{"15 days", 15, true, false, false},
		{"56 days", 56, true, true, false},
		{"200 days", 200, true, true, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCertExpiryFixture(t, tc.daysRemaining)
			f.onAssetChanged(t)

			for _, rung := range []struct {
				code   string
				passes bool
			}{
				{"cert-expiry-not-expired", tc.notExpiredPasses},
				{"cert-expiry-30-day", tc.thirtyPasses},
				{"cert-expiry-90-day", tc.ninetyPasses},
			} {
				passing, failing := 0, 1
				if rung.passes {
					passing, failing = 1, 0
				}
				wantRollup(t, f.certRollup(t, rung.code), rung.code, passing, failing,
					fmt.Sprintf("a certificate with %d days of remaining validity", tc.daysRemaining))
			}
		})
	}
}

// TestIntegration_CertExpiry_CertificateChangeAgrees pins that the OTHER entry
// point into the same reconcile reaches the same verdict for the same
// certificate. The two paths cover the subject from opposite ends — the asset
// fans out to its certificates, the certificate fans out to its assets — and a
// tenant's posture must not depend on which event happened to fire.
func TestIntegration_CertExpiry_CertificateChangeAgrees(t *testing.T) {
	f := newCertExpiryFixture(t, 56)

	if err := f.findings.OnCertificateChanged(context.Background(), sharedevents.CertificateChangedEvent{
		EventID:       uuid.New(),
		EventType:     sharedevents.EventTypeCertificateChanged,
		TenantID:      f.tenant,
		CertificateID: f.cert,
		ChangeType:    sharedevents.ChangeTypeCreated,
		Source:        "cert-expiry-regression-test",
	}); err != nil {
		t.Fatalf("OnCertificateChanged: %v", err)
	}

	wantRollup(t, f.certRollup(t, "cert-expiry-90-day"), "cert-expiry-90-day", 0, 1,
		"the certificate-change path must reach the same verdict as the asset-change path")
	wantRollup(t, f.certRollup(t, "cert-expiry-30-day"), "cert-expiry-30-day", 1, 0,
		"the certificate-change path must reach the same verdict as the asset-change path")
}

// TestIntegration_PerAssetReconcile_LeavesOtherSubjectsAlone is the blast-radius
// guard on the fan-out.
//
// Reconciling one asset now covers SEVERAL subjects (the asset and each of its
// certificates), and the stale-finding load that decides what to retire had to
// widen from `subject_id = $2` to `subject_id = ANY($2)`. A predicate that widens
// is one edit away from a predicate that does not constrain at all — and a pass
// that loads every subject's active findings, then retires everything its own
// (bounded) violation set does not contain, silently erases the rest of the
// tenant's posture. Nothing else in this package fails when that scoping is
// removed, which is exactly why this exists.
//
// Two hosts, each serving an already-expired certificate, both reconciled. Then
// one host is reconciled again. The other host's findings must not move.
func TestIntegration_PerAssetReconcile_LeavesOtherSubjectsAlone(t *testing.T) {
	f := newCertExpiryFixture(t, -31)

	// A second host with its own expired certificate, in the same tenant.
	other := uuid.New()
	if _, err := f.db.Exec(`
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path)
		VALUES ($1, $2, 'other.example.test', 'server', 'hardware.computer.server')`,
		other, f.tenant); err != nil {
		t.Fatalf("seed other asset: %v", err)
	}
	otherCert := uuid.New()
	fingerprint := strings.ReplaceAll(otherCert.String(), "-", "")
	if _, err := f.db.Exec(`
		INSERT INTO certificates (id, tenant_id, subject_dn, issuer_dn, common_name,
			fingerprint_sha256, public_key_algorithm, public_key_size,
			signature_algorithm, not_before, not_after, is_ca_certificate)
		VALUES ($1, $2, 'CN=other.example.test', 'CN=Fixture CA', 'other.example.test',
			$3, 'RSA', 2048, 'SHA256withRSA', now() - interval '400 days', now() - interval '31 days', false)`,
		otherCert, f.tenant, fingerprint+fingerprint); err != nil {
		t.Fatalf("seed other certificate: %v", err)
	}
	if _, err := f.db.Exec(`
		INSERT INTO crypto_implementations_partitioned (tenant_id, asset_id, protocol, discovery_method, certificate_id)
		VALUES ($1, $2, 'TLS', 'passive', $3)`, f.tenant, other, otherCert); err != nil {
		t.Fatalf("seed other crypto implementation: %v", err)
	}

	// Materialize both hosts' findings.
	testdb.RetryTransient(t, func() error {
		_, err := f.findings.EvaluateTenantFrameworks(context.Background(), f.tenant)
		return err
	})
	activeFor := func(subject uuid.UUID) int {
		t.Helper()
		var n int
		if err := f.db.Get(&n, `
			SELECT count(*) FROM findings
			WHERE tenant_id = $1 AND subject_id = $2 AND detection_state = 'ACTIVE' AND producer = 'compliance'`,
			f.tenant, subject); err != nil {
			t.Fatalf("count active findings for %s: %v", subject, err)
		}
		return n
	}
	before := activeFor(otherCert)
	if before == 0 {
		t.Fatalf("fixture: the other host's expired certificate produced no active findings, so this test proves nothing")
	}

	// Reconcile ONLY the first host.
	f.onAssetChanged(t)

	if after := activeFor(otherCert); after != before {
		t.Errorf("reconciling asset %s changed the active-finding count of an unrelated certificate %s: %d -> %d; "+
			"a bounded per-subject pass must never retire a finding about a subject it did not evaluate",
			f.asset, otherCert, before, after)
	}
}

// TestIntegration_CertExpiry_SeededRungsAreThreeDistinctThresholds guards the
// other end of the ladder: the predicates seed.sql actually writes.
//
// The Go evaluator can be perfectly correct and the product still ship three
// frameworks that measure the same thing, if the seed gives them the same
// threshold. This reads the shipped rows rather than restating them.
func TestIntegration_CertExpiry_SeededRungsAreThreeDistinctThresholds(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")

	type seededRung struct {
		Framework string `db:"code"`
		Control   string `db:"control_id"`
		RuleType  string `db:"rule_type"`
		Operator  string `db:"operator"`
		Value     string `db:"value"`
	}
	var rungs []seededRung
	if err := db.Select(&rungs, `
		SELECT fw.code, c.control_id, cm.rule_type,
		       cm.predicate->>'operator' AS operator, cm.predicate->>'value' AS value
		FROM platform_frameworks fw
		JOIN platform_framework_controls c ON c.framework_id = fw.id
		JOIN control_measurements cm ON cm.control_id = c.id AND cm.framework_type = 'platform'
		JOIN measurement_types mt ON mt.id = cm.measurement_type_id
		WHERE fw.code IN ('cert-expiry-not-expired','cert-expiry-30-day','cert-expiry-90-day')
		  AND mt.code = 'cert_expiration_days'
		ORDER BY fw.code`); err != nil {
		t.Fatalf("read seeded rungs: %v", err)
	}

	if len(rungs) != 3 {
		t.Fatalf("expected exactly 3 seeded cert-expiry measurements (one per framework), got %d: %+v", len(rungs), rungs)
	}
	want := map[string]string{
		"cert-expiry-not-expired": "> 0",
		"cert-expiry-30-day":      ">= 30",
		"cert-expiry-90-day":      ">= 90",
	}
	seen := map[string]bool{}
	for _, r := range rungs {
		if r.RuleType != "threshold" {
			t.Errorf("%s/%s is rule_type %q, want threshold", r.Framework, r.Control, r.RuleType)
		}
		got := r.Operator + " " + r.Value
		if got != want[r.Framework] {
			t.Errorf("%s/%s predicate is %q, want %q", r.Framework, r.Control, got, want[r.Framework])
		}
		if seen[got] {
			t.Errorf("%s/%s repeats the threshold %q already used by another cert-expiry framework — "+
				"the rungs have collapsed", r.Framework, r.Control, got)
		}
		seen[got] = true
	}
}
