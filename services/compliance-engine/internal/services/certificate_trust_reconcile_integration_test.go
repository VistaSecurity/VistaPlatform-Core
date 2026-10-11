package services

// DB-integration test for the Certificate Hygiene trust controls (feature
//slice 3): the spec's mutation check "distrust a CA → finding appears"
// from the compliance side.
//
// inventory-service publishes a compliance.reconcile.tenant job with reason
// `certificate_trust_changed` after any trust decision changes. The test drives
// that exact message through the real handler, so it pins both halves: the
// worker re-evaluates the Core frameworks on a job of that reason (the handler
// does not filter on reason), and CH-003 reads the new verdict.
//
// Skips unless TEST_DATABASE_URL is set; run via `make test-integration-db`.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/nats-io/nats.go"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type trustFixture struct {
	db     *sqlx.DB
	tenant uuid.UUID
	asset  uuid.UUID
	ca     uuid.UUID
	leaf   uuid.UUID
	sub    *EventSubscriberService
}

func newTrustFixture(t *testing.T) *trustFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	asset := uuid.New()
	if _, err := raw.Exec(`
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path)
		VALUES ($1, $2, 'trust.example.test', 'server', 'hardware.computer.server')`,
		asset, tenant); err != nil {
		t.Fatalf("seed asset: %v", err)
	}

	cert := func(id uuid.UUID, subject, issuer string, isCA, selfSigned bool) {
		t.Helper()
		fp := strings.ReplaceAll(id.String(), "-", "")
		if _, err := raw.Exec(`
			INSERT INTO certificates (id, tenant_id, subject_dn, issuer_dn, common_name,
				fingerprint_sha256, public_key_algorithm, public_key_size,
				signature_algorithm, not_before, not_after, is_ca_certificate, is_self_signed)
			VALUES ($1, $2, $3, $4, $5, $6, 'RSA', 2048, 'SHA256withRSA',
				now() - interval '30 days', now() + interval '200 days', $7, $8)`,
			id, tenant, "CN="+subject, "CN="+issuer, subject, fp+fp, isCA, selfSigned); err != nil {
			t.Fatalf("seed certificate %s: %v", subject, err)
		}
	}
	ca := uuid.New()
	cert(ca, "Fixture Internal Root", "Fixture Internal Root", true, true)
	leaf := uuid.New()
	cert(leaf, "trust.example.test", "Fixture Internal Root", false, false)

	// The binding an ordinary TLS discovery writes: the asset serves the leaf.
	if _, err := raw.Exec(`
		INSERT INTO crypto_implementations_partitioned (tenant_id, asset_id, protocol, discovery_method, certificate_id)
		VALUES ($1, $2, 'TLS', 'passive', $3)`, tenant, asset, leaf); err != nil {
		t.Fatalf("seed crypto implementation: %v", err)
	}

	extractor := NewMeasurementExtractor(db)
	evaluator := NewRuleEvaluator(db, extractor)
	findings := NewFindingsService(db, db, evaluator, nil, NewEvaluationService(db, evaluator), nil)
	return &trustFixture{
		db: db, tenant: tenant, asset: asset, ca: ca, leaf: leaf,
		sub: &EventSubscriberService{findingService: findings},
	}
}

// setTrust writes what certtrust.Evaluate writes for the leaf.
func (f *trustFixture) setTrust(t *testing.T, status string) {
	t.Helper()
	var s, anchor interface{}
	if status != "" {
		s, anchor = status, f.ca
	}
	if _, err := f.db.Exec(`
		UPDATE certificates SET trust_status = $1::text, trust_anchor_certificate_id = $2::uuid,
			trust_evaluated_at = CASE WHEN $1::text IS NULL THEN NULL ELSE now() END
		WHERE tenant_id = $3 AND id = $4`, s, anchor, f.tenant, f.leaf); err != nil {
		t.Fatalf("set trust_status=%q: %v", status, err)
	}
}

// reconcile delivers the job inventory-service publishes after a trust change
// to the real compliance.reconcile.tenant handler.
func (f *trustFixture) reconcile(t *testing.T) {
	t.Helper()
	data, err := json.Marshal(ReconcileJob{TenantID: f.tenant.String(), Reason: "certificate_trust_changed"})
	if err != nil {
		t.Fatal(err)
	}
	testdb.RetryTransient(t, func() error {
		return f.sub.handleReconcileTenant(context.Background(), &nats.Msg{Data: data})
	})
}

// finding returns the detection state and evidence of the leaf's finding for a
// seeded control, or "" when there is none.
func (f *trustFixture) finding(t *testing.T, framework, control string) (string, map[string]interface{}) {
	t.Helper()
	var row struct {
		State    string `db:"detection_state"`
		Evidence []byte `db:"evidence"`
	}
	err := f.db.Get(&row, `
		SELECT fi.detection_state, fi.evidence
		FROM findings fi
		JOIN platform_framework_controls pfc ON pfc.id = fi.control_id
		JOIN platform_frameworks fw ON fw.id = pfc.framework_id
		WHERE fi.tenant_id = $1 AND fi.subject_id = $2
		  AND fw.code = $3 AND pfc.control_id = $4`,
		f.tenant, f.leaf, framework, control)
	if err != nil {
		return "", nil
	}
	var ev map[string]interface{}
	_ = json.Unmarshal(row.Evidence, &ev)
	return row.State, ev
}

func TestIntegration_CertTrust_DistrustRaisesCH003AndTrustResolvesIt(t *testing.T) {
	f := newTrustFixture(t)

	// Not yet evaluated: no trust control may judge the certificate.
	f.reconcile(t)
	for _, c := range [][2]string{{"cert-hygiene", "CH-003"}, {"cert-hygiene", "CH-004"}, {"best-practices", "BP-007"}} {
		if state, _ := f.finding(t, c[0], c[1]); state != "" {
			t.Errorf("unevaluated certificate: %s %s finding is %s, want none", c[0], c[1], state)
		}
	}

	// The CA is nobody's: CH-003 is raised against the leaf.
	f.setTrust(t, "untrusted")
	f.reconcile(t)
	state, evidence := f.finding(t, "cert-hygiene", "CH-003")
	if state != "ACTIVE" {
		t.Fatalf("untrusted: CH-003 finding state %q, want ACTIVE", state)
	}
	if !strings.Contains(string(mustJSON(t, evidence)), "Fixture Internal Root") {
		t.Errorf("CH-003 evidence does not name the anchor CA: %s", mustJSON(t, evidence))
	}
	if !strings.Contains(string(mustJSON(t, evidence)), f.ca.String()) {
		t.Errorf("CH-003 evidence does not carry the anchor certificate id: %s", mustJSON(t, evidence))
	}
	if state, _ := f.finding(t, "cert-hygiene", "CH-004"); state == "ACTIVE" {
		t.Error("untrusted (not self-signed): CH-004 must not fire")
	}
	if state, _ := f.finding(t, "best-practices", "BP-007"); state != "ACTIVE" {
		t.Errorf("untrusted: BP-007 finding state %q, want ACTIVE", state)
	}

	// The organisation trusts its CA: the finding resolves on the next reconcile.
	f.setTrust(t, "private_trusted")
	f.reconcile(t)
	if state, _ := f.finding(t, "cert-hygiene", "CH-003"); state != "INACTIVE" {
		t.Errorf("private_trusted: CH-003 finding state %q, want INACTIVE", state)
	}
	if state, _ := f.finding(t, "best-practices", "BP-007"); state != "INACTIVE" {
		t.Errorf("private_trusted: BP-007 finding state %q, want INACTIVE", state)
	}

	// Distrust the CA: the finding comes back.
	f.setTrust(t, "distrusted")
	f.reconcile(t)
	if state, _ := f.finding(t, "cert-hygiene", "CH-003"); state != "ACTIVE" {
		t.Errorf("distrusted: CH-003 finding state %q, want ACTIVE", state)
	}
}

func TestIntegration_CertTrust_SelfSignedRaisesCH004NotCH003(t *testing.T) {
	f := newTrustFixture(t)
	f.setTrust(t, "self_signed")
	f.reconcile(t)
	if state, _ := f.finding(t, "cert-hygiene", "CH-004"); state != "ACTIVE" {
		t.Errorf("self_signed: CH-004 finding state %q, want ACTIVE", state)
	}
	if state, _ := f.finding(t, "cert-hygiene", "CH-003"); state != "" {
		t.Errorf("self_signed: CH-003 finding state %q, want none", state)
	}
}

func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
