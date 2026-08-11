package services

// End-to-end verdict tests for the seeded Best Practices / Certificate Hygiene
// controls, against a real Postgres carrying the real schema and seed.
//
// The pure tests next door pin the evaluator's logic and the predicate regexes
// in isolation. These pin the thing the customer actually sees: given a
// compliant asset and a non-compliant one, does the seeded control tell them
// apart? Every finding in WP-A of the audit was a rule that said
// something confident about assets it could not actually distinguish, so the
// assertions below are always stated as a PAIR.
//
// Skips unless TEST_DATABASE_URL is set (see shared/testdb); run with
// `make test-integration-db`.

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type verdictFixture struct {
	db     *sqlx.DB
	tenant uuid.UUID
	eval   *RuleEvaluator
}

func newVerdictFixture(t *testing.T) verdictFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)
	return verdictFixture{db: db, tenant: tenant, eval: NewRuleEvaluator(db, NewMeasurementExtractor(db))}
}

// controlByCode resolves a seeded platform control (e.g. "BP-005") to its row id.
func (f verdictFixture) controlByCode(t *testing.T, frameworkCode, controlCode string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.db.Get(&id, `
		SELECT c.id FROM platform_framework_controls c
		JOIN platform_frameworks fw ON fw.id = c.framework_id
		WHERE fw.code = $1 AND c.control_id = $2`, frameworkCode, controlCode); err != nil {
		t.Fatalf("resolve control %s/%s (is it seeded?): %v", frameworkCode, controlCode, err)
	}
	return id
}

// addCertificate inserts a leaf certificate and returns its id.
func (f verdictFixture) addCertificate(t *testing.T, cn, algorithm string, keySize int, selfSigned bool, notAfter time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	fingerprint := uuid.NewString() + uuid.NewString() // 72 chars; trimmed below
	if _, err := f.db.Exec(`
		INSERT INTO certificates (id, tenant_id, common_name, subject_dn, issuer_dn, fingerprint_sha256,
		                          serial_number, not_before, not_after, public_key_algorithm, public_key_size,
		                          is_ca_certificate, is_self_signed, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,NOW() - interval '30 days',$8,$9,$10,false,$11,NOW(),NOW())`,
		id, f.tenant, cn, "CN="+cn, "CN=issuer", sanitizeFingerprint(fingerprint), id.String()[:8],
		notAfter, algorithm, keySize, selfSigned); err != nil {
		t.Fatalf("insert certificate %s: %v", cn, err)
	}
	return id
}

// sanitizeFingerprint produces the 64 lowercase hex chars the
// valid_fingerprint_sha256 CHECK constraint requires.
func sanitizeFingerprint(s string) string {
	hex := make([]byte, 0, 64)
	for i := 0; len(hex) < 64; i++ {
		c := s[i%len(s)]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
			hex = append(hex, c)
		default:
			hex = append(hex, 'a')
		}
	}
	return string(hex)
}

// addTLSImplementation inserts an asset plus one TLS crypto implementation with
// the given key exchange, and returns the ASSET id (measurements are reported
// against the asset).
func (f verdictFixture) addTLSImplementation(t *testing.T, hostname, keyExchange string) uuid.UUID {
	t.Helper()
	asset := uuid.New()
	if _, err := f.db.Exec(`
		INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,$3,'server','monitoring',NOW(),NOW(),NOW(),NOW())`, asset, f.tenant, hostname); err != nil {
		t.Fatalf("insert asset %s: %v", hostname, err)
	}
	if _, err := f.db.Exec(`
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, protocol, protocol_version, key_exchange_algorithm,
		                                    discovery_method, last_verified_at, created_at, updated_at)
		VALUES ($1,$2,$3,'TLS','TLS 1.2',$4,'passive',NOW(),NOW(),NOW())`,
		uuid.New(), f.tenant, asset, keyExchange); err != nil {
		t.Fatalf("insert implementation for %s: %v", hostname, err)
	}
	return asset
}

// flaggedAssets evaluates a control and returns the set of assets it produced
// findings for.
func (f verdictFixture) flaggedAssets(t *testing.T, controlID uuid.UUID) map[uuid.UUID]bool {
	t.Helper()
	res, err := f.eval.EvaluateControl(f.tenant, controlID, "platform")
	if err != nil {
		t.Fatalf("EvaluateControl: %v", err)
	}
	flagged := make(map[uuid.UUID]bool, len(res.Findings))
	for _, finding := range res.Findings {
		flagged[finding.AssetID] = true
	}
	return flagged
}

// CMP-1: BP-004 must tell an ECDHE endpoint from a static-RSA one. Before the
// fix it flagged both — the boolean pfs_support measurement was "present"
// whether it was true or false, so the seeded predicate produced a violation
// for every asset in the inventory.
func TestIntegration_BP004_PFS_DistinguishesECDHEFromStaticRSA(t *testing.T) {
	f := newVerdictFixture(t)
	ecdhe := f.addTLSImplementation(t, "pfs.example.test", "ECDHE_RSA")
	static := f.addTLSImplementation(t, "nopfs.example.test", "RSA")

	flagged := f.flaggedAssets(t, f.controlByCode(t, "best-practices", "BP-004"))

	if flagged[ecdhe] {
		t.Error("BP-004 flagged an ECDHE endpoint, which supports forward secrecy")
	}
	if !flagged[static] {
		t.Error("BP-004 did not flag a static-RSA endpoint, which has no forward secrecy")
	}
}

// CMP-1: same pair for BP-007's certificate_chain_valid boolean.
func TestIntegration_BP007_Chain_DistinguishesValidFromSelfSigned(t *testing.T) {
	f := newVerdictFixture(t)
	future := time.Now().Add(200 * 24 * time.Hour)
	valid := f.addCertificate(t, "valid-chain.example.test", "RSA", 2048, false, future)
	selfSigned := f.addCertificate(t, "self-signed.example.test", "RSA", 2048, true, future)

	flagged := f.flaggedAssets(t, f.controlByCode(t, "best-practices", "BP-007"))

	if flagged[valid] {
		t.Error("BP-007 flagged a certificate with a valid chain")
	}
	if !flagged[selfSigned] {
		t.Error("BP-007 did not flag a self-signed certificate")
	}
}

// CMP-3: BP-009 exists for the STATIC key-exchange suites, and the compound
// forms the passive sensor emits are exactly those. The ephemeral forms differ
// by one letter and must not be flagged.
func TestIntegration_BP009_FlagsStaticKexNotEphemeral(t *testing.T) {
	f := newVerdictFixture(t)
	staticECDH := f.addTLSImplementation(t, "static-ecdh.example.test", "ECDH_RSA")
	staticDH := f.addTLSImplementation(t, "static-dh.example.test", "DH_DSS")
	ephemeral := f.addTLSImplementation(t, "ephemeral.example.test", "ECDHE_RSA")

	flagged := f.flaggedAssets(t, f.controlByCode(t, "best-practices", "BP-009"))

	for name, asset := range map[string]uuid.UUID{"ECDH_RSA": staticECDH, "DH_DSS": staticDH} {
		if !flagged[asset] {
			t.Errorf("BP-009 did not flag %s — a static suite with no forward secrecy", name)
		}
	}
	if flagged[ephemeral] {
		t.Error("BP-009 flagged ECDHE_RSA, which does provide forward secrecy")
	}
}

// CMP-4: a P-256 certificate must pass the key-size controls and an RSA-1024
// certificate must fail them — in BOTH frameworks that carry the rule. The
// single `key_size >= 2048` measurement flagged every elliptic-curve
// certificate in the inventory as a weak key.
func TestIntegration_KeySizeControlsAreAlgorithmAware(t *testing.T) {
	f := newVerdictFixture(t)
	future := time.Now().Add(200 * 24 * time.Hour)
	p256 := f.addCertificate(t, "p256.example.test", "ECDSA", 256, false, future)
	rsa1024 := f.addCertificate(t, "rsa1024.example.test", "RSA", 1024, false, future)
	rsa2048 := f.addCertificate(t, "rsa2048.example.test", "RSA", 2048, false, future)

	for _, ctl := range []struct{ framework, control string }{
		{"best-practices", "BP-005"},
		{"cert-hygiene", "CH-001"},
	} {
		flagged := f.flaggedAssets(t, f.controlByCode(t, ctl.framework, ctl.control))

		if flagged[p256] {
			t.Errorf("%s flagged a P-256 certificate — 256-bit EC is 128-bit security, above the RSA-2048 floor", ctl.control)
		}
		if flagged[rsa2048] {
			t.Errorf("%s flagged an RSA-2048 certificate", ctl.control)
		}
		if !flagged[rsa1024] {
			t.Errorf("%s did not flag an RSA-1024 certificate", ctl.control)
		}
	}
}

// CMP-10: a certificate-expiry finding's timestamps record when the
// measurement was TAKEN. Stamping them with not_after put every finding's
// first_seen/last_seen in the future by the certificate's remaining lifetime.
func TestIntegration_CertExpiryMeasurementIsStampedWithNow(t *testing.T) {
	f := newVerdictFixture(t)
	notAfter := time.Now().Add(200 * 24 * time.Hour)
	certID := f.addCertificate(t, "expiry.example.test", "RSA", 2048, false, notAfter)

	values, err := NewMeasurementExtractor(f.db).GetCertificateExpirationDays(f.tenant, certID)
	if err != nil {
		t.Fatalf("GetCertificateExpirationDays: %v", err)
	}
	if len(values) != 1 {
		t.Fatalf("got %d measurements, want 1", len(values))
	}

	if values[0].MeasuredAt.After(time.Now().Add(time.Minute)) {
		t.Errorf("MeasuredAt = %s is in the future; a measurement is taken now, not when the certificate expires", values[0].MeasuredAt)
	}
	if got := values[0].Metadata["not_after"]; got == nil {
		t.Error("not_after did not travel in the evidence metadata")
	}

	// 200 days out, floored: 199 (the partial day is not yet elapsed).
	days, ok := values[0].Value.(int)
	if !ok {
		t.Fatalf("value is %T, want int", values[0].Value)
	}
	if days != 199 && days != 200 {
		t.Errorf("expiration days = %d, want 199 or 200", days)
	}
}
