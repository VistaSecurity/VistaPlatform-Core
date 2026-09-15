package services

// Guards the certificate half of GetSummary's weak-key-size count.
//
// The certificate branch of the issue query used a bare
// `public_key_size < 2048`, the RSA/finite-field floor, applied to every key
// family. A healthy 256-bit EC certificate — a modern, correctly-sized key —
// was counted as a certificate issue, while the `crypto` finding producer
// (shared/cryptoparse.WeakKeySizeSeverity) raised no `weak_certificate` finding
// for the same certificate: two opinions, and the uncited one (this file) won
// in the dashboard's CertificateIssues counter. The fix reuses
// anyWeakKeySizeSQL, the same family-aware SQL classifier already used for
// crypto_implementations' key_size_issues counter a few lines above, against
// certificates.public_key_algorithm / public_key_size instead.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_CryptoRisksSummary_CertificateKeySizeIsFamilyAware(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := &CryptoRisksService{db: db}

	insertCert := func(commonName, keyAlgorithm string, keySize int) {
		if _, err := db.Exec(`
			INSERT INTO certificates (
				id, tenant_id, subject_dn, issuer_dn, common_name,
				public_key_algorithm, public_key_size, fingerprint_sha256,
				created_at, updated_at
			) VALUES ($1,$2,$3,$3,$4,$5,$6,$7,NOW(),NOW())`,
			uuid.New(), tenant, "CN="+commonName, commonName,
			keyAlgorithm, keySize, fpFor(commonName)); err != nil {
			t.Fatalf("insert %s certificate: %v", commonName, err)
		}
	}

	// A healthy, modern 256-bit EC certificate. Not an issue at any severity —
	// 256 bits is well above the EC floor (cryptoparse.MinECCKeySizeBits).
	insertCert("ec-p256.example.test", "ECDSA", 256)
	// A critically weak 1024-bit RSA certificate. Below both the RSA floor
	// (2048) and the "critically weak" threshold (1024), so it IS an issue.
	insertCert("rsa-1024.example.test", "RSA", 1024)

	summary, err := svc.GetSummary(tenant)
	if err != nil {
		t.Fatalf("GetSummary: %v", err)
	}
	if summary.CertificateIssues != 1 {
		t.Errorf("CertificateIssues = %d, want 1 — the 256-bit EC certificate "+
			"must NOT be counted as a weak key (family-blind '<2048' would "+
			"wrongly count it, making CertificateIssues = 2)", summary.CertificateIssues)
	}
}
