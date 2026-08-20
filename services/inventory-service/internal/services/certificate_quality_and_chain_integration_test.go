package services

// Real-Postgres guards for two certificate defects, both of which reported
// success while doing nothing:
//
//   - B-19: updateCertQualityFlags PERSISTED has_sct / is_ev / ocsp_status /
//     ocsp_detail, and models.Certificate declares all four with db tags, but
//     certificateColumns — the file's self-declared canonical column list —
//     omitted them and scanCertificateRowFull had no scan destinations. Every
//     read returned them nil, so the drawer's Trust & revocation block was
//     blank on every certificate, including revoked ones. The flags were also
//     written only on the create path, so re-discovery never refreshed them.
//   - B-20: findCertificateBySubjectDN filtered `AND deleted_at IS NULL` on
//     `certificates`, which has no such column. The query errored on EVERY
//     call; RebuildCertificateChain collapsed the error into "no issuer found"
//     and still returned 200 with links_created: 0, and the bulk variant 500'd
//     for every tenant.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// hexFingerprint renders a stable 64-hex-character SHA-256 fingerprint for a
// fixture label. The certificates table CHECKs the column against
// ^[a-fA-F0-9]{64}$, so a readable placeholder is rejected outright.
func hexFingerprint(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])
}

func newCertFixture(t *testing.T) (*CertificateService, *database.DB, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	return &CertificateService{db: db}, db, testdb.NewTenant(t, raw)
}

// TestIntegration_CertificateQualityFlags_SurviveTheRoundTrip is the B-19
// regression: the flags are in the table, so a read path that omits them from
// its column list is the only thing that can make them nil.
func TestIntegration_CertificateQualityFlags_SurviveTheRoundTrip(t *testing.T) {
	svc, db, tenant := newCertFixture(t)

	certID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO certificates (
			id, tenant_id, subject_dn, issuer_dn, fingerprint_sha256,
			not_before, not_after, is_self_signed, is_ca_certificate,
			has_sct, is_ev, ocsp_status, ocsp_detail, known_bad_ca,
			created_at, updated_at
		) VALUES ($1,$2,'CN=leaf.example.test','CN=Issuer CA',$3,
		          NOW() - INTERVAL '1 day', NOW() + INTERVAL '30 days', false, false,
		          true, true, 'revoked', 'revoked at 2026-01-01 (keyCompromise)', NULL,
		          NOW(), NOW())`, certID, tenant, hexFingerprint("quality-flags")); err != nil {
		t.Fatalf("insert certificate: %v", err)
	}

	got, err := svc.GetCertificateByID(tenant, certID)
	if err != nil {
		t.Fatalf("GetCertificateByID: %v", err)
	}
	if got == nil {
		t.Fatal("GetCertificateByID returned nil")
	}
	if got.HasSCT == nil || !*got.HasSCT {
		t.Errorf("HasSCT = %v, want true", got.HasSCT)
	}
	if got.IsEV == nil || !*got.IsEV {
		t.Errorf("IsEV = %v, want true", got.IsEV)
	}
	if got.OCSPStatus == nil || *got.OCSPStatus != "revoked" {
		t.Errorf("OCSPStatus = %v, want \"revoked\" — a revoked certificate must not read the same as an unchecked one", got.OCSPStatus)
	}
	if got.OCSPDetail == nil || *got.OCSPDetail == "" {
		t.Errorf("OCSPDetail = %v, want the stored detail", got.OCSPDetail)
	}

	// The LIST path appends deployment_count + effective_ownership AFTER
	// certificateColumns, so it is the one most likely to break on a column-list
	// change. Assert it carries the flags too.
	list, _, err := svc.GetCertificates(tenant, models.CertificateFilters{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("GetCertificates: %v", err)
	}
	var found bool
	for _, c := range list {
		if c.ID != certID {
			continue
		}
		found = true
		if c.HasSCT == nil || c.IsEV == nil || c.OCSPStatus == nil {
			t.Errorf("list path dropped quality flags: has_sct=%v is_ev=%v ocsp_status=%v", c.HasSCT, c.IsEV, c.OCSPStatus)
		}
	}
	if !found {
		t.Fatalf("certificate %s missing from the list response", certID)
	}
}

// TestIntegration_CertificateQualityFlags_RefreshOnRediscovery covers the
// second half of B-19: updateCertQualityFlags was invoked only from the create
// path, so a certificate first seen before its OCSP check could never acquire
// the result.
func TestIntegration_CertificateQualityFlags_RefreshOnRediscovery(t *testing.T) {
	svc, _, tenant := newCertFixture(t)

	base := models.CertificateData{
		SubjectDN:         "CN=refresh.example.test",
		IssuerDN:          "CN=Issuer CA",
		FingerprintSHA256: hexFingerprint("refresh-on-rediscovery"),
		NotBefore:         time.Now().Add(-24 * time.Hour),
		NotAfter:          time.Now().Add(720 * time.Hour),
	}

	first, err := svc.FindOrCreateCertificate(tenant, base)
	if err != nil {
		t.Fatalf("first FindOrCreateCertificate: %v", err)
	}
	if first.OCSPStatus != nil {
		t.Fatalf("premise failed: OCSPStatus already set on first sight (%v)", *first.OCSPStatus)
	}

	// Same certificate, re-observed — this time the prober got an OCSP answer.
	enriched := base
	hasSCT := true
	enriched.HasSCT = &hasSCT
	enriched.OCSPStatus = "good"
	enriched.OCSPDetail = "responder replied good"

	second, err := svc.FindOrCreateCertificate(tenant, enriched)
	if err != nil {
		t.Fatalf("second FindOrCreateCertificate: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("re-discovery created a new certificate (%s != %s)", second.ID, first.ID)
	}
	if second.OCSPStatus == nil || *second.OCSPStatus != "good" {
		t.Errorf("OCSPStatus after re-discovery = %v, want \"good\"", second.OCSPStatus)
	}
	if second.HasSCT == nil || !*second.HasSCT {
		t.Errorf("HasSCT after re-discovery = %v, want true", second.HasSCT)
	}
}

// insertChainCert inserts a certificate with no PEM, so RebuildCertificateChain
// skips x509 signature verification and exercises purely the DN-matching path
// the missing-column bug broke.
func insertChainCert(t *testing.T, db *database.DB, tenant uuid.UUID, subject, issuer string, selfSigned bool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO certificates (
			id, tenant_id, subject_dn, issuer_dn, fingerprint_sha256,
			not_before, not_after, is_self_signed, is_ca_certificate, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,NOW() - INTERVAL '1 day', NOW() + INTERVAL '365 days',$6,$6,NOW(),NOW())`,
		id, tenant, subject, issuer, hexFingerprint(id.String()), selfSigned); err != nil {
		t.Fatalf("insert certificate %s: %v", subject, err)
	}
	return id
}

// TestIntegration_RebuildCertificateChain_LinksIssuer is the B-20 regression.
// Before the fix this returned links_created: 0 / chain_complete: false with no
// error and no log line, forever.
func TestIntegration_RebuildCertificateChain_LinksIssuer(t *testing.T) {
	svc, db, tenant := newCertFixture(t)

	root := insertChainCert(t, db, tenant, "CN=Test Root CA", "CN=Test Root CA", true)
	leaf := insertChainCert(t, db, tenant, "CN=leaf.example.test", "CN=Test Root CA", false)

	result, err := svc.RebuildCertificateChain(tenant, leaf)
	if err != nil {
		t.Fatalf("RebuildCertificateChain: %v", err)
	}
	if result.LinksCreated != 1 {
		t.Errorf("LinksCreated = %d, want 1", result.LinksCreated)
	}
	if !result.ChainComplete {
		t.Error("ChainComplete = false, want true (the issuer is a self-signed root)")
	}
	if result.ChainLength != 2 {
		t.Errorf("ChainLength = %d, want 2", result.ChainLength)
	}

	var linked uuid.UUID
	if err := db.QueryRow(`SELECT issuer_certificate_id FROM certificates WHERE id = $1`, leaf).Scan(&linked); err != nil {
		t.Fatalf("read issuer_certificate_id: %v", err)
	}
	if linked != root {
		t.Errorf("issuer_certificate_id = %s, want %s", linked, root)
	}
}

// TestIntegration_RebuildAllCertificateChains_Runs proves the bulk variant no
// longer 500s on the missing column, and that it actually links.
func TestIntegration_RebuildAllCertificateChains_Runs(t *testing.T) {
	svc, db, tenant := newCertFixture(t)

	insertChainCert(t, db, tenant, "CN=Bulk Root CA", "CN=Bulk Root CA", true)
	insertChainCert(t, db, tenant, "CN=bulk-a.example.test", "CN=Bulk Root CA", false)
	insertChainCert(t, db, tenant, "CN=bulk-b.example.test", "CN=Bulk Root CA", false)
	// An orphan: its issuer is not in the tenant's inventory.
	insertChainCert(t, db, tenant, "CN=orphan.example.test", "CN=Absent CA", false)

	result, err := svc.RebuildAllCertificateChains(context.Background(), tenant)
	if err != nil {
		t.Fatalf("RebuildAllCertificateChains: %v", err)
	}
	if result.TotalCertificates != 3 {
		t.Errorf("TotalCertificates = %d, want 3 (the self-signed root is excluded)", result.TotalCertificates)
	}
	if result.LinksCreated != 2 {
		t.Errorf("LinksCreated = %d, want 2", result.LinksCreated)
	}
	if len(result.Errors) != 0 {
		t.Errorf("Errors = %v, want none", result.Errors)
	}
}
