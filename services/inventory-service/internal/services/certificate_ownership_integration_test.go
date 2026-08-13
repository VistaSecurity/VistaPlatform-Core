package services

// Proof for #H-6 and #M-7 (QA findings, v0.5.7 live Inventory review):
//
//   - H-6: the `?ownership=` filter on GET /certificates must PARTITION the
//     whole set — every certificate must match exactly one of
//     internal/third_party/unknown, and the buckets must sum to the
//     unfiltered total. The old filter (`na.asset_ownership = $N OR
//     cert_ownership = $N`) let a cert with no linked asset AND no declared
//     cert_ownership fall through every bucket when ownership=unknown was
//     requested, because NULL never equals the literal 'unknown'.
//   - The list response's `ownership` field must show the SAME effective
//     value the filter partitions on (previously the list only exposed the
//     raw, mostly-null `cert_ownership` column).
//   - M-7: deployment_count (and the drawer's related-assets) must credit a
//     CA/intermediate certificate with the deployments of every leaf
//     certificate it issued (walking certificates.issuer_certificate_id),
//     not just certs that are themselves a crypto_implementation's direct
//     certificate_id. Without this, a CA cert showed "Unassigned" while the
//     key extracted from that same cert showed "1 asset" (#M-7).
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type certOwnershipFixture struct {
	db     *database.DB
	svc    *CertificateService
	tenant uuid.UUID
}

func newCertOwnershipFixture(t *testing.T) certOwnershipFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	return certOwnershipFixture{db: db, svc: NewCertificateService(db, nil), tenant: tenant}
}

// insertCert inserts a bare certificate row. certOwnership may be "" (NULL).
func (f certOwnershipFixture) insertCert(t *testing.T, cn, fingerprint, certOwnership string, issuerCertID *uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	var ownership interface{}
	if certOwnership != "" {
		ownership = certOwnership
	}
	_, err := f.db.Exec(`
		INSERT INTO certificates (id, tenant_id, subject_dn, issuer_dn, common_name, fingerprint_sha256, cert_ownership, issuer_certificate_id, created_at, updated_at)
		VALUES ($1,$2,$3,$3,$4,$5,$6,$7,NOW(),NOW())`,
		id, f.tenant, "CN="+cn, cn, fingerprint, ownership, issuerCertID)
	if err != nil {
		t.Fatalf("insert cert %s: %v", cn, err)
	}
	return id
}

func (f certOwnershipFixture) insertAsset(t *testing.T, hostname, ownership string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := f.db.Exec(`
		INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, asset_ownership, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,$3,'server','monitoring',$4,NOW(),NOW(),NOW(),NOW())`,
		id, f.tenant, hostname, ownership)
	if err != nil {
		t.Fatalf("insert asset %s: %v", hostname, err)
	}
	return id
}

func (f certOwnershipFixture) linkCertToAsset(t *testing.T, assetID, certID uuid.UUID) {
	t.Helper()
	_, err := f.db.Exec(`
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, protocol, certificate_id, discovery_method, created_at, updated_at)
		VALUES ($1,$2,$3,'TLS',$4,'passive',NOW(),NOW())`,
		uuid.New(), f.tenant, assetID, certID)
	if err != nil {
		t.Fatalf("link cert to asset: %v", err)
	}
}

// Every certificate must land in exactly one ownership bucket, and the
// buckets must sum to the unfiltered total (#H-6). This fixture reproduces
// the QA scenario: 5 certs total — one deployed on an internal asset, one
// deployed on a third_party asset, two with an explicit-'unknown' asset link
// or declared cert_ownership, and (the bug) ONE with no asset link and no
// declared cert_ownership at all.
func TestIntegration_CertificateOwnership_PartitionsWholeSet(t *testing.T) {
	f := newCertOwnershipFixture(t)

	internalAsset := f.insertAsset(t, "internal.example.test", "internal")
	thirdPartyAsset := f.insertAsset(t, "vendor.example.test", "third_party")
	unknownAsset := f.insertAsset(t, "unclassified.example.test", "unknown")

	c1 := f.insertCert(t, "internal-cert", fpFor("c1"), "", nil)
	f.linkCertToAsset(t, internalAsset, c1)

	c2 := f.insertCert(t, "vendor-cert", fpFor("c2"), "", nil)
	f.linkCertToAsset(t, thirdPartyAsset, c2)

	c3 := f.insertCert(t, "unknown-asset-cert", fpFor("c3"), "", nil)
	f.linkCertToAsset(t, unknownAsset, c3)

	// Manually uploaded, never linked to any asset — ownership declared at
	// upload time via cert_ownership (the column only accepts
	// internal/third_party, never the literal 'unknown'; see
	// valid_cert_ownership). Exercises the cert_ownership fallback path of
	// effectiveOwnershipExpr distinctly from the asset-link path (c2, above).
	f.insertCert(t, "manual-vendor-cert", fpFor("c4"), "third_party", nil)

	// THE BUG CASE: no asset link at all, no declared cert_ownership (NULL).
	f.insertCert(t, "orphan-cert", fpFor("c5"), "", nil)

	all, total, err := f.svc.GetCertificates(f.tenant, models.CertificateFilters{Page: 1, PageSize: 50})
	if err != nil {
		t.Fatalf("GetCertificates (unfiltered): %v", err)
	}
	if total != 5 || len(all) != 5 {
		t.Fatalf("unfiltered total = %d (%d rows), want 5", total, len(all))
	}
	// Every cert's list-response `ownership` must be one of the three buckets.
	for _, c := range all {
		cn := ""
		if c.CommonName != nil {
			cn = *c.CommonName
		}
		if c.Ownership != "internal" && c.Ownership != "third_party" && c.Ownership != "unknown" {
			t.Errorf("cert %s ownership = %q, want internal/third_party/unknown", cn, c.Ownership)
		}
	}

	sum := 0
	for _, bucket := range []string{"internal", "third_party", "unknown"} {
		b := bucket
		_, n, err := f.svc.GetCertificates(f.tenant, models.CertificateFilters{Page: 1, PageSize: 50, Ownership: &b})
		if err != nil {
			t.Fatalf("GetCertificates(ownership=%s): %v", bucket, err)
		}
		sum += n
	}
	if sum != total {
		t.Fatalf("ownership buckets summed to %d, want %d (unfiltered total) — a cert fell through every bucket", sum, total)
	}

	// The orphan cert (no link, no declared ownership) specifically must land
	// in "unknown" — this is the exact case that used to fall through.
	unknown := "unknown"
	unknownCerts, _, err := f.svc.GetCertificates(f.tenant, models.CertificateFilters{Page: 1, PageSize: 50, Ownership: &unknown})
	if err != nil {
		t.Fatalf("GetCertificates(ownership=unknown): %v", err)
	}
	found := false
	for _, c := range unknownCerts {
		if c.CommonName != nil && *c.CommonName == "orphan-cert" {
			found = true
		}
	}
	if !found {
		t.Errorf("orphan-cert (no asset link, no declared cert_ownership) did not appear in the unknown bucket")
	}
}

// M-7: a CA/intermediate certificate that is never itself a config's leaf
// certificate_id must still show deployment_count > 0 when it issued a
// certificate that IS directly deployed — matching what the Keys lens shows
// for a key extracted from that same CA cert.
func TestIntegration_CertificateDeploymentCount_CreditsIssuerChain(t *testing.T) {
	f := newCertOwnershipFixture(t)
	asset := f.insertAsset(t, "leaf-host.example.test", "internal")

	caCert := f.insertCert(t, "Example CA Intermediate CA", fpFor("ca1"), "", nil)
	leafCert := f.insertCert(t, "leaf.example.test", fpFor("leaf1"), "", &caCert)
	f.linkCertToAsset(t, asset, leafCert)

	all, _, err := f.svc.GetCertificates(f.tenant, models.CertificateFilters{Page: 1, PageSize: 50})
	if err != nil {
		t.Fatalf("GetCertificates: %v", err)
	}

	var caDeployCount, leafDeployCount *int
	for i := range all {
		if all[i].CommonName != nil && *all[i].CommonName == "Example CA Intermediate CA" {
			caDeployCount = all[i].DeploymentCount
		}
		if all[i].CommonName != nil && *all[i].CommonName == "leaf.example.test" {
			leafDeployCount = all[i].DeploymentCount
		}
	}
	if leafDeployCount == nil || *leafDeployCount != 1 {
		t.Fatalf("leaf cert deployment_count = %v, want 1", leafDeployCount)
	}
	if caDeployCount == nil || *caDeployCount != 1 {
		t.Fatalf("CA cert deployment_count = %v, want 1 (credited via the issuer chain of the deployed leaf) — this is #M-7: a CA cert showing 0/\"Unassigned\" while a key extracted from it shows \"1 asset\"", caDeployCount)
	}
}

func fpFor(seed string) string {
	// A syntactically valid 64-hex-char fingerprint, distinct per seed.
	const hex = "0123456789abcdef"
	out := make([]byte, 64)
	for i := range out {
		out[i] = hex[(int(seed[i%len(seed)])+i)%16]
	}
	return string(out)
}
