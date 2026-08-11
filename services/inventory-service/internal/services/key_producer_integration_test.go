package services

// Integration proof for the cryptographic-key inventory producer
// (produceKeyFromCertificate). Before this, the keys table had no writer at all,
// so the Keys lens was structurally always empty (overnight review F4). These
// tests prove the producer:
//   - derives a public-key row from a certificate's public key (metadata only),
//   - keys it on the SPKI fingerprint (NOT the whole-cert fingerprint), so the
//     same key across hosts/renewals dedups to one row, and
//   - links it through implementation_keys so the lens "used by N assets" count
//     and the key drawer resolve.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	sharedcerts "github.com/vistasecurity/vistaplatform/shared/certificates"
)

// selfSignedRSACert returns a real RSA-2048 self-signed certificate as PEM plus
// the hex SHA-256 of its DER (the whole-cert fingerprint).
func selfSignedRSACert(t *testing.T, cn string) (pemStr, certSHA256 string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	sum := sha256.Sum256(der)
	pemStr = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return pemStr, hex.EncodeToString(sum[:])
}

func insertAssetAndImpl(t *testing.T, db *database.DB, tenant uuid.UUID) (assetID, implID uuid.UUID) {
	t.Helper()
	assetID = uuid.New()
	if _, err := db.Exec(
		`INSERT INTO network_assets (id, tenant_id, hostname, asset_type) VALUES ($1, $2, $3, 'server')`,
		assetID, tenant, "host-"+assetID.String()[:8]); err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	implID = uuid.New()
	if _, err := db.Exec(
		`INSERT INTO crypto_implementations (id, tenant_id, asset_id, protocol, discovery_method) VALUES ($1, $2, $3, 'TLS', 'integration')`,
		implID, tenant, assetID); err != nil {
		t.Fatalf("insert crypto implementation: %v", err)
	}
	return assetID, implID
}

func TestIntegration_KeyProducer_FromCertificate(t *testing.T) {
	svc, db, tenant := newKeysSvc(t)
	_, implID := insertAssetAndImpl(t, db, tenant)

	pemStr, certSHA256 := selfSignedRSACert(t, "producer.example")
	certID := uuid.New()
	cn := "producer.example"
	cert := &models.Certificate{
		ID:               certID,
		TenantID:         tenant,
		CertificateState: "active",
		CommonName:       &cn,
	}
	data := models.CertificateData{
		PublicKeyAlgorithm: "RSA",
		PublicKeySize:      2048,
		FingerprintSHA256:  certSHA256,
		CertificatePEM:     pemStr,
		KeyUsage:           []string{"DigitalSignature", "KeyEncipherment"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
	}

	svc.produceKeyFromCertificate(tenant, implID, cert, data)

	keys, err := svc.ListKeys(tenant)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("producer wrote %d keys, want 1 (was 0 before this feature)", len(keys))
	}
	k := keys[0]

	if k.MaterialType != "public-key" {
		t.Errorf("material_type = %q, want public-key (metadata only, never private/secret)", k.MaterialType)
	}
	if k.KeyType != "RSA" {
		t.Errorf("key_type = %q, want RSA", k.KeyType)
	}
	if k.SizeBits == nil || *k.SizeBits != 2048 {
		t.Errorf("size_bits = %v, want 2048", k.SizeBits)
	}
	if len(k.KeyUsage) != 2 {
		t.Errorf("key_usage = %v, want 2 entries", k.KeyUsage)
	}

	// public_fingerprint must be the SPKI hash, NOT the whole-cert fingerprint —
	// that's what makes the same key across certs dedup.
	x, err := sharedcerts.ParseCertificatePEM(pemStr)
	if err != nil {
		t.Fatalf("parse pem: %v", err)
	}
	wantSPKI := sharedcerts.PublicKeyFingerprintSHA256(x)
	if k.PublicFingerprint == nil || *k.PublicFingerprint != wantSPKI {
		t.Errorf("public_fingerprint = %v, want SPKI %s", k.PublicFingerprint, wantSPKI)
	}
	if k.PublicFingerprint != nil && *k.PublicFingerprint == certSHA256 {
		t.Errorf("public_fingerprint is the whole-cert SHA-256, not the SPKI fingerprint")
	}

	// algorithm_id resolved against the catalogue → algorithm_ref (alg.name) set.
	if k.AlgorithmRef == nil || *k.AlgorithmRef == "" {
		t.Errorf("algorithm_ref not resolved (RSA-2048 should match the algorithms catalogue)")
	}

	// Linked to the implementation → deployment_count = 1, drawer resolves.
	if k.DeploymentCount == nil || *k.DeploymentCount != 1 {
		t.Errorf("deployment_count = %v, want 1", k.DeploymentCount)
	}
	impls, err := svc.GetKeyImplementations(tenant, k.ID)
	if err != nil {
		t.Fatalf("GetKeyImplementations: %v", err)
	}
	if len(impls) != 1 || impls[0].ImplementationID != implID {
		t.Errorf("GetKeyImplementations = %+v, want the one implementation %s", impls, implID)
	}
}

func TestIntegration_KeyProducer_DedupsSameKeyAcrossAssets(t *testing.T) {
	svc, db, tenant := newKeysSvc(t)

	pemStr, certSHA256 := selfSignedRSACert(t, "shared-key.example")
	cn := "shared-key.example"
	mkCert := func() *models.Certificate {
		return &models.Certificate{ID: uuid.New(), TenantID: tenant, CertificateState: "active", CommonName: &cn}
	}
	data := models.CertificateData{
		PublicKeyAlgorithm: "RSA",
		PublicKeySize:      2048,
		FingerprintSHA256:  certSHA256,
		CertificatePEM:     pemStr,
		KeyUsage:           []string{"DigitalSignature"},
	}

	// Same public key presented on two different assets/implementations.
	_, impl1 := insertAssetAndImpl(t, db, tenant)
	_, impl2 := insertAssetAndImpl(t, db, tenant)
	svc.produceKeyFromCertificate(tenant, impl1, mkCert(), data)
	svc.produceKeyFromCertificate(tenant, impl2, mkCert(), data)

	keys, err := svc.ListKeys(tenant)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("dedup failed: %d key rows for one public key, want 1", len(keys))
	}
	if keys[0].DeploymentCount == nil || *keys[0].DeploymentCount != 2 {
		t.Errorf("deployment_count = %v, want 2 (used by both assets)", keys[0].DeploymentCount)
	}
}
