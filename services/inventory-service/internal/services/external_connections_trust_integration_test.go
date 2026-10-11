package services

// 3rd-party connections read the tenant's trust decisions ( slice 3):
// trust_status is the verdict on the leaf the server presented, and the
// "untrusted certificate authority" hygiene flag follows the tenant's
// decision rather than the probing runtime's OS store.
//
// Skips without TEST_DATABASE_URL (`make test-integration-db`).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services/certtrust"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type extPKI struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func extIssue(t *testing.T, cn string, isCA bool, parent *extPKI) extPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Example Ext Trust " + uuid.NewString()[:8]}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
	}
	if isCA {
		tpl.IsCA, tpl.BasicConstraintsValid = true, true
		tpl.KeyUsage = x509.KeyUsageCertSign
	} else {
		tpl.DNSNames = []string{cn}
	}
	signer, signerKey := tpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return extPKI{cert: c, key: key}
}

func extPEM(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func TestIntegration_ExternalConnections_FollowTenantTrust(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	ctx := context.Background()

	certs := NewCertificateService(db, nil)
	eval := certtrust.NewEvaluator(db).WithAIAGuard(nil)
	certs.SetTrustEvaluator(eval)
	store := certtrust.NewStore(db, eval, certs)
	svc := NewExternalConnectionsService(db, NewAlgorithmService(db))
	svc.SetTrustEvaluator(eval)

	// The vendor's private CA is in the tenant's inventory (seen elsewhere);
	// the connection carries only the leaf.
	root := extIssue(t, "Vendor Root", true, nil)
	inter := extIssue(t, "Vendor Issuing CA", true, &root)
	leaf := extIssue(t, "api.vendor.example", false, &inter)
	var ids []uuid.UUID
	for _, c := range []*x509.Certificate{inter.cert, root.cert} {
		stored, err := certs.FindOrCreateCertificate(tenant, certtrust.CertificateDataFromX509(c))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, stored.ID)
	}
	if err := certs.LinkCertificateIssuer(tenant, ids[0], ids[1]); err != nil {
		t.Fatal(err)
	}
	rootID := ids[1]

	upsert := func() *models.ExternalConnection {
		t.Helper()
		pemText, status := extPEM(leaf.cert), "untrusted_ca"
		c, err := svc.Upsert(tenant, models.ExternalConnectionUpsert{
			SourceIP: "192.0.2.80", DestIP: "198.51.100.80", DestPort: 443, Protocol: "TLS",
			CipherSuite: strPtr("TLS_AES_256_GCM_SHA384"), CertPEM: &pemText, CertValidationStatus: &status,
		})
		if err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		return c
	}
	stored := func(id uuid.UUID) (string, []string) {
		t.Helper()
		var ts *string
		var arr pq.StringArray
		if err := raw.QueryRow(`SELECT trust_status, COALESCE(cert_hygiene_flags, '{}'::text[]) FROM external_connections WHERE id = $1`, id).
			Scan(&ts, &arr); err != nil {
			t.Fatal(err)
		}
		flags := []string(arr)
		if ts == nil {
			return "", flags
		}
		return *ts, flags
	}
	has := func(flags []string, f string) bool {
		for _, x := range flags {
			if x == f {
				return true
			}
		}
		return false
	}
	trustIssue := func() int {
		t.Helper()
		yes := true
		_, total, err := svc.List(tenant, models.ExternalConnectionFilters{CertTrustIssue: &yes, Page: 1, PageSize: 50})
		if err != nil {
			t.Fatal(err)
		}
		return total
	}

	conn := upsert()
	if ts, flags := stored(conn.ID); ts != certtrust.StatusUntrusted || !has(flags, certtrust.HygieneUntrustedCA) {
		t.Fatalf("no decision: trust_status=%q flags=%q, want untrusted + the untrusted-CA flag", ts, flags)
	}
	if n := trustIssue(); n != 1 {
		t.Errorf("cert_trust_issue with no decision = %d, want 1", n)
	}

	// Trust the vendor root: the decision's recompute rewrites the row.
	a, err := store.CreateAnchor(ctx, tenant, certtrust.CreateRequest{CertificateID: &rootID, Decision: certtrust.DecisionTrusted})
	if err != nil {
		t.Fatal(err)
	}
	if ts, flags := stored(conn.ID); ts != certtrust.StatusPrivateTrusted || has(flags, certtrust.HygieneUntrustedCA) {
		t.Fatalf("root trusted: trust_status=%q flags=%q, want private_trusted and no untrusted-CA flag", ts, flags)
	}
	if n := trustIssue(); n != 0 {
		t.Errorf("cert_trust_issue after trusting the CA = %d, want 0", n)
	}
	// A re-observation still says untrusted_ca; the tenant's decision wins,
	// and the accumulated prior flags do not bring the flag back.
	conn = upsert()
	if ts, flags := stored(conn.ID); ts != certtrust.StatusPrivateTrusted || has(flags, certtrust.HygieneUntrustedCA) {
		t.Fatalf("re-observed after trust: trust_status=%q flags=%q", ts, flags)
	}
	// Nor does the catalogue reassessment pass.
	if _, _, err := svc.ReassessBatch(ctx, tenant, uuid.Nil, 200); err != nil {
		t.Fatal(err)
	}
	if _, flags := stored(conn.ID); has(flags, certtrust.HygieneUntrustedCA) {
		t.Fatalf("reassessment re-added the untrusted-CA flag: %q", flags)
	}

	// Distrust it: the distrusted flag, and a trust issue whatever the probe said.
	d := certtrust.DecisionDistrusted
	if _, err := store.UpdateAnchor(ctx, tenant, a.ID, certtrust.UpdateRequest{Decision: &d}); err != nil {
		t.Fatal(err)
	}
	if ts, flags := stored(conn.ID); ts != certtrust.StatusDistrusted || !has(flags, certtrust.HygieneDistrustedCA) || has(flags, certtrust.HygieneUntrustedCA) {
		t.Fatalf("root distrusted: trust_status=%q flags=%q, want distrusted + only the distrusted flag", ts, flags)
	}
	if n := trustIssue(); n != 1 {
		t.Errorf("cert_trust_issue after distrust = %d, want 1", n)
	}

	// Removed: back to the probe's verdict.
	if err := store.DeleteAnchor(ctx, tenant, a.ID); err != nil {
		t.Fatal(err)
	}
	if ts, flags := stored(conn.ID); ts != certtrust.StatusUntrusted || !has(flags, certtrust.HygieneUntrustedCA) || has(flags, certtrust.HygieneDistrustedCA) {
		t.Fatalf("decision removed: trust_status=%q flags=%q", ts, flags)
	}
}
