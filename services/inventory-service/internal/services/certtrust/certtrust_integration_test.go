package certtrust_test

// Real-Postgres tests for tenant certificate trust. They skip without
// TEST_DATABASE_URL (nightly test-backend / make test-integration-db).
//
// Certificates are generated per test, so nothing depends on the contents of
// the embedded Mozilla bundle; the bundle-completion test substitutes a
// RootStore holding a generated root.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services/certtrust"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// --- generated PKI -----------------------------------------------------------

type issued struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serial atomic.Int64

func issue(t *testing.T, cn string, isCA bool, parent *issued) issued {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + serial.Add(1)),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Example Trust Test " + uuid.NewString()[:8]}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	if isCA {
		tpl.IsCA = true
		tpl.BasicConstraintsValid = true
		tpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tpl.DNSNames = []string{cn}
		tpl.KeyUsage = x509.KeyUsageDigitalSignature
	}
	signerCert, signerKey := tpl, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return issued{cert: c, key: key}
}

func pemOf(certs ...*x509.Certificate) string {
	var b strings.Builder
	for _, c := range certs {
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return b.String()
}

// --- fixture -------------------------------------------------------------------

type fixture struct {
	raw    *sql.DB
	db     *database.DB
	tenant uuid.UUID
	certs  *services.CertificateService
	eval   *certtrust.Evaluator
	store  *certtrust.Store
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	certs := services.NewCertificateService(db, nil)
	eval := certtrust.NewEvaluator(db)
	certs.SetTrustEvaluator(eval)
	return fixture{raw: raw, db: db, tenant: tenant, certs: certs, eval: eval, store: certtrust.NewStore(db, eval, certs)}
}

// ingest stores a chain the way discovery does: each certificate through
// FindOrCreateCertificate, leaf first, then each linked to its issuer.
func (f fixture) ingest(t *testing.T, chain ...*x509.Certificate) []uuid.UUID {
	t.Helper()
	ids := make([]uuid.UUID, len(chain))
	for i, c := range chain {
		stored, err := f.certs.FindOrCreateCertificate(f.tenant, certtrust.CertificateDataFromX509(c))
		if err != nil {
			t.Fatalf("store %s: %v", c.Subject.CommonName, err)
		}
		ids[i] = stored.ID
		if i > 0 {
			if err := f.certs.LinkCertificateIssuer(f.tenant, ids[i-1], ids[i]); err != nil {
				t.Fatalf("link: %v", err)
			}
		}
	}
	return ids
}

type trustRow struct {
	status, chainSource sql.NullString
	anchor              uuid.NullUUID
	evaluatedAt         sql.NullTime
}

func (f fixture) trust(t *testing.T, id uuid.UUID) trustRow {
	t.Helper()
	var r trustRow
	if err := f.raw.QueryRow(`SELECT trust_status, trust_anchor_certificate_id, trust_evaluated_at, chain_source
		FROM certificates WHERE tenant_id = $1 AND id = $2`, f.tenant, id).
		Scan(&r.status, &r.anchor, &r.evaluatedAt, &r.chainSource); err != nil {
		t.Fatalf("read trust of %s: %v", id, err)
	}
	return r
}

func (f fixture) wantTrust(t *testing.T, label string, id uuid.UUID, status string, anchor uuid.UUID) {
	t.Helper()
	r := f.trust(t, id)
	if !r.status.Valid || r.status.String != status {
		t.Errorf("%s: trust_status = %v, want %s", label, r.status, status)
	}
	if !r.anchor.Valid || r.anchor.UUID != anchor {
		t.Errorf("%s: trust_anchor_certificate_id = %v, want %s", label, r.anchor, anchor)
	}
	if !r.evaluatedAt.Valid {
		t.Errorf("%s: trust_evaluated_at is NULL", label)
	}
}

// --- tests -----------------------------------------------------------------------

// TestIntegration_TrustRecomputeOnAnchorChange walks one private chain through
// every decision: none -> trusted -> distrusted -> removed.
func TestIntegration_TrustRecomputeOnAnchorChange(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	root := issue(t, "Example Private Root", true, nil)
	inter := issue(t, "Example Private Issuing CA", true, &root)
	leaf := issue(t, "app.example.test", false, &inter)
	ids := f.ingest(t, leaf.cert, inter.cert, root.cert)
	leafID, interID, rootID := ids[0], ids[1], ids[2]

	// A deployed leaf, so affected_assets has something to count.
	asset := uuid.New()
	if _, err := f.raw.Exec(`INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, asset_ownership, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1, $2, 'app', 'server', 'hardware.computer.server', 'monitoring', 'internal', NOW(), NOW(), NOW(), NOW())`, asset, f.tenant); err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	if _, err := f.raw.Exec(`INSERT INTO crypto_implementations (id, tenant_id, asset_id, protocol, certificate_id, discovery_method, created_at, updated_at)
		VALUES ($1, $2, $3, 'TLS', $4, 'passive', NOW(), NOW())`, uuid.New(), f.tenant, asset, leafID); err != nil {
		t.Fatalf("insert crypto implementation: %v", err)
	}

	// No decision: the chain ends at a self-signed root nobody trusted.
	f.wantTrust(t, "leaf, no decision", leafID, certtrust.StatusUntrusted, rootID)
	f.wantTrust(t, "intermediate, no decision", interID, certtrust.StatusUntrusted, rootID)
	f.wantTrust(t, "root alone, no decision", rootID, certtrust.StatusSelfSigned, rootID)

	created, err := f.store.CreateAnchor(ctx, f.tenant, certtrust.CreateRequest{CertificateID: &rootID, Decision: certtrust.DecisionTrusted, Note: "our private root", DecidedBy: uuid.New()})
	if err != nil {
		t.Fatalf("CreateAnchor: %v", err)
	}
	f.wantTrust(t, "leaf, trusted root", leafID, certtrust.StatusPrivateTrusted, rootID)
	f.wantTrust(t, "intermediate, trusted root", interID, certtrust.StatusPrivateTrusted, rootID)
	f.wantTrust(t, "root, trusted", rootID, certtrust.StatusPrivateTrusted, rootID)
	if created.AffectedCertificates != 2 || created.AffectedAssets != 1 {
		t.Errorf("affected = %d certificates / %d assets, want 2 / 1", created.AffectedCertificates, created.AffectedAssets)
	}
	if created.Note == nil || *created.Note != "our private root" || created.DecidedBy == nil {
		t.Errorf("note / decided_by not recorded: %+v", created)
	}
	if !created.Certificate.IsCACertificate || created.Certificate.FingerprintSHA256 == "" {
		t.Errorf("certificate projection incomplete: %+v", created.Certificate)
	}

	// The reads the UI uses carry the verdict.
	got, err := f.certs.GetCertificateByID(f.tenant, leafID)
	if err != nil || got.TrustStatus == nil || *got.TrustStatus != certtrust.StatusPrivateTrusted ||
		got.TrustAnchorCertificateID == nil || *got.TrustAnchorCertificateID != rootID || got.TrustEvaluatedAt == nil {
		t.Errorf("GetCertificateByID trust fields = %+v (err %v)", got, err)
	}
	byAsset, err := f.certs.GetCertificatesByAssetID(f.tenant, asset)
	if err != nil {
		t.Fatalf("GetCertificatesByAssetID: %v", err)
	}
	if len(byAsset) != 1 || byAsset[0].TrustStatus == nil || *byAsset[0].TrustStatus != certtrust.StatusPrivateTrusted {
		t.Errorf("GetCertificatesByAssetID = %+v, want the leaf, private_trusted", byAsset)
	}
	chain, err := f.certs.GetCertificateChain(f.tenant, leafID)
	if err != nil || len(chain) != 3 || chain[2].TrustStatus == nil {
		t.Errorf("GetCertificateChain = %d certs (err %v), want 3 with trust fields", len(chain), err)
	}

	distrusted := certtrust.DecisionDistrusted
	updated, err := f.store.UpdateAnchor(ctx, f.tenant, created.ID, certtrust.UpdateRequest{Decision: &distrusted, DecidedBy: uuid.New()})
	if err != nil {
		t.Fatalf("UpdateAnchor: %v", err)
	}
	if updated.Decision != certtrust.DecisionDistrusted || !updated.DecidedAt.After(created.DecidedAt) {
		t.Errorf("updated decision = %s decided_at %v (was %v)", updated.Decision, updated.DecidedAt, created.DecidedAt)
	}
	f.wantTrust(t, "leaf, distrusted root", leafID, certtrust.StatusDistrusted, rootID)
	f.wantTrust(t, "intermediate, distrusted root", interID, certtrust.StatusDistrusted, rootID)

	list, err := f.store.ListAnchors(ctx, f.tenant)
	if err != nil || len(list) != 1 || list[0].ID != created.ID {
		t.Fatalf("ListAnchors = %+v (err %v)", list, err)
	}

	if err := f.store.DeleteAnchor(ctx, f.tenant, created.ID); err != nil {
		t.Fatalf("DeleteAnchor: %v", err)
	}
	f.wantTrust(t, "leaf, decision removed", leafID, certtrust.StatusUntrusted, rootID)
	f.wantTrust(t, "intermediate, decision removed", interID, certtrust.StatusUntrusted, rootID)
	if err := f.store.DeleteAnchor(ctx, f.tenant, created.ID); !errors.Is(err, certtrust.ErrAnchorNotFound) {
		t.Errorf("second DeleteAnchor = %v, want ErrAnchorNotFound", err)
	}
}

// TestIntegration_TrustEvaluatedOnCertificateCreate is the WIRING test: a
// certificate stored through CertificateService must leave with a verdict.
// Deleting the evaluateTrust call in CreateCertificate turns it red.
func TestIntegration_TrustEvaluatedOnCertificateCreate(t *testing.T) {
	f := newFixture(t)
	selfSigned := issue(t, "standalone.example.test", false, nil)
	data := certtrust.CertificateDataFromX509(selfSigned.cert)
	created, err := f.certs.CreateCertificate(f.tenant, data)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	r := f.trust(t, created.ID)
	if !r.status.Valid {
		t.Fatal("trust_status is NULL after CreateCertificate: the ingest hook did not run")
	}
	if r.status.String != certtrust.StatusSelfSigned {
		t.Errorf("trust_status = %s, want self_signed", r.status.String)
	}
	if created.TrustStatus == nil || *created.TrustStatus != certtrust.StatusSelfSigned {
		t.Errorf("CreateCertificate response trust_status = %v, want self_signed", created.TrustStatus)
	}

	// A leaf whose issuer is not in inventory is incomplete, not trusted.
	ca := issue(t, "Absent CA", true, nil)
	orphan := issue(t, "orphan.example.test", false, &ca)
	stored, err := f.certs.FindOrCreateCertificate(f.tenant, certtrust.CertificateDataFromX509(orphan.cert))
	if err != nil {
		t.Fatalf("FindOrCreateCertificate: %v", err)
	}
	f.wantTrust(t, "orphan leaf", stored.ID, certtrust.StatusIncomplete, stored.ID)
}

// staticRoots is a RootStore holding generated roots.
type staticRoots struct{ roots []*x509.Certificate }

func (s staticRoots) Lookup(fp string) *x509.Certificate {
	for _, r := range s.roots {
		if certtrustFingerprint(r) == strings.ToLower(fp) {
			return r
		}
	}
	return nil
}

func (s staticRoots) FindIssuer(c *x509.Certificate) *x509.Certificate {
	for _, r := range s.roots {
		if string(r.RawSubject) == string(c.RawIssuer) && c.CheckSignatureFrom(r) == nil {
			return r
		}
	}
	return nil
}

func certtrustFingerprint(c *x509.Certificate) string {
	return certtrust.CertificateDataFromX509(c).FingerprintSHA256
}

// TestIntegration_TrustCompletedFromPublicBundle: an intermediate whose root is
// only in the public bundle is completed from it — the root is stored for the
// tenant with chain_source 'bundle' and the chain is public. An explicit
// distrust of that root overrides the bundle; removing it restores public.
func TestIntegration_TrustCompletedFromPublicBundle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	root := issue(t, "Example Public Root", true, nil)
	inter := issue(t, "Example Public Issuing CA", true, &root)
	leaf := issue(t, "www.example.test", false, &inter)

	eval := f.eval.WithRoots(staticRoots{roots: []*x509.Certificate{root.cert}})
	f.certs.SetTrustEvaluator(eval)
	store := certtrust.NewStore(f.db, eval, f.certs)

	ids := f.ingest(t, leaf.cert, inter.cert)
	leafID, interID := ids[0], ids[1]

	var rootID uuid.UUID
	var chainSource, dataSource string
	if err := f.raw.QueryRow(`SELECT id, chain_source, data_source FROM certificates WHERE tenant_id = $1 AND fingerprint_sha256 = $2`,
		f.tenant, certtrustFingerprint(root.cert)).Scan(&rootID, &chainSource, &dataSource); err != nil {
		t.Fatalf("bundle root not stored for the tenant: %v", err)
	}
	if chainSource != certtrust.ChainSourceBundle || dataSource != certtrust.DataSourceBundle {
		t.Errorf("bundle root chain_source/data_source = %s/%s, want bundle/bundle", chainSource, dataSource)
	}
	f.wantTrust(t, "leaf via bundle", leafID, certtrust.StatusPublic, rootID)
	f.wantTrust(t, "intermediate via bundle", interID, certtrust.StatusPublic, rootID)
	f.wantTrust(t, "bundle root", rootID, certtrust.StatusPublic, rootID)

	a, err := store.CreateAnchor(ctx, f.tenant, certtrust.CreateRequest{CertificateID: &rootID, Decision: certtrust.DecisionDistrusted})
	if err != nil {
		t.Fatalf("distrust public root: %v", err)
	}
	f.wantTrust(t, "leaf, distrusted public root", leafID, certtrust.StatusDistrusted, rootID)
	if err := store.DeleteAnchor(ctx, f.tenant, a.ID); err != nil {
		t.Fatalf("DeleteAnchor: %v", err)
	}
	f.wantTrust(t, "leaf, distrust removed", leafID, certtrust.StatusPublic, rootID)
}

// TestIntegration_TrustAnchorFromPEM covers the certificate_pem path and the
// request errors.
func TestIntegration_TrustAnchorFromPEM(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	root := issue(t, "Uploaded Root", true, nil)
	inter := issue(t, "Uploaded Issuing CA", true, &root)
	leaf := issue(t, "uploaded-leaf.example.test", false, &inter)

	// The leaf was seen first; its chain is incomplete until the CAs arrive.
	leafIDs := f.ingest(t, leaf.cert)
	f.wantTrust(t, "leaf before upload", leafIDs[0], certtrust.StatusIncomplete, leafIDs[0])

	// Root listed LAST: the decision is recorded against it.
	a, err := f.store.CreateAnchor(ctx, f.tenant, certtrust.CreateRequest{CertificatePEM: pemOf(inter.cert, root.cert), Decision: certtrust.DecisionTrusted})
	if err != nil {
		t.Fatalf("CreateAnchor(pem): %v", err)
	}
	if a.Certificate.FingerprintSHA256 != certtrustFingerprint(root.cert) {
		t.Fatalf("decision recorded against %s, want the last certificate in the file (the root)", a.Certificate.SubjectDN)
	}
	var interID uuid.UUID
	var interIssuer uuid.NullUUID
	var interSource sql.NullString
	if err := f.raw.QueryRow(`SELECT id, issuer_certificate_id, chain_source FROM certificates WHERE tenant_id = $1 AND fingerprint_sha256 = $2`,
		f.tenant, certtrustFingerprint(inter.cert)).Scan(&interID, &interIssuer, &interSource); err != nil {
		t.Fatalf("uploaded intermediate not stored: %v", err)
	}
	if !interIssuer.Valid || interIssuer.UUID != a.CertificateID {
		t.Errorf("uploaded intermediate issuer link = %v, want the uploaded root %s", interIssuer, a.CertificateID)
	}
	if interSource.String != certtrust.ChainSourceUpload {
		t.Errorf("uploaded intermediate chain_source = %v, want upload", interSource)
	}
	f.wantTrust(t, "uploaded intermediate", interID, certtrust.StatusPrivateTrusted, a.CertificateID)

	// The earlier leaf is linked once its issuer exists (chain rebuild), and
	// then picks up the decision.
	if _, err := f.certs.RebuildCertificateChain(f.tenant, leafIDs[0]); err != nil {
		t.Fatalf("RebuildCertificateChain: %v", err)
	}
	f.wantTrust(t, "leaf after rebuild", leafIDs[0], certtrust.StatusPrivateTrusted, a.CertificateID)

	// Duplicate decision -> conflict naming the existing one.
	_, err = f.store.CreateAnchor(ctx, f.tenant, certtrust.CreateRequest{CertificatePEM: pemOf(root.cert), Decision: certtrust.DecisionDistrusted})
	var conflict *certtrust.ErrConflict
	if !errors.As(err, &conflict) || conflict.ExistingID != a.ID {
		t.Errorf("duplicate CreateAnchor = %v, want ErrConflict naming %s", err, a.ID)
	}

	invalid := []certtrust.CreateRequest{
		{CertificatePEM: pemOf(leaf.cert), Decision: certtrust.DecisionTrusted},                          // not a CA
		{CertificatePEM: "not pem", Decision: certtrust.DecisionTrusted},                                 // no block
		{CertificateID: &leafIDs[0], Decision: certtrust.DecisionTrusted},                                // not a CA
		{CertificateID: ptr(uuid.New()), Decision: certtrust.DecisionTrusted},                            // not in inventory
		{CertificateID: &interID, CertificatePEM: pemOf(root.cert), Decision: certtrust.DecisionTrusted}, // both
		{Decision: certtrust.DecisionTrusted},                                                            // neither
		{CertificateID: &interID, Decision: "maybe"},                                                     // bad decision
		{CertificateID: &interID, Decision: certtrust.DecisionTrusted, Note: strings.Repeat("x", 1001)},  // note too long
	}
	for i, req := range invalid {
		var inv *certtrust.ErrInvalid
		if _, err := f.store.CreateAnchor(ctx, f.tenant, req); !errors.As(err, &inv) {
			t.Errorf("invalid request %d: err = %v, want ErrInvalid", i, err)
		}
	}
}

func ptr[T any](v T) *T { return &v }

// TestIntegration_TrustAnchors_TenantIsolation runs as the RLS-subject app
// role: tenant B cannot see, change or delete tenant A's decision, and the
// policy itself (not only the WHERE clause) hides the row.
func TestIntegration_TrustAnchors_TenantIsolation(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenantA := testdb.NewTenant(t, owner)
	tenantB := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	db := &database.DB{DB: sqlx.NewDb(app, "postgres")}
	certs := services.NewCertificateService(db, nil)
	eval := certtrust.NewEvaluator(db)
	certs.SetTrustEvaluator(eval)
	store := certtrust.NewStore(db, eval, certs)
	ctx := context.Background()

	root := issue(t, "Tenant A Root", true, nil)
	a, err := store.CreateAnchor(ctx, tenantA, certtrust.CreateRequest{CertificatePEM: pemOf(root.cert), Decision: certtrust.DecisionTrusted})
	if err != nil {
		t.Fatalf("tenant A CreateAnchor: %v", err)
	}

	listB, err := store.ListAnchors(ctx, tenantB)
	if err != nil || len(listB) != 0 {
		t.Errorf("tenant B ListAnchors = %d anchors (err %v), want 0", len(listB), err)
	}
	if _, err := store.GetAnchor(ctx, tenantB, a.ID); !errors.Is(err, certtrust.ErrAnchorNotFound) {
		t.Errorf("tenant B GetAnchor = %v, want ErrAnchorNotFound", err)
	}
	d := certtrust.DecisionDistrusted
	if _, err := store.UpdateAnchor(ctx, tenantB, a.ID, certtrust.UpdateRequest{Decision: &d}); !errors.Is(err, certtrust.ErrAnchorNotFound) {
		t.Errorf("tenant B UpdateAnchor = %v, want ErrAnchorNotFound", err)
	}
	if err := store.DeleteAnchor(ctx, tenantB, a.ID); !errors.Is(err, certtrust.ErrAnchorNotFound) {
		t.Errorf("tenant B DeleteAnchor = %v, want ErrAnchorNotFound", err)
	}
	// Tenant B cannot name A's CA by id either.
	if _, err := store.CreateAnchor(ctx, tenantB, certtrust.CreateRequest{CertificateID: &a.CertificateID, Decision: certtrust.DecisionDistrusted}); err == nil {
		t.Error("tenant B recorded a decision on tenant A's certificate")
	}

	// The policy, not just the WHERE: no tenant filter, tenant B's context.
	var visible int
	if err := database.WithTenantTx(ctx, db, tenantB, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`SELECT COUNT(*) FROM tenant_trust_anchors WHERE id = $1`, a.ID).Scan(&visible)
	}); err != nil {
		t.Fatalf("count under tenant B: %v", err)
	}
	if visible != 0 {
		t.Errorf("tenant B sees %d of tenant A's anchors through RLS, want 0", visible)
	}

	listA, err := store.ListAnchors(ctx, tenantA)
	if err != nil || len(listA) != 1 || listA[0].Decision != certtrust.DecisionTrusted {
		t.Errorf("tenant A's decision did not survive tenant B's attempts: %+v (err %v)", listA, err)
	}
}
