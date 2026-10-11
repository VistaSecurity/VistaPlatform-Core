package certtrust_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services/certtrust"
)

// issueWithAIA is issue() with caIssuers URLs on the certificate.
func issueWithAIA(t *testing.T, cn string, isCA bool, parent *issued, aia ...string) issued {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano() + serial.Add(1)),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Example AIA Test " + uuid.NewString()[:8]}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		IssuingCertificateURL: aia,
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

// aiaRepo is a CA repository on loopback. The platform guard refuses
// loopback, so the evaluator under test is given a permissive guard
// (WithAIAGuard) — the fetch still goes through the guarded client.
type aiaRepo struct {
	srv   *httptest.Server
	mu    sync.Mutex
	files map[string][]byte
	hits  int
}

func newAIARepo(t *testing.T) *aiaRepo {
	r := &aiaRepo{files: map[string][]byte{}}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		body, ok := r.files[req.URL.Path]
		r.hits++
		r.mu.Unlock()
		if !ok {
			http.NotFound(w, req)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *aiaRepo) put(path string, body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.files[path] = body
}

func (r *aiaRepo) url(path string) string { return r.srv.URL + path }

func allowLoopback(netip.Addr) error { return nil }

func (f fixture) idByFingerprint(t *testing.T, c *x509.Certificate) (uuid.UUID, string, string) {
	t.Helper()
	var id uuid.UUID
	var chainSource, dataSource string
	if err := f.raw.QueryRow(`SELECT id, COALESCE(chain_source,''), COALESCE(data_source,'') FROM certificates
		WHERE tenant_id = $1 AND fingerprint_sha256 = $2`, f.tenant, certtrustFingerprint(c)).
		Scan(&id, &chainSource, &dataSource); err != nil {
		t.Fatalf("%s not stored for the tenant: %v", c.Subject.CommonName, err)
	}
	return id, chainSource, dataSource
}

// TestIntegration_TrustChainCompletedByAIA: only the leaf is observed; its
// intermediate (DER) and root (PEM) are fetched from caIssuers URLs, stored
// with chain_source 'aia', linked, and the leaf's verdict follows a decision
// on the fetched root.
func TestIntegration_TrustChainCompletedByAIA(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	repo := newAIARepo(t)

	root := issueWithAIA(t, "Example Private Root", true, nil)
	inter := issueWithAIA(t, "Example Issuing CA", true, &root, repo.url("/root.pem"))
	leaf := issueWithAIA(t, "app.example.test", false, &inter, repo.url("/inter.cer"))
	repo.put("/root.pem", []byte(pemOf(root.cert)))
	repo.put("/inter.cer", inter.cert.Raw)

	eval := f.eval.WithAIAGuard(allowLoopback).WithRoots(staticRoots{})
	f.certs.SetTrustEvaluator(eval)
	store := certtrust.NewStore(f.db, eval, f.certs)

	// Ingest evaluates LocalOnly: nothing local has the issuer, so the leaf is
	// incomplete for now and the completion is queued in the background.
	leafID := f.ingest(t, leaf.cert)[0]

	// The background worker completes it; poll rather than sleep.
	deadline := time.Now().Add(20 * time.Second)
	for {
		r := f.trust(t, leafID)
		if r.status.Valid && r.status.String == certtrust.StatusUntrusted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("leaf trust_status = %v after the background completion, want untrusted", r.status)
		}
		time.Sleep(100 * time.Millisecond)
	}

	interID, interSrc, interData := f.idByFingerprint(t, inter.cert)
	rootID, rootSrc, rootData := f.idByFingerprint(t, root.cert)
	if interSrc != certtrust.ChainSourceAIA || rootSrc != certtrust.ChainSourceAIA {
		t.Errorf("chain_source inter/root = %s/%s, want aia/aia", interSrc, rootSrc)
	}
	if interData != certtrust.DataSourceAIA || rootData != certtrust.DataSourceAIA {
		t.Errorf("data_source inter/root = %s/%s, want aia/aia", interData, rootData)
	}
	f.wantTrust(t, "leaf, completed by AIA", leafID, certtrust.StatusUntrusted, rootID)
	f.wantTrust(t, "fetched intermediate", interID, certtrust.StatusUntrusted, rootID)
	f.wantTrust(t, "fetched root", rootID, certtrust.StatusSelfSigned, rootID)

	if _, err := store.CreateAnchor(ctx, f.tenant, certtrust.CreateRequest{CertificateID: &rootID, Decision: certtrust.DecisionTrusted}); err != nil {
		t.Fatalf("trust fetched root: %v", err)
	}
	f.wantTrust(t, "leaf, fetched root trusted", leafID, certtrust.StatusPrivateTrusted, rootID)
}

// TestIntegration_TrustAIAFailureIsCachedAndInline: a direct (not LocalOnly)
// evaluation fetches inline; a dead URL leaves the chain incomplete and is not
// fetched again within the hour.
func TestIntegration_TrustAIAFailureIsCachedAndInline(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	repo := newAIARepo(t)

	root := issueWithAIA(t, "Example Root", true, nil)
	leaf := issueWithAIA(t, "dead.example.test", false, &root, repo.url("/missing.cer"))

	// Store without evaluating anything over the network: the default
	// evaluator has no loopback access.
	eval := f.eval.WithAIAGuard(allowLoopback).WithRoots(staticRoots{})
	leafID := f.ingest(t, leaf.cert)[0]

	for i := 0; i < 3; i++ {
		v, err := eval.Evaluate(ctx, f.tenant, leafID)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if v.Status != certtrust.StatusIncomplete {
			t.Fatalf("status = %s, want incomplete (the URL is dead)", v.Status)
		}
	}
	repo.mu.Lock()
	hits := repo.hits
	repo.mu.Unlock()
	if hits != 1 {
		t.Errorf("the dead URL was fetched %d times in three evaluations, want 1 (failure cache)", hits)
	}

	// Inline success: the URL now serves the root.
	repo.put("/missing.cer", root.cert.Raw)
	eval2 := f.eval.WithAIAGuard(allowLoopback).WithRoots(staticRoots{})
	v, err := eval2.Evaluate(ctx, f.tenant, leafID)
	if err != nil || v.Status != certtrust.StatusUntrusted {
		t.Fatalf("after the repository came back: status=%s err=%v, want untrusted", v.Status, err)
	}
}
