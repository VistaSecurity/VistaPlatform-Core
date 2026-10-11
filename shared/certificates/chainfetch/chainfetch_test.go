package chainfetch

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
)

type node struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serial int64

func issue(t *testing.T, cn string, parent *node, isCA bool, aia []string) *node {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial++
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Chainfetch Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		IssuingCertificateURL: aia,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &node{cert: c, key: key}
}

func pemOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// allowAll is the guard for tests that serve from httptest on loopback: the
// fetch still goes through GuardedHTTPClient (no redirects, no proxy).
func allowAll(netip.Addr) error { return nil }

// aiaServer serves whatever body is registered for a path.
type aiaServer struct {
	*httptest.Server
	mu     sync.Mutex
	bodies map[string][]byte
	hits   map[string]int
}

func newAIAServer(t *testing.T) *aiaServer {
	s := &aiaServer{bodies: map[string][]byte{}, hits: map[string]int{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		body, ok := s.bodies[r.URL.Path]
		s.hits[r.URL.Path]++
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *aiaServer) serve(path string, body []byte) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bodies[path] = body
	return s.URL + path
}

func noBundle(*x509.Certificate) *x509.Certificate { return nil }

func TestResolve_AIA_DERAndPEM(t *testing.T) {
	srv := newAIAServer(t)
	root := issue(t, "Root", nil, true, nil)
	// The intermediate's AIA serves the root as PEM; the leaf's serves the
	// intermediate as DER.
	rootURL := srv.serve("/root.pem", pemOf(root.cert))
	inter := issue(t, "Intermediate", root, true, []string{rootURL})
	interURL := srv.serve("/inter.cer", inter.cert.Raw)
	leaf := issue(t, "leaf.example", inter, false, []string{interURL})

	found, sources, err := Resolve(context.Background(), []*x509.Certificate{leaf.cert},
		Options{Guard: allowAll, Bundle: noBundle})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(found) != 2 || !found[0].Equal(inter.cert) || !found[1].Equal(root.cert) {
		t.Fatalf("found %d certs, want [intermediate, root]", len(found))
	}
	for i, s := range sources {
		if s != SourceAIA {
			t.Errorf("source[%d] = %s, want aia", i, s)
		}
	}
}

func TestResolve_LocalSourcesBeforeAIA(t *testing.T) {
	srv := newAIAServer(t)
	root := issue(t, "Root", nil, true, nil)
	interURL := srv.serve("/inter.cer", nil)
	inter := issue(t, "Intermediate", root, true, []string{srv.serve("/root.cer", root.cert.Raw)})
	srv.serve("/inter.cer", inter.cert.Raw)
	leaf := issue(t, "leaf.example", inter, false, []string{interURL})

	found, sources, err := Resolve(context.Background(), []*x509.Certificate{leaf.cert}, Options{
		Guard:         allowAll,
		Inventory:     func(_ context.Context, c *x509.Certificate) *x509.Certificate { return inter.cert },
		Bundle:        func(c *x509.Certificate) *x509.Certificate { return root.cert },
		TenantAnchors: func(context.Context, *x509.Certificate) *x509.Certificate { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 || sources[0] != SourceInventory || sources[1] != SourceBundle {
		t.Fatalf("sources = %v, want [inventory bundle]", sources)
	}
	if srv.hits["/inter.cer"]+srv.hits["/root.cer"] != 0 {
		t.Error("AIA was fetched although a local source had the issuer")
	}
}

func TestResolve_TenantAnchorSource(t *testing.T) {
	root := issue(t, "Private Root", nil, true, nil)
	leaf := issue(t, "leaf.internal", root, false, nil)
	found, sources, err := Resolve(context.Background(), []*x509.Certificate{leaf.cert}, Options{
		Bundle:        noBundle,
		TenantAnchors: func(context.Context, *x509.Certificate) *x509.Certificate { return root.cert },
	})
	if err != nil || len(found) != 1 || sources[0] != SourceTenantAnchor {
		t.Fatalf("found=%d sources=%v err=%v", len(found), sources, err)
	}
}

// A local source that returns the wrong certificate must not be used: the
// signature check is what makes every source safe.
func TestResolve_RejectsNonIssuerCandidates(t *testing.T) {
	root := issue(t, "Root", nil, true, nil)
	impostor := issue(t, "Root", nil, true, nil) // same name, different key
	leaf := issue(t, "leaf", root, false, nil)
	_, _, err := Resolve(context.Background(), []*x509.Certificate{leaf.cert}, Options{
		Bundle:    func(*x509.Certificate) *x509.Certificate { return impostor.cert },
		Inventory: func(context.Context, *x509.Certificate) *x509.Certificate { return impostor.cert },
	})
	if !errors.Is(err, ErrIssuerNotFound) {
		t.Fatalf("err = %v, want ErrIssuerNotFound", err)
	}
}

func TestResolve_OversizeBodyRefused(t *testing.T) {
	srv := newAIAServer(t)
	root := issue(t, "Root", nil, true, nil)
	big := append(pemOf(root.cert), bytes.Repeat([]byte("#"), DefaultMaxBytes)...)
	leaf := issue(t, "leaf", root, false, []string{srv.serve("/big.pem", big)})
	var failed error
	found, _, err := Resolve(context.Background(), []*x509.Certificate{leaf.cert}, Options{
		Guard: allowAll, Bundle: noBundle,
		OnFetchFailure: func(_ string, e error) { failed = e },
	})
	if len(found) != 0 || !errors.Is(err, ErrIssuerNotFound) {
		t.Fatalf("found=%d err=%v, want nothing and ErrIssuerNotFound", len(found), err)
	}
	if !errors.Is(failed, ErrBodyTooLarge) {
		t.Errorf("failure = %v, want ErrBodyTooLarge", failed)
	}
}

func TestResolve_RedirectRefused(t *testing.T) {
	other := newAIAServer(t)
	root := issue(t, "Root", nil, true, nil)
	target := other.serve("/root.cer", root.cert.Raw)
	redirector := httptest.NewServer(http.RedirectHandler(target, http.StatusFound))
	t.Cleanup(redirector.Close)
	leaf := issue(t, "leaf", root, false, []string{redirector.URL + "/root.cer"})

	var failed error
	found, _, err := Resolve(context.Background(), []*x509.Certificate{leaf.cert}, Options{
		Guard: allowAll, Bundle: noBundle,
		OnFetchFailure: func(_ string, e error) { failed = e },
	})
	if len(found) != 0 || !errors.Is(err, ErrIssuerNotFound) {
		t.Fatalf("found=%d err=%v: the redirect was followed", len(found), err)
	}
	if failed == nil || !strings.Contains(failed.Error(), "redirect") {
		t.Errorf("failure = %v, want a refused redirect", failed)
	}
	if other.hits["/root.cer"] != 0 {
		t.Error("the redirect target was contacted")
	}
}

// The platform's own guard refuses a caIssuers URL on loopback — the shape of
// a scanned server steering the platform at its own network.
func TestResolve_PlatformGuardRefusesPrivateAddress(t *testing.T) {
	srv := newAIAServer(t)
	root := issue(t, "Root", nil, true, nil)
	leaf := issue(t, "leaf", root, false, []string{srv.serve("/root.cer", root.cert.Raw)})

	var failed error
	found, _, err := Resolve(context.Background(), []*x509.Certificate{leaf.cert}, Options{
		Guard: dispatchguard.PlatformFetchGuard(), Bundle: noBundle,
		OnFetchFailure: func(_ string, e error) { failed = e },
	})
	if len(found) != 0 || !errors.Is(err, ErrIssuerNotFound) {
		t.Fatalf("found=%d err=%v: a loopback AIA URL was fetched", len(found), err)
	}
	if !errors.Is(failed, discovery.ErrOutboundAddressRefused) {
		t.Errorf("failure = %v, want the guard's refusal", failed)
	}
	if srv.hits["/root.cer"] != 0 {
		t.Error("the loopback server was contacted")
	}
}

func TestResolve_NoGuardMeansNoFetch(t *testing.T) {
	srv := newAIAServer(t)
	root := issue(t, "Root", nil, true, nil)
	leaf := issue(t, "leaf", root, false, []string{srv.serve("/root.cer", root.cert.Raw)})
	_, _, err := Resolve(context.Background(), []*x509.Certificate{leaf.cert}, Options{Bundle: noBundle})
	if !errors.Is(err, ErrIssuerNotFound) || srv.hits["/root.cer"] != 0 {
		t.Fatalf("err=%v hits=%d: fetched without a guard", err, srv.hits["/root.cer"])
	}
}

func TestResolve_MaxHops(t *testing.T) {
	srv := newAIAServer(t)
	// A chain of 8 CAs, each pointing by AIA at its issuer.
	parent := issue(t, "CA 0", nil, true, nil)
	url := srv.serve("/ca0.cer", parent.cert.Raw)
	for i := 1; i < 8; i++ {
		n := issue(t, fmt.Sprintf("CA %d", i), parent, true, []string{url})
		url = srv.serve(fmt.Sprintf("/ca%d.cer", i), n.cert.Raw)
		parent = n
	}
	leaf := issue(t, "leaf", parent, false, []string{url})

	found, _, err := Resolve(context.Background(), []*x509.Certificate{leaf.cert},
		Options{Guard: allowAll, Bundle: noBundle, MaxHops: 5})
	if len(found) != 5 {
		t.Fatalf("found %d issuers, want the 5-hop limit", len(found))
	}
	if !errors.Is(err, ErrIssuerNotFound) || !strings.Contains(err.Error(), "5 hops") {
		t.Errorf("err = %v, want the hop limit reported", err)
	}
	if srv.hits["/ca0.cer"]+srv.hits["/ca1.cer"] != 0 {
		t.Error("fetched past the hop limit")
	}
}

func TestResolve_AllowFetchSkips(t *testing.T) {
	srv := newAIAServer(t)
	root := issue(t, "Root", nil, true, nil)
	leaf := issue(t, "leaf", root, false, []string{srv.serve("/root.cer", root.cert.Raw)})
	_, _, err := Resolve(context.Background(), []*x509.Certificate{leaf.cert}, Options{
		Guard: allowAll, Bundle: noBundle, AllowFetch: func(string) bool { return false },
	})
	if !errors.Is(err, ErrIssuerNotFound) || srv.hits["/root.cer"] != 0 {
		t.Fatalf("err=%v hits=%d: AllowFetch=false still fetched", err, srv.hits["/root.cer"])
	}
}

func TestResolve_SelfSignedTopNeedsNothing(t *testing.T) {
	root := issue(t, "Root", nil, true, nil)
	found, _, err := Resolve(context.Background(), []*x509.Certificate{root.cert}, Options{})
	if err != nil || len(found) != 0 {
		t.Fatalf("found=%d err=%v", len(found), err)
	}
}

func TestParseCertificates_PKCS7Refused(t *testing.T) {
	root := issue(t, "Root", nil, true, nil)
	// A minimal ContentInfo{signedData, [0] ...}: enough for the type check.
	inner, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: root.cert.Raw})
	body, err := asn1.Marshal(struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}{oidSignedData, asn1.RawValue{FullBytes: inner}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCertificates(body); !errors.Is(err, ErrPKCS7Unsupported) {
		t.Fatalf("err = %v, want ErrPKCS7Unsupported", err)
	}
	if got, err := ParseCertificates(append(append([]byte{}, root.cert.Raw...), root.cert.Raw...)); err != nil || len(got) != 2 {
		t.Fatalf("concatenated DER: got %d, err %v", len(got), err)
	}
}
