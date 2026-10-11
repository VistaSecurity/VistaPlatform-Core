package publicroots

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestEmbeddedBundleParses(t *testing.T) {
	if n := Count(); n <= 100 {
		t.Fatalf("Count() = %d, want > 100 roots in the embedded bundle", n)
	}
	if Version() == "" {
		t.Fatal("Version() is empty; the bundle header line was not found")
	}
	if Source() == "" {
		t.Fatal("Source() is empty")
	}
	if got := len(Roots()); got != Count() {
		t.Fatalf("len(Roots()) = %d, Count() = %d", got, Count())
	}
	if Pool() == nil {
		t.Fatal("Pool() is nil")
	}
	// Every root is findable by its own fingerprint, in either case.
	for _, r := range Roots() {
		fp := Fingerprint(r)
		if Lookup(fp) != r || Lookup(strings.ToUpper(fp)) != r {
			t.Fatalf("Lookup(%s) did not return the root %q", fp, r.Subject)
		}
	}
	if Lookup(strings.Repeat("0", 64)) != nil {
		t.Fatal("Lookup of an unknown fingerprint returned a root")
	}
}

type genCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newRoot(t *testing.T, cn string) genCA {
	t.Helper()
	key := mustKey(t)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Example Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return genCA{cert: c, key: key}
}

func newLeaf(t *testing.T, issuer genCA, cn string) *x509.Certificate {
	t.Helper()
	key := mustKey(t)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, issuer.cert, &key.PublicKey, issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFindIssuer_GeneratedChain(t *testing.T) {
	root := newRoot(t, "Example Test Root")
	other := newRoot(t, "Unrelated Test Root")
	// Same subject as root, different key: a name match alone must not do.
	impostor := newRoot(t, "Example Test Root")

	leaf := newLeaf(t, root, "leaf.example.test")
	unrelated := newLeaf(t, other, "other.example.test")

	roots := []*x509.Certificate{impostor.cert, root.cert}
	if got := findIssuer(roots, leaf); got != root.cert {
		t.Fatalf("findIssuer(leaf) = %v, want the generated root", got)
	}
	if got := findIssuer(roots, unrelated); got != nil {
		t.Fatalf("findIssuer(unrelated) = %q, want nil", got.Subject)
	}
	if got := findIssuer(roots, nil); got != nil {
		t.Fatal("findIssuer(nil) returned a root")
	}
	// And the embedded bundle does not claim to have issued a test certificate.
	if got := FindIssuer(leaf); got != nil {
		t.Fatalf("FindIssuer(leaf) = %q from the embedded bundle, want nil", got.Subject)
	}
}

func TestParse_SyntheticBundle(t *testing.T) {
	root := newRoot(t, "Synthetic Root")
	pemRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.cert.Raw})
	data := "##\n## Certificate data from Mozilla as of: Mon Jan  5 00:00:00 2026 GMT\n##\n\nSynthetic Root\n==============\n" +
		string(pemRoot) + "\nGarbage\n=======\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" + string(pemRoot)
	s := parse([]byte(data))
	if s.version != "Mon Jan  5 00:00:00 2026 GMT" {
		t.Fatalf("version = %q", s.version)
	}
	if len(s.roots) != 1 {
		t.Fatalf("roots = %d, want 1 (malformed skipped, duplicate collapsed)", len(s.roots))
	}
	if s.byFP[Fingerprint(root.cert)] == nil {
		t.Fatal("root not indexed by fingerprint")
	}
}
