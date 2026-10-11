// Package publicroots embeds the public root store the platform trusts by
// default: Mozilla's CA certificates, as extracted by curl (cacert.pem).
//
// Trust is decided centrally, for every tenant and every agent alike, so the
// answer to "is this chain public?" must not depend on the operating-system
// store of whichever pod or host happened to look. The bundle is compiled into
// the binary and refreshed per release (see README.md); Version reports which
// snapshot a build carries so the UI can say what "public" means on it.
package publicroots

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"sync"
)

//go:embed cacert.pem
var bundle []byte

// source names where the bundle comes from, for display.
const source = "Mozilla NSS root store via curl.se/ca"

// versionPrefix introduces the snapshot date in the bundle's header.
const versionPrefix = "Certificate data from Mozilla as of:"

type store struct {
	version string
	roots   []*x509.Certificate
	byFP    map[string]*x509.Certificate
	pool    *x509.CertPool
}

var (
	loadOnce sync.Once
	loaded   *store
)

func get() *store {
	loadOnce.Do(func() { loaded = parse(bundle) })
	return loaded
}

// parse reads a curl-format CA bundle. Blocks that are not certificates, or do
// not parse, are skipped: one malformed entry must not withdraw every root.
func parse(data []byte) *store {
	s := &store{byFP: map[string]*x509.Certificate{}, pool: x509.NewCertPool()}
	for _, line := range bytes.Split(data, []byte("\n")) {
		l := strings.TrimSpace(strings.TrimLeft(string(line), "#"))
		if strings.HasPrefix(l, versionPrefix) {
			s.version = strings.TrimSpace(strings.TrimPrefix(l, versionPrefix))
			break
		}
	}
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		fp := Fingerprint(cert)
		if _, dup := s.byFP[fp]; dup {
			continue
		}
		s.byFP[fp] = cert
		s.roots = append(s.roots, cert)
		s.pool.AddCert(cert)
	}
	return s
}

// Fingerprint is the lowercase hex SHA-256 of a certificate's raw DER, the
// same form certificates.fingerprint_sha256 stores.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// Version is the bundle's snapshot, as its header states it (a date for the
// Mozilla bundle). Empty only if the header is missing.
func Version() string { return get().version }

// Source names where the bundle comes from.
func Source() string { return source }

// Count is the number of roots the bundle carries.
func Count() int { return len(get().roots) }

// Pool returns a fresh CertPool of every root, safe for the caller to extend.
func Pool() *x509.CertPool { return get().pool.Clone() }

// Roots returns every root. The slice is a copy; the certificates are shared
// and must not be modified.
func Roots() []*x509.Certificate {
	r := get().roots
	out := make([]*x509.Certificate, len(r))
	copy(out, r)
	return out
}

// Lookup returns the root whose SHA-256 fingerprint (hex, either case) is
// given, or nil when the bundle does not carry it.
func Lookup(fingerprintSHA256 string) *x509.Certificate {
	return get().byFP[strings.ToLower(strings.TrimSpace(fingerprintSHA256))]
}

// FindIssuer returns a root that issued cert: its subject matches cert's issuer
// and cert's signature verifies under it. Nil when the bundle has none.
func FindIssuer(cert *x509.Certificate) *x509.Certificate {
	return findIssuer(get().roots, cert)
}

func findIssuer(roots []*x509.Certificate, cert *x509.Certificate) *x509.Certificate {
	if cert == nil {
		return nil
	}
	for _, root := range roots {
		if !bytes.Equal(root.RawSubject, cert.RawIssuer) {
			continue
		}
		if cert.CheckSignatureFrom(root) == nil {
			return root
		}
	}
	return nil
}
