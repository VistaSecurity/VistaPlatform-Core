package hostinventory

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/certificates"
)

// Certificate stores are read for CERTIFICATES and nothing else.
//
// A trust-store directory is also where an operator's private key ends up: a
// misplaced server.key, a PKCS#8 block appended to a bundle, a combined
// fullchain+key PEM. This reader cannot carry one out, and that is structural
// rather than careful:
//
//  1. Only PEM blocks whose Type is exactly "CERTIFICATE" are decoded. A
//     "PRIVATE KEY", "RSA PRIVATE KEY" or "ENCRYPTED PRIVATE KEY" block is
//     skipped by the loop, never read into a variable, and never mentioned in
//     an error.
//  2. The [Cert] shape has four fields — subject, issuer, SHA-256 fingerprint,
//     expiry. There is nowhere for key bytes to sit even if a parser wanted to
//     put them there. In particular there is no CertificatePEM, unlike the
//     crypto-posture CertificateInfo the interrogators emit.
//  3. The file scan asks `find` for regular files only, so the ~140 symlinks in
//     /etc/ssl/certs collapse to the one real bundle behind them instead of
//     being read 140 times.
//
// TestCertStore_APrivateKeyOnDiskNeverReachesTheReport is the guard.

// certStoreFileExtensions are the file names a trust store keeps certificates
// in. A `.key` is not on the list, which is the first of the three defences
// above: the file is never opened at all.
var certStoreFileExtensions = []string{"*.pem", "*.crt", "*.cer"}

// maxCertStoreFiles bounds the per-store file scan.
const maxCertStoreFiles = 64

// collectCertStoresUnix enumerates the configured trust stores on a POSIX host.
//
// A store path that does not exist is not a failure — /etc/pki/tls/certs is
// absent on Debian and /etc/ssl/certs is absent on nothing, and reporting the
// first as broken would make every Debian host look degraded. Only a store that
// exists and could not be read is a failure.
func collectCertStoresUnix(ctx context.Context, r Runner, rep *Report, paths []string, opts Options) {
	var stores []CertStore
	var problems []string
	found := false

	for _, path := range paths {
		files, err := listCertFiles(ctx, r, path)
		if err != nil {
			// Distinguish "no such store" from "the store would not read".
			if isMissingPath(err) {
				continue
			}
			problems = append(problems, fmt.Sprintf("%s: %v", path, err))
			continue
		}
		found = true
		store := CertStore{Path: path}
		for _, f := range files {
			b, rerr := r.ReadFile(ctx, f)
			if rerr != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", f, rerr))
				continue
			}
			certs, other := ParseCertificatePEM(b, opts.maxCertsPerStore()-store.Count)
			for _, c := range certs {
				store.Certs = append(store.Certs, c)
				store.Count++
			}
			store.NonCertificateBlocks += other
			if store.Count >= opts.maxCertsPerStore() {
				break
			}
		}
		stores = append(stores, store)
	}

	rep.CertStores = stores
	switch {
	case !found && len(problems) == 0:
		// No trust store at any configured path. That is a real and reportable
		// state (a scratch container), not a collector failure.
		rep.mark(SectionCertStores, SectionOK)
	case len(problems) > 0 && len(stores) == 0:
		rep.fail(SectionCertStores, fmt.Errorf("%s", strings.Join(problems, "; ")))
	default:
		rep.mark(SectionCertStores, SectionOK)
		if len(problems) > 0 {
			rep.Errors = append(rep.Errors, StepError{Step: SectionCertStores, Message: strings.Join(problems, "; ")})
		}
	}
}

// listCertFiles returns the regular certificate files directly inside path.
//
// `-type f` is load-bearing twice over: it collapses /etc/ssl/certs's symlink
// farm onto the single ca-certificates.crt bundle they all point into, and it
// refuses to follow a symlink that points somewhere a trust store has no
// business reaching.
func listCertFiles(ctx context.Context, r Runner, path string) ([]string, error) {
	argv := []string{"find", path, "-maxdepth", "1", "-type", "f", "("}
	for i, ext := range certStoreFileExtensions {
		if i > 0 {
			argv = append(argv, "-o")
		}
		argv = append(argv, "-name", ext)
	}
	argv = append(argv, ")")

	out, errOut, exit, err := r.Run(ctx, argv)
	if err != nil {
		return nil, err
	}
	if exit != 0 {
		return nil, fmt.Errorf("find exited %d: %s", exit, strings.TrimSpace(string(errOut)))
	}

	var files []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" {
			continue
		}
		files = append(files, line)
		if len(files) >= maxCertStoreFiles {
			break
		}
	}
	return files, nil
}

// isMissingPath reports whether an error is "that path is not there", which is
// a normal answer for a store path that this distribution does not use.
func isMissingPath(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no such file") || strings.Contains(s, "not found") ||
		strings.Contains(s, "cannot find")
}

// ParseCertificatePEM decodes up to limit CERTIFICATE blocks from a PEM file,
// summarises each, and reports how many blocks it refused on TYPE.
//
// Non-certificate blocks are skipped by type before any decoding happens: a
// PRIVATE KEY block ends its life at the `block.Type` comparison, and its bytes
// are never parsed, never copied and never named in an error.
//
// otherBlocks is what makes that guard observable, and it exists for two
// reasons. The first is that a guard nothing can see is a guard nothing can
// test — x509.ParseCertificate would reject a key's bytes anyway, so without a
// count the type check and the parse check are indistinguishable and the type
// check could be deleted with every test still green. The second is that the
// count is worth surfacing on its own: a private key sitting loose in a trust
// directory is a real finding, and "this store holds 3 blocks that are not
// certificates" says so without carrying a single byte of the thing.
//
// A block that CLAIMS to be a certificate and does not parse is skipped
// silently and is not counted here: a malformed entry in a trust bundle is a
// fact about the bundle rather than about the store's contents.
func ParseCertificatePEM(b []byte, limit int) (certs []Cert, otherBlocks int) {
	if limit <= 0 {
		return nil, 0
	}
	rest := b
	for len(rest) > 0 && len(certs) < limit {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			otherBlocks++
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		certs = append(certs, summariseCert(cert))
	}
	return certs, otherBlocks
}

// summariseCert projects an x509 certificate onto the four posture fields.
//
// It reuses shared/certificates for the fingerprint and the DN spelling so a
// certificate found in a host's trust store and the same certificate observed
// on the wire produce the SAME fingerprint string and the same subject — which
// is what lets a consumer join them. The projection to four fields is this
// package's own: the shared shape carries CertificatePEM, and a trust store's
// contents do not need to travel as PEM.
func summariseCert(cert *x509.Certificate) Cert {
	infos := certificates.ExtractCertificatesFromX509([]*x509.Certificate{cert})
	if len(infos) == 0 {
		return Cert{}
	}
	info := infos[0]
	return Cert{
		SubjectDN:         info.SubjectDN,
		IssuerDN:          info.IssuerDN,
		FingerprintSHA256: info.FingerprintSHA256,
		NotAfter:          info.NotAfter.UTC().Format(time.RFC3339),
	}
}
