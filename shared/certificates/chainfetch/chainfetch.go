// Package chainfetch completes a certificate chain whose top is not
// self-signed: it finds the missing issuer, then that issuer's issuer, up to a
// bounded number of hops (feature, enhancement E2).
//
// An issuer is looked for, in this order:
//
//  1. Inventory   — a certificate the tenant already holds (Options.Inventory);
//  2. Bundle      — the embedded public root bundle (shared/certificates/publicroots);
//  3. TenantAnchor — a CA the tenant explicitly decided on (Options.TenantAnchors);
//  4. AIA         — the certificate's Authority Information Access caIssuers
//     URLs (RFC 5280 §4.2.2.1), fetched over HTTP(S).
//
// The local sources come first because they are free and deterministic: a
// certificate found locally is the same issuer an AIA fetch would return (the
// signature check below holds either way), so asking the network first would
// only add latency and tell a CA's repository which certificates a tenant has.
//
// Every candidate, from every source, must be the issuer by construction: its
// subject equals the child's issuer name AND the child's signature verifies
// under its key. A repository that serves some other certificate cannot insert
// it into a chain.
//
// # The AIA fetch is guarded
//
// The URL comes from a certificate a scanned server presented, so it is
// attacker-chosen data, exactly like the OCSP responder URL. Every fetch goes
// through discovery.GuardedHTTPClient with the caller's AddressGuard: the guard
// is applied to the address actually dialled (after DNS), redirects are never
// followed, and no environment proxy is used. There is no unguarded path — a
// nil guard disables AIA rather than fetching without one. Bodies are capped
// (MaxBytes, 64 KiB by default) and each fetch is bounded by Timeout (5 s).
//
// An AIA fetch retrieves a CA's published certificate from the CA's own
// repository. It is not a probe of a tenant's or a third party's asset, so
// shared/probeconsent does not apply to it.
//
// Formats accepted: DER (one or several concatenated certificates) and PEM.
// PKCS#7 "certs-only" bundles (.p7c) are NOT parsed — no PKCS#7 library is in
// the workspace and one is not added for this; such a response is reported as
// ErrPKCS7Unsupported and the chain stays incomplete.
//
// Agents never call this (owner decision D4): it runs only inside
// inventory-service.
package chainfetch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/certificates/publicroots"
	"github.com/vistasecurity/vistaplatform/shared/discovery"
)

// Source says where an issuer was found. The values match
// certificates.chain_source for the three that store a new certificate
// (aia, bundle, tenant_anchor); inventory means the tenant already had it.
type Source string

const (
	SourceInventory    Source = "inventory"
	SourceAIA          Source = "aia"
	SourceBundle       Source = "bundle"
	SourceTenantAnchor Source = "tenant_anchor"
)

// Defaults for the bounds in Options.
const (
	DefaultMaxHops  = 5
	DefaultMaxBytes = 64 << 10
	DefaultTimeout  = 5 * time.Second
	// maxURLsPerCert bounds how many caIssuers URLs of one certificate are
	// tried; real certificates carry one or two.
	maxURLsPerCert = 3
)

// ErrIssuerNotFound is returned (wrapped, with the reasons) when the walk
// stopped at a certificate that is not self-signed and no source had its
// issuer. Issuers found before that point are still returned.
var ErrIssuerNotFound = errors.New("issuer not found")

// ErrPKCS7Unsupported is the AIA failure for a PKCS#7 response.
var ErrPKCS7Unsupported = errors.New("PKCS#7 caIssuers responses are not supported")

// ErrBodyTooLarge is the AIA failure for a response over MaxBytes.
var ErrBodyTooLarge = errors.New("caIssuers response exceeds the size limit")

// Lookup returns the issuer of cert from a local source, or nil. A returned
// certificate is still verified as the issuer before it is used.
type Lookup func(ctx context.Context, cert *x509.Certificate) *x509.Certificate

// Options configures Resolve. The zero value consults only the embedded
// bundle (no inventory, no anchors, no AIA).
type Options struct {
	// Inventory finds the issuer among certificates the tenant already holds.
	Inventory Lookup
	// TenantAnchors finds the issuer among the CAs the tenant decided on.
	TenantAnchors Lookup
	// Bundle replaces the embedded public bundle (tests). Nil means
	// publicroots.FindIssuer; set NoBundle to skip the bundle entirely.
	Bundle   func(*x509.Certificate) *x509.Certificate
	NoBundle bool

	// Guard is the address guard every AIA connection is checked against.
	// Nil disables AIA: there is no unguarded fetch.
	Guard discovery.AddressGuard
	// AllowFetch is asked before each AIA URL is fetched (a failure cache, a
	// per-tenant rate limit). Nil allows every URL.
	AllowFetch func(url string) bool
	// OnFetchFailure is told about every failed AIA fetch, so the caller can
	// stop re-fetching a dead URL.
	OnFetchFailure func(url string, err error)

	MaxHops  int
	MaxBytes int64
	Timeout  time.Duration
}

func (o Options) maxHops() int {
	if o.MaxHops > 0 {
		return o.MaxHops
	}
	return DefaultMaxHops
}

func (o Options) maxBytes() int64 {
	if o.MaxBytes > 0 {
		return o.MaxBytes
	}
	return DefaultMaxBytes
}

func (o Options) timeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	return DefaultTimeout
}

// SelfSigned reports whether cert names itself as issuer — the top of a chain.
// The same test chain rebuild and trust evaluation use (subject == issuer).
func SelfSigned(cert *x509.Certificate) bool {
	return cert != nil && bytes.Equal(cert.RawSubject, cert.RawIssuer)
}

// IsIssuer reports whether candidate issued child: names match and child's
// signature verifies under candidate's key.
func IsIssuer(child, candidate *x509.Certificate) bool {
	if child == nil || candidate == nil {
		return false
	}
	if !bytes.Equal(candidate.RawSubject, child.RawIssuer) {
		return false
	}
	return child.CheckSignatureFrom(candidate) == nil
}

func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// Resolve walks up from the last certificate of leafChain (ordered leaf ->
// top) and returns the issuers it found, each with where it came from, in
// walk order: found[0] issued the top of leafChain, found[1] issued found[0],
// and so on. It stops at a self-signed certificate, after MaxHops issuers, or
// when no source has the next issuer — the last with ErrIssuerNotFound
// wrapped with the reasons. A context error stops it too.
func Resolve(ctx context.Context, leafChain []*x509.Certificate, opts Options) ([]*x509.Certificate, []Source, error) {
	if len(leafChain) == 0 || leafChain[len(leafChain)-1] == nil {
		return nil, nil, errors.New("chainfetch: empty chain")
	}
	seen := map[string]bool{}
	for _, c := range leafChain {
		if c != nil {
			seen[fingerprint(c)] = true
		}
	}
	var client *http.Client
	if opts.Guard != nil {
		client = discovery.GuardedHTTPClient(opts.Guard, opts.timeout())
	}

	var found []*x509.Certificate
	var sources []Source
	top := leafChain[len(leafChain)-1]
	for hop := 0; hop < opts.maxHops(); hop++ {
		if SelfSigned(top) {
			return found, sources, nil
		}
		if err := ctx.Err(); err != nil {
			return found, sources, err
		}
		issuer, src, reasons := findIssuer(ctx, top, opts, client)
		if issuer == nil {
			why := "no source had it"
			if len(reasons) > 0 {
				why = strings.Join(reasons, "; ")
			}
			return found, sources, fmt.Errorf("%w for %q: %s", ErrIssuerNotFound, top.Issuer.String(), why)
		}
		fp := fingerprint(issuer)
		if seen[fp] {
			// A cycle (cross-signed pairs can produce one): what we have is
			// the chain; going round again finds nothing new.
			return found, sources, nil
		}
		seen[fp] = true
		found = append(found, issuer)
		sources = append(sources, src)
		top = issuer
	}
	if SelfSigned(top) {
		return found, sources, nil
	}
	return found, sources, fmt.Errorf("%w for %q: stopped after %d hops", ErrIssuerNotFound, top.Issuer.String(), opts.maxHops())
}

func findIssuer(ctx context.Context, child *x509.Certificate, opts Options, client *http.Client) (*x509.Certificate, Source, []string) {
	if opts.Inventory != nil {
		if c := opts.Inventory(ctx, child); IsIssuer(child, c) {
			return c, SourceInventory, nil
		}
	}
	if !opts.NoBundle {
		bundle := opts.Bundle
		if bundle == nil {
			bundle = publicroots.FindIssuer
		}
		if c := bundle(child); IsIssuer(child, c) {
			return c, SourceBundle, nil
		}
	}
	if opts.TenantAnchors != nil {
		if c := opts.TenantAnchors(ctx, child); IsIssuer(child, c) {
			return c, SourceTenantAnchor, nil
		}
	}
	var reasons []string
	urls := httpURLs(child.IssuingCertificateURL)
	if len(urls) == 0 {
		return nil, "", []string{"the certificate names no caIssuers URL"}
	}
	if client == nil {
		return nil, "", []string{"AIA fetching is not enabled"}
	}
	for _, u := range urls {
		if opts.AllowFetch != nil && !opts.AllowFetch(u) {
			reasons = append(reasons, fmt.Sprintf("AIA %s skipped (failed recently or rate-limited)", u))
			continue
		}
		certs, err := fetch(ctx, client, u, opts.maxBytes(), opts.timeout())
		if err == nil {
			for _, c := range certs {
				if IsIssuer(child, c) {
					return c, SourceAIA, nil
				}
			}
			err = errors.New("the response holds no certificate that issued this one")
		}
		if opts.OnFetchFailure != nil {
			opts.OnFetchFailure(u, err)
		}
		reasons = append(reasons, fmt.Sprintf("AIA fetch failed: %s: %v", u, err))
	}
	return nil, "", reasons
}

// httpURLs keeps the http(s) caIssuers URLs (RFC 5280 also allows ldap://,
// which is not fetched), at most maxURLsPerCert of them.
func httpURLs(in []string) []string {
	var out []string
	for _, u := range in {
		l := strings.ToLower(strings.TrimSpace(u))
		if strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") {
			out = append(out, strings.TrimSpace(u))
			if len(out) == maxURLsPerCert {
				break
			}
		}
	}
	return out
}

// fetch GETs one caIssuers URL through the guarded client and parses the body.
// A redirect is a failure: the guarded client does not follow it, so the 3xx
// itself comes back and is refused here.
func fetch(ctx context.Context, client *http.Client, url string, maxBytes int64, timeout time.Duration) ([]*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, fmt.Errorf("redirect (%d) refused", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("%w (%d bytes)", ErrBodyTooLarge, maxBytes)
	}
	return ParseCertificates(body)
}

// oidSignedData is PKCS#7 signedData (RFC 2315 §14), the content type of a
// .p7c certs-only bundle.
var oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

// ParseCertificates reads a caIssuers body: PEM (any number of CERTIFICATE
// blocks) or DER (one or several concatenated certificates). A PKCS#7 body is
// recognised and refused with ErrPKCS7Unsupported.
func ParseCertificates(body []byte) ([]*x509.Certificate, error) {
	trimmed := bytes.TrimSpace(body)
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		var out []*x509.Certificate
		rest := trimmed
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			switch block.Type {
			case "CERTIFICATE":
				c, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return nil, fmt.Errorf("PEM certificate does not parse: %w", err)
				}
				out = append(out, c)
			case "PKCS7":
				return nil, ErrPKCS7Unsupported
			}
		}
		if len(out) == 0 {
			return nil, errors.New("PEM response holds no CERTIFICATE block")
		}
		return out, nil
	}
	certs, err := x509.ParseCertificates(body)
	if err == nil && len(certs) > 0 {
		return certs, nil
	}
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
	}
	if _, perr := asn1.Unmarshal(body, &ci); perr == nil && ci.ContentType.Equal(oidSignedData) {
		return nil, ErrPKCS7Unsupported
	}
	if err == nil {
		err = errors.New("no certificate in the response")
	}
	return nil, fmt.Errorf("response is neither DER nor PEM: %w", err)
}
