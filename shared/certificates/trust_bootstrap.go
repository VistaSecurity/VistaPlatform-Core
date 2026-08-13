package certificates

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Trust bootstrap: how an agent comes to trust a platform whose edge certificate
// is signed by a CA the host does not already know.
//
// The agent NEVER skips verification when talking to the platform. Instead the
// operator makes an explicit, one-time trust decision at install time — the SSH
// known_hosts model — and from then on the agent verifies every connection
// against that one pinned anchor. Two ways to make the decision:
//
//   - interactive: the wizard fetches the anchor, shows its fingerprint, and asks
//   - unattended:  the installer passes --ca-fingerprint, checked before pinning
//
// The insecure dial below exists only to READ the anchor so it can be shown or
// fingerprint-checked. It sends no request and carries no registration key, and
// its tls.Conn is closed before anything else happens. Nothing downstream of it
// runs with verification disabled.
//
// This is trust-on-first-use: an attacker in position at bootstrap can present
// their own anchor. The fingerprint comparison is what closes that hole, so the
// caller must show the fingerprint (or demand one) rather than quietly accepting.

// TrustAnchor is a certificate an agent may pin as its platform trust root,
// together with what a human needs to decide whether to trust it.
type TrustAnchor struct {
	Certificate *x509.Certificate
	// PEM is the anchor encoded for writing to disk / config.
	PEM string
	// FingerprintSHA256 is the lowercase hex SHA-256 of the anchor's DER bytes,
	// unseparated — the same form `step ca bootstrap --fingerprint` accepts, so
	// an operator can paste a fingerprint from either tool.
	FingerprintSHA256 string
	// SelfSigned reports whether the anchor signed itself (a root). False means
	// the server did not present its root and this is the issuer-most
	// intermediate it did present — still usable as a pin, but the operator is
	// trusting a narrower anchor than the CA's actual root.
	SelfSigned bool
	// ChainLength is how many certificates the server presented.
	ChainLength int

	// Leaf is the end-entity certificate the server presented (chain[0]). It is
	// not what gets pinned — that is Anchor/Certificate — but it decides whether
	// pinning can ever work at all, so the caller needs it to answer honestly.
	Leaf *x509.Certificate
	// ServerName is the hostname the agent will connect to and therefore the
	// name the leaf has to be valid for.
	ServerName string
	// HostnameErr is non-nil when Leaf is not valid for ServerName.
	//
	// This is the difference between "you do not trust this CA yet" (fixable by
	// pinning) and "this server is serving the wrong certificate" (not fixable
	// by pinning, ever). Go's x509 Verify runs VerifyHostname BEFORE it builds
	// a chain, so no trust root the operator installs can rescue a name
	// mismatch. A platform whose TLS Secret is missing serves its ingress
	// controller's placeholder — a fingerprint an operator has no way to
	// recognise as wrong — and pinning it produces a sensor that fails every
	// connection while the operator believes they completed a security step.
	HostnameErr error
}

// UsableForHost reports whether pinning this anchor could actually produce a
// working connection. False means the server's own certificate is not valid for
// the host being connected to, so the trust decision is moot.
func (a *TrustAnchor) UsableForHost() bool { return a.HostnameErr == nil }

// FetchServerTrustAnchor completes a TLS handshake with the platform WITHOUT
// verifying its certificate, purely to read back the chain it presents, and
// returns the issuer-most certificate as a candidate anchor.
//
// It sends no application data. The caller must not act on the result without
// either showing the fingerprint to a human or checking it against an expected
// value — see FingerprintsEqual.
func FetchServerTrustAnchor(rawURL string) (*TrustAnchor, error) {
	host, err := hostPortFromURL(rawURL)
	if err != nil {
		return nil, err
	}
	serverName, _, err := net.SplitHostPort(host)
	if err != nil {
		return nil, fmt.Errorf("could not parse host from %q: %w", host, err)
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{
		// Deliberate and contained: this handshake exists only to READ the
		// server's chain so the operator can inspect it. See the package note
		// above — no request is sent over this connection.
		InsecureSkipVerify: true, //nolint:gosec // trust bootstrap: chain inspection only, no data sent
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return nil, fmt.Errorf("TLS handshake with %s failed: %w", host, err)
	}
	chain := conn.ConnectionState().PeerCertificates
	_ = conn.Close()

	if len(chain) == 0 {
		return nil, fmt.Errorf("%s presented no certificates", host)
	}

	// Issuer-most certificate the server presented. Servers commonly omit their
	// root, in which case this is the intermediate — pinning it still verifies
	// correctly, it just anchors trust one level lower than the true root.
	anchor := chain[len(chain)-1]
	leaf := chain[0]

	return &TrustAnchor{
		Certificate:       anchor,
		PEM:               string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: anchor.Raw})),
		FingerprintSHA256: FingerprintSHA256(anchor),
		SelfSigned:        isSelfSigned(anchor),
		ChainLength:       len(chain),
		Leaf:              leaf,
		ServerName:        serverName,
		// Checked here, at the only point the presented chain is in hand.
		// Pinning cannot fix a name mismatch, so the caller must not offer one.
		HostnameErr: leaf.VerifyHostname(serverName),
	}, nil
}

// DescribeHostnameMismatch renders, in the operator's terms, why the server's
// certificate can never work for the host they typed — naming the certificate's
// actual identity, which is the part that tells them what is misconfigured.
func DescribeHostnameMismatch(anchor *TrustAnchor) string {
	if anchor == nil || anchor.HostnameErr == nil {
		return ""
	}
	identity := anchor.Leaf.Subject.CommonName
	if len(anchor.Leaf.DNSNames) > 0 {
		identity = strings.Join(anchor.Leaf.DNSNames, ", ")
	}
	if strings.TrimSpace(identity) == "" {
		identity = "(no hostname at all)"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "\n❌ The server at %s is presenting a certificate for %s.\n\n", anchor.ServerName, identity)
	b.WriteString("    Its TLS is misconfigured — this is a problem on the platform, not here.\n")
	b.WriteString("    Trusting the CA behind it would not help: certificate verification\n")
	b.WriteString("    checks the hostname BEFORE it checks who signed it, so every\n")
	b.WriteString("    connection would still fail with the same error.\n\n")
	b.WriteString("    Common cause: the platform's TLS certificate was never installed, so\n")
	b.WriteString("    its ingress controller is serving a placeholder.\n\n")
	fmt.Fprintf(&b, "    Verification error: %v\n", anchor.HostnameErr)
	return b.String()
}

// hostPortFromURL extracts a dialable host:port from a platform URL, defaulting
// to 443. A plain-http URL is rejected: there is no certificate to anchor to,
// and silently "succeeding" here would hide that the platform is not on TLS.
func hostPortFromURL(rawURL string) (string, error) {
	trimmed := strings.TrimSpace(rawURL)
	if !strings.Contains(trimmed, "://") {
		trimmed = "https://" + trimmed
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("could not parse URL %q: %w", rawURL, err)
	}
	if u.Scheme == "http" {
		return "", fmt.Errorf("%s is plain HTTP — there is no TLS certificate to trust", rawURL)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("could not determine a host from URL %q", rawURL)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port), nil
}

// VerifiesAgainstSystemRoots reports whether a TLS endpoint's certificate
// validates against this host's trust store — i.e. whether an agent would
// connect with no trust prompt at all. Used to avoid presenting a
// pin-this-CA workflow to operators who do not need one.
func VerifiesAgainstSystemRoots(rawURL string) bool {
	host, err := hostPortFromURL(rawURL)
	if err != nil {
		return false
	}
	serverName, _, err := net.SplitHostPort(host)
	if err != nil {
		return false
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", host, &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func isSelfSigned(cert *x509.Certificate) bool {
	if !cert.IsCA {
		return false
	}
	if cert.Subject.String() != cert.Issuer.String() {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil
}

// FingerprintSHA256 returns the lowercase, unseparated hex SHA-256 of a
// certificate's DER bytes.
func FingerprintSHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// FormatFingerprint renders a fingerprint as colon-separated byte pairs across
// two lines, so a human can realistically compare it against a screen.
func FormatFingerprint(fingerprint string) string {
	normalized := normalizeFingerprint(fingerprint)
	var pairs []string
	for i := 0; i+1 < len(normalized); i += 2 {
		pairs = append(pairs, normalized[i:i+2])
	}
	if len(pairs) <= 16 {
		return strings.Join(pairs, ":")
	}
	return strings.Join(pairs[:16], ":") + ":\n" + strings.Join(pairs[16:], ":")
}

// FingerprintsEqual compares two SHA-256 fingerprints, tolerating the
// formatting differences between tools and copy-paste: colons, spaces, a
// "sha256:" prefix, and case.
func FingerprintsEqual(a, b string) bool {
	na, nb := normalizeFingerprint(a), normalizeFingerprint(b)
	return na != "" && na == nb
}

func normalizeFingerprint(fingerprint string) string {
	s := strings.ToLower(strings.TrimSpace(fingerprint))
	s = strings.TrimPrefix(s, "sha256:")
	replacer := strings.NewReplacer(":", "", " ", "", "-", "", "\n", "", "\t", "", "\r", "")
	return replacer.Replace(s)
}

// DescribeTrustAnchor renders the anchor for an operator to inspect before
// deciding. Everything a trust decision turns on is here: who it is, who signed
// it, whether it is currently valid, and the fingerprint to compare.
func DescribeTrustAnchor(anchor *TrustAnchor) string {
	cert := anchor.Certificate
	kind := "intermediate CA (the server did not present its root)"
	if anchor.SelfSigned {
		kind = "self-signed root CA"
	} else if !cert.IsCA {
		kind = "end-entity certificate — NOT a CA; the server presented no CA to anchor to"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "    Subject:     %s\n", cert.Subject.String())
	fmt.Fprintf(&b, "    Issuer:      %s\n", cert.Issuer.String())
	fmt.Fprintf(&b, "    Type:        %s\n", kind)
	fmt.Fprintf(&b, "    Valid:       %s → %s\n",
		cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))

	now := time.Now()
	switch {
	case now.Before(cert.NotBefore):
		b.WriteString("    ⚠️  NOT YET VALID\n")
	case now.After(cert.NotAfter):
		b.WriteString("    ⚠️  EXPIRED\n")
	}

	fmt.Fprintf(&b, "    SHA-256:     %s\n", strings.ReplaceAll(
		FormatFingerprint(anchor.FingerprintSHA256), "\n", "\n                 "))
	return b.String()
}
