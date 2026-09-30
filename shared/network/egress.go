package network

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

// Outbound egress for customer-configured integrations (integrations review,
// work package W8).
//
// Every integration that calls a system the TENANT names — a NetBox, a CMDB,
// a SIEM collector, a webhook receiver — needs the same three things, and each
// connector growing its own copy is how they drifted apart before:
//
//  1. An SSRF guard that judges the TARGET, including when an operator routes
//     egress through an HTTP(S) proxy.
//  2. A per-connection opt-in for on-premises targets in private address space.
//  3. A per-connection CA bundle, for a receiver whose certificate an internal
//     CA issued.
//
// [NewEgressClient] is the one constructor that provides all three. New
// integration code builds its client there and nowhere else.
//
// There is deliberately NO "skip certificate verification" option. The only
// legitimate reason to want one is a receiver signed by a CA the platform does
// not trust, and a CA bundle solves exactly that without giving up the thing
// TLS is for: a bearer token or a stream of audit events sent over a connection
// that verifies nothing is readable by whoever sits in the path. `curl -k`
// validates nothing, and a checkbox that does the same would be the easiest
// wrong answer on the form.

// ConnectorAllowPrivateEndpointsEnv is the platform operator's kill switch for
// private-address integration targets. Set to "false", no connection may reach
// an RFC1918/ULA/CGNAT address whatever its own opt-in says; any other value
// (including unset) leaves the per-connection opt-in in charge. The operator's
// setting wins over the tenant's.
const ConnectorAllowPrivateEndpointsEnv = "CONNECTOR_ALLOW_PRIVATE_ENDPOINTS"

// maxCABundleBytes bounds a pasted CA bundle. A real internal chain is a few
// kilobytes; this leaves room for a long one without letting a form field hold
// megabytes of whatever was pasted into it.
const maxCABundleBytes = 64 * 1024

// EgressOptions are the per-connection knobs of an integration's outbound
// client. The zero value is the strict default: public targets only, system
// trust store only.
type EgressOptions struct {
	// AllowPrivateEndpoint permits RFC1918 / ULA / CGNAT targets — the
	// tenant's own network. It is for a connector whose target system is
	// on-premises by construction, behind a per-connection opt-in that is
	// recorded in the audit log. It never opens loopback, link-local (and so
	// the cloud metadata endpoints) or the platform's own cluster ranges
	// (PlatformInternalCIDRsEnv), and it is ANDed with the operator's
	// ConnectorAllowPrivateEndpointsEnv.
	AllowPrivateEndpoint bool
	// CABundlePEM holds additional trusted root certificates, PEM-encoded.
	// They are APPENDED to the system trust store, not substituted for it, so
	// a connection that sets one can still reach a publicly-signed endpoint
	// (a redirect to a CDN, a SaaS instance moved in front of a public cert).
	// Empty means the system trust store alone. Validate it at save time with
	// [ValidateCABundlePEM] so a bad paste is a form error, not a failed run.
	CABundlePEM string
}

// PrivateEndpointsPermitted reports whether the operator allows private
// integration targets at all. It defaults to TRUE: an on-premises source of
// truth is the normal case, and a default of false would break it.
func PrivateEndpointsPermitted() bool {
	return !strings.EqualFold(strings.TrimSpace(os.Getenv(ConnectorAllowPrivateEndpointsEnv)), "false")
}

// NewEgressClient returns the SSRF-guarded *http.Client an integration uses to
// reach a tenant-configured endpoint. timeout bounds each request (0 = none).
//
// It returns an error only for a CA bundle that does not parse, or for a
// malformed PlatformInternalCIDRsEnv — both of which should stop a connection
// from being built rather than produce a client that behaves differently from
// what the operator or tenant configured.
//
// Redirects are followed with the http.Client default (10 hops) and every hop
// is re-judged by the same guard; a caller that sends a credential should also
// set CheckRedirect to refuse off-origin hops, as the NetBox connector does.
func NewEgressClient(timeout time.Duration, opts EgressOptions) (*http.Client, error) {
	return newEgressClient(timeout, opts, egressDeps{})
}

// ValidateCABundlePEM reports whether text is a usable CA bundle: one or more
// PEM "CERTIFICATE" blocks that each parse as X.509, and nothing else. Empty
// (or all-whitespace) text is valid and means "no bundle".
//
// It is strict on purpose. A bundle that half-parses would be silently
// truncated by x509.CertPool.AppendCertsFromPEM, and the connection would then
// fail at run time with "unknown authority" for a certificate the tenant can
// see they pasted. And it refuses a private key outright: a key pasted into the
// wrong field would otherwise be stored in a non-secret column and returned by
// the API. We collect posture, never key material.
func ValidateCABundlePEM(text string) error {
	_, err := parseCABundle(text)
	return err
}

func parseCABundle(text string) ([]*x509.Certificate, error) {
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	if len(text) > maxCABundleBytes {
		return nil, fmt.Errorf("CA bundle is %d bytes; the limit is %d", len(text), maxCABundleBytes)
	}
	rest := []byte(text)
	var certs []*x509.Certificate
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			if strings.Contains(block.Type, "PRIVATE KEY") {
				return nil, errors.New("CA bundle contains a private key; paste only the CA certificate(s) — " +
					"a private key must never be entered here")
			}
			return nil, fmt.Errorf("CA bundle contains a %q block; only CERTIFICATE blocks are accepted", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("CA bundle certificate %d does not parse: %w", len(certs)+1, err)
		}
		certs = append(certs, cert)
	}
	if strings.TrimSpace(string(rest)) != "" {
		if len(certs) == 0 {
			return nil, errors.New("CA bundle is not PEM: expected one or more " +
				"-----BEGIN CERTIFICATE----- blocks")
		}
		return nil, errors.New("CA bundle has text after its last certificate that is not a PEM block; " +
			"remove it or check the paste is complete")
	}
	if len(certs) == 0 {
		return nil, errors.New("CA bundle contains no certificates")
	}
	return certs, nil
}

// ---------------------------------------------------------------------------
// target policy
// ---------------------------------------------------------------------------

// targetPolicy is the one address rule every guarded outbound connection
// applies, whether the address is the socket the kernel is about to connect
// (direct) or the destination a proxy is about to be asked for (proxied).
type targetPolicy struct {
	allowPrivate bool
	internal     []netip.Prefix
	// configErr fails every check closed: a malformed platform CIDR list must
	// not quietly degrade to "no platform CIDRs".
	configErr error
}

func newTargetPolicy(allowPrivate bool) targetPolicy {
	prefixes, err := platformInternalPrefixes(os.Getenv(PlatformInternalCIDRsEnv))
	return targetPolicy{allowPrivate: allowPrivate, internal: prefixes, configErr: err}
}

// checkIP applies the policy to one concrete address.
func (p targetPolicy) checkIP(ip net.IP) error {
	if p.configErr != nil {
		return p.configErr
	}
	if ip == nil {
		return errors.New("ssrf guard: no IP address to check")
	}
	if p.allowPrivate {
		if IsNeverReachable(ip) {
			return fmt.Errorf("ssrf guard: refusing to connect to %s — loopback, link-local and "+
				"metadata addresses are never reachable, whatever the connector's private-endpoint setting says", ip)
		}
	} else if isPrivateIP(ip) {
		return fmt.Errorf("ssrf guard: refusing to connect to internal address %s", ip)
	}
	if addr, ok := netip.AddrFromSlice(ip); ok {
		addr = addr.Unmap()
		for _, prefix := range p.internal {
			if prefix.Contains(addr) {
				return fmt.Errorf("ssrf guard: refusing to connect to platform-internal address %s (matched %s)", addr, prefix)
			}
		}
	}
	return nil
}

// control is the policy as a net.Dialer.Control hook: it runs AFTER name
// resolution, on the concrete IP the kernel is about to connect to, which is
// what closes the DNS-rebinding gap for a DIRECT connection.
func (p targetPolicy) control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("ssrf guard: unparseable address %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("ssrf guard: %q did not resolve to an IP", host)
	}
	return p.checkIP(ip)
}

// blockedTargetName reports whether a hostname names this platform or its
// cluster rather than anything a tenant could legitimately integrate with. It
// is only consulted for PROXIED requests, where the name — not an address — is
// what we hand on (see checkProxiedTarget).
func blockedTargetName(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	switch h {
	case "localhost", "metadata", "metadata.google.internal", "host.docker.internal",
		"kubernetes", "kubernetes.default", "kubernetes.default.svc":
		return true
	}
	for _, suffix := range []string{".localhost", ".svc", ".cluster.local"} {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return false
}

// checkProxiedTarget judges the DESTINATION of a request that is about to be
// handed to a proxy.
//
// Why this exists: with HTTP(S)_PROXY set, the socket we open is to the proxy,
// so a dial-time guard sees the proxy's address, not the target's. Judging
// that address answers the wrong question twice over — a proxy on a private
// address (the normal deployment) was refused, so every guarded client failed;
// and had it been allowed, nothing would have judged the target at all.
//
// The limits of this check, stated plainly:
//
//   - The PROXY resolves the name, not us. We resolve it too and refuse if any
//     answer is disallowed, but a name that resolves differently for the proxy
//     (split-horizon DNS, a rebinding answer between our lookup and the
//     proxy's) is outside what this process can see. The proxy is operator
//     infrastructure; its own destination ACL is the control that closes this,
//     and the operator doc says to configure one.
//   - If WE cannot resolve the name, the request is handed to the proxy
//     anyway. Egress-restricted clusters often cannot resolve public names at
//     all — resolving them is the proxy's job — and refusing here would make
//     the proxy unusable, which is the bug this replaces pointed the other
//     way. IP literals and the names in blockedTargetName are refused without
//     any lookup.
func (p targetPolicy) checkProxiedTarget(ctx context.Context, host string,
	lookup func(context.Context, string) ([]net.IP, error)) error {

	if p.configErr != nil {
		return p.configErr
	}
	if host == "" {
		return errors.New("ssrf guard: request has no target host")
	}
	if ip := net.ParseIP(host); ip != nil {
		return p.checkIP(ip)
	}
	if blockedTargetName(host) {
		return fmt.Errorf("ssrf guard: refusing to connect to %q — it names this platform or its cluster", host)
	}
	ips, err := lookup(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil // deferred to the proxy's resolution; see above
	}
	for _, ip := range ips {
		if err := p.checkIP(ip); err != nil {
			return fmt.Errorf("%w (resolved from %q)", err, host)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// transport
// ---------------------------------------------------------------------------

// egressDeps are the seams tests replace. Zero values mean production.
type egressDeps struct {
	// proxy chooses a proxy per request. Default http.ProxyFromEnvironment —
	// the same function http.DefaultTransport uses, so HTTP_PROXY,
	// HTTPS_PROXY and NO_PROXY behave exactly as they did before.
	proxy func(*http.Request) (*url.URL, error)
	// lookup resolves a proxied target's name. Default net.DefaultResolver.
	lookup func(context.Context, string) ([]net.IP, error)
	// systemRoots returns the base trust store a CA bundle is appended to.
	// Default x509.SystemCertPool.
	systemRoots func() (*x509.CertPool, error)
}

func defaultLookup(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

func newEgressClient(timeout time.Duration, opts EgressOptions, deps egressDeps) (*http.Client, error) {
	certs, err := parseCABundle(opts.CABundlePEM)
	if err != nil {
		return nil, err
	}
	policy := newTargetPolicy(opts.AllowPrivateEndpoint && PrivateEndpointsPermitted())
	if policy.configErr != nil {
		return nil, policy.configErr
	}
	return buildEgressClient(timeout, policy, certs, deps), nil
}

// buildEgressClient assembles the guarded client. It cannot fail: a policy
// carrying a configErr produces a client that refuses every request, which is
// what [SafeHTTPClient] — whose signature has no error to return — relies on.
func buildEgressClient(timeout time.Duration, policy targetPolicy, certs []*x509.Certificate,
	deps egressDeps) *http.Client {

	if deps.proxy == nil {
		deps.proxy = http.ProxyFromEnvironment
	}
	if deps.lookup == nil {
		deps.lookup = defaultLookup
	}
	if deps.systemRoots == nil {
		deps.systemRoots = x509.SystemCertPool
	}

	var tlsConfig *tls.Config
	if len(certs) > 0 {
		pool, err := deps.systemRoots()
		if err != nil || pool == nil {
			// No readable system store (a scratch image without one). The
			// bundle still applies; public endpoints then fail verification,
			// which is the honest result on a host that trusts nothing.
			pool = x509.NewCertPool()
		} else {
			pool = pool.Clone()
		}
		for _, c := range certs {
			pool.AddCert(c)
		}
		tlsConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}

	// Two transports, chosen per request by the proxy decision. Keeping them
	// apart is what lets the proxied one trust its dial target without that
	// trust being keyed on an ADDRESS: if it were, a tenant URL naming the
	// proxy's own host:port (which NO_PROXY or Go's loopback rule would send
	// direct) would inherit the proxy's exemption.
	direct := http.DefaultTransport.(*http.Transport).Clone()
	direct.Proxy = nil
	direct.DialContext = (&net.Dialer{Timeout: timeout, Control: policy.control}).DialContext
	direct.TLSClientConfig = tlsConfig

	proxyFn := deps.proxy
	proxied := http.DefaultTransport.(*http.Transport).Clone()
	proxied.Proxy = func(req *http.Request) (*url.URL, error) {
		u, err := proxyFn(req)
		if err == nil && u == nil {
			// Only reachable if the proxy decision changed between the outer
			// RoundTrip and here. Fail closed rather than dial the target on
			// the unguarded dialer below.
			return nil, errors.New("egress: proxy selection changed mid-request")
		}
		return u, err
	}
	// Unguarded ON PURPOSE: this transport only ever dials the operator's
	// configured proxy, and every request reaching it had its destination
	// judged by checkProxiedTarget first.
	proxied.DialContext = (&net.Dialer{Timeout: timeout}).DialContext
	proxied.TLSClientConfig = tlsConfig

	return &http.Client{
		Timeout: timeout,
		Transport: &egressTransport{
			policy:  policy,
			proxy:   proxyFn,
			lookup:  deps.lookup,
			direct:  direct,
			proxied: proxied,
		},
	}
}

// egressTransport routes each request — every redirect hop included, because
// http.Client sends each hop through RoundTrip — to the direct transport (the
// dial-time guard judges the resolved target IP) or to the proxied one (the
// destination is judged here before the proxy is asked for it).
type egressTransport struct {
	policy  targetPolicy
	proxy   func(*http.Request) (*url.URL, error)
	lookup  func(context.Context, string) ([]net.IP, error)
	direct  *http.Transport
	proxied *http.Transport
}

func (t *egressTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	proxyURL, err := t.proxy(req)
	if err != nil {
		closeBody(req)
		return nil, err
	}
	if proxyURL == nil {
		return t.direct.RoundTrip(req)
	}
	if err := t.policy.checkProxiedTarget(req.Context(), req.URL.Hostname(), t.lookup); err != nil {
		closeBody(req)
		return nil, err
	}
	return t.proxied.RoundTrip(req)
}

// CloseIdleConnections lets http.Client.CloseIdleConnections reach both pools.
func (t *egressTransport) CloseIdleConnections() {
	t.direct.CloseIdleConnections()
	t.proxied.CloseIdleConnections()
}

// closeBody honours the RoundTripper contract: the body is closed even when
// the request is refused before any transport sees it.
func closeBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}
