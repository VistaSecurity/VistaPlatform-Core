package discovery

import (
	"context"
	"crypto/tls"
	"net"
	"slices"
	"strconv"
	"time"
)

// ContextDialFunc dials one address. It is the shape of net.Dialer.DialContext,
// so a caller's guarded dialer (dialguard, a sensor's own) plugs in directly.
type ContextDialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// TLSEndpointOptions configures ProbeTLSEndpoint.
type TLSEndpointOptions struct {
	// Hostname is the SNI to present and the identity the certificate is
	// checked against. Empty means no SNI (the identity is then taken from the
	// certificate, see ResolveVerifyHost).
	Hostname string
	// Dial carries EVERY connection the probe makes: the main handshake, the
	// key-exchange support handshakes and the version enumeration. Nil means a
	// plain net.Dialer.
	Dial ContextDialFunc
	// EnumerateVersions also works out which TLS versions the server accepts,
	// one forced-version handshake per version the main handshake did not
	// already prove. A prober built WithoutSupportHandshakes ignores it: that
	// prober promised the target one handshake.
	EnumerateVersions bool
}

// ProbeTLSEndpoint handshakes host:port through opts.Dial and returns the
// shared TLS ProbeResult — certificates, validation, quality flags, OCSP, the
// negotiated key exchange (and, unless WithoutSupportHandshakes, classical /
// hybrid support), whether the server asked for a client certificate, and with
// EnumerateVersions the accepted versions. Every handshake is bounded by the
// prober's timeout and by ctx.
//
// It is the entry point for a caller that already knows the endpoint — the
// standalone sensor's TLS enricher, device interrogation — as opposed to the
// scan engine, which identifies a port first. host is what opts.Dial is asked
// to reach: an address literal, or a name the caller's dialer resolves under
// its own guard.
func (p *Prober) ProbeTLSEndpoint(ctx context.Context, host string, port int, opts TLSEndpointOptions) (*ProbeResult, error) {
	dial := opts.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	dialOnce := func(ctx context.Context) (net.Conn, error) {
		dctx, cancel := context.WithTimeout(ctx, p.timeout)
		defer cancel()
		return dial(dctx, "tcp", address)
	}

	conn, err := dialOnce(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	redial := func(timeout time.Duration) (net.Conn, error) {
		dctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return dial(dctx, "tcp", address)
	}
	res, err := probeTLSConn(ctx, p, conn, opts.Hostname, port, redial)
	if err != nil {
		return nil, err
	}
	if opts.EnumerateVersions && !p.noSupportHandshakes {
		_ = conn.Close() // the main handshake is done; hold one connection at a time
		applyTLSVersions(res, enumerateTLSVersions(ctx, dialOnce, opts.Hostname, p.timeout, negotiatedTLSVersion(res)))
	}
	return res, nil
}

// tlsVersionsNewestFirst is the order enumeration tests versions in, and the
// order an accepted list is reported in.
var tlsVersionsNewestFirst = []uint16{tls.VersionTLS13, tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10}

// enumerateTLSVersions makes one forced-version handshake per TLS version,
// newest first, each over a fresh connection from dial and bounded by timeout
// and ctx, and returns the labels of the versions the server accepted. skip,
// when non-zero, is a version already proven (the negotiated one): it is
// neither tested again nor returned. A version whose connection could not be
// made, or whose deadline could not be set, is left out — untested, not
// refused.
func enumerateTLSVersions(ctx context.Context, dial func(context.Context) (net.Conn, error), hostname string, timeout time.Duration, skip uint16) []string {
	var accepted []string
	for _, ver := range tlsVersionsNewestFirst {
		if ver == skip {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		if tlsVersionAccepted(ctx, dial, hostname, timeout, ver) {
			accepted = append(accepted, TLSVersionName(ver))
		}
	}
	return accepted
}

func tlsVersionAccepted(ctx context.Context, dial func(context.Context) (net.Conn, error), hostname string, timeout time.Duration, ver uint16) bool {
	conn, err := dial(ctx)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true, //nolint:gosec // intentional — discovery probes any endpoint
		MinVersion:         ver,
		MaxVersion:         ver,
	})
	defer func() { _ = tlsConn.Close() }()
	// Without a deadline the handshake below can block indefinitely, so a
	// failure here means this version cannot be tested — skip it rather than
	// record an untested version as unaccepted.
	if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false
	}
	return tlsConn.HandshakeContext(ctx) == nil
}

// negotiatedTLSVersion is the wire version of the result's main handshake, or 0.
func negotiatedTLSVersion(res *ProbeResult) uint16 {
	if v, ok := res.Metadata["tls_version_raw"].(uint16); ok {
		return v
	}
	return 0
}

// applyTLSVersions records enumerated versions on res. The negotiated version
// stays FIRST — it is what jobunits.TLSProbeMetadata reports as "version" —
// and the other accepted versions follow, newest first. For a server that
// negotiates its newest version, which is every conforming server, that is
// exactly the newest-first list the legacy enumeration reports.
func applyTLSVersions(res *ProbeResult, others []string) {
	if len(others) == 0 {
		return
	}
	versions := make([]string, 0, len(res.TLSVersions)+len(others))
	versions = append(versions, res.TLSVersions...)
	for _, v := range others {
		if !slices.Contains(versions, v) {
			versions = append(versions, v)
		}
	}
	res.TLSVersions = versions
}
