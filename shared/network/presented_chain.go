package network

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// errChainCaptured aborts the diagnostic handshake once the server's
// certificates have been read. Returning it from VerifyConnection fails the
// handshake on OUR side, so the connection never carries an HTTP request.
var errChainCaptured = errors.New("egress: presented chain captured; handshake abandoned by design")

// CapturePresentedChain reads the certificate chain the server at rawURL
// presents, leaf first, without trusting it and without sending it anything.
//
// It exists for one purpose: when a connection fails with "unknown authority",
// a person is shown the chain so they can decide whether to trust its CA —
// rather than being asked to find and paste a PEM file.
//
// What makes it safe to skip verification here, and only here:
//
//   - Nothing is sent. The handshake is abandoned inside VerifyConnection —
//     before the client's Finished message — so no HTTP request, header,
//     token or body is ever written to the connection. The request it is
//     driven by carries no credential in any case.
//   - Nothing is trusted. The certificates are returned as data for display;
//     the connection that read them is closed, never reused, and the caller's
//     real client still verifies against its own roots.
//   - The same guard applies. It is built from the same [EgressOptions] as the
//     caller's real client, so the private-endpoint opt-in, the operator's
//     switch, the platform-internal ranges and the proxy handling are exactly
//     the real client's. Redirects cannot arise (no response is ever read).
//
// It returns an error when the address is refused, unreachable, not HTTPS, or
// presented no certificate.
func CapturePresentedChain(ctx context.Context, rawURL string, timeout time.Duration,
	opts EgressOptions) ([]*x509.Certificate, error) {
	return capturePresentedChain(ctx, rawURL, timeout, opts, egressDeps{})
}

func capturePresentedChain(ctx context.Context, rawURL string, timeout time.Duration,
	opts EgressOptions, deps egressDeps) ([]*x509.Certificate, error) {

	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("capture chain: unparseable URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") || u.Host == "" {
		return nil, errors.New("capture chain: only an https:// URL presents a certificate chain")
	}
	policy := newTargetPolicy(opts.AllowPrivateEndpoint && PrivateEndpointsPermitted())
	if policy.configErr != nil {
		return nil, policy.configErr
	}

	var (
		mu       sync.Mutex
		captured []*x509.Certificate
	)
	probe := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Diagnostic only: the handshake is abandoned in VerifyConnection
		// before any application data, and the certificates read are shown
		// to a person, never trusted. See the function comment.
		InsecureSkipVerify: true, //nolint:gosec // G402: result is displayed, never trusted; nothing is sent
		VerifyConnection: func(cs tls.ConnectionState) error {
			mu.Lock()
			captured = append([]*x509.Certificate(nil), cs.PeerCertificates...)
			mu.Unlock()
			return errChainCaptured
		},
	}
	client := buildEgressClient(timeout, policy, probe, deps)
	defer client.CloseIdleConnections()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	// Origin only: no path, no query, no header beyond what net/http adds.
	origin := &url.URL{Scheme: "https", Host: u.Host, Path: "/"}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, origin.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, doErr := client.Do(req)
	if resp != nil {
		// Unreachable: VerifyConnection always fails the handshake.
		_ = resp.Body.Close()
		return nil, errors.New("capture chain: the diagnostic handshake unexpectedly completed")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(captured) == 0 {
		if doErr == nil {
			doErr = errors.New("no certificate presented")
		}
		return nil, fmt.Errorf("capture chain: %w", doErr)
	}
	return captured, nil
}
