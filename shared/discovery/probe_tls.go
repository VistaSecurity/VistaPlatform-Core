package discovery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/certificates"
)

func init() {
	tcpProberRegistry["TLS"] = probeTLS
	tcpProberRegistry["HTTPS"] = probeTLS
}

// probeTLS probes TLS/HTTPS connections over a pre-dialed connection and returns
// a neutral ProbeResult. InsecureSkipVerify is intentional — discovery must
// collect certificate data even from self-signed or expired certificates. A
// separate validation pass after the handshake records what the validation
// outcome would have been (status, quality flags, OCSP).
//
// It is the registry entry: the key-exchange support handshakes redial the
// address conn reached directly. A caller with its own dialer uses
// ProbeTLSEndpoint, which hands probeTLSConn a redial through that dialer.
func probeTLS(p *Prober, conn net.Conn, hostname string, port int) (*ProbeResult, error) {
	var redial TLSDialFunc
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok && addr != nil {
		target := addr.String()
		redial = func(timeout time.Duration) (net.Conn, error) { return net.DialTimeout("tcp", target, timeout) }
	}
	return probeTLSConn(context.Background(), p, conn, hostname, port, redial)
}

// probeTLSConn is the one TLS handshake every shared caller makes, over conn.
// redial, when the prober allows support handshakes, carries the key-exchange
// support offers; it must reach exactly the target conn reached.
func probeTLSConn(ctx context.Context, p *Prober, conn net.Conn, hostname string, port int, redial TLSDialFunc) (*ProbeResult, error) {
	res, kex, err := handshakeTLSConn(ctx, p, conn, hostname, port)
	if err != nil {
		return nil, err
	}
	if !p.noSupportHandshakes {
		kex.measureSupport(res, redial, p.timeout)
	}
	return res, nil
}

// tlsKexFollowUp is what the key-exchange support handshakes need from a
// completed main handshake: its state (what it already proved) and its config
// (each support offer is a clone of it, so SNI and client-certificate
// behaviour are identical and a refusal can only be about the groups).
type tlsKexFollowUp struct {
	state  tls.ConnectionState
	config *tls.Config
}

// measureSupport asks the support questions the main handshake left open, each
// over a connection from dial, all within one budget, and records the answers
// (and the negotiated group again, unchanged) on res. A nil dial asks nothing.
func (k *tlsKexFollowUp) measureSupport(res *ProbeResult, dial TLSDialFunc, budget time.Duration) {
	if k == nil || res == nil || dial == nil {
		return
	}
	MeasureTLSKeyExchange(k.state, k.config, dial, budget).ApplyTo(res.Metadata)
}

// TLSHandshakeRefusedError is a handshake the SERVER ended with a TLS alert
// before it had sent anything worth recording. The alert is itself a TLS
// record, so the port speaks TLS even though nothing was negotiated — the
// usual cause is a server that requires a server name it was not offered (a
// scan targets an address, so there is none to offer).
type TLSHandshakeRefusedError struct {
	// Alert is the alert's description as crypto/tls names it, without the
	// "tls: " prefix (e.g. "internal error", "unrecognized name").
	Alert string
	err   error
}

func (e *TLSHandshakeRefusedError) Error() string {
	return "TLS handshake refused by the server: " + e.Alert
}

func (e *TLSHandshakeRefusedError) Unwrap() error { return e.err }

// remoteTLSAlert reports whether err is an alert the peer sent, and its
// description. crypto/tls surfaces a received alert as a *net.OpError with Op
// "remote error" wrapping its unexported alert type (see isGroupRefusal).
// Anything else — a timeout, a reset, EOF, bytes that are not a TLS record —
// is not evidence the port speaks TLS.
func remoteTLSAlert(err error) (string, bool) {
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "remote error" || opErr.Err == nil {
		return "", false
	}
	return strings.TrimPrefix(opErr.Err.Error(), "tls: "), true
}

// handshakeTLSConn makes the main handshake over conn and builds the result —
// certificates, validation, quality flags, OCSP, the negotiated key-exchange
// group — but makes NO support handshake: the returned follow-up is the
// caller's to run, through its own dialer, once it has let go of conn (which
// is closed when this returns).
//
// A handshake the server ends with an alert is still a measurement of a TLS
// endpoint. When the alert arrives AFTER the server's hello and certificate —
// a TLS 1.2 server that requires a client certificate rejects our empty one
// there — the version, cipher suite and chain it sent are recorded, marked
// tls_handshake_completed=false, with no follow-up (every support offer would
// be refused the same way). When it arrives before that, there is nothing to
// record and the error is a *TLSHandshakeRefusedError.
func handshakeTLSConn(ctx context.Context, p *Prober, conn net.Conn, hostname string, port int) (*ProbeResult, *tlsKexFollowUp, error) {
	// Whether the server sent a CertificateRequest: the endpoint is configured
	// for mutual TLS. We hold no client certificate, so we answer with an
	// empty one — exactly what crypto/tls sends when the config has none, so
	// asking changes nothing on the wire. Atomic because the support
	// handshakes clone this config, callback included.
	var clientCertRequested atomic.Bool
	tlsConfig := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true, //nolint:gosec // intentional — discovery requires seeing all certs
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			clientCertRequested.Store(true)
			return &tls.Certificate{}, nil
		},
	}

	tlsConn := tls.Client(conn, tlsConfig)
	defer func() { _ = tlsConn.Close() }()

	if err := tlsConn.SetDeadline(time.Now().Add(p.timeout)); err != nil {
		return nil, nil, fmt.Errorf("failed to set TLS probe deadline: %w", err)
	}

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		alert, refused := remoteTLSAlert(err)
		if !refused {
			return nil, nil, err
		}
		state := tlsConn.ConnectionState()
		if state.Version == 0 || state.CipherSuite == 0 || len(state.PeerCertificates) == 0 {
			return nil, nil, &TLSHandshakeRefusedError{Alert: alert, err: err}
		}
		result := tlsResultFromState(p, state, tlsConfig, hostname, port, clientCertRequested.Load())
		result.Metadata["tls_handshake_completed"] = false
		result.Metadata["tls_handshake_alert"] = alert
		return result, nil, nil
	}

	state := tlsConn.ConnectionState()
	result := tlsResultFromState(p, state, tlsConfig, hostname, port, clientCertRequested.Load())
	return result, &tlsKexFollowUp{state: state, config: tlsConfig}, nil
}

// tlsResultFromState builds the canonical result from what the server sent:
// version, cipher suite, chain, validation, quality flags, OCSP and the
// negotiated key-exchange group.
func tlsResultFromState(p *Prober, state tls.ConnectionState, tlsConfig *tls.Config, hostname string, port int, clientCertRequested bool) *ProbeResult {
	// SupportedCiphers is left empty: this probe negotiates one suite and does
	// not enumerate the rest, and presenting the one it negotiated as the
	// server's supported set claims a measurement nobody made (E-02).
	result := &ProbeResult{
		Protocol:       "TLS",
		Port:           port,
		TLSVersions:    []string{TLSVersionName(state.Version)},
		SelectedCipher: CipherSuiteName(state.CipherSuite),
		ALPN:           []string{state.NegotiatedProtocol},
		Certificates:   certificates.ExtractCertificatesFromX509(state.PeerCertificates),
		Metadata: map[string]interface{}{
			// The *_raw keys carry the numeric wire values. They are
			// deliberately not named "tls_version"/"cipher_suite": those are
			// canonical string-valued keys downstream, and a numeric value
			// under the same name reads as a valid answer while meaning
			// nothing to any consumer.
			"tls_version_raw":     state.Version,
			"cipher_suite_raw":    state.CipherSuite,
			"negotiated_protocol": state.NegotiatedProtocol,
			"tls_fingerprint":     fmt.Sprintf("%d-%d", state.Version, state.CipherSuite),
			// An explicit false is an answer — the server did not ask for a
			// client certificate — and must survive every merge downstream
			// (CLAUDE.md "empty never wins"). Same key as the sensor's TLS
			// enricher.
			"server_requests_client_cert": clientCertRequested,
		},
	}

	// The negotiated key-exchange group. Whether the server also accepts a
	// classical-only and a hybrid-only offer is the follow-up's question.
	MeasureTLSKeyExchange(state, tlsConfig, nil, 0).ApplyTo(result.Metadata)

	// Validate chain, compute quality flags, and check OCSP revocation.
	// The identity we verify against is not necessarily the dial target —
	// probing an IP must not be reported as a hostname mismatch.
	verifyHost := ResolveVerifyHost(hostname, state.PeerCertificates)
	// The OCSP responder URL comes from the server's own certificate, so the
	// query goes through the prober's outbound client — guarded on a platform
	// runtime (outbound.go).
	validation := ValidateAndClassifyCertChainWith(state.PeerCertificates, verifyHost, state.OCSPResponse, p.outboundClient)
	result.CertValidationStatus = validation.ValidationStatus
	result.CertValidationError = validation.ValidationError

	// Refine cert_has_sct/cert_sct_source using the two SCT delivery routes
	// only this live handshake can see (TLS extension + OCSP) — the embedded
	// route above already checked the certificate bytes.
	var sctIssuer *x509.Certificate
	if len(state.PeerCertificates) > 1 {
		sctIssuer = state.PeerCertificates[1]
	}
	RefineSCTFlags(validation.QualityFlags, state.SignedCertificateTimestamps, state.OCSPResponse, sctIssuer)

	for k, v := range validation.QualityFlags {
		result.Metadata[k] = v
	}
	if validation.OCSPStatus != "" {
		result.Metadata["ocsp_status"] = validation.OCSPStatus
		if validation.OCSPDetail != "" {
			result.Metadata["ocsp_detail"] = validation.OCSPDetail
		}
	}

	return result
}
