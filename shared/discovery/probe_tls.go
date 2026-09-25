package discovery

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
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
func probeTLS(p *Prober, conn net.Conn, hostname string, port int) (*ProbeResult, error) {
	tlsConfig := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true, //nolint:gosec // intentional — discovery requires seeing all certs
	}

	tlsConn := tls.Client(conn, tlsConfig)
	defer func() { _ = tlsConn.Close() }()

	if err := tlsConn.SetDeadline(time.Now().Add(p.timeout)); err != nil {
		return nil, fmt.Errorf("failed to set TLS probe deadline: %w", err)
	}

	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	state := tlsConn.ConnectionState()

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
		},
	}

	// The negotiated key-exchange group, and whether the server also accepts a
	// classical-only and a hybrid-only offer. The extra handshakes redial the
	// address this connection reached, so they touch exactly this target.
	var redial TLSDialFunc
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok && addr != nil && !p.noSupportHandshakes {
		target := addr.String()
		redial = func(timeout time.Duration) (net.Conn, error) { return net.DialTimeout("tcp", target, timeout) }
	}
	MeasureTLSKeyExchange(state, tlsConfig, redial, p.timeout).ApplyTo(result.Metadata)

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

	return result, nil
}
