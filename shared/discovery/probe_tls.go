package discovery

import (
	"crypto/tls"
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
	defer tlsConn.Close()

	tlsConn.SetDeadline(time.Now().Add(p.timeout))

	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	state := tlsConn.ConnectionState()

	cipher := CipherSuiteName(state.CipherSuite)
	result := &ProbeResult{
		Protocol:         "TLS",
		Port:             port,
		TLSVersions:      []string{TLSVersionName(state.Version)},
		SelectedCipher:   cipher,
		SupportedCiphers: []string{cipher},
		ALPN:             []string{state.NegotiatedProtocol},
		Certificates:     certificates.ExtractCertificatesFromX509(state.PeerCertificates),
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

	// Validate chain, compute quality flags, and check OCSP revocation.
	// The identity we verify against is not necessarily the dial target —
	// probing an IP must not be reported as a hostname mismatch.
	verifyHost := ResolveVerifyHost(hostname, state.PeerCertificates)
	validation := ValidateAndClassifyCertChain(state.PeerCertificates, verifyHost, state.OCSPResponse)
	result.CertValidationStatus = validation.ValidationStatus
	result.CertValidationError = validation.ValidationError
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
