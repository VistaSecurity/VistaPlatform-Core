package services

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/certificates"
	"github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	"github.com/vistasecurity/vistaplatform/shared/jobunits"
)

// TLSHandshakeService performs TLS handshakes against cloud-discovered endpoints
// to extract certificate chains and negotiated TLS parameters.
type TLSHandshakeService struct {
	timeout time.Duration

	// dial opens every connection a handshake makes (the handshake and its
	// key-exchange support handshakes). A plain net.Dialer: the endpoints are
	// the tenant's own load balancers / CDNs / gateways as its cloud API
	// reported them, and this dial has never been address-guarded. A field so
	// a test can count connections.
	dial discovery.ContextDialFunc

	// prober is the shared TLS probe. Its OCSP query — the responder URL is in
	// the probed server's certificate — goes through the platform fetch guard:
	// this service runs inside the cluster, so a certificate must not point
	// it at loopback, the metadata service or an in-cluster address.
	prober *discovery.Prober
}

// platformFetchGuard is the address rule for fetches a probed server's data
// asks for (the OCSP responder), built once so the platform's own addresses
// are read when the process is up. The same guard platformOCSPClient uses.
var platformFetchGuard = sync.OnceValue(func() discovery.AddressGuard {
	return dispatchguard.PlatformFetchGuard()
})

// TLSHandshakeResult contains the results of a TLS handshake
type TLSHandshakeResult struct {
	Success      bool
	TLSVersion   string
	CipherSuite  string
	ALPN         string
	Certificates []map[string]interface{} // Pipeline-compatible certificate format
	Error        string

	// KeyExchange is the negotiated group and the endpoint's classical /
	// hybrid post-quantum support, measured by the same shared code as every
	// other TLS probe. applyHandshakeKeyExchange copies it onto a crypto
	// config.
	KeyExchange discovery.TLSKeyExchange

	// Validation is what the probe measured about whether the certificate can
	// be trusted: chain validation outcome, quality flags, OCSP status — under
	// the canonical top-level keys scan-engine TLS findings use
	// (jobunits.TLSValidationMetadata). applyHandshakeValidation copies it
	// onto a crypto config. Nil when the handshake did not succeed.
	Validation map[string]interface{}
}

// applyHandshakeValidation writes a handshake's certificate validation onto a
// cloud crypto config, where WriteSensorDiscoveries forwards it to the
// finding. Without it the probe's chain validation and OCSP answer — the
// slowest part of the handshake — were measured and discarded.
func applyHandshakeValidation(cfg map[string]interface{}, r *TLSHandshakeResult) {
	if cfg == nil || r == nil {
		return
	}
	for k, v := range r.Validation {
		cfg[k] = v
	}
}

// applyHandshakeMeasurements is what every cloud collector site applies from a
// successful handshake onto its crypto config beyond the cipher and
// certificates: the key-exchange measurement and the certificate validation.
func applyHandshakeMeasurements(cfg map[string]interface{}, r *TLSHandshakeResult) {
	applyHandshakeKeyExchange(cfg, r)
	applyHandshakeValidation(cfg, r)
}

// applyHandshakeKeyExchange writes a handshake's key-exchange measurement onto
// a cloud crypto config, under the keys WriteSensorDiscoveries forwards and
// convertCryptoConfigToAsset reads.
func applyHandshakeKeyExchange(cfg map[string]interface{}, r *TLSHandshakeResult) {
	if cfg == nil || r == nil {
		return
	}
	r.KeyExchange.ApplyTo(cfg)
}

// NewTLSHandshakeService creates a new TLS handshake service
func NewTLSHandshakeService(timeout time.Duration) *TLSHandshakeService {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &TLSHandshakeService{
		timeout: timeout,
		dial:    (&net.Dialer{Timeout: timeout}).DialContext,
		prober:  discovery.NewProber(timeout).WithOutboundAddressGuard(platformFetchGuard()),
	}
}

// PerformHandshake connects to the given hostname:port, performs a TLS handshake,
// and extracts the certificate chain and negotiated parameters.
// Returns nil result (not error) if the host is unreachable -- callers should
// treat a nil result as "handshake skipped" and continue without certificates.
func (s *TLSHandshakeService) PerformHandshake(ctx context.Context, hostname string, port int) (*TLSHandshakeResult, error) {
	if hostname == "" {
		return nil, fmt.Errorf("hostname is required")
	}
	return s.handshakeTo(ctx, hostname, net.JoinHostPort(hostname, strconv.Itoa(port)))
}

// cloudHandshakeTimeout bounds each cloud collector's handshake (and, as one
// shared budget, its key-exchange support handshakes).
const cloudHandshakeTimeout = 10 * time.Second

// cloudTLSHandshake is the handshake every cloud collector site makes against
// the tenant's own load balancer / CDN / gateway. A variable only so a test can
// point a real collector path at a loopback fixture; production never
// reassigns it.
var cloudTLSHandshake = func(ctx context.Context, hostname string, port int) (*TLSHandshakeResult, error) {
	return NewTLSHandshakeService(cloudHandshakeTimeout).PerformHandshake(ctx, hostname, port)
}

// handshakeTo is PerformHandshake with the dial address given separately from
// the SNI name. It is the shared TLS probe (discovery.ProbeTLSEndpoint),
// mapped onto TLSHandshakeResult.
func (s *TLSHandshakeService) handshakeTo(ctx context.Context, hostname, address string) (*TLSHandshakeResult, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return &TLSHandshakeResult{Success: false, Error: fmt.Sprintf("connection failed: %v", err)}, nil
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return &TLSHandshakeResult{Success: false, Error: fmt.Sprintf("connection failed: invalid port %q", portText)}, nil
	}

	// Every connection — the handshake and the key-exchange support
	// handshakes — goes through s.dial. The support handshakes redial the
	// ADDRESS the first connection reached, not the hostname: a CDN or
	// load-balancer name resolves to many addresses and a re-resolution could
	// land on a different one. They keep the same SNI.
	connected := false
	dial := discovery.PinToReachedAddress(func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := s.dial(ctx, network, address)
		if err == nil {
			connected = true
		}
		return conn, err
	})

	res, err := s.prober.ProbeTLSEndpoint(ctx, host, port, discovery.TLSEndpointOptions{Hostname: hostname, Dial: dial})
	if err != nil {
		if !connected {
			// Network unreachable is expected for private/internal resources
			log.Printf("TLS handshake: connection to %s failed (likely private endpoint): %v", address, err)
			return &TLSHandshakeResult{Success: false, Error: fmt.Sprintf("connection failed: %v", err)}, nil
		}
		log.Printf("TLS handshake: handshake with %s failed: %v", address, err)
		return &TLSHandshakeResult{Success: false, Error: fmt.Sprintf("handshake failed: %v", err)}, nil
	}

	result := &TLSHandshakeResult{
		Success:      true,
		CipherSuite:  res.SelectedCipher,
		Certificates: pipelineCertificateMaps(res.Certificates),
		// The negotiated group and the classical / hybrid support the probe
		// measured, as the struct applyHandshakeKeyExchange writes.
		KeyExchange: discovery.TLSKeyExchangeFromMetadata(res.Metadata),
		Validation:  jobunits.TLSValidationMetadata(res),
	}
	if len(res.TLSVersions) > 0 {
		result.TLSVersion = res.TLSVersions[0]
	}
	result.ALPN, _ = res.Metadata["negotiated_protocol"].(string)

	log.Printf("TLS handshake: successfully connected to %s -- TLS %s, cipher %s, %d certificates",
		address, result.TLSVersion, result.CipherSuite, len(result.Certificates))

	return result, nil
}

// pipelineCertificateMaps renders the shared probe's certificate chain in the
// map format the cloud collectors store and the inventory-service's
// extractCertificateData() reads from RawData["certificates"] — the canonical
// entry (CLAUDE.md "Single certificate format") plus the "subject" / "issuer"
// aliases this service has always written. The values come from
// certificates.ExtractCertificatesFromX509; this only names them.
func pipelineCertificateMaps(certs []certificates.CertificateInfo) []map[string]interface{} {
	var result []map[string]interface{}
	for _, c := range certs {
		result = append(result, map[string]interface{}{
			"subject_dn":                c.SubjectDN,
			"issuer_dn":                 c.IssuerDN,
			"serial_number":             c.SerialNumber,
			"not_before":                c.NotBefore.Format(time.RFC3339),
			"not_after":                 c.NotAfter.Format(time.RFC3339),
			"fingerprint_sha256":        c.FingerprintSHA256,
			"fingerprint_sha1":          c.FingerprintSHA1,
			"certificate_pem":           c.CertificatePEM,
			"subject_alternative_names": c.SubjectAlternativeNames,
			"key_usage":                 c.KeyUsage,
			"extended_key_usage":        c.ExtendedKeyUsage,
			"key_algorithm":             c.KeyAlgorithm,
			"signature_alg":             c.SignatureAlg,
			"key_size":                  c.KeySize,
			"is_ca":                     c.IsCA,
			"chain_order":               c.ChainOrder, // 0 = leaf, 1+ = intermediates

			// Backward compatibility fields
			"subject": c.SubjectDN,
			"issuer":  c.IssuerDN,
		})
	}
	return result
}

// EnrichCertificatesWithACM merges ACM metadata into handshake-discovered certificates.
// It matches by domain name or SANs and adds ACM-specific fields like ARN, renewal status, etc.
func EnrichCertificatesWithACM(certificates []map[string]interface{}, acmCerts []map[string]interface{}) []map[string]interface{} {
	if len(certificates) == 0 || len(acmCerts) == 0 {
		return certificates
	}

	for i, cert := range certificates {
		certDomain := ""
		if sans, ok := cert["subject_alternative_names"].([]string); ok && len(sans) > 0 {
			certDomain = sans[0]
		}
		if certDomain == "" {
			if subjectDN, ok := cert["subject_dn"].(string); ok {
				certDomain = subjectDN
			}
		}

		// Try to find a matching ACM certificate
		for _, acmCert := range acmCerts {
			acmDetails, ok := acmCert["details"].(map[string]interface{})
			if !ok {
				continue
			}

			acmDomain := ""
			if d, ok := acmDetails["domain_name"].(string); ok {
				acmDomain = d
			}

			// Match by domain name in SANs or subject
			matched := false
			if acmDomain != "" && certDomain != "" {
				// Check if the ACM domain matches any SAN
				if sans, ok := cert["subject_alternative_names"].([]string); ok {
					for _, san := range sans {
						if san == acmDomain || matchesWildcard(san, acmDomain) || matchesWildcard(acmDomain, san) {
							matched = true
							break
						}
					}
				}
			}

			if matched {
				// Enrich with ACM metadata
				acmMetadata := map[string]interface{}{}
				if arn, ok := acmCert["arn"].(string); ok {
					acmMetadata["arn"] = arn
				}
				if status, ok := acmDetails["status"].(string); ok {
					acmMetadata["status"] = status
				}
				if certType, ok := acmDetails["type"].(string); ok {
					acmMetadata["type"] = certType
				}
				if renewal, ok := acmDetails["renewal_eligibility"].(string); ok {
					acmMetadata["renewal_eligibility"] = renewal
				}
				if inUseBy, ok := acmDetails["in_use_by"].([]string); ok {
					acmMetadata["in_use_by"] = inUseBy
				}
				if validationOpts, ok := acmDetails["domain_validation_options"]; ok {
					acmMetadata["domain_validation_options"] = validationOpts
				}

				certificates[i]["acm_metadata"] = acmMetadata
				break
			}
		}
	}

	return certificates
}

// matchesWildcard checks if a wildcard pattern matches a domain
func matchesWildcard(pattern, domain string) bool {
	if len(pattern) < 2 || pattern[:2] != "*." {
		return false
	}
	// *.example.com matches foo.example.com
	suffix := pattern[1:] // .example.com
	if len(domain) > len(suffix) && domain[len(domain)-len(suffix):] == suffix {
		return true
	}
	return false
}
