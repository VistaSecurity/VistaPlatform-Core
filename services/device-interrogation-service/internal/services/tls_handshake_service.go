package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // intentional — SHA-1 cert fingerprint is the standard X.509 identifier (see line 135), not a security primitive
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"
)

// TLSHandshakeService performs TLS handshakes against cloud-discovered endpoints
// to extract certificate chains and negotiated TLS parameters.
type TLSHandshakeService struct {
	timeout time.Duration
}

// TLSHandshakeResult contains the results of a TLS handshake
type TLSHandshakeResult struct {
	Success      bool
	TLSVersion   string
	CipherSuite  string
	ALPN         string
	Certificates []map[string]interface{} // Pipeline-compatible certificate format
	Error        string
}

// NewTLSHandshakeService creates a new TLS handshake service
func NewTLSHandshakeService(timeout time.Duration) *TLSHandshakeService {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &TLSHandshakeService{
		timeout: timeout,
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

	address := net.JoinHostPort(hostname, strconv.Itoa(port))

	// Create a dialer with context support and timeout
	dialer := &net.Dialer{
		Timeout: s.timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		// Network unreachable is expected for private/internal resources
		log.Printf("TLS handshake: connection to %s failed (likely private endpoint): %v", address, err)
		return &TLSHandshakeResult{
			Success: false,
			Error:   fmt.Sprintf("connection failed: %v", err),
		}, nil
	}
	defer conn.Close()

	// Configure TLS with SNI
	tlsConfig := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true, //nolint:gosec // intentional — discovery probes any TLS endpoint regardless of certificate validity
	}

	tlsConn := tls.Client(conn, tlsConfig)
	defer tlsConn.Close()

	// Set connection deadline
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(s.timeout)
	}
	tlsConn.SetDeadline(deadline)

	// Perform TLS handshake
	err = tlsConn.Handshake()
	if err != nil {
		log.Printf("TLS handshake: handshake with %s failed: %v", address, err)
		return &TLSHandshakeResult{
			Success: false,
			Error:   fmt.Sprintf("handshake failed: %v", err),
		}, nil
	}

	// Extract TLS information
	state := tlsConn.ConnectionState()

	result := &TLSHandshakeResult{
		Success:      true,
		TLSVersion:   tlsVersionToString(state.Version),
		CipherSuite:  cipherSuiteToString(state.CipherSuite),
		ALPN:         state.NegotiatedProtocol,
		Certificates: convertX509ToPipelineFormat(state.PeerCertificates),
	}

	log.Printf("TLS handshake: successfully connected to %s -- TLS %s, cipher %s, %d certificates",
		address, result.TLSVersion, result.CipherSuite, len(result.Certificates))

	return result, nil
}

// convertX509ToPipelineFormat converts x509 certificates into the map format
// expected by the inventory-service's extractCertificateData() function.
// Field names match what extractCertificatesFromFinding() looks for in RawData["certificates"].
func convertX509ToPipelineFormat(certs []*x509.Certificate) []map[string]interface{} {
	var result []map[string]interface{}

	for i, cert := range certs {
		// Encode to PEM
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemBytes := pem.EncodeToMemory(pemBlock)

		// Calculate fingerprints
		fingerprintSHA256 := sha256.Sum256(cert.Raw)
		fingerprintSHA256Hex := hex.EncodeToString(fingerprintSHA256[:])

		fingerprintSHA1 := sha1.Sum(cert.Raw) //nolint:gosec // intentional — SHA-1 fingerprint is the standard X.509 identifier, not used as a security primitive
		fingerprintSHA1Hex := hex.EncodeToString(fingerprintSHA1[:])

		// Extract Subject Alternative Names
		sans := make([]string, 0)
		sans = append(sans, cert.DNSNames...)
		sans = append(sans, cert.EmailAddresses...)
		for _, ip := range cert.IPAddresses {
			sans = append(sans, ip.String())
		}

		// Extract key usage
		keyUsage := extractX509KeyUsage(cert.KeyUsage)
		extKeyUsage := extractX509ExtendedKeyUsage(cert.ExtKeyUsage)

		// Calculate key size
		keySize := calculatePublicKeySize(cert.PublicKey)

		subjectDN := cert.Subject.String()
		issuerDN := cert.Issuer.String()

		certMap := map[string]interface{}{
			// Primary fields (used by extractCertificateData)
			"subject_dn":                subjectDN,
			"issuer_dn":                 issuerDN,
			"serial_number":             cert.SerialNumber.String(),
			"not_before":                cert.NotBefore.Format(time.RFC3339),
			"not_after":                 cert.NotAfter.Format(time.RFC3339),
			"fingerprint_sha256":        fingerprintSHA256Hex,
			"fingerprint_sha1":          fingerprintSHA1Hex,
			"certificate_pem":           string(pemBytes),
			"subject_alternative_names": sans,
			"key_usage":                 keyUsage,
			"extended_key_usage":        extKeyUsage,
			"key_algorithm":             cert.PublicKeyAlgorithm.String(),
			"signature_alg":             cert.SignatureAlgorithm.String(),
			"key_size":                  keySize,
			"is_ca":                     cert.IsCA,
			"chain_order":               i, // 0 = leaf, 1+ = intermediates

			// Backward compatibility fields
			"subject": subjectDN,
			"issuer":  issuerDN,
		}

		result = append(result, certMap)
	}

	return result
}

// tlsVersionToString converts a TLS version constant to a human-readable string
func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown-0x%04X", version)
	}
}

// cipherSuiteToString converts a TLS cipher suite constant to its IANA name
func cipherSuiteToString(suite uint16) string {
	switch suite {
	case tls.TLS_RSA_WITH_RC4_128_SHA:
		return "TLS_RSA_WITH_RC4_128_SHA"
	case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_RSA_WITH_AES_128_CBC_SHA256"
	case 0x003D: // TLS_RSA_WITH_AES_256_CBC_SHA256
		return "TLS_RSA_WITH_AES_256_CBC_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:
		return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
		return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
	case tls.TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case tls.TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	default:
		return fmt.Sprintf("Unknown-0x%04X", suite)
	}
}

// extractX509KeyUsage converts x509.KeyUsage flags to a string array
func extractX509KeyUsage(keyUsage x509.KeyUsage) []string {
	var usage []string
	if keyUsage&x509.KeyUsageDigitalSignature != 0 {
		usage = append(usage, "DigitalSignature")
	}
	if keyUsage&x509.KeyUsageContentCommitment != 0 {
		usage = append(usage, "ContentCommitment")
	}
	if keyUsage&x509.KeyUsageKeyEncipherment != 0 {
		usage = append(usage, "KeyEncipherment")
	}
	if keyUsage&x509.KeyUsageDataEncipherment != 0 {
		usage = append(usage, "DataEncipherment")
	}
	if keyUsage&x509.KeyUsageKeyAgreement != 0 {
		usage = append(usage, "KeyAgreement")
	}
	if keyUsage&x509.KeyUsageCertSign != 0 {
		usage = append(usage, "CertSign")
	}
	if keyUsage&x509.KeyUsageCRLSign != 0 {
		usage = append(usage, "CRLSign")
	}
	if keyUsage&x509.KeyUsageEncipherOnly != 0 {
		usage = append(usage, "EncipherOnly")
	}
	if keyUsage&x509.KeyUsageDecipherOnly != 0 {
		usage = append(usage, "DecipherOnly")
	}
	return usage
}

// extractX509ExtendedKeyUsage converts x509.ExtKeyUsage OIDs to a string array
func extractX509ExtendedKeyUsage(extKeyUsage []x509.ExtKeyUsage) []string {
	var usage []string
	for _, eku := range extKeyUsage {
		switch eku {
		case x509.ExtKeyUsageAny:
			usage = append(usage, "Any")
		case x509.ExtKeyUsageServerAuth:
			usage = append(usage, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			usage = append(usage, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			usage = append(usage, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			usage = append(usage, "EmailProtection")
		case x509.ExtKeyUsageIPSECEndSystem:
			usage = append(usage, "IPSECEndSystem")
		case x509.ExtKeyUsageIPSECTunnel:
			usage = append(usage, "IPSECTunnel")
		case x509.ExtKeyUsageIPSECUser:
			usage = append(usage, "IPSECUser")
		case x509.ExtKeyUsageTimeStamping:
			usage = append(usage, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			usage = append(usage, "OCSPSigning")
		default:
			usage = append(usage, fmt.Sprintf("Unknown(%d)", eku))
		}
	}
	return usage
}

// calculatePublicKeySize determines the key size from a public key
func calculatePublicKeySize(pubKey interface{}) int {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256 // Ed25519 uses 256-bit keys
	default:
		return 0
	}
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
