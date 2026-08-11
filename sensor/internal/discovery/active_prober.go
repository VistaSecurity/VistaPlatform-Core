package discovery

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/certificates"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// ActiveProber handles active probing for TLS/SSH discovery
type ActiveProber struct {
	timeout time.Duration
	prober  *shareddisc.Prober
}

// NewActiveProber creates a new active prober. The protocol probes themselves
// (TLS/SSH/SMB/OT) live in the shared discovery core; this type owns the
// sensor-side orchestration (DNS resolution, the ip×protocol×port sweep, TLS
// version enumeration) and maps shared ProbeResults onto the sensor model.
func NewActiveProber(timeout time.Duration) *ActiveProber {
	return &ActiveProber{
		timeout: timeout,
		prober:  shareddisc.NewProber(timeout),
	}
}

// ProbeTarget probes a single target for crypto configurations.
// All resolved IP addresses are probed to handle multi-homed hosts, CDN pools,
// and DNS round-robin entries.  Duplicate ip:port:protocol combinations
// (from multi-A-record responses) are deduplicated.
func (p *ActiveProber) ProbeTarget(target string, protocols []string, ports []int, options models.DiscoveryOptions) (*models.DiscoveryJobResult, error) {
	result := &models.DiscoveryJobResult{
		Target:      target,
		Status:      "failed",
		ExecutedVia: "sensor",
		CreatedAt:   time.Now(),
	}

	// Resolve target to all IPs
	ips, err := net.LookupIP(target)
	if err != nil {
		result.ErrorCode = "dns_resolution_failed"
		result.ErrorMessage = err.Error()
		return result, nil
	}

	if len(ips) == 0 {
		result.ErrorCode = "no_ip_found"
		result.ErrorMessage = "no IP addresses found for target"
		return result, nil
	}

	// Collect all resolved IPs; deduplicate while preserving order
	seen := make(map[string]bool)
	for _, ip := range ips {
		s := ip.String()
		if !seen[s] {
			seen[s] = true
			result.ResolvedIPs = append(result.ResolvedIPs, s)
		}
	}
	// Keep backward-compat ResolvedIP field pointing at the first IP
	result.ResolvedIP = result.ResolvedIPs[0]

	// Probe every ip × protocol × port combination; deduplicate findings
	var findings []models.DiscoveryFinding
	probed := make(map[string]bool) // "ip:port:protocol" dedup key
	startTime := time.Now()

	for _, ip := range result.ResolvedIPs {
		for _, protocol := range protocols {
			for _, port := range ports {
				key := fmt.Sprintf("%s:%d:%s", ip, port, strings.ToUpper(protocol))
				if probed[key] {
					continue
				}
				probed[key] = true

				finding, err := p.probeProtocolPort(target, ip, protocol, port, options)
				if err != nil {
					continue
				}
				if finding != nil {
					findings = append(findings, *finding)
				}
			}
		}
	}

	// Always enumerate supported TLS versions for TLS findings.
	// This was previously gated behind options.DeepScan but TLS version
	// enumeration is lightweight and critical for compliance assessment.
	findings = p.enumerateTLSVersions(target, result.ResolvedIPs, ports, findings)

	result.Findings = findings
	result.ExecutionTime = time.Since(startTime).Milliseconds()

	if len(findings) > 0 {
		result.Status = "success"
	} else {
		result.Status = "failed"
		result.ErrorCode = "no_findings"
		result.ErrorMessage = "no crypto configurations found"
	}

	return result, nil
}

// SweepHost discovers open crypto/secure-protocol ports on a single host and
// identifies the crypto on each via the shared prober — the "find listeners +
// identify crypto" path for network-sweep jobs (CIDR/range targets). The cheap
// TCP-connect scan runs first so only open ports get the (more expensive)
// protocol probes.
func (p *ActiveProber) SweepHost(host string, ports []int, _ models.DiscoveryOptions) []models.DiscoveryFinding {
	open := p.prober.ScanOpenPorts(host, ports, 0)
	var findings []models.DiscoveryFinding
	for _, port := range open {
		for _, protocol := range shareddisc.ProtocolsForPort(port) {
			res, err := p.prober.Probe(host, host, protocol, port)
			if err != nil || res == nil {
				continue
			}
			finding := probeResultToFinding(res)
			finding.Target = host
			findings = append(findings, *finding)
		}
	}
	return findings
}

// enumerateTLSVersions probes each TLS port with forced MinVersion/MaxVersion
// constraints to determine which TLS versions the server actually accepts.
// Results are merged back into the existing TLS findings for each port.
func (p *ActiveProber) enumerateTLSVersions(hostname string, ips []string, ports []int, findings []models.DiscoveryFinding) []models.DiscoveryFinding {
	// Build a map of port → first TLS finding index.
	// Deep scan currently probes only ips[0], so the first finding for a given
	// port is the one that should be enriched.
	portIdx := make(map[int]int)
	for i, f := range findings {
		if f.Protocol == "TLS" {
			if _, exists := portIdx[f.Port]; !exists {
				portIdx[f.Port] = i
			}
		}
	}

	ip := ""
	if len(ips) > 0 {
		ip = ips[0]
	}

	for _, port := range ports {
		idx, hasFinding := portIdx[port]
		if !hasFinding {
			continue
		}

		accepted := p.prober.EnumerateTLSVersions(hostname, ip, port)
		if len(accepted) > 0 {
			findings[idx].TLSVersions = accepted
		}
	}

	return findings
}

// probeProtocolPort probes a specific protocol/port combination via the shared
// discovery prober (which owns the TCP/UDP dispatch and every protocol probe),
// then maps the neutral ProbeResult onto the sensor's DiscoveryFinding.
func (p *ActiveProber) probeProtocolPort(hostname, ip string, protocol string, port int, _ models.DiscoveryOptions) (*models.DiscoveryFinding, error) {
	res, err := p.prober.Probe(hostname, ip, protocol, port)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, nil
	}
	return probeResultToFinding(res), nil
}

// probeResultToFinding maps a shared discovery ProbeResult onto the sensor's
// DiscoveryFinding model.
func probeResultToFinding(res *shareddisc.ProbeResult) *models.DiscoveryFinding {
	finding := &models.DiscoveryFinding{
		Protocol:              res.Protocol,
		Port:                  res.Port,
		Confidence:            res.Confidence,
		TLSVersions:           res.TLSVersions,
		SelectedCipher:        res.SelectedCipher,
		SupportedCiphers:      res.SupportedCiphers,
		ALPN:                  res.ALPN,
		CertValidationStatus:  res.CertValidationStatus,
		CertValidationError:   res.CertValidationError,
		SSHBanner:             res.SSHBanner,
		SSHKeyTypes:           res.SSHKeyTypes,
		SSHHostKeyType:        res.SSHHostKeyType,
		SSHHostKeyFingerprint: res.SSHHostKeyFingerprint,
		SSHKexAlgorithm:       res.SSHKexAlgorithm,
		RawMetadata:           res.Metadata,
	}
	if finding.RawMetadata == nil {
		finding.RawMetadata = map[string]interface{}{}
	}
	if len(res.Certificates) > 0 {
		certs := make([]models.CertificateInfo, 0, len(res.Certificates))
		for i := range res.Certificates {
			certs = append(certs, convertSharedCert(res.Certificates[i]))
		}
		finding.Certificates = certs
	}
	return finding
}

// convertSharedCert maps a shared certificates.CertificateInfo onto the
// sensor's models.CertificateInfo (field-compatible by design).
func convertSharedCert(c certificates.CertificateInfo) models.CertificateInfo {
	return models.CertificateInfo{
		SubjectDN:               c.SubjectDN,
		IssuerDN:                c.IssuerDN,
		Subject:                 c.Subject,
		Issuer:                  c.Issuer,
		SerialNumber:            c.SerialNumber,
		Serial:                  c.Serial,
		NotBefore:               c.NotBefore,
		NotAfter:                c.NotAfter,
		ValidFrom:               c.ValidFrom,
		ValidTo:                 c.ValidTo,
		KeyAlgorithm:            c.KeyAlgorithm,
		KeySize:                 c.KeySize,
		SignatureAlg:            c.SignatureAlg,
		Signature:               c.Signature,
		IsCA:                    c.IsCA,
		CertificatePEM:          c.CertificatePEM,
		FingerprintSHA256:       c.FingerprintSHA256,
		FingerprintSHA1:         c.FingerprintSHA1,
		SubjectAlternativeNames: c.SubjectAlternativeNames,
		KeyUsage:                c.KeyUsage,
		ExtendedKeyUsage:        c.ExtendedKeyUsage,
		ChainOrder:              c.ChainOrder,
	}
}

// ClassifyCertValidationError maps an x509 verification error to a short status
// label and returns the raw error string for operator visibility.
// Exported for use by the enrichment package. Delegates to the shared
// discovery primitives so the sensor and the in-cluster Platform Sensor
// classify identically.
func ClassifyCertValidationError(err error) (status, detail string) {
	return shareddisc.ClassifyValidationError(err)
}

func isSelfSignedCertificate(cert *x509.Certificate) bool {
	return shareddisc.IsSelfSigned(cert)
}

// VerifyDNSName returns the host string to use as x509.VerifyOptions.DNSName
// when the dial target is host (often a raw IP). Delegates to the shared
// discovery primitive so the sensor and the in-cluster Platform Sensor resolve
// the verification identity identically.
func VerifyDNSName(leaf *x509.Certificate, host string) string {
	return shareddisc.VerifyDNSName(leaf, host)
}

// ClassifyCertificateFlags produces additional metadata flags for a leaf certificate
// and its chain. These are stored in RawMetadata and forwarded to the platform for
// deeper assessment beyond basic chain validation.
// Exported for use by the enrichment package. Delegates to the shared discovery
// primitive so the sensor and the in-cluster Platform Sensor flag identically.
func ClassifyCertificateFlags(leaf *x509.Certificate, chain []*x509.Certificate) map[string]interface{} {
	return shareddisc.ClassifyCertificateFlags(leaf, chain)
}

// CheckOCSPStaple parses the OCSP response stapled by the server during the TLS
// handshake. Exported for use by the enrichment package; delegates to the
// shared discovery primitive.
func CheckOCSPStaple(staple []byte, leaf, issuer *x509.Certificate) (status, detail string) {
	return shareddisc.CheckOCSPStaple(staple, leaf, issuer)
}

// CheckOCSPRevocation performs a direct OCSP query for the leaf certificate.
// Exported for use by the enrichment package; delegates to the shared
// discovery primitive.
func CheckOCSPRevocation(leaf, issuer *x509.Certificate) (status, detail string) {
	return shareddisc.CheckOCSPRevocation(leaf, issuer)
}

// ExtractCertificatesFromX509 extracts certificate metadata from a chain of
// parsed X.509 certificates.  Exported for use by the enrichment package.
func ExtractCertificatesFromX509(certs []*x509.Certificate) []models.CertificateInfo {
	var result []models.CertificateInfo

	for i, cert := range certs {
		// Extract PEM
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemBytes := pem.EncodeToMemory(pemBlock)

		// Calculate SHA256 fingerprint
		fingerprintSHA256 := sha256.Sum256(cert.Raw)
		fingerprintSHA256Hex := hex.EncodeToString(fingerprintSHA256[:])

		// Calculate SHA1 fingerprint
		fingerprintSHA1 := sha1.Sum(cert.Raw)
		fingerprintSHA1Hex := hex.EncodeToString(fingerprintSHA1[:])

		// Extract Subject Alternative Names
		sans := make([]string, 0)
		sans = append(sans, cert.DNSNames...)
		sans = append(sans, cert.EmailAddresses...)
		for _, ip := range cert.IPAddresses {
			sans = append(sans, ip.String())
		}

		// Extract key usage
		keyUsage := extractKeyUsage(cert.KeyUsage)
		extKeyUsage := extractExtendedKeyUsage(cert.ExtKeyUsage)

		// Calculate key size
		keySize := calculateKeySize(cert.PublicKey)

		subjectDN := cert.Subject.String()
		issuerDN := cert.Issuer.String()

		info := models.CertificateInfo{
			SerialNumber:            cert.SerialNumber.String(),
			SubjectDN:               subjectDN,
			IssuerDN:                issuerDN,
			Subject:                 subjectDN, // Keep for backward compatibility
			Issuer:                  issuerDN,  // Keep for backward compatibility
			NotBefore:               cert.NotBefore,
			NotAfter:                cert.NotAfter,
			KeyAlgorithm:            cert.PublicKeyAlgorithm.String(),
			SignatureAlg:            cert.SignatureAlgorithm.String(),
			IsCA:                    cert.IsCA,
			CertificatePEM:          string(pemBytes),
			FingerprintSHA256:       fingerprintSHA256Hex,
			FingerprintSHA1:         fingerprintSHA1Hex,
			SubjectAlternativeNames: sans,
			KeyUsage:                keyUsage,
			ExtendedKeyUsage:        extKeyUsage,
			KeySize:                 keySize,
			ChainOrder:              i, // 0 = leaf, 1+ = intermediates
		}
		result = append(result, info)
	}

	return result
}

func extractCertificates(certs []*tls.Certificate) []models.CertificateInfo {
	var result []models.CertificateInfo

	for i, cert := range certs {
		if cert.Leaf == nil {
			continue
		}

		// Extract PEM from certificate
		var pemBytes []byte
		if cert.Certificate != nil && len(cert.Certificate) > 0 {
			pemBlock := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Certificate[0],
			}
			pemBytes = pem.EncodeToMemory(pemBlock)
		}

		// Calculate fingerprints
		var fingerprintSHA256Hex, fingerprintSHA1Hex string
		if cert.Leaf.Raw != nil {
			fingerprintSHA256 := sha256.Sum256(cert.Leaf.Raw)
			fingerprintSHA256Hex = hex.EncodeToString(fingerprintSHA256[:])
			fingerprintSHA1 := sha1.Sum(cert.Leaf.Raw)
			fingerprintSHA1Hex = hex.EncodeToString(fingerprintSHA1[:])
		}

		// Extract SANs
		sans := make([]string, 0)
		sans = append(sans, cert.Leaf.DNSNames...)
		sans = append(sans, cert.Leaf.EmailAddresses...)
		for _, ip := range cert.Leaf.IPAddresses {
			sans = append(sans, ip.String())
		}

		// Extract key usage
		keyUsage := extractKeyUsage(cert.Leaf.KeyUsage)
		extKeyUsage := extractExtendedKeyUsage(cert.Leaf.ExtKeyUsage)

		// Calculate key size
		keySize := calculateKeySize(cert.Leaf.PublicKey)

		subjectDN := cert.Leaf.Subject.String()
		issuerDN := cert.Leaf.Issuer.String()

		info := models.CertificateInfo{
			SerialNumber:            cert.Leaf.SerialNumber.String(),
			SubjectDN:               subjectDN,
			IssuerDN:                issuerDN,
			Subject:                 subjectDN, // Keep for backward compatibility
			Issuer:                  issuerDN,  // Keep for backward compatibility
			NotBefore:               cert.Leaf.NotBefore,
			NotAfter:                cert.Leaf.NotAfter,
			KeyAlgorithm:            cert.Leaf.PublicKeyAlgorithm.String(),
			SignatureAlg:            cert.Leaf.SignatureAlgorithm.String(),
			IsCA:                    cert.Leaf.IsCA,
			CertificatePEM:          string(pemBytes),
			FingerprintSHA256:       fingerprintSHA256Hex,
			FingerprintSHA1:         fingerprintSHA1Hex,
			SubjectAlternativeNames: sans,
			KeyUsage:                keyUsage,
			ExtendedKeyUsage:        extKeyUsage,
			KeySize:                 keySize,
			ChainOrder:              i, // 0 = leaf, 1+ = intermediates
		}

		result = append(result, info)
	}

	return result
}

// extractKeyUsage converts x509.KeyUsage flags to string array
func extractKeyUsage(keyUsage x509.KeyUsage) []string {
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

// extractExtendedKeyUsage converts x509.ExtKeyUsage OIDs to string array
func extractExtendedKeyUsage(extKeyUsage []x509.ExtKeyUsage) []string {
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
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			usage = append(usage, "MicrosoftServerGatedCrypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			usage = append(usage, "NetscapeServerGatedCrypto")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			usage = append(usage, "MicrosoftCommercialCodeSigning")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			usage = append(usage, "MicrosoftKernelCodeSigning")
		default:
			usage = append(usage, fmt.Sprintf("Unknown(%d)", eku))
		}
	}
	return usage
}

// calculateKeySize calculates the actual key size from a public key
func calculateKeySize(pubKey interface{}) int {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256 // Ed25519 uses 256-bit keys
	default:
		return 0 // Unknown key type
	}
}
