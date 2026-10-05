package discovery

// The sensor model's side of the shared probe and certificate shapes: what
// the TLS enricher (enrichment/tls_enricher.go) and the passive capture
// assemblers (capture/*) still need. The protocols × ports executor that
// used to live beside these (ActiveProber, JobExecutor) was deleted in
// WP5 — every active scan runs on shared/discovery's engine
// (shared/sensordispatch/planrun) — and these were moved here from it
// unchanged.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/certificates"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// FindingFromProbeResult maps a shared discovery ProbeResult onto the sensor's
// DiscoveryFinding, for the TLS enricher, which probes through
// shared/discovery.ProbeTLSEndpoint.
func FindingFromProbeResult(res *shareddisc.ProbeResult) *models.DiscoveryFinding {
	if res == nil {
		return nil
	}
	return probeResultToFinding(res)
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
		SSHProtocolVersion:    res.SSHProtocolVersion,
		SSHSoftwareVersion:    res.SSHSoftwareVersion,

		// The SSH algorithm fields are carried as TYPED fields, not left to
		// RawMetadata: the sensor serializes RawMetadata as "raw_metadata",
		// and sensor-manager's own DiscoveryFinding has no field under that
		// name, so anything reaching the platform by that route alone is
		// dropped at the upload boundary. buildFindingDetails reads these.
		SSHKexAlgorithm:     res.SSHKexAlgorithm,
		SSHHostKeyAlgorithm: res.SSHHostKeyAlgorithm,
		SSHEncryptionAlgC2S: res.SSHEncryptionAlgC2S,
		SSHEncryptionAlgS2C: res.SSHEncryptionAlgS2C,
		SSHMACAlgC2S:        res.SSHMACAlgC2S,
		SSHMACAlgS2C:        res.SSHMACAlgS2C,
		SSHCompressionAlg:   res.SSHCompressionAlg,

		SSHServerKexAlgorithms:     res.SSHServerKexAlgorithms,
		SSHServerHostKeyAlgorithms: res.SSHServerHostKeyAlgorithms,
		SSHServerEncryptionC2S:     res.SSHServerEncryptionC2S,
		SSHServerEncryptionS2C:     res.SSHServerEncryptionS2C,
		SSHServerMACsC2S:           res.SSHServerMACsC2S,
		SSHServerMACsS2C:           res.SSHServerMACsS2C,
		SSHServerCompressionC2S:    res.SSHServerCompressionC2S,
		SSHServerCompressionS2C:    res.SSHServerCompressionS2C,

		RawMetadata: res.Metadata,
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

// VerifyDNSName returns the host string to use as x509.VerifyOptions.DNSName
// when the dial target is host (often a raw IP). Delegates to the shared
// discovery primitive so the sensor and the in-cluster Platform Sensor resolve
// the verification identity identically.
func VerifyDNSName(leaf *x509.Certificate, host string) string {
	return shareddisc.VerifyDNSName(leaf, host)
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

// CertificateInfoMaps renders a certificate chain in the canonical
// `certificates` array shape every discovery path emits (see CLAUDE.md,
// "Single certificate format"). The TLS enricher and the passive capture
// path share it so they cannot drift.
func CertificateInfoMaps(certs []models.CertificateInfo) []interface{} {
	out := make([]interface{}, len(certs))
	for i, cert := range certs {
		out[i] = map[string]interface{}{
			"serial_number":             cert.SerialNumber,
			"subject_dn":                cert.SubjectDN,
			"issuer_dn":                 cert.IssuerDN,
			"not_before":                cert.NotBefore.Format(time.RFC3339),
			"not_after":                 cert.NotAfter.Format(time.RFC3339),
			"key_algorithm":             cert.KeyAlgorithm,
			"signature_alg":             cert.SignatureAlg,
			"is_ca":                     cert.IsCA,
			"certificate_pem":           cert.CertificatePEM,
			"fingerprint_sha256":        cert.FingerprintSHA256,
			"fingerprint_sha1":          cert.FingerprintSHA1,
			"subject_alternative_names": cert.SubjectAlternativeNames,
			"key_usage":                 cert.KeyUsage,
			"extended_key_usage":        cert.ExtendedKeyUsage,
			"key_size":                  cert.KeySize,
			"chain_order":               cert.ChainOrder,
		}
	}
	return out
}
