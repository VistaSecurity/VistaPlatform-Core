package certificates

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
)

// CertificateInfo represents extracted certificate information.
// Field names and JSON tags match the sensor's models.CertificateInfo for
// cross-service consistency.
type CertificateInfo struct {
	SubjectDN               string    `json:"subject_dn"`
	IssuerDN                string    `json:"issuer_dn"`
	Subject                 string    `json:"subject"`
	Issuer                  string    `json:"issuer"`
	ValidFrom               time.Time `json:"valid_from"`
	ValidTo                 time.Time `json:"valid_to"`
	KeySize                 int       `json:"key_size"`
	Signature               string    `json:"signature"`
	Serial                  string    `json:"serial"`
	SerialNumber            string    `json:"serial_number"`
	NotBefore               time.Time `json:"not_before"`
	NotAfter                time.Time `json:"not_after"`
	KeyAlgorithm            string    `json:"key_algorithm"`
	SignatureAlg            string    `json:"signature_alg"`
	IsCA                    bool      `json:"is_ca"`
	CertificatePEM          string    `json:"certificate_pem"`
	FingerprintSHA256       string    `json:"fingerprint_sha256"`
	FingerprintSHA1         string    `json:"fingerprint_sha1"`
	SubjectAlternativeNames []string  `json:"subject_alternative_names"`
	KeyUsage                []string  `json:"key_usage"`
	ExtendedKeyUsage        []string  `json:"extended_key_usage"`
	ChainOrder              int       `json:"chain_order"`
}

// ExtractCertificatesFromX509 extracts comprehensive certificate data from
// a slice of parsed x509 certificates. The returned slice preserves chain
// order: index 0 is the leaf, subsequent entries are intermediates.
func ExtractCertificatesFromX509(certs []*x509.Certificate) []CertificateInfo {
	var result []CertificateInfo

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
		keyUsage := ExtractKeyUsage(cert.KeyUsage)
		extKeyUsage := ExtractExtendedKeyUsage(cert.ExtKeyUsage)

		// Calculate key size
		keySize := CalculateKeySize(cert.PublicKey)

		subjectDN := cert.Subject.String()
		issuerDN := cert.Issuer.String()

		info := CertificateInfo{
			SerialNumber:            cert.SerialNumber.String(),
			SubjectDN:               subjectDN,
			IssuerDN:                issuerDN,
			Subject:                 subjectDN,
			Issuer:                  issuerDN,
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
			ChainOrder:              i,
		}
		result = append(result, info)
	}

	return result
}

// ExtractKeyUsage converts x509.KeyUsage bit flags to a human-readable
// string slice.
func ExtractKeyUsage(keyUsage x509.KeyUsage) []string {
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

// ExtractExtendedKeyUsage converts x509.ExtKeyUsage OIDs to a
// human-readable string slice.
func ExtractExtendedKeyUsage(extKeyUsage []x509.ExtKeyUsage) []string {
	usageMap := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                            "Any",
		x509.ExtKeyUsageServerAuth:                     "ServerAuth",
		x509.ExtKeyUsageClientAuth:                     "ClientAuth",
		x509.ExtKeyUsageCodeSigning:                    "CodeSigning",
		x509.ExtKeyUsageEmailProtection:                "EmailProtection",
		x509.ExtKeyUsageIPSECEndSystem:                 "IPSECEndSystem",
		x509.ExtKeyUsageIPSECTunnel:                    "IPSECTunnel",
		x509.ExtKeyUsageIPSECUser:                      "IPSECUser",
		x509.ExtKeyUsageTimeStamping:                   "TimeStamping",
		x509.ExtKeyUsageOCSPSigning:                    "OCSPSigning",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "MicrosoftServerGatedCrypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:      "NetscapeServerGatedCrypto",
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "MicrosoftCommercialCodeSigning",
		x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "MicrosoftKernelCodeSigning",
	}

	var usage []string
	for _, eku := range extKeyUsage {
		if name, ok := usageMap[eku]; ok {
			usage = append(usage, name)
		} else {
			usage = append(usage, fmt.Sprintf("Unknown(%d)", int(eku)))
		}
	}
	return usage
}

// PublicKeyFingerprintSHA256 returns the hex-encoded SHA-256 of the
// certificate's SubjectPublicKeyInfo (SPKI). Unlike the whole-certificate
// fingerprint, this identifies the public KEY itself, independent of the
// certificate wrapping it: two certificates carrying the same public key (a
// renewal that reuses the key, the same key presented on multiple hosts) share
// this value. It is the natural dedup identity for a cryptographic-key
// inventory. Only public, non-secret bytes are hashed — no key material is
// exposed by the fingerprint.
func PublicKeyFingerprintSHA256(cert *x509.Certificate) string {
	if cert == nil || len(cert.RawSubjectPublicKeyInfo) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// PublicKeyCurve returns the named elliptic curve for an ECDSA public key
// (e.g. "P-256"), or "" for non-EC keys or unknown curves.
func PublicKeyCurve(pubKey interface{}) string {
	if key, ok := pubKey.(*ecdsa.PublicKey); ok && key.Curve != nil {
		return key.Curve.Params().Name
	}
	return ""
}

// ParseCertificatePEM decodes the first CERTIFICATE block from a PEM string and
// parses it into an *x509.Certificate. Returns an error if no block is present
// or parsing fails.
func ParseCertificatePEM(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

// CalculateKeySize returns the bit size of the given public key.
// Supported key types: RSA, ECDSA, Ed25519. Returns 0 for unknown types.
func CalculateKeySize(pubKey interface{}) int {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	case *ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}
