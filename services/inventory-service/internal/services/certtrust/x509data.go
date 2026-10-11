package certtrust

import (
	"crypto/x509"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	sharedcerts "github.com/vistasecurity/vistaplatform/shared/certificates"
)

// CertificateDataFromX509 maps a parsed certificate onto the ingest shape,
// through the canonical shared extractor so a CA stored here carries the same
// fields as one discovered on the wire.
func CertificateDataFromX509(cert *x509.Certificate) models.CertificateData {
	info := sharedcerts.ExtractCertificatesFromX509([]*x509.Certificate{cert})[0]
	return models.CertificateData{
		SubjectDN:               info.SubjectDN,
		IssuerDN:                info.IssuerDN,
		SerialNumber:            info.SerialNumber,
		CommonName:              cert.Subject.CommonName,
		SubjectAlternativeNames: info.SubjectAlternativeNames,
		NotBefore:               info.NotBefore,
		NotAfter:                info.NotAfter,
		FingerprintSHA256:       info.FingerprintSHA256,
		FingerprintSHA1:         info.FingerprintSHA1,
		CertificatePEM:          info.CertificatePEM,
		PublicKeyAlgorithm:      info.KeyAlgorithm,
		PublicKeySize:           info.KeySize,
		SignatureAlgorithm:      info.SignatureAlg,
		IsCACertificate:         info.IsCA,
		IsSelfSigned:            info.SubjectDN == info.IssuerDN,
		KeyUsage:                info.KeyUsage,
		ExtendedKeyUsage:        info.ExtendedKeyUsage,
	}
}
