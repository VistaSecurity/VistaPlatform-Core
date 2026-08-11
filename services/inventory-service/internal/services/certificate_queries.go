// Package services: certificate extraction from discovery raw data.
package services

import (
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// extractCertificateData extracts certificate information from raw_data.
func (s *AssetService) extractCertificateData(rawData map[string]interface{}) *models.CertificateData {
	var certMap map[string]interface{}
	if cert, ok := rawData["certificate"].(map[string]interface{}); ok {
		certMap = cert
	} else if cert, ok := rawData["cert"].(map[string]interface{}); ok {
		certMap = cert
	} else if cert, ok := rawData["certificate_info"].(map[string]interface{}); ok {
		certMap = cert
	} else {
		return nil
	}

	certData := &models.CertificateData{}
	if subjectDN, ok := certMap["subject_dn"].(string); ok && subjectDN != "" {
		certData.SubjectDN = subjectDN
	} else if subject, ok := certMap["subject"].(string); ok && subject != "" {
		certData.SubjectDN = subject
	} else {
		return nil
	}
	if issuerDN, ok := certMap["issuer_dn"].(string); ok && issuerDN != "" {
		certData.IssuerDN = issuerDN
	} else if issuer, ok := certMap["issuer"].(string); ok && issuer != "" {
		certData.IssuerDN = issuer
	} else {
		return nil
	}

	if serial, ok := certMap["serial_number"].(string); ok {
		certData.SerialNumber = serial
	} else if serial, ok := certMap["serial"].(string); ok {
		certData.SerialNumber = serial
	}
	if cn, ok := certMap["common_name"].(string); ok {
		certData.CommonName = cn
	} else if subjectDN := certData.SubjectDN; subjectDN != "" && strings.Contains(subjectDN, "CN=") {
		parts := strings.Split(subjectDN, "CN=")
		if len(parts) > 1 {
			certData.CommonName = strings.TrimSpace(strings.Split(parts[1], ",")[0])
		}
	}
	if sans, ok := certMap["subject_alternative_names"].([]interface{}); ok {
		for _, san := range sans {
			if sanStr, ok := san.(string); ok {
				certData.SubjectAlternativeNames = append(certData.SubjectAlternativeNames, sanStr)
			}
		}
	}
	if notBefore, ok := certMap["not_before"].(string); ok {
		if t, err := time.Parse(time.RFC3339, notBefore); err == nil {
			certData.NotBefore = t
		}
	}
	if notAfter, ok := certMap["not_after"].(string); ok {
		if t, err := time.Parse(time.RFC3339, notAfter); err == nil {
			certData.NotAfter = t
		}
	}
	if fingerprint, ok := certMap["fingerprint"].(string); ok {
		if len(fingerprint) == 64 {
			certData.FingerprintSHA256 = fingerprint
		} else if len(fingerprint) == 40 {
			certData.FingerprintSHA1 = fingerprint
		}
	}
	if v, ok := certMap["fingerprint_sha256"].(string); ok {
		certData.FingerprintSHA256 = v
	}
	if v, ok := certMap["fingerprint_sha1"].(string); ok {
		certData.FingerprintSHA1 = v
	}
	if pem, ok := certMap["certificate_pem"].(string); ok {
		certData.CertificatePEM = pem
	} else if pem, ok := certMap["pem"].(string); ok {
		certData.CertificatePEM = pem
	}
	if v, ok := certMap["public_key_algorithm"].(string); ok {
		certData.PublicKeyAlgorithm = v
	} else if v, ok := certMap["key_algorithm"].(string); ok {
		certData.PublicKeyAlgorithm = v
	}
	if keySize, ok := certMap["public_key_size"].(float64); ok {
		certData.PublicKeySize = int(keySize)
	} else if keySize, ok := certMap["key_size"].(float64); ok {
		certData.PublicKeySize = int(keySize)
	}
	if v, ok := certMap["signature_algorithm"].(string); ok {
		certData.SignatureAlgorithm = v
	} else if v, ok := certMap["signature_alg"].(string); ok {
		certData.SignatureAlgorithm = v
	}
	if isSelfSigned, ok := certMap["is_self_signed"].(bool); ok {
		certData.IsSelfSigned = isSelfSigned
	} else {
		certData.IsSelfSigned = certData.SubjectDN == certData.IssuerDN
	}
	if isCA, ok := certMap["is_ca_certificate"].(bool); ok {
		certData.IsCACertificate = isCA
	} else if isCA, ok := certMap["is_ca"].(bool); ok {
		certData.IsCACertificate = isCA
	}
	if keyUsage, ok := certMap["key_usage"].([]interface{}); ok {
		for _, usage := range keyUsage {
			if usageStr, ok := usage.(string); ok {
				certData.KeyUsage = append(certData.KeyUsage, usageStr)
			}
		}
	}
	if extKeyUsage, ok := certMap["extended_key_usage"].([]interface{}); ok {
		for _, usage := range extKeyUsage {
			if usageStr, ok := usage.(string); ok {
				certData.ExtendedKeyUsage = append(certData.ExtendedKeyUsage, usageStr)
			}
		}
	}
	return certData
}

// extractCertificatesFromFinding extracts certificates from discovery finding format.
func (s *AssetService) extractCertificatesFromFinding(f IngestFinding) []models.CertificateData {
	var certificates []models.CertificateData
	dataSource := ""
	if f.RawData != nil {
		if dm, ok := f.RawData["discovery_method"].(string); ok && dm == "cloud_api" {
			dataSource = "cloud_api"
		}
	}
	if f.RawData != nil {
		if certs, ok := f.RawData["certificates"].([]interface{}); ok {
			for _, certInterface := range certs {
				if certMap, ok := certInterface.(map[string]interface{}); ok {
					certData := s.extractCertificateData(map[string]interface{}{"certificate": certMap})
					if certData != nil {
						if dataSource != "" {
							certData.DataSource = dataSource
						}
						if acm, ok := certMap["acm_metadata"].(map[string]interface{}); ok {
							certData.ACMMetadata = acm
						}
						certificates = append(certificates, *certData)
					}
				}
			}
		}
		if certData := s.extractCertificateData(f.RawData); certData != nil {
			found := false
			for _, existingCert := range certificates {
				if existingCert.SerialNumber == certData.SerialNumber && existingCert.IssuerDN == certData.IssuerDN {
					found = true
					break
				}
			}
			if !found {
				if dataSource != "" {
					certData.DataSource = dataSource
				}
				certificates = append(certificates, *certData)
			}
		}
	}
	return certificates
}
