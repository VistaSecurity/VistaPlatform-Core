package certificates

import (
	"encoding/base64"
	"encoding/pem"
	"strings"
)

// NormalizePEM normalizes a certificate string to standard PEM encoding.
// Device management APIs return certificates in several shapes — proper PEM,
// bare base64 DER, or base64 with embedded whitespace/newlines — and every
// interrogation prober needs the same canonicalization (this is the single
// home for the logic that f5.go and fortinet.go used to fork).
// Unrecognized input is returned unchanged so callers can still carry it as
// an opaque blob.
func NormalizePEM(pemData string) string {
	pemData = strings.TrimSpace(pemData)
	if strings.HasPrefix(pemData, "-----BEGIN CERTIFICATE-----") {
		return pemData
	}
	if decoded, err := base64.StdEncoding.DecodeString(pemData); err == nil {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: decoded}))
	}
	clean := strings.ReplaceAll(strings.ReplaceAll(pemData, "\n", ""), " ", "")
	if decoded, err := base64.StdEncoding.DecodeString(clean); err == nil {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: decoded}))
	}
	return pemData
}
