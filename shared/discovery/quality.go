package discovery

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/certificates"
	"golang.org/x/crypto/ocsp"
)

// ClassifyCertificateFlags produces additional quality/risk flags for a leaf
// certificate and its chain (weak signature/key, incomplete chain, embedded
// SCTs, known-bad CAs, EV status, large SAN counts). These are forwarded to the
// platform for assessment beyond basic chain validation. Both the sensor and
// the in-cluster service emit these, so they must be identical — hence shared.
func ClassifyCertificateFlags(leaf *x509.Certificate, chain []*x509.Certificate) map[string]interface{} {
	flags := make(map[string]interface{})

	// --- No Subject / No Common Name ---
	if len(leaf.Subject.Names) == 0 {
		flags["cert_no_subject"] = true
	} else if leaf.Subject.CommonName == "" {
		flags["cert_no_common_name"] = true
	}

	// --- Weak signature algorithm (SHA-1, MD5, MD2) on the leaf cert ---
	sigAlg := strings.ToUpper(leaf.SignatureAlgorithm.String())
	if strings.Contains(sigAlg, "SHA1") || strings.Contains(sigAlg, "SHA-1") {
		flags["cert_weak_signature"] = "SHA-1"
	} else if strings.Contains(sigAlg, "MD5") {
		flags["cert_weak_signature"] = "MD5"
	} else if strings.Contains(sigAlg, "MD2") {
		flags["cert_weak_signature"] = "MD2"
	}

	// --- Weak public key size ---
	keySize := certificates.CalculateKeySize(leaf.PublicKey)
	if keySize > 0 {
		switch leaf.PublicKeyAlgorithm {
		case x509.RSA:
			if keySize < 2048 {
				flags["cert_weak_public_key"] = fmt.Sprintf("RSA-%d", keySize)
			}
		case x509.ECDSA:
			if keySize < 224 {
				flags["cert_weak_public_key"] = fmt.Sprintf("ECDSA-%d", keySize)
			}
		}
	}

	// --- Incomplete chain detection ---
	// Only the leaf was sent and it's not self-signed → intermediates missing.
	if len(chain) == 1 && !IsSelfSigned(leaf) && !leaf.IsCA {
		flags["cert_incomplete_chain"] = true
	}

	// --- Certificate Transparency: embedded SCTs (OID 1.3.6.1.4.1.11129.2.4.2) ---
	hasSCT := false
	sctOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(sctOID) {
			hasSCT = true
			break
		}
	}
	flags["cert_has_sct"] = hasSCT

	// --- Known-bad CA fingerprints (Superfish, eDellRoot, etc.) ---
	for _, cert := range chain {
		fp := sha256.Sum256(cert.Raw)
		fpHex := hex.EncodeToString(fp[:])
		if name, bad := knownBadCAFingerprints[fpHex]; bad {
			flags["cert_known_bad_ca"] = name
			break
		}
	}

	// --- EV certificate detection ---
	for _, oid := range leaf.PolicyIdentifiers {
		if isEVPolicyOID(oid) {
			flags["cert_is_ev"] = true
			break
		}
	}

	// --- Large SAN count (informational) ---
	sanCount := len(leaf.DNSNames) + len(leaf.EmailAddresses) + len(leaf.IPAddresses)
	if sanCount > 100 {
		flags["cert_large_san_count"] = sanCount
	}

	return flags
}

// knownBadCAFingerprints maps SHA-256 fingerprints of known-bad CA certificates
// (adware/malware-installed or compromised/distrusted) to their common names.
//
// This is a tripwire for a small set of specific, well-documented bad actors —
// not a comprehensive CA distrust database. It will not catch every CA a root
// program has ever removed or blocked; it only flags the handful of incidents
// listed below where the exact SHA-256 fingerprint has been independently
// verified against an authoritative source. Do not add an entry here on the
// strength of a name alone — confirm the fingerprint (e.g. against the CCADB
// "All Certificate Records" report at https://www.ccadb.org/resources, or by
// downloading the certificate and computing the hash directly) and cite the
// source in a comment.
var knownBadCAFingerprints = map[string]string{
	// Superfish (Lenovo adware, 2015)
	"c864484869d41d2b0d32319c5a62f9315aac2f6eef5c94043b11ece93700be1a": "Superfish",
	// eDellRoot (Dell pre-installed, 2015)
	"ec30c9c3065a06bb07dc5b1c6b497f370c1ca65c0fecbdbe9d3034a3c6060a52": "eDellRoot",
	// DSDTestProvider (Dell, 2015)
	"3b35e1ae9c25709a2014f48c9cbff734c0143f3f3e785baa0a7da7b5b9bb3d1e": "DSDTestProvider",
	// Superfish SHA1 variant
	"0f912fd7be760be25afbc56bdc09cd9e5dcc9f6f6065b2ea902c24725abda2a2": "Superfish-SHA1",
	// DigiNotar Root CA (O=DigiNotar, C=NL; 2011 breach — fraudulent *.google.com
	// and other mis-issuance, actively removed from Apple's and Microsoft's trust
	// stores). Fingerprint verified against the CCADB "All Certificate Records"
	// report (record A010553, https://www.ccadb.org/resources) and independently
	// recomputed from the certificate itself (subject key identifier
	// 88:68:BF:E0:8E:35:C4:3B:38:6B:62:F7:28:3B:84:81:C8:0C:D7:4D matches both
	// sources; validity to GMT).
	"0d136e439f0ab6e97f3a02a540da9f0641aa554e1d66ea51ae2920d51b2f7217": "DigiNotar Root CA",
	// TrustCor RootCert CA-1 (2022 distrust — ties to malware surveillance
	// vendor Measurement Systems; blocked/disabled/removed by Apple, Google
	// Chrome, Microsoft and Mozilla). Fingerprint verified against the CCADB
	// "All Certificate Records" report (https://www.ccadb.org/resources) and
	// independently recomputed from the certificate published at
	// https://trustcor.com/certs/TrustCor_RootCert_CA1.pem.
	"d40e9c86cd8fe468c1776959f49ea774fa548684b6c406f3909261f4dce2575c": "TrustCor RootCert CA-1",
	// TrustCor RootCert CA-2 (same 2022 distrust as CA-1). Fingerprint verified
	// against the CCADB "All Certificate Records" report and independently
	// recomputed from https://trustcor.com/certs/TrustCor_RootCert_CA2.pem.
	"0753e940378c1bd5e3836e395daea5cb839e5046f1bd0eae1951cf10fec7c965": "TrustCor RootCert CA-2",
	// TrustCor ECA-1 (same 2022 distrust as CA-1/CA-2). Fingerprint verified
	// against the CCADB "All Certificate Records" report and independently
	// recomputed from https://trustcor.com/certs/TrustCor_ECA1.pem.
	"5a885db19c01d912c5759388938cafbbdf031ab2d48e91ee15589b42971d039c": "TrustCor ECA-1",
}

// isEVPolicyOID reports whether an OID matches a known EV certificate policy.
func isEVPolicyOID(oid asn1.ObjectIdentifier) bool {
	evOIDs := map[string]bool{
		// CA/Browser Forum umbrella EV policy OID. Modern EV certificates
		// assert this alongside (or instead of) the issuer-specific OID, so
		// omitting it missed most current EV certs outright.
		"2.23.140.1.1":                 true, // CA/Browser Forum EV
		"2.16.840.1.114028.10.1.2":     true, // Entrust
		"2.16.840.1.114412.2.1":        true, // DigiCert
		"2.16.840.1.114413.1.7.23.3":   true, // GoDaddy
		"2.16.840.1.114414.1.7.23.3":   true, // Starfield
		"1.3.6.1.4.1.6449.1.2.1.5.1":   true, // Comodo/Sectigo
		"2.16.840.1.113733.1.7.23.6":   true, // VeriSign/Symantec
		"1.3.6.1.4.1.8024.0.2.100.1.2": true, // QuoVadis
		"2.16.756.1.89.1.2.1.1":        true, // SwissSign
		"1.2.616.1.113527.2.5.1.1":     true, // Certum
		"2.16.840.1.114171.500.9":      true, // Wells Fargo
		"1.3.6.1.4.1.34697.2.1":        true, // AffirmTrust
		"1.3.6.1.4.1.14370.1.6":        true, // GeoTrust
		"1.3.6.1.4.1.4146.1.1":         true, // GlobalSign EV
		// NOTE: 2.16.840.1.101.2.1 was listed here as "GlobalSign". It is not:
		// that is the US DoD infosec arc (joint-iso-itu-t...2.16.840.1.101.2.1),
		// which has nothing to do with EV. Flagging DoD PKI certificates as EV
		// is a false positive, so the entry is gone rather than relabelled.
	}
	return evOIDs[oid.String()]
}

// ocspTimeout bounds a single OCSP responder HTTP round-trip.
const ocspTimeout = 3 * time.Second

// CheckOCSPStaple parses an OCSP response stapled during the TLS handshake.
// Returns ("", "") if no staple was provided or parsing failed.
func CheckOCSPStaple(staple []byte, leaf, issuer *x509.Certificate) (status, detail string) {
	if len(staple) == 0 {
		return "", ""
	}
	resp, err := ocsp.ParseResponse(staple, issuer)
	if err != nil {
		return "", ""
	}
	return ocspStatusString(resp), fmt.Sprintf("stapled, produced_at=%s", resp.ProducedAt.UTC().Format(time.RFC3339))
}

// CheckOCSPRevocation performs a direct OCSP query for the leaf certificate,
// trying each responder URL in order. Returns ("", "") if no check could be
// completed (no responder URLs, network failure, etc.).
func CheckOCSPRevocation(leaf, issuer *x509.Certificate) (status, detail string) {
	if leaf == nil || issuer == nil {
		return "", ""
	}
	if len(leaf.OCSPServer) == 0 {
		return "", ""
	}
	ocspReq, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return "", ""
	}
	client := &http.Client{Timeout: ocspTimeout}
	for _, responderURL := range leaf.OCSPServer {
		s, d := queryOCSPResponder(client, responderURL, ocspReq, issuer)
		if s != "" {
			return s, d
		}
	}
	return "", ""
}

// queryOCSPResponder sends an OCSP request to a single responder. Returns
// ("", "") on any failure.
func queryOCSPResponder(client *http.Client, responderURL string, request []byte, issuer *x509.Certificate) (status, detail string) {
	httpResp, err := client.Post(responderURL, "application/ocsp-request", bytes.NewReader(request))
	if err != nil {
		return "", ""
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return "", ""
	}
	// Limit response body to 1MB to prevent memory exhaustion.
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if err != nil {
		return "", ""
	}
	resp, err := ocsp.ParseResponse(body, issuer)
	if err != nil {
		return "", ""
	}
	return ocspStatusString(resp), fmt.Sprintf("responder=%s, produced_at=%s", responderURL, resp.ProducedAt.UTC().Format(time.RFC3339))
}

// ocspStatusString converts an OCSP response status code to a string.
func ocspStatusString(resp *ocsp.Response) string {
	switch resp.Status {
	case ocsp.Good:
		return "good"
	case ocsp.Revoked:
		return "revoked"
	case ocsp.Unknown:
		return "unknown"
	default:
		return ""
	}
}
