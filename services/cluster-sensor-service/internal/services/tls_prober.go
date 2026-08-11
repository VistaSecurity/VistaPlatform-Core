package services

import (
	"fmt"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/certificates"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// TLSProber performs TLS probing and certificate extraction for the in-cluster
// Platform Sensor.
//
// The probe/validate core is NOT implemented here — it is the same
// shared/discovery code the standalone sensor runs, because the two runtimes
// are meant to be functionally equivalent and a bespoke copy drifted:
// it verified chains with no Intermediates pool (so any server presenting
// leaf+intermediate — nearly every valid endpoint — classified as
// untrusted_ca), passed raw IPs as x509 DNSName (false hostname_mismatch),
// and emitted a metadata dialect nothing downstream reads. This type now owns
// only the cluster-specific concerns: timeouts, version enumeration policy,
// and flattening the neutral ProbeResult into the finding Data map.
type TLSProber struct {
	timeout time.Duration
	prober  *shareddisc.Prober
}

// NewTLSProber creates a new TLS prober instance
func NewTLSProber(timeout time.Duration) *TLSProber {
	return &TLSProber{
		timeout: timeout,
		prober:  shareddisc.NewProber(timeout),
	}
}

// ProbeTLS performs a TLS handshake, extracts the certificate chain, validates
// it and returns canonical discovery metadata. When skipVersionEnum is true,
// only the negotiated TLS version is recorded (no extra probes).
func (tp *TLSProber) ProbeTLS(hostname string, port int, skipVersionEnum bool) (map[string]interface{}, error) {
	res, err := tp.prober.Probe(hostname, hostname, "TLS", port)
	if err != nil {
		return nil, fmt.Errorf("TLS probe failed: %w", err)
	}
	if res == nil {
		return nil, fmt.Errorf("TLS probe returned no result for %s:%d", hostname, port)
	}

	versions := res.TLSVersions
	if !skipVersionEnum {
		if accepted := tp.prober.EnumerateTLSVersions(hostname, hostname, port); len(accepted) > 0 {
			versions = accepted
		}
	}

	return tlsProbeMetadata(res, versions), nil
}

// tlsProbeMetadata flattens a shared ProbeResult into the canonical discovery
// metadata shape. Canonical field names are load-bearing: the discovery
// processor reads "version" and a "certificates" array of subject_dn /
// issuer_dn / key_algorithm / signature_alg, and reads the certificate quality
// flags at the TOP LEVEL. Nesting them, or renaming them, silently drops the
// data on the floor without any error anywhere.
func tlsProbeMetadata(res *shareddisc.ProbeResult, versions []string) map[string]interface{} {
	out := make(map[string]interface{}, len(res.Metadata)+10)

	// Shared metadata carries the raw wire values, the quality flags and the
	// OCSP status — all already at the top level.
	for k, v := range res.Metadata {
		out[k] = v
	}

	if len(res.TLSVersions) > 0 && res.TLSVersions[0] != "" {
		out["version"] = res.TLSVersions[0]
	}
	if res.SelectedCipher != "" {
		out["cipher_suite"] = res.SelectedCipher
		out["selected_cipher"] = res.SelectedCipher
	}
	if len(versions) > 0 {
		out["tls_versions"] = versions
	}
	if len(res.ALPN) > 0 && res.ALPN[0] != "" {
		out["alpn_selected"] = res.ALPN[0]
	}

	certs := make([]map[string]interface{}, 0, len(res.Certificates))
	for _, ci := range res.Certificates {
		certs = append(certs, certInfoToMap(ci))
	}
	out["certificates"] = certs
	out["certificate_count"] = len(certs)

	out["cert_validation_status"] = res.CertValidationStatus
	if res.CertValidationStatus == "" {
		out["cert_validation_status"] = "unknown"
	}
	out["cert_validation_error"] = res.CertValidationError

	return out
}

// certInfoToMap converts a certificates.CertificateInfo into the canonical
// certificate entry shape (see CLAUDE.md "Single certificate format"). The
// field names here must match what the sensor emits — subject_dn, issuer_dn,
// key_algorithm, signature_alg — not the x509-ish aliases.
func certInfoToMap(ci certificates.CertificateInfo) map[string]interface{} {
	// Determine certificate lifecycle state based on validity period
	certState := "active"
	now := time.Now()
	if !ci.NotAfter.IsZero() && now.After(ci.NotAfter) {
		certState = "expired"
	} else if !ci.NotBefore.IsZero() && now.Before(ci.NotBefore) {
		certState = "pre-activation"
	}

	return map[string]interface{}{
		"certificate_pem":           ci.CertificatePEM,
		"fingerprint_sha256":        ci.FingerprintSHA256,
		"fingerprint_sha1":          ci.FingerprintSHA1,
		"subject_dn":                ci.SubjectDN,
		"issuer_dn":                 ci.IssuerDN,
		"serial_number":             ci.SerialNumber,
		"not_before":                ci.NotBefore.Format(time.RFC3339),
		"not_after":                 ci.NotAfter.Format(time.RFC3339),
		"subject_alternative_names": ci.SubjectAlternativeNames,
		"key_usage":                 ci.KeyUsage,
		"extended_key_usage":        ci.ExtendedKeyUsage,
		"key_algorithm":             ci.KeyAlgorithm,
		"key_size":                  ci.KeySize,
		"signature_alg":             ci.SignatureAlg,
		"is_ca":                     ci.IsCA,
		"is_self_signed":            ci.SubjectDN == ci.IssuerDN,
		"is_ca_certificate":         ci.IsCA,
		"chain_order":               ci.ChainOrder,
		"certificate_format":        "X.509",
		"certificate_state":         certState,
	}
}
