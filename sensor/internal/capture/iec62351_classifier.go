package capture

import "strings"

// IEC 62351-3 is the energy-sector TLS profile referenced by NERC CIP and the
// IEC 61850 / DNP3 / ICCP security profiles. It restricts TLS to forward-secret
// AEAD cipher suites with adequate certificate key sizes. This file applies
// the profile as a pure-function classifier — call ClassifyIEC62351 from
// wherever a TLS discovery is finalized, on energy-relevant ports only.
//
// Standard reference: IEC 62351-3 (TLS profile for energy communications).

// energyRelevantTCPPorts are the TCP ports where IEC 62351-3 applies.
//   - 102:   IEC 61850 MMS, ICCP/TASE.2
//   - 4712:  IEC 61968/61970 CIM services (some implementations)
//   - 20000: DNP3/TLS
//   - 443:   web HMI / EMS API
//   - 8443:  alt-HTTPS for OT consoles
//
// Kept as a small switch rather than a map so the function is allocation-free.
func IsEnergyRelevantPort(port int) bool {
	switch port {
	case 102, 443, 4712, 8443, 20000:
		return true
	}
	return false
}

// IsTLSVersionCompliantIEC62351 returns true for TLS 1.2 or TLS 1.3.
// IEC 62351-3 requires TLS 1.2 minimum; 1.3 is acceptable and preferred.
func IsTLSVersionCompliantIEC62351(version string) bool {
	switch version {
	case "TLS 1.2", "TLS 1.3":
		return true
	}
	return false
}

// IsCipherSuiteCompliantIEC62351 returns true for IANA cipher names that
// satisfy the profile: forward-secret key exchange (ECDHE/DHE), AEAD symmetric
// (AES-GCM or ChaCha20-Poly1305), and no banned primitives (RC4/3DES/DES/NULL/
// EXPORT/ANON/MD5).
//
// All TLS 1.3 suites pass by definition (forward secrecy and AEAD are baked
// into the protocol).
func IsCipherSuiteCompliantIEC62351(cipher string) bool {
	if cipher == "" {
		return false
	}
	// TLS 1.3 cipher suite names start with TLS_ but do not encode key
	// exchange — the protocol always uses (EC)DHE and AEAD.
	switch cipher {
	case "TLS_AES_128_GCM_SHA256",
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256":
		return true
	}

	// Reject banned primitives outright — order matters: the substring scan
	// must run before the prefix check so we don't accept "ECDHE_RSA_3DES".
	banned := []string{"RC4", "3DES", "_DES_", "NULL", "EXPORT", "_ANON_", "_MD5"}
	for _, b := range banned {
		if strings.Contains(cipher, b) {
			return false
		}
	}

	// Require ECDHE or DHE key exchange.
	if !strings.HasPrefix(cipher, "TLS_ECDHE_") && !strings.HasPrefix(cipher, "TLS_DHE_") {
		return false
	}

	// Require AEAD symmetric cipher (AES-GCM or ChaCha20-Poly1305).
	if strings.Contains(cipher, "_AES_128_GCM_") ||
		strings.Contains(cipher, "_AES_256_GCM_") ||
		strings.Contains(cipher, "_CHACHA20_POLY1305_") {
		return true
	}
	return false
}

// IsCertificateKeyCompliantIEC62351 returns true for RSA ≥2048 bits or
// ECC curves of ≥224 bits (P-256 and P-384 pass; P-192 does not).
//
// keyAlgorithm uses the names emitted by Go's x509: "RSA", "ECDSA", "Ed25519",
// "DSA". keyBits is the modulus size for RSA / curve bit size for ECDSA.
// Ed25519 is treated as compliant (it's a strong modern signature primitive
// not explicitly banned by the profile).
func IsCertificateKeyCompliantIEC62351(keyAlgorithm string, keyBits int) bool {
	switch strings.ToUpper(keyAlgorithm) {
	case "RSA":
		return keyBits >= 2048
	case "ECDSA":
		return keyBits >= 224
	case "ED25519":
		return true
	}
	return false
}

// IEC62351Result is the structured classification result merged into a TLS
// discovery's RawMetadata. All fields are present; consumers can render
// per-aspect compliance independently of the overall verdict.
type IEC62351Result struct {
	Applicable        bool   `json:"iec62351_applicable"`
	TLSVersionOK      bool   `json:"iec62351_tls_version_compliant"`
	CipherOK          bool   `json:"iec62351_cipher_compliant"`
	CertOK            bool   `json:"iec62351_cert_compliant"`
	Overall           bool   `json:"iec62351_overall"`
	NonComplianceCode string `json:"iec62351_noncompliance,omitempty"`
}

// ClassifyIEC62351 returns nil when the port is outside the energy-relevant
// set (the discovery is silently unaffected). Otherwise it returns a populated
// result; callers merge it into RawMetadata via ToMetadata.
//
// keyAlgorithm/keyBits should be the leaf certificate's public-key algorithm
// and bit size; pass zero values when unknown (CertOK will be false, which is
// the correct conservative behavior).
func ClassifyIEC62351(port int, tlsVersion, cipherSuite, keyAlgorithm string, keyBits int) *IEC62351Result {
	if !IsEnergyRelevantPort(port) {
		return nil
	}
	r := &IEC62351Result{Applicable: true}
	r.TLSVersionOK = IsTLSVersionCompliantIEC62351(tlsVersion)
	r.CipherOK = IsCipherSuiteCompliantIEC62351(cipherSuite)
	r.CertOK = IsCertificateKeyCompliantIEC62351(keyAlgorithm, keyBits)
	r.Overall = r.TLSVersionOK && r.CipherOK && r.CertOK
	if !r.Overall {
		r.NonComplianceCode = nonComplianceCode(r)
	}
	return r
}

// nonComplianceCode summarizes why a discovery failed the profile, for at-a-
// glance triage in the UI. Only one code is returned (the most severe);
// per-aspect booleans give the full picture.
func nonComplianceCode(r *IEC62351Result) string {
	switch {
	case !r.TLSVersionOK && !r.CipherOK && !r.CertOK:
		return "version+cipher+cert"
	case !r.TLSVersionOK && !r.CipherOK:
		return "version+cipher"
	case !r.TLSVersionOK && !r.CertOK:
		return "version+cert"
	case !r.CipherOK && !r.CertOK:
		return "cipher+cert"
	case !r.TLSVersionOK:
		return "version"
	case !r.CipherOK:
		return "cipher"
	case !r.CertOK:
		return "cert"
	}
	return ""
}

// ToMetadata flattens the result into the map shape used by RawMetadata.
// Returns an empty map when r is nil so callers can unconditionally range
// over it.
func (r *IEC62351Result) ToMetadata() map[string]interface{} {
	if r == nil {
		return map[string]interface{}{}
	}
	m := map[string]interface{}{
		"iec62351_applicable":            r.Applicable,
		"iec62351_tls_version_compliant": r.TLSVersionOK,
		"iec62351_cipher_compliant":      r.CipherOK,
		"iec62351_cert_compliant":        r.CertOK,
		"iec62351_overall":               r.Overall,
	}
	if r.NonComplianceCode != "" {
		m["iec62351_noncompliance"] = r.NonComplianceCode
	}
	return m
}
