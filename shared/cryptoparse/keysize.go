package cryptoparse

import "strings"

// Key-algorithm families and the size floors that apply to them.
//
// A bit-length floor only means something for the family it was derived for:
// finite-field moduli (RSA/DSA/DH) are measured in thousands of bits, elliptic
// curve keys in hundreds, and post-quantum key sizes are comparable to neither.
// Comparing a healthy 256-bit EC key against the 2048-bit RSA floor reports the
// most modern configuration in the estate as critically weak, which is the bug
// this classification exists to prevent — and which it was written to fix.
//
// This lived in inventory-service's weak-crypto detector, where the finding
// producers could not reach it. It is pure string classification over published
// NIST floors with no platform coupling, so it belongs beside the rest of the
// crypto-string parsing; `weak_crypto_detector.go` now forwards to it and its
// SQL twins are generated from these same token lists, exactly as before.

// KexFamily buckets a key-exchange or public-key algorithm by the kind of size
// floor that applies to it.
type KexFamily int

const (
	// KexFamilyUnknown is the answer when nothing matched. It is deliberately
	// NOT a family with a floor: a bare 256 could be an EC key (healthy) or an
	// RSA modulus (catastrophic), and guessing wrong in either direction is
	// worse than staying quiet.
	KexFamilyUnknown KexFamily = iota
	KexFamilyFiniteField
	KexFamilyEllipticCurve
	KexFamilyPostQuantum
)

// Family tokens. Exported so the SQL predicates that select the same rows are
// generated from the SAME lists this classifier uses — they ran on
// hand-written, divergent rules once, and the list view disagreed with the
// facet filter that was supposed to select it.
var (
	KexPostQuantumTokens   = []string{"ML-KEM", "MLKEM", "HQC", "ML-DSA", "MLDSA", "SLH-DSA", "FN-DSA", "KYBER", "DILITHIUM"}
	KexEllipticCurveTokens = []string{"ECDH", "ECDSA", "X25519", "X448", "CURVE25519", "SECP", "DH-ECP", "PRIME256", "ED25519", "ED448"}
	KexFiniteFieldTokens   = []string{"RSA", "DSA", "DH", "DHE"}
)

// Minimum key sizes in bits, per NIST SP 800-131A Rev 2: 112-bit security means
// a 2048-bit finite-field modulus or a 256-bit curve.
const (
	MinRSAKeySizeBits = 2048
	MinECCKeySizeBits = 256
)

// ContainsAnyToken reports whether k contains any of tokens. k is expected
// upper-cased; the tokens are.
func ContainsAnyToken(k string, tokens []string) bool {
	for _, p := range tokens {
		if strings.Contains(k, p) {
			return true
		}
	}
	return false
}

// KeyAlgorithmFamily classifies an algorithm name.
//
// Post-quantum is tested FIRST: SecP256r1MLKEM768 contains both "SECP" and
// "MLKEM", and the post-quantum reading is the correct one — a hybrid group is
// not an elliptic-curve group with a long name.
func KeyAlgorithmFamily(name string) KexFamily {
	k := strings.ToUpper(strings.TrimSpace(name))
	if k == "" {
		return KexFamilyUnknown
	}
	switch {
	case ContainsAnyToken(k, KexPostQuantumTokens):
		return KexFamilyPostQuantum
	case ContainsAnyToken(k, KexEllipticCurveTokens):
		return KexFamilyEllipticCurve
	case ContainsAnyToken(k, KexFiniteFieldTokens):
		return KexFamilyFiniteField
	}
	return KexFamilyUnknown
}

// ---------------------------------------------------------------------------
// Weakness classification
// ---------------------------------------------------------------------------
//
// Two rules that are NOT expressible as a row in the algorithms catalogue, and
// are therefore the one place Go is allowed a crypto opinion:
//
//   - a key SIZE floor, which is a property of a key rather than of an
//     algorithm (SP 800-131A Rev 2), and
//   - a hash family that is broken outright whatever it is spelled as inside a
//     composite signature name ("md5WithRSAEncryption" resolves to no catalogue
//     code at all).
//
// Everything else about how risky an algorithm is comes from the catalogue and
// must keep coming from there: "To change how risky an algorithm is, edit the
// catalogue row, not Go code" (CLAUDE.md). Both lived in inventory-service's
// weak-crypto detector; they are here so the `crypto` finding producer can make
// the same judgement about a CERTIFICATE's key and signature without holding a
// second opinion, and the detector forwards to them.

// The severity ladder, spelled as findings_severity_check spells it.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// WeakCryptoSeverityScore is the 0-100 risk contribution of a detector severity.
//
// These four numbers are the detector's own scale and have been the product's
// weak-crypto scores since before the algorithms catalogue was wired in; they
// are named here rather than re-derived so the catalogue-vs-detector "worse of
// the two wins" comparison keeps comparing the same things. An unrecognised
// severity scores 0 — a severity nothing can place is not evidence of risk.
func WeakCryptoSeverityScore(severity string) int {
	switch severity {
	case SeverityCritical:
		return 90
	case SeverityHigh:
		return 70
	case SeverityMedium:
		return 50
	case SeverityLow:
		return 20
	}
	return 0
}

// WeakHashSeverity classifies a hash or composite signature algorithm name.
//
// Returns "" when the name names no broken hash — which is NOT the same as "the
// hash is strong": an unrecognised name is unassessed, and the caller must not
// read the empty string as reassurance.
func WeakHashSeverity(name string) string {
	h := strings.ToUpper(strings.TrimSpace(name))
	if h == "" {
		return ""
	}
	if strings.Contains(h, "MD5") || strings.Contains(h, "MD4") || strings.Contains(h, "MD2") {
		return SeverityCritical
	}
	// SHA-1 is deprecated rather than broken for every use, and is scored below
	// the MD family accordingly. Both spellings, because certificates carry both
	// ("sha1WithRSAEncryption", "ecdsa-with-SHA-1").
	if strings.Contains(h, "SHA1") || strings.Contains(h, "SHA-1") {
		return SeverityHigh
	}
	return ""
}

// WeakKeySizeSeverity classifies a key by its length, against the floor for the
// family its algorithm name places it in.
//
// Returns "" when the key is at or above its floor, when the size is unknown,
// and — importantly — when the FAMILY is unknown or post-quantum. A bare 256
// could be an EC key (healthy) or an RSA modulus (catastrophic); guessing wrong
// in either direction is worse than staying quiet, and post-quantum key sizes
// are not comparable to either floor.
func WeakKeySizeSeverity(algorithm string, bits int) string {
	if bits <= 0 {
		return ""
	}
	switch KeyAlgorithmFamily(algorithm) {
	case KexFamilyEllipticCurve:
		if bits < MinECCKeySizeBits {
			return SeverityHigh
		}
	case KexFamilyFiniteField:
		if bits < 1024 {
			return SeverityCritical
		}
		if bits < MinRSAKeySizeBits {
			return SeverityHigh
		}
	case KexFamilyUnknown, KexFamilyPostQuantum:
		return ""
	}
	return ""
}
