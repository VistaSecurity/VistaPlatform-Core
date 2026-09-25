package cryptoparse

import (
	"regexp"
	"strings"
)

// The key-size floors in keysize.go (SP 800-131A Rev 2: 2048-bit finite-field
// modulus, 256-bit curve) are floors for ASYMMETRIC keys. A crypto
// CONFIGURATION row, however, carries a single key_size, and the device
// collectors fill it with whatever bit count they can read — which for IPsec,
// WireGuard and F5 is the symmetric cipher's key length: AES-256 → 256.
//
// Measured against the asymmetric floor that number is nonsense in both
// directions it can go wrong:
//
//   - With no key-exchange family, the old family-blind `key_size < 2048` rule
//     reported "Weak key size" on every AES-256 tunnel (P-06).
//   - With one — Cisco's IKEv2 SA puts "DH Group 14" in the key-exchange field
//     beside Encr AES-CBC-256 — the family-aware rule read 256 as a DH modulus
//     and raised a CRITICAL "below 1024 bits".
//
// ConfigurationKeySizeSeverity is the configuration-level question: it declines
// to apply an asymmetric floor to a size that is exactly the key length the
// configuration's own symmetric cipher pins. A size that is not — the 1024-bit
// RSA certificate key behind an AES suite, say — is still measured.
//
// The rule is stated over the configuration's stored SYMMETRIC COMPONENT (the
// symmetric_encryption column — ingest writes SymmetricComponent(cipher) there)
// and a pattern over its cipher text, never over a free-form reading of the
// cipher string, because it has a SQL twin (inventory-service's
// configurationWeakKeySizeSQL) that must select exactly the rows this flags —
// the list filter, the summary counter and the MCP tool read the SQL. A row
// with no stored symmetric component is therefore measured as before, by both.

// SymmetricKeyLengths are the key lengths, in bits, a symmetric catalogue code
// can be reported with. 3DES appears as 168 (keying option 1) or 112 (its
// effective strength, SP 800-57 Pt 1 Table 2); DES as 56 or 64 with parity.
// 3DES's 192-with-parity spelling is deliberately NOT accepted: 192 is also a
// P-192 curve, which is below the elliptic-curve floor, and a 3DES suite with a
// P-192 certificate must still be flagged.
var SymmetricKeyLengths = map[string][]int{
	SymAES128:   {128},
	SymAES256:   {256},
	SymChaCha20: {256},
	Sym3DES:     {112, 168},
	SymDES:      {56, 64},
}

// AES192Pattern catches AES-192, which the suite vocabulary has no code for
// (no TLS suite uses it) but IPsec proposals do ("aes192", "AES-192-CBC"). It
// is matched against the upper-cased cipher text, and it is written in the
// regular-expression subset Go's RE2 and PostgreSQL's ARE read identically.
const AES192Pattern = `AES[-_ ]?192`

// IKEECPGroupPattern matches an IKE key-exchange named by group number when the
// group is elliptic-curve: 19-21 (RFC 5903), 25-26 (RFC 5114 ECP), 27-30
// (brainpool, RFC 6954), 31-32 (Curve25519/448, RFC 8031) — IANA "IKEv2
// Transform Type 4". "DH Group 25" contains "DH", so the family classifier
// alone calls it finite-field; it is a 192-bit curve. Same RE2/ARE subset.
const IKEECPGroupPattern = `GROUP ?(19|20|21|25|26|27|28|29|30|31|32)([^0-9]|$)`

var (
	aes192Re = regexp.MustCompile(AES192Pattern)
	ikeECPRe = regexp.MustCompile(IKEECPGroupPattern)
)

// ikeGroupIsECP reports whether a key-exchange string names an elliptic-curve
// IKE group by number.
func ikeGroupIsECP(upperKex string) bool { return ikeECPRe.MatchString(upperKex) }

// SizeIsSymmetricKeyLength reports whether bits is the key length of the
// configuration's symmetric cipher.
//
// symmetric is the configuration's stored symmetric component (see
// SymmetricComponent); it is NOT re-derived here, so the rule reads exactly
// what its SQL twin reads.
//
// AES-192 is the one ambiguous length: 192 is also a P-192 key, and IKE group
// 25 is a 192-bit curve. It is exempted only beside a finite-field key
// exchange that names no elliptic-curve group; beside an elliptic-curve or
// unknown key exchange the size is left to the asymmetric rule.
func SizeIsSymmetricKeyLength(keyAlgorithm, symmetric, cipher string, bits int) bool {
	if bits <= 0 {
		return false
	}
	sym := strings.ToUpper(strings.TrimSpace(symmetric))
	for _, l := range SymmetricKeyLengths[sym] {
		if l == bits {
			return true
		}
	}
	if bits == 192 && aes192Re.MatchString(strings.ToUpper(cipher)) {
		kex := strings.ToUpper(strings.TrimSpace(keyAlgorithm))
		return KeyAlgorithmFamily(kex) == KexFamilyFiniteField && !ikeGroupIsECP(kex)
	}
	return false
}

// SymmetricComponent is the symmetric component ingest stores for a cipher
// value: the one ParseCipherSuite names, which for a cipher string is the one
// every definitely-enabled suite shares — an excluded cipher never vouches.
func SymmetricComponent(cipher string) string {
	if strings.TrimSpace(cipher) == "" {
		return ""
	}
	if c, err := ParseCipherSuite(cipher); err == nil && c != nil {
		return c.Symmetric
	}
	return ""
}

// ConfigurationKeySizeSeverity is WeakKeySizeSeverity for a crypto
// configuration: keyAlgorithm is its key-exchange / public-key algorithm,
// symmetric its stored symmetric component, cipher its cipher suite (or
// transform, or cipher string), bits its key_size.
func ConfigurationKeySizeSeverity(keyAlgorithm, symmetric, cipher string, bits int) string {
	if SizeIsSymmetricKeyLength(keyAlgorithm, symmetric, cipher, bits) {
		return ""
	}
	return WeakKeySizeSeverity(keyAlgorithm, bits)
}
