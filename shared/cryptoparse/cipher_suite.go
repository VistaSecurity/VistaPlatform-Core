// Package cryptoparse holds the canonical, pure-Go parsing and normalization of
// cryptographic identifiers observed on the wire — cipher-suite names, protocol
// version strings — into the algorithm-catalogue vocabulary.
//
// It is deliberately free of any platform-runtime concern: no database, no NATS,
// no tenant context, no logging sink. That is what lets the standalone sensor
// import it alongside the in-cluster services, and it is why the catalogue
// LOOKUP (which needs a DB) stays in inventory-service while the string parsing
// lives here.
//
// There used to be two copies of this parser — inventory-service's and a
// hand-transcribed "mirror" inside cbom-service. They drifted: the mirror still
// emitted the mode-decorated names (AES-256-GCM, CHACHA20-POLY1305) that
// inventory's parser was specifically fixed to stop emitting, and its
// key-exchange table differed. Because CBOM artifacts are audit-grade evidence,
// that meant a CBOM could name a component differently from the inventory it was
// generated from, for the very same observed suite. One parser, one vocabulary.
package cryptoparse

import (
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// Cipher-suite parser vocabulary
//
// Every parser path emits ALGORITHM CATALOGUE CODES, never descriptive names.
// Consumers resolve these against `algorithms.code` (case-insensitively) and
// the compliance engine's seeded measurement predicates match on them
// literally, so the vocabulary is a contract, not an implementation detail:
//
//	symmetric     AES128 | AES256 | CHACHA20 | 3DES | DES | RC4 | NULL
//	hash          SHA1 | SHA224 | SHA256 | SHA384 | SHA512 | MD5 | NULL
//	key exchange  ECDHE | DHE | ECDH | DH | RSA | PSK | SRP | NULL
//
// Operating modes (GCM/CBC/CCM/POLY1305) are deliberately NOT part of a code:
// the mode is a property of the negotiated suite, and the suite itself is
// linked as its own `cipher_suite` catalogue row. Emitting "AES-256-GCM" — not
// a code — meant the fuzzy fallback matched whatever else happened to contain
// that substring, in practice the SMB-AES-256-GCM row, so ordinary TLS
// connections were recorded as using an SMB algorithm. "CHACHA20-POLY1305"
// likewise landed on the IPSec row, and the CBC/3DES/RC4 spellings matched
// nothing at all and were fabricated into the catalogue at risk 50.
const (
	SymAES128    = "AES128"
	SymAES256    = "AES256"
	SymChaCha20  = "CHACHA20"
	Sym3DES      = "3DES"
	SymDES       = "DES"
	SymRC4       = "RC4"
	SymNULL      = "NULL"
	KexECDHE     = "ECDHE"
	KexDHE       = "DHE"
	KexECDH      = "ECDH"
	KexDH        = "DH"
	KexRSA       = "RSA"
	HashSHA1     = "SHA1"
	HashSHA224   = "SHA224"
	HashSHA256   = "SHA256"
	HashSHA384   = "SHA384"
	HashSHA512   = "SHA512"
	HashMD5      = "MD5"
	SigRSA       = "RSA"
	SigECDSA     = "ECDSA"
	SigDSA       = "DSA"
	SigEd25519   = "ED25519"
	SigAnonymous = "ANON"
)

// CipherSuiteComponents represents the parsed components of a cipher suite.
type CipherSuiteComponents struct {
	KeyExchange string
	Signature   string
	Symmetric   string
	Hash        string
	IsInferred  bool
	Confidence  float64
}

// ParseCipherSuite parses a cipher suite name and extracts its components.
func ParseCipherSuite(cipherSuite string) (*CipherSuiteComponents, error) {
	if cipherSuite == "" {
		return nil, fmt.Errorf("cipher suite is empty")
	}

	components := &CipherSuiteComponents{
		Confidence: 1.0,
		IsInferred: false,
	}

	// Normalize cipher suite name
	cipherSuite = strings.TrimSpace(cipherSuite)
	cipherSuiteUpper := strings.ToUpper(cipherSuite)

	// Handle TLS 1.3 cipher suites (different format)
	// TLS 1.3 cipher suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
	if strings.HasPrefix(cipherSuiteUpper, "TLS_AES_") || strings.HasPrefix(cipherSuiteUpper, "TLS_CHACHA20_") {
		return parseTLS13CipherSuite(cipherSuiteUpper, components)
	}

	// Handle standard TLS 1.0-1.2 cipher suites
	// Format: TLS_{KEY_EXCHANGE}_{SIGNATURE}_WITH_{SYMMETRIC}_{HASH}
	// Example: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	if strings.HasPrefix(cipherSuiteUpper, "TLS_") && strings.Contains(cipherSuiteUpper, "_WITH_") {
		return parseStandardCipherSuite(cipherSuiteUpper, components)
	}

	// Handle non-standard or simplified cipher suite names
	// Examples: "AES128-SHA", "ECDHE-RSA-AES256-SHA", "RC4-SHA"
	return parseNonStandardCipherSuite(cipherSuiteUpper, components)
}

// SymmetricKeyBits returns the key length implied by a symmetric catalogue code,
// or 0 when the code does not pin one. Only the codes whose length is fixed by
// the name itself are reported — RC4 and NULL are deliberately 0 rather than
// guessed, because a wrong number in a CBOM is worse than an absent one.
func SymmetricKeyBits(code string) int {
	switch strings.ToUpper(strings.TrimSpace(code)) {
	case SymAES128:
		return 128
	case SymAES256:
		return 256
	case SymChaCha20:
		return 256
	default:
		return 0
	}
}

// codePattern maps a token that may appear in an abbreviated (OpenSSL-style)
// cipher-suite name to the catalogue code it denotes. Order matters and is the
// whole point of using a slice: matching is substring-based, so the more
// specific token has to be tried first. With a map (random iteration order) the
// part "ECDHE" matched "DHE" about half the time, and "3DES" matched "DES" —
// the same suite could be classified differently on two consecutive runs.
type codePattern struct {
	token string
	code  string
}

var nonStandardKeyExchangePatterns = []codePattern{
	{"ECDHE", KexECDHE},
	{"EECDH", KexECDHE},
	{"ECDH", KexECDH},
	{"EDH", KexDHE},
	{"DHE", KexDHE},
	{"DH", KexDH},
	{"RSA", KexRSA},
	{"PSK", "PSK"},
}

var nonStandardSignaturePatterns = []codePattern{
	{"ECDSA", SigECDSA},
	{"ED25519", SigEd25519},
	{"DSS", SigDSA},
	{"DSA", SigDSA},
	{"RSA", SigRSA},
}

var nonStandardSymmetricPatterns = []codePattern{
	{"CHACHA20", SymChaCha20},
	{"3DES", Sym3DES},
	{"CBC3", Sym3DES}, // OpenSSL spells triple-DES suites "DES-CBC3-SHA"
	{"DES_EDE", Sym3DES},
	{"DES40", SymDES},
	{"DES", SymDES},
	{"RC4", SymRC4},
	{"AES128", SymAES128},
	{"AES_128", SymAES128},
	{"AES256", SymAES256},
	{"AES_256", SymAES256},
}

var nonStandardHashPatterns = []codePattern{
	{"SHA384", HashSHA384},
	{"SHA512", HashSHA512},
	{"SHA256", HashSHA256},
	{"SHA224", HashSHA224},
	{"SHA1", HashSHA1},
	{"SHA", HashSHA1},
	{"MD5", HashMD5},
}

// matchCodePattern returns the first pattern whose token is contained in part.
func matchCodePattern(part string, patterns []codePattern) (string, bool) {
	for _, p := range patterns {
		if strings.Contains(part, p.token) {
			return p.code, true
		}
	}
	return "", false
}

// parseTLS13CipherSuite parses TLS 1.3 cipher suite format
func parseTLS13CipherSuite(cipherSuite string, components *CipherSuiteComponents) (*CipherSuiteComponents, error) {
	// TLS 1.3 cipher suites don't have explicit key exchange or signature
	// They use ephemeral key exchange (ECDHE) and authentication is separate
	components.KeyExchange = KexECDHE
	components.Signature = "" // TLS 1.3 uses separate authentication

	// Extract symmetric encryption and hash.
	//
	// These are algorithm CODES, not descriptions: every consumer resolves them
	// against the `algorithms` catalogue. Emitting "AES-256-GCM" (which is not a
	// code) meant the fuzzy fallback matched whatever else happened to contain
	// that substring — in practice SMB-AES-256-GCM, so every TLS 1.3 AES-256
	// connection was recorded as using an SMB algorithm.
	if strings.Contains(cipherSuite, "AES_128_GCM") || strings.Contains(cipherSuite, "AES_128_CCM") {
		components.Symmetric = SymAES128
	} else if strings.Contains(cipherSuite, "AES_256_GCM") || strings.Contains(cipherSuite, "AES_256_CCM") {
		components.Symmetric = SymAES256
	} else if strings.Contains(cipherSuite, "CHACHA20_POLY1305") {
		components.Symmetric = SymChaCha20
	}

	// Extract hash
	if strings.Contains(cipherSuite, "SHA256") {
		components.Hash = HashSHA256
	} else if strings.Contains(cipherSuite, "SHA384") {
		components.Hash = HashSHA384
	}

	return components, nil
}

// parseStandardCipherSuite parses standard IANA TLS cipher suite format
func parseStandardCipherSuite(cipherSuite string, components *CipherSuiteComponents) (*CipherSuiteComponents, error) {
	// Pattern: TLS_{KEY_EXCHANGE}_{SIGNATURE}_WITH_{SYMMETRIC}_{HASH}
	// Example: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

	// Split by "_WITH_" to separate key exchange/signature from symmetric/hash
	parts := strings.Split(cipherSuite, "_WITH_")
	if len(parts) != 2 {
		components.IsInferred = true
		components.Confidence = 0.5
		return components, fmt.Errorf("invalid cipher suite format")
	}

	// Parse key exchange and signature from first part
	// Remove "TLS_" prefix
	keyExchAndSig := strings.TrimPrefix(parts[0], "TLS_")
	keyExchAndSigParts := strings.Split(keyExchAndSig, "_")

	// Key exchange algorithms.
	//
	// The STATIC forms matter and are not interchangeable with the ephemeral
	// ones: TLS_ECDH_RSA_* and TLS_DH_RSA_* offer no forward secrecy, which is
	// exactly what the no-PFS compliance controls look for. Without "ECDH" and
	// "DH" as keys the loop skipped straight past them to the RSA token in the
	// AUTHENTICATION position and labelled a static-ECDH suite "RSA".
	keyExchangeMap := map[string]string{
		"ECDHE": KexECDHE,
		"EECDH": KexECDHE,
		"DHE":   KexDHE,
		"EDH":   KexDHE,
		"ECDH":  KexECDH,
		"DH":    KexDH,
		"RSA":   KexRSA,
		"PSK":   "PSK",
		"SRP":   "SRP",
		"NULL":  "NULL",
	}

	// Signature algorithms
	signatureMap := map[string]string{
		"RSA":   SigRSA,
		"ECDSA": SigECDSA,
		"DSA":   SigDSA,
		"DSS":   SigDSA,
		"ANON":  SigAnonymous,
		"PSK":   "PSK",
		"NULL":  "NULL",
	}

	// Extract key exchange
	for _, part := range keyExchAndSigParts {
		if ke, ok := keyExchangeMap[part]; ok {
			components.KeyExchange = ke
			break
		}
	}

	// Extract signature
	for _, part := range keyExchAndSigParts {
		if sig, ok := signatureMap[part]; ok {
			components.Signature = sig
			break
		}
	}

	// Parse symmetric and hash from second part
	symAndHash := parts[1]
	symAndHashParts := strings.Split(symAndHash, "_")

	// Symmetric encryption algorithms. Keys are the wire spelling; values are
	// catalogue codes, with the operating mode dropped (see the vocabulary note
	// above — the mode belongs to the cipher_suite row, not to the cipher).
	symmetricMap := map[string]string{
		"AES_128":           SymAES128,
		"AES_256":           SymAES256,
		"3DES_EDE":          Sym3DES,
		"3DES":              Sym3DES,
		"DES40":             SymDES,
		"DES":               SymDES,
		"RC4_40":            SymRC4,
		"RC4_128":           SymRC4,
		"RC4":               SymRC4,
		"CHACHA20":          SymChaCha20,
		"CHACHA20_POLY1305": SymChaCha20,
		"NULL":              SymNULL,
	}

	// Hash/MAC algorithms
	hashMap := map[string]string{
		"SHA":    HashSHA1,
		"SHA224": HashSHA224,
		"SHA256": HashSHA256,
		"SHA384": HashSHA384,
		"SHA512": HashSHA512,
		"MD5":    HashMD5,
		"NULL":   "NULL",
	}

	// Extract symmetric encryption
	for i := 0; i < len(symAndHashParts); i++ {
		// Try multi-part matches first
		if i+1 < len(symAndHashParts) {
			combined := symAndHashParts[i] + "_" + symAndHashParts[i+1]
			if sym, ok := symmetricMap[combined]; ok {
				components.Symmetric = sym
				break
			}
			if i+2 < len(symAndHashParts) {
				combined3 := symAndHashParts[i] + "_" + symAndHashParts[i+1] + "_" + symAndHashParts[i+2]
				if sym, ok := symmetricMap[combined3]; ok {
					components.Symmetric = sym
					break
				}
			}
		}
		// Try single part
		if sym, ok := symmetricMap[symAndHashParts[i]]; ok {
			components.Symmetric = sym
			break
		}
	}

	// Extract hash (usually the last part)
	if len(symAndHashParts) > 0 {
		lastPart := symAndHashParts[len(symAndHashParts)-1]
		if hash, ok := hashMap[lastPart]; ok {
			components.Hash = hash
		}
	}

	return components, nil
}

// parseNonStandardCipherSuite parses non-standard or simplified cipher suite names
func parseNonStandardCipherSuite(cipherSuite string, components *CipherSuiteComponents) (*CipherSuiteComponents, error) {
	components.IsInferred = true
	components.Confidence = 0.7

	// Common patterns in non-standard names
	cipherSuite = strings.ReplaceAll(cipherSuite, "-", "_")
	cipherSuite = strings.ReplaceAll(cipherSuite, " ", "_")
	parts := strings.Split(cipherSuite, "_")

	// Extract components using ordered pattern matching over the WHOLE
	// normalized name. See the vocabulary note above for why these are ordered
	// slices rather than maps; matching the whole string rather than each part
	// in turn is what lets OpenSSL's "DES-CBC3-SHA" be recognised as 3DES —
	// scanning left to right, its first part is the bare token "DES".
	normalized := strings.ToUpper(strings.Join(parts, "_"))

	if code, ok := matchCodePattern(normalized, nonStandardKeyExchangePatterns); ok {
		components.KeyExchange = code
	}
	if code, ok := matchCodePattern(normalized, nonStandardSignaturePatterns); ok {
		components.Signature = code
	}
	if code, ok := matchCodePattern(normalized, nonStandardSymmetricPatterns); ok {
		components.Symmetric = code
	}
	if code, ok := matchCodePattern(normalized, nonStandardHashPatterns); ok {
		components.Hash = code
	}

	return components, nil
}
