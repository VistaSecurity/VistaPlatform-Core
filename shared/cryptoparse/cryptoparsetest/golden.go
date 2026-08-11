// Package cryptoparsetest holds the cross-consumer conformance fixture for the
// cipher-suite parser.
//
// Every service that turns an observed cipher-suite name into algorithm
// components must produce the SAME components for the same suite — inventory
// records them as crypto_implementation_algorithms links, and cbom-service
// names them as components in an audit-grade CBOM artifact. When those two
// disagree, a customer's evidence contradicts the inventory it was generated
// from, for the same wire observation. That is exactly what happened while
// cbom-service carried a hand-transcribed copy of the parser.
//
// The table lives in its own package (rather than in either consumer's tests,
// or as an exported var in cryptoparse itself) so that one edit governs both
// consumers and neither can quietly weaken its own copy.
package cryptoparsetest

// GoldenSuite is one representative suite and the components every consumer
// must derive from it. Empty means "must produce no component in this role".
type GoldenSuite struct {
	Suite       string
	KeyExchange string
	Signature   string
	Symmetric   string
	Hash        string
	// SymmetricKeyBits is the key length the suite name itself pins, or 0 when
	// the name does not pin one.
	SymmetricKeyBits int
}

// GoldenSuites spans the shapes real producers emit: TLS 1.3 (no key exchange
// in the name), IANA TLS 1.2 in both AEAD and CBC form, the static
// (non-forward-secret) ECDH variant, legacy 3DES and RC4, and the OpenSSL
// abbreviations the sensor's enrichment path can surface.
var GoldenSuites = []GoldenSuite{
	// TLS 1.3 — the suite names no key exchange, so ECDHE is inferred.
	{Suite: "TLS_AES_128_GCM_SHA256", KeyExchange: "ECDHE", Symmetric: "AES128", Hash: "SHA256", SymmetricKeyBits: 128},
	{Suite: "TLS_AES_256_GCM_SHA384", KeyExchange: "ECDHE", Symmetric: "AES256", Hash: "SHA384", SymmetricKeyBits: 256},
	{Suite: "TLS_CHACHA20_POLY1305_SHA256", KeyExchange: "ECDHE", Symmetric: "CHACHA20", Hash: "SHA256", SymmetricKeyBits: 256},

	// IANA TLS 1.2 — AEAD and CBC. The mode is deliberately absent from the
	// symmetric code; the suite itself is linked as its own cipher_suite row.
	{Suite: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", KeyExchange: "ECDHE", Signature: "RSA", Symmetric: "AES256", Hash: "SHA384", SymmetricKeyBits: 256},
	{Suite: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", KeyExchange: "ECDHE", Signature: "RSA", Symmetric: "AES256", Hash: "SHA384", SymmetricKeyBits: 256},
	{Suite: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", KeyExchange: "ECDHE", Signature: "ECDSA", Symmetric: "AES128", Hash: "SHA256", SymmetricKeyBits: 128},

	// Static ECDH / DH: no forward secrecy. These must NOT be reported as plain
	// RSA — the no-PFS controls are looking for exactly this.
	{Suite: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", KeyExchange: "ECDH", Signature: "RSA", Symmetric: "AES128", Hash: "SHA256", SymmetricKeyBits: 128},
	{Suite: "TLS_DH_RSA_WITH_AES_256_CBC_SHA256", KeyExchange: "DH", Signature: "RSA", Symmetric: "AES256", Hash: "SHA256", SymmetricKeyBits: 256},

	// Legacy / weak.
	{Suite: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", KeyExchange: "RSA", Signature: "RSA", Symmetric: "3DES", Hash: "SHA1"},
	{Suite: "TLS_RSA_WITH_RC4_128_SHA", KeyExchange: "RSA", Signature: "RSA", Symmetric: "RC4", Hash: "SHA1"},
	{Suite: "TLS_RSA_WITH_DES_CBC_SHA", KeyExchange: "RSA", Signature: "RSA", Symmetric: "DES", Hash: "SHA1"},

	// OpenSSL abbreviations.
	{Suite: "ECDHE-RSA-AES256-GCM-SHA384", KeyExchange: "ECDHE", Signature: "RSA", Symmetric: "AES256", Hash: "SHA384", SymmetricKeyBits: 256},
	{Suite: "DES-CBC3-SHA", Symmetric: "3DES", Hash: "SHA1"},
	{Suite: "AES128-SHA", Symmetric: "AES128", Hash: "SHA1", SymmetricKeyBits: 128},
	{Suite: "RC4-MD5", Symmetric: "RC4", Hash: "MD5"},
}
