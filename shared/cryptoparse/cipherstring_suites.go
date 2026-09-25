package cryptoparse

import "strings"

// TLSCipherSuite is one concrete TLS 1.0-1.2 cipher suite the cipher-string
// parser can resolve a token to.
//
// The attributes are not hand-entered: every field except the two names is
// derived from the IANA name by ParseCipherSuite, so a suite's key exchange,
// cipher and hash are spelled in the same catalogue vocabulary everything else
// in this package emits, and the cipher-string keywords select on exactly the
// components inventory would link for the same suite.
type TLSCipherSuite struct {
	// OpenSSLName is the name OpenSSL (and the vendors whose cipher strings
	// borrow its syntax: F5 BIG-IP, Cisco ASA custom lists) use in a cipher
	// string, e.g. "ECDHE-RSA-AES256-GCM-SHA384".
	OpenSSLName string
	// IANAName is the registered name, e.g.
	// "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384". It is also the code the
	// algorithm catalogue keys its cipher_suite rows on.
	IANAName string

	KeyExchange    string // ECDHE | DHE | ECDH | DH | RSA (catalogue codes)
	Authentication string // RSA | ECDSA | DSA | ANON
	Symmetric      string // AES128 | AES256 | CHACHA20 | 3DES | DES | RC4 | NULL
	Mode           string // GCM | CCM | POLY1305 | CBC | "" (stream / none)
	// MAC is the record MAC: MD5 | SHA1 | SHA256 | SHA384, or "AEAD" for the
	// AEAD modes, which have no separate MAC. OpenSSL's MD5/SHA1/SHA256/SHA384
	// cipher-string keywords select on this, not on Hash.
	MAC string
	// Hash is the hash the suite name carries (for AEAD suites that is the PRF
	// hash), exactly as ParseCipherSuite reports it.
	Hash string
	// StrengthBits is the symmetric strength OpenSSL sorts on for @STRENGTH.
	StrengthBits int
}

// aead reports whether the suite uses an AEAD mode.
func (s TLSCipherSuite) aead() bool { return s.MAC == "AEAD" }

// tls12Only reports whether the suite can only be negotiated at TLS 1.2: every
// AEAD suite, and the CBC suites with a SHA-2 MAC (RFC 5246 §A.5, RFC 5288,
// RFC 5289, RFC 7905, RFC 6655).
func (s TLSCipherSuite) tls12Only() bool {
	return s.aead() || s.MAC == HashSHA256 || s.MAC == HashSHA384
}

func (s TLSCipherSuite) anonymous() bool { return s.Authentication == SigAnonymous }

// dhFamily / ecdhFamily group the ephemeral and anonymous forms: the anonymous
// suites parse as "DH"/"ECDH" (no authentication in the name), and the table
// below holds no fixed-(EC)DH suites.
func (s TLSCipherSuite) dhFamily() bool {
	return s.KeyExchange == KexDHE || s.KeyExchange == KexDH
}

func (s TLSCipherSuite) ecdhFamily() bool {
	return s.KeyExchange == KexECDHE || s.KeyExchange == KexECDH
}

func (s TLSCipherSuite) aes() bool { return s.Symmetric == SymAES128 || s.Symmetric == SymAES256 }

// modernSymmetric is the set of ciphers OpenSSL has classed HIGH in every
// release that shipped them (ssl/s3_lib.c strength field): no version of
// LOW/MEDIUM/EXPORT has ever selected an AES or ChaCha20 suite.
func (s TLSCipherSuite) modernSymmetric() bool {
	return s.aes() || s.Symmetric == SymChaCha20
}

// cipherStringSuitePairs is the bounded suite table: OpenSSL name → IANA name.
//
// Source: the "CIPHER SUITE NAMES" section of OpenSSL's ciphers(1) manual page
// (https://docs.openssl.org/1.1.1/man1/ciphers/ and the 1.0.2 page for the
// single-DES and EDH-* spellings, which 1.1.0 renamed/removed), which lists the
// OpenSSL name for each registered suite. Coverage is deliberately limited to
// the RSA/DH/ECDH suites with AES, ChaCha20, 3DES, DES, RC4 or NULL ciphers —
// the ciphers the algorithm catalogue and the weak-crypto rules speak about.
// CAMELLIA, ARIA, SEED, IDEA, PSK, SRP, GOST, fixed-(EC)DH and export suites are
// NOT listed; a token that selects only those resolves to nothing here and is
// reported as unexpanded rather than guessed at.
//
// TLS 1.3 suites are absent on purpose: OpenSSL configures them separately
// (SSL_CTX_set_ciphersuites) and its cipher-string keywords never select them.
//
// Where OpenSSL has renamed a suite, both spellings are listed as extra names.
var cipherStringSuitePairs = []struct {
	openssl string
	iana    string
	aliases []string
}{
	// RSA key exchange (RFC 5246, RFC 3268, RFC 5288).
	{"NULL-MD5", "TLS_RSA_WITH_NULL_MD5", nil},
	{"NULL-SHA", "TLS_RSA_WITH_NULL_SHA", nil},
	{"NULL-SHA256", "TLS_RSA_WITH_NULL_SHA256", nil},
	{"RC4-MD5", "TLS_RSA_WITH_RC4_128_MD5", nil},
	{"RC4-SHA", "TLS_RSA_WITH_RC4_128_SHA", nil},
	{"DES-CBC-SHA", "TLS_RSA_WITH_DES_CBC_SHA", nil},
	{"DES-CBC3-SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", nil},
	{"AES128-SHA", "TLS_RSA_WITH_AES_128_CBC_SHA", nil},
	{"AES256-SHA", "TLS_RSA_WITH_AES_256_CBC_SHA", nil},
	{"AES128-SHA256", "TLS_RSA_WITH_AES_128_CBC_SHA256", nil},
	{"AES256-SHA256", "TLS_RSA_WITH_AES_256_CBC_SHA256", nil},
	{"AES128-GCM-SHA256", "TLS_RSA_WITH_AES_128_GCM_SHA256", nil},
	{"AES256-GCM-SHA384", "TLS_RSA_WITH_AES_256_GCM_SHA384", nil},
	{"AES128-CCM", "TLS_RSA_WITH_AES_128_CCM", nil},
	{"AES256-CCM", "TLS_RSA_WITH_AES_256_CCM", nil},

	// Ephemeral DH (RFC 5246, RFC 3268, RFC 5288, RFC 6655, RFC 7905).
	{"EDH-DSS-DES-CBC-SHA", "TLS_DHE_DSS_WITH_DES_CBC_SHA", nil},
	{"EDH-RSA-DES-CBC-SHA", "TLS_DHE_RSA_WITH_DES_CBC_SHA", nil},
	{"DHE-DSS-DES-CBC3-SHA", "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", []string{"EDH-DSS-DES-CBC3-SHA"}},
	{"DHE-RSA-DES-CBC3-SHA", "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", []string{"EDH-RSA-DES-CBC3-SHA"}},
	{"DHE-DSS-AES128-SHA", "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", nil},
	{"DHE-DSS-AES256-SHA", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", nil},
	{"DHE-RSA-AES128-SHA", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", nil},
	{"DHE-RSA-AES256-SHA", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", nil},
	{"DHE-DSS-AES128-SHA256", "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", nil},
	{"DHE-DSS-AES256-SHA256", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", nil},
	{"DHE-RSA-AES128-SHA256", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", nil},
	{"DHE-RSA-AES256-SHA256", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", nil},
	{"DHE-DSS-AES128-GCM-SHA256", "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", nil},
	{"DHE-DSS-AES256-GCM-SHA384", "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", nil},
	{"DHE-RSA-AES128-GCM-SHA256", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", nil},
	{"DHE-RSA-AES256-GCM-SHA384", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", nil},
	{"DHE-RSA-AES128-CCM", "TLS_DHE_RSA_WITH_AES_128_CCM", nil},
	{"DHE-RSA-AES256-CCM", "TLS_DHE_RSA_WITH_AES_256_CCM", nil},
	{"DHE-RSA-CHACHA20-POLY1305", "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", nil},

	// Anonymous DH — no authentication at all.
	{"ADH-RC4-MD5", "TLS_DH_anon_WITH_RC4_128_MD5", nil},
	{"ADH-DES-CBC3-SHA", "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", nil},
	{"ADH-AES128-SHA", "TLS_DH_anon_WITH_AES_128_CBC_SHA", nil},
	{"ADH-AES256-SHA", "TLS_DH_anon_WITH_AES_256_CBC_SHA", nil},
	{"ADH-AES128-SHA256", "TLS_DH_anon_WITH_AES_128_CBC_SHA256", nil},
	{"ADH-AES256-SHA256", "TLS_DH_anon_WITH_AES_256_CBC_SHA256", nil},
	{"ADH-AES128-GCM-SHA256", "TLS_DH_anon_WITH_AES_128_GCM_SHA256", nil},
	{"ADH-AES256-GCM-SHA384", "TLS_DH_anon_WITH_AES_256_GCM_SHA384", nil},

	// Ephemeral ECDH (RFC 4492, RFC 5289, RFC 7251, RFC 7905).
	{"ECDHE-RSA-NULL-SHA", "TLS_ECDHE_RSA_WITH_NULL_SHA", nil},
	{"ECDHE-RSA-RC4-SHA", "TLS_ECDHE_RSA_WITH_RC4_128_SHA", nil},
	{"ECDHE-RSA-DES-CBC3-SHA", "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", nil},
	{"ECDHE-RSA-AES128-SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", nil},
	{"ECDHE-RSA-AES256-SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", nil},
	{"ECDHE-RSA-AES128-SHA256", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", nil},
	{"ECDHE-RSA-AES256-SHA384", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", nil},
	{"ECDHE-RSA-AES128-GCM-SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", nil},
	{"ECDHE-RSA-AES256-GCM-SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", nil},
	{"ECDHE-RSA-CHACHA20-POLY1305", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", nil},
	{"ECDHE-ECDSA-NULL-SHA", "TLS_ECDHE_ECDSA_WITH_NULL_SHA", nil},
	{"ECDHE-ECDSA-RC4-SHA", "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", nil},
	{"ECDHE-ECDSA-DES-CBC3-SHA", "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", nil},
	{"ECDHE-ECDSA-AES128-SHA", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", nil},
	{"ECDHE-ECDSA-AES256-SHA", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", nil},
	{"ECDHE-ECDSA-AES128-SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", nil},
	{"ECDHE-ECDSA-AES256-SHA384", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", nil},
	{"ECDHE-ECDSA-AES128-GCM-SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", nil},
	{"ECDHE-ECDSA-AES256-GCM-SHA384", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", nil},
	{"ECDHE-ECDSA-AES128-CCM", "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", nil},
	{"ECDHE-ECDSA-AES256-CCM", "TLS_ECDHE_ECDSA_WITH_AES_256_CCM", nil},
	{"ECDHE-ECDSA-CHACHA20-POLY1305", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", nil},

	// Anonymous ECDH.
	{"AECDH-NULL-SHA", "TLS_ECDH_anon_WITH_NULL_SHA", nil},
	{"AECDH-RC4-SHA", "TLS_ECDH_anon_WITH_RC4_128_SHA", nil},
	{"AECDH-DES-CBC3-SHA", "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", nil},
	{"AECDH-AES128-SHA", "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", nil},
	{"AECDH-AES256-SHA", "TLS_ECDH_anon_WITH_AES_256_CBC_SHA", nil},
}

// cipherStringSuites is the table with its attributes derived, in table order.
var cipherStringSuites []TLSCipherSuite

// cipherStringSuiteByName resolves an upper-cased OpenSSL name, IANA name, or
// hyphenated IANA name (FortiOS spells "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384")
// to an index into cipherStringSuites.
var cipherStringSuiteByName map[string]int

func init() {
	cipherStringSuiteByName = make(map[string]int, len(cipherStringSuitePairs)*4)
	for _, p := range cipherStringSuitePairs {
		s := deriveTLSCipherSuite(p.openssl, p.iana)
		idx := len(cipherStringSuites)
		cipherStringSuites = append(cipherStringSuites, s)
		names := append([]string{p.openssl, p.iana, strings.ReplaceAll(p.iana, "_", "-")}, p.aliases...)
		for _, n := range names {
			cipherStringSuiteByName[strings.ToUpper(n)] = idx
		}
	}
}

// deriveTLSCipherSuite fills a suite's attributes from its IANA name.
func deriveTLSCipherSuite(openssl, iana string) TLSCipherSuite {
	s := TLSCipherSuite{OpenSSLName: openssl, IANAName: iana}
	c, err := ParseCipherSuite(iana)
	if err == nil && c != nil {
		s.KeyExchange = c.KeyExchange
		s.Authentication = c.Signature
		s.Symmetric = c.Symmetric
		s.Hash = c.Hash
	}
	upper := strings.ToUpper(iana)
	switch {
	case strings.Contains(upper, "_GCM"):
		s.Mode = "GCM"
	case strings.Contains(upper, "_CCM"):
		s.Mode = "CCM"
	case strings.Contains(upper, "CHACHA20_POLY1305"):
		s.Mode = "POLY1305"
	case strings.Contains(upper, "_CBC"):
		s.Mode = "CBC"
	}
	s.MAC = s.Hash
	if s.Mode == "GCM" || s.Mode == "CCM" || s.Mode == "POLY1305" {
		s.MAC = "AEAD"
	}
	// Strength bits as OpenSSL 1.1.0+ reports them (3DES dropped from 168 to 112
	// there, reflecting its real security level).
	switch s.Symmetric {
	case SymAES256, SymChaCha20:
		s.StrengthBits = 256
	case SymAES128, SymRC4:
		s.StrengthBits = 128
	case Sym3DES:
		s.StrengthBits = 112
	case SymDES:
		s.StrengthBits = 56
	}
	return s
}

// LookupTLSCipherSuite resolves one suite name (OpenSSL, IANA, or the
// hyphenated IANA spelling) against the bounded table.
func LookupTLSCipherSuite(name string) (TLSCipherSuite, bool) {
	idx, ok := cipherStringSuiteByName[strings.ToUpper(strings.TrimSpace(name))]
	if !ok {
		return TLSCipherSuite{}, false
	}
	return cipherStringSuites[idx], true
}
