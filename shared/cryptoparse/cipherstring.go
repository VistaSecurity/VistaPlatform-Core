package cryptoparse

import (
	"sort"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// OpenSSL cipher strings
// ---------------------------------------------------------------------------
//
// Network devices do not report "the cipher suite". They report a cipher
// STRING — a small program in OpenSSL's ciphers(1) grammar that the device's
// TLS library evaluates into an ordered suite list:
//
//	ECDHE+AES-GCM:!aNULL:!RC4:!3DES:!MD5      (F5 BIG-IP client-ssl profile)
//	ECDHE:RSA:!SSLV3:!RC4:!EXP:!DES           (F5's built-in f5-secure rule)
//	AES256-SHA:AES128-SHA:DES-CBC3-SHA        (Cisco ASA `ssl cipher … custom`)
//
// Reading that string as if it were one suite name — substring-matching RC4,
// 3DES and MD5 in it — turns every exclusion into a feature: the hardened
// profile above was reported as running RC4, 3DES and MD5 and scored Critical.
//
// ParseCipherString evaluates the grammar instead. Its one rule is that it
// never says more than the string proves:
//
//   - A cipher named after `!` or `-` is never reported as enabled.
//   - A keyword whose expansion depends on the vendor or the library version
//     (DEFAULT, HIGH, MEDIUM, F5's NATIVE, a cipher-group name, …) is reported
//     as unexpanded, and the result is marked incomplete. No expansion is
//     invented for it.
//   - When such a keyword REMOVES ciphers, the suites it might have removed are
//     moved to Uncertain rather than kept as Enabled — "might be enabled" is
//     not "enabled".
//
// Grammar, per ciphers(1) (https://docs.openssl.org/master/man1/openssl-ciphers/,
// "CIPHER LIST FORMAT"):
//
//   - The list is cipher strings separated by `:`; `,` and spaces are also
//     accepted.
//   - A string is a suite name, a keyword, or keywords AND-combined with `+`
//     ("SHA1+DES": suites using SHA1 and DES).
//   - Prefix `!`: the suites are permanently deleted and never reappear, even if
//     named explicitly later.
//   - Prefix `-`: the suites are deleted but later options may add them back.
//   - Prefix `+`: matching suites already in the list move to the end; nothing
//     is added.
//   - No prefix: suites are appended; ones already present are not moved.
//   - `@STRENGTH` sorts the list by symmetric key strength, `@SECLEVEL=n` sets
//     the library's security level.

// CipherStringDialect says whose keyword definitions apply.
type CipherStringDialect int

const (
	// CipherStringVendor is an OpenSSL-DERIVED syntax whose keyword expansions
	// the vendor defines — F5 BIG-IP, Cisco ASA custom lists, FortiOS, or a
	// stored string whose origin is unknown. Only explicit suite names are
	// ever added. Removals by a keyword that names an algorithm (RC4, 3DES,
	// MD5, aNULL, AES256, …) are exact; removals by a keyword that names a
	// class of suites (ECDHE, RSA, DHE, …) only put their reach in doubt,
	// because vendors define those classes differently: F5's built-in f5-ecc
	// rule is "ECDHE:ECDHE_ECDSA", which only makes sense if F5's ECDHE does
	// NOT include the ECDSA-authenticated suites that OpenSSL's does.
	CipherStringVendor CipherStringDialect = iota
	// CipherStringOpenSSL applies OpenSSL's own keyword definitions
	// (ciphers(1), "CIPHER STRINGS") to every keyword they cover.
	CipherStringOpenSSL
)

// CipherStringResult is what a cipher string provably selects.
type CipherStringResult struct {
	Raw     string
	Dialect CipherStringDialect

	// Enabled is the ordered list of table suites the string definitely
	// selects. It is bounded by the suite table (cipherstring_suites.go): a
	// keyword can also select suites the table does not list (CAMELLIA, PSK, …),
	// and a library may not implement every listed suite — the string cannot
	// say either. Suites added by keyword expansion appear in table order.
	Enabled []TLSCipherSuite
	// Uncertain are suites the string added but an unexpanded removal (or
	// @SECLEVEL) may have taken out again. They are neither enabled nor
	// disabled as far as the string can prove.
	Uncertain []TLSCipherSuite
	// Excluded are the tokens that followed `!` or `-`, as written without the
	// operator, in order.
	Excluded []string
	// Unexpanded are the tokens (with any operator, as written) whose effect the
	// parser could not determine: version- or vendor-defined keywords, cipher
	// groups, unknown names, and keywords that select only suites outside the
	// table.
	Unexpanded []string
	// Complete is true only when Enabled is the whole table-bounded selection:
	// the string adds at least one thing, every addition was resolved, and
	// nothing is Uncertain.
	Complete bool
	// PossiblyEnabled is what the string MAY enable and could not be resolved
	// either way: the IANA names of the Uncertain suites, the algorithm
	// keywords it adds without expanding (RC4, 3DES, MD5, aNULL, LOW, …) and
	// the explicit suite names outside the table (EXP-RC4-MD5). Never a token
	// that an exact exclusion covers.
	//
	// It exists for RISK. "Not proven enabled" is not "proven disabled": a
	// string that adds RC4 through a keyword the parser declines to expand, or
	// names an RC4 suite it does not list, still exposes RC4, and scoring it
	// as if it did not would make an unresolved answer read as a safe one.
	PossiblyEnabled []string
}

// EnabledNames returns the OpenSSL names of the definitely-enabled suites.
func (r *CipherStringResult) EnabledNames() []string {
	out := make([]string, 0, len(r.Enabled))
	for _, s := range r.Enabled {
		out = append(out, s.OpenSSLName)
	}
	return out
}

// Components returns the cipher-suite components every enabled suite shares —
// the only components the string as a whole can be said to use in a
// single-valued field. A role on which the enabled suites differ is left empty.
// Returns nil when nothing is enabled.
func (r *CipherStringResult) Components() *CipherSuiteComponents {
	if len(r.Enabled) == 0 {
		return nil
	}
	first := r.Enabled[0]
	c := &CipherSuiteComponents{
		KeyExchange: first.KeyExchange,
		Signature:   first.Authentication,
		Symmetric:   first.Symmetric,
		Hash:        first.Hash,
		IsInferred:  true,
		Confidence:  0.7,
	}
	for _, s := range r.Enabled[1:] {
		if s.KeyExchange != c.KeyExchange {
			c.KeyExchange = ""
		}
		if s.Authentication != c.Signature {
			c.Signature = ""
		}
		if s.Symmetric != c.Symmetric {
			c.Symmetric = ""
		}
		if s.Hash != c.Hash {
			c.Hash = ""
		}
	}
	return c
}

// suitePredicate selects table suites.
type suitePredicate func(TLSCipherSuite) bool

func anySuite(TLSCipherSuite) bool        { return true }
func noSuite(TLSCipherSuite) bool         { return false }
func not(p suitePredicate) suitePredicate { return func(s TLSCipherSuite) bool { return !p(s) } }

// cipherKeyword is one ciphers(1) keyword.
type cipherKeyword struct {
	// openssl is OpenSSL's definition, or nil when the keyword's membership is
	// version-dependent (HIGH, MEDIUM, DEFAULT, …) and therefore never expanded.
	openssl suitePredicate
	// algorithm marks keywords that name an algorithm rather than a class of
	// suites, whose meaning is the same in every OpenSSL-derived dialect.
	algorithm bool
	// may bounds what the keyword could select under ANY dialect or library
	// version; it decides which suites an unexpanded removal puts in doubt. nil
	// means "the definition, if any; otherwise everything".
	may suitePredicate
}

func symIs(codes ...string) suitePredicate {
	return func(s TLSCipherSuite) bool {
		for _, c := range codes {
			if s.Symmetric == c {
				return true
			}
		}
		return false
	}
}

func macIs(code string) suitePredicate {
	return func(s TLSCipherSuite) bool { return s.MAC == code }
}

func hashIs(code string) suitePredicate {
	return func(s TLSCipherSuite) bool { return s.Hash == code }
}

func authIs(code string) suitePredicate {
	return func(s TLSCipherSuite) bool { return s.Authentication == code }
}

// cipherKeywords holds the keywords, with definitions quoted from ciphers(1)
// ("CIPHER STRINGS" section, OpenSSL 1.1.1 / 3.x unless noted).
var cipherKeywords = map[string]cipherKeyword{
	// --- keywords naming an algorithm ------------------------------------
	// "eNULL, NULL: The cipher suites offering no encryption."
	"eNULL": {openssl: symIs(SymNULL), algorithm: true},
	"NULL":  {openssl: symIs(SymNULL), algorithm: true},
	// "aNULL: The cipher suites offering no authentication."
	"aNULL": {openssl: authIs(SigAnonymous), algorithm: true},
	// "AES128, AES256, AES: cipher suites using 128 bit AES, 256 bit AES or
	// either 128 or 256 bit AES."
	"AES128": {openssl: symIs(SymAES128), algorithm: true},
	"AES256": {openssl: symIs(SymAES256), algorithm: true},
	"AES":    {openssl: symIs(SymAES128, SymAES256), algorithm: true},
	// "AESGCM: AES in Galois Counter Mode (GCM)" / "AESCCM: AES in CCM mode".
	"AESGCM": {openssl: func(s TLSCipherSuite) bool { return s.aes() && s.Mode == "GCM" }, algorithm: true},
	"AESCCM": {openssl: func(s TLSCipherSuite) bool { return s.aes() && s.Mode == "CCM" }, algorithm: true},
	// "CHACHA20: cipher suites using ChaCha20."
	"CHACHA20": {openssl: symIs(SymChaCha20), algorithm: true},
	// "3DES: cipher suites using triple DES." / "DES: Cipher suites using DES
	// (not triple DES)." / "RC4: cipher suites using RC4."
	"3DES": {openssl: symIs(Sym3DES), algorithm: true},
	"DES":  {openssl: symIs(SymDES), algorithm: true},
	"RC4":  {openssl: symIs(SymRC4), algorithm: true},
	// "MD5, SHA1, SHA, SHA256, SHA384: cipher suites using MD5, SHA1, SHA256 or
	// SHA384" — the record MAC, so AEAD suites (whose name carries only the PRF
	// hash) do not match. A vendor could read SHA256 as "the name says SHA256",
	// so `may` covers the PRF hash too.
	"MD5":    {openssl: macIs(HashMD5), algorithm: true},
	"SHA1":   {openssl: macIs(HashSHA1), algorithm: true, may: hashIs(HashSHA1)},
	"SHA":    {openssl: macIs(HashSHA1), algorithm: true, may: func(s TLSCipherSuite) bool { return strings.HasPrefix(s.Hash, "SHA") }},
	"SHA256": {openssl: macIs(HashSHA256), algorithm: true, may: hashIs(HashSHA256)},
	"SHA384": {openssl: macIs(HashSHA384), algorithm: true, may: hashIs(HashSHA384)},
	// Algorithms the suite table holds no suite for. Removing them cannot touch
	// a table suite; adding them selects suites the parser cannot list.
	"CAMELLIA": {openssl: noSuite, algorithm: true}, "CAMELLIA128": {openssl: noSuite, algorithm: true},
	"CAMELLIA256": {openssl: noSuite, algorithm: true}, "ARIA": {openssl: noSuite, algorithm: true},
	"ARIA128": {openssl: noSuite, algorithm: true}, "ARIA256": {openssl: noSuite, algorithm: true},
	"ARIAGCM": {openssl: noSuite, algorithm: true}, "SEED": {openssl: noSuite, algorithm: true},
	"IDEA": {openssl: noSuite, algorithm: true}, "RC2": {openssl: noSuite, algorithm: true},
	"AESCCM8": {openssl: noSuite, algorithm: true}, "PSK": {openssl: noSuite, algorithm: true},
	"kPSK": {openssl: noSuite, algorithm: true}, "aPSK": {openssl: noSuite, algorithm: true},
	"SRP": {openssl: noSuite, algorithm: true}, "kSRP": {openssl: noSuite, algorithm: true},
	"aSRP": {openssl: noSuite, algorithm: true},
	// 1.0.2: "EXP, EXPORT: export encryption algorithms. Including 40 and 56
	// bits algorithms." Export suites are separate registrations (EXP-RC4-MD5,
	// EXP1024-DES-CBC-SHA, …) and none is in the table. A vendor that meant
	// "weak DES/RC4" by it could reach further, hence `may`.
	"EXP":      {openssl: noSuite, algorithm: true, may: symIs(SymDES, SymRC4)},
	"EXPORT":   {openssl: noSuite, algorithm: true, may: symIs(SymDES, SymRC4)},
	"EXPORT40": {openssl: noSuite, algorithm: true, may: symIs(SymDES, SymRC4)},
	"EXPORT56": {openssl: noSuite, algorithm: true, may: symIs(SymDES, SymRC4)},

	// --- keywords naming a class of suites (vendor-defined outside OpenSSL) --
	// "kRSA, RSA: Cipher suites using RSA key exchange." A vendor's "RSA" might
	// mean RSA authentication instead, so `may` covers both.
	"kRSA": {openssl: func(s TLSCipherSuite) bool { return s.KeyExchange == KexRSA }},
	"RSA": {openssl: func(s TLSCipherSuite) bool { return s.KeyExchange == KexRSA },
		may: func(s TLSCipherSuite) bool { return s.KeyExchange == KexRSA || s.Authentication == SigRSA }},
	// "aRSA: Cipher suites using RSA authentication."
	"aRSA": {openssl: authIs(SigRSA)},
	// "kDHE, kEDH, DH: Cipher suites using ephemeral DH key agreement, including
	// anonymous cipher suites."
	"kDHE": {openssl: TLSCipherSuite.dhFamily}, "kEDH": {openssl: TLSCipherSuite.dhFamily},
	"DH": {openssl: TLSCipherSuite.dhFamily},
	// "DHE, EDH: Cipher suites using authenticated ephemeral DH key agreement."
	"DHE": {openssl: func(s TLSCipherSuite) bool { return s.dhFamily() && !s.anonymous() }, may: TLSCipherSuite.dhFamily},
	"EDH": {openssl: func(s TLSCipherSuite) bool { return s.dhFamily() && !s.anonymous() }, may: TLSCipherSuite.dhFamily},
	// "ADH: Anonymous DH cipher suites, note that this does not include
	// anonymous Elliptic Curve DH (ECDH) cipher suites."
	"ADH": {openssl: func(s TLSCipherSuite) bool { return s.dhFamily() && s.anonymous() }},
	// "kEECDH, kECDHE, ECDH: Cipher suites using ephemeral ECDH key agreement,
	// including anonymous cipher suites."
	"kEECDH": {openssl: TLSCipherSuite.ecdhFamily}, "kECDHE": {openssl: TLSCipherSuite.ecdhFamily},
	"ECDH": {openssl: TLSCipherSuite.ecdhFamily},
	// "ECDHE, EECDH: Cipher suites using authenticated ephemeral ECDH key
	// agreement."
	"ECDHE": {openssl: func(s TLSCipherSuite) bool { return s.ecdhFamily() && !s.anonymous() }, may: TLSCipherSuite.ecdhFamily},
	"EECDH": {openssl: func(s TLSCipherSuite) bool { return s.ecdhFamily() && !s.anonymous() }, may: TLSCipherSuite.ecdhFamily},
	// "AECDH: Anonymous Elliptic Curve Diffie-Hellman cipher suites."
	"AECDH": {openssl: func(s TLSCipherSuite) bool { return s.ecdhFamily() && s.anonymous() }},
	// "aDSS, DSS: Cipher suites using DSS authentication."
	"aDSS": {openssl: authIs(SigDSA)}, "DSS": {openssl: authIs(SigDSA)},
	// "aECDSA, ECDSA: Cipher suites using ECDSA authentication."
	"aECDSA": {openssl: authIs(SigECDSA)}, "ECDSA": {openssl: authIs(SigECDSA)},

	// --- version-dependent: never expanded ---------------------------------
	// DEFAULT, ALL, COMPLEMENTOF*, HIGH and the FIPS/Suite B lists have changed
	// membership across OpenSSL releases (and vendors define their own), so any
	// suite could be in them.
	"DEFAULT": {}, "ALL": {}, "COMPLEMENTOFDEFAULT": {}, "COMPLEMENTOFALL": {},
	"HIGH": {}, "FIPS": {}, "SUITEB128": {}, "SUITEB128ONLY": {}, "SUITEB192": {},
	// LOW and MEDIUM moved suites between releases (3DES went HIGH→MEDIUM in
	// 1.1.0; LOW emptied when single DES was removed), but no release has ever
	// classed an AES or ChaCha20 suite below HIGH.
	"LOW":    {may: not(TLSCipherSuite.modernSymmetric)},
	"MEDIUM": {may: not(TLSCipherSuite.modernSymmetric)},
	// "TLSv1.2, TLSv1.0, SSLv3: Lists cipher suites which are only supported in
	// at least TLS v1.2, TLS v1.0 or SSL v3.0 respectively." Vendors also use
	// these to mean the protocol itself; under either reading an SSLv3/TLSv1.0
	// keyword cannot reach a suite that only exists at TLS 1.2.
	"SSLv3":   {may: not(TLSCipherSuite.tls12Only)},
	"TLSv1":   {may: not(TLSCipherSuite.tls12Only)},
	"TLSv1.0": {may: not(TLSCipherSuite.tls12Only)},
	"TLSv1_0": {may: not(TLSCipherSuite.tls12Only)},
}

// cipherKeywordsFolded is the case-insensitive fallback index. Two keyword
// pairs differ only by case in OpenSSL 1.0.2 — "ADH"/"aDH" and "AECDH"/"aECDH"
// (fixed-DH authentication, a different set) — so those spellings resolve only
// when written exactly.
var cipherKeywordsFolded = func() map[string]string {
	ambiguous := map[string]bool{"ADH": true, "AECDH": true}
	out := make(map[string]string, len(cipherKeywords))
	for k := range cipherKeywords {
		u := strings.ToUpper(k)
		if ambiguous[u] {
			continue
		}
		out[u] = k
	}
	return out
}()

func lookupCipherKeyword(token string) (cipherKeyword, bool) {
	if kw, ok := cipherKeywords[token]; ok {
		return kw, true
	}
	if canon, ok := cipherKeywordsFolded[strings.ToUpper(token)]; ok {
		return cipherKeywords[canon], true
	}
	return cipherKeyword{}, false
}

// tokenMeaning is what one (possibly AND-combined) token means in a dialect.
type tokenMeaning struct {
	// definite selects the suites the token certainly means; nil when the
	// token's expansion is not known.
	definite suitePredicate
	// may is the broadest set the token could mean.
	may suitePredicate
	// addable is whether an ADDITION of the token can be expanded: always for
	// an explicit suite name, and for keywords only in OpenSSL's own dialect.
	// A vendor keyword addition means "whatever suites this software version
	// implements that match", which the string cannot enumerate — expanding
	// "AES" against the table would, for one, claim the anonymous ADH-AES
	// suites a BIG-IP may not even implement.
	addable bool
}

func (d CipherStringDialect) meaning(body string) tokenMeaning {
	if s, ok := LookupTLSCipherSuite(body); ok {
		name := s.OpenSSLName
		p := func(t TLSCipherSuite) bool { return t.OpenSSLName == name }
		return tokenMeaning{definite: p, may: p, addable: true}
	}
	parts := strings.Split(body, "+")
	var defs, mays []suitePredicate
	allDefinite, allAddable := true, true
	for _, part := range parts {
		m := d.meaningOfKeyword(part)
		if m.definite == nil {
			allDefinite = false
		} else {
			defs = append(defs, m.definite)
		}
		allAddable = allAddable && m.addable
		mays = append(mays, m.may)
	}
	out := tokenMeaning{may: and(mays)}
	if allDefinite {
		out.definite = and(defs)
		out.addable = allAddable
	}
	return out
}

func (d CipherStringDialect) meaningOfKeyword(part string) tokenMeaning {
	if s, ok := LookupTLSCipherSuite(part); ok {
		name := s.OpenSSLName
		p := func(t TLSCipherSuite) bool { return t.OpenSSLName == name }
		return tokenMeaning{definite: p, may: p, addable: true}
	}
	kw, ok := lookupCipherKeyword(part)
	if !ok {
		// A vendor keyword, a cipher-group name, or a suite outside the table:
		// it could mean anything.
		return tokenMeaning{may: anySuite}
	}
	var m tokenMeaning
	if kw.openssl != nil && (d == CipherStringOpenSSL || kw.algorithm) {
		m.definite = kw.openssl
		m.addable = d == CipherStringOpenSSL
	}
	switch {
	case kw.may != nil && kw.openssl != nil:
		// The broadest reading is the union of the definition and the bound.
		def, bound := kw.openssl, kw.may
		m.may = func(s TLSCipherSuite) bool { return def(s) || bound(s) }
	case kw.may != nil:
		m.may = kw.may
	case kw.openssl != nil:
		m.may = kw.openssl
	default:
		m.may = anySuite
	}
	if d == CipherStringOpenSSL && m.definite != nil {
		// In OpenSSL's own dialect the definition is exact.
		m.may = m.definite
	}
	return m
}

func and(ps []suitePredicate) suitePredicate {
	return func(s TLSCipherSuite) bool {
		for _, p := range ps {
			if !p(s) {
				return false
			}
		}
		return true
	}
}

// suiteState tracks one table suite through evaluation.
type suiteState struct {
	present     bool
	uncertain   bool // present, but possibly removed
	banned      bool // definitely `!`-removed: can never come back
	maybeBanned bool // possibly `!`-removed: coming back is uncertain
}

// cipherStringSeparators are ciphers(1)'s list separators.
func isCipherStringSeparator(r rune) bool {
	return r == ':' || r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
}

// ParseCipherString evaluates an OpenSSL-style cipher string.
func ParseCipherString(raw string, dialect CipherStringDialect) *CipherStringResult {
	res := &CipherStringResult{Raw: raw, Dialect: dialect}
	cleaned := strings.Trim(strings.TrimSpace(raw), `"'`)

	states := make([]suiteState, len(cipherStringSuites))
	var order []int // indices of present suites, in list order
	added := false
	additionUnresolved := false
	filtered := false // an @-directive may filter the final list

	// possible are the unresolved additions that may still expose a weak
	// algorithm; removals is every removal, so exact exclusions can retire them.
	type possibleAddition struct {
		at   int
		name string
	}
	type removal struct {
		at   int
		op   byte
		body string
		m    tokenMeaning
	}
	var possible []possibleAddition
	var removals []removal

	remove := func(idx int) {
		states[idx].present = false
		states[idx].uncertain = false
		for i, o := range order {
			if o == idx {
				order = append(order[:i], order[i+1:]...)
				return
			}
		}
	}

	for at, tok := range strings.FieldsFunc(cleaned, isCipherStringSeparator) {
		op := byte(0)
		body := tok
		if tok[0] == '!' || tok[0] == '-' || tok[0] == '+' {
			op, body = tok[0], tok[1:]
		}
		if body == "" {
			continue
		}

		if strings.HasPrefix(body, "@") {
			if res.applyDirective(tok, body, &order) {
				filtered = true
			}
			continue
		}

		m := dialect.meaning(body)

		switch op {
		case 0: // append
			added = true
			if m.definite == nil || !m.addable {
				additionUnresolved = true
				res.Unexpanded = append(res.Unexpanded, tok)
				for _, name := range possiblyExposed(body) {
					possible = append(possible, possibleAddition{at, name})
				}
				continue
			}
			selected := 0
			for i, s := range cipherStringSuites {
				if !m.definite(s) {
					continue
				}
				selected++
				st := &states[i]
				switch {
				case st.banned:
					// "!" deletions are permanent.
				case st.maybeBanned:
					if !st.present {
						st.present = true
						order = append(order, i)
					}
					st.uncertain = true
				case !st.present:
					st.present = true
					order = append(order, i)
				default:
					// Already present: OpenSSL does not move it. If it was only
					// possibly removed by a "-", naming it again settles it.
					st.uncertain = false
				}
			}
			if selected == 0 {
				// The token selects only suites the table does not list.
				additionUnresolved = true
				res.Unexpanded = append(res.Unexpanded, tok)
				for _, name := range possiblyExposed(body) {
					possible = append(possible, possibleAddition{at, name})
				}
			}

		case '!', '-':
			res.Excluded = append(res.Excluded, body)
			removals = append(removals, removal{at, op, body, m})
			if m.definite == nil {
				res.Unexpanded = append(res.Unexpanded, tok)
			}
			for i, s := range cipherStringSuites {
				definite := m.definite != nil && m.definite(s)
				maybe := !definite && m.may(s)
				st := &states[i]
				switch {
				case definite:
					if st.present {
						remove(i)
					}
					if op == '!' {
						st.banned = true
					}
				case maybe:
					if st.present {
						st.uncertain = true
					}
					if op == '!' {
						st.maybeBanned = true
					}
				}
			}

		case '+': // move to end; adds nothing
			if m.definite == nil {
				// Only the ORDER is in doubt; membership is unchanged.
				res.Unexpanded = append(res.Unexpanded, tok)
				continue
			}
			var keep, moved []int
			for _, idx := range order {
				if m.definite(cipherStringSuites[idx]) {
					moved = append(moved, idx)
				} else {
					keep = append(keep, idx)
				}
			}
			order = append(keep, moved...)
		}
	}

	for _, idx := range order {
		if filtered || states[idx].uncertain {
			res.Uncertain = append(res.Uncertain, cipherStringSuites[idx])
		} else {
			res.Enabled = append(res.Enabled, cipherStringSuites[idx])
		}
	}
	for _, s := range res.Uncertain {
		res.PossiblyEnabled = append(res.PossiblyEnabled, s.IANAName)
	}
	for _, p := range possible {
		retired := false
		for _, r := range removals {
			// "!" is permanent wherever it stands; "-" only removes what came
			// before it (a later addition brings the cipher back).
			if r.op == '-' && r.at < p.at {
				continue
			}
			if exclusionCovers(r.body, r.m, p.name) {
				retired = true
				break
			}
		}
		if !retired {
			res.PossiblyEnabled = append(res.PossiblyEnabled, p.name)
		}
	}
	// A string that adds nothing selects nothing in OpenSSL
	// (SSL_CTX_set_cipher_list fails with "no cipher match"), so a device that
	// accepted one is applying it on top of a list it got from elsewhere —
	// profile inheritance or a built-in default. Not complete.
	res.Complete = added && !additionUnresolved && len(res.Uncertain) == 0
	return res
}

// applyDirective handles the "@" commands. It reports whether the directive
// may FILTER the list — which it does to the final list, wherever it appears.
func (r *CipherStringResult) applyDirective(tok, body string, order *[]int) bool {
	switch {
	case strings.EqualFold(body, "@STRENGTH"):
		// "@STRENGTH: the current cipher list is sorted in order of encryption
		// algorithm key length." Stable, like OpenSSL's.
		sort.SliceStable(*order, func(a, b int) bool {
			return cipherStringSuites[(*order)[a]].StrengthBits > cipherStringSuites[(*order)[b]].StrengthBits
		})
		return false
	case len(body) > len("@SECLEVEL=") && strings.EqualFold(body[:len("@SECLEVEL=")], "@SECLEVEL="):
		if level, err := strconv.Atoi(body[len("@SECLEVEL="):]); err == nil && level == 0 {
			// Level 0 permits everything (SSL_CTX_set_security_level(3)).
			return false
		}
		// Levels 1-5 prohibit suites by rules that depend on the library version
		// and the key sizes in use, so any enabled suite may be filtered out.
		r.Unexpanded = append(r.Unexpanded, tok)
		return true
	default:
		// An unknown directive: it could filter as well as order.
		r.Unexpanded = append(r.Unexpanded, tok)
		return true
	}
}

// possiblyExposed returns what an unresolved addition may expose, for risk:
// each part that is an algorithm keyword (or LOW, whose every historical
// membership is weak ciphers), and the token itself when it is one explicit
// suite name the table does not list. Class keywords (ECDHE, RSA), version
// keywords (DEFAULT, HIGH, ALL) and cipher groups name no algorithm and yield
// nothing — their unknown content is what makes the result incomplete.
func possiblyExposed(body string) []string {
	parts := strings.Split(body, "+")
	var out []string
	for _, part := range parts {
		if members := weakClassMembers(part); members != nil {
			// EXP / EXPORT* / LOW name a CLASS of weak suites; what they may
			// expose is those suites, spelled so every weak-cipher rule
			// recognises them (TLS_RSA_EXPORT_WITH_RC4_40_MD5 names EXPORT,
			// RC4 and MD5; TLS_RSA_WITH_DES_CBC_SHA names single DES).
			out = append(out, members...)
			continue
		}
		kw, ok := lookupCipherKeyword(part)
		if ok && kw.algorithm {
			out = append(out, part)
		}
	}
	if len(parts) == 1 && len(out) == 0 && suiteShaped(body) {
		if _, known := lookupCipherKeyword(body); !known {
			out = append(out, body)
		}
	}
	return out
}

// suiteShaped reports whether an unknown token reads as a cipher-suite name
// (EXP-RC4-MD5, TLS_…) rather than a cipher-group path or a bare word.
func suiteShaped(token string) bool {
	return strings.ContainsAny(token, "-_") && !strings.ContainsAny(token, "/@")
}

// exclusionCovers reports whether an exclusion removes a possibly-enabled
// entry: the very same token, or an exact (definite) exclusion whose
// definition matches the components of an explicit suite name. An exclusion
// the parser could not expand retires nothing else.
func exclusionCovers(removed string, m tokenMeaning, name string) bool {
	if sameKeyword(removed, name) {
		// Excluding exactly what was added removes it, whatever it expands to.
		return true
	}
	if weakClassCovers(removed, name) {
		// "!EXP" removes the export suites "EXP" (or "EXPORT") added.
		return true
	}
	if m.definite == nil {
		return false
	}
	if c, err := ParseCipherSuite(name); err == nil && c != nil {
		pseudo := TLSCipherSuite{KeyExchange: c.KeyExchange, Authentication: c.Signature, Symmetric: c.Symmetric, Hash: c.Hash, MAC: c.Hash}
		upper := strings.ToUpper(name)
		if strings.Contains(upper, "GCM") || strings.Contains(upper, "CCM") || strings.Contains(upper, "POLY1305") {
			pseudo.MAC = "AEAD"
		}
		if pseudo.Symmetric != "" || pseudo.MAC != "" || pseudo.Authentication != "" {
			return m.definite(pseudo)
		}
	}
	return false
}

// sameKeyword reports whether two tokens name the same keyword, through the
// same case folding the parser applies.
func sameKeyword(a, b string) bool {
	if a == b {
		return true
	}
	ca, okA := canonicalKeyword(a)
	cb, okB := canonicalKeyword(b)
	return okA && okB && ca == cb
}

// canonicalKeyword folds a keyword the way the parser does, and folds
// ciphers(1)'s synonyms onto one name ("EXP, EXPORT: export encryption
// algorithms"; "DHE, EDH"; "ECDHE, EECDH"; "eNULL, NULL"; "SHA1, SHA").
func canonicalKeyword(token string) (string, bool) {
	canon, ok := cipherKeywordsFolded[strings.ToUpper(token)]
	if !ok {
		if _, exact := cipherKeywords[token]; !exact {
			return "", false
		}
		canon = token
	}
	switch canon {
	case "EXPORT":
		return "EXP", true
	case "EDH":
		return "DHE", true
	case "EECDH":
		return "ECDHE", true
	case "eNULL":
		return "NULL", true
	case "SHA":
		return "SHA1", true
	}
	return canon, true
}

// The members of the weak suite CLASSES a cipher string can add by keyword.
// ciphers(1) (OpenSSL 1.0.2, the last release that shipped them) defines:
//
//	"EXP, EXPORT: export encryption algorithms. Including 40 and 56 bits
//	algorithms." / "EXPORT40: 40-bit export encryption algorithms" /
//	"EXPORT56: 56-bit export encryption algorithms."
//	"LOW: Low strength encryption cipher suites, currently those using 64 or
//	56 bit encryption algorithms but excluding export cipher suites."
//
// and lists the suites by name in its "CIPHER SUITE NAMES" section (TLS v1.0
// cipher suites; "Additional Export 1024 and other cipher suites"). They are
// the IANA names of those suites. They are not in the resolution table: they
// are only ever reported as what a keyword MAY expose, never as enabled.
var (
	export40Suites = []string{
		"TLS_RSA_EXPORT_WITH_RC4_40_MD5",        // EXP-RC4-MD5
		"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",    // EXP-RC2-CBC-MD5
		"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",     // EXP-DES-CBC-SHA
		"TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", // EXP-EDH-DSS-DES-CBC-SHA
		"TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", // EXP-EDH-RSA-DES-CBC-SHA
		"TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",    // EXP-ADH-RC4-MD5
		"TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", // EXP-ADH-DES-CBC-SHA
	}
	export56Suites = []string{
		"TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",     // EXP1024-DES-CBC-SHA
		"TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",      // EXP1024-RC4-SHA
		"TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA", // EXP1024-DHE-DSS-DES-CBC-SHA
		"TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA",  // EXP1024-DHE-DSS-RC4-SHA
	}
	lowSuites = []string{
		"TLS_RSA_WITH_DES_CBC_SHA",     // DES-CBC-SHA
		"TLS_DHE_DSS_WITH_DES_CBC_SHA", // EDH-DSS-DES-CBC-SHA
		"TLS_DHE_RSA_WITH_DES_CBC_SHA", // EDH-RSA-DES-CBC-SHA
		"TLS_DH_anon_WITH_DES_CBC_SHA", // ADH-DES-CBC-SHA
	}
)

// weakClassMembers returns the suites a weak-class keyword names, or nil.
func weakClassMembers(token string) []string {
	canon, ok := canonicalKeyword(token)
	if !ok {
		return nil
	}
	switch canon {
	case "EXP":
		return append(append([]string{}, export40Suites...), export56Suites...)
	case "EXPORT40":
		return append([]string{}, export40Suites...)
	case "EXPORT56":
		return append([]string{}, export56Suites...)
	case "LOW":
		return append([]string{}, lowSuites...)
	}
	return nil
}

// weakClassCovers reports whether excluding a weak-class keyword removes a
// suite of that class.
func weakClassCovers(removed, name string) bool {
	for _, member := range weakClassMembers(removed) {
		if member == name {
			return true
		}
	}
	return false
}

// cipherStringBareKeywords are values that are a cipher string on their own
// even without an operator: a stored "DEFAULT" is a keyword, not a suite name.
var cipherStringBareKeywords = map[string]bool{
	"DEFAULT": true, "ALL": true, "HIGH": true, "MEDIUM": true, "LOW": true,
	"COMPLEMENTOFDEFAULT": true, "COMPLEMENTOFALL": true, "FIPS": true,
	// F5 BIG-IP's cipher-stack keywords.
	"NATIVE": true, "COMPAT": true,
}

// LooksLikeCipherString reports whether a stored cipher value is a cipher
// STRING rather than a single suite name: it contains list separators or
// operators, or is a bare list keyword.
//
// Whitespace alone does not qualify — FortiOS IPsec proposals are
// space-separated ("aes256-sha256 aes128-sha1") and are not cipher strings.
func LooksLikeCipherString(value string) bool {
	v := strings.Trim(strings.TrimSpace(value), `"'`)
	if v == "" {
		return false
	}
	if strings.ContainsAny(v, ":!+,") || v[0] == '-' {
		return true
	}
	// A bare keyword is a cipher string: "LOW", "EXP", "RSA", "HIGH" name a
	// set of suites, not one. The one exception is a keyword that names a
	// single algorithm (RC4, 3DES, AES256, MD5, …): the same spelling is a
	// catalogue component code that non-TLS producers store as a cipher
	// (Cisco's IPsec transform "3DES"), and read as a name it already means
	// exactly that algorithm to every rule. EXP/EXPORT* are algorithm
	// keywords that name a CLASS, so they are strings.
	if kw, ok := lookupCipherKeyword(v); ok && (!kw.algorithm || weakClassMembers(v) != nil) {
		return true
	}
	// "@" is a cipher-string marker only as a directive token — an SSH
	// algorithm name such as chacha20-poly1305@openssh.com carries one too.
	for _, tok := range strings.FieldsFunc(v, isCipherStringSeparator) {
		u := strings.ToUpper(tok)
		if u == "@STRENGTH" || strings.HasPrefix(u, "@SECLEVEL=") {
			return true
		}
	}
	return cipherStringBareKeywords[strings.ToUpper(v)]
}

// SuitesPossiblyInUse returns what a stored cipher value may expose, for RISK.
//
// For a single suite name it is that name, unchanged, so every existing
// substring rule keeps working on it. For a cipher string it is the IANA names
// of the suites the string definitely enables, plus everything it may enable
// and could not be resolved either way (CipherStringResult.PossiblyEnabled).
// IANA rather than OpenSSL names because they are the catalogue's cipher_suite
// codes and because they spell out what the OpenSSL abbreviations hide
// ("ADH-AES128-SHA" is TLS_DH_anon_…). Every rule that asks "is a weak
// algorithm exposed here" uses this, so an unresolved cipher string never
// reads as a safe one; an excluded token is never returned. The origin of a
// stored string is unknown, so the conservative vendor dialect applies.
func SuitesPossiblyInUse(value string) []string {
	v := strings.TrimSpace(value)
	if v == "" {
		return nil
	}
	if !LooksLikeCipherString(v) {
		return []string{v}
	}
	r := ParseCipherString(v, CipherStringVendor)
	out := make([]string, 0, len(r.Enabled)+len(r.PossiblyEnabled))
	for _, s := range r.Enabled {
		out = append(out, s.IANAName)
	}
	return append(out, r.PossiblyEnabled...)
}

// CipherStringAssessment says whether a stored cipher value was fully resolved.
// Partial is true for a cipher string whose enabled set could not be fully
// determined (CipherStringResult.Complete is false); Unexpanded names why. A
// single suite name, or no value, is not partial.
func CipherStringAssessment(value string) (partial bool, unexpanded []string) {
	v := strings.TrimSpace(value)
	if v == "" || !LooksLikeCipherString(v) {
		return false, nil
	}
	r := ParseCipherString(v, CipherStringVendor)
	if r.Complete {
		return false, nil
	}
	unexpanded = append([]string{}, r.Unexpanded...)
	if len(unexpanded) == 0 && len(r.Uncertain) == 0 {
		// Only exclusions: the base list comes from elsewhere.
		unexpanded = []string{"(no additions: base list set elsewhere)"}
	}
	return true, unexpanded
}
