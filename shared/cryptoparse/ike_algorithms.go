package cryptoparse

import (
	"strings"
)

// IKE and IPsec encryption and integrity transforms (DCIM row 4.3).
//
// A tunnel's IKE and IPsec proposals are stored NetBox-shaped: the algorithm
// in NetBox's own spelling (vpn.choices EncryptionAlgorithmChoices /
// AuthenticationAlgorithmChoices — "aes-256-cbc", "hmac-sha256") AND as a
// foreign key into the `algorithms` catalogue, so the catalogue scores the
// tunnel exactly as it scores TLS and SSH. Collectors report the same
// transforms in a dozen spellings (FortiOS "aes256-sha256" pairs, Cisco
// "esp-aes 256", strongSwan "aes256gcm16", Palo Alto "aes-256-cbc"), so this
// file is the one place that turns a spelling into (NetBox name, catalogue
// code).
//
// Like ike_groups.go, it holds NO opinion about strength: that is the
// catalogue row's. A spelling it does not recognise passes through with no
// code — stored, unlinked, and therefore unassessed, never a guess.

// ikeEncryption maps a folded spelling (lower-case, separators removed) to
// NetBox's choice.
var ikeEncryption = map[string]string{
	"aes128": "aes-128-cbc", "aes128cbc": "aes-128-cbc", "aescbc128": "aes-128-cbc", "espaes128": "aes-128-cbc", "aes": "aes-128-cbc", "espaes": "aes-128-cbc",
	"aes192": "aes-192-cbc", "aes192cbc": "aes-192-cbc", "aescbc192": "aes-192-cbc", "espaes192": "aes-192-cbc",
	"aes256": "aes-256-cbc", "aes256cbc": "aes-256-cbc", "aescbc256": "aes-256-cbc", "espaes256": "aes-256-cbc",
	"aes128gcm": "aes-128-gcm", "aes128gcm16": "aes-128-gcm", "aesgcm128": "aes-128-gcm", "espgcm128": "aes-128-gcm", "espaesgcm128": "aes-128-gcm", "aes128gcm128": "aes-128-gcm",
	"aes192gcm": "aes-192-gcm", "aes192gcm16": "aes-192-gcm", "aesgcm192": "aes-192-gcm", "espgcm192": "aes-192-gcm",
	"aes256gcm": "aes-256-gcm", "aes256gcm16": "aes-256-gcm", "aesgcm256": "aes-256-gcm", "espgcm256": "aes-256-gcm", "espaesgcm256": "aes-256-gcm", "aes256gcm128": "aes-256-gcm", "espgcm": "aes-128-gcm",
	"3des": "3des-cbc", "3descbc": "3des-cbc", "esp3des": "3des-cbc", "tripledes": "3des-cbc", "des3": "3des-cbc",
	"des": "des-cbc", "descbc": "des-cbc", "espdes": "des-cbc",
	"chacha20poly1305": "chacha20poly1305", "chacha20": "chacha20poly1305",
	"null": "null", "espnull": "null",
}

// ikeEncryptionCode is the catalogue row each NetBox encryption choice is
// assessed under.
var ikeEncryptionCode = map[string]string{
	"aes-128-cbc":      "ENCR-AES-CBC-128",
	"aes-192-cbc":      "ENCR-AES-CBC-192",
	"aes-256-cbc":      "ENCR-AES-CBC-256",
	"aes-128-gcm":      "ENCR-AES-GCM-128",
	"aes-192-gcm":      "ENCR-AES-GCM-192",
	"aes-256-gcm":      "ENCR-AES-GCM-256",
	"3des-cbc":         "ENCR-3DES",
	"des-cbc":          "ENCR-DES",
	"chacha20poly1305": "ENCR-CHACHA20-POLY1305-IPSEC",
	"null":             "NULL",
}

// ikeIntegrity maps a folded spelling to NetBox's authentication choice.
var ikeIntegrity = map[string]string{
	"sha1": "hmac-sha1", "sha": "hmac-sha1", "hmacsha1": "hmac-sha1", "espshahmac": "hmac-sha1", "espsha1hmac": "hmac-sha1", "hmacsha196": "hmac-sha1", "sha196": "hmac-sha1", "prfsha1": "hmac-sha1",
	"sha256": "hmac-sha256", "sha2256": "hmac-sha256", "hmacsha256": "hmac-sha256", "espsha256hmac": "hmac-sha256", "sha256128": "hmac-sha256", "hmacsha2256128": "hmac-sha256", "prfsha256": "hmac-sha256",
	"sha384": "hmac-sha384", "sha2384": "hmac-sha384", "hmacsha384": "hmac-sha384", "espsha384hmac": "hmac-sha384", "sha384192": "hmac-sha384", "prfsha384": "hmac-sha384",
	"sha512": "hmac-sha512", "sha2512": "hmac-sha512", "hmacsha512": "hmac-sha512", "espsha512hmac": "hmac-sha512", "sha512256": "hmac-sha512", "prfsha512": "hmac-sha512",
	"md5": "hmac-md5", "hmacmd5": "hmac-md5", "espmd5hmac": "hmac-md5", "hmacmd596": "hmac-md5", "md596": "hmac-md5", "prfmd5": "hmac-md5",
}

var ikeIntegrityCode = map[string]string{
	"hmac-sha1":   "AUTH-HMAC-SHA1-96",
	"hmac-sha256": "AUTH-HMAC-SHA2-256-128",
	"hmac-sha384": "AUTH-HMAC-SHA2-384-192",
	"hmac-sha512": "AUTH-HMAC-SHA2-512-256",
	"hmac-md5":    "AUTH-HMAC-MD5-96",
}

func foldIKEToken(s string) string {
	return strings.NewReplacer("-", "", "_", "", " ", "", ".", "", "/", "").Replace(strings.ToLower(strings.TrimSpace(s)))
}

// CanonicalIKEEncryption returns NetBox's spelling of an encryption transform
// and the catalogue code it is assessed under. An unrecognised spelling comes
// back trimmed and lower-cased with no code.
func CanonicalIKEEncryption(raw string) (name, code string) {
	t := strings.ToLower(strings.TrimSpace(raw))
	if t == "" {
		return "", ""
	}
	if n, ok := ikeEncryption[foldIKEToken(t)]; ok {
		return n, ikeEncryptionCode[n]
	}
	if c, ok := ikeEncryptionCode[t]; ok {
		return t, c
	}
	return t, ""
}

// CanonicalIKEIntegrity returns NetBox's spelling of an integrity
// (authentication) transform and its catalogue code. Unrecognised → no code.
func CanonicalIKEIntegrity(raw string) (name, code string) {
	t := strings.ToLower(strings.TrimSpace(raw))
	if t == "" {
		return "", ""
	}
	if n, ok := ikeIntegrity[foldIKEToken(t)]; ok {
		return n, ikeIntegrityCode[n]
	}
	if c, ok := ikeIntegrityCode[t]; ok {
		return t, c
	}
	return t, ""
}

// IKEEncryptionIsAEAD reports whether a NetBox encryption choice carries its
// own integrity, so a proposal needs no separate authentication transform.
func IKEEncryptionIsAEAD(name string) bool {
	return strings.HasSuffix(name, "-gcm") || name == "chacha20poly1305"
}

// IKEGroupCode is the catalogue code of an IANA key-exchange transform ID, or
// "" when the group is unassigned or has no catalogue row.
func IKEGroupCode(id int) string {
	if g, ok := ikeKeyExchangeMethods[id]; ok {
		return g.Code
	}
	return ""
}

// IKETransformPair is one encryption + integrity pair a vendor lists as a
// single token ("aes256-sha256", "aes128gcm-prfsha256", "3des-md5").
type IKETransformPair struct {
	Encryption, Integrity string // NetBox spellings; Integrity "" for an AEAD
}

// ParseIKETransformPairs reads a FortiOS-style proposal list — space-separated
// tokens, each an encryption and an integrity joined by '-' — in the vendor's
// preference order, without duplicates. A token whose encryption is not
// recognised is skipped, never guessed. A trailing "prfXXX" on an AEAD token
// names the PRF, not an integrity transform, and is dropped.
func ParseIKETransformPairs(s string) []IKETransformPair {
	var out []IKETransformPair
	seen := map[IKETransformPair]bool{}
	for _, tok := range strings.Fields(strings.ToLower(s)) {
		// A whole token that is one encryption ("aes-256-cbc", NetBox's own
		// spelling) is not a pair.
		encName, encCode := CanonicalIKEEncryption(tok)
		integ := ""
		if encCode == "" {
			var enc string
			enc, integ, _ = strings.Cut(tok, "-")
			if encName, encCode = CanonicalIKEEncryption(enc); encCode == "" {
				continue
			}
		}
		p := IKETransformPair{Encryption: encName}
		if !IKEEncryptionIsAEAD(encName) || !strings.HasPrefix(integ, "prf") {
			if n, _ := CanonicalIKEIntegrity(integ); n != "" {
				p.Integrity = n
			}
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
