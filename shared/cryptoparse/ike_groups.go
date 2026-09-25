package cryptoparse

import (
	"regexp"
	"strconv"
	"strings"
)

// IKE Diffie-Hellman groups ("Key Exchange Methods", IKEv2 Transform Type 4).
//
// Every VPN collector reports the DH group of an IPsec tunnel, and every one
// reports it differently: UniFi a bare number, FortiOS a space-separated
// preference list ("14 5"), Cisco "Group 19" or "group14", Linux gateways a
// strongSwan name ("modp2048"). None of those spellings is an `algorithms`
// code, so the group was kept only in metadata, never linked, and the tunnel's
// key exchange — its one Shor-breakable component — was invisible to scoring
// and to PQC readiness. A VPN linking nothing but AES and SHA-2 was counted as
// quantum-safe.
//
// This file turns a vendor spelling into the IANA group and the catalogue code
// the group is assessed under. It holds NO opinion about how strong a group is:
// strength, deprecation and risk live on the catalogue row, where a reviewer
// can read and correct them (CLAUDE.md, "Crypto Assessment Source of Truth").
// The table only says which row a group is.

// IKEGroup is one IKEv2 Key Exchange Method.
type IKEGroup struct {
	// ID is the IANA Transform Type 4 Transform ID.
	ID int
	// Name is the registry's own description of the group.
	Name string
	// Code is the algorithms.code the group is assessed under. Empty when the
	// catalogue has no row for it — the group is then left unlinked, which the
	// product reads as "not assessed", rather than being pinned to a guess.
	Code string
	// Bits is the size of the group's key: the modulus for a MODP group, the
	// field size for an elliptic curve. It is what key_size means next to a
	// key exchange everywhere in the platform (the SP 800-131A size floors are
	// applied per key family). Zero for ML-KEM, whose sizes are comparable to
	// neither floor.
	Bits int
}

// ikeKeyExchangeMethods is the IANA registry "Internet Key Exchange Version 2
// (IKEv2) Parameters", table "Transform Type 4 - Key Exchange Method Transform
// IDs" (https://www.iana.org/assignments/ikev2-parameters), as published on
//. Every assigned ID is listed, including those with no catalogue
// row, so an assigned group is never mistaken for garbage.
//
// References per group: 1-2 RFC 7296/2409; 5, 14-18 RFC 3526; 19-21 RFC 5903;
// 22-26 RFC 5114; 27-30 RFC 6954; 31-32 RFC 8031; 33-34 RFC 9385; 35-37
// draft-ietf-ipsecme-ikev2-mlkem (RFC 9370 carries them as additional key
// exchanges). RFC 7919's ffdhe groups are TLS named groups and have NO IKEv2
// transform ID, so they are deliberately absent.
var ikeKeyExchangeMethods = map[int]IKEGroup{
	1:  {ID: 1, Name: "768-bit MODP Group", Code: "DH-768", Bits: 768},
	2:  {ID: 2, Name: "1024-bit MODP Group", Code: "DH-1024", Bits: 1024},
	5:  {ID: 5, Name: "1536-bit MODP Group", Code: "DH-MODP-1536", Bits: 1536},
	14: {ID: 14, Name: "2048-bit MODP Group", Code: "DH-MODP-2048", Bits: 2048},
	15: {ID: 15, Name: "3072-bit MODP Group", Code: "DH-MODP-3072", Bits: 3072},
	16: {ID: 16, Name: "4096-bit MODP Group", Code: "DH-MODP-4096", Bits: 4096},
	17: {ID: 17, Name: "6144-bit MODP Group", Code: "DH-MODP-6144", Bits: 6144},
	18: {ID: 18, Name: "8192-bit MODP Group", Code: "DH-MODP-8192", Bits: 8192},
	19: {ID: 19, Name: "256-bit random ECP group", Code: "DH-ECP-256", Bits: 256},
	20: {ID: 20, Name: "384-bit random ECP group", Code: "DH-ECP-384", Bits: 384},
	21: {ID: 21, Name: "521-bit random ECP group", Code: "DH-ECP-521", Bits: 521},
	22: {ID: 22, Name: "1024-bit MODP Group with 160-bit Prime Order Subgroup", Code: "DH-RFC5114-1024-160", Bits: 1024},
	23: {ID: 23, Name: "2048-bit MODP Group with 224-bit Prime Order Subgroup", Code: "DH-RFC5114-2048-224", Bits: 2048},
	24: {ID: 24, Name: "2048-bit MODP Group with 256-bit Prime Order Subgroup", Code: "DH-RFC5114-2048-256", Bits: 2048},
	25: {ID: 25, Name: "192-bit Random ECP Group", Code: "DH-ECP-192", Bits: 192},
	26: {ID: 26, Name: "224-bit Random ECP Group", Code: "DH-ECP-224", Bits: 224},
	27: {ID: 27, Name: "brainpoolP224r1", Code: "ECDH-BRAINPOOLP224R1", Bits: 224},
	28: {ID: 28, Name: "brainpoolP256r1", Code: "ECDH-BRAINPOOLP256R1", Bits: 256},
	29: {ID: 29, Name: "brainpoolP384r1", Code: "ECDH-BRAINPOOLP384R1", Bits: 384},
	30: {ID: 30, Name: "brainpoolP512r1", Code: "ECDH-BRAINPOOLP512R1", Bits: 512},
	31: {ID: 31, Name: "Curve25519", Code: "X25519", Bits: 256},
	32: {ID: 32, Name: "Curve448", Code: "X448", Bits: 448},
	// GOST R 34.10-2012 has no catalogue assessment. Recognised, not linked.
	33: {ID: 33, Name: "GOST3410_2012_256", Bits: 256},
	34: {ID: 34, Name: "GOST3410_2012_512", Bits: 512},
	35: {ID: 35, Name: "ml-kem-512", Code: "ML-KEM-512"},
	36: {ID: 36, Name: "ml-kem-768", Code: "ML-KEM-768"},
	37: {ID: 37, Name: "ml-kem-1024", Code: "ML-KEM-1024"},
}

// ikeGroupNames maps the named spellings (strongSwan/libreswan proposal
// keywords, curve names, the ML-KEM parameter sets) to their transform IDs.
// Keys are lower-case with '-' and '_' removed, the form tokens are folded to.
var ikeGroupNames = map[string]int{
	"modp768": 1, "modp1024": 2, "modp1536": 5,
	"modp2048": 14, "modp3072": 15, "modp4096": 16, "modp6144": 17, "modp8192": 18,
	"ecp256": 19, "ecp384": 20, "ecp521": 21,
	"modp1024s160": 22, "modp2048s224": 23, "modp2048s256": 24,
	"ecp192": 25, "ecp224": 26,
	"ecp224bp": 27, "ecp256bp": 28, "ecp384bp": 29, "ecp512bp": 30,
	"brainpoolp224r1": 27, "brainpoolp256r1": 28, "brainpoolp384r1": 29, "brainpoolp512r1": 30,
	"curve25519": 31, "x25519": 31,
	"curve448": 32, "x448": 32,
	"mlkem512": 35, "mlkem768": 36, "mlkem1024": 37,
}

// ikeGroupWordRe folds the worded forms onto one token before splitting:
// "Group 14", "DH Group 19", "DH Grp: 20" (Cisco `show crypto ikev2 sa`),
// "D-H Grp:21" all become "group14" and friends. Without it the space inside
// "Group 14" would split the word from its number.
var ikeGroupWordRe = regexp.MustCompile(`(?i)(?:\bd-?h\s*)?\b(?:group|grp)\s*[:#]?\s*(\d+)\b`)

// ikeGroupSplitRe separates the entries of a list: FortiOS uses spaces,
// others commas.
var ikeGroupSplitRe = regexp.MustCompile(`[\s,;/|]+`)

// ikeAdditionalKeyExchangeRe recognises RFC 9370 ADDITIONAL key exchanges:
// strongSwan's `ke1_`…`ke7_` proposal prefixes ("ecp256-ke1_mlkem768") and
// FortiOS's `addke1`…`addke7` settings. Those are not alternatives: every one
// of them runs, in addition to the main exchange, and the result is a hybrid.
// Read as a preference list, "ecp256-ke1_mlkem768" would become "ECP-256 or
// ML-KEM-768", which is a different — and differently classified — thing.
var ikeAdditionalKeyExchangeRe = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(?:add)?ke[1-7](?:[^a-z0-9]|$)`)

// IKEKeyExchangeMethod returns the registry entry for an assigned transform ID.
func IKEKeyExchangeMethod(id int) (IKEGroup, bool) {
	g, ok := ikeKeyExchangeMethods[id]
	return g, ok
}

// ParseIKEGroups reads a vendor's DH-group setting — one group or a list, in
// the vendor's preference order — and returns the IANA groups it names, in
// that order, without duplicates.
//
// A token that is not an assigned group is skipped, never defaulted: "0" and
// "none" are IANA's NONE (no key exchange), and an unassigned number or an
// unrecognised word names nothing we can assess. Unknown stays unknown.
func ParseIKEGroups(s string) []IKEGroup {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	// An RFC 9370 additional-key-exchange setting is not a list of
	// alternatives, and this function only reads alternatives. It answers
	// nothing rather than half an answer. No collector reads additional key
	// exchanges today; when one does, they go under a key of their own.
	if ikeAdditionalKeyExchangeRe.MatchString(s) {
		return nil
	}
	s = ikeGroupWordRe.ReplaceAllString(s, " group$1 ")

	var out []IKEGroup
	seen := map[int]bool{}
	for _, raw := range ikeGroupSplitRe.Split(s, -1) {
		id, ok := ikeGroupTokenID(raw)
		if !ok || seen[id] {
			continue
		}
		g, ok := ikeKeyExchangeMethods[id]
		if !ok {
			continue
		}
		seen[id] = true
		out = append(out, g)
	}
	return out
}

// ikeGroupTokenID resolves one list entry to a transform ID.
func ikeGroupTokenID(raw string) (int, bool) {
	t := strings.ToLower(strings.Trim(raw, ":#"))
	t = strings.NewReplacer("-", "", "_", "").Replace(t)
	if t == "" {
		return 0, false
	}
	if id, ok := ikeGroupNames[t]; ok {
		return id, true
	}
	for _, prefix := range []string{"group", "dh", ""} {
		digits, found := strings.CutPrefix(t, prefix)
		if !found || digits == "" || !isASCIIDigits(digits) {
			continue
		}
		id, err := strconv.Atoi(digits)
		if err != nil {
			return 0, false
		}
		return id, true
	}
	return 0, false
}

func isASCIIDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// IKEGroupCodes returns the catalogue codes of the groups that have one, in
// order. A group without a catalogue row contributes nothing.
func IKEGroupCodes(groups []IKEGroup) []string {
	var codes []string
	for _, g := range groups {
		if g.Code != "" {
			codes = append(codes, g.Code)
		}
	}
	return codes
}

// OfferedIKEGroupCodes is every Diffie-Hellman exchange a tunnel's
// configuration can be made to run, as catalogue codes: the IKE groups in
// preference order, then the PFS (phase-2) groups, without duplicates. A peer
// can steer the tunnel onto any of them, so the tunnel is scored on the
// weakest, and it is quantum-vulnerable if any is classical.
func OfferedIKEGroupCodes(ike, pfs []IKEGroup) []string {
	var codes []string
	seen := map[string]bool{}
	for _, code := range append(IKEGroupCodes(ike), IKEGroupCodes(pfs)...) {
		if !seen[code] {
			seen[code] = true
			codes = append(codes, code)
		}
	}
	return codes
}

// PreferredIKEGroup returns the group a configuration prefers — the first one
// listed — when the catalogue can assess it.
//
// It deliberately does NOT fall through to the next group when the first has
// no catalogue row: the scalar key exchange of a configuration means "the one
// it uses", and naming the second choice as the one in use would be a guess.
// The rest of the offer is still linked through the full list.
func PreferredIKEGroup(groups []IKEGroup) (IKEGroup, bool) {
	if len(groups) == 0 || groups[0].Code == "" {
		return IKEGroup{}, false
	}
	return groups[0], true
}
