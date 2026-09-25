package cryptoparse

import (
	"reflect"
	"testing"
)

// Real spellings, taken from what each collector hands over as its DH group:
//
//   - UniFi networkconf `ipsec_dh_group` / `ike_dh_group`: a JSON number the
//     collector renders as "14".
//   - FortiOS `vpn.ipsec/phase1-interface` `dhgrp`: space-separated IDs in
//     preference order, "14 5".
//   - Cisco IOS `show crypto ikev2 sa detailed` "DH Grp:19", which the collector
//     stores as "Group 19"; `show crypto map` prints "DH group:  group14".
//   - strongSwan-style names ("modp2048", "ecp256", "curve25519"), which some
//     appliances and every Linux gateway use.
func TestParseIKEGroups(t *testing.T) {
	cases := []struct {
		in        string
		wantIDs   []int
		wantCodes []string
	}{
		{"14", []int{14}, []string{"DH-MODP-2048"}},
		{"group14", []int{14}, []string{"DH-MODP-2048"}},
		{"Group 14", []int{14}, []string{"DH-MODP-2048"}},
		{"GROUP 14", []int{14}, []string{"DH-MODP-2048"}},
		{"DH Group 19", []int{19}, []string{"DH-ECP-256"}},
		{"DH Grp: 20", []int{20}, []string{"DH-ECP-384"}},
		// Cisco's own spelling has no space after the colon, so the word and
		// the number arrive as ONE token; only the word-folding regex splits
		// them.
		{"DH Grp:20", []int{20}, []string{"DH-ECP-384"}},
		{"D-H Grp:21", []int{21}, []string{"DH-ECP-521"}},
		{"Grp:14", []int{14}, []string{"DH-MODP-2048"}},
		{"dh21", []int{21}, []string{"DH-ECP-521"}},
		{"14 5", []int{14, 5}, []string{"DH-MODP-2048", "DH-MODP-1536"}},
		{"21 20 19", []int{21, 20, 19}, []string{"DH-ECP-521", "DH-ECP-384", "DH-ECP-256"}},
		{"19,14", []int{19, 14}, []string{"DH-ECP-256", "DH-MODP-2048"}},
		{"group19, group14", []int{19, 14}, []string{"DH-ECP-256", "DH-MODP-2048"}},
		{"modp2048", []int{14}, []string{"DH-MODP-2048"}},
		{"MODP-1024", []int{2}, []string{"DH-1024"}},
		{"modp768", []int{1}, []string{"DH-768"}},
		{"ecp256", []int{19}, []string{"DH-ECP-256"}},
		{"ecp384 ecp521", []int{20, 21}, []string{"DH-ECP-384", "DH-ECP-521"}},
		{"curve25519", []int{31}, []string{"X25519"}},
		{"x25519", []int{31}, []string{"X25519"}},
		{"31", []int{31}, []string{"X25519"}},
		{"curve448", []int{32}, []string{"X448"}},
		{"ecp256bp", []int{28}, []string{"ECDH-BRAINPOOLP256R1"}},
		{"brainpoolP384r1", []int{29}, []string{"ECDH-BRAINPOOLP384R1"}},
		{"modp2048s256", []int{24}, []string{"DH-RFC5114-2048-256"}},
		{"24", []int{24}, []string{"DH-RFC5114-2048-256"}},
		{"ml-kem-768", []int{36}, []string{"ML-KEM-768"}},
		{"mlkem1024", []int{37}, []string{"ML-KEM-1024"}},
		{"35", []int{35}, []string{"ML-KEM-512"}},
		// A group listed twice is one offer.
		{"14 14 group14", []int{14}, []string{"DH-MODP-2048"}},
		// Unknown tokens are skipped, never defaulted; known ones around them
		// still count.
		{"14 bogus 99 5", []int{14, 5}, []string{"DH-MODP-2048", "DH-MODP-1536"}},
		// GOST is in the IANA registry but has no catalogue assessment: the
		// group is recognised (so it is not mistaken for garbage) but carries no
		// code, so nothing is linked for it.
		{"33", []int{33}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			groups := ParseIKEGroups(tc.in)
			var ids []int
			for _, g := range groups {
				ids = append(ids, g.ID)
			}
			if !reflect.DeepEqual(ids, tc.wantIDs) {
				t.Errorf("ParseIKEGroups(%q) IDs = %v, want %v", tc.in, ids, tc.wantIDs)
			}
			if got := IKEGroupCodes(groups); !reflect.DeepEqual(got, tc.wantCodes) {
				t.Errorf("IKEGroupCodes(%q) = %v, want %v", tc.in, got, tc.wantCodes)
			}
		})
	}
}

// Unknown stays unknown: nothing a reader cannot place may turn into a group,
// and "0"/"none" is IANA's NONE — no key exchange, not a group.
func TestParseIKEGroups_UnknownYieldsNothing(t *testing.T) {
	for _, in := range []string{
		"", "   ", "0", "none", "NONE", "3", "4", "6", "13", "38", "1023", "1024",
		"IKEV2", "ikev1", "aes256", "sha256", "group", "Group", "modp", "ecp",
		"ffdhe2048", // RFC 7919 names TLS groups; IKEv2 has no such transform ID
		"14.0", "group-", "curve",
	} {
		if got := ParseIKEGroups(in); len(got) != 0 {
			t.Errorf("ParseIKEGroups(%q) = %+v, want nothing", in, got)
		}
	}
}

// RFC 9370 additional key exchanges are not alternatives. strongSwan's
// "ecp256-ke1_mlkem768" runs ECP-256 AND ML-KEM-768; read as a preference list
// it would become "ECP-256 or ML-KEM-768". The parser must answer nothing for
// them — never a partial list — until a collector reads them into a key of
// their own.
func TestParseIKEGroups_AdditionalKeyExchangesAreNotAlternatives(t *testing.T) {
	for _, in := range []string{
		"ecp256-ke1_mlkem768",
		"ECP256-KE1_MLKEM768",
		"ecp256 ke1_mlkem768",
		"aes256-sha256-ecp256-ke1_mlkem768-ke2_mlkem1024",
		"x25519-ke1_mlkem768",
		"addke1 36",
		"19 addke1=36",
	} {
		if got := ParseIKEGroups(in); len(got) != 0 {
			t.Errorf("ParseIKEGroups(%q) = %+v, want nothing — an additional key exchange is not an alternative", in, got)
		}
	}
	// The guard must not swallow ordinary names that merely contain the
	// letters: "ke" inside a word is not a marker.
	for in, want := range map[string]int{"mlkem768": 36, "ml-kem-1024": 37, "group14": 14} {
		if got := ParseIKEGroups(in); len(got) != 1 || got[0].ID != want {
			t.Errorf("ParseIKEGroups(%q) = %+v, want group %d", in, got, want)
		}
	}
}

// Every group the helper links must say how big its key is, because the
// platform reads key_size against the key-exchange family (SP 800-131A floors):
// an IPsec config whose collector put the AES key length in key_size would
// otherwise read as a 256-bit finite-field modulus — critically weak.
func TestIKEGroups_ClassicalGroupsCarryTheirKeySize(t *testing.T) {
	for _, g := range ikeKeyExchangeMethods {
		if g.Code == "" {
			continue
		}
		family := KeyAlgorithmFamily(g.Code)
		switch family {
		case KexFamilyPostQuantum:
			if g.Bits != 0 {
				t.Errorf("group %d (%s): post-quantum groups have no comparable key size, got %d", g.ID, g.Code, g.Bits)
			}
		case KexFamilyFiniteField, KexFamilyEllipticCurve:
			if g.Bits <= 0 {
				t.Errorf("group %d (%s): classical group without a key size", g.ID, g.Code)
			}
		default:
			t.Errorf("group %d (%s): code classifies as no key family — key-size rules would ignore it", g.ID, g.Code)
		}
	}
	// And the family must be the RIGHT one, or a 256-bit curve is measured
	// against the 2048-bit modulus floor.
	for id, want := range map[int]KexFamily{
		2: KexFamilyFiniteField, 14: KexFamilyFiniteField, 24: KexFamilyFiniteField,
		19: KexFamilyEllipticCurve, 25: KexFamilyEllipticCurve, 28: KexFamilyEllipticCurve,
		31: KexFamilyEllipticCurve, 32: KexFamilyEllipticCurve,
		36: KexFamilyPostQuantum,
	} {
		g, ok := IKEKeyExchangeMethod(id)
		if !ok {
			t.Fatalf("group %d missing", id)
		}
		if got := KeyAlgorithmFamily(g.Code); got != want {
			t.Errorf("group %d (%s) family = %v, want %v", id, g.Code, got, want)
		}
	}
}

// The IDs are the IANA "Transform Type 4 - Key Exchange Method Transform IDs"
// registry (checked against the registry of. This pins the ones a
// wrong number would silently swap: a typo here re-labels a 1024-bit group as
// 2048-bit.
func TestIKEKeyExchangeMethod_IANAAssignments(t *testing.T) {
	want := map[int]string{
		1: "768-bit MODP Group", 2: "1024-bit MODP Group", 5: "1536-bit MODP Group",
		14: "2048-bit MODP Group", 15: "3072-bit MODP Group", 16: "4096-bit MODP Group",
		17: "6144-bit MODP Group", 18: "8192-bit MODP Group",
		19: "256-bit random ECP group", 20: "384-bit random ECP group", 21: "521-bit random ECP group",
		22: "1024-bit MODP Group with 160-bit Prime Order Subgroup",
		23: "2048-bit MODP Group with 224-bit Prime Order Subgroup",
		24: "2048-bit MODP Group with 256-bit Prime Order Subgroup",
		25: "192-bit Random ECP Group", 26: "224-bit Random ECP Group",
		27: "brainpoolP224r1", 28: "brainpoolP256r1", 29: "brainpoolP384r1", 30: "brainpoolP512r1",
		31: "Curve25519", 32: "Curve448", 33: "GOST3410_2012_256", 34: "GOST3410_2012_512",
		35: "ml-kem-512", 36: "ml-kem-768", 37: "ml-kem-1024",
	}
	if len(ikeKeyExchangeMethods) != len(want) {
		t.Errorf("table has %d groups, registry has %d assigned", len(ikeKeyExchangeMethods), len(want))
	}
	for id, name := range want {
		g, ok := IKEKeyExchangeMethod(id)
		if !ok {
			t.Errorf("group %d missing", id)
			continue
		}
		if g.Name != name || g.ID != id {
			t.Errorf("group %d = %+v, want name %q", id, g, name)
		}
	}
	for _, id := range []int{0, 3, 4, 6, 13, 38} {
		if _, ok := IKEKeyExchangeMethod(id); ok {
			t.Errorf("group %d is not an assigned key exchange method", id)
		}
	}
}
