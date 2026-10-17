// Package wireless holds the rules of DCIM wireless LANs (BUILD_PLAN row 4.4;
// ADR-0010 D8) that more than one layer applies: how a LAN's authentication
// and cipher name a row of the algorithms catalogue, and which values are
// accepted.
//
// The catalogue, not this package, says how risky a cipher is. This package
// only maps a LAN's (auth_type, auth_cipher) onto the catalogue row that
// describes it.
package wireless

import "strings"

// Authentication types and ciphers (NetBox wireless/choices.py).
var (
	AuthTypes   = []string{"open", "wep", "wpa-personal", "wpa-enterprise"}
	AuthCiphers = []string{"auto", "tkip", "aes"}
)

// The catalogue codes (scripts/database/seed.sql, "Wi-Fi link-layer ciphers").
const (
	AlgorithmCCMP = "WIFI-CCMP"
	AlgorithmTKIP = "WIFI-TKIP"
	AlgorithmWEP  = "WIFI-WEP"
	AlgorithmOpen = "WIFI-OPEN"
)

// ValidAuthType reports whether t is an accepted auth_type.
func ValidAuthType(t string) bool { return contains(AuthTypes, t) }

// ValidAuthCipher reports whether c is an accepted auth_cipher.
func ValidAuthCipher(c string) bool { return contains(AuthCiphers, c) }

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// AlgorithmCode is the catalogue row that scores a LAN's link-layer
// protection, or "" when none can be named: no auth type recorded, or a
// WPA LAN whose cipher is `auto` (it negotiates, and the controller did not say
// what) or unrecorded. "" means NOT ASSESSED, never "safe".
func AlgorithmCode(authType, authCipher string) string {
	switch strings.ToLower(strings.TrimSpace(authType)) {
	case "open":
		return AlgorithmOpen
	case "wep":
		return AlgorithmWEP
	case "wpa-personal", "wpa-enterprise":
		switch strings.ToLower(strings.TrimSpace(authCipher)) {
		case "tkip":
			return AlgorithmTKIP
		case "aes":
			return AlgorithmCCMP
		}
	}
	return ""
}
