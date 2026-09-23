// Package ssoclaims holds the one policy every SSO sign-in path uses to decide
// whether an identity provider's email assertion may be trusted.
//
// Three callers share it: tenant SSO JIT provisioning and platform social
// signup (auth-service) and staff sign-in to the admin console
// (admin-service). They used to carry their own copies, which is how the staff
// path came to skip the check entirely. The package is pure Go with no
// platform-runtime dependencies.
package ssoclaims

import "strings"

// EmailVerifiedClaim reads an `email_verified` value from a decoded userinfo
// or id_token claim map. Only an explicit assertion counts: the JSON boolean
// true, or the string "true" (any case) that some IdPs and SAML-bridged OIDC
// send, matched exactly apart from case (no whitespace trimming). A missing
// claim, false, a number, or any other string is NOT verified.
func EmailVerifiedClaim(v interface{}) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true")
	default:
		return false
	}
}

// EmailEffectivelyVerified reports whether an SSO email may be treated as
// verified (provider parity). Rules:
//   - If the IdP asserted email_verified=true, it is verified (Google, Okta, ...).
//   - Microsoft Entra ID (provider_type "microsoft"/"azure") does NOT emit an
//     email_verified claim. For those work/school providers, organizational
//     control of a configured allowed domain is equivalent assurance: an email
//     whose domain is in a NON-EMPTY allow-list is accepted as org-verified.
//   - Never relaxed for an empty allow-list, and never for any other provider.
//
// A caller with no allow-list concept passes nil, which makes the claim
// mandatory for every provider.
func EmailEffectivelyVerified(claimVerified bool, providerType, email string, allowedDomains []string) bool {
	if claimVerified {
		return true
	}
	if providerType != "microsoft" && providerType != "azure" {
		return false
	}
	if len(allowedDomains) == 0 {
		return false
	}
	parts := strings.SplitN(strings.ToLower(email), "@", 2)
	if len(parts) != 2 || parts[1] == "" {
		return false
	}
	for _, d := range allowedDomains {
		if strings.EqualFold(parts[1], strings.TrimSpace(d)) {
			return true
		}
	}
	return false
}
