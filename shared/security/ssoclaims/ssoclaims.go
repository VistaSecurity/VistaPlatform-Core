// Package ssoclaims holds the one policy every SSO sign-in path uses to decide
// whether an identity provider's email assertion may be trusted.
//
// Three callers share it: tenant SSO JIT provisioning and platform social
// signup (auth-service) and staff sign-in to the admin console
// (admin-service). They used to carry their own copies, which is how the staff
// path came to skip the check entirely. The package is pure Go with no
// platform-runtime dependencies.
package ssoclaims

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
)

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
//     The match is EmailDomainAllowed's: exact, ASCII-only, no subdomains.
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
	return EmailDomainAllowed(email, allowedDomains)
}

// EmailDomainAllowed reports whether email's domain is exactly one of the
// allowed domains. It is deliberately strict, because a match stands in for
// the IdP's own verification:
//   - an empty list allows nothing;
//   - the email must have exactly one "@" and a non-empty local part;
//   - only ASCII letters are case-folded. Unicode case folding maps some
//     non-ASCII letters onto ASCII ones (the Kelvin sign U+212A lower-cases to
//     "k"), so strings.ToLower/EqualFold would let a non-ASCII address
//     impersonate an allowed ASCII domain. Folded ASCII-only, a domain with any
//     non-ASCII byte can never equal an entry, because every usable entry is
//     ASCII (NormalizeAllowedDomain);
//   - the comparison is ASCII case-insensitive and exact: "example.com" does
//     not allow "sub.example.com", "example.com.evil.test" or "example.com.";
//   - an entry that is not itself a valid domain (see NormalizeAllowedDomain)
//     never matches, so a hand-written row cannot widen the rule.
func EmailDomainAllowed(email string, allowedDomains []string) bool {
	if len(allowedDomains) == 0 {
		return false
	}
	email = strings.TrimSpace(email)
	at := strings.IndexByte(email, '@')
	if at <= 0 || strings.Count(email, "@") != 1 {
		return false
	}
	domain := asciiLower(email[at+1:])
	if domain == "" {
		return false
	}
	for _, d := range allowedDomains {
		norm, err := NormalizeAllowedDomain(d)
		if err != nil {
			continue
		}
		if domain == norm {
			return true
		}
	}
	return false
}

// CanonicalEmail trims surrounding whitespace and lower-cases ASCII letters
// only. strings.ToLower would also fold non-ASCII letters onto ASCII ones
// (U+212A KELVIN SIGN becomes "k"), letting an IdP-asserted address such as
// "admin@\u212Aorp.example" match the account "admin@korp.example". With
// ASCII-only folding a non-ASCII address stays distinct and matches nothing
// stored in ASCII.
func CanonicalEmail(s string) string {
	return asciiLower(strings.TrimSpace(s))
}

// MaxAllowedDomains caps an allow-list. It is a list of an organisation's own
// mail domains, not a directory.
const MaxAllowedDomains = 50

// NormalizeAllowedDomain validates one allow-list entry and returns its
// canonical form (trimmed, lower-case). Accepted: an ASCII hostname of at
// least two labels, each 1–63 letters, digits or hyphens, not starting or
// ending with a hyphen, 253 characters at most. An internationalised domain
// must be entered in its punycode form ("xn--…"). Rejected with a reason: an
// empty entry, a wildcard ("*.example.com" — only exact domains are
// supported), an email address, a URL, a trailing dot, or any non-ASCII
// character.
func NormalizeAllowedDomain(s string) (string, error) {
	d := strings.TrimSpace(s)
	switch {
	case d == "":
		return "", errors.New("domain is empty")
	case !isASCII(d):
		return "", fmt.Errorf("%q contains non-ASCII characters; enter an internationalised domain in its punycode (xn--) form", d)
	case strings.HasPrefix(d, "*"):
		return "", fmt.Errorf("%q is a wildcard; only exact domains are supported (list each domain you want to allow)", d)
	case strings.Contains(d, "@"):
		return "", fmt.Errorf("%q is an email address; enter only the part after the @", d)
	case strings.Contains(d, "/") || strings.Contains(d, ":"):
		return "", fmt.Errorf("%q is not a bare domain", d)
	case strings.HasSuffix(d, "."):
		return "", fmt.Errorf("%q ends with a dot", d)
	}
	d = asciiLower(d)
	if len(d) > 253 {
		return "", fmt.Errorf("%q is longer than 253 characters", d)
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("%q is not a fully qualified domain (expected e.g. example.com)", d)
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return "", fmt.Errorf("%q has an empty or over-long label", d)
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return "", fmt.Errorf("%q has a label starting or ending with a hyphen", d)
		}
		for i := 0; i < len(l); i++ {
			ch := l[i]
			isLetter := ch >= 'a' && ch <= 'z'
			isDigit := ch >= '0' && ch <= '9'
			if !isLetter && !isDigit && ch != '-' {
				return "", fmt.Errorf("%q contains %q; only letters, digits, hyphens and dots are allowed", d, string(ch))
			}
		}
	}
	return d, nil
}

// NormalizeAllowedDomains validates a whole allow-list: every entry through
// NormalizeAllowedDomain, duplicates removed (first occurrence kept, order
// preserved), at most MaxAllowedDomains. The result is never nil, so an
// empty list round-trips as [] rather than null.
func NormalizeAllowedDomains(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, raw := range in {
		d, err := NormalizeAllowedDomain(raw)
		if err != nil {
			return nil, err
		}
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	if len(out) > MaxAllowedDomains {
		return nil, fmt.Errorf("at most %d allowed domains", MaxAllowedDomains)
	}
	return out, nil
}

// entraMultiTenantAuthorities are the Microsoft identity platform authority
// segments that accept accounts from ANY directory (or personal accounts).
var entraMultiTenantAuthorities = map[string]bool{
	"common":        true,
	"organizations": true,
	"consumers":     true,
	// The Microsoft personal-account (MSA) directory. Its GUID works as the
	// "consumers" authority: it names one directory, but one that holds every
	// personal Microsoft account, which no organisation controls.
	"9188040d-6c67-4c5b-b112-36a304b66dad": true,
}

// EntraAuthorityIsSingleTenant reports whether a Microsoft identity platform
// endpoint URL (authorize or token) names one specific directory
// (https://login.microsoftonline.com/<tenant-id or domain>/oauth2/v2.0/token)
// rather than a multi-tenant authority (common, organizations, consumers, or
// the personal-account directory's GUID).
//
// This is what makes a domain allow-list meaningful for Entra. Entra does not
// verify the `email` claim: an administrator of ANY directory can give one of
// their users any mail address. Through a multi-tenant endpoint such a user
// could sign in asserting an allow-listed domain (the "nOAuth" class). Pinned
// to the organisation's own directory, only that directory's administrators
// control the address — which is the organisational control the allow-list
// relies on.
//
// The authority is the first segment of the CLEANED, decoded path. Reading the
// raw first segment let dot segments and percent-encoding put a multi-tenant
// authority behind something that is not one ("/./common/…", "/%2e/common/…",
// "/x/../common/…"), which a server that normalises the path resolves to
// "common". The segment must then have the shape of a directory identifier
// Entra issues — a GUID or a dotted domain name — or be one of the named
// multi-tenant authorities, so junk ("common;x", "common%20", a backslash) is
// refused rather than guessed at. An unparsable URL, one with no host, or one
// with no path is not single-tenant.
func EntraAuthorityIsSingleTenant(rawURL string) bool {
	seg, ok := entraAuthoritySegment(rawURL)
	if !ok {
		return false
	}
	return !entraMultiTenantAuthorities[seg]
}

// entraAuthoritySegment returns the lower-cased authority segment of an Entra
// endpoint URL, or false when there is none that can be trusted.
func entraAuthoritySegment(rawURL string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" || u.Opaque != "" {
		return "", false
	}
	// url.Parse has already percent-decoded Path, so "%2e" and "%2f" are real
	// dots and slashes here; path.Clean then drops ".", ".." and empty
	// segments the way a normalising server would.
	cleaned := path.Clean("/" + u.Path)
	seg := asciiLower(strings.SplitN(strings.TrimPrefix(cleaned, "/"), "/", 2)[0])
	if !isEntraAuthorityShape(seg) {
		return "", false
	}
	return seg, true
}

// isEntraAuthorityShape reports whether seg looks like an Entra authority: a
// GUID, a dotted domain name, or one of the named multi-tenant authorities.
func isEntraAuthorityShape(seg string) bool {
	switch {
	case seg == "":
		return false
	case isGUID(seg), entraMultiTenantAuthorities[seg]:
		return true
	case !strings.Contains(seg, "."):
		return false
	}
	_, err := NormalizeAllowedDomain(seg)
	return err == nil
}

// isGUID reports whether s is a lower-case 8-4-4-4-12 hexadecimal GUID.
func isGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch i {
		case 8, 13, 18, 23:
			if ch != '-' {
				return false
			}
		default:
			if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
				return false
			}
		}
	}
	return true
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, ch := range b {
		if ch >= 'A' && ch <= 'Z' {
			b[i] = ch + ('a' - 'A')
		}
	}
	return string(b)
}
