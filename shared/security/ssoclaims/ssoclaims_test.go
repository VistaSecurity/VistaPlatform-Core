package ssoclaims

import (
	"fmt"
	"strings"
	"testing"
)

// Provider-parity: Google asserts email_verified; Microsoft/Azure (Entra)
// omit it, so an allow-listed work/school domain is accepted as org-verified.
func TestEmailEffectivelyVerified(t *testing.T) {
	cases := []struct {
		name           string
		claimVerified  bool
		providerType   string
		email          string
		allowedDomains []string
		want           bool
	}{
		{"google verified claim", true, "google", "a@gmail.com", nil, true},
		{"google unverified claim rejected", false, "google", "a@gmail.com", []string{"gmail.com"}, false},
		{"microsoft no claim, allow-listed domain", false, "microsoft", "a@contoso.com", []string{"contoso.com"}, true},
		{"azure no claim, allow-listed domain", false, "azure", "a@contoso.com", []string{"contoso.com"}, true},
		{"microsoft no claim, case-insensitive domain", false, "microsoft", "a@Contoso.COM", []string{"contoso.com"}, true},
		{"microsoft no claim, domain not in list", false, "microsoft", "a@evil.com", []string{"contoso.com"}, false},
		{"microsoft no claim, empty allow-list rejected", false, "microsoft", "a@contoso.com", nil, false},
		{"microsoft verified claim still passes", true, "microsoft", "a@contoso.com", nil, true},
		{"other provider never relaxed", false, "okta", "a@contoso.com", []string{"contoso.com"}, false},
		{"malformed email rejected", false, "microsoft", "not-an-email", []string{"contoso.com"}, false},
		{"allow-list with whitespace entry", false, "microsoft", "a@contoso.com", []string{" contoso.com "}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EmailEffectivelyVerified(tc.claimVerified, tc.providerType, tc.email, tc.allowedDomains); got != tc.want {
				t.Errorf("EmailEffectivelyVerified(%v, %q, %q, %v) = %v, want %v",
					tc.claimVerified, tc.providerType, tc.email, tc.allowedDomains, got, tc.want)
			}
		})
	}
}

// Only an explicit assertion is a verification. Each "false" row is a value an
// IdP (or an endpoint an operator pointed the platform at) could plausibly send.
func TestEmailVerifiedClaim(t *testing.T) {
	cases := []struct {
		name string
		v    interface{}
		want bool
	}{
		{"bool true", true, true},
		{"string true", "true", true},
		{"string TRUE", "TRUE", true},
		{"string true padded (exact match only, as before)", " true ", false},
		{"bool false", false, false},
		{"string false", "false", false},
		{"missing", nil, false},
		{"number 1", float64(1), false},
		{"string 1", "1", false},
		{"string yes", "yes", false},
		{"empty string", "", false},
		{"object", map[string]interface{}{"value": true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EmailVerifiedClaim(tc.v); got != tc.want {
				t.Errorf("EmailVerifiedClaim(%#v) = %v, want %v", tc.v, got, tc.want)
			}
		})
	}
}

// The allow-list stands in for the IdP's own verification, so every near miss
// an attacker controls must fail: lookalike suffixes and prefixes, subdomains,
// a trailing dot, a second "@", and non-ASCII letters that Unicode case
// folding would map onto the allowed ASCII domain.
func TestEmailDomainAllowed(t *testing.T) {
	allowed := []string{"example.com", "Corp.Example.ORG", "kontoso.example"}
	cases := []struct {
		name  string
		email string
		want  bool
	}{
		{"exact", "a@example.com", true},
		{"case-insensitive address", "A@EXAMPLE.COM", true},
		{"case-insensitive entry", "a@corp.example.org", true},
		{"surrounding whitespace", "  a@example.com ", true},
		{"lookalike suffix", "a@example.com.evil.test", false},
		{"lookalike prefix", "a@evilexample.com", false},
		{"subdomain not implied", "a@sub.example.com", false},
		{"parent of an entry not implied", "a@example.org", false},
		{"trailing dot", "a@example.com.", false},
		{"two @", "a@evil.test@example.com", false},
		{"empty local part", "@example.com", false},
		{"empty domain", "a@", false},
		{"no @", "example.com", false},
		{"genuine k", "a@kontoso.example", true},
		{"Kelvin sign folds to k", "a@\u212Aontoso.example", false},
		{"Cyrillic small a lookalike", "a@ex\u0430mple.com", false},
		{"fullwidth letters", "a@\uFF45xample.com", false},
		{"dotless i", "a@\u0131xample.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EmailDomainAllowed(tc.email, allowed); got != tc.want {
				t.Errorf("EmailDomainAllowed(%q) = %v, want %v", tc.email, got, tc.want)
			}
		})
	}
	t.Run("empty list allows nothing", func(t *testing.T) {
		if EmailDomainAllowed("a@example.com", nil) || EmailDomainAllowed("a@example.com", []string{}) {
			t.Fatal("an empty allow-list must allow nothing")
		}
	})
	t.Run("an invalid stored entry never matches", func(t *testing.T) {
		for _, entry := range []string{"*.example.com", "example.com.", "ex\u0430mple.com", "a@example.com"} {
			if EmailDomainAllowed("a@example.com", []string{entry}) {
				t.Errorf("entry %q matched a@example.com", entry)
			}
		}
	})
}

// Microsoft relaxation reaches the stricter matcher: the Kelvin-sign address
// that strings.ToLower would have folded onto the allowed domain is refused.
func TestEmailEffectivelyVerified_UnicodeLookalikeRefused(t *testing.T) {
	if EmailEffectivelyVerified(false, "microsoft", "admin@\u212Aorp.example", []string{"korp.example"}) {
		t.Fatal("a non-ASCII address folded onto an allowed ASCII domain")
	}
	if !EmailEffectivelyVerified(false, "microsoft", "admin@korp.example", []string{"korp.example"}) {
		t.Fatal("the genuine ASCII address must still be allowed")
	}
}

func TestCanonicalEmail(t *testing.T) {
	cases := map[string]string{
		" Admin@Example.COM ":  "admin@example.com",
		"admin@\u212Aorp.test": "admin@\u212Aorp.test", // NOT folded onto "korp"
		"":                     "",
	}
	for in, want := range cases {
		if got := CanonicalEmail(in); got != want {
			t.Errorf("CanonicalEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeAllowedDomain(t *testing.T) {
	ok := map[string]string{
		"example.com":            "example.com",
		"  Example.COM ":         "example.com",
		"mail.corp-1.example.io": "mail.corp-1.example.io",
		"xn--bcher-kva.example":  "xn--bcher-kva.example",
	}
	for in, want := range ok {
		got, err := NormalizeAllowedDomain(in)
		if err != nil || got != want {
			t.Errorf("NormalizeAllowedDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"", "   ", "localhost", "*.example.com", "*example.com", "user@example.com", "@example.com",
		"https://example.com", "example.com/path", "example.com:443", "example.com.", ".example.com",
		"exa mple.com", "exa_mple.com", "-example.com", "example-.com", "b\u00FCcher.example",
		"ex\u0430mple.com", "example..com", strings.Repeat("a", 64) + ".com",
	} {
		if got, err := NormalizeAllowedDomain(bad); err == nil {
			t.Errorf("NormalizeAllowedDomain(%q) = %q, want an error", bad, got)
		}
	}
}

func TestNormalizeAllowedDomains(t *testing.T) {
	got, err := NormalizeAllowedDomains([]string{"Example.com", "example.com", "b.example"})
	if err != nil || strings.Join(got, ",") != "example.com,b.example" {
		t.Fatalf("got %v, %v; want deduplicated [example.com b.example]", got, err)
	}
	if got, err := NormalizeAllowedDomains(nil); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("nil input: got %#v, %v; want a non-nil empty list", got, err)
	}
	if _, err := NormalizeAllowedDomains([]string{"example.com", "*.example.com"}); err == nil {
		t.Fatal("one bad entry must fail the whole list")
	}
	many := make([]string, MaxAllowedDomains+1)
	for i := range many {
		many[i] = fmt.Sprintf("d%d.example", i)
	}
	if _, err := NormalizeAllowedDomains(many); err == nil {
		t.Fatalf("more than %d domains must be refused", MaxAllowedDomains)
	}
}

func TestEntraAuthorityIsSingleTenant(t *testing.T) {
	cases := map[string]bool{
		"https://login.microsoftonline.com/0b6f3c9e-1d2a-4c5b-9e8f-7a6b5c4d3e2f/oauth2/v2.0/token": true,
		"https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/authorize":          true,
		"https://login.microsoftonline.com/common/oauth2/v2.0/token":                               false,
		"https://login.microsoftonline.com/Common/oauth2/v2.0/token":                               false,
		"https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize":                    false,
		"https://login.microsoftonline.com/consumers/oauth2/v2.0/token":                            false,
		"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/oauth2/v2.0/token": false,
		"https://login.microsoftonline.com/9188040D-6C67-4C5B-B112-36A304B66DAD/oauth2/v2.0/token": false,
		"https://login.microsoftonline.com/%63ommon/oauth2/v2.0/token":                             false,
		// Dot segments and empty segments are cleaned before the authority is
		// read: each of these reaches "common" (or the personal-account GUID)
		// on a server that normalises the path, so none may pass as a single
		// directory. Before the cleaning, "." and "x" were read as the authority.
		"https://login.microsoftonline.com/./common/oauth2/v2.0/token":                                     false,
		"https://login.microsoftonline.com//common/oauth2/v2.0/token":                                      false,
		"https://login.microsoftonline.com/%2e/common/oauth2/v2.0/token":                                   false,
		"https://login.microsoftonline.com/%2E/organizations/oauth2/v2.0/authorize":                        false,
		"https://login.microsoftonline.com/contoso.com/../common/oauth2/v2.0/token":                        false,
		"https://login.microsoftonline.com/contoso.com/%2e%2e/consumers/oauth2/v2.0/token":                 false,
		"https://login.microsoftonline.com/contoso.com%2f..%2fcommon/oauth2/v2.0/token":                    false,
		"https://login.microsoftonline.com/./9188040d-6c67-4c5b-b112-36a304b66dad/oauth2/v2.0/token":       false,
		"https://login.microsoftonline.com//9188040D-6C67-4C5B-B112-36A304B66DAD/oauth2/v2.0/authorize":    false,
		"https://login.microsoftonline.com/%2e/9188040d-6c67-4c5b-b112-36a304b66dad/oauth2/v2.0/authorize": false,
		"https://login.microsoftonline.com/./0b6f3c9e-1d2a-4c5b-9e8f-7a6b5c4d3e2f/oauth2/v2.0/token":       true,
		"https://login.microsoftonline.com//contoso.onmicrosoft.com/oauth2/v2.0/token":                     true,
		// Junk in the authority segment is refused, not guessed at.
		"https://login.microsoftonline.com/common;x/oauth2/v2.0/token":         false,
		"https://login.microsoftonline.com/common%20/oauth2/v2.0/token":        false,
		"https://login.microsoftonline.com/contoso.com%5C..%5Ccommon/oauth2":   false,
		"https://login.microsoftonline.com/tenant/oauth2/v2.0/token":           false,
		"https://login.microsoftonline.com/0b6f3c9e-1d2a-4c5b-9e8f/oauth2":     false,
		"https://login.microsoftonline.com/.contoso.com/oauth2/v2.0/token":     false,
		"https://login.microsoftonline.com/..":                                 false,
		"https://login.microsoftonline.com/.":                                  false,
		"https:login.microsoftonline.com/0b6f3c9e-1d2a-4c5b-9e8f-7a6b5c4d3e2f": false,
		"https://login.microsoftonline.com/":                                   false,
		"https://login.microsoftonline.com":                                    false,
		"not a url":                                                            false,
		"":                                                                     false,
	}
	for in, want := range cases {
		if got := EntraAuthorityIsSingleTenant(in); got != want {
			t.Errorf("EntraAuthorityIsSingleTenant(%q) = %v, want %v", in, got, want)
		}
	}
}
