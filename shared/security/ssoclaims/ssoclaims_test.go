package ssoclaims

import "testing"

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
