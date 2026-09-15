package catalogs

// The citation rule, in both polarities.
//
// The forward direction is the security one: a URL a model supplied must not be
// able to point a reviewer at this cluster's own network. The inverse matters
// exactly as much — a validator that refused everything would pass every
// "is it refused?" case below and quietly empty the proposal queue, which is
// the same bug pointed the other way.

import (
	"strings"
	"testing"
)

func TestValidateCitationURL_Refuses(t *testing.T) {
	cases := map[string]string{
		"empty":                    "",
		"whitespace only":          "   ",
		"plain http":               "http://www.cisco.com/eol",
		"a scheme we do not serve": "file:///etc/passwd",
		"not a URL at all":         "the vendor's website",
		"no host":                  "https:///eol",
		"a single-label host":      "https://intranet/eol",
		"an internal hostname":     "https://kubernetes.default.svc/eol",
		"a .internal suffix":       "https://wiki.corp.internal/eol",
		"a .local suffix":          "https://printer.local/eol",
		"localhost":                "https://localhost/eol",
		"a trailing-dot localhost": "https://localhost./eol",
		"RFC1918":                  "https://10.0.0.1/eol",
		"loopback":                 "https://127.0.0.1/eol",
		"the cloud metadata IP":    "https://169.254.169.254/latest/meta-data/",
		"an IPv6 loopback literal": "https://[::1]/eol",
		"an IPv6 literal":          "https://[2001:db8::1]/eol",
		// net.ParseIP is strict about leading zeros, so this is not an "IP
		// literal" by its reckoning — but a browser resolves it to 127.0.0.1.
		"loopback in octal":     "https://0177.0.0.1/eol",
		"a public IPv4 literal": "https://93.184.216.34/eol",
		"prose past the cap":    "https://example.com/" + strings.Repeat("a", 2100),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			err := ValidateCitationURL(raw)
			if err == nil {
				t.Fatalf("ValidateCitationURL(%q) = nil, want a refusal", raw)
			}
			// The message is read by an operator debugging an empty queue, so
			// it has to name the rule that fired rather than say "invalid".
			if strings.TrimSpace(err.Error()) == "" {
				t.Error("a refusal with no reason is not a refusal a person can act on")
			}
		})
	}
}

func TestValidateCitationURL_Accepts(t *testing.T) {
	for _, raw := range []string{
		"https://endoflife.date/ubuntu",
		"https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2022",
		"https://www.cisco.com/c/en/us/support/docs/eol.html?x=1#anchor",
		"HTTPS://WWW.CISCO.COM/eol",
		"https://support.hpe.com:443/hpesc/public/km/product/1009/lifecycle",
		"  https://endoflife.date/nginx  ",
	} {
		if err := ValidateCitationURL(raw); err != nil {
			t.Errorf("ValidateCitationURL(%q) = %v, want it accepted", raw, err)
		}
	}
}

// The rule that closes the notation hole is "the last label is a number", not
// an enumeration of IP spellings. ICANN forbids an all-numeric TLD precisely so
// that a hostname can never be mistaken for an address, so the test is a fixed
// property rather than a list to keep up to date.
func TestIsNumericHost(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "0177.0.0.1", "2130706433", "93.184.216.34", "example.42", "1.2.3.4."} {
		if !isNumericHost(h) {
			t.Errorf("isNumericHost(%q) = false, want true", h)
		}
	}
	for _, h := range []string{"endoflife.date", "www.cisco.com", "3com.com", "a.b.c0m", "x.co"} {
		if isNumericHost(h) {
			t.Errorf("isNumericHost(%q) = true, want false", h)
		}
	}
}
