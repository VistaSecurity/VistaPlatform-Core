package classificationrules

import (
	"strings"
	"testing"
)

// source_url is the one field of a classification rule that becomes a live link
// in someone else's browser: it is copied onto every class proposal the rule
// produces and rendered as a raw href in EVERY tenant's console as well as in
// the admin catalogue. Until this check existed the value was only trimmed.
//
// The sibling EOL catalogue path has enforced the same policy at three doors
// since ADR-0008 D4.4; this path — the wider blast radius — was the one that
// was missed.
//
// BOTH polarities, because refusing a vendor's ordinary documentation URL would
// make the field unusable and is the same bug pointed the other way.
func TestValidate_SourceURL(t *testing.T) {
	base := func(u *string) Input {
		return Input{
			RuleKind:   "oui",
			Pattern:    "0018E7",
			Vendor:     ptr("Ubiquiti"),
			Confidence: 0.8,
			SourceURL:  u,
		}
	}

	accepted := []string{
		"https://standards-oui.ieee.org/oui/oui.txt",
		"https://www.cisco.com/c/en/us/products/collateral/datasheet.html",
		"https://help.ui.com/hc/en-us/articles/204910064",
		"https://vendor.example/eol?product=x",
	}
	for _, u := range accepted {
		if err := Validate(base(ptr(u))); err != nil {
			t.Errorf("Validate(source_url=%q) = %v; an ordinary vendor citation must be accepted", u, err)
		}
	}

	// Uncited stays legal: classify.Rule documents an admin rule with nothing
	// public to point at as legitimate, and the console shows it as "uncited".
	// This governs what a CITED rule may cite, not whether it must cite.
	for _, empty := range []*string{nil, ptr(""), ptr("   ")} {
		if err := Validate(base(empty)); err != nil {
			t.Errorf("Validate(uncited) = %v; a rule with no source_url must still be accepted", err)
		}
	}

	refused := map[string]string{
		"http://vendor.example/oui":               "plaintext",
		"https://169.254.169.254/latest/":         "cloud metadata literal",
		"https://192.168.1.1/admin":               "private address literal",
		"https://localhost/notes":                 "internal hostname",
		"https://wiki.internal/oui":               "internal hostname",
		"https://intranet/oui":                    "single-label host",
		"https://203.0.113.10/oui":                "bare IP rather than a vendor page",
		"javascript:alert(document.cookie)":       "not https",
		"data:text/html;base64,PHNjcmlwdD4=":      "not https",
		"https://0177.0.0.1/oui":                  "octal IP literal that net.ParseIP will not parse",
		"https://2130706433/oui":                  "integer IP literal",
		"https://host.docker.internal/oui":        "internal hostname",
		"https://kubernetes.default.svc/oui":      "internal hostname",
		"https://vendor.example.local/oui":        "internal hostname",
		"https://vendor.cluster.local/oui":        "internal hostname",
		"https://metadata.google.internal/x":      "internal hostname",
		"https://vendor.example/\x00oui":          "control character",
		"ftp://vendor.example/oui":                "not https",
		"//vendor.example/oui":                    "no scheme",
		strings.Repeat("https://a.example/", 200): "longer than a URL",
	}
	for u, why := range refused {
		if err := Validate(base(ptr(u))); err == nil {
			t.Errorf("Validate(source_url=%q) = nil; it must be refused (%s)", u, why)
		}
	}
}

func ptr(s string) *string { return &s }
