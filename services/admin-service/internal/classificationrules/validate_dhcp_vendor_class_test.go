package classificationrules

import (
	"strings"
	"testing"
)

// The admin API runs the ENGINE's validator, so a dhcp_vendor_class rule the
// console accepts is one the engine will compile, and one it refuses is refused
// with the engine's own reason. Both polarities.
func TestValidate_DHCPVendorClass(t *testing.T) {
	rule := func(pattern string) Input {
		return Input{
			RuleKind:   "dhcp_vendor_class",
			Pattern:    pattern,
			ClassKey:   ptr("computer"),
			Confidence: 0.75,
			SourceURL:  ptr("https://www.rfc-editor.org/rfc/rfc2132#section-9.13"),
		}
	}

	if !ValidKind("dhcp_vendor_class") {
		t.Fatal("dhcp_vendor_class is not in the console's kind vocabulary")
	}
	for _, p := range []string{`^MSFT 5\.0$`, `(?i)^acme-dhcp-`} {
		if err := Validate(rule(p)); err != nil {
			t.Errorf("Validate(%q) = %v; a compiling RE2 pattern must be accepted", p, err)
		}
	}
	for _, p := range []string{`^MSFT(?!X)`, `^(MSFT`} {
		err := Validate(rule(p))
		if err == nil {
			t.Errorf("Validate(%q) accepted a pattern RE2 cannot compile", p)
			continue
		}
		if !strings.Contains(err.Error(), "does not compile") || strings.HasPrefix(err.Error(), "classify:") {
			t.Errorf("Validate(%q) = %q; want the engine's compile message, prefix trimmed", p, err)
		}
	}
	if err := Validate(rule("  ")); err == nil {
		t.Error("an empty dhcp_vendor_class pattern was accepted")
	}
}
