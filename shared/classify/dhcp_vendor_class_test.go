package classify

import (
	"context"
	"strings"
	"testing"
)

// dhcpRuleRefs is the dhcp_vendor_class rules a proposal cites.
func dhcpRuleRefs(refs []RuleRef) []RuleRef {
	var out []RuleRef
	for _, r := range refs {
		if r.Kind == KindDHCPVendorClass {
			out = append(out, r)
		}
	}
	return out
}

// The SHIPPED rules, against the strings real clients send. Both polarities:
// the identifiers the catalogue rules on reach their class, and the ones it
// deliberately leaves ruleless (standards/classification-rules.yaml says why
// for each) match no dhcp_vendor_class rule at all.
func TestDHCPVendorClass_ShippedRules(t *testing.T) {
	ctx := context.Background()
	e := Default()

	hits := []struct {
		vc, class, vendor string
	}{
		{"MSFT 5.0", "computer", ""},
		{"android-dhcp-14", "mobile", ""},
		{"android-dhcp-9", "mobile", ""},
		{"Cisco AP c3700", "access_point", "Cisco Systems"},
		{"Cisco AP c9120", "access_point", "Cisco Systems"},
		{"Hewlett-Packard JetDirect", "printer", "Hewlett Packard"},
	}
	for _, tc := range hits {
		got := e.Classify(ctx, ClassifyInput{DHCPVendorClass: tc.vc})
		if got.Class != tc.class {
			t.Errorf("%q: class = %q, want %q (matched %+v)", tc.vc, got.Class, tc.class, got.MatchedRules)
		}
		if got.Vendor != tc.vendor {
			t.Errorf("%q: vendor = %q, want %q — option 60 names client software, so only a rule stating a vendor may set one",
				tc.vc, got.Vendor, tc.vendor)
		}
		if n := len(dhcpRuleRefs(got.MatchedRules)); n != 1 {
			t.Errorf("%q: %d dhcp_vendor_class rules matched, want exactly 1", tc.vc, n)
		}
	}

	ruleless := []string{
		"MSFT 5.0 XBOX", // the anchor: a console that claims to be an Xbox
		"MSFT 98",       // a Windows 9x client
		"msft 5.0",      // case is the client's; the rule does not fold it
		"udhcp 1.36.1",  // BusyBox: routers, cameras, TVs, plugs alike
		"dhcpcd-10.0.6", // any Linux or BSD host
		"PXEClient:Arch:00000:UNDI:002001",
		"AAPLBSDPC/i386",
		"Linux 6.1.0 x86_64",
		"SUNW.UltraSPARC-IIi-cEngine",
		"ubnt",
		"Polycom-VVX450",
		"XCisco AP c3700", // the anchor, on the vendor-bearing rule too
	}
	for _, vc := range ruleless {
		got := e.Classify(ctx, ClassifyInput{DHCPVendorClass: vc})
		if refs := dhcpRuleRefs(got.MatchedRules); len(refs) != 0 {
			t.Errorf("%q matched %+v; it is deliberately ruleless", vc, refs)
		}
		if !got.Unknown || got.Class != "" {
			t.Errorf("%q: got class %q; with no other evidence it must stay unknown", vc, got.Class)
		}
	}
}

// Every shipped dhcp_vendor_class pattern is anchored at the start. The
// generator refuses an unanchored one; this pins the generated table too, so a
// hand-edit of rules_gen.go cannot slip one past.
func TestDHCPVendorClass_ShippedPatternsAreAnchored(t *testing.T) {
	n := 0
	for _, r := range generatedRules {
		if r.Kind != KindDHCPVendorClass {
			continue
		}
		n++
		p := r.Pattern
		if strings.HasPrefix(p, "(?") {
			if i := strings.Index(p, ")"); i > 0 {
				p = p[i+1:]
			}
		}
		if !strings.HasPrefix(p, "^") {
			t.Errorf("shipped dhcp_vendor_class pattern %q is not anchored", r.Pattern)
		}
		if r.SourceURL == "" {
			t.Errorf("shipped dhcp_vendor_class pattern %q has no citation", r.Pattern)
		}
	}
	if n == 0 {
		t.Fatal("no dhcp_vendor_class rules in the generated table")
	}
}

// Two dhcp_vendor_class rules fitting one identifier and naming unrelated
// classes at similar confidence are a conflict: every match is returned, and
// the arbitration proposes nothing.
func TestDHCPVendorClass_TwoDisagreeingRulesConflict(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindDHCPVendorClass, Pattern: `^acme-`, Class: "printer", Confidence: 0.75, SourceURL: "https://x"},
		Rule{Kind: KindDHCPVendorClass, Pattern: `^acme-cam`, Class: "iot_device", Confidence: 0.72, SourceURL: "https://x"},
	)
	got := e.Classify(context.Background(), ClassifyInput{DHCPVendorClass: "acme-cam 2.1"})
	if got.Class != "" || !got.Unknown || !got.Conflict {
		t.Errorf("got %+v; two matching rules naming unrelated classes must conflict", got)
	}
	if n := len(dhcpRuleRefs(got.MatchedRules)); n != 2 {
		t.Errorf("%d rules matched, want both", n)
	}
	// And only one fits a different identifier: no conflict there.
	if got := e.Classify(context.Background(), ClassifyInput{DHCPVendorClass: "acme-printer"}); got.Class != "printer" {
		t.Errorf("acme-printer: class %q, want printer", got.Class)
	}
}

// MSFT 5.0 says computer; a Windows SERVER also sends it, and the os_name rule
// that says server REFINES computer rather than arguing with it. And an Android
// TV — android-dhcp plus a cast receiver — is a conflict, not a phone.
func TestDHCPVendorClass_InteractsWithTheShippedCatalogue(t *testing.T) {
	ctx := context.Background()
	e := Default()

	got := e.Classify(ctx, ClassifyInput{DHCPVendorClass: "MSFT 5.0", OS: "Microsoft Windows Server 2022 Datacenter"})
	if got.Class != "server" || got.Conflict {
		t.Errorf("MSFT 5.0 + Windows Server = %+v, want server (a refinement of computer, not a conflict)", got)
	}

	got = e.Classify(ctx, ClassifyInput{DHCPVendorClass: "android-dhcp-12", MDNSServices: []string{"_googlecast._tcp"}})
	if got.Class == "mobile" {
		t.Errorf("an Android device advertising a cast receiver was called mobile; it is likely a TV and must not be")
	}
	if !got.Unknown || !got.Conflict {
		t.Errorf("android-dhcp + _googlecast._tcp = %+v, want a conflict", got)
	}
}

// An invalid regexp is refused at build: NewStrict fails the set, New skips the
// row and reports it — the same contract every regexp kind keeps.
func TestDHCPVendorClass_InvalidRegexpRefusedAtBuild(t *testing.T) {
	bad := []Rule{
		{Kind: KindDHCPVendorClass, Pattern: `^MSFT(?!X)`, Class: "computer", Confidence: 0.75, SourceURL: "https://x"},
		{Kind: KindDHCPVendorClass, Pattern: `^(MSFT`, Class: "computer", Confidence: 0.75, SourceURL: "https://x"},
	}
	for _, r := range bad {
		if _, err := NewStrict([]Rule{r}); err == nil || !strings.Contains(err.Error(), "does not compile") {
			t.Errorf("NewStrict(%q) = %v, want a compile refusal", r.Pattern, err)
		}
		e, skipped, err := New([]Rule{r})
		if err != nil || len(skipped) != 1 {
			t.Errorf("New(%q): skipped %d, err %v; want the row skipped and reported", r.Pattern, len(skipped), err)
		}
		if got := e.Classify(context.Background(), ClassifyInput{DHCPVendorClass: "MSFT 5.0"}); !got.Unknown {
			t.Errorf("a skipped rule classified something: %+v", got)
		}
	}
	empty := Rule{Kind: KindDHCPVendorClass, Pattern: "", Class: "computer", Confidence: 0.75}
	if err := empty.Validate(); err == nil {
		t.Error("an empty dhcp_vendor_class pattern validated")
	}
}
