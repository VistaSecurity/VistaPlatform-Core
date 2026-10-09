package classify

import (
	"context"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/ouiregistry"
)

// Real assignments, from the embedded IEEE snapshot:
//
//	00:1B:A9          Brother Industries   MA-L, canonical
//	00:00:0C          Cisco Systems        MA-L, canonical
//	4C:74:A7:E        Kyocera              MA-M (28-bit); 4C:74:A7 itself is an
//	                                       IEEE Registration Authority block the
//	                                       registry does not attribute
//	00:55:DA:0        a registrant standards/oui/vendors.yaml does not name
const (
	macBrother     = "00:1b:a9:11:22:33"
	macBrother2    = "00:80:77:11:22:33" // a second Brother MA-L
	macCisco       = "00:00:0c:11:22:33"
	macKyocera28   = "4c:74:a7:e1:23:45"
	macUncanonical = "00:55:da:01:23:45"
)

func registryStatements(refs []RuleRef) []string {
	var out []string
	for _, r := range refs {
		if r.IsRegistryStatement() {
			out = append(out, r.Vendor)
		}
	}
	return out
}

// A rule written against a vendor fires for every assignment that vendor holds
// — which is the whole point of writing it against the vendor.
func TestOUIVendor_MatchesTheCanonicalVendorOfEveryAssignment(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindOUIVendor, Pattern: "Brother Industries", Class: "printer", Confidence: 0.85, SourceURL: "https://x"},
	)
	for _, mac := range []string{macBrother, macBrother2, "001B.A911.2233"} {
		got := e.Classify(context.Background(), ClassifyInput{MACs: []string{mac}})
		if got.Class != "printer" {
			t.Errorf("%s: Class = %q, want printer (matched %+v)", mac, got.Class, got.MatchedRules)
		}
		if got.Vendor != "Brother Industries" {
			t.Errorf("%s: Vendor = %q, want Brother Industries", mac, got.Vendor)
		}
	}
}

// The engine hands the registry the FULL MAC, so a 28-bit MA-M block resolves
// to its own registrant. Looking up only the first three octets would find the
// Registration Authority's parent block — which the registry does not attribute
// to anybody — and the rule would never fire.
func TestOUIVendor_Resolves28BitBlocks(t *testing.T) {
	entry, ok := ouiregistry.Lookup(macKyocera28)
	if !ok || entry.Bits != 28 || entry.Vendor != "Kyocera" {
		t.Fatalf("fixture drift: Lookup(%s) = %+v, %v; want a 28-bit Kyocera block", macKyocera28, entry, ok)
	}
	if v := ouiregistry.VendorForMAC("4c:74:a7:01:23:45"); v == "Kyocera" {
		t.Fatal("fixture drift: 4C:74:A7 outside the E block is Kyocera too; the 28-bit case no longer proves anything")
	}

	e := mustEngine(t,
		Rule{Kind: KindOUIVendor, Pattern: "Kyocera", Class: "printer", Confidence: 0.80, SourceURL: "https://x"},
	)
	got := e.Classify(context.Background(), ClassifyInput{MACs: []string{macKyocera28}})
	if got.Class != "printer" || got.Vendor != "Kyocera" {
		t.Errorf("got class %q vendor %q, want printer / Kyocera (matched %+v)", got.Class, got.Vendor, got.MatchedRules)
	}
}

// The vendor flows with NO rule at all. Vendor-only knowledge is what the
// registry is for; requiring a rule row per vendor is exactly what this design
// retired.
func TestOUIVendor_VendorIsReportedWithoutAnyRule(t *testing.T) {
	e := mustEngine(t)
	got := e.Classify(context.Background(), ClassifyInput{MACs: []string{macCisco}})
	if got.Vendor != "Cisco Systems" {
		t.Errorf("Vendor = %q, want Cisco Systems", got.Vendor)
	}
	if !got.Unknown || got.Class != "" {
		t.Errorf("a vendor statement implied a class: %+v", got)
	}
	if want := []string{"Cisco Systems"}; strings.Join(registryStatements(got.MatchedRules), "|") != strings.Join(want, "|") {
		t.Errorf("MatchedRules = %+v; want the registry's statement for Cisco Systems in the audit trail", got.MatchedRules)
	}
	r := got.MatchedRules[0]
	if r.Confidence != RegistryVendorConfidence || r.SourceURL != RegistrySourceURL || r.ID != "" {
		t.Errorf("registry statement = %+v", r)
	}
}

// A registrant vendors.yaml does not name is REPORTED — it is what the IEEE
// says — but no rule ever matches it, even one spelled exactly like it: an
// uncanonicalised registrant string is not a stable thing to write a rule
// against.
func TestOUIVendor_NonCanonicalRegistrantIsReportedButNeverMatched(t *testing.T) {
	entry, ok := ouiregistry.Lookup(macUncanonical)
	if !ok || entry.Canonical {
		t.Fatalf("fixture drift: Lookup(%s) = %+v, %v; want a non-canonical registrant", macUncanonical, entry, ok)
	}

	e := mustEngine(t,
		Rule{Kind: KindOUIVendor, Pattern: entry.Vendor, Class: "printer", Confidence: 0.85, SourceURL: "https://x"},
	)
	got := e.Classify(context.Background(), ClassifyInput{MACs: []string{macUncanonical}})
	if got.Class != "" {
		t.Errorf("a rule matched a non-canonical registrant: class %q (matched %+v)", got.Class, got.MatchedRules)
	}
	if got.Vendor != entry.Vendor {
		t.Errorf("Vendor = %q, want the registrant %q", got.Vendor, entry.Vendor)
	}
}

// For one MAC, a prefix rule OUTRANKS the vendor rule: it is the more specific
// statement. The two must never produce a conflict against each other, so the
// prefix rule here is deliberately inside ConflictEpsilon of the vendor rule
// and names an unrelated class — counted together they WOULD conflict.
func TestOUIVendor_APrefixRuleOutranksTheVendorRuleForItsMAC(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindOUIVendor, Pattern: "Brother Industries", Class: "printer", Confidence: 0.85, SourceURL: "https://x"},
		Rule{Kind: KindOUI, Pattern: "001BA9", Class: "iot_device", Confidence: 0.80, SourceURL: "https://x"},
	)

	got := e.Classify(context.Background(), ClassifyInput{MACs: []string{macBrother}})
	if got.Conflict {
		t.Fatalf("a prefix rule and a vendor rule for the same MAC conflicted: %v", got.ConflictingClasses)
	}
	if got.Class != "iot_device" {
		t.Errorf("Class = %q, want the prefix rule's iot_device (matched %+v)", got.Class, got.MatchedRules)
	}
	for _, r := range got.MatchedRules {
		if r.Kind == KindOUIVendor && r.Class != "" {
			t.Errorf("the vendor rule was consulted for a MAC a prefix rule covers: %+v", r)
		}
	}
	// The prefix rule names no vendor, so the registry's still flows.
	if got.Vendor != "Brother Industries" {
		t.Errorf("Vendor = %q, want Brother Industries", got.Vendor)
	}

	// A different Brother assignment the prefix rule does not cover still gets
	// the vendor rule.
	got = e.Classify(context.Background(), ClassifyInput{MACs: []string{macBrother2}})
	if got.Class != "printer" {
		t.Errorf("other Brother MAC: Class = %q, want printer", got.Class)
	}
}

// A prefix rule that names its own vendor is the answer for that address, and
// the registry's statement is not added beside it.
func TestOUIVendor_APrefixRuleNamingAVendorReplacesTheRegistryStatement(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindOUI, Pattern: "001BA9", Vendor: "Brother", Confidence: 0.85, SourceURL: "https://x"},
	)
	got := e.Classify(context.Background(), ClassifyInput{MACs: []string{macBrother}})
	if got.Vendor != "Brother" {
		t.Errorf("Vendor = %q, want the prefix rule's Brother", got.Vendor)
	}
	if s := registryStatements(got.MatchedRules); len(s) != 0 {
		t.Errorf("registry statements %v added beside a prefix rule that names the vendor", s)
	}
}

// Two MACs resolving to two different canonical vendors propose NO vendor —
// the class conflict rule applied to vendors — and the audit trail names both.
// The class-bearing rule for one of them does not get to decide the vendor by
// out-scoring the other at a lower confidence.
func TestOUIVendor_TwoVendorsProposeNoVendor(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindOUIVendor, Pattern: "Cisco Systems", Class: "network_device", Confidence: 0.70, SourceURL: "https://x"},
	)
	got := e.Classify(context.Background(), ClassifyInput{MACs: []string{macBrother, macCisco}})
	if got.Vendor != "" {
		t.Errorf("Vendor = %q; two manufacturers were resolved and one was picked", got.Vendor)
	}
	stmts := registryStatements(got.MatchedRules)
	if strings.Join(stmts, "|") != "Brother Industries|Cisco Systems" {
		t.Errorf("registry statements = %v, want both vendors recorded", stmts)
	}
}

// An input Vendor is an ANSWER, returned as-is over anything the registry
// infers, and it still guards model rules.
func TestOUIVendor_AStatedVendorStillWins(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindModel, Pattern: "HL-", Class: "printer", Vendor: "Brother Industries", Confidence: 0.85, SourceURL: "https://x"},
	)
	got := e.Classify(context.Background(), ClassifyInput{MACs: []string{macCisco}, Vendor: "Brother Industries", Model: "HL-L2350DW"})
	if got.Vendor != "Brother Industries" {
		t.Errorf("Vendor = %q; the registry overrode what the device said", got.Vendor)
	}
	if got.Class != "printer" {
		t.Errorf("Class = %q, want printer", got.Class)
	}
	got = e.Classify(context.Background(), ClassifyInput{MACs: []string{macBrother}, Vendor: "Cisco Systems", Model: "HL-L2350DW"})
	if got.Class != "" {
		t.Errorf("a model rule for another vendor fired: %q", got.Class)
	}
}

func TestOUIVendor_Validate(t *testing.T) {
	long := strings.Repeat("x", MaxOUIVendorPatternLen+1)
	for _, tc := range []struct {
		name string
		rule Rule
		want string
	}{
		{"too long", Rule{Kind: KindOUIVendor, Pattern: long, Class: "printer", Confidence: 0.8}, "at most 64"},
		{"whitespace", Rule{Kind: KindOUIVendor, Pattern: " Canon", Class: "printer", Confidence: 0.8}, "whitespace"},
		{"vendor disagrees", Rule{Kind: KindOUIVendor, Pattern: "Canon", Vendor: "Ricoh", Class: "printer", Confidence: 0.8}, "vendor rule's vendor is its pattern"},
		{"no pattern", Rule{Kind: KindOUIVendor, Class: "printer", Confidence: 0.8}, "has no pattern"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.rule
			err := r.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Validate() = %v, want an error containing %q", err, tc.want)
			}
		})
	}

	r := Rule{Kind: KindOUIVendor, Pattern: "Canon", Class: "printer", Confidence: 0.8}
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if r.Vendor != "Canon" {
		t.Errorf("Vendor = %q; a vendor rule's vendor is its pattern", r.Vendor)
	}
}
