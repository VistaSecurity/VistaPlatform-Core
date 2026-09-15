package classify

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/hostobs"
)

// OUI -> vendor has exactly one owner: standards/oui-vendors.csv.
//
// Two packages read it. shared/hostobs compiles it into the sensor so a passive
// capture can name a manufacturer with no network call; this package derives an
// `oui` classification rule per prefix from the same file. Both are generated,
// from one source, which is the arrangement — and this test is what says the
// arrangement is still in force.
//
// It is not hypothetical. The first cut of standards/classification-rules.yaml
// carried 123 hand-written OUI rules; when the CSV landed, 27 of them disagreed
// with it about a vendor's own name for the SAME prefix — Netgear/NETGEAR,
// Brother/Brother Industries, Rockwell Automation/Allen-Bradley. Nothing would
// have failed. The two tables would simply have told a customer two different
// things about one device, depending on which code path answered.
func TestOUIRules_AgreeWithTheSharedVendorTable(t *testing.T) {
	rules := 0
	for _, r := range generatedRules {
		if r.Kind != KindOUI {
			continue
		}
		rules++

		if r.Vendor == "" {
			t.Errorf("oui rule %s has no vendor; every prefix in the CSV has one", r.Pattern)
			continue
		}

		// hostobs keys on the colon-separated lower-case spelling; a rule keys
		// on 6 uppercase hex digits. Same 24 bits, and the conversion here is
		// the only place that has to know both.
		mac := strings.ToLower(r.Pattern[0:2] + ":" + r.Pattern[2:4] + ":" + r.Pattern[4:6] + ":00:00:01")
		got := hostobs.VendorForMAC(mac)
		if got != r.Vendor {
			t.Errorf("prefix %s: classification rule says vendor %q, shared/hostobs says %q",
				r.Pattern, r.Vendor, got)
		}
	}

	if rules < 100 {
		t.Fatalf("only %d oui rules; they are no longer being derived from the CSV", rules)
	}

	// Every prefix in the shared table has a rule. A prefix the sensor can name
	// a vendor for but the classifier cannot is a gap with no reason to exist:
	// both read the same file.
	if rules != hostobs.OUICount() {
		t.Errorf("%d oui rules for %d prefixes in shared/hostobs — the two are no longer derived from one file",
			rules, hostobs.OUICount())
	}
}

// Most OUI rules carry a VENDOR and no class, and that is the rule of thumb
// working rather than a gap to be filled in.
//
// A manufacturer selling servers, switches and printers under one IEEE
// assignment has no majority worth guessing at. If this ratio ever inverts,
// somebody has been filling in blanks, and the next thing to happen is a
// plausible wrong class getting bulk-approved.
func TestOUIRules_AreMostlyVendorOnly(t *testing.T) {
	var withClass, vendorOnly int
	for _, r := range generatedRules {
		if r.Kind != KindOUI {
			continue
		}
		if r.Class == "" {
			vendorOnly++
		} else {
			withClass++
		}
	}
	if withClass == 0 {
		t.Fatal("no oui rule proposes a class; the oui_classes map is not being applied")
	}
	if vendorOnly <= withClass {
		t.Errorf("%d oui rules carry a class and only %d are vendor-only — "+
			"a wrong class is worse than none, and this ratio says the blanks are being filled in",
			withClass, vendorOnly)
	}
}

// The CAPABILITY vocabularies have exactly one owner too: shared/hostobs'
// decoders, which turn a CDP or 802.1AB bitmask into names.
//
// A `cdp_capabilities` or `lldp_capability` rule is written in those words, and
// this is the same silent-failure shape as the banner contract one section over:
// a rule whose pattern names `wlan_acess_point` is a perfectly valid rule — the
// generator's regexp accepts it, the engine's validator accepts it, the CHECK
// accepts it, and it matches NOTHING for any device, for ever, while nothing
// anywhere says so. The classifier just quietly stops proposing `access_point`.
//
// Neither validator can catch it, because neither knows the vocabulary. This
// does, and it is the only thing that does.
//
// Mutation-checked: change one capability name in the YAML, run
// `make generate`, and this fails naming the rule.
func TestCapabilityRules_SpeakTheDecodersVocabulary(t *testing.T) {
	known := map[string]map[string]bool{
		KindCDPCapabilities: setOf(hostobs.CDPCapabilityNames()),
		KindLLDPCapability:  setOf(hostobs.LLDPCapabilityNames()),
	}
	seen := 0
	for _, r := range Default().Rules() {
		vocab, ok := known[r.Kind]
		if !ok {
			continue
		}
		seen++
		for _, name := range strings.Split(r.Pattern, ",") {
			if !vocab[name] {
				t.Errorf("%s rule %q names capability %q, which shared/hostobs' decoder never emits — "+
					"the rule can never match anything, and nothing would report that",
					r.Kind, r.Pattern, name)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no capability rules were checked; this test would then prove nothing")
	}
}

func setOf(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, v := range values {
		out[v] = true
	}
	return out
}
