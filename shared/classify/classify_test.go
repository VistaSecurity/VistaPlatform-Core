package classify

import (
	"context"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
)

func mustEngine(t *testing.T, rules ...Rule) *Engine {
	t.Helper()
	e, err := NewStrict(rules)
	if err != nil {
		t.Fatalf("NewStrict: %v", err)
	}
	return e
}

// Every kind matches the evidence it is for, and only that evidence. One table,
// one case per kind, because a kind whose matcher was never exercised is a kind
// that can silently stop matching — the failure this package's whole point is
// to avoid downstream.
func TestClassify_EveryKindMatchesItsOwnEvidence(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name  string
		rule  Rule
		hit   ClassifyInput
		miss  ClassifyInput
		class string
	}{
		{
			name:  "oui",
			rule:  Rule{Kind: KindOUI, Pattern: "00000C", Class: "network_device", Vendor: "Cisco Systems", Confidence: 0.7, SourceURL: "https://x"},
			hit:   ClassifyInput{MACs: []string{"00:00:0c:11:22:33"}},
			miss:  ClassifyInput{MACs: []string{"00:00:0d:11:22:33"}},
			class: "network_device",
		},
		{
			name:  "sysobjectid",
			rule:  Rule{Kind: KindSysObjectID, Pattern: "1.3.6.1.4.1.3375", Class: "load_balancer", Vendor: "F5 Networks", Confidence: 0.8, SourceURL: "https://x"},
			hit:   ClassifyInput{SysObjectID: "1.3.6.1.4.1.3375.2.1.3.4.10"},
			miss:  ClassifyInput{SysObjectID: "1.3.6.1.4.1.9.1.1745"},
			class: "load_balancer",
		},
		{
			name:  "enip",
			rule:  Rule{Kind: KindENIP, Pattern: "1", Class: "ot_device", Vendor: "Rockwell", Confidence: 0.8, SourceURL: "https://x"},
			hit:   ClassifyInput{ENIPVendorID: 1},
			miss:  ClassifyInput{ENIPVendorID: 2},
			class: "ot_device",
		},
		{
			name:  "cloud_type",
			rule:  Rule{Kind: KindCloudType, Pattern: "aws_s3_bucket", Class: "object_storage", Confidence: 0.95, SourceURL: "https://x"},
			hit:   ClassifyInput{CloudResourceType: "AWS_S3_BUCKET"}, // case-insensitive
			miss:  ClassifyInput{CloudResourceType: "aws_rds_instance"},
			class: "object_storage",
		},
		{
			name:  "banner",
			rule:  Rule{Kind: KindBanner, Pattern: `(?i)^server:\s*nginx(?:[/ ]|$)`, Class: "web_application", Confidence: 0.65, SourceURL: "https://x"},
			hit:   ClassifyInput{Banners: map[string]string{"http": "Server: nginx/1.24.0"}},
			miss:  ClassifyInput{Banners: map[string]string{"http": "Server: Caddy"}},
			class: "web_application",
		},
		{
			name:  "port_profile",
			rule:  Rule{Kind: KindPortProfile, Pattern: "631,9100", Class: "printer", Confidence: 0.8, SourceURL: "https://x"},
			hit:   ClassifyInput{OpenPorts: []int{80, 443, 631, 9100}},
			miss:  ClassifyInput{OpenPorts: []int{80, 9100}}, // ALL ports required
			class: "printer",
		},
		{
			name:  "model",
			rule:  Rule{Kind: KindModel, Pattern: "C9300", Class: "switch", Vendor: "Cisco Systems", Confidence: 0.85, SourceURL: "https://x"},
			hit:   ClassifyInput{Model: "C9300-48P", Vendor: "Cisco Systems"},
			miss:  ClassifyInput{Model: "C9800-40", Vendor: "Cisco Systems"},
			class: "switch",
		},
		{
			name:  "platform",
			rule:  Rule{Kind: KindPlatform, Pattern: "fortios", Class: "firewall", Vendor: "Fortinet", Confidence: 0.8, SourceURL: "https://x"},
			hit:   ClassifyInput{Platform: "FortiOS"}, // case-insensitive
			miss:  ClassifyInput{Platform: "panos"},
			class: "firewall",
		},
		{
			name:  "cdp_capabilities",
			rule:  Rule{Kind: KindCDPCapabilities, Pattern: "router,switch", Class: "switch", Confidence: 0.7, SourceURL: "https://x"},
			hit:   ClassifyInput{CDPCapabilities: []string{"Router", "Switch", "IGMP"}}, // case-insensitive, extras ignored
			miss:  ClassifyInput{CDPCapabilities: []string{"router", "host"}},           // ALL names required
			class: "switch",
		},
		{
			name:  "lldp_capability",
			rule:  Rule{Kind: KindLLDPCapability, Pattern: "wlan_access_point", Class: "access_point", Confidence: 0.75, SourceURL: "https://x"},
			hit:   ClassifyInput{LLDPCapabilities: []string{"bridge", "wlan_access_point"}},
			miss:  ClassifyInput{LLDPCapabilities: []string{"bridge", "router"}},
			class: "access_point",
		},
		{
			name:  "mdns_service",
			rule:  Rule{Kind: KindMDNSService, Pattern: "_ipp._tcp", Class: "printer", Confidence: 0.75, SourceURL: "https://x"},
			hit:   ClassifyInput{MDNSServices: []string{"_workstation._tcp", "_IPP._tcp."}}, // folded, root dot trimmed
			miss:  ClassifyInput{MDNSServices: []string{"_ssh._tcp"}},
			class: "printer",
		},
		{
			name:  "os_name",
			rule:  Rule{Kind: KindOSName, Pattern: `(?i)\bwindows[ ]+server\b`, Class: "server", Confidence: 0.80, SourceURL: "https://x"},
			hit:   ClassifyInput{OS: "Microsoft Windows Server 2022 Datacenter"},
			miss:  ClassifyInput{OS: "Microsoft Windows 11 Pro"},
			class: "server",
		},
	}

	seen := map[string]bool{}
	for _, tc := range cases {
		seen[tc.rule.Kind] = true
		t.Run(tc.name, func(t *testing.T) {
			e := mustEngine(t, tc.rule)

			got := e.Classify(ctx, tc.hit)
			if got.Class != tc.class {
				t.Errorf("hit: Class = %q, want %q (matched %+v)", got.Class, tc.class, got.MatchedRules)
			}
			if got.Unknown {
				t.Error("hit: Unknown = true despite a class")
			}
			if len(got.MatchedRules) != 1 {
				t.Errorf("hit: matched %d rules, want 1", len(got.MatchedRules))
			}

			got = e.Classify(ctx, tc.miss)
			if got.Class != "" || !got.Unknown {
				t.Errorf("miss: got %+v, want an unknown proposal", got)
			}
			if got.Conflict {
				t.Error("miss: reported a conflict, but nothing matched")
			}
		})
	}

	// The table above IS the coverage claim, so it has to be checked rather
	// than trusted: a ninth kind added to Kinds with no case here would
	// otherwise look tested.
	for _, k := range Kinds {
		if !seen[k] {
			t.Errorf("kind %q has no case in this table — add one before adding rules for it", k)
		}
	}
}

// Two unrelated classes at similar confidence must produce NO class. This is
// the rule the package exists to hold: a plausible wrong proposal is the one
// that gets bulk-approved, so "we do not know" has to be a first-class answer.
func TestClassify_ConflictingClassesAtSimilarConfidenceProposeNothing(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindOUI, Pattern: "AAAAAA", Class: "firewall", Confidence: 0.80, SourceURL: "https://x"},
		Rule{Kind: KindPlatform, Pattern: "somewhere", Class: "load_balancer", Confidence: 0.80, SourceURL: "https://x"},
	)

	got := e.Classify(context.Background(), ClassifyInput{
		MACs:     []string{"aa:aa:aa:00:00:01"},
		Platform: "somewhere",
	})

	if got.Class != "" {
		t.Errorf("Class = %q; two rules disagreed and one of them was believed", got.Class)
	}
	if !got.Unknown {
		t.Error("Unknown = false on a conflict")
	}
	if !got.Conflict {
		t.Error("Conflict = false; the caller cannot tell a contradiction from a gap")
	}
	if got.Confidence != 0 {
		t.Errorf("Confidence = %v; no class was proposed, so there is nothing to be confident about", got.Confidence)
	}
	want := map[string]bool{"firewall": true, "load_balancer": true}
	if len(got.ConflictingClasses) != 2 {
		t.Fatalf("ConflictingClasses = %v, want both classes named", got.ConflictingClasses)
	}
	for _, c := range got.ConflictingClasses {
		if !want[c] {
			t.Errorf("ConflictingClasses names %q, which did not compete", c)
		}
	}
	// Both rules are still reported, so a reviewer can see the contradiction
	// and fix the catalogue rather than guess at it.
	if len(got.MatchedRules) != 2 {
		t.Errorf("MatchedRules = %d, want both rules reported", len(got.MatchedRules))
	}
}

// Three disagreeing rules are reported as three, not two. A reviewer shown only
// the top pair would fix half the contradiction and see it come back.
func TestClassify_ConflictReportsEveryClassWithinEpsilon(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindOUI, Pattern: "AAAAAA", Class: "firewall", Confidence: 0.80, SourceURL: "https://x"},
		Rule{Kind: KindPlatform, Pattern: "p", Class: "load_balancer", Confidence: 0.78, SourceURL: "https://x"},
		Rule{Kind: KindCloudType, Pattern: "ct", Class: "printer", Confidence: 0.75, SourceURL: "https://x"},
		// Far enough below the leader to be out of the argument entirely.
		Rule{Kind: KindENIP, Pattern: "9", Class: "storage_device", Confidence: 0.55, SourceURL: "https://x"},
	)

	got := e.Classify(context.Background(), ClassifyInput{
		MACs: []string{"aa:aa:aa:00:00:01"}, Platform: "p",
		CloudResourceType: "ct", ENIPVendorID: 9,
	})

	if got.Class != "" || !got.Conflict {
		t.Fatalf("got %+v, want a conflict with no class", got)
	}
	if len(got.ConflictingClasses) != 3 {
		t.Errorf("ConflictingClasses = %v, want the three within epsilon of the leader", got.ConflictingClasses)
	}
	for _, c := range got.ConflictingClasses {
		if c == "storage_device" {
			t.Error("a class 0.25 below the leader was reported as conflicting")
		}
	}
}

// A refinement is not a disagreement. An SNMP enterprise number saying
// `network_device` and a product id saying `switch` are one answer at two
// resolutions, and the engine must keep the better one rather than throw both
// away — which is what a naive conflict rule would do the moment the two
// confidences happened to land close together.
func TestClassify_AncestorAndDescendantResolveToTheSpecificClass(t *testing.T) {
	ctx := context.Background()

	t.Run("specific rule scores higher", func(t *testing.T) {
		e := mustEngine(t,
			Rule{Kind: KindOUI, Pattern: "AAAAAA", Class: "network_device", Confidence: 0.70, SourceURL: "https://x"},
			Rule{Kind: KindModel, Pattern: "C9300", Class: "switch", Confidence: 0.85, SourceURL: "https://x"},
		)
		got := e.Classify(ctx, ClassifyInput{MACs: []string{"aa:aa:aa:01:02:03"}, Model: "C9300-48P"})
		if got.Class != "switch" {
			t.Errorf("Class = %q, want switch", got.Class)
		}
	})

	// The case that matters: the GENERAL rule scores higher. The specific class
	// still wins, because it is not in conflict with its own ancestor.
	t.Run("general rule scores higher", func(t *testing.T) {
		e := mustEngine(t,
			Rule{Kind: KindOUI, Pattern: "AAAAAA", Class: "network_device", Confidence: 0.90, SourceURL: "https://x"},
			Rule{Kind: KindModel, Pattern: "C9300", Class: "switch", Confidence: 0.85, SourceURL: "https://x"},
		)
		got := e.Classify(ctx, ClassifyInput{MACs: []string{"aa:aa:aa:01:02:03"}, Model: "C9300-48P"})
		if got.Class != "switch" {
			t.Errorf("Class = %q, want switch — an ancestor must not out-argue its own descendant", got.Class)
		}
		if got.Conflict {
			t.Error("Conflict = true; network_device and switch are one answer at two resolutions")
		}
	})

	// A refinement must not HIDE a real disagreement sitting behind it.
	//
	// network_device 0.80, firewall 0.78, switch 0.77. Comparing only the top
	// two found network_device and firewall related, returned `firewall` as the
	// refinement, and never looked at `switch` — which is one hundredth away
	// from firewall, is not related to it, and is exactly the contradiction the
	// conflict rule exists to refuse. The honest answer here is neither.
	t.Run("an unrelated third class is not hidden behind a refinement", func(t *testing.T) {
		e := mustEngine(t,
			Rule{Kind: KindOUI, Pattern: "AAAAAA", Class: "network_device", Confidence: 0.80, SourceURL: "https://x"},
			Rule{Kind: KindPlatform, Pattern: "somefw", Class: "firewall", Confidence: 0.78, SourceURL: "https://x"},
			Rule{Kind: KindModel, Pattern: "C9300", Class: "switch", Confidence: 0.77, SourceURL: "https://x"},
		)
		got := e.Classify(ctx, ClassifyInput{
			MACs: []string{"aa:aa:aa:01:02:03"}, Platform: "somefw", Model: "C9300-48P",
		})
		if got.Class != "" || !got.Conflict {
			t.Errorf("Class = %q, Conflict = %v; want no class and a conflict — firewall and switch "+
				"are unrelated and one hundredth apart", got.Class, got.Conflict)
		}
		if len(got.ConflictingClasses) != 2 {
			t.Errorf("ConflictingClasses = %v, want the two that actually disagree "+
				"(their common ancestor is not a third opinion)", got.ConflictingClasses)
		}
	})

	// The same three-candidate shape where the third is NOT in conflict still
	// resolves — the drop must not turn every refinement into a stand-off.
	t.Run("a distant third class does not create a conflict", func(t *testing.T) {
		e := mustEngine(t,
			Rule{Kind: KindOUI, Pattern: "AAAAAA", Class: "network_device", Confidence: 0.80, SourceURL: "https://x"},
			Rule{Kind: KindModel, Pattern: "C9300", Class: "switch", Confidence: 0.78, SourceURL: "https://x"},
			Rule{Kind: KindBanner, Pattern: `(?i)web`, Class: "web_application", Confidence: 0.60, SourceURL: "https://x"},
		)
		got := e.Classify(ctx, ClassifyInput{
			MACs:    []string{"aa:aa:aa:01:02:03"},
			Model:   "C9300-48P",
			Banners: map[string]string{"http": "Server: webthing"},
		})
		if got.Class != "switch" || got.Conflict {
			t.Errorf("Class = %q, Conflict = %v; want switch and no conflict", got.Class, got.Conflict)
		}
	})
}

// Confidence ordering decides between unrelated classes that are far enough
// apart, and the winner's own confidence is what the proposal carries.
func TestClassify_HighestConfidenceUnrelatedClassWins(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindOUI, Pattern: "AAAAAA", Class: "printer", Confidence: 0.85, SourceURL: "https://x"},
		Rule{Kind: KindBanner, Pattern: `(?i)web`, Class: "web_application", Confidence: 0.65, SourceURL: "https://x"},
	)

	got := e.Classify(context.Background(), ClassifyInput{
		MACs:    []string{"aa:aa:aa:01:02:03"},
		Banners: map[string]string{"http": "web thing"},
	})

	if got.Class != "printer" {
		t.Errorf("Class = %q, want printer", got.Class)
	}
	if got.Confidence != 0.85 {
		t.Errorf("Confidence = %v, want the winning rule's 0.85", got.Confidence)
	}
	if got.Conflict {
		t.Error("Conflict = true; 0.20 apart is not a tie")
	}
	// The loser is still reported: a reviewer asking why this is a printer and
	// not a web app should be able to see that both were considered.
	if len(got.MatchedRules) != 2 {
		t.Errorf("MatchedRules = %d, want the losing rule reported too", len(got.MatchedRules))
	}
	if got.MatchedRules[0].Class != "printer" {
		t.Errorf("MatchedRules is not ordered by confidence: %+v", got.MatchedRules)
	}
}

// Evidence supporting one class does not ACCUMULATE. Three rules naming Cisco
// are three views of one fact, and letting them out-score a single better rule
// would make the catalogue's size, not its quality, decide the answer.
func TestClassify_MatchingRulesDoNotAccumulateConfidence(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindOUI, Pattern: "AAAAAA", Class: "printer", Confidence: 0.60, SourceURL: "https://x"},
		Rule{Kind: KindOUI, Pattern: "BBBBBB", Class: "printer", Confidence: 0.60, SourceURL: "https://x"},
		Rule{Kind: KindPortProfile, Pattern: "631,9100", Class: "printer", Confidence: 0.60, SourceURL: "https://x"},
		Rule{Kind: KindPlatform, Pattern: "p", Class: "iot_device", Confidence: 0.80, SourceURL: "https://x"},
	)

	got := e.Classify(context.Background(), ClassifyInput{
		MACs:      []string{"aa:aa:aa:01:02:03", "bb:bb:bb:01:02:03"},
		OpenPorts: []int{631, 9100},
		Platform:  "p",
	})

	if got.Class != "iot_device" {
		t.Errorf("Class = %q, want iot_device — three 0.60 rules out-voted one 0.80 rule", got.Class)
	}
}

// Unknown stays unknown. ADR-0008 D4.3, and the reason the null classifier
// exists in the shape it does.
func TestClassify_NoEvidenceIsUnknownNotAGuess(t *testing.T) {
	got := Default().Classify(context.Background(), ClassifyInput{})

	if got.Class != "" {
		t.Errorf("Class = %q; an empty input produced a class", got.Class)
	}
	if !got.Unknown {
		t.Error("Unknown = false for an empty input")
	}
	if got.Conflict {
		t.Error("Conflict = true for an empty input; nothing was even considered")
	}
	if got.Confidence != 0 {
		t.Errorf("Confidence = %v; no claim was made", got.Confidence)
	}
	if len(got.MatchedRules) != 0 {
		t.Errorf("MatchedRules = %+v; nothing should have matched", got.MatchedRules)
	}
}

// Evidence that resolves a VENDOR but no class is the normal shape of an OUI
// rule, not a degenerate one. The proposal has to carry the vendor and still
// say Unknown.
func TestClassify_VendorWithoutClassIsStillUnknown(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindOUI, Pattern: "00188B", Vendor: "Dell Inc.", Confidence: 0.85, SourceURL: "https://x"},
	)

	got := e.Classify(context.Background(), ClassifyInput{MACs: []string{"00:18:8b:aa:bb:cc"}})

	if got.Vendor != "Dell Inc." {
		t.Errorf("Vendor = %q, want Dell Inc.", got.Vendor)
	}
	if got.Class != "" || !got.Unknown {
		t.Errorf("got %+v; a vendor-only rule must not imply a class", got)
	}
	if len(got.MatchedRules) != 1 {
		t.Errorf("MatchedRules = %d; the vendor-only rule must still be reported", len(got.MatchedRules))
	}
}

// A vendor the device stated beats a vendor a rule inferred. This is the same
// precedence snmpIdentity applied before the rule table existed: a device that
// names itself has given us a measured fact, an OUI has given us an inference.
func TestClassify_StatedVendorBeatsAnInferredOne(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindOUI, Pattern: "005056", Vendor: "VMware", Class: "virtual_machine", Confidence: 0.85, SourceURL: "https://x"},
	)

	got := e.Classify(context.Background(), ClassifyInput{
		MACs:   []string{"00:50:56:aa:bb:cc"},
		Vendor: "Dell Inc.",
	})

	if got.Vendor != "Dell Inc." {
		t.Errorf("Vendor = %q; the rule overrode what the device said about itself", got.Vendor)
	}
	// The class still comes from the rule — the input said nothing about class.
	if got.Class != "virtual_machine" {
		t.Errorf("Class = %q, want virtual_machine", got.Class)
	}
}

// Two rules naming DIFFERENT vendors at similar confidence yield no vendor, the
// same way they yield no class. A device with two NICs from two manufacturers
// is real, and picking one at random would put a fabricated manufacturer into
// hw.vendor — which is half the key into the hardware end-of-life catalogue.
func TestClassify_ConflictingVendorsProposeNoVendor(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindOUI, Pattern: "001B21", Vendor: "Intel", Confidence: 0.85, SourceURL: "https://x"},
		Rule{Kind: KindOUI, Pattern: "00188B", Vendor: "Dell Inc.", Confidence: 0.85, SourceURL: "https://x"},
	)

	got := e.Classify(context.Background(), ClassifyInput{
		MACs: []string{"00:1b:21:aa:bb:cc", "00:18:8b:aa:bb:cc"},
	})

	if got.Vendor != "" {
		t.Errorf("Vendor = %q; two manufacturers were named and one was picked", got.Vendor)
	}
	if len(got.MatchedRules) != 2 {
		t.Errorf("MatchedRules = %d, want both", len(got.MatchedRules))
	}
}

// The longest sysObjectID prefix answers, and only it. A product-tree rule an
// admin adds must REPLACE the enterprise-level answer, not argue with it.
func TestClassify_SysObjectIDTakesTheLongestPrefixOnly(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindSysObjectID, Pattern: "1.3.6.1.4.1.9", Class: "network_device", Vendor: "Cisco Systems", Confidence: 0.70, SourceURL: "https://x"},
		Rule{Kind: KindSysObjectID, Pattern: "1.3.6.1.4.1.9.1.1745", Class: "switch", Vendor: "Cisco Systems", Model: "Catalyst 9300", Confidence: 0.85, SourceURL: "https://x"},
	)

	got := e.Classify(context.Background(), ClassifyInput{SysObjectID: ".1.3.6.1.4.1.9.1.1745"})

	if got.Class != "switch" {
		t.Errorf("Class = %q, want switch", got.Class)
	}
	if got.Model != "Catalyst 9300" {
		t.Errorf("Model = %q, want Catalyst 9300", got.Model)
	}
	if len(got.MatchedRules) != 1 {
		t.Errorf("MatchedRules = %d, want only the longest-prefix rule", len(got.MatchedRules))
	}
}

// Arc boundaries, not string prefixes. Enterprise 4526 (Netgear) must not match
// a rule for enterprise 452, which is exactly the silent misattribution a
// strings.HasPrefix would produce.
func TestClassify_SysObjectIDMatchesOnArcBoundaries(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindSysObjectID, Pattern: "1.3.6.1.4.1.452", Vendor: "Not Netgear", Confidence: 0.85, SourceURL: "https://x"},
	)

	got := e.Classify(context.Background(), ClassifyInput{SysObjectID: "1.3.6.1.4.1.4526.100.4.1"})

	if len(got.MatchedRules) != 0 {
		t.Errorf("enterprise 4526 matched a rule for enterprise 452: %+v", got.MatchedRules)
	}
}

// Longest model prefix wins, so AIR-CT (a controller) is not read as AIR- (an
// access point).
func TestClassify_ModelTakesTheLongestPrefix(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindModel, Pattern: "AIR-", Class: "access_point", Vendor: "Cisco Systems", Confidence: 0.85, SourceURL: "https://x"},
		Rule{Kind: KindModel, Pattern: "AIR-CT", Class: "wireless_controller", Vendor: "Cisco Systems", Confidence: 0.85, SourceURL: "https://x"},
	)
	ctx := context.Background()

	if got := e.Classify(ctx, ClassifyInput{Model: "AIR-CT5520-K9"}); got.Class != "wireless_controller" {
		t.Errorf("AIR-CT5520-K9: Class = %q, want wireless_controller", got.Class)
	}
	if got := e.Classify(ctx, ClassifyInput{Model: "AIR-AP3802I-B-K9"}); got.Class != "access_point" {
		t.Errorf("AIR-AP3802I: Class = %q, want access_point", got.Class)
	}
}

// A model rule that names a vendor does not fire for a different one. That
// guard is what lets short prefixes like "usw" live in the table at all.
func TestClassify_ModelRuleIsScopedToItsVendor(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindModel, Pattern: "usw", Class: "switch", Vendor: "Ubiquiti", Confidence: 0.85, SourceURL: "https://x"},
	)
	ctx := context.Background()

	if got := e.Classify(ctx, ClassifyInput{Vendor: "Ubiquiti", Model: "usw"}); got.Class != "switch" {
		t.Errorf("Ubiquiti usw: Class = %q, want switch", got.Class)
	}
	if got := e.Classify(ctx, ClassifyInput{Vendor: "Some Other Co", Model: "USW-Pro"}); got.Class != "" {
		t.Errorf("another vendor's USW- model matched a Ubiquiti rule: %+v", got)
	}
	// With no vendor stated the rule still fires — the prefix is the curator's
	// judgement, and refusing to match would lose the UniFi path entirely,
	// since the controller states a type and not a manufacturer.
	if got := e.Classify(ctx, ClassifyInput{Model: "usw"}); got.Class != "switch" {
		t.Errorf("usw with no vendor: Class = %q, want switch", got.Class)
	}
}

// MACs in every spelling resolve to the same assignment, and the placeholders
// resolve to none.
func TestOUIOf(t *testing.T) {
	cases := map[string]string{
		"00:1b:63:aa:bb:cc": "001B63",
		"00-1B-63-AA-BB-CC": "001B63",
		"001b.63aa.bbcc":    "001B63",
		"001B63AABBCC":      "001B63",
		"":                  "",
		"00:1b:63":          "",
		"00:00:00:00:00:00": "", // placeholder, not an identity
		"ff:ff:ff:ff:ff:ff": "", // broadcast, not an identity
		"zz:1b:63:aa:bb:cc": "",
	}
	for in, want := range cases {
		if got := ouiOf(in); got != want {
			t.Errorf("ouiOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// A duplicate MAC must not turn one rule into two matches. Two NICs on the same
// OUI are one fact about the manufacturer.
func TestClassify_RepeatedOUIMatchesOnce(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindOUI, Pattern: "005056", Vendor: "VMware", Class: "virtual_machine", Confidence: 0.85, SourceURL: "https://x"},
	)

	got := e.Classify(context.Background(), ClassifyInput{
		MACs: []string{"00:50:56:aa:bb:01", "00:50:56:aa:bb:02"},
	})

	if len(got.MatchedRules) != 1 {
		t.Errorf("MatchedRules = %d, want 1", len(got.MatchedRules))
	}
}

// --- validation -------------------------------------------------------------

// New refuses a bad rule rather than dropping it. A rule set that silently lost
// three entries is a classifier that silently stopped proposing three classes.
func TestNew_RejectsInvalidRules(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
		want string
	}{
		{"unknown kind", Rule{Kind: "astrology", Pattern: "x", Class: "server", Confidence: 0.8, SourceURL: "u"}, "unknown kind"},
		{"no pattern", Rule{Kind: KindOUI, Class: "server", Confidence: 0.8, SourceURL: "u"}, "has no pattern"},
		{"asserts nothing", Rule{Kind: KindOUI, Pattern: "AABBCC", Confidence: 0.8, SourceURL: "u"}, "asserts nothing"},
		{"unknown class", Rule{Kind: KindOUI, Pattern: "AABBCC", Class: "toaster", Confidence: 0.8, SourceURL: "u"}, "not in standards/asset-classes.yaml"},
		{"confidence too low", Rule{Kind: KindOUI, Pattern: "AABBCC", Class: "server", Confidence: 0.2, SourceURL: "u"}, "outside"},
		{"confidence too high", Rule{Kind: KindOUI, Pattern: "AABBCC", Class: "server", Confidence: 1.0, SourceURL: "u"}, "outside"},
		{"lowercase oui", Rule{Kind: KindOUI, Pattern: "aabbcc", Class: "server", Confidence: 0.8, SourceURL: "u"}, "6 uppercase hex digits"},
		{"oui with separators", Rule{Kind: KindOUI, Pattern: "AA:BB:CC", Class: "server", Confidence: 0.8, SourceURL: "u"}, "6 uppercase hex digits"},
		{"oid outside the enterprise arc", Rule{Kind: KindSysObjectID, Pattern: "1.3.6.1.2.1.1", Class: "server", Confidence: 0.8, SourceURL: "u"}, "private-enterprise arc"},
		{"non-numeric enip id", Rule{Kind: KindENIP, Pattern: "rockwell", Class: "ot_device", Confidence: 0.8, SourceURL: "u"}, "decimal ODVA vendor id"},
		{"banner that does not compile", Rule{Kind: KindBanner, Pattern: "(unclosed", Class: "web_application", Confidence: 0.6, SourceURL: "u"}, "does not compile"},
		{"banner with lookahead RE2 refuses", Rule{Kind: KindBanner, Pattern: "(?=x)", Class: "web_application", Confidence: 0.6, SourceURL: "u"}, "does not compile"},
		{"single-port profile", Rule{Kind: KindPortProfile, Pattern: "9100", Class: "printer", Confidence: 0.8, SourceURL: "u"}, "one open port is not a profile"},
		{"unsorted port profile", Rule{Kind: KindPortProfile, Pattern: "9100,631", Class: "printer", Confidence: 0.8, SourceURL: "u"}, "ascending and deduplicated"},
		{"duplicate port", Rule{Kind: KindPortProfile, Pattern: "9100,9100", Class: "printer", Confidence: 0.8, SourceURL: "u"}, "ascending and deduplicated"},
		{"port out of range", Rule{Kind: KindPortProfile, Pattern: "631,99999", Class: "printer", Confidence: 0.8, SourceURL: "u"}, "out of range"},
		{"padded model", Rule{Kind: KindModel, Pattern: " C9300 ", Class: "switch", Confidence: 0.8, SourceURL: "u"}, "whitespace"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewStrict([]Rule{tc.rule})
			if err == nil {
				t.Fatalf("NewStrict accepted %+v", tc.rule)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// --- the generated table ----------------------------------------------------

// Every generated rule passes the engine's own validation. This is the gate the
// JS generator cannot be: Go's RE2 is what actually compiles the banner
// patterns, and a JS RegExp accepts constructs RE2 refuses.
func TestGeneratedRules_AreValid(t *testing.T) {
	e, err := NewStrict(generatedRules)
	if err != nil {
		t.Fatalf("the generated rule table does not pass Rule.Validate: %v", err)
	}
	if e.Len() < 100 {
		t.Fatalf("only %d generated rules; the table has lost most of itself", e.Len())
	}
	if e.Len() != len(generatedRules) {
		t.Errorf("engine holds %d of %d generated rules", e.Len(), len(generatedRules))
	}
}

// Every class a generated rule proposes exists in the taxonomy. A proposal for
// a class nothing recognises reaches Approvals as something the reviewer cannot
// act on, which is strictly worse than no proposal — the same check
// classhint_test.go carried before these rules existed, now over the table.
func TestGeneratedRules_ProposeOnlyRegisteredClasses(t *testing.T) {
	classed := 0
	for _, r := range generatedRules {
		if r.Class == "" {
			continue
		}
		classed++
		if _, ok := assetclass.Get(r.Class); !ok {
			t.Errorf("rule %s/%s proposes class %q, which is not in standards/asset-classes.yaml", r.Kind, r.Pattern, r.Class)
		}
	}
	if classed < 50 {
		t.Fatalf("only %d generated rules carry a class; the walk has stopped finding them", classed)
	}
}

// Every generated rule cites something. Enforced here as well as in the
// generator because a rule loaded from the database has not been through the
// generator at all, and this is the assertion that says the SEEDED ones did.
func TestGeneratedRules_EveryRuleCitesASource(t *testing.T) {
	for _, r := range generatedRules {
		if !strings.HasPrefix(r.SourceURL, "http") {
			t.Errorf("rule %s/%s has source_url %q", r.Kind, r.Pattern, r.SourceURL)
		}
	}
}

// (kind, pattern) is the table's unique index, so a duplicate in the generated
// set means the seed's ON CONFLICT silently collapses two rules into one while
// the Go table keeps both — the two homes disagreeing, quietly.
func TestGeneratedRules_HaveNoDuplicateIdentity(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range generatedRules {
		id := r.Kind + "\x00" + r.Pattern
		if seen[id] {
			t.Errorf("duplicate rule: %s/%s", r.Kind, r.Pattern)
		}
		seen[id] = true
	}
}

// The seeded table must not contradict itself on any single piece of evidence.
//
// Two rules of the same kind and pattern are caught above; this catches the
// subtler case — two rules that would match the SAME device and propose
// unrelated classes at similar confidence, which the engine would then refuse
// to decide. That is correct behaviour for a curated rule an admin added, and a
// bug in the seed, where we control both rules.
func TestGeneratedRules_DoNotConflictOnOneOUI(t *testing.T) {
	e := Default()
	ctx := context.Background()
	for _, r := range generatedRules {
		if r.Kind != KindOUI {
			continue
		}
		mac := r.Pattern + "AABBCC"
		got := e.Classify(ctx, ClassifyInput{MACs: []string{mac}})
		if got.Conflict {
			t.Errorf("OUI %s alone produces a conflict between %v — two seeded rules disagree",
				r.Pattern, got.ConflictingClasses)
		}
	}
}

// One manufacturer, one name — proved on the SEEDED table, through the engine.
//
// The rules in this table come from two files: the OUI rules are DERIVED from
// standards/oui-vendors.csv, and every other kind is hand-written in
// standards/classification-rules.yaml. When the two spelled a manufacturer
// differently they did not disagree loudly — the vendor arbitration refuses to
// choose between two names inside the conflict epsilon, so they CANCELLED. A
// Dell server seen by both its MAC and its sysObjectID came back with no vendor
// and, because both rules were vendor-only, no class either: strictly less than
// either piece of evidence would have given on its own.
//
// Every case here is a real device presenting two pieces of evidence at once,
// which is the normal case for anything an SNMP walk reaches. The generator's
// vendor-spelling gate is what keeps this true; this is what says the gate is
// aimed at the right thing.
func TestGeneratedRules_TwoPiecesOfEvidenceNeverCancelTheVendor(t *testing.T) {
	e := Default()
	ctx := context.Background()

	cases := []struct {
		name       string
		in         ClassifyInput
		wantVendor string
	}{
		{"Dell server: MAC + sysObjectID", ClassifyInput{
			MACs: []string{"00:06:5b:11:22:33"}, SysObjectID: "1.3.6.1.4.1.674.10892.5",
		}, "Dell"},
		{"HP: MAC + sysObjectID", ClassifyInput{
			MACs: []string{"00:01:e6:11:22:33"}, SysObjectID: "1.3.6.1.4.1.11.2.3.9",
		}, "Hewlett Packard"},
		{"APC UPS: MAC + sysObjectID", ClassifyInput{
			MACs: []string{"00:c0:b7:11:22:33"}, SysObjectID: "1.3.6.1.4.1.318.1.1.1",
		}, "American Power Conversion"},
		{"NETGEAR switch: MAC + sysObjectID", ClassifyInput{
			MACs: []string{"00:09:5b:11:22:33"}, SysObjectID: "1.3.6.1.4.1.4526.100",
		}, "NETGEAR"},
		{"Huawei: MAC + sysObjectID", ClassifyInput{
			MACs: []string{"00:18:82:11:22:33"}, SysObjectID: "1.3.6.1.4.1.2011.2",
		}, "Huawei Technologies"},
		{"UniFi switch: MAC + controller device type", ClassifyInput{
			MACs: []string{"00:15:6d:11:22:33"}, Model: "usw",
		}, "Ubiquiti Networks"},
		{"UniFi gateway: MAC + sysObjectID", ClassifyInput{
			MACs: []string{"00:15:6d:11:22:33"}, SysObjectID: "1.3.6.1.4.1.41112.1",
		}, "Ubiquiti Networks"},
		{"Allen-Bradley PLC: MAC + EtherNet/IP identity", ClassifyInput{
			MACs: []string{"00:00:bc:11:22:33"}, ENIPVendorID: 1,
		}, "Rockwell Automation"},
	}

	for _, tc := range cases {
		got := e.Classify(ctx, tc.in)
		if got.Vendor != tc.wantVendor {
			t.Errorf("%s: Vendor = %q, want %q — two rules naming the same manufacturer "+
				"differently cancelled each other (matched: %+v)",
				tc.name, got.Vendor, tc.wantVendor, got.MatchedRules)
		}
	}
}

// The UniFi switch above must also still get its CLASS, which is the second
// thing a vendor-spelling mismatch breaks and the one that fails silently.
//
// A `model` rule that names a vendor is skipped when the input names a DIFFERENT
// one — that guard is what lets a three-letter prefix like "usw" live in the
// table at all. It is also a guard that, on a spelling variant, produces no
// error and no matched rule and no class: the device just comes back
// unclassified, and nothing anywhere says why.
func TestClassify_ModelRuleSurvivesAVendorSpellingVariant(t *testing.T) {
	e := Default()
	ctx := context.Background()

	for _, vendor := range []string{"Ubiquiti Networks", "Ubiquiti", "ubiquiti networks", "UBIQUITI-NETWORKS"} {
		got := e.Classify(ctx, ClassifyInput{Vendor: vendor, Model: "usw"})
		if got.Class != "switch" {
			t.Errorf("vendor %q + model usw: Class = %q, want switch", vendor, got.Class)
		}
	}

	// And the guard still guards. A model rule scoped to Ubiquiti must not fire
	// for a manufacturer that merely shares some letters with it — nor, and this
	// is the deliberate limit of a prefix rule, for a name that diverges after
	// the shared stem. "Ubiquiti, Inc." does not agree with "Ubiquiti Networks"
	// here, and it should not: a rule loose enough to merge those two is loose
	// enough to merge "Cisco Systems" with "Cisco Meraki".
	for _, vendor := range []string{"Cisco Systems", "Ubiquity Systems Ltd", "NETGEAR", "Ubiquiti, Inc."} {
		got := e.Classify(ctx, ClassifyInput{Vendor: vendor, Model: "usw"})
		if got.Class != "" {
			t.Errorf("vendor %q + model usw: Class = %q, want none — the vendor guard let a "+
				"foreign model prefix through", vendor, got.Class)
		}
	}
}

// vendorAgrees decides both of the above, and it has to be wrong in neither
// direction: too strict and one manufacturer's two spellings cancel, too loose
// and two manufacturers merge into one.
func TestVendorAgrees(t *testing.T) {
	same := [][2]string{
		{"Dell", "Dell Inc."},
		{"Ubiquiti Networks", "Ubiquiti"},
		{"NETGEAR", "Netgear"},
		{"Hewlett Packard", "Hewlett-Packard"},
		{"Brother Industries", "Brother"},
		{"IBM", "IBM Corp"},
	}
	for _, p := range same {
		if !vendorAgrees(p[0], p[1]) || !vendorAgrees(p[1], p[0]) {
			t.Errorf("vendorAgrees(%q, %q) = false, want true", p[0], p[1])
		}
	}

	different := [][2]string{
		{"Cisco Systems", "Cisco Meraki"},
		{"Allen-Bradley", "Rockwell Automation"},
		{"Fortinet", "F5 Networks"},
		// Below the three-character floor: two letters are not enough to
		// conclude anything, or "HP" would be a licence to match every
		// manufacturer whose name starts that way.
		{"HP", "HPE Networking"},
		{"", "Dell"},
		{"Dell", ""},
	}
	for _, p := range different {
		if vendorAgrees(p[0], p[1]) || vendorAgrees(p[1], p[0]) {
			t.Errorf("vendorAgrees(%q, %q) = true, want false", p[0], p[1])
		}
	}
}

// The os_name rules, over the SHIPPED table, against the OS names the
// collectors actually report.
//
// This is the end of the chain the reclassification fix depends on, and it is
// the one part of it a unit test can hold on its own. The asset that prompted
// the fix is a Dell XPS 16 running Windows 11 Pro, fully inventoried — OS,
// vendor, model, serial, 106 packages, 83 listening sockets — and it stayed
// `unknown_host` because no rule kind could read any of it: its OUI belongs to
// Dell and is vendor-only, it answers no SNMP, it advertises nothing, and
// "XPS 16 9640" is a consumer product line no catalogue enumerates. If these
// rules stop firing, the fix downstream still runs and still changes nothing,
// which is exactly the shape of failure this repo keeps paying for.
//
// Both polarities. A Linux distribution must stay unclassified: Debian runs on
// a rack server, a laptop, a firewall and a printer alike, and there is no
// spelling of "Ubuntu" that means `server`.
func TestGeneratedRules_ClassifyAHostByItsOperatingSystem(t *testing.T) {
	e := Default()
	ctx := context.Background()

	for _, tc := range []struct {
		os    string
		class string
	}{
		// The reported asset, and the other spellings of it that reach
		// `os.name` from different collectors.
		{"Microsoft Windows 11 Pro", "computer"},
		{"Windows 11 Pro", "computer"},
		{"Microsoft Windows 10 Enterprise", "computer"},
		{"Windows 7 Professional", "computer"},
		{"macOS 15.1", "computer"},
		{"Mac OS X 10.15.7", "computer"},

		// Server editions are their own product line with one meaning, and
		// `server` refines `computer` rather than arguing with it.
		{"Microsoft Windows Server 2022 Datacenter", "server"},
		{"Windows Server 2019 Standard", "server"},

		// Deliberately unclassified. See the os_name block in
		// standards/classification-rules.yaml for why each one gets no rule.
		{"Ubuntu", ""},
		{"Debian GNU/Linux 12 (bookworm)", ""},
		{"Red Hat Enterprise Linux 9.4", ""},
		{"FreeBSD 14.1-RELEASE", ""},
		{"", ""},
	} {
		t.Run(tc.os, func(t *testing.T) {
			got := e.Classify(ctx, ClassifyInput{OS: tc.os})
			if got.Class != tc.class {
				t.Errorf("os.name %q classified as %q, want %q (matched %+v)",
					tc.os, got.Class, tc.class, got.MatchedRules)
			}
			if tc.class == "" && !got.Unknown {
				t.Errorf("os.name %q: Unknown = false with no class", tc.os)
			}
		})
	}
}

// A client Windows release must not out-argue the whole taxonomy. The rule
// proposes `computer` — the common ancestor of workstation and laptop — and a
// LATER, better-evidenced rule has to be able to refine it, which is the whole
// reason it stops at the ancestor rather than guessing `workstation`.
func TestGeneratedRules_AnOSClassIsRefinableByBetterEvidence(t *testing.T) {
	e, err := NewStrict(append(append([]Rule(nil), generatedRules...),
		Rule{Kind: KindOUI, Pattern: "AAAAAA", Class: "laptop", Confidence: 0.85, SourceURL: "https://x"}))
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}

	got := e.Classify(context.Background(), ClassifyInput{
		OS:   "Microsoft Windows 11 Pro",
		MACs: []string{"aa:aa:aa:00:00:01"},
	})
	if got.Class != "laptop" {
		t.Errorf("Class = %q, want laptop — `computer` is an ancestor of it and must drop out, not tie", got.Class)
	}
	if got.Conflict {
		t.Errorf("reported a conflict between a class and its own ancestor: %v", got.ConflictingClasses)
	}
}
