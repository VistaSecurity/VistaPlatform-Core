package seams

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/ai"
	"github.com/vistasecurity/vistaplatform/shared/classify"
)

func mustRuleEngine(t *testing.T, rules ...classify.Rule) *classify.Engine {
	t.Helper()
	e, err := classify.NewStrict(rules)
	if err != nil {
		t.Fatalf("classify.NewStrict: %v", err)
	}
	return e
}

// The adapter reads every ClassifyInput field out of AssetFacts. One rule per
// field, all at once, so a field the adapter forgot to map shows up as a
// missing match rather than as a classification that is quietly worse.
func TestRuleClassifier_MapsEveryInputFieldOutOfAssetFacts(t *testing.T) {
	engine := mustRuleEngine(t,
		classify.Rule{Kind: classify.KindOUI, Pattern: "005056", Vendor: "VMware", Confidence: 0.85, SourceURL: "u"},
		classify.Rule{Kind: classify.KindSysObjectID, Pattern: "1.3.6.1.4.1.9", Vendor: "Cisco Systems", Confidence: 0.85, SourceURL: "u"},
		classify.Rule{Kind: classify.KindENIP, Pattern: "1", Vendor: "Rockwell", Confidence: 0.80, SourceURL: "u"},
		classify.Rule{Kind: classify.KindCloudType, Pattern: "aws_s3_bucket", Model: "bucket", Confidence: 0.95, SourceURL: "u"},
		classify.Rule{Kind: classify.KindBanner, Pattern: `(?i)nginx`, Model: "nginx", Confidence: 0.65, SourceURL: "u"},
		classify.Rule{Kind: classify.KindPortProfile, Pattern: "631,9100", Model: "printer-profile", Confidence: 0.80, SourceURL: "u"},
		classify.Rule{Kind: classify.KindModel, Pattern: "C9300", Model: "catalyst", Confidence: 0.85, SourceURL: "u"},
		classify.Rule{Kind: classify.KindPlatform, Pattern: "panos", Vendor: "Palo Alto Networks", Confidence: 0.80, SourceURL: "u"},
		classify.Rule{Kind: classify.KindCDPCapabilities, Pattern: "switch", Model: "cdp-switch", Confidence: 0.65, SourceURL: "u"},
		classify.Rule{Kind: classify.KindLLDPCapability, Pattern: "wlan_access_point", Model: "lldp-ap", Confidence: 0.75, SourceURL: "u"},
		classify.Rule{Kind: classify.KindMDNSService, Pattern: "_ipp._tcp", Model: "ipp-printer", Confidence: 0.75, SourceURL: "u"},
		classify.Rule{Kind: classify.KindOSName, Pattern: `(?i)\bwindows[ ]+server\b`, Model: "windows-server", Confidence: 0.80, SourceURL: "u"},
	)
	c := RuleClassifier{Engine: engine}

	facts := AssetFacts{
		Identifiers: map[string]string{FactMACAddress: "00:50:56:aa:bb:cc"},
		Facts: map[string]any{
			FactSysObjectID:       "1.3.6.1.4.1.9.1.1745",
			FactENIPVendorID:      1,
			FactCloudResourceType: "aws_s3_bucket",
			FactBanners:           map[string]string{"http": "Server: nginx/1.24"},
			FactOpenPorts:         []int{631, 9100},
			FactModel:             "C9300-48P",
			FactPlatform:          "panos",
			FactMDNSServices:      []string{"_ipp._tcp"},
			FactLLDPCapabilities:  []string{"wlan_access_point"},
			FactCDPCapabilities:   []string{"switch"},
			FactOSName:            "Microsoft Windows Server 2022 Datacenter",
		},
	}

	got := c.Explain(context.Background(), facts)

	byKind := map[string]bool{}
	for _, r := range got.MatchedRules {
		byKind[r.Kind] = true
	}
	for _, kind := range classify.Kinds {
		if !byKind[kind] {
			t.Errorf("no %s rule matched — the adapter is not mapping that field out of AssetFacts", kind)
		}
	}
}

// Facts arrive as map[string]any, so everything in them survives a JSON round
// trip — where an int becomes a float64 and a []string becomes a []any. A
// reader that only handled the native shape would classify correctly in process
// and silently stop the moment the facts crossed a service boundary.
func TestRuleClassifier_ReadsFactsThatHaveBeenThroughJSON(t *testing.T) {
	engine := mustRuleEngine(t,
		classify.Rule{Kind: classify.KindENIP, Pattern: "1", Class: "ot_device", Confidence: 0.80, SourceURL: "u"},
		classify.Rule{Kind: classify.KindPortProfile, Pattern: "631,9100", Vendor: "some printer", Confidence: 0.80, SourceURL: "u"},
		classify.Rule{Kind: classify.KindOUI, Pattern: "00188B", Model: "dell", Confidence: 0.85, SourceURL: "u"},
		classify.Rule{Kind: classify.KindBanner, Pattern: `(?i)nginx`, Model: "nginx", Confidence: 0.65, SourceURL: "u"},
	)
	c := RuleClassifier{Engine: engine}

	native := AssetFacts{Facts: map[string]any{
		FactENIPVendorID: 1,
		FactOpenPorts:    []int{631, 9100},
		FactMACAddresses: []string{"00:18:8b:aa:bb:cc"},
		FactBanners:      map[string]string{"http": "nginx"},
	}}

	blob, err := json.Marshal(native)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded AssetFacts
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	nativeRules := len(c.Explain(context.Background(), native).MatchedRules)
	decodedRules := len(c.Explain(context.Background(), decoded).MatchedRules)

	if nativeRules != 4 {
		t.Fatalf("the native facts matched %d rules, want 4 — the test's own fixture is wrong", nativeRules)
	}
	if decodedRules != nativeRules {
		t.Errorf("the same facts matched %d rules after a JSON round trip, %d before", decodedRules, nativeRules)
	}
}

// A fact of the wrong type is an absent fact, not a failure. One collector
// writing a port list as strings must not stop the whole classification.
func TestRuleClassifier_IgnoresFactsOfTheWrongType(t *testing.T) {
	engine := mustRuleEngine(t,
		classify.Rule{Kind: classify.KindOUI, Pattern: "00188B", Class: "server", Confidence: 0.85, SourceURL: "u"},
	)
	c := RuleClassifier{Engine: engine}

	got, err := c.Classify(context.Background(), AssetFacts{
		Identifiers: map[string]string{FactMACAddress: "00:18:8b:aa:bb:cc"},
		Facts: map[string]any{
			FactOpenPorts:    "631,9100",       // wrong type
			FactBanners:      []string{"nope"}, // wrong type
			FactENIPVendorID: struct{}{},       // wrong type
		},
	})

	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got.Class != "server" {
		t.Errorf("Class = %q; a malformed fact took the whole classification down with it", got.Class)
	}
}

// The rule classifier never guesses, and its conflict outcome reaches the seam
// as Unknown — the same answer the null classifier gives, from evidence rather
// than from having none.
func TestRuleClassifier_NeverGuesses(t *testing.T) {
	ctx := context.Background()

	t.Run("no evidence", func(t *testing.T) {
		got, err := RuleClassifier{}.Classify(ctx, AssetFacts{})
		if err != nil {
			t.Fatalf("Classify: %v", err)
		}
		if !got.Unknown || got.Class != "" || got.Confidence != 0 {
			t.Errorf("got %+v, want an unknown proposal with no confidence", got)
		}
	})

	t.Run("evidence the rules do not cover", func(t *testing.T) {
		got, err := RuleClassifier{}.Classify(ctx, AssetFacts{
			Facts: map[string]any{FactBanners: map[string]string{"ssh": "SSH-2.0-OpenSSH_9.6"}},
		})
		if err != nil {
			t.Fatalf("Classify: %v", err)
		}
		// An SSH banner says the host runs sshd, not what the host IS. No rule
		// covers it, deliberately, and the seam must say so rather than reach
		// for `service_daemon`.
		if !got.Unknown || got.Class != "" {
			t.Errorf("got %+v; an SSH banner produced a class", got)
		}
	})

	t.Run("rules that contradict each other", func(t *testing.T) {
		engine := mustRuleEngine(t,
			classify.Rule{Kind: classify.KindOUI, Pattern: "AAAAAA", Class: "firewall", Confidence: 0.80, SourceURL: "u"},
			classify.Rule{Kind: classify.KindPlatform, Pattern: "p", Class: "printer", Confidence: 0.80, SourceURL: "u"},
		)
		got, err := RuleClassifier{Engine: engine}.Classify(ctx, AssetFacts{
			Identifiers: map[string]string{FactMACAddress: "aa:aa:aa:00:00:01"},
			Facts:       map[string]any{FactPlatform: "p"},
		})
		if err != nil {
			t.Fatalf("Classify: %v", err)
		}
		if !got.Unknown || got.Class != "" || got.Confidence != 0 {
			t.Errorf("got %+v; a contradiction produced a class", got)
		}
	})
}

// A rule-based proposal carries provenance too, and its source_ref distinguishes
// it from the null classifier's. "The rules said unknown" and "nothing was
// configured" are different facts about a deployment, and a stored proposal has
// to be able to tell them apart — exactly the reason nullProvenance names its
// producer.
func TestRuleClassifier_CarriesProvenanceThatNamesTheRules(t *testing.T) {
	engine := mustRuleEngine(t,
		classify.Rule{Kind: classify.KindOUI, Pattern: "005056", Class: "virtual_machine", Vendor: "VMware", Confidence: 0.85, SourceURL: "u"},
	)

	got, err := RuleClassifier{Engine: engine}.Classify(context.Background(), AssetFacts{
		Identifiers: map[string]string{FactMACAddress: "00:50:56:aa:bb:cc"},
	})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}

	p := ProposalOf(got)
	if p.SourceKind != SourceKindInferred {
		t.Errorf("SourceKind = %q; a rule-derived class is inferred, not measured", p.SourceKind)
	}
	wantRef := string(ai.SeamClassifier) + ":" + ImplRules
	if p.SourceRef != wantRef {
		t.Errorf("SourceRef = %q, want %q", p.SourceRef, wantRef)
	}
	if p.ModelID != "" {
		t.Errorf("ModelID = %q; no model produced this and a rule table is not one", p.ModelID)
	}
	if p.Confidence != 0.85 {
		t.Errorf("Confidence = %v, want the rule's 0.85", p.Confidence)
	}

	// And it survives serialisation as an inferred proposal, which is the whole
	// point of Proposal's fields being fields.
	blob, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(blob), `"source_kind":"inferred"`) {
		t.Errorf("serialised proposal does not say inferred:\n%s", blob)
	}
}

// A nil Engine means the compiled-in table, not a panic and not an empty one.
// This is the path every runtime without a database takes.
func TestRuleClassifier_NilEngineUsesTheGeneratedTable(t *testing.T) {
	got, err := RuleClassifier{}.Classify(context.Background(), AssetFacts{
		Facts: map[string]any{FactCloudResourceType: "aws_s3_bucket"},
	})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got.Class != "object_storage" {
		t.Errorf("Class = %q, want object_storage from the generated table", got.Class)
	}
}

// Explain hands back the full argument — the matched rules and their citations
// — which is what makes a rule-based proposal reviewable rather than just
// something to rubber-stamp.
func TestRuleClassifier_ExplainReportsTheRulesAndTheirCitations(t *testing.T) {
	got := RuleClassifier{}.Explain(context.Background(), AssetFacts{
		Identifiers: map[string]string{FactMACAddress: "00:50:56:aa:bb:cc"},
	})

	if len(got.MatchedRules) == 0 {
		t.Fatal("Explain reported no rules for a known VMware OUI")
	}
	for _, r := range got.MatchedRules {
		if r.SourceURL == "" {
			t.Errorf("matched rule %s/%s has no citation", r.Kind, r.Pattern)
		}
		if r.Pattern == "" {
			t.Errorf("matched rule of kind %s has no pattern; a reviewer cannot see what fired", r.Kind)
		}
	}
}
