package seams

import (
	"context"
	"errors"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/classify"
)

func intakeEngine(t *testing.T) *classify.Engine {
	t.Helper()
	e, err := classify.NewStrict([]classify.Rule{
		{Kind: classify.KindMDNSService, Pattern: "_ipp._tcp", Class: "printer", Confidence: 0.75, SourceURL: "https://x"},
	})
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	return e
}

// The curated engine reaches whichever choice runs rules — the DEFAULT chain,
// whose first stage is the rule engine, and the rules-only choice alike.
//
// Both, because handling only one is the shape of bug this function exists to
// prevent. Workstream 4.2 made the default a chain; a ClassifierFor that still
// only knew RuleClassifier would leave it running the COMPILED-IN table for
// ever, an admin's curated rules would never fire, and nothing would say so.
func TestClassifierFor_SwapsTheEngineIntoEveryRuleRunningChoice(t *testing.T) {
	t.Run("the default chain", func(t *testing.T) {
		c := ClassifierFor(Default(), intakeEngine(t))
		chain, ok := c.(ChainClassifier)
		if !ok {
			t.Fatalf("ClassifierFor returned %T, want the chain", c)
		}
		if chain.Rules.Engine == nil {
			t.Fatal("the curated engine was not swapped into the chain's rule stage; " +
				"the service would classify against the compiled-in table")
		}
		got := Explain(context.Background(), c, ClassFacts(classify.ClassifyInput{MDNSServices: []string{"_ipp._tcp"}}))
		if got.Class != "printer" {
			t.Errorf("Class = %q, want printer", got.Class)
		}
	})

	t.Run("the rules-only choice", func(t *testing.T) {
		set := Default()
		set.Classifier = RuleClassifier{}
		c := ClassifierFor(set, intakeEngine(t))
		rc, ok := c.(RuleClassifier)
		if !ok {
			t.Fatalf("ClassifierFor returned %T, want the rule classifier", c)
		}
		if rc.Engine == nil {
			t.Fatal("the curated engine was not swapped in")
		}
		got := Explain(context.Background(), c, ClassFacts(classify.ClassifyInput{MDNSServices: []string{"_ipp._tcp"}}))
		if got.Class != "printer" {
			t.Errorf("Class = %q, want printer", got.Class)
		}
	})
}

// The OPERATOR'S choice stays in charge. This is the whole reason the selection
// moved out of the call sites: `Config{Classifier: "none"}` means "propose no
// class at all", and an intake that named RuleClassifier itself would go on
// proposing.
func TestClassifierFor_LeavesAnotherChoiceAlone(t *testing.T) {
	set := Default()
	set.Classifier = NullClassifier{}
	c := ClassifierFor(set, intakeEngine(t))
	if _, isRule := c.(RuleClassifier); isRule {
		t.Fatal("ClassifierFor replaced the operator's NullClassifier with the rule one")
	}
	if _, isChain := c.(ChainClassifier); isChain {
		t.Fatal("ClassifierFor replaced the operator's NullClassifier with the default chain")
	}
	got := Explain(context.Background(), c, ClassFacts(classify.ClassifyInput{MDNSServices: []string{"_ipp._tcp"}}))
	if got.Class != "" || !got.Unknown {
		t.Errorf("a null classifier answered %+v, want no proposal", got)
	}
}

// A nil engine means "whatever the implementation defaults to" rather than a
// panic — a service whose pool is not usable yet still classifies.
func TestClassifierFor_NilEngineIsTheCompiledInTable(t *testing.T) {
	c := ClassifierFor(Default(), nil)
	got := Explain(context.Background(), c, ClassFacts(classify.ClassifyInput{CloudResourceType: "aws_s3_bucket"}))
	if got.Class != "object_storage" {
		t.Errorf("Class = %q, want object_storage from the compiled-in table", got.Class)
	}
}

// --- Explain over an implementation that cannot explain itself ---------------

type plainClassifier struct {
	out ClassProposal
	err error
}

func (p plainClassifier) Classify(context.Context, AssetFacts) (ClassProposal, error) {
	return p.out, p.err
}

func TestExplain_CarriesWhatAPlainClassifierGave(t *testing.T) {
	c := plainClassifier{out: ClassProposal{Class: "server", Proposal: NewProposal("m", "r", 0.8)}}
	got := Explain(context.Background(), c, AssetFacts{})
	if got.Class != "server" || got.Confidence != 0.8 {
		t.Errorf("got %+v, want server/0.8", got)
	}
	if len(got.MatchedRules) != 0 {
		t.Error("matched rules were invented for a classifier that reported none")
	}
}

// Unknown is preserved, and so is an error — both mean "no proposal", and
// neither is a reason to fail an intake.
func TestExplain_UnknownAndErrorBothMeanNoProposal(t *testing.T) {
	for name, c := range map[string]Classifier{
		"unknown": plainClassifier{out: ClassProposal{Unknown: true}},
		"error":   plainClassifier{err: errors.New("boom")},
		"nil":     nil,
	} {
		t.Run(name, func(t *testing.T) {
			got := Explain(context.Background(), c, AssetFacts{})
			if got.Class != "" || !got.Unknown {
				t.Errorf("got %+v, want an unknown proposal", got)
			}
		})
	}
}

// ClassFacts and the adapter in rule_classifier.go are inverses. A field added
// to ClassifyInput and not to ClassFacts is evidence the classifier silently
// stops seeing, so the round trip is pinned per kind rather than eyeballed.
func TestClassFacts_RoundTripsEveryKindOfEvidence(t *testing.T) {
	e, err := classify.NewStrict([]classify.Rule{
		{Kind: classify.KindOUI, Pattern: "005056", Vendor: "VMware", Confidence: 0.85, SourceURL: "u"},
		{Kind: classify.KindSysObjectID, Pattern: "1.3.6.1.4.1.9", Vendor: "Cisco Systems", Confidence: 0.85, SourceURL: "u"},
		{Kind: classify.KindENIP, Pattern: "1", Vendor: "Rockwell", Confidence: 0.80, SourceURL: "u"},
		{Kind: classify.KindCloudType, Pattern: "aws_s3_bucket", Model: "bucket", Confidence: 0.95, SourceURL: "u"},
		{Kind: classify.KindBanner, Pattern: `(?i)nginx`, Model: "nginx", Confidence: 0.65, SourceURL: "u"},
		{Kind: classify.KindPortProfile, Pattern: "631,9100", Model: "printer-profile", Confidence: 0.80, SourceURL: "u"},
		{Kind: classify.KindModel, Pattern: "C9300", Model: "catalyst", Confidence: 0.85, SourceURL: "u"},
		{Kind: classify.KindPlatform, Pattern: "panos", Vendor: "Palo Alto Networks", Confidence: 0.80, SourceURL: "u"},
		{Kind: classify.KindCDPCapabilities, Pattern: "switch", Model: "cdp-switch", Confidence: 0.65, SourceURL: "u"},
		{Kind: classify.KindLLDPCapability, Pattern: "wlan_access_point", Model: "lldp-ap", Confidence: 0.75, SourceURL: "u"},
		{Kind: classify.KindMDNSService, Pattern: "_ipp._tcp", Model: "ipp-printer", Confidence: 0.75, SourceURL: "u"},
		{Kind: classify.KindOSName, Pattern: `(?i)\bwindows[ ]+server\b`, Model: "windows-server", Confidence: 0.80, SourceURL: "u"},
	})
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}

	in := classify.ClassifyInput{
		MACs:              []string{"00:50:56:aa:bb:cc"},
		SysObjectID:       "1.3.6.1.4.1.9.1.1745",
		ENIPVendorID:      1,
		CloudResourceType: "aws_s3_bucket",
		Banners:           map[string]string{"http": "Server: nginx/1.24"},
		OpenPorts:         []int{631, 9100},
		Model:             "C9300-48P",
		Platform:          "panos",
		MDNSServices:      []string{"_ipp._tcp"},
		LLDPCapabilities:  []string{"wlan_access_point"},
		CDPCapabilities:   []string{"switch"},
		OS:                "Microsoft Windows Server 2022 Datacenter",
	}
	got := Explain(context.Background(), RuleClassifier{Engine: e}, ClassFacts(in))

	byKind := map[string]bool{}
	for _, r := range got.MatchedRules {
		byKind[r.Kind] = true
	}
	for _, kind := range classify.Kinds {
		if !byKind[kind] {
			t.Errorf("no %s rule matched — ClassFacts is not carrying that field across", kind)
		}
	}
}
