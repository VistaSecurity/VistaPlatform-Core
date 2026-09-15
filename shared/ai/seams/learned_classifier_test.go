package seams

// The chain's semantics, condition by condition (workstream 4.2).
//
// Every one of the five conditions on ChainClassifier.Explain is tested in BOTH
// polarities: the case it refuses, and the neighbouring case it allows. A guard
// only tested on the refusing side is a guard that would still pass if it
// refused everything, which is the same bug as one that refuses nothing.
//
// The probability conditions use a SYNTHETIC model rather than the shipped
// weights, for two reasons. It puts the score exactly where the test needs it —
// a hundredth either side of the floor — which no real input reliably does; and
// it keeps these tests from failing the next time the fixtures are retrained,
// which would be a false alarm about the chain from a change to the model.

import (
	"context"
	"math"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/ai"
	"github.com/vistasecurity/vistaplatform/shared/classify"
	classmodel "github.com/vistasecurity/vistaplatform/shared/classify/model"
)

// chainEngine is a small curated table whose VOCABULARY is
// {printer, network_device, access_point, switch}.
//
// The vocabulary matters as much as the matching: condition 4 of the chain is
// that a model may only propose a class this table could itself argue, so a
// class present here but not matched by any test input (`switch`, via a CDP
// rule nothing in these tests advertises) is what lets the vocabulary check be
// tested apart from the matching.
func chainEngine(t *testing.T) *classify.Engine {
	t.Helper()
	e, err := classify.NewStrict([]classify.Rule{
		{Kind: classify.KindMDNSService, Pattern: "_ipp._tcp", Class: "printer", Confidence: 0.75, SourceURL: "u"},
		{Kind: classify.KindOUI, Pattern: "00000C", Class: "network_device", Vendor: "Cisco Systems", Confidence: 0.70, SourceURL: "u"},
		{Kind: classify.KindLLDPCapability, Pattern: "wlan_access_point", Class: "access_point", Confidence: 0.75, SourceURL: "u"},
		{Kind: classify.KindCDPCapabilities, Pattern: "switch", Class: "switch", Confidence: 0.65, SourceURL: "u"},
	})
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	return e
}

// fixedModel is a two-class model whose answer does not depend on the input at
// all: `top` wins at probability `p`, and `other` takes the rest.
//
// Built from the bias alone. With two classes the softmax is a logistic, so a
// bias difference of ln(p/(1-p)) puts the top class at exactly p — which is how
// a test can sit a hundredth either side of the floor and mean it.
func fixedModel(t *testing.T, top, other string, p float64) *classmodel.Model {
	t.Helper()
	if p <= 0 || p >= 1 {
		t.Fatalf("p = %v is not a probability", p)
	}
	d := math.Log(p / (1 - p))
	// Classes must be sorted: Predict walks them in order and the model's own
	// contract says the list is sorted.
	classes := []string{top, other}
	if other < top {
		classes = []string{other, top}
	}
	return &classmodel.Model{
		ModelID:       "test-fixed",
		Classes:       classes,
		Temperature:   1,
		FeatureSchema: classmodel.FeatureSchemaID(),
		Weights: map[string]map[string]float64{
			top:   {classmodel.FeatureBias: d},
			other: {classmodel.FeatureBias: 0},
		},
	}
}

func chainWith(t *testing.T, m *classmodel.Model) ChainClassifier {
	t.Helper()
	return ChainClassifier{Rules: RuleClassifier{Engine: chainEngine(t)}, Model: m}
}

func explain(t *testing.T, c ChainClassifier, in classify.ClassifyInput) classify.ClassProposal {
	t.Helper()
	return c.Explain(context.Background(), ClassFacts(in))
}

// ── condition 1: a rule that decides is the answer ─────────────────────────

// The rules win outright, and the model is not consulted at all.
//
// Mutation-proven by the second half: a model that would answer `switch` at
// 0.99 for any input changes nothing while the rules have an answer, and does
// change the answer the moment they do not.
func TestChain_ARuleThatDecidesIsTheAnswer(t *testing.T) {
	loud := fixedModel(t, "switch", "printer", 0.99)
	c := chainWith(t, loud)

	decided := explain(t, c, classify.ClassifyInput{MDNSServices: []string{"_ipp._tcp"}})
	if decided.Class != "printer" {
		t.Errorf("Class = %q, want printer from the rule", decided.Class)
	}
	if decided.ModelID != "" {
		t.Errorf("a rule-decided class carries model id %q; the provenance would be `inferred` "+
			"for a class a deterministic rule argued", decided.ModelID)
	}
	if decided.Confidence != 0.75 {
		t.Errorf("Confidence = %v, want the RULE's 0.75 — the model must not soften or sharpen it", decided.Confidence)
	}
	if len(decided.ModelReasons) != 0 {
		t.Errorf("a rule-decided class carries model reasons: %+v", decided.ModelReasons)
	}

	// The same loud model, where the rules have nothing: now it answers. Without
	// this half, a chain that never consulted the model at all would pass.
	silent := explain(t, c, classify.ClassifyInput{OpenPorts: []int{9100}})
	if silent.Class != "switch" || silent.ModelID != "test-fixed" {
		t.Fatalf("where the rules are silent the model did not answer: %+v", silent)
	}
}

// ── condition 2: no model means the rules alone ────────────────────────────

func TestChain_WithNoModelTheRulesStillRun(t *testing.T) {
	c := ChainClassifier{Rules: RuleClassifier{Engine: chainEngine(t)}}

	decided := explain(t, c, classify.ClassifyInput{MDNSServices: []string{"_ipp._tcp"}})
	if decided.Class != "printer" {
		t.Errorf("Class = %q; switching the model half off must not switch the rules off", decided.Class)
	}
	silent := explain(t, c, classify.ClassifyInput{OpenPorts: []int{9100}})
	if silent.Class != "" || !silent.Unknown {
		t.Errorf("a model-less chain proposed %+v where the rules were silent", silent)
	}
	if c.ModelID() != "" {
		t.Errorf("ModelID() = %q with no model loaded", c.ModelID())
	}
}

// The env switch turns the MODEL half off and nothing else, in both polarities.
func TestChain_TheEnvSwitchTurnsOffOnlyTheModel(t *testing.T) {
	off := []string{"false", "FALSE", "0", "off", "no", " false "}
	on := []string{"", "true", "1", "yes", "on", "banana"}

	for _, v := range off {
		if modelEnabled(v) {
			t.Errorf("%s=%q left the model on", ModelEnabledEnvVar, v)
		}
		c, ok := newChainClassifier(v).(ChainClassifier)
		if !ok {
			t.Fatalf("%s=%q produced %T, want the chain with its model half off", ModelEnabledEnvVar, v, c)
		}
		if c.Model != nil {
			t.Errorf("%s=%q still loaded a model", ModelEnabledEnvVar, v)
		}
	}
	for _, v := range on {
		if !modelEnabled(v) {
			t.Errorf("%s=%q switched the model off; an unset or unparseable value must leave a "+
				"capability ON rather than silently disabling it", ModelEnabledEnvVar, v)
		}
		c, ok := newChainClassifier(v).(ChainClassifier)
		if !ok {
			t.Fatalf("%s=%q produced %T, want the chain", ModelEnabledEnvVar, v, c)
		}
		if c.Model == nil {
			t.Errorf("%s=%q did not load the embedded model", ModelEnabledEnvVar, v)
		}
	}
}

// ── condition 3: the floor ─────────────────────────────────────────────────

// A hundredth either side of the floor. This is the mutation test for the floor
// itself: raise or remove the comparison and one of these two fails.
func TestChain_TheFloorIsWhereItSays(t *testing.T) {
	facts := classify.ClassifyInput{OpenPorts: []int{9100}}

	below := explain(t, chainWith(t, fixedModel(t, "printer", "switch", classmodel.ModelProposalFloor-0.01)), facts)
	if below.Class != "" || !below.Unknown {
		t.Errorf("a model answer just BELOW the %.2f floor was proposed: %+v",
			classmodel.ModelProposalFloor, below)
	}
	if below.ModelID != "" {
		t.Errorf("a refused answer still carried model id %q", below.ModelID)
	}

	above := explain(t, chainWith(t, fixedModel(t, "printer", "switch", classmodel.ModelProposalFloor+0.01)), facts)
	if above.Class != "printer" {
		t.Errorf("a model answer just ABOVE the floor was not proposed: %+v", above)
	}
	if above.ModelID != "test-fixed" {
		t.Errorf("ModelID = %q, want the model that proposed it", above.ModelID)
	}
	if math.Abs(above.Confidence-above.ModelProbability) > 1e-9 {
		t.Errorf("Confidence %v and ModelProbability %v disagree; they are one quantity",
			above.Confidence, above.ModelProbability)
	}
	if above.Unknown {
		t.Error("a proposal with a class is still marked Unknown")
	}
}

// ── condition 4: the live rule vocabulary ──────────────────────────────────

// The model may only propose a class the CURATED table could itself argue.
//
// Both polarities against the same model: `access_point` is in this engine's
// vocabulary and `container` is not, and only the difference between them
// decides the outcome.
func TestChain_TheClassMustBeInTheLiveRuleVocabulary(t *testing.T) {
	facts := classify.ClassifyInput{OpenPorts: []int{9100}}

	inVocabulary := explain(t, chainWith(t, fixedModel(t, "access_point", "printer", 0.95)), facts)
	if inVocabulary.Class != "access_point" {
		t.Errorf("a class the curated table names was refused: %+v", inVocabulary)
	}

	outOfVocabulary := explain(t, chainWith(t, fixedModel(t, "container", "printer", 0.95)), facts)
	if outOfVocabulary.Class != "" {
		t.Errorf("the model proposed %q, which no rule in this deployment's table can argue — "+
			"an admin who deleted the last rule naming a class has said it is not something this "+
			"deployment classifies", outOfVocabulary.Class)
	}
}

// ── condition 5: a conflict is settled, never widened ──────────────────────

func conflictFacts() classify.ClassifyInput {
	// The Cisco OUI (network_device @ 0.70) against an advertised _ipp._tcp
	// (printer @ 0.75): unrelated classes inside ConflictEpsilon.
	return classify.ClassifyInput{
		MACs:         []string{"00:00:0c:11:22:33"},
		MDNSServices: []string{"_ipp._tcp"},
	}
}

func TestChain_OnAConflictTheModelMayOnlyPickOneOfTheTiedClasses(t *testing.T) {
	facts := conflictFacts()
	if base := explain(t, chainWith(t, nil), facts); !base.Conflict {
		t.Fatalf("the fixture no longer produces a conflict: %+v", base)
	}

	t.Run("one of the tied classes is taken", func(t *testing.T) {
		got := explain(t, chainWith(t, fixedModel(t, "printer", "access_point", 0.95)), facts)
		if got.Class != "printer" {
			t.Fatalf("the model's pick of a tied class was not taken: %+v", got)
		}
		if got.ModelID != "test-fixed" {
			t.Errorf("ModelID = %q", got.ModelID)
		}
		// The disagreement is still on the record. A reviewer settling it needs
		// to see WHAT was argued, and the catalogue bug behind it does not stop
		// being a bug because a model had an opinion.
		if !got.Conflict {
			t.Error("the conflict flag was cleared; the reviewer would not know the rules disagreed")
		}
		if len(got.ConflictingClasses) < 2 {
			t.Errorf("the tied classes were dropped: %+v", got.ConflictingClasses)
		}
	})

	t.Run("a third opinion is refused", func(t *testing.T) {
		// access_point is in the engine's vocabulary and clears the floor, so
		// the ONLY thing refusing it is that the rules never named it.
		got := explain(t, chainWith(t, fixedModel(t, "access_point", "printer", 0.95)), facts)
		if got.Class != "" {
			t.Fatalf("the model introduced %q, a class neither conflicting rule argued", got.Class)
		}
		if !got.Conflict || len(got.ConflictingClasses) < 2 {
			t.Errorf("the unresolved conflict was not passed through: %+v", got)
		}
		if got.ModelID != "" {
			t.Errorf("a refused answer carried model id %q", got.ModelID)
		}
	})
}

// ── the seam's narrow answer ───────────────────────────────────────────────

// Classify carries the right provenance for each producer: a rule-derived class
// names `classifier:rules` and no model, a learned one names `classifier:model`
// and the weights that proposed it.
func TestChain_ClassifyCarriesTheProducerThatAnswered(t *testing.T) {
	c := chainWith(t, fixedModel(t, "printer", "switch", 0.95))

	rule, err := c.Classify(context.Background(), ClassFacts(classify.ClassifyInput{MDNSServices: []string{"_ipp._tcp"}}))
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if rule.ModelID != "" {
		t.Errorf("a rule-derived proposal names model %q", rule.ModelID)
	}
	if want := string(ai.SeamClassifier) + ":" + ImplRules; rule.SourceRef != want {
		t.Errorf("SourceRef = %q, want %q", rule.SourceRef, want)
	}

	learned, err := c.Classify(context.Background(), ClassFacts(classify.ClassifyInput{OpenPorts: []int{9100}}))
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if learned.ModelID != "test-fixed" {
		t.Errorf("ModelID = %q, want the weights that proposed it", learned.ModelID)
	}
	if want := string(ai.SeamClassifier) + ":" + ImplModel; learned.SourceRef != want {
		t.Errorf("SourceRef = %q, want %q — a proposal that cannot name its producer is not auditable",
			learned.SourceRef, want)
	}
	if learned.Class != "printer" || learned.Unknown {
		t.Errorf("got %+v", learned)
	}
}

// ── the explanation ────────────────────────────────────────────────────────

// A learned proposal carries reasons a reviewer can read, and none of them is a
// host identifier.
func TestChain_ALearnedProposalCarriesReadableReasons(t *testing.T) {
	// The real weights here, not the synthetic model: the reasons come from the
	// feature contributions, and a fixed-bias model has none to give.
	c := ChainClassifier{Rules: RuleClassifier{}, Model: embeddedChainModel()}
	if c.Model == nil {
		t.Skip("the embedded weights did not load")
	}
	const mac = "00:01:e6:de:ad:be"
	got := explain(t, c, classify.ClassifyInput{
		MACs:      []string{mac},
		OpenPorts: []int{80, 9100},
		Banners:   map[string]string{"http_banner": "Server: HP HTTP Server"},
	})
	if got.Class == "" {
		t.Fatalf("the shipped model proposed nothing for a clear printer: %+v", got)
	}
	if len(got.ModelReasons) == 0 {
		t.Fatal("a learned proposal carried no reasons; a proposal a reviewer cannot audit is one " +
			"they can only rubber-stamp")
	}
	if len(got.ModelReasons) > classmodel.ExplanationDepth {
		t.Errorf("%d reasons, more than the %d the row shows", len(got.ModelReasons), classmodel.ExplanationDepth)
	}
	var blob strings.Builder
	for _, r := range got.ModelReasons {
		if strings.TrimSpace(r.Label) == "" {
			t.Errorf("reason %q has no phrase behind it; it would render as a blank bullet", r.Feature)
		}
		if r.Contribution == 0 {
			t.Errorf("reason %q contributed nothing to the score", r.Feature)
		}
		blob.WriteString(r.Feature + " " + r.Label + "\n")
	}
	for _, forbidden := range []string{mac, "0001e6deadbe", "de:ad:be", "deadbe"} {
		if strings.Contains(strings.ToLower(blob.String()), strings.ToLower(forbidden)) {
			t.Errorf("a reason contains the MAC (%q):\n%s", forbidden, blob.String())
		}
	}
	t.Logf("%s at %.4f because: %s", got.Class, got.ModelProbability, blob.String())
}

// The model is never the whole classifier: even with the rules engine present
// and the model loaded, `unknown_host` can never be proposed, because it is not
// a target and the vocabulary check would refuse it anyway.
func TestChain_UnknownHostIsNeverProposed(t *testing.T) {
	m := embeddedChainModel()
	if m == nil {
		t.Skip("the embedded weights did not load")
	}
	for _, class := range m.Classes {
		if class == "unknown_host" || class == "external" {
			t.Errorf("the shipped model can propose %q", class)
		}
	}
	// And thin evidence produces no proposal at all rather than a coarse one.
	c := ChainClassifier{Rules: RuleClassifier{}, Model: m}
	got := explain(t, c, classify.ClassifyInput{})
	if got.Class != "" || !got.Unknown {
		t.Errorf("an input with no evidence produced %+v, want no proposal", got)
	}
}
