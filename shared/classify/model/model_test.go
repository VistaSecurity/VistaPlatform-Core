package model

// The learned classifier's own tests (asset-inventory workstream 4.2).
//
// Three groups, and the middle one is the load-bearing one:
//
//  1. The SHIPPED weights are the file the committed fixtures produce. Without
//     that, weights.json is a number nobody can account for.
//  2. The model GENERALISES — held-out folds, not in-sample accuracy, which on a
//     set designed to be separable says only that the features can express it.
//  3. Nothing that identifies a host can reach an explanation, and the target
//     vocabulary can never contain `unknown_host` or a group class.

import (
	"context"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/classify"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
)

const (
	fixturesPath = "testdata/fixtures.json"
	folds        = 5
)

func loadFixtures(t *testing.T) []Sample {
	t.Helper()
	raw, err := os.ReadFile(fixturesPath)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	s, err := ParseSamples(raw)
	if err != nil {
		t.Fatalf("parse fixtures: %v", err)
	}
	if len(s) < 150 {
		t.Fatalf("the fixture set has shrunk to %d samples; it is the model's whole evidence base "+
			"and workstream 4.2 asks for at least 150", len(s))
	}
	return s
}

func embeddedModel(t *testing.T) *Model {
	t.Helper()
	m, err := Default()
	if err != nil {
		t.Fatalf("load the embedded model: %v", err)
	}
	return m
}

// trainedOn is the provenance string the shipped weights carry, rebuilt so the
// reproducibility test compares like with like.
func trainedOn(samples []Sample) string {
	return fmt.Sprintf("%d synthetic fixtures", len(samples))
}

// ── the shipped weights ────────────────────────────────────────────────────

// The embedded weights must be the ones the committed fixtures produce,
// through the same pipeline the trainer runs.
//
// Without this, weights.json is a file somebody once generated and nobody can
// account for: a hand-edited weight, or one trained on a set that was then
// changed, would ship indistinguishably from a real one. Reproducibility is the
// only provenance a number like this can have.
func TestEmbeddedWeightsAreReproducibleFromTheFixtures(t *testing.T) {
	samples := loadFixtures(t)
	trained, _, _, err := TrainAndCalibrate(samples, folds, TrainOptions{
		ModelID:   DefaultModelID,
		TrainedOn: trainedOn(samples),
	})
	if err != nil {
		t.Fatalf("train: %v", err)
	}
	shipped := embeddedModel(t)

	const regenerate = " — regenerate with `go run ./cmd/train-classifier -out weights.json`"
	if shipped.ModelID != trained.ModelID {
		t.Errorf("model id: shipped %q, retrained %q", shipped.ModelID, trained.ModelID)
	}
	if shipped.Temperature != trained.Temperature {
		t.Errorf("temperature: shipped %v, retrained %v%s", shipped.Temperature, trained.Temperature, regenerate)
	}
	if strings.Join(shipped.Classes, ",") != strings.Join(trained.Classes, ",") {
		t.Errorf("classes: shipped %v, retrained %v%s", shipped.Classes, trained.Classes, regenerate)
	}
	for class, weights := range trained.Weights {
		got, ok := shipped.Weights[class]
		if !ok {
			t.Errorf("weights.json has no weights for %s%s", class, regenerate)
			continue
		}
		if len(got) != len(weights) {
			t.Errorf("weights.json has %d weights for %s, retraining gives %d%s",
				len(got), class, len(weights), regenerate)
		}
		for name, want := range weights {
			if got[name] != want {
				t.Errorf("weights.json %s/%s = %v, retraining the committed fixtures gives %v%s",
					class, name, got[name], want, regenerate)
			}
		}
	}
}

func TestEmbeddedModelValidates(t *testing.T) {
	if err := embeddedModel(t).Validate(); err != nil {
		t.Fatalf("the embedded model is not usable by this build: %v", err)
	}
}

// The embedded model must record what it achieved. A weights file with no
// measured quality is a number nobody can argue with.
func TestEmbeddedModelRecordsItsMeasurements(t *testing.T) {
	m := embeddedModel(t)
	if m.HeldOutAccuracy < HeldOutAccuracyFloor {
		t.Errorf("the shipped weights record a held-out accuracy of %.4f, below the %.2f floor",
			m.HeldOutAccuracy, HeldOutAccuracyFloor)
	}
	if len(m.Calibration) != len(m.Classes) {
		t.Errorf("%d classes but %d calibration entries; every class the model can propose has to "+
			"report what its probabilities were worth", len(m.Classes), len(m.Calibration))
	}
	for _, class := range m.Classes {
		if c := m.Calibration[class]; c.N == 0 {
			t.Errorf("class %s has no held-out samples behind its calibration", class)
		}
	}
	if strings.TrimSpace(m.TrainedOn) == "" {
		t.Error("the shipped weights do not say what they were trained on")
	}
}

// The shipped calibration table must be on the scale the model RUNS at.
//
// CrossValidate scores its folds before the temperature exists, so its
// mean-predicted column is at T=1 — and the fitted temperature here is well
// below one, which sharpens. Ship the un-rescaled column and the field inverts:
// `Model.Calibration`'s own doc says to read a mean predicted probability well
// above the observed accuracy as over-confidence, and at T=1 every class in
// this file reads under-confident while the shipped model is far more certain
// than that. A reviewer judging a retrain from it would reach the opposite
// conclusion from the truth.
//
// Pinned by comparing the file against BOTH scales: it has to match the
// tempered one and not the raw one, or the test would pass on either.
func TestTheShippedCalibrationIsOnTheShippedScale(t *testing.T) {
	samples := loadFixtures(t)
	m := embeddedModel(t)

	raw, calibration, err := CrossValidate(samples, folds, TrainOptions{})
	if err != nil {
		t.Fatalf("cross-validate: %v", err)
	}
	tempered := RescaleHeldOut(raw, calibration, m.Temperature)

	var matchesTempered, matchesRaw int
	for _, class := range m.Classes {
		got := m.Calibration[class].MeanPredicted
		if math.Abs(got-tempered.PerClass[class].MeanPredicted) < 1e-6 {
			matchesTempered++
		}
		if math.Abs(got-raw.PerClass[class].MeanPredicted) < 1e-6 {
			matchesRaw++
		}
	}
	if matchesTempered != len(m.Classes) {
		t.Errorf("%d of %d classes carry a mean predicted probability that is not the one measured at "+
			"the shipped temperature %.4f — retrain with `go run ./cmd/train-classifier -out weights.json`",
			len(m.Classes)-matchesTempered, len(m.Classes), m.Temperature)
	}
	// The two scales have to be genuinely different here, or the assertion above
	// would hold for the wrong pipeline too and prove nothing.
	if matchesRaw == len(m.Classes) {
		t.Errorf("the tempered and un-tempered calibration columns are identical, so this test cannot "+
			"tell the two pipelines apart (temperature %.4f)", m.Temperature)
	}
}

// A weights file this build cannot honestly evaluate must be REFUSED, and each
// refusal is tested in both polarities: the valid model loads, the tampered one
// does not.
func TestValidateRefusesAModelThisBuildCannotEvaluate(t *testing.T) {
	base := embeddedModel(t)
	if err := base.Validate(); err != nil {
		t.Fatalf("the baseline model does not validate: %v", err)
	}

	clone := func() *Model {
		c := *base
		c.Weights = map[string]map[string]float64{}
		for k, v := range base.Weights {
			inner := map[string]float64{}
			for n, w := range v {
				inner[n] = w
			}
			c.Weights[k] = inner
		}
		c.Classes = append([]string(nil), base.Classes...)
		return &c
	}

	t.Run("a foreign feature schema", func(t *testing.T) {
		m := clone()
		m.FeatureSchema = "v1;oui=16"
		if err := m.Validate(); err == nil {
			t.Fatal("a model trained against a different feature space was accepted; its buckets " +
				"mean something else in this build and it would score confidently and wrongly")
		}
	})
	t.Run("a feature this build does not compute", func(t *testing.T) {
		m := clone()
		m.Weights[m.Classes[0]]["invented/7"] = 1
		if err := m.Validate(); err == nil {
			t.Fatal("a model carrying an unknown feature was accepted")
		}
	})
	t.Run("unknown_host as a target", func(t *testing.T) {
		m := clone()
		m.Classes = append(m.Classes, assetclass.KeyUnknownHost)
		m.Weights[assetclass.KeyUnknownHost] = map[string]float64{FeatureBias: 1}
		if err := m.Validate(); err == nil {
			t.Fatal("a model that can propose `unknown_host` was accepted; proposing unknown is " +
				"proposing to change nothing, and ADR-0008 D4.3 says unknown stays unknown")
		}
	})
	t.Run("a group class as a target", func(t *testing.T) {
		m := clone()
		m.Classes = append(m.Classes, assetclass.KeyNetworkDevice)
		m.Weights[assetclass.KeyNetworkDevice] = map[string]float64{FeatureBias: 1}
		if err := m.Validate(); err == nil {
			t.Fatal("a model that can propose `network_device` was accepted; it has seven children " +
				"and the rules already reach it from an OUI")
		}
	})
	t.Run("no temperature", func(t *testing.T) {
		m := clone()
		m.Temperature = 0
		if err := m.Validate(); err == nil {
			t.Fatal("a model with a zero temperature was accepted; it divides every logit")
		}
	})
	t.Run("no model id", func(t *testing.T) {
		m := clone()
		m.ModelID = ""
		if err := m.Validate(); err == nil {
			t.Fatal("a model with no id was accepted; the id is what a proposal's source_ref names")
		}
	})
}

// ── fit and generalisation ─────────────────────────────────────────────────

// HeldOutAccuracyFloor is what workstream 4.2 asks of the fixtures: 0.85 on
// folds the model has not seen.
const HeldOutAccuracyFloor = 0.85

func TestFixtureAccuracy(t *testing.T) {
	m := embeddedModel(t)
	samples := loadFixtures(t)
	metrics := Evaluate(m, samples)

	t.Logf("in-sample accuracy %.4f over %d, log-loss %.4f, rejections honoured %d/%d\n\n%s",
		metrics.Accuracy, metrics.Scored, metrics.LogLoss,
		metrics.NegativesHonoured, metrics.Negatives, metrics.ConfusionMatrix())

	// In-sample is NOT evidence of quality — the fixtures are designed to be
	// separable, so this says the feature set can express the traps and nothing
	// more. TestHeldOutFoldsGeneralise is the number that means something. What
	// this catches is a weights file that does not fit its own training set,
	// which is a broken pipeline rather than a modelling question.
	if metrics.Accuracy < 0.95 {
		t.Errorf("in-sample accuracy %.4f; the shipped weights do not even fit the set they were "+
			"trained on. Misclassified: %v", metrics.Accuracy, metrics.Misclassified)
	}
	if metrics.Scored < 150 {
		t.Errorf("only %d labelled samples were scored", metrics.Scored)
	}
}

// Five-fold cross-validation: train on four fifths, score the fifth the model
// has never seen.
//
// The in-sample number above says the FEATURES can express the fixtures. It
// cannot say the model generalises — a model with hundreds of features and a
// couple of hundred samples can fit its own training set perfectly and be
// worthless, and reading an in-sample 1.0 as evidence of quality is the same
// mistake as reading a green suite that asserts nothing.
func TestHeldOutFoldsGeneralise(t *testing.T) {
	samples := loadFixtures(t)
	heldOut, _, err := CrossValidate(samples, folds, TrainOptions{})
	if err != nil {
		t.Fatalf("cross-validate: %v", err)
	}
	t.Logf("held-out accuracy %.4f (%d/%d), log-loss %.4f\n\n%s\nmisclassified: %v",
		heldOut.Accuracy, heldOut.Correct, heldOut.Scored, heldOut.LogLoss,
		heldOut.ConfusionMatrix(), heldOut.Misclassified)

	if heldOut.Accuracy < HeldOutAccuracyFloor {
		t.Errorf("held-out accuracy %.4f is below the %.2f floor", heldOut.Accuracy, HeldOutAccuracyFloor)
	}
	if heldOut.Scored < 150 {
		t.Errorf("only %d samples were held out and scored across %d folds", heldOut.Scored, folds)
	}
}

// AboveFloorPrecisionFloor is what the 0.80 proposal floor has to BUY: of the
// held-out inputs the chain would actually raise a proposal for, at least this
// share name the right class.
//
// 0.95 rather than something nearer 1. A calibrated probability floor cannot
// promise correctness — that is what "calibrated" means. P ≥ 0.80 over
// eighteen classes is a STATED error budget, and a model that never once
// cleared the floor with a wrong class would be one whose probabilities were
// not probabilities. The number this pins is the budget, not its absence.
const AboveFloorPrecisionFloor = 0.95

// What the floor is worth, measured rather than asserted.
//
// The rest of this file measures held-out ACCURACY — over every labelled
// sample, at the argmax, with no floor. That is not the quantity a reviewer
// experiences. What reaches them is the subset the CHAIN raises: the rules were
// silent or conflicting, the class is in the live vocabulary, a conflict's
// answer is one of the tied classes, and P cleared the floor. Precision over
// THAT set is what decides whether the approval queue is worth reading, and
// nothing measured it before this test.
//
// Two ways of not measuring it, both of which this exists to rule out:
//
//   - Scoring every sample. Half the fixtures are rule-decided, and on those
//     the model is never consulted at all; counting them measures a population
//     that does not exist.
//   - Scoring at temperature 1. CrossValidate's own probabilities are
//     un-tempered, and the shipped temperature is BELOW one — so a miss that
//     reads 0.51 in the cross-validation reads 0.97 at the scale the chain
//     compares against the floor. Measured the wrong way, zero held-out misses
//     clear the floor and this test would assert nothing whatsoever.
//
// It logs every wrong proposal by name. A retrain that makes the tail worse
// should name the case it broke, not move a percentage.
func TestTheFloorBuysWhatTheDocsSayItBuys(t *testing.T) {
	samples := loadFixtures(t)
	shipped := embeddedModel(t)
	eng := classify.Default()

	var right, wrong int
	var wrongNames []string

	for fold := range folds {
		var train, held []Sample
		for i, s := range samples {
			if i%folds == fold {
				held = append(held, s)
				continue
			}
			train = append(train, s)
		}
		m, _, err := Train(train, TrainOptions{ModelID: fmt.Sprintf("fold-%d", fold)})
		if err != nil {
			t.Fatalf("fold %d: %v", fold, err)
		}
		// The scale the CHAIN compares against the floor, not Train's default.
		m.Temperature = shipped.Temperature

		for _, s := range held {
			if s.Negative {
				continue
			}
			if _, ok := m.Weights[s.Class]; !ok {
				continue
			}
			facts := s.Facts.Input()
			rules := eng.Classify(context.Background(), facts)
			// The chain's own five conditions, in the same order.
			if rules.Class != "" {
				continue // 1: a rule decided; the model is never consulted.
			}
			scores := m.PredictVector(Features(Input{Facts: facts, Rules: rules}))
			if len(scores) == 0 || scores[0].P < ModelProposalFloor {
				continue // 3
			}
			if !eng.ProposesClass(scores[0].Class) {
				continue // 4
			}
			if rules.Conflict && !containsString(rules.ConflictingClasses, scores[0].Class) {
				continue // 5
			}
			if scores[0].Class == s.Class {
				right++
				continue
			}
			wrong++
			wrongNames = append(wrongNames,
				fmt.Sprintf("%s (proposed %s at P=%.4f, want %s)", s.Name, scores[0].Class, scores[0].P, s.Class))
		}
	}

	total := right + wrong
	if total < 50 {
		t.Fatalf("only %d held-out inputs reached a proposal; the fixture set no longer exercises the "+
			"chain's own path and this measures nothing", total)
	}
	precision := float64(right) / float64(total)
	sort.Strings(wrongNames)
	t.Logf("above the %.2f floor, on chain-reachable held-out inputs: %d right, %d wrong (precision %.4f)\n"+
		"wrong proposals:\n  %s", ModelProposalFloor, right, wrong, precision, strings.Join(wrongNames, "\n  "))

	if precision < AboveFloorPrecisionFloor {
		t.Errorf("above-floor precision %.4f is below the %.2f floor: a reviewer would see more than "+
			"one wrong class in twenty. Either the floor has to rise or the confusable classes have to "+
			"come out of the target set — see CLASSIFICATION_RULES.md, \"What the floor buys\".",
			precision, AboveFloorPrecisionFloor)
	}
}

func containsString(in []string, want string) bool {
	for _, s := range in {
		if s == want {
			return true
		}
	}
	return false
}

// A class a reviewer REJECTED must not stay the model's answer.
//
// Not all of them: a rejection carries no alternative label, so an input whose
// every signal argues for the rejected class has nowhere else to go and the
// honest outcome is that the model still says it — and the CHAIN then refuses
// to re-propose it, which is where that case is actually handled
// (`class_rejected` suppression, tested in inventory-service). What this pins
// is that the constraint does something at all: before the negative gradient
// existed, every rejection was simply dropped from the set.
func TestRejectionsMostlyMoveTheModel(t *testing.T) {
	m := embeddedModel(t)
	metrics := Evaluate(m, loadFixtures(t))
	if metrics.Negatives == 0 {
		t.Fatal("the fixture set carries no rejections; the negative-gradient path is untested")
	}
	ratio := float64(metrics.NegativesHonoured) / float64(metrics.Negatives)
	t.Logf("rejections honoured %d/%d", metrics.NegativesHonoured, metrics.Negatives)
	if ratio < 0.6 {
		t.Errorf("only %d of %d rejections moved the model off the rejected class", metrics.NegativesHonoured, metrics.Negatives)
	}
}

// ── the floor means something ──────────────────────────────────────────────

// An input with NO evidence must not clear the floor.
//
// This is the property the whole chain rests on: the model is consulted exactly
// where the rules had nothing to say, so the commonest input it will ever see
// is a thin one, and a model that answered confidently to thin evidence would
// fill the approval queue with the statistically most common class — the bug
// the 2026-08 audit found sixty times, with a decimal beside it.
func TestAnEmptyInputCannotClearTheFloor(t *testing.T) {
	m := embeddedModel(t)
	scores := m.Predict(Input{})
	if len(scores) == 0 {
		t.Fatal("Predict returned nothing for an empty input; it should return every class at its base rate")
	}
	t.Logf("empty input: %s at %.4f", scores[0].Class, scores[0].P)
	if scores[0].P >= ModelProposalFloor {
		t.Errorf("an input with no evidence scored %s at %.4f, at or above the %.2f floor",
			scores[0].Class, scores[0].P, ModelProposalFloor)
	}
}

// And a clear one MUST clear it, or the model is shipped switched off.
//
// The other polarity of the test above, and the one that catches a floor set so
// high that nothing ever reaches it — which would look exactly like a working
// deployment and propose nothing for ever.
func TestClearEvidenceClearsTheFloor(t *testing.T) {
	m := embeddedModel(t)
	cases := []struct {
		name  string
		want  string
		facts classify.ClassifyInput
	}{
		{
			name: "a print server on 9100 with an HP embedded web server",
			want: assetclass.KeyPrinter,
			facts: classify.ClassifyInput{
				MACs:      []string{"00:01:e6:aa:bb:cc"},
				OpenPorts: []int{80, 9100},
				Banners:   map[string]string{"http_banner": "Server: HP HTTP Server"},
			},
		},
		{
			name: "a bridging NETGEAR box answering SNMP",
			want: assetclass.KeySwitch,
			facts: classify.ClassifyInput{
				MACs:             []string{"00:09:5b:aa:bb:cc"},
				OpenPorts:        []int{22, 161},
				LLDPCapabilities: []string{"bridge"},
				Model:            "GS724T",
			},
		},
		{
			name: "a cloud key store nobody has catalogued",
			want: assetclass.KeyKeyStore,
			facts: classify.ClassifyInput{
				CloudResourceType: "aws_kms_alias",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := classify.Default().Classify(context.Background(), tc.facts)
			if rules.Class != "" {
				t.Fatalf("the RULES already decide this (%s); the fixture no longer tests the model", rules.Class)
			}
			scores := m.Predict(Input{Facts: tc.facts, Rules: rules})
			top := scores[0]
			t.Logf("%s at %.4f; reasons: %v", top.Class, top.P, Reasons(top))
			if top.Class != tc.want {
				t.Errorf("top class %s at %.4f, want %s", top.Class, top.P, tc.want)
			}
			if top.P < ModelProposalFloor {
				t.Errorf("%s scored %.4f, below the %.2f floor — a model that never clears its own "+
					"floor is shipped switched off", top.Class, top.P, ModelProposalFloor)
			}
		})
	}
}

// ── the targets ────────────────────────────────────────────────────────────

// The target vocabulary is the leaf classes of the RULE vocabulary, and never
// `unknown_host` or a group.
func TestTargetClassesAreLeavesOfTheRuleVocabulary(t *testing.T) {
	vocabulary := map[string]bool{}
	for _, c := range RuleClassVocabulary() {
		vocabulary[c] = true
	}
	targets := TargetClasses()
	if len(targets) == 0 {
		t.Fatal("there are no target classes at all")
	}
	for _, target := range targets {
		if !vocabulary[target] {
			t.Errorf("%s is a target but no rule can produce it; the chain would refuse the proposal", target)
		}
		if target == assetclass.KeyUnknownHost || target == assetclass.KeyExternal {
			t.Errorf("%s is a target; it is not an answer", target)
		}
		if kids := assetclass.Children(target); len(kids) > 0 {
			t.Errorf("%s is a target and has %d children; a group class is a word, not an answer", target, len(kids))
		}
		if c, ok := assetclass.Get(target); !ok || c.Parent == "" {
			t.Errorf("%s is a target and is top-level (or unknown to the taxonomy)", target)
		}
	}
	// And the exclusions are real, not vacuous: the rule vocabulary DOES name
	// group classes, so a target list equal to the vocabulary would mean the
	// filter never ran.
	if len(targets) >= len(vocabulary) {
		t.Errorf("%d targets from a %d-class rule vocabulary; the leaf filter excluded nothing, "+
			"which it cannot have done — `network_device` and `ot_device` both have children",
			len(targets), len(vocabulary))
	}
}

// ── features ───────────────────────────────────────────────────────────────

// The same input must extract to the same vector, every time and in any order.
//
// The hashing is FNV over the token rather than Go's map hash precisely because
// the latter is randomised per process: a weights file trained on one machine
// has to mean the same thing on another, and a per-process seed would make the
// model's answer depend on which process asked.
func TestFeatureExtractionIsDeterministic(t *testing.T) {
	facts := classify.ClassifyInput{
		MACs:              []string{"00:0c:29:11:22:33", "00-01-E6-44-55-66"},
		SysObjectID:       ".1.3.6.1.4.1.9.1.1745",
		CloudResourceType: "aws_rds_instance",
		Banners: map[string]string{
			"http_banner":  "Server: nginx/1.24.0",
			"https_banner": "Server: Apache/2.4.57 (Ubuntu)",
		},
		OpenPorts:        []int{443, 9100, 161},
		Model:            "C9300-48P",
		MDNSServices:     []string{"_ipp._tcp.local.", "_smb._tcp"},
		LLDPCapabilities: []string{"bridge", "router"},
		CDPCapabilities:  []string{"switch"},
	}
	in := Input{Facts: facts, Rules: classify.Default().Classify(context.Background(), facts)}

	first := Features(in)
	for i := range 5 {
		again := Features(in)
		if len(first.Values) != len(again.Values) {
			t.Fatalf("run %d extracted %d features, the first extracted %d", i, len(again.Values), len(first.Values))
		}
		for name, want := range first.Values {
			if got := again.Values[name]; got != want {
				t.Errorf("run %d: %s = %v, first run gave %v", i, name, got, want)
			}
		}
	}

	// The bucket for a token is a property of the TOKEN, not of the run.
	if a, b := bucket(NamespaceOUI, "Cisco Systems", OUIBuckets), bucket(NamespaceOUI, "cisco systems", OUIBuckets); a != b {
		t.Errorf("the vendor bucket is case-sensitive: %q vs %q", a, b)
	}
	if a, b := bucket(NamespaceOUI, "Cisco Systems", OUIBuckets), bucket(NamespaceBanner, "Cisco Systems", BannerBuckets); a == b {
		t.Error("two namespaces produced the same feature name for one token; the namespaces are not separating anything")
	}
}

// Every namespace must be set by at least one fixture.
//
// A weight fitted on no evidence is a number the data never expressed, and a
// namespace no fixture exercises is a feature the model was never taught to
// use — it would sit in the schema, in the fingerprint and in nobody's score.
func TestEveryFeatureNamespaceIsExercisedByTheFixtures(t *testing.T) {
	namespaces := []string{
		NamespaceOUI, NamespaceSysOID, NamespaceSysOIDSub, NamespacePID, NamespacePIDToken,
		NamespaceBanner, NamespacePort, NamespaceMDNS, NamespaceLLDP, NamespaceCloud,
		NamespaceRuleTop, NamespaceRuleTied,
	}
	scalars := []string{FeatureBias, FeatureRuleConflict, FeatureRuleSilent, FeatureRuleConfidence}

	seen := map[string]bool{}
	for _, s := range loadFixtures(t) {
		for name := range s.Vector().Values {
			seen[name] = true
			if i := strings.IndexByte(name, '/'); i > 0 {
				seen[name[:i]] = true
			}
		}
	}
	for _, n := range append(namespaces, scalars...) {
		if !seen[n] {
			t.Errorf("no fixture sets any %s feature", n)
		}
	}
}

// ── the explanation carries no identifier ──────────────────────────────────

// Nothing that identifies a host may appear in an explanation.
//
// The structural half is already true — [classify.ClassifyInput] carries no
// hostname and no address, and [Features] turns a MAC into the VENDOR its
// assignment belongs to — so this is the assertion that it stays true when
// somebody adds a feature. A label is rendered into an approval row and may be
// logged; a MAC in one is an identifier leaving the tenant's own screen for no
// benefit.
func TestNoRawIdentifierReachesAnExplanation(t *testing.T) {
	m := embeddedModel(t)
	const mac = "00:0c:29:de:ad:be"
	facts := classify.ClassifyInput{
		MACs:        []string{mac},
		SysObjectID: "1.3.6.1.4.1.9.1.1745",
		OpenPorts:   []int{22, 161},
		Model:       "C9300-48P",
		Banners:     map[string]string{"http_banner": "Server: nginx/1.24.0"},
		Platform:    "cisco_switch",
	}
	scores := m.Predict(Input{Facts: facts, Rules: classify.Default().Classify(context.Background(), facts)})

	// Everything a reviewer or a log could see.
	var text []string
	for _, s := range scores {
		for _, c := range s.Explanation {
			text = append(text, c.Feature, c.Label)
		}
	}
	blob := strings.ToLower(strings.Join(text, "\n"))

	forbidden := map[string]string{
		"000c29deadbe":         "the whole MAC",
		"00:0c:29:de:ad:be":    "the whole MAC",
		"deadbe":               "the MAC's device half",
		"de:ad:be":             "the MAC's device half",
		"1.3.6.1.4.1.9.1.1745": "the full sysObjectID, which pins one device",
	}
	for needle, what := range forbidden {
		if strings.Contains(blob, strings.ToLower(needle)) {
			t.Errorf("an explanation contains %s (%q):\n%s", what, needle, blob)
		}
	}
	// And the vendor name IS allowed and IS there — otherwise this test would
	// pass just as well against a model that explained nothing at all.
	if !strings.Contains(blob, "vmware") && !strings.Contains(blob, "cisco") {
		t.Errorf("no explanation names the evidence it used; the test above would pass on an empty "+
			"explanation. Got:\n%s", blob)
	}
}

// The same property, held STRUCTURALLY rather than against one benign input.
//
// The test above feeds a well-formed host and greps for its identifiers. That
// catches a feature that carried a MAC through, and nothing else: every string
// field it supplies is already the shape the extractor expects, so an extractor
// that echoed its input verbatim would pass it.
//
// The fields here are not that shape, and none of them is hypothetical.
// `classify.ClassifyInput` carries no hostname and no address — which is the
// structural claim the package doc makes — but it does carry four
// producer-supplied strings that reach an explanation label, and
// inventory-service fills three of them straight out of a finding's `raw_data`
// (`resource_type`, `server_header`, and `mdns_services` falling back to a bare
// `services` key). Nothing between a sensor and here holds those to a shape,
// and the label is stored in `asset_history` and rendered to a reviewer.
//
// So: feed each field something a careless or hostile producer could put there,
// and assert that no fragment of it survives into any label.
func TestNoRawValueSurvivesIntoAnExplanation(t *testing.T) {
	const (
		host   = "ceo-laptop.finance.corp.example"
		secret = "eyJhbGciOiJIUzI1NiJ9supersecrettoken"
		addr   = "10.77.4.19"
	)
	facts := classify.ClassifyInput{
		MACs: []string{"00:01:e6:aa:bb:cc"},
		// A DNS-SD INSTANCE name, which begins with the host's own label — what
		// a producer that collected instances rather than service types emits.
		MDNSServices: []string{"printer at " + host + "._ipp._tcp", "_ipp._tcp"},
		// A resource type that is really a resource id.
		CloudResourceType: "aws_ec2_instance/" + host,
		// A whole response rather than the one line the contract asks for.
		Banners: map[string]string{
			"http": "Server: nginx/1.24.0\r\nX-Auth: " + secret + "\r\nHost: " + host,
		},
		// An OID whose arc is not a number.
		SysObjectID: "1.3.6.1.4.1." + host,
		Model:       "PRINTER-" + secret,
		OpenPorts:   []int{80, 9100},
	}

	v := Features(Input{Facts: facts, Rules: classify.Default().Classify(context.Background(), facts)})
	var labels []string
	for _, name := range v.Names() {
		labels = append(labels, name, v.Evidence[name])
	}
	blob := strings.ToLower(strings.Join(labels, "\n"))

	// Word by word, not just the whole string. The leak this found was a
	// multi-line banner being split into product tokens, so every WORD of a
	// later header became its own feature and its own label — a needle list of
	// whole strings would have missed four of the five.
	for _, needle := range []string{
		host, "ceo-laptop", "ceo", "laptop", "finance", "corp", "example",
		secret, "supersecrettoken", "eyjhbgci", "auth",
		addr, "10.77",
	} {
		if strings.Contains(blob, strings.ToLower(needle)) {
			t.Errorf("an explanation label carries %q, which came straight from the input:\n%s", needle, blob)
		}
	}

	// The benign evidence in the SAME input still got through, or this test
	// would pass just as well against an extractor that produced no labels at
	// all — which is the shape of check the whole file exists to avoid.
	for _, want := range []string{"9100", "nginx", "_ipp._tcp"} {
		if !strings.Contains(blob, want) {
			t.Errorf("no label mentions %q; the assertions above would hold on an empty vector:\n%s", want, blob)
		}
	}
}

// ── the arithmetic ─────────────────────────────────────────────────────────

// A class's probabilities sum to one and the ordering is stable.
func TestPredictIsAProperDistribution(t *testing.T) {
	m := embeddedModel(t)
	facts := classify.ClassifyInput{MACs: []string{"00:09:5b:01:02:03"}, OpenPorts: []int{22, 161},
		LLDPCapabilities: []string{"bridge"}, Model: "GS724T"}
	scores := m.Predict(Input{Facts: facts, Rules: classify.Default().Classify(context.Background(), facts)})

	var sum float64
	for i, s := range scores {
		sum += s.P
		if i > 0 && scores[i-1].P < s.P {
			t.Errorf("scores are not sorted: %s %.6f before %s %.6f", scores[i-1].Class, scores[i-1].P, s.Class, s.P)
		}
		if len(s.Explanation) > ExplanationDepth {
			t.Errorf("%s carries %d contributions, more than the %d depth", s.Class, len(s.Explanation), ExplanationDepth)
		}
	}
	if math.Abs(sum-1) > 1e-9 {
		t.Errorf("the probabilities sum to %v, not 1", sum)
	}
	if len(scores) != len(m.Classes) {
		t.Errorf("%d scores for %d classes; every class must be scored, including the ones that lose", len(scores), len(m.Classes))
	}
}

// An explanation is not an approximation of what the model did — it IS what the
// model did. The contributions plus the bias are the logit, exactly.
func TestTheExplanationIsTheLogit(t *testing.T) {
	m := embeddedModel(t)
	facts := classify.ClassifyInput{
		MACs: []string{"00:01:e6:01:02:03"}, OpenPorts: []int{80, 9100},
		Banners: map[string]string{"http_banner": "Server: HP HTTP Server"},
	}
	v := Features(Input{Facts: facts, Rules: classify.Default().Classify(context.Background(), facts)})

	for _, class := range m.Classes {
		// The full list, not the top three: the truncation is a display choice
		// and this is the arithmetic behind it.
		var sum float64
		for name, value := range v.Values {
			if name == FeatureBias {
				continue
			}
			sum += value * m.Weights[class][name]
		}
		sum += v.At(FeatureBias) * m.Weights[class][FeatureBias]
		if got := m.logit(class, v); math.Abs(got-sum) > 1e-9 {
			t.Errorf("%s: logit %v, contributions sum to %v", class, got, sum)
		}
	}
}

// A contribution of zero is not an explanation, and a feature the input did not
// set must never appear in one. A large weight on a feature that measured zero
// moved nothing, and saying otherwise is the commonest way an explanation lies.
func TestAnExplanationOnlyNamesFeaturesTheInputSet(t *testing.T) {
	m := embeddedModel(t)
	facts := classify.ClassifyInput{MACs: []string{"00:07:4d:01:02:03"}, OpenPorts: []int{9100}}
	v := Features(Input{Facts: facts, Rules: classify.Default().Classify(context.Background(), facts)})
	for _, s := range m.PredictVector(v) {
		for _, c := range s.Explanation {
			if v.At(c.Feature) == 0 {
				t.Errorf("%s's explanation names %s, which this input did not set", s.Class, c.Feature)
			}
			if c.Contribution == 0 {
				t.Errorf("%s's explanation names %s, which contributed nothing", s.Class, c.Feature)
			}
			if c.Feature == FeatureBias {
				t.Errorf("%s's explanation names the bias, which is the same for every input", s.Class)
			}
		}
	}
}

// ── vocabularies shared with other packages ────────────────────────────────

// The capability names are restated in this package so it stays importable by
// the sensor. TestCapabilityVocabularyMatchesHostobs is what stops the copy
// drifting: a name this package spells differently is a feature no device ever
// sets, silently.
func TestCapabilityVocabularyMatchesHostobs(t *testing.T) {
	compare := func(name string, mine, theirs []string) {
		t.Helper()
		if strings.Join(mine, ",") != strings.Join(theirs, ",") {
			t.Errorf("%s vocabulary has drifted from shared/hostobs:\n  here:   %v\n  hostobs: %v", name, mine, theirs)
		}
	}
	compare("LLDP", lldpCapabilities, hostobs.LLDPCapabilityNames())
	compare("CDP", cdpCapabilities, hostobs.CDPCapabilityNames())
}

// The OUI extraction has to agree with the engine's, because the two are read
// as one fact: the engine matches an OUI rule and this package hashes the
// vendor that rule names. A spelling one accepts and the other rejects would
// make the model's vendor feature disagree with the rule that fired.
func TestOUIExtractionAgreesWithTheEngine(t *testing.T) {
	// VMware's 00:0C:29, which the shipped table classes as virtual_machine.
	for _, spelling := range []string{
		"00:0c:29:11:22:33", "00-0C-29-11-22-33", "000c.2911.2233", "000C29112233",
	} {
		t.Run(spelling, func(t *testing.T) {
			if got := ouiOf(spelling); got != "000C29" {
				t.Fatalf("ouiOf(%q) = %q, want 000C29", spelling, got)
			}
			prop := classify.Default().Classify(context.Background(), classify.ClassifyInput{MACs: []string{spelling}})
			if prop.Class != assetclass.KeyVirtualMachine {
				t.Errorf("the engine read %q as %q; the two readings of one MAC disagree", spelling, prop.Class)
			}
			v := Features(Input{Facts: classify.ClassifyInput{MACs: []string{spelling}}})
			if v.At(bucket(NamespaceOUI, "VMware", OUIBuckets)) != 1 {
				t.Errorf("no VMware vendor feature was set for %q", spelling)
			}
			if v.At(FeatureOUIUnknown) != 0 {
				t.Errorf("%q set oui_unknown even though the table names its vendor", spelling)
			}
		})
	}
	// A MAC the table does not name sets the unknown feature, not a vendor one.
	v := Features(Input{Facts: classify.ClassifyInput{MACs: []string{"aa:bb:cc:dd:ee:ff"}}})
	if v.At(FeatureOUIUnknown) != 1 {
		t.Error("an uncatalogued MAC prefix did not set oui_unknown; 'a manufacturer we have never " +
			"catalogued' is evidence, not an absence")
	}
	// And a non-MAC is neither.
	if got := ouiOf("not-a-mac"); got != "" {
		t.Errorf("ouiOf(%q) = %q, want empty", "not-a-mac", got)
	}
	if got := ouiOf("00:00:00:00:00:00"); got != "" {
		t.Errorf("the all-zero MAC produced OUI %q; it is a placeholder, not an identity", got)
	}
}

// ── the rule half of the features ──────────────────────────────────────────

// The three rule states are distinct and only one is set at a time, and a
// caller that did NOT consult the rules sets none of them.
func TestTheRuleFeaturesDistinguishSilentFromNotAsked(t *testing.T) {
	facts := classify.ClassifyInput{MACs: []string{"aa:bb:cc:11:22:33"}}

	notAsked := Features(Input{Facts: facts})
	if notAsked.At(FeatureRuleSilent) != 0 {
		t.Error("a caller that did not consult the rules set rule_silent; " +
			"'the rules were not asked' and 'the rules had nothing to say' are different facts")
	}

	asked := Features(Input{Facts: facts, Rules: classify.Default().Classify(context.Background(), facts)})
	if asked.At(FeatureRuleSilent) != 1 {
		t.Error("the rules matched nothing and rule_silent was not set")
	}
	if asked.At(FeatureRuleConflict) != 0 {
		t.Error("rule_conflict was set on an input the rules simply did not match")
	}
}

// A conflict sets rule_conflict, names every tied class, and — crucially —
// still carries a confidence.
//
// [classify.ClassProposal.Confidence] is zero on a conflict by construction: a
// proposal with no class makes no claim. Reading that field for the feature
// would have made it identically zero on every input the chain actually hands
// the model, which is a weight fitted on evidence the model never sees.
func TestAConflictCarriesTheLeadingRuleConfidence(t *testing.T) {
	// Cisco OUI (network_device @ 0.70) against an advertised _ipp._tcp
	// (printer @ 0.75): unrelated classes inside ConflictEpsilon.
	facts := classify.ClassifyInput{
		MACs:         []string{"00:00:0c:12:34:56"},
		MDNSServices: []string{"_ipp._tcp"},
	}
	prop := classify.Default().Classify(context.Background(), facts)
	if !prop.Conflict {
		t.Fatalf("the fixture no longer produces a conflict (class %q); the catalogue has moved", prop.Class)
	}
	if prop.Confidence != 0 {
		t.Fatalf("the engine now reports a confidence of %v on a conflict; this test's premise is gone", prop.Confidence)
	}

	v := Features(Input{Facts: facts, Rules: prop})
	if v.At(FeatureRuleConflict) != 1 {
		t.Error("rule_conflict was not set on a conflict")
	}
	if v.At(FeatureRuleSilent) != 0 {
		t.Error("rule_silent was set on a conflict; they are different states")
	}
	if got := v.At(FeatureRuleConfidence); got <= 0 {
		t.Errorf("rule_confidence = %v on a conflict; it must carry the strongest class-bearing "+
			"rule's assertion, or it is dead on every input the chain gives the model", got)
	}
	for _, class := range prop.ConflictingClasses {
		if v.At(NamespaceRuleTied+"/"+class) != 1 {
			t.Errorf("the tied class %s has no rule_tied feature", class)
		}
	}
	if v.At(NamespaceRuleTop+"/"+prop.ConflictingClasses[0]) != 1 {
		t.Errorf("rule_top was not set to the leading candidate %s", prop.ConflictingClasses[0])
	}
}

// ── the trainer ────────────────────────────────────────────────────────────

// Training is deterministic. Two runs over one set produce the same file, which
// is what makes the reproducibility test above possible at all.
func TestTrainingIsDeterministic(t *testing.T) {
	samples := loadFixtures(t)[:60]
	opts := TrainOptions{Iterations: 200, ModelID: "determinism"}
	a, _, err := Train(samples, opts)
	if err != nil {
		t.Fatalf("train: %v", err)
	}
	b, _, err := Train(samples, opts)
	if err != nil {
		t.Fatalf("retrain: %v", err)
	}
	rawA, err := MarshalWeights(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rawB, err := MarshalWeights(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(rawA) != string(rawB) {
		t.Error("two runs of Train over the same samples produced different weights")
	}
}

// A set the samples cannot label is refused rather than trained on.
func TestParseSamplesRefusesABadSet(t *testing.T) {
	cases := map[string]string{
		"an unnamed sample":   `[{"class":"printer","facts":{}}]`,
		"a duplicate name":    `[{"name":"a","class":"printer","facts":{}},{"name":"a","class":"switch","facts":{}}]`,
		"unknown_host":        `[{"name":"a","class":"unknown_host","facts":{}}]`,
		"a group class":       `[{"name":"a","class":"network_device","facts":{}}]`,
		"a class that is not": `[{"name":"a","class":"not_a_class","facts":{}}]`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSamples([]byte(raw)); err == nil {
				t.Fatal("the set was accepted")
			}
		})
	}
	// The valid shape is accepted, so the cases above are testing the checks
	// rather than a parser that refuses everything.
	if _, err := ParseSamples([]byte(`[{"name":"a","class":"printer","facts":{"open_ports":[9100]}}]`)); err != nil {
		t.Fatalf("a valid one-sample set was refused: %v", err)
	}
}

// Temperature scaling fitted on the training set is a sharpener, not a
// calibration: the weights separate their own fixtures, so the loss falls all
// the way to the search floor. Fitted on HELD-OUT logits it lands somewhere a
// person can defend.
//
// Both polarities, because this is the bug that shipped a 0.05 temperature and
// would have made every proposal read 0.999.
func TestTheTemperatureIsFittedOnHeldOutLogits(t *testing.T) {
	samples := loadFixtures(t)
	m, _, _, err := TrainAndCalibrate(samples, folds, TrainOptions{})
	if err != nil {
		t.Fatalf("train: %v", err)
	}
	t.Logf("held-out temperature %.4f", m.Temperature)
	if m.Temperature <= 0.06 {
		t.Errorf("temperature %.4f is at the search floor; that is what fitting on the TRAINING set "+
			"produces, and it makes every probability read as near-certainty", m.Temperature)
	}

	// In-sample logits, for contrast: this is what the wrong pipeline saw.
	inSample := make([]CalibrationSample, 0, len(samples))
	for _, s := range samples {
		if s.Negative {
			continue
		}
		inSample = append(inSample, CalibrationSample{
			Classes: m.Classes, Logits: m.logits(s.Vector()), True: s.Class,
		})
	}
	if got := FitTemperature(inSample); got > m.Temperature {
		t.Errorf("the in-sample fit (%.4f) is no sharper than the held-out one (%.4f); the two "+
			"pipelines are indistinguishable and this test proves nothing", got, m.Temperature)
	}
}
