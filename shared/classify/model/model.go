// Package model is the learned classifier: the half of ADR-0008 D1's
// Classifier row that the rule table cannot fill, and nothing more.
//
// It speaks only where the curated rules of [classify] cannot — when they
// decide no class, or decide two — and even then it PROPOSES. It never sets a
// class on an asset, on a new one or an existing one; the chain that calls it
// (shared/ai/seams) routes every answer it gives through the class-proposal
// writer of workstream 2.10b, which puts it in front of a person. That is
// ADR-0008 D3 and ADR-0002 D5, and it is not a policy this package could choose
// to relax: it returns scores, and it has no path to a database.
//
// # What it is
//
// A multinomial logistic regression over hashed categorical features,
// trained offline, shipped as weights.json embedded in the binary, evaluated in
// pure Go. No runtime, no network, no ONNX, no dependency outside the standard
// library, shared/assetclass and shared/classify — which is what lets the
// sensor and the device agent, which cross-compile with CGO off, carry it.
//
// Three properties, the same three that made shared/identity/matcher a logistic
// regression rather than something with more capacity:
//
//  1. **Explainable by construction.** A class's score is
//     softmax(Σ wᵢxᵢ), so [Model.Predict]'s contributions are not a post-hoc
//     approximation of the model's reasoning — they are the arithmetic it did.
//  2. **Calibrated.** Fitted by minimising cross-entropy and temperature-scaled
//     afterwards, so [ModelProposalFloor] is a probability and not a number on
//     an arbitrary scale.
//  3. **Auditable.** A committed JSON file, reproducible from committed
//     fixtures by a committed command, pinned by a test.
//
// # What it may never do
//
// Decide. Propose `unknown_host` (it is not a target — see [TargetClasses]).
// Propose a class the rules' own vocabulary does not contain. Outrank a rule.
// See a hostname, an address, a serial or a key — none is an input to
// classification and none has a feature to land in.
package model

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
)

// weightsJSON is the trained model, compiled into the binary.
//
// ADR-0008 D2: "classical models ship as weights inside the service image, run
// in-process, need no network". An embed is the whole of that — no model file
// to mount, no download at start-up, and the image digest covers the model
// exactly as it covers the code.
//
//go:embed weights.json
var weightsJSON []byte

// ModelProposalFloor is the probability below which the chain proposes nothing.
//
// 0.80 rather than 0.5. A classifier is not a coin toss between two options: it
// is a choice among eighteen, so 0.5 is already strong evidence and a proposal
// at 0.5 would be a reviewer's problem eight times out of ten. The floor is the
// price of the queue staying readable, and it is deliberately a CONSTANT rather
// than a tenant setting — a per-tenant dial on how much guessing is acceptable
// is a dial on how true the inventory is, and ADR-0008 D4.3 does not have a
// slider.
//
// Below it the chain returns `unknown_host` with no proposal, which is a
// complete answer and the honest one.
const ModelProposalFloor = 0.80

// Model is the trained multinomial logistic regression.
//
// Immutable after loading, so one is safe to share across goroutines and
// [Default] is a singleton.
type Model struct {
	// ModelID identifies these weights: `classifier-softmax-v<n>`. It is
	// written onto every proposal the model raises as
	// `class_source_ref: model:<id>` (ADR-0008 D4.1 — inferred facts carry
	// confidence and model_id), so a class that turns out wrong can be traced
	// to the weights that proposed it.
	ModelID string `json:"model_id"`

	// TrainedOn describes the labelled set in one phrase. Provenance for
	// numbers nobody can otherwise account for.
	TrainedOn string `json:"trained_on"`

	// Classes is what this model may propose, sorted. A subset of
	// [TargetClasses] — a class with no labelled example is not in a trained
	// file, because a class the data never expressed is not something the model
	// knows.
	Classes []string `json:"classes"`

	// Weights is class → feature name → signed weight, in log-odds.
	//
	// SPARSE, unlike shared/identity/matcher's dense twenty. A feature absent
	// for a class is zero, and that is the normal case rather than a
	// corruption: [FeatureNames] enumerates just over a THOUSAND features, most
	// of which no input in the training set ever sets, so a dense file would be
	// eighteen thousand numbers — nearly all of them zero — in every diff. The
	// shipped file carries about 260 features per class instead.
	//
	// The guard shared/identity/matcher gets from requiring every weight is
	// here instead on the SCHEMA: [Model.Validate] refuses a weight whose
	// feature name this build does not know, and [FeatureSchemaID] fingerprints
	// the widths, the port list and the class vocabularies so a file trained
	// against a different feature space cannot load at all.
	Weights map[string]map[string]float64 `json:"weights"`

	// FeatureSchema is [FeatureSchemaID] at training time.
	FeatureSchema string `json:"feature_schema"`

	// Temperature divides every logit before the softmax (Guo et al.
	// temperature scaling). It is GLOBAL and not per class, deliberately: a
	// per-class temperature is a different divisor per logit, which can reorder
	// the classes — so the calibration would change the ANSWER and not merely
	// the confidence in it. A single divisor is monotone in every logit at
	// once and cannot.
	//
	// Per-class calibration is still measured and still shipped; it is
	// [Model.Calibration], which reports what each class's probabilities were
	// worth on held-out folds rather than silently bending them.
	Temperature float64 `json:"temperature"`

	// Calibration is per class: what the model claimed, and what it was worth.
	// A class whose mean predicted probability is well above its observed
	// accuracy is over-confident, and the floor does not protect a reviewer
	// from that — reading it is how a retrain is judged.
	//
	// Measured on held-out folds and AT [Model.Temperature], the scale this
	// model actually runs at. That second half is the load-bearing one: the
	// fold models are scored before the temperature is known, so the raw
	// cross-validation column is at T=1, and shipping that under a field whose
	// purpose is spotting over-confidence would invert every reading of it.
	Calibration map[string]ClassCalibration `json:"calibration,omitempty"`

	// Accuracy is the argmax accuracy on the set these weights were trained on.
	// In-sample and stated as such: it says the features can SEPARATE the
	// fixtures, which is not evidence of quality. The held-out number is the
	// one that means something and it is in CLASSIFICATION_RULES.md.
	Accuracy float64 `json:"accuracy"`
	// HeldOutAccuracy is the k-fold cross-validated accuracy recorded at
	// training time.
	HeldOutAccuracy float64 `json:"held_out_accuracy,omitempty"`
}

// ClassCalibration is one class's reliability.
type ClassCalibration struct {
	// N is how many held-out samples of this class were scored.
	N int `json:"n"`
	// MeanPredicted is the mean probability the model gave the TRUE class on
	// those samples.
	MeanPredicted float64 `json:"mean_predicted"`
	// Accuracy is how often it actually won.
	Accuracy float64 `json:"accuracy"`
}

// FeatureSchemaID fingerprints the feature space: the hash widths, the port
// list, the capability vocabularies and the two class vocabularies.
//
// It is what makes a sparse weights file safe. shared/identity/matcher can
// demand every weight be present because it has twenty; here a missing weight
// is the normal case, so the thing that has to be pinned is the SHAPE — and a
// weights file trained when the OUI table named a different set of vendors, or
// when a width was 64 rather than 32, refers to buckets this build computes
// differently. It would load, score, and be wrong in a way nothing could see.
func FeatureSchemaID() string {
	deriveFromRules()
	var b strings.Builder
	fmt.Fprintf(&b, "v1;oui=%d;sysoid=%d,%d;pid=%d,%d;banner=%d;mdns=%d;cloud=%d;ports=%d;lldp=%d;cdp=%d;rules=%d;targets=%d",
		OUIBuckets, SysOIDBuckets, SysOIDSubBuckets, PIDBuckets, PIDTokenBuckets,
		BannerBuckets, MDNSBuckets, CloudBuckets, len(WellKnownPorts),
		len(lldpCapabilities), len(cdpCapabilities), len(derivedClasses), len(derivedTargets))
	// The OUI table's CONTENTS, as a hash of its sorted prefix→vendor pairs.
	//
	// It was the row COUNT, and a count is blind to the change that actually
	// moves buckets. `NamespaceOUI` hashes the VENDOR NAME, so renaming
	// "Cisco Systems" to "Cisco Systems, Inc." moves every Cisco device to a
	// different bucket while `len(derivedOUI)` does not move at all — and a
	// count is equally blind to the commoner shape of a catalogue edit, one
	// vendor dropped and another added in the same release. Either way the
	// weights file still loads, still scores, and is wrong about every device
	// of that vendor with nothing anywhere saying so. That is the exact failure
	// the fingerprint exists to make loud, so it hashes what it is protecting.
	fmt.Fprintf(&b, ";ouirows=%d;ouihash=%s", len(derivedOUI), ouiContentHash())
	return b.String()
}

// ouiContentHash is a stable hash of the compiled-in OUI table's contents.
//
// Sorted by prefix, so it does not depend on map iteration order, and the pair
// separator is a byte that cannot occur in either half — a prefix is hex and a
// vendor name is a vendor name — so "ab" + "cd" and "abc" + "d" cannot collide
// into the same bytes.
//
// Truncated to 16 hex characters. The whole digest would make [FeatureSchemaID]
// unreadable in the error message it exists to print, and 64 bits is far more
// than an accidental catalogue edit will ever collide on; this is a change
// detector, not a security boundary — nothing here defends against an attacker
// choosing vendor names.
func ouiContentHash() string { return hashOUITable(derivedOUI) }

// hashOUITable is [ouiContentHash] over an explicit table, so the hash can be
// tested against fabricated tables without reaching into the compiled-in one.
func hashOUITable(table map[string]string) string {
	prefixes := make([]string, 0, len(table))
	for prefix := range table {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)
	h := sha256.New()
	for _, prefix := range prefixes {
		h.Write([]byte(prefix))
		h.Write([]byte{0})
		h.Write([]byte(table[prefix]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Validate reports whether a model is usable by THIS build.
func (m *Model) Validate() error {
	if strings.TrimSpace(m.ModelID) == "" {
		return fmt.Errorf("classify/model: the model has no model_id")
	}
	if len(m.Classes) == 0 {
		return fmt.Errorf("classify/model: model %q proposes no classes", m.ModelID)
	}
	if want := FeatureSchemaID(); m.FeatureSchema != want {
		return fmt.Errorf("classify/model: model %q was trained against feature schema %q, this build computes %q"+
			" — retrain with `go run ./cmd/train-classifier -out weights.json`", m.ModelID, m.FeatureSchema, want)
	}
	if m.Temperature <= 0 {
		return fmt.Errorf("classify/model: model %q has temperature %v; it divides the logits and must be positive", m.ModelID, m.Temperature)
	}
	targets := make(map[string]bool, len(derivedTargets))
	for _, t := range TargetClasses() {
		targets[t] = true
	}
	known := make(map[string]bool, 512)
	for _, n := range FeatureNames() {
		known[n] = true
	}
	for _, class := range m.Classes {
		if !targets[class] {
			return fmt.Errorf("classify/model: model %q names %q as a target; it is not a leaf class of the rule vocabulary"+
				" — a group class or `unknown_host` is not something to propose", m.ModelID, class)
		}
		if _, ok := m.Weights[class]; !ok {
			return fmt.Errorf("classify/model: model %q lists class %q with no weights at all", m.ModelID, class)
		}
	}
	for class, weights := range m.Weights {
		if !targets[class] {
			return fmt.Errorf("classify/model: model %q carries weights for %q, which is not a valid target", m.ModelID, class)
		}
		for name := range weights {
			if !known[name] {
				return fmt.Errorf("classify/model: model %q carries a weight for %q, a feature this build does not compute",
					m.ModelID, name)
			}
		}
	}
	return nil
}

// LoadModel parses a weights file and validates it.
func LoadModel(raw []byte) (*Model, error) {
	var m Model
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("classify/model: parse weights: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

var (
	defaultOnce  sync.Once
	defaultModel *Model
	defaultErr   error
)

// Default returns the model embedded in this binary, parsed once and shared.
//
// A failure is returned rather than panicking: a classifier that cannot load is
// a classifier with no proposal, which is a state every caller already handles
// (it is the null default), and the rule engine beside it is complete without
// any of this. A weights file that failed to parse must not stop a service from
// classifying assets.
func Default() (*Model, error) {
	defaultOnce.Do(func() {
		defaultModel, defaultErr = LoadModel(weightsJSON)
	})
	return defaultModel, defaultErr
}

// Contribution is one feature's signed contribution to one class's logit.
type Contribution struct {
	// Feature is the stable machine name — `oui/7`, `port/9100`.
	Feature string `json:"feature"`

	// Label is the phrase a reviewer reads, built from THIS input's own
	// evidence: "the MAC prefix is registered to Brother", "port 9100 is open",
	// "the service banner said “nginx”".
	//
	// A vendor name, a port number, a banner token, an advertised service, a
	// model family. Never a host identifier: a MAC, a hostname and an address
	// are not inputs to classification and there is no feature that could carry
	// one here. TestNoRawIdentifierReachesAnExplanation is the assertion.
	Label string `json:"label"`

	// Value is what the extractor measured, 0..1.
	Value float64 `json:"value"`
	// Weight is this class's signed weight for the feature, in log-odds.
	Weight float64 `json:"weight"`
	// Contribution is Value × Weight: how much the feature moved THIS score,
	// which is not how much the model cares about it in general. A large weight
	// on a feature that measured zero contributed nothing, and saying otherwise
	// is the commonest way an explanation lies.
	Contribution float64 `json:"contribution"`
}

// ClassScore is one class and what the model thinks of it.
type ClassScore struct {
	// Class is the asset-class key.
	Class string `json:"class"`
	// P is the calibrated probability, 0..1. The eighteen sum to 1.
	P float64 `json:"p"`
	// Explanation is the features that actually moved this class's logit,
	// largest absolute contribution first, at most [ExplanationDepth].
	Explanation []Contribution `json:"explanation,omitempty"`
}

// ExplanationDepth is how many contributions a score carries. Three: a reviewer
// deciding whether a box is a printer reads reasons, not a spreadsheet, and the
// fourth is never what changes their mind.
const ExplanationDepth = 3

// Predict scores every class this model knows, best first.
//
// It never errors and it never abstains: abstention is the CHAIN's decision,
// made against [ModelProposalFloor] and the rules' vocabulary, and folding it
// in here would give the model two jobs and hide one of them. An input with no
// evidence at all scores the trained base rates, which are flat enough that
// nothing clears the floor — which is the honest outcome, arrived at by
// arithmetic rather than by a special case.
func (m *Model) Predict(in Input) []ClassScore {
	return m.PredictVector(Features(in))
}

// PredictVector scores an already-extracted vector. Separate from [Model.Predict]
// so the trainer does not extract the same features twice.
func (m *Model) PredictVector(v Vector) []ClassScore {
	logits := make([]float64, len(m.Classes))
	for i, class := range m.Classes {
		logits[i] = m.logit(class, v) / m.Temperature
	}
	probs := softmax(logits)

	out := make([]ClassScore, 0, len(m.Classes))
	for i, class := range m.Classes {
		out = append(out, ClassScore{
			Class:       class,
			P:           probs[i],
			Explanation: m.explain(class, v),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].P != out[j].P {
			return out[i].P > out[j].P
		}
		// A deterministic tie-break, so two classes the model genuinely cannot
		// separate come back in the same order on every call. Without it the
		// chain's "best" would depend on map iteration order upstream, and a
		// proposal would differ between two runs over identical evidence.
		return out[i].Class < out[j].Class
	})
	return out
}

// logits is the uncalibrated linear part for every class, in [Model.Classes]
// order. The temperature is deliberately NOT applied: it is what the trainer
// fits to these, and applying it here would make the calibration depend on
// itself.
func (m *Model) logits(v Vector) []float64 {
	out := make([]float64, len(m.Classes))
	for i, class := range m.Classes {
		out[i] = m.logit(class, v)
	}
	return out
}

// logit is the linear part for one class: the signed sum of weight × value.
func (m *Model) logit(class string, v Vector) float64 {
	weights := m.Weights[class]
	if len(weights) == 0 {
		return 0
	}
	var z float64
	for name, value := range v.Values {
		z += weights[name] * value
	}
	return z
}

// explain returns the features that moved this class's logit, largest absolute
// contribution first, dropping the ones that contributed nothing and the bias.
//
// The bias is excluded because it is the same for every input and explains
// nothing about THIS one. It is still in the score; [Model.logit] is where to
// read it.
func (m *Model) explain(class string, v Vector) []Contribution {
	weights := m.Weights[class]
	if len(weights) == 0 {
		return nil
	}
	out := make([]Contribution, 0, len(v.Values))
	// Sorted names, not map order: two runs over one input must produce the
	// same explanation, and equal contributions are common in a space of
	// indicator features.
	for _, name := range v.Names() {
		if name == FeatureBias {
			continue
		}
		value, w := v.Values[name], weights[name]
		c := value * w
		if c == 0 {
			continue
		}
		out = append(out, Contribution{
			Feature:      name,
			Label:        v.Evidence[name],
			Value:        value,
			Weight:       w,
			Contribution: c,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return math.Abs(out[i].Contribution) > math.Abs(out[j].Contribution)
	})
	if len(out) > ExplanationDepth {
		out = out[:ExplanationDepth]
	}
	return out
}

// Reasons renders an explanation as the phrases a reviewer reads, dropping the
// ones with no evidence phrase behind them.
func Reasons(cs ClassScore) []string {
	out := make([]string, 0, len(cs.Explanation))
	for _, c := range cs.Explanation {
		if strings.TrimSpace(c.Label) == "" {
			continue
		}
		out = append(out, c.Label)
	}
	return out
}

// softmax turns logits into probabilities, shifted by the maximum so a large
// logit cannot overflow exp.
func softmax(z []float64) []float64 {
	if len(z) == 0 {
		return nil
	}
	max := z[0]
	for _, v := range z[1:] {
		if v > max {
			max = v
		}
	}
	out := make([]float64, len(z))
	var sum float64
	for i, v := range z {
		e := math.Exp(v - max)
		out[i] = e
		sum += e
	}
	for i := range out {
		out[i] /= sum
	}
	return out
}
