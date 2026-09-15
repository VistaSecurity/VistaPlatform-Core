package matcher

import (
	_ "embed"
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
// in-process, need no network". An embed is the whole of that — there is no
// model file to mount, no download at start-up, and the image's digest covers
// the model exactly as it covers the code.
//
//go:embed weights.json
var weightsJSON []byte

// Model is a logistic regression over the features of [Features].
//
// Immutable after loading, so one is safe to share across goroutines and the
// package-level [Default] is a singleton.
type Model struct {
	// ModelID identifies these weights: `matcher-logreg-v<n>`. It is written
	// onto every proposal the model scores (ADR-0008 D4.1 — "inferred facts
	// carry confidence and model_id"), so a merge that turns out to be wrong
	// can be traced to the weights that proposed it.
	ModelID string `json:"model_id"`

	// TrainedOn describes the labelled set these weights came from, in one
	// phrase. Provenance for a number nobody can otherwise account for.
	TrainedOn string `json:"trained_on"`

	// Weights is feature name → signed weight, in log-odds. Keyed by NAME and
	// not positional: a positional file silently re-maps every weight onto a
	// different feature the moment a feature is inserted.
	Weights map[string]float64 `json:"weights"`

	// Accuracy, Precision and Recall are what these weights achieved on the
	// set they were trained on. Recorded because a weights file with no
	// measured quality is a number nobody can argue with.
	Accuracy  float64 `json:"accuracy"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
}

// SingletonConflictCeiling is the highest score [Model.Score] will return for a
// pair whose singleton identifiers disagree.
//
// ADR-0002 D3's singleton erratum is categorical: "two ARNs are two resources
// whatever a matcher scores the pair", and the auto-accept threshold does not
// apply to a singleton disagreement. The trained weight for
// [FeatureIDConflictSingleton] is large and negative, so this cap is almost
// never the binding constraint — but "almost never" is not a guarantee, and a
// future retrain on a skewed export could produce a weight that does not
// dominate. The cap makes it structural.
//
// It is deliberately NOT zero. Zero means UNSCORED everywhere else in this
// codebase (`identity.MergeCandidate.Score`: "zero means unscored, not
// certainly wrong"), and reporting a confident rejection as an absence of
// opinion is the same conflation the 2026-08 audit found sixty times. A small
// positive number says "scored, and scored badly", which is the truth.
//
// It is also NOT what stops an auto-accept. The engine refuses one on a
// singleton conflict outright, without consulting any score. This is the second
// of two independent mechanisms, not the only one.
const SingletonConflictCeiling = 0.05

// Validate reports whether the model is usable: an id, and exactly the features
// this build knows about.
//
// "Exactly" in both directions. A missing weight would silently read as zero —
// a feature the model was trained to care about, contributing nothing — and an
// extra one is a weights file from a build with a feature this one has dropped,
// which means the remaining weights were fitted alongside something that is no
// longer there. Both are a model that is not the model that was measured.
func (m *Model) Validate() error {
	if strings.TrimSpace(m.ModelID) == "" {
		return fmt.Errorf("matcher: model has no model_id")
	}
	var missing, extra []string
	known := make(map[string]bool, len(featureNames))
	for _, n := range featureNames {
		known[n] = true
		if _, ok := m.Weights[n]; !ok {
			missing = append(missing, n)
		}
	}
	for n := range m.Weights {
		if !known[n] {
			extra = append(extra, n)
		}
	}
	sort.Strings(extra)
	if len(missing) > 0 || len(extra) > 0 {
		return fmt.Errorf("matcher: model %q does not match this build's feature set (missing %v, unknown %v)",
			m.ModelID, missing, extra)
	}
	return nil
}

// LoadModel parses a weights file and validates it.
func LoadModel(raw []byte) (*Model, error) {
	var m Model
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("matcher: parse weights: %w", err)
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

// Default returns the model embedded in this binary.
//
// It is parsed once and shared. A failure is returned rather than panicking,
// and the seam's adapter degrades to proposing nothing — a matcher that cannot
// load is a matcher with no proposal, which is a state every caller already
// handles, rather than a service that will not start.
func Default() (*Model, error) {
	defaultOnce.Do(func() {
		defaultModel, defaultErr = LoadModel(weightsJSON)
	})
	return defaultModel, defaultErr
}

// LogOdds is the linear part: the signed sum of weight × value.
func (m *Model) LogOdds(v Vector) float64 {
	var z float64
	for _, n := range featureNames {
		z += m.Weights[n] * v[n]
	}
	return z
}

// Score is the calibrated probability that the pair is the same thing, 0..1.
//
// Calibrated means what it says: the model is fitted by minimising log-loss, so
// 0.5 is "as likely as not" and a tenant setting an auto-accept threshold of
// 0.9 is asking for nine-in-ten rather than picking a number on an arbitrary
// scale. [TestScoreIsCalibrated] holds the trained weights to that on the
// fixture set.
func (m *Model) Score(p Pair) float64 {
	return m.ScoreVector(Features(p))
}

// ScoreVector scores an already-extracted vector. Separate from [Model.Score]
// so the trainer and the explainer do not extract the same features twice.
func (m *Model) ScoreVector(v Vector) float64 {
	s := sigmoid(m.LogOdds(v))
	if v[FeatureIDConflictSingleton] > 0 && s > SingletonConflictCeiling {
		return SingletonConflictCeiling
	}
	return s
}

// Factor is one feature's signed contribution to a score.
type Factor struct {
	// Feature is the stable machine name — one of [FeatureNames].
	Feature string `json:"feature"`
	// Label is the phrase a reviewer reads.
	Label string `json:"label"`
	// Value is what the extractor measured, 0..1.
	Value float64 `json:"value"`
	// Weight is the model's signed weight for the feature, in log-odds.
	Weight float64 `json:"weight"`
	// Contribution is Value × Weight: how much this feature moved THIS score,
	// which is not the same as how much the model cares about the feature in
	// general. A large weight on a feature that measured zero contributed
	// nothing, and saying otherwise is the commonest way an explanation lies.
	Contribution float64 `json:"contribution"`
}

// Explain returns the features that actually moved this score, largest absolute
// contribution first, dropping the ones that contributed nothing.
//
// It is not an approximation of what the model did. A logistic regression's
// output IS the sum of these contributions passed through a sigmoid, so the
// list is complete and exact — which is the whole reason ADR-0008 D2's
// "classical, in-process" family is a logistic regression and not something
// that would need a post-hoc explainer to guess at its own reasoning.
//
// The bias is excluded: it is the same for every pair and explains nothing
// about THIS one. It is still in the score, and [Model.LogOdds] is where to
// read it.
//
// No identifier VALUE appears in a factor. "serial_number matched" is the
// evidence; the serial itself is on the proposal's matched-identifier list,
// where the reviewer is already looking at it under the tenant's own access
// control, rather than duplicated into a model explanation that may be logged.
func (m *Model) Explain(p Pair) []Factor {
	return m.ExplainVector(Features(p))
}

// ExplainVector explains an already-extracted vector.
func (m *Model) ExplainVector(v Vector) []Factor {
	out := make([]Factor, 0, len(featureNames))
	for _, n := range featureNames {
		if n == FeatureBias {
			continue
		}
		val, w := v[n], m.Weights[n]
		c := val * w
		if c == 0 {
			continue
		}
		out = append(out, Factor{
			Feature:      n,
			Label:        factorLabel(n, val),
			Value:        val,
			Weight:       w,
			Contribution: c,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return math.Abs(out[i].Contribution) > math.Abs(out[j].Contribution)
	})
	return out
}

// Reason is the one-phrase summary a merge proposal carries beside the score —
// the strongest contributing factor, positive or negative, and how many others
// there were.
//
// A proposal with a score and no reason "can only be rubber-stamped"
// (identity.MergeCandidate). This is the sentence that stops that.
func (m *Model) Reason(factors []Factor) string {
	if len(factors) == 0 {
		return "nothing about these two is comparable"
	}
	lead := factors[0].Label
	switch len(factors) {
	case 1:
		return lead
	case 2:
		return lead + ", and one other signal"
	default:
		return fmt.Sprintf("%s, and %d other signals", lead, len(factors)-1)
	}
}

// factorLabel is the human phrase for a feature at a given value. The
// graded features (similarity, recency, breadth) read their value; the rest are
// indicator features and read as a statement.
func factorLabel(name string, value float64) string {
	switch name {
	case FeatureIDMatchSingleton:
		return "a one-per-asset identifier matches (serial, cloud id, agent id or CMDB sys_id)"
	case FeatureIDConflictSingleton:
		return "a one-per-asset identifier DISAGREES — these are two things"
	case FeatureIDMatchStrong:
		return "a tenant-unique identifier matches (SSH host key, MAC or FQDN)"
	case FeatureIDMatchWeak:
		return "a scope-local identifier matches (hostname, address or name)"
	case FeatureIDMatchBreadth:
		return fmt.Sprintf("%d identifier kinds agree", int(math.Round(value*4)))
	case FeatureNameSimilarity:
		return fmt.Sprintf("the names are %d%% alike", int(math.Round(value*100)))
	case FeatureNameTrailingDigitsDiffer:
		return "the names differ only in a trailing number, like web01 and web02"
	case FeatureVendorMatch:
		return "same vendor"
	case FeatureVendorConflict:
		return "different vendors"
	case FeatureModelMatch:
		return "same hardware model"
	case FeatureModelConflict:
		return "different hardware models"
	case FeatureClassEqual:
		return "same asset class"
	case FeatureClassRelated:
		return "one class is a refinement of the other"
	case FeatureClassConflict:
		return "unrelated asset classes"
	case FeatureSegmentMatch:
		return "same network segment"
	case FeatureSegmentConflict:
		return "different network segments"
	case FeatureRecency:
		return fmt.Sprintf("seen %s apart", recencyPhrase(value))
	case FeatureSourceSame:
		return "both came from the same kind of source"
	case FeatureSourceCross:
		return "two different kinds of source agree"
	default:
		return name
	}
}

// recencyPhrase inverts the decay so the label states the gap rather than the
// feature's value, which is meaningless to a reviewer.
func recencyPhrase(value float64) string {
	if value <= 0 {
		return "an unknown time"
	}
	days := -math.Log(value) * recencyHalfLife
	switch {
	case days < 1:
		return "less than a day"
	case days < 60:
		return fmt.Sprintf("about %d days", int(math.Round(days)))
	default:
		return fmt.Sprintf("about %d months", int(math.Round(days/30)))
	}
}

func sigmoid(z float64) float64 {
	// Split on the sign to avoid overflowing exp on a large positive z. Both
	// branches are the same function; only the arithmetic differs.
	if z >= 0 {
		return 1 / (1 + math.Exp(-z))
	}
	e := math.Exp(z)
	return e / (1 + e)
}
