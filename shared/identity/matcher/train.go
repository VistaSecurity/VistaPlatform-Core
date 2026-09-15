package matcher

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"
)

// Sample is one labelled pair: a comparison and the answer.
//
// It is the on-disk exchange format for BOTH halves of the training set — the
// synthetic fixtures in testdata/fixtures.json, and a tenant's real merge
// decisions exported from `asset_history` (see MATCHER.md for the query). One
// shape, so the trainer has one reader and a real decision and a fixture are
// weighted identically.
type Sample struct {
	// Name is a label for the case, so a misclassification names something a
	// person can look at rather than an index.
	Name string `json:"name"`

	// Match is the ground truth: these two are the same thing.
	//
	// For an exported real decision, TRUE is a proposal a reviewer resolved
	// `merged` and FALSE one they resolved `kept_separate`. A proposal still
	// `pending` is not a label and must not be exported as one — an
	// unanswered question is not an answer, and feeding it in as a negative is
	// how a model learns to agree with whatever the queue has not got to yet.
	Match bool `json:"match"`

	Observation SampleSide `json:"observation"`
	Candidate   SampleSide `json:"candidate"`
}

// SampleSide is [Side] in its JSON spelling, with SeenAt as an RFC-3339 string.
type SampleSide struct {
	Name        string            `json:"name,omitempty"`
	Class       string            `json:"class,omitempty"`
	Identifiers map[string]string `json:"identifiers,omitempty"`
	Segment     string            `json:"segment,omitempty"`
	Vendor      string            `json:"vendor,omitempty"`
	Model       string            `json:"model,omitempty"`
	SourceKind  string            `json:"source_kind,omitempty"`
	SeenAt      string            `json:"seen_at,omitempty"`
	Status      string            `json:"status,omitempty"`
}

// Side converts the JSON spelling to the extractor's. An unparseable time is
// reported rather than silently becoming the zero time: "we do not know when"
// and "1970" are different facts, and only one of them is in the data.
func (s SampleSide) Side() (Side, error) {
	out := Side{
		Name:        s.Name,
		Class:       s.Class,
		Identifiers: s.Identifiers,
		Segment:     s.Segment,
		Vendor:      s.Vendor,
		Model:       s.Model,
		SourceKind:  s.SourceKind,
		Status:      s.Status,
	}
	if s.SeenAt != "" {
		t, err := time.Parse(time.RFC3339, s.SeenAt)
		if err != nil {
			return Side{}, fmt.Errorf("seen_at %q: %w", s.SeenAt, err)
		}
		out.SeenAt = t
	}
	return out, nil
}

// Pair converts a sample into a comparison.
func (s Sample) Pair() (Pair, error) {
	obs, err := s.Observation.Side()
	if err != nil {
		return Pair{}, fmt.Errorf("sample %q observation: %w", s.Name, err)
	}
	cand, err := s.Candidate.Side()
	if err != nil {
		return Pair{}, fmt.Errorf("sample %q candidate: %w", s.Name, err)
	}
	return Pair{Observation: obs, Candidate: cand}, nil
}

// ParseSamples reads a labelled set.
func ParseSamples(raw []byte) ([]Sample, error) {
	var out []Sample
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("matcher: parse samples: %w", err)
	}
	for i, s := range out {
		if s.Name == "" {
			return nil, fmt.Errorf("matcher: sample %d has no name", i)
		}
		if _, err := s.Pair(); err != nil {
			return nil, fmt.Errorf("matcher: %w", err)
		}
	}
	return out, nil
}

// TrainOptions are the training hyper-parameters. The zero value is the one the
// shipped weights were trained with, so a retrain with no options reproduces
// them byte for byte.
type TrainOptions struct {
	// Iterations of full-batch gradient descent. 0 means [DefaultIterations].
	Iterations int
	// LearningRate. 0 means [DefaultLearningRate].
	LearningRate float64
	// L2 is the ridge penalty, applied to every weight EXCEPT the bias —
	// penalising the intercept would pull the model's base rate towards 0.5
	// regardless of the data, which is a claim about the world and not a
	// regularisation. 0 means [DefaultL2].
	L2 float64
	// ModelID is stamped on the result.
	ModelID string
	// TrainedOn describes the set, for provenance.
	TrainedOn string
}

// Training defaults. They are constants rather than tuned per run because the
// weights file records the accuracy they achieved, and a retrain that quietly
// used different hyper-parameters would make that number incomparable.
const (
	DefaultIterations   = 4000
	DefaultLearningRate = 0.35
	DefaultL2           = 0.004
)

// Metrics are what a trained model achieved on a labelled set.
type Metrics struct {
	// The confusion matrix, at the 0.5 decision boundary.
	TruePositives  int `json:"true_positives"`
	FalsePositives int `json:"false_positives"`
	TrueNegatives  int `json:"true_negatives"`
	FalseNegatives int `json:"false_negatives"`

	Accuracy  float64 `json:"accuracy"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	// LogLoss is the mean cross-entropy: what the training actually minimised,
	// and the number that says whether the SCORES are calibrated rather than
	// merely on the right side of 0.5.
	LogLoss float64 `json:"log_loss"`

	// Misclassified names the samples the model got wrong, so a regression
	// names a case rather than a percentage.
	Misclassified []string `json:"misclassified,omitempty"`
}

// ConfusionMatrix renders the matrix as a small fixed-width block.
func (m Metrics) ConfusionMatrix() string {
	return fmt.Sprintf(""+
		"                 predicted match   predicted separate\n"+
		"  actual match    %15d   %18d\n"+
		"  actual separate %15d   %18d\n",
		m.TruePositives, m.FalseNegatives, m.FalsePositives, m.TrueNegatives)
}

// Train fits a logistic regression by full-batch gradient descent.
//
// Deterministic: weights start at zero, the batch is the whole set in the order
// given, and there is no shuffling or random initialisation. Training the same
// samples twice produces byte-identical weights, which is what makes
// `make standards-check` able to assert the shipped weights.json is the one the
// shipped fixtures produce — a weights file nobody can reproduce is a number
// with no provenance.
//
// Full-batch rather than stochastic because the set is a few hundred samples:
// the whole gradient is cheaper than the bookkeeping to shuffle one.
func Train(samples []Sample, opts TrainOptions) (*Model, Metrics, error) {
	if len(samples) == 0 {
		return nil, Metrics{}, fmt.Errorf("matcher: cannot train on an empty set")
	}
	iters := opts.Iterations
	if iters <= 0 {
		iters = DefaultIterations
	}
	lr := opts.LearningRate
	if lr <= 0 {
		lr = DefaultLearningRate
	}
	l2 := opts.L2
	if l2 <= 0 {
		l2 = DefaultL2
	}

	xs := make([][]float64, len(samples))
	ys := make([]float64, len(samples))
	for i, s := range samples {
		p, err := s.Pair()
		if err != nil {
			return nil, Metrics{}, err
		}
		xs[i] = Features(p).Slice()
		if s.Match {
			ys[i] = 1
		}
	}

	n := float64(len(samples))
	w := make([]float64, len(featureNames))
	grad := make([]float64, len(featureNames))
	for range iters {
		for j := range grad {
			grad[j] = 0
		}
		for i, x := range xs {
			var z float64
			for j, v := range x {
				z += w[j] * v
			}
			err := sigmoid(z) - ys[i]
			for j, v := range x {
				grad[j] += err * v
			}
		}
		for j := range w {
			g := grad[j] / n
			if featureNames[j] != FeatureBias {
				g += l2 * w[j]
			}
			w[j] -= lr * g
		}
	}

	m := &Model{
		ModelID:   orDefault(opts.ModelID, "matcher-logreg-v1"),
		TrainedOn: opts.TrainedOn,
		Weights:   make(map[string]float64, len(featureNames)),
	}
	for j, name := range featureNames {
		// Round to nine decimals so the JSON is stable across platforms: the
		// last bit of a float64 can differ between architectures for the same
		// arithmetic, and a weights file that differs by a bit fails an
		// is-this-reproducible check for no real reason.
		m.Weights[name] = round(w[j], 9)
	}
	metrics := Evaluate(m, samples)
	m.Accuracy = round(metrics.Accuracy, 6)
	m.Precision = round(metrics.Precision, 6)
	m.Recall = round(metrics.Recall, 6)
	return m, metrics, nil
}

// Evaluate measures a model against a labelled set at the 0.5 boundary.
func Evaluate(m *Model, samples []Sample) Metrics {
	var out Metrics
	var loss float64
	for _, s := range samples {
		p, err := s.Pair()
		if err != nil {
			// ParseSamples has already rejected these; a sample that cannot be
			// converted here counts as wrong rather than being skipped, so a
			// bad set cannot flatter a model by shrinking the denominator.
			out.Misclassified = append(out.Misclassified, s.Name+" (unparseable)")
			continue
		}
		v := Features(p)
		score := m.ScoreVector(v)
		predicted := score >= 0.5
		switch {
		case s.Match && predicted:
			out.TruePositives++
		case s.Match && !predicted:
			out.FalseNegatives++
			out.Misclassified = append(out.Misclassified, s.Name)
		case !s.Match && predicted:
			out.FalsePositives++
			out.Misclassified = append(out.Misclassified, s.Name)
		default:
			out.TrueNegatives++
		}
		// Clamp before the log: a score of exactly 0 or 1 would give an
		// infinite loss and destroy the mean for every other sample.
		c := math.Min(math.Max(score, 1e-12), 1-1e-12)
		if s.Match {
			loss += -math.Log(c)
		} else {
			loss += -math.Log(1 - c)
		}
	}
	total := out.TruePositives + out.TrueNegatives + out.FalsePositives + out.FalseNegatives
	if total > 0 {
		out.Accuracy = float64(out.TruePositives+out.TrueNegatives) / float64(total)
		out.LogLoss = loss / float64(total)
	}
	if p := out.TruePositives + out.FalsePositives; p > 0 {
		out.Precision = float64(out.TruePositives) / float64(p)
	}
	if r := out.TruePositives + out.FalseNegatives; r > 0 {
		out.Recall = float64(out.TruePositives) / float64(r)
	}
	sort.Strings(out.Misclassified)
	return out
}

// MarshalWeights renders a model as the weights file, with the keys sorted so
// the bytes are stable.
func MarshalWeights(m *Model) ([]byte, error) {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("matcher: marshal weights: %w", err)
	}
	return append(raw, '\n'), nil
}

func round(v float64, places int) float64 {
	p := math.Pow(10, float64(places))
	r := math.Round(v*p) / p
	if r == 0 {
		// -0 and 0 serialise differently and compare equal, which makes a
		// byte-comparison of two identical models fail.
		return 0
	}
	return r
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
