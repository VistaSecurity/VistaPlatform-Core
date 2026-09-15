package model

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/classify"
)

// Sample is one labelled observation: the evidence, and what the thing was.
//
// It is the on-disk exchange format for BOTH halves of the training set — the
// synthetic fixtures in testdata/fixtures.json and a tenant's real class
// decisions exported from `asset_history`. One shape, so the trainer has one
// reader and a real decision and a fixture are weighted identically.
type Sample struct {
	// Name labels the case, so a misclassification names something a person can
	// look at rather than an index.
	Name string `json:"name"`

	// Class is the asset class. For a POSITIVE sample it is what the thing is;
	// for a negative one it is what a reviewer said it is NOT.
	Class string `json:"class"`

	// Negative marks a sample as a rejection rather than an answer.
	//
	// A `class_rejected` row says "not a printer". It does not say what the
	// thing IS, so it cannot be a label in the ordinary sense — and inventing
	// one (picking the runner-up, say) would be exactly the fabricated fact
	// this whole slice exists to avoid. [Train] handles it as a constraint
	// instead: see the gradient note there.
	Negative bool `json:"negative,omitempty"`

	// Facts is the evidence, in [classify.ClassifyInput]'s vocabulary.
	Facts SampleFacts `json:"facts"`
}

// SampleFacts is [classify.ClassifyInput] in its JSON spelling. A mirror rather
// than the struct itself only because ClassifyInput carries no json tags, and a
// fixture file a person has to read and review should not be in Go field names.
type SampleFacts struct {
	MACs              []string          `json:"macs,omitempty"`
	SysObjectID       string            `json:"sysobjectid,omitempty"`
	ENIPVendorID      int               `json:"enip_vendor_id,omitempty"`
	CloudResourceType string            `json:"cloud_resource_type,omitempty"`
	Banners           map[string]string `json:"banners,omitempty"`
	OpenPorts         []int             `json:"open_ports,omitempty"`
	Vendor            string            `json:"vendor,omitempty"`
	Model             string            `json:"model,omitempty"`
	Platform          string            `json:"platform,omitempty"`
	MDNSServices      []string          `json:"mdns_services,omitempty"`
	LLDPCapabilities  []string          `json:"lldp_capabilities,omitempty"`
	CDPCapabilities   []string          `json:"cdp_capabilities,omitempty"`
}

// Input converts a sample's facts to the engine's input.
func (f SampleFacts) Input() classify.ClassifyInput {
	return classify.ClassifyInput{
		MACs:              f.MACs,
		SysObjectID:       f.SysObjectID,
		ENIPVendorID:      f.ENIPVendorID,
		CloudResourceType: f.CloudResourceType,
		Banners:           f.Banners,
		OpenPorts:         f.OpenPorts,
		Vendor:            f.Vendor,
		Model:             f.Model,
		Platform:          f.Platform,
		MDNSServices:      f.MDNSServices,
		LLDPCapabilities:  f.LLDPCapabilities,
		CDPCapabilities:   f.CDPCapabilities,
	}
}

// Vector extracts a sample's features, running the COMPILED-IN rule engine over
// its facts to fill the rule half.
//
// Running the engine rather than letting a fixture state the rules' answer is
// what keeps the fixture honest: a sample that claimed the rules were silent
// while the shipped table decides it would train the model on a world that does
// not exist, and the first retrain after a rule was added would change the
// weights for reasons nobody could see.
//
// For an EXPORTED decision it is an approximation, and a stated one: the rules
// that were in force when the reviewer answered may not be today's. That is the
// same lossiness shared/identity/matcher's export has, and the same answer — the
// synthetic fixtures stay in the set.
func (s Sample) Vector() Vector {
	facts := s.Facts.Input()
	return Features(Input{Facts: facts, Rules: classify.Default().Classify(context.Background(), facts)})
}

// ParseSamples reads a labelled set and checks every label.
func ParseSamples(raw []byte) ([]Sample, error) {
	var out []Sample
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("classify/model: parse samples: %w", err)
	}
	targets := map[string]bool{}
	for _, t := range TargetClasses() {
		targets[t] = true
	}
	seen := map[string]bool{}
	for i, s := range out {
		if strings.TrimSpace(s.Name) == "" {
			return nil, fmt.Errorf("classify/model: sample %d has no name", i)
		}
		if seen[s.Name] {
			return nil, fmt.Errorf("classify/model: two samples are named %q; a duplicate name makes a"+
				" misclassification unattributable", s.Name)
		}
		seen[s.Name] = true
		if !targets[s.Class] {
			return nil, fmt.Errorf("classify/model: sample %q is labelled %q, which is not a target class"+
				" — targets are the leaf classes of the rule vocabulary, and `unknown_host` is never one", s.Name, s.Class)
		}
	}
	return out, nil
}

// TrainOptions are the hyper-parameters. The zero value is what the shipped
// weights were trained with, so a retrain with no options reproduces them byte
// for byte.
type TrainOptions struct {
	// Iterations of full-batch gradient descent. 0 means [DefaultIterations].
	Iterations int
	// LearningRate. 0 means [DefaultLearningRate].
	LearningRate float64
	// L2 is the ridge penalty, applied to every weight EXCEPT the per-class
	// bias — penalising the intercepts would pull every class's base rate
	// towards uniform regardless of the data, which is a claim about the world
	// and not a regularisation. 0 means [DefaultL2].
	L2 float64
	// ModelID is stamped on the result.
	ModelID string
	// TrainedOn describes the set, for provenance.
	TrainedOn string
}

// Training defaults. Constants rather than tuned per run, because the weights
// file records the accuracy they achieved and a retrain that quietly used
// different ones would make that number incomparable.
const (
	DefaultIterations   = 3000
	DefaultLearningRate = 0.55
	DefaultL2           = 0.0025

	// DefaultModelID is the shipped weights' id. Bump it when a change is one
	// anybody should be able to tell apart in an audit — the id lands in
	// `class_source_ref` on every asset whose class came from a proposal the
	// model raised.
	DefaultModelID = "classifier-softmax-v1"

	// NegativeGradientCap bounds the weight a rejection carries. See [Train].
	NegativeGradientCap = 10.0
)

// Metrics are what a trained model achieved on a labelled set.
type Metrics struct {
	// Correct and Scored count the POSITIVE samples only: argmax accuracy over
	// a rejection is not defined, because a rejection has no right answer.
	Correct int `json:"correct"`
	Scored  int `json:"scored"`

	// NegativesHonoured and Negatives count the rejections: a rejection is
	// honoured when the class a reviewer rejected is NOT the model's argmax.
	NegativesHonoured int `json:"negatives_honoured"`
	Negatives         int `json:"negatives"`

	Accuracy float64 `json:"accuracy"`
	// LogLoss is the mean cross-entropy over the positives: what training
	// minimised, and the number that says whether the probabilities are worth
	// anything rather than merely being on the right side of the argmax.
	LogLoss float64 `json:"log_loss"`

	// Confusion is actual class → predicted class → count.
	Confusion map[string]map[string]int `json:"confusion,omitempty"`

	// Misclassified names the samples the model got wrong, so a regression
	// names a case rather than a percentage.
	Misclassified []string `json:"misclassified,omitempty"`

	// PerClass is the reliability table that ships as [Model.Calibration].
	PerClass map[string]ClassCalibration `json:"per_class,omitempty"`
}

// ConfusionMatrix renders the matrix as a fixed-width block, actual down the
// side and predicted across. Only the classes that appear.
func (m Metrics) ConfusionMatrix() string {
	if len(m.Confusion) == 0 {
		return "  (no positive samples)\n"
	}
	cols := map[string]bool{}
	var rows []string
	for actual, preds := range m.Confusion {
		rows = append(rows, actual)
		for p := range preds {
			cols[p] = true
		}
	}
	sort.Strings(rows)
	var header []string
	for c := range cols {
		header = append(header, c)
	}
	sort.Strings(header)

	var b strings.Builder
	fmt.Fprintf(&b, "  %-22s", "actual \\ predicted")
	for _, c := range header {
		fmt.Fprintf(&b, " %8s", abbreviate(c))
	}
	b.WriteString("\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "  %-22s", r)
		for _, c := range header {
			n := m.Confusion[r][c]
			if n == 0 {
				fmt.Fprintf(&b, " %8s", ".")
				continue
			}
			fmt.Fprintf(&b, " %8d", n)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// abbreviate shortens a class key for a column header: `wireless_controller`
// becomes `wirl_cnt`. Lossy on purpose — the rows carry the full keys and a
// matrix eighteen columns wide has to fit on a terminal.
func abbreviate(key string) string {
	parts := strings.Split(key, "_")
	var b strings.Builder
	for i, p := range parts {
		n := 4
		if len(parts) > 2 {
			n = 3
		}
		if len(p) < n {
			n = len(p)
		}
		if i > 0 {
			b.WriteString("_")
		}
		b.WriteString(p[:n])
	}
	s := b.String()
	if len(s) > 8 {
		s = s[:8]
	}
	return s
}

// Train fits a multinomial logistic regression by full-batch gradient descent.
//
// Deterministic: weights start at zero, the batch is the whole set in the order
// given, and there is no shuffling or random initialisation. Training the same
// samples twice produces byte-identical weights, which is what lets
// TestEmbeddedWeightsAreReproducibleFromTheFixtures assert the shipped file is
// the one the shipped fixtures produce. A weights file nobody can reproduce is
// a number with no provenance, and a hand-edited one would ship
// indistinguishably from a real one.
//
// # How a REJECTION is trained on
//
// A positive sample's gradient with respect to the logits is the textbook
// `p − e_y`. A rejection has no `y`: the reviewer said "not a printer" and
// nothing about what it is. So its loss is `−log(1 − p_X)` — make the rejected
// class unlikely, say nothing about the rest — whose gradient works out to
// `−c · (p − e_X)` with `c = p_X / (1 − p_X)`.
//
// Which is the positive gradient for X, negated and scaled. A rejection is
// therefore an anti-example of exactly the strength of how wrong the model
// currently is, and one the model already disbelieves contributes almost
// nothing — correctly, because there is nothing left to learn from it. `c` is
// capped at [NegativeGradientCap] because it diverges as `p_X → 1`, and one
// confidently-wrong rejection must not be able to dominate the batch.
func Train(samples []Sample, opts TrainOptions) (*Model, Metrics, error) {
	if len(samples) == 0 {
		return nil, Metrics{}, fmt.Errorf("classify/model: cannot train on an empty set")
	}
	iters := orDefaultInt(opts.Iterations, DefaultIterations)
	lr := orDefaultFloat(opts.LearningRate, DefaultLearningRate)
	l2 := orDefaultFloat(opts.L2, DefaultL2)

	classes := classesOf(samples)
	if len(classes) < 2 {
		return nil, Metrics{}, fmt.Errorf("classify/model: the set names %d classes; a classifier over one class"+
			" is not a classifier", len(classes))
	}
	classIndex := make(map[string]int, len(classes))
	for i, c := range classes {
		classIndex[c] = i
	}
	prep := prepare(samples)

	// Dense over the features the SET actually uses, sparse over the whole
	// space. The space is just over a thousand wide, the committed fixtures set
	// 260 of them and one sample sets about ten, so a dense-over-everything
	// matrix would be four times the arithmetic for no gain;
	// a map-keyed one would be a hash lookup per multiply, which at three
	// thousand iterations is seconds rather than a fraction of one. Indexing
	// once, up front, is both.
	index, order := featureIndex(prep)
	nFeat := len(order)
	rows := make([]sparseRow, len(prep))
	for i, p := range prep {
		names := p.vector.Names()
		row := sparseRow{
			idx:    make([]int, 0, len(names)),
			values: make([]float64, 0, len(names)),
			label:  classIndex[samples[i].Class],
			neg:    samples[i].Negative,
		}
		for _, n := range names {
			row.idx = append(row.idx, index[n])
			row.values = append(row.values, p.vector.Values[n])
		}
		rows[i] = row
	}

	biasIdx, hasBias := index[FeatureBias]
	weights := make([][]float64, len(classes))
	grad := make([][]float64, len(classes))
	for i := range classes {
		weights[i] = make([]float64, nFeat)
		grad[i] = make([]float64, nFeat)
	}
	logits := make([]float64, len(classes))
	n := float64(len(samples))

	for range iters {
		for c := range classes {
			for j := range grad[c] {
				grad[c][j] = 0
			}
		}
		for _, row := range rows {
			for c := range classes {
				var z float64
				w := weights[c]
				for j, fi := range row.idx {
					z += w[fi] * row.values[j]
				}
				logits[c] = z
			}
			p := softmax(logits)

			scale := 1.0
			if row.neg {
				pX := p[row.label]
				c := pX / math.Max(1-pX, 1e-12)
				if c > NegativeGradientCap {
					c = NegativeGradientCap
				}
				scale = -c
			}
			for c := range classes {
				d := p[c]
				if c == row.label {
					d--
				}
				d *= scale
				if d == 0 {
					continue
				}
				g := grad[c]
				for j, fi := range row.idx {
					g[fi] += d * row.values[j]
				}
			}
		}
		for c := range classes {
			w, g := weights[c], grad[c]
			for j := range w {
				d := g[j] / n
				if !hasBias || j != biasIdx {
					d += l2 * w[j]
				}
				w[j] -= lr * d
			}
		}
	}

	m := &Model{
		ModelID:       orDefaultString(opts.ModelID, DefaultModelID),
		TrainedOn:     opts.TrainedOn,
		Classes:       classes,
		Weights:       map[string]map[string]float64{},
		FeatureSchema: FeatureSchemaID(),
		Temperature:   1,
	}
	for i, c := range classes {
		out := make(map[string]float64, nFeat)
		for j, name := range order {
			// Round to six decimals so the JSON is stable across
			// architectures — the last bit of a float64 can differ between two
			// of them for the same arithmetic, and a weights file that differs
			// by a bit fails an is-this-reproducible check for no real reason.
			// Drop what rounds to nothing: a weight of 1e-12 is noise from the
			// ridge term, and thousands of them would make a retrain's diff
			// unreadable.
			if r := round(weights[i][j], 6); r != 0 {
				out[name] = r
			}
		}
		m.Weights[c] = out
	}
	metrics := evaluatePrepared(m, prep)
	m.Accuracy = round(metrics.Accuracy, 6)
	m.Calibration = metrics.PerClass
	return m, metrics, nil
}

// sparseRow is one sample as the trainer reads it: the indices of the features
// it set, their values, its label, and whether the label is a rejection.
type sparseRow struct {
	idx    []int
	values []float64
	label  int
	neg    bool
}

// prepared is a sample with its features already extracted.
//
// Extraction runs the rule engine over 564 rules, and the temperature search
// alone evaluates the set sixty-three times. Extracting once is the difference
// between a trainer that runs in a test and one that does not.
type prepared struct {
	sample Sample
	vector Vector
}

func prepare(samples []Sample) []prepared {
	out := make([]prepared, len(samples))
	for i, s := range samples {
		out[i] = prepared{sample: s, vector: s.Vector()}
	}
	return out
}

// featureIndex assigns a dense position to every feature the set uses, in
// sorted order so the assignment — and therefore the arithmetic — is identical
// on every run.
func featureIndex(prep []prepared) (map[string]int, []string) {
	set := map[string]bool{}
	for _, p := range prep {
		for n := range p.vector.Values {
			set[n] = true
		}
	}
	order := make([]string, 0, len(set))
	for n := range set {
		order = append(order, n)
	}
	sort.Strings(order)
	index := make(map[string]int, len(order))
	for i, n := range order {
		index[n] = i
	}
	return index, order
}

// CalibrationSample is one HELD-OUT prediction, kept as raw logits so a
// temperature can be fitted against data the weights never saw.
type CalibrationSample struct {
	// Classes and Logits are the fold model's answer, before any temperature.
	Classes []string
	Logits  []float64
	// True is the sample's actual class.
	True string
}

// FitTemperature searches for the divisor that minimises log-loss on held-out
// predictions (Guo et al. temperature scaling).
//
// # It must be held-out, and this is the whole reason
//
// Fitted on the TRAINING set it is not a calibration, it is a sharpener. The
// weights separate their own fixtures perfectly — that is what an in-sample 1.0
// means — so the loss falls monotonically as the temperature approaches zero
// and the search bottoms out at its floor, producing a model that answers 0.999
// to everything. Which is the exact shape of a check that cannot fail, pointed
// at a probability: the number would clear [ModelProposalFloor] on every input
// and the floor would stop meaning anything.
//
// Against cross-validated logits the objective is real: the loss is minimised
// by whatever confidence the model's held-out answers actually deserve, and the
// grid lands above 1 for a model that is over-confident on new data.
//
// A fixed deterministic grid refined twice, rather than a solver: sixty
// evaluations of a one-dimensional objective is nothing, and a grid cannot fail
// to converge or land somewhere different on another machine. Temperature
// scaling is MONOTONE in every logit at once, so it changes the confidences and
// never the ranking — which is what makes it safe to apply after the fact
// rather than a second model.
func FitTemperature(samples []CalibrationSample) float64 {
	if len(samples) == 0 {
		return 1
	}
	loss := func(t float64) float64 {
		var total float64
		for _, s := range samples {
			scaled := make([]float64, len(s.Logits))
			for i, z := range s.Logits {
				scaled[i] = z / t
			}
			p := softmax(scaled)
			var pTrue float64
			for i, c := range s.Classes {
				if c == s.True {
					pTrue = p[i]
					break
				}
			}
			total += -math.Log(math.Min(math.Max(pTrue, 1e-12), 1))
		}
		return total / float64(len(samples))
	}

	best, bestLoss := 1.0, math.Inf(1)
	low, high := 0.25, 6.0
	for range 3 {
		step := (high - low) / 20
		for i := range 21 {
			t := low + step*float64(i)
			if t <= 0 {
				continue
			}
			if l := loss(t); l < bestLoss {
				best, bestLoss = t, l
			}
		}
		low, high = math.Max(0.05, best-step), best+step
	}
	return round(best, 4)
}

// TrainAndCalibrate is the whole shipped pipeline, in one deterministic call:
// cross-validate to measure generalisation AND to collect the held-out logits,
// fit the temperature to those, then train the final weights on everything.
//
// One function rather than three steps in the trainer command, because the
// reproducibility test has to run EXACTLY what produced weights.json. A
// pipeline assembled at the call site is a pipeline the test can assemble
// differently, and the difference would show up as a weights file nobody could
// reproduce — which is the one property the file has to have.
//
// It returns the in-sample metrics and the held-out metrics, in that order.
// The model's Calibration table is the HELD-OUT one: what a class's
// probabilities were worth on data the weights had not seen is the only version
// of that number worth printing.
func TrainAndCalibrate(samples []Sample, folds int, opts TrainOptions) (*Model, Metrics, Metrics, error) {
	heldOut, calibration, err := CrossValidate(samples, folds, opts)
	if err != nil {
		return nil, Metrics{}, Metrics{}, err
	}
	m, inSample, err := Train(samples, opts)
	if err != nil {
		return nil, Metrics{}, Metrics{}, err
	}
	m.Temperature = FitTemperature(calibration)
	// Re-measure the HELD-OUT probabilities at that temperature, for exactly the
	// reason the in-sample ones are re-measured below: a number taken before the
	// calibration describes a model that was never shipped.
	//
	// CrossValidate scores each fold with a model whose Temperature is still
	// Train's default of 1, so its mean-predicted column and its log-loss are on
	// a scale nothing runs at — and here the two differ a great deal, because the
	// fitted temperature is BELOW one (the folds are under-confident, so
	// calibration sharpens them). Shipping the T=1 column under a field whose own
	// doc says to read it for over-confidence would invert the reading: every
	// class looks under-confident in the file while the shipped model is far more
	// certain than that. The accuracy is untouched — temperature scaling is
	// monotone, so it cannot move an argmax — which is why only the probabilities
	// are recomputed.
	heldOut = RescaleHeldOut(heldOut, calibration, m.Temperature)
	m.HeldOutAccuracy = round(heldOut.Accuracy, 6)
	m.Calibration = heldOut.PerClass
	// Re-measure in-sample AFTER the temperature: the accuracy is unchanged by
	// a monotone rescale, but the log-loss is not, and reporting the one from
	// before the calibration would describe a model that was never shipped.
	inSample = Evaluate(m, samples)
	m.Accuracy = round(inSample.Accuracy, 6)
	return m, inSample, heldOut, nil
}

// RescaleHeldOut recomputes the held-out probabilities at `temperature`.
//
// The fold predictions were kept as raw logits precisely so this is exact
// arithmetic rather than a second cross-validation: [CalibrationSample] carries
// the fold model's classes and its un-tempered logits, which is everything a
// probability needs. Counts, the confusion matrix and the misclassified list
// come through untouched — a monotone rescale cannot change which class won.
func RescaleHeldOut(in Metrics, calibration []CalibrationSample, temperature float64) Metrics {
	if len(calibration) == 0 || temperature <= 0 {
		return in
	}
	out := in
	sumP := map[string]float64{}
	n := map[string]int{}
	var loss float64
	for _, s := range calibration {
		scaled := make([]float64, len(s.Logits))
		for i, z := range s.Logits {
			scaled[i] = z / temperature
		}
		p := softmax(scaled)
		var pTrue float64
		for i, c := range s.Classes {
			if c == s.True {
				pTrue = p[i]
				break
			}
		}
		sumP[s.True] += pTrue
		n[s.True]++
		loss += -math.Log(math.Min(math.Max(pTrue, 1e-12), 1))
	}
	out.LogLoss = loss / float64(len(calibration))
	out.PerClass = make(map[string]ClassCalibration, len(in.PerClass))
	for class, c := range in.PerClass {
		if n[class] == 0 {
			out.PerClass[class] = c
			continue
		}
		out.PerClass[class] = ClassCalibration{
			N:             c.N,
			MeanPredicted: round(sumP[class]/float64(n[class]), 6),
			// Unchanged: temperature scaling is monotone in every logit at once,
			// so the argmax — and therefore how often the class actually won —
			// is exactly what CrossValidate measured.
			Accuracy: c.Accuracy,
		}
	}
	return out
}

// Evaluate measures a model against a labelled set.
func Evaluate(m *Model, samples []Sample) Metrics {
	return evaluatePrepared(m, prepare(samples))
}

func evaluatePrepared(m *Model, prep []prepared) Metrics {
	out := Metrics{Confusion: map[string]map[string]int{}, PerClass: map[string]ClassCalibration{}}
	var loss float64
	sumP := map[string]float64{}
	correct := map[string]int{}

	for _, p := range prep {
		s := p.sample
		scores := m.PredictVector(p.vector)
		if len(scores) == 0 {
			continue
		}
		top := scores[0]
		if s.Negative {
			out.Negatives++
			if top.Class != s.Class {
				out.NegativesHonoured++
			} else {
				out.Misclassified = append(out.Misclassified, s.Name+" (a rejected class is still the model's answer)")
			}
			continue
		}
		out.Scored++
		if out.Confusion[s.Class] == nil {
			out.Confusion[s.Class] = map[string]int{}
		}
		out.Confusion[s.Class][top.Class]++
		if top.Class == s.Class {
			out.Correct++
			correct[s.Class]++
		} else {
			out.Misclassified = append(out.Misclassified,
				fmt.Sprintf("%s (%s, want %s)", s.Name, top.Class, s.Class))
		}
		pTrue := probabilityOf(scores, s.Class)
		sumP[s.Class] += pTrue
		out.PerClass[s.Class] = ClassCalibration{N: out.PerClass[s.Class].N + 1}
		// Clamp before the log: a probability of exactly 0 would give an
		// infinite loss and destroy the mean for every other sample.
		loss += -math.Log(math.Min(math.Max(pTrue, 1e-12), 1))
	}
	if out.Scored > 0 {
		out.Accuracy = float64(out.Correct) / float64(out.Scored)
		out.LogLoss = loss / float64(out.Scored)
	}
	for class, c := range out.PerClass {
		if c.N == 0 {
			continue
		}
		out.PerClass[class] = ClassCalibration{
			N:             c.N,
			MeanPredicted: round(sumP[class]/float64(c.N), 6),
			Accuracy:      round(float64(correct[class])/float64(c.N), 6),
		}
	}
	sort.Strings(out.Misclassified)
	return out
}

func probabilityOf(scores []ClassScore, class string) float64 {
	for _, s := range scores {
		if s.Class == class {
			return s.P
		}
	}
	return 0
}

// CrossValidate trains k models, each on all but one stride of the set, and
// scores the stride it never saw.
//
// The in-sample accuracy says the FEATURES can express the fixtures. It cannot
// say the model generalises — a model with hundreds of features and a couple of
// hundred samples can fit its own training set perfectly and be worthless, and
// reading an in-sample 1.0 as evidence of quality is the same mistake as
// reading a green suite that asserts nothing.
//
// The folds are taken by index stride rather than at random, so the split is
// the same on every run and a failure is reproducible.
func CrossValidate(samples []Sample, folds int, opts TrainOptions) (Metrics, []CalibrationSample, error) {
	if folds < 2 {
		return Metrics{}, nil, fmt.Errorf("classify/model: %d folds is not cross-validation", folds)
	}
	agg := Metrics{Confusion: map[string]map[string]int{}, PerClass: map[string]ClassCalibration{}}
	sumP := map[string]float64{}
	correct := map[string]int{}
	var loss float64
	var calibration []CalibrationSample

	for fold := range folds {
		var train, held []Sample
		for i, s := range samples {
			if i%folds == fold {
				held = append(held, s)
				continue
			}
			train = append(train, s)
		}
		o := opts
		o.ModelID = fmt.Sprintf("fold-%d", fold)
		m, _, err := Train(train, o)
		if err != nil {
			return Metrics{}, nil, fmt.Errorf("fold %d: %w", fold, err)
		}
		for _, s := range held {
			if _, ok := m.Weights[s.Class]; !ok {
				// The fold's training half never saw this class, so the model
				// cannot name it. Counted as WRONG rather than skipped: a fold
				// that dropped its hard cases would flatter the model by
				// shrinking the denominator.
				agg.Scored++
				agg.Misclassified = append(agg.Misclassified, s.Name+" (class absent from the fold's training half)")
				continue
			}
			v := s.Vector()
			scores := m.PredictVector(v)
			top := scores[0]
			if s.Negative {
				agg.Negatives++
				if top.Class != s.Class {
					agg.NegativesHonoured++
				}
				continue
			}
			agg.Scored++
			if agg.Confusion[s.Class] == nil {
				agg.Confusion[s.Class] = map[string]int{}
			}
			agg.Confusion[s.Class][top.Class]++
			p := probabilityOf(scores, s.Class)
			sumP[s.Class] += p
			agg.PerClass[s.Class] = ClassCalibration{N: agg.PerClass[s.Class].N + 1}
			loss += -math.Log(math.Min(math.Max(p, 1e-12), 1))
			calibration = append(calibration, CalibrationSample{
				Classes: append([]string(nil), m.Classes...),
				Logits:  m.logits(v),
				True:    s.Class,
			})
			if top.Class == s.Class {
				agg.Correct++
				correct[s.Class]++
			} else {
				agg.Misclassified = append(agg.Misclassified,
					fmt.Sprintf("%s (%s, want %s)", s.Name, top.Class, s.Class))
			}
		}
	}
	if agg.Scored > 0 {
		agg.Accuracy = float64(agg.Correct) / float64(agg.Scored)
		agg.LogLoss = loss / float64(agg.Scored)
	}
	for class, c := range agg.PerClass {
		agg.PerClass[class] = ClassCalibration{
			N:             c.N,
			MeanPredicted: round(sumP[class]/float64(c.N), 6),
			Accuracy:      round(float64(correct[class])/float64(c.N), 6),
		}
	}
	sort.Strings(agg.Misclassified)
	return agg, calibration, nil
}

// MarshalWeights renders a model as the weights file. json.MarshalIndent sorts
// map keys, so the bytes are stable.
func MarshalWeights(m *Model) ([]byte, error) {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("classify/model: marshal weights: %w", err)
	}
	return append(raw, '\n'), nil
}

// classesOf is every class the set labels, sorted. A class that appears only as
// a REJECTION is included: "not a printer" is trainable evidence about printers,
// and leaving the class out would discard it.
func classesOf(samples []Sample) []string {
	set := map[string]bool{}
	for _, s := range samples {
		set[s.Class] = true
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
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

func orDefaultInt(v, fallback int) int {
	if v <= 0 {
		return fallback
	}
	return v
}

func orDefaultFloat(v, fallback float64) float64 {
	if v <= 0 {
		return fallback
	}
	return v
}

func orDefaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
