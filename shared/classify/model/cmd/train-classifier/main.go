// Command train-classifier fits the learned classifier's weights and writes
// weights.json.
//
// It is an operator tool, not part of any service. The weights it produces are
// committed and shipped inside the image (ADR-0008 D2), so running it is a
// deliberate act with a reviewable diff — which is the point: a model whose
// weights change without a commit is a model nobody can account for.
//
//	# reproduce the shipped weights from the shipped fixtures
//	go run ./cmd/train-classifier -out weights.json
//
//	# retrain including a tenant's real class decisions
//	go run ./cmd/train-classifier -decisions exported-decisions.json -out weights.json
//
//	# measure the shipped weights without changing them
//	go run ./cmd/train-classifier -eval-only
//
// The decisions file is the same JSON shape as the fixtures;
// docsv4/internal/developer/standards/CLASSIFICATION_RULES.md carries the query
// that produces one from `asset_history`.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/classify"
	"github.com/vistasecurity/vistaplatform/shared/classify/model"
)

func main() {
	var (
		fixtures  = flag.String("fixtures", "testdata/fixtures.json", "labelled synthetic fixtures")
		decisions = flag.String("decisions", "", "optional: exported real class decisions, same JSON shape")
		out       = flag.String("out", "", "where to write the weights file; empty prints to stdout")
		modelID   = flag.String("model-id", model.DefaultModelID, "the model id stamped on the weights")
		evalOnly  = flag.Bool("eval-only", false, "measure the weights already in -out (or the embedded ones) instead of training")
		rulesOnly = flag.Bool("rules-report", false, "print what the RULES made of each sample and stop; the curation tool for the fixtures")
		folds     = flag.Int("folds", 5, "cross-validation folds; also what the temperature is calibrated against")
		iters     = flag.Int("iterations", model.DefaultIterations, "gradient-descent iterations")
		lr        = flag.Float64("learning-rate", model.DefaultLearningRate, "gradient-descent learning rate")
		l2        = flag.Float64("l2", model.DefaultL2, "ridge penalty (not applied to the per-class bias)")
	)
	flag.Parse()

	if err := run(options{
		fixtures: *fixtures, decisions: *decisions, out: *out, modelID: *modelID,
		evalOnly: *evalOnly, rulesReport: *rulesOnly, folds: *folds,
		iterations: *iters, learningRate: *lr, l2: *l2,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "train-classifier:", err)
		os.Exit(1)
	}
}

type options struct {
	fixtures     string
	decisions    string
	out          string
	modelID      string
	evalOnly     bool
	rulesReport  bool
	folds        int
	iterations   int
	learningRate float64
	l2           float64
}

func run(o options) error {
	samples, provenance, err := loadSamples(o.fixtures, o.decisions)
	if err != nil {
		return err
	}
	positives, negatives := 0, 0
	byClass := map[string]int{}
	for _, s := range samples {
		if s.Negative {
			negatives++
			continue
		}
		positives++
		byClass[s.Class]++
	}
	fmt.Fprintf(os.Stderr, "%d samples (%d labelled, %d rejections) over %d classes, from %s\n",
		len(samples), positives, negatives, len(byClass), provenance)

	if o.rulesReport {
		rulesReport(samples)
		return nil
	}
	reportRuleOutcomeSummary(samples)

	opts := model.TrainOptions{
		Iterations:   o.iterations,
		LearningRate: o.learningRate,
		L2:           o.l2,
		ModelID:      o.modelID,
		TrainedOn:    provenance,
	}

	var m *model.Model
	var metrics, heldOut model.Metrics
	if o.evalOnly {
		if m, err = loadExisting(o.out); err != nil {
			return err
		}
		metrics = model.Evaluate(m, samples)
		if o.folds >= 2 {
			var calibration []model.CalibrationSample
			if heldOut, calibration, err = model.CrossValidate(samples, o.folds, opts); err != nil {
				return err
			}
			// On the scale the loaded weights RUN at, exactly as -out reports
			// it. CrossValidate scores its folds un-tempered, so without this
			// the two commands would print different held-out log-losses and
			// different per-class probabilities for the same weights file, with
			// nothing on screen saying which was which.
			heldOut = model.RescaleHeldOut(heldOut, calibration, m.Temperature)
		}
	} else if m, metrics, heldOut, err = model.TrainAndCalibrate(samples, o.folds, opts); err != nil {
		return err
	}

	report(m, metrics, heldOut, byClass)

	if o.evalOnly {
		return nil
	}
	raw, err := model.MarshalWeights(m)
	if err != nil {
		return err
	}
	if o.out == "" {
		_, err = os.Stdout.Write(raw)
		return err
	}
	if err := os.WriteFile(o.out, raw, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", o.out, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", filepath.Clean(o.out))
	return nil
}

// loadSamples reads the fixtures and, when given, appends the exported real
// decisions.
//
// Appended rather than replacing, and weighted equally. The fixtures encode the
// traps a tenant's own history may contain NONE of — nobody has been asked
// about an HTTP banner on a printer if they own no printers — and dropping them
// would let one population teach the model that a trap it has never seen does
// not exist.
func loadSamples(fixtures, decisions string) ([]model.Sample, string, error) {
	raw, err := os.ReadFile(fixtures) //nolint:gosec // an operator-supplied path is the point of the flag
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", fixtures, err)
	}
	samples, err := model.ParseSamples(raw)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", fixtures, err)
	}
	provenance := fmt.Sprintf("%d synthetic fixtures", len(samples))
	if decisions == "" {
		return samples, provenance, nil
	}

	rawDecisions, err := os.ReadFile(decisions) //nolint:gosec // ditto
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", decisions, err)
	}
	real, err := model.ParseSamples(rawDecisions)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", decisions, err)
	}
	provenance = fmt.Sprintf("%s + %d exported class decisions", provenance, len(real))
	return append(samples, real...), provenance, nil
}

// ruleOutcome is what the shipped rule table made of one sample: the class it
// decided, the classes it could not choose between, or nothing.
func ruleOutcome(s model.Sample) (state, detail string) {
	prop := classify.Default().Classify(context.Background(), s.Facts.Input())
	switch {
	case prop.Conflict:
		return "conflict", strings.Join(prop.ConflictingClasses, " vs ")
	case prop.Class != "":
		return "decided", fmt.Sprintf("%s @ %.2f", prop.Class, prop.Confidence)
	default:
		return "silent", ""
	}
}

// rulesReport prints what the rules made of every sample.
//
// The fixtures exist to teach the model where the RULES cannot answer, so the
// distribution of this table is the thing to curate: a set dominated by samples
// the rules already decide would measure how well the model echoes them, which
// is not a question anybody has.
func rulesReport(samples []model.Sample) {
	counts := map[string]int{}
	for _, s := range samples {
		state, detail := ruleOutcome(s)
		counts[state]++
		label := s.Class
		if s.Negative {
			label = "NOT " + label
		}
		_, _ = fmt.Fprintf(os.Stdout, "%-8s %-46s %-22s %s\n", state, s.Name, label, detail)
	}
	_, _ = fmt.Fprintf(os.Stdout, "\nsilent %d, conflict %d, decided %d\n",
		counts["silent"], counts["conflict"], counts["decided"])
}

func reportRuleOutcomeSummary(samples []model.Sample) {
	counts := map[string]int{}
	for _, s := range samples {
		state, _ := ruleOutcome(s)
		counts[state]++
	}
	fmt.Fprintf(os.Stderr, "  the rules are silent on %d, conflicted on %d, and decide %d of them\n",
		counts["silent"], counts["conflict"], counts["decided"])
}

func loadExisting(path string) (*model.Model, error) {
	if path == "" {
		return model.Default()
	}
	raw, err := os.ReadFile(path) //nolint:gosec // ditto
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return model.LoadModel(raw)
}

func report(m *model.Model, metrics, heldOut model.Metrics, byClass map[string]int) {
	fmt.Fprintf(os.Stderr, "\nmodel %s  (temperature %.4f, schema %s)\n", m.ModelID, m.Temperature, m.FeatureSchema)
	fmt.Fprintf(os.Stderr, "  in-sample accuracy %.4f over %d labelled, log-loss %.4f\n",
		metrics.Accuracy, metrics.Scored, metrics.LogLoss)
	if metrics.Negatives > 0 {
		fmt.Fprintf(os.Stderr, "  rejections honoured %d/%d\n", metrics.NegativesHonoured, metrics.Negatives)
	}
	if heldOut.Scored > 0 {
		fmt.Fprintf(os.Stderr, "  HELD-OUT accuracy   %.4f over %d, log-loss %.4f\n",
			heldOut.Accuracy, heldOut.Scored, heldOut.LogLoss)
	}

	fmt.Fprint(os.Stderr, "\nconfusion (in-sample)\n", metrics.ConfusionMatrix())
	if heldOut.Scored > 0 {
		fmt.Fprint(os.Stderr, "\nconfusion (held out)\n", heldOut.ConfusionMatrix())
	}

	fmt.Fprintln(os.Stderr, "\nper class: samples, held-out mean P of the true class, held-out accuracy")
	classes := make([]string, 0, len(byClass))
	for c := range byClass {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	for _, c := range classes {
		cal := heldOut.PerClass[c]
		fmt.Fprintf(os.Stderr, "  %-22s %3d   P=%.3f  acc=%.3f\n", c, byClass[c], cal.MeanPredicted, cal.Accuracy)
	}

	misses := heldOut.Misclassified
	label := "held out"
	if len(misses) == 0 {
		misses, label = metrics.Misclassified, "in sample"
	}
	if len(misses) > 0 {
		fmt.Fprintf(os.Stderr, "\nmisclassified (%s, %d):\n", label, len(misses))
		for _, n := range misses {
			fmt.Fprintf(os.Stderr, "  %s\n", n)
		}
	}
}
