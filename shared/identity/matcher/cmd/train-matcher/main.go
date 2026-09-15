// Command train-matcher fits the learned matcher's weights and writes
// weights.json.
//
// It is an operator tool, not part of any service. The weights it produces are
// committed and shipped inside the image (ADR-0008 D2), so running it is a
// deliberate act with a reviewable diff — which is the point: a model whose
// weights change without a commit is a model nobody can account for.
//
//	# reproduce the shipped weights from the shipped fixtures
//	go run ./cmd/train-matcher -out weights.json
//
//	# retrain including a tenant's real merge decisions
//	go run ./cmd/train-matcher -decisions exported-decisions.json -out weights.json
//
//	# measure the shipped weights without changing them
//	go run ./cmd/train-matcher -eval-only
//
// The decisions file is the same JSON shape as the fixtures; MATCHER.md carries
// the query that produces one from `asset_history`.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vistasecurity/vistaplatform/shared/identity/matcher"
)

func main() {
	var (
		fixtures  = flag.String("fixtures", "testdata/fixtures.json", "labelled synthetic fixtures")
		decisions = flag.String("decisions", "", "optional: exported real merge decisions, same JSON shape")
		out       = flag.String("out", "", "where to write the weights file; empty prints to stdout")
		modelID   = flag.String("model-id", "matcher-logreg-v1", "the model id stamped on the weights")
		evalOnly  = flag.Bool("eval-only", false, "measure the weights already in -out (or the embedded ones) instead of training")
		iters     = flag.Int("iterations", matcher.DefaultIterations, "gradient-descent iterations")
		lr        = flag.Float64("learning-rate", matcher.DefaultLearningRate, "gradient-descent learning rate")
		l2        = flag.Float64("l2", matcher.DefaultL2, "ridge penalty (not applied to the bias)")
	)
	flag.Parse()

	if err := run(*fixtures, *decisions, *out, *modelID, *evalOnly, *iters, *lr, *l2); err != nil {
		fmt.Fprintln(os.Stderr, "train-matcher:", err)
		os.Exit(1)
	}
}

func run(fixtures, decisions, out, modelID string, evalOnly bool, iters int, lr, l2 float64) error {
	samples, provenance, err := loadSamples(fixtures, decisions)
	if err != nil {
		return err
	}
	positives := 0
	for _, s := range samples {
		if s.Match {
			positives++
		}
	}
	fmt.Fprintf(os.Stderr, "%d samples (%d match, %d separate) from %s\n",
		len(samples), positives, len(samples)-positives, provenance)

	var model *matcher.Model
	var metrics matcher.Metrics
	if evalOnly {
		if model, err = loadExisting(out); err != nil {
			return err
		}
		metrics = matcher.Evaluate(model, samples)
	} else {
		model, metrics, err = matcher.Train(samples, matcher.TrainOptions{
			Iterations:   iters,
			LearningRate: lr,
			L2:           l2,
			ModelID:      modelID,
			TrainedOn:    provenance,
		})
		if err != nil {
			return err
		}
	}

	report(model, metrics)

	if evalOnly {
		return nil
	}
	raw, err := matcher.MarshalWeights(model)
	if err != nil {
		return err
	}
	if out == "" {
		_, err = os.Stdout.Write(raw)
		return err
	}
	if err := os.WriteFile(out, raw, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", filepath.Clean(out))
	return nil
}

// loadSamples reads the fixtures and, when given, appends the exported real
// decisions.
//
// They are appended rather than replacing the fixtures, and weighted equally.
// The fixtures encode the failure modes a tenant's own history may contain NONE
// of — nobody has yet been asked about the two VPCs sharing a CIDR if they do
// not have two — and dropping them would let one tenant's population teach the
// model that a trap it has never seen does not exist.
func loadSamples(fixtures, decisions string) ([]matcher.Sample, string, error) {
	raw, err := os.ReadFile(fixtures) //nolint:gosec // an operator-supplied path is the point of the flag
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", fixtures, err)
	}
	samples, err := matcher.ParseSamples(raw)
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
	real, err := matcher.ParseSamples(rawDecisions)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", decisions, err)
	}
	provenance = fmt.Sprintf("%s + %d exported merge decisions", provenance, len(real))
	return append(samples, real...), provenance, nil
}

func loadExisting(path string) (*matcher.Model, error) {
	if path == "" {
		return matcher.Default()
	}
	raw, err := os.ReadFile(path) //nolint:gosec // ditto
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return matcher.LoadModel(raw)
}

func report(m *matcher.Model, metrics matcher.Metrics) {
	fmt.Fprintf(os.Stderr, "\nmodel %s\n", m.ModelID)
	fmt.Fprintf(os.Stderr, "  accuracy %.4f  precision %.4f  recall %.4f  log-loss %.4f\n",
		metrics.Accuracy, metrics.Precision, metrics.Recall, metrics.LogLoss)
	fmt.Fprint(os.Stderr, "\n", metrics.ConfusionMatrix())
	if len(metrics.Misclassified) > 0 {
		fmt.Fprintf(os.Stderr, "\nmisclassified (%d):\n", len(metrics.Misclassified))
		for _, n := range metrics.Misclassified {
			fmt.Fprintf(os.Stderr, "  %s\n", n)
		}
	}
	fmt.Fprintln(os.Stderr, "\nweights (log-odds), largest first:")
	for _, w := range sortedWeights(m) {
		fmt.Fprintf(os.Stderr, "  %+9.4f  %s\n", w.weight, w.name)
	}
}

type namedWeight struct {
	name   string
	weight float64
}

func sortedWeights(m *matcher.Model) []namedWeight {
	out := make([]namedWeight, 0, len(m.Weights))
	for _, n := range matcher.FeatureNames() {
		out = append(out, namedWeight{n, m.Weights[n]})
	}
	// Insertion sort by absolute weight: the list is twenty long and this keeps
	// the tool free of a sort import for one call.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && abs(out[j].weight) > abs(out[j-1].weight); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}
