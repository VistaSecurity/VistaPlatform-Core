package matcher_test

import (
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity/matcher"
)

const fixturesPath = "testdata/fixtures.json"

func loadFixtures(t *testing.T) []matcher.Sample {
	t.Helper()
	raw, err := os.ReadFile(fixturesPath)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	s, err := matcher.ParseSamples(raw)
	if err != nil {
		t.Fatalf("parse fixtures: %v", err)
	}
	if len(s) < 40 {
		t.Fatalf("the fixture set has shrunk to %d samples; it is the model's whole evidence base", len(s))
	}
	return s
}

func defaultModel(t *testing.T) *matcher.Model {
	t.Helper()
	m, err := matcher.Default()
	if err != nil {
		t.Fatalf("load the embedded model: %v", err)
	}
	return m
}

// ── the shipped weights ────────────────────────────────────────────────────

// The embedded weights must be the ones the committed fixtures produce.
//
// Without this, weights.json is a file somebody once generated and nobody can
// account for: a hand-edited weight, or one trained on a set that was then
// changed, would ship indistinguishably from a real one. Reproducibility is the
// only provenance a number like this can have.
func TestEmbeddedWeightsAreReproducibleFromTheFixtures(t *testing.T) {
	samples := loadFixtures(t)
	trained, _, err := matcher.Train(samples, matcher.TrainOptions{
		ModelID:   "matcher-logreg-v1",
		TrainedOn: fmt.Sprintf("%d synthetic fixtures", len(samples)),
	})
	if err != nil {
		t.Fatalf("train: %v", err)
	}
	shipped := defaultModel(t)

	if shipped.ModelID != trained.ModelID {
		t.Errorf("model id: shipped %q, retrained %q", shipped.ModelID, trained.ModelID)
	}
	for name, want := range trained.Weights {
		got, ok := shipped.Weights[name]
		if !ok {
			t.Errorf("weights.json is missing %s", name)
			continue
		}
		if got != want {
			t.Errorf("weights.json %s = %v, retraining the committed fixtures gives %v"+
				" — regenerate with `go run ./cmd/train-matcher -out weights.json`", name, got, want)
		}
	}
}

func TestEmbeddedModelValidates(t *testing.T) {
	if err := defaultModel(t).Validate(); err != nil {
		t.Fatalf("the embedded model is not usable by this build: %v", err)
	}
}

// A weights file from a build with a different feature set must be REFUSED,
// both ways round. A missing weight reads as zero — a feature the model was
// trained to weigh, silently contributing nothing — and an extra one means the
// remaining weights were fitted alongside something this build no longer has.
func TestValidateRefusesAFeatureSetMismatch(t *testing.T) {
	base := defaultModel(t)
	t.Run("missing", func(t *testing.T) {
		m := &matcher.Model{ModelID: "x", Weights: map[string]float64{}}
		for k, v := range base.Weights {
			m.Weights[k] = v
		}
		delete(m.Weights, matcher.FeatureSegmentMatch)
		if err := m.Validate(); err == nil {
			t.Fatal("a model missing a weight was accepted")
		}
	})
	t.Run("extra", func(t *testing.T) {
		m := &matcher.Model{ModelID: "x", Weights: map[string]float64{"invented_feature": 1}}
		for k, v := range base.Weights {
			m.Weights[k] = v
		}
		if err := m.Validate(); err == nil {
			t.Fatal("a model carrying an unknown weight was accepted")
		}
	})
	t.Run("no model id", func(t *testing.T) {
		m := &matcher.Model{Weights: base.Weights}
		if err := m.Validate(); err == nil {
			t.Fatal("a model with no id was accepted")
		}
	})
}

// ── fit and generalisation ─────────────────────────────────────────────────

func TestFixtureAccuracy(t *testing.T) {
	m := defaultModel(t)
	samples := loadFixtures(t)
	metrics := matcher.Evaluate(m, samples)

	t.Logf("accuracy %.4f  precision %.4f  recall %.4f  log-loss %.4f\n\n%s",
		metrics.Accuracy, metrics.Precision, metrics.Recall, metrics.LogLoss, metrics.ConfusionMatrix())

	if metrics.Accuracy < 0.9 {
		t.Errorf("accuracy %.4f is below the 0.90 floor; misclassified: %v",
			metrics.Accuracy, metrics.Misclassified)
	}
	if metrics.TruePositives+metrics.FalseNegatives == 0 || metrics.TrueNegatives+metrics.FalsePositives == 0 {
		t.Fatal("the fixture set has lost one of its two classes; accuracy over one class is meaningless")
	}
}

// Five-fold cross-validation: train on four fifths, score the fifth the model
// has never seen.
//
// The in-sample accuracy above says the FEATURES can express the traps. It
// cannot say the model generalises — a model with twenty features and seventy
// samples can fit its own training set perfectly and be worthless, and reading
// an in-sample 1.0 as evidence of quality is the same mistake as reading a
// green test suite that asserts nothing.
//
// The folds are taken by index stride rather than at random, so the split is
// the same on every run and a failure is reproducible.
func TestHeldOutFoldsGeneralise(t *testing.T) {
	samples := loadFixtures(t)
	const folds = 5

	var totalCorrect, totalScored int
	for fold := range folds {
		var train, held []matcher.Sample
		for i, s := range samples {
			if i%folds == fold {
				held = append(held, s)
				continue
			}
			train = append(train, s)
		}
		m, _, err := matcher.Train(train, matcher.TrainOptions{ModelID: fmt.Sprintf("fold-%d", fold)})
		if err != nil {
			t.Fatalf("fold %d: train: %v", fold, err)
		}
		metrics := matcher.Evaluate(m, held)
		t.Logf("fold %d: %d held out, accuracy %.4f, misclassified %v",
			fold, len(held), metrics.Accuracy, metrics.Misclassified)
		totalCorrect += metrics.TruePositives + metrics.TrueNegatives
		totalScored += len(held)
	}

	accuracy := float64(totalCorrect) / float64(totalScored)
	t.Logf("held-out accuracy across %d folds: %.4f (%d/%d)", folds, accuracy, totalCorrect, totalScored)
	if accuracy < 0.9 {
		t.Errorf("held-out accuracy %.4f is below the 0.90 floor", accuracy)
	}
}

// The scores must be on the right SIDE of 0.5, which is a stronger statement
// than the accuracy number: it is the statement a tenant relies on when they
// set a threshold.
func TestPositivesScoreAboveAHalfAndNegativesBelow(t *testing.T) {
	m := defaultModel(t)
	for _, s := range loadFixtures(t) {
		p, err := s.Pair()
		if err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
		score := m.Score(p)
		if s.Match && score < 0.5 {
			t.Errorf("%s: a match scored %.4f, below 0.5", s.Name, score)
		}
		if !s.Match && score >= 0.5 {
			t.Errorf("%s: a non-match scored %.4f, at or above 0.5", s.Name, score)
		}
	}
}

// Calibration: the mean score over the matches must be well above the mean over
// the non-matches, and the log-loss low enough that 0.5 means something.
//
// "0.5 = as likely as not" is what makes a tenant's threshold a meaningful
// number rather than a position on an arbitrary scale, and it is the one
// property of this model a tenant depends on without being told about it.
func TestScoreIsCalibrated(t *testing.T) {
	m := defaultModel(t)
	var posSum, negSum float64
	var pos, neg int
	for _, s := range loadFixtures(t) {
		p, _ := s.Pair()
		score := m.Score(p)
		if s.Match {
			posSum += score
			pos++
			continue
		}
		negSum += score
		neg++
	}
	meanPos, meanNeg := posSum/float64(pos), negSum/float64(neg)
	t.Logf("mean score: matches %.4f, non-matches %.4f", meanPos, meanNeg)
	if meanPos < 0.7 {
		t.Errorf("matches average %.4f: the model is under-confident about pairs that ARE the same", meanPos)
	}
	if meanNeg > 0.3 {
		t.Errorf("non-matches average %.4f: the model is over-confident about pairs that are NOT", meanNeg)
	}
	if metrics := matcher.Evaluate(m, loadFixtures(t)); metrics.LogLoss > 0.35 {
		t.Errorf("log-loss %.4f: the scores are on the right side of 0.5 but are not calibrated", metrics.LogLoss)
	}
}

// ── the individual features ────────────────────────────────────────────────

func side(name, class, segment string, ids map[string]string) matcher.Side {
	return matcher.Side{
		Name:        name,
		Class:       class,
		Segment:     segment,
		Identifiers: ids,
		SourceKind:  "measured",
		SeenAt:      time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC),
	}
}

func TestEveryFeatureIsExercisedByTheFixtures(t *testing.T) {
	// A feature no fixture ever sets is a feature whose weight was fitted on
	// nothing: the trainer leaves it at whatever the ridge penalty pulls it to
	// and the number reads as an opinion the data never expressed.
	seen := map[string]bool{}
	for _, s := range loadFixtures(t) {
		p, _ := s.Pair()
		for name, v := range matcher.Features(p) {
			if v != 0 {
				seen[name] = true
			}
		}
	}
	for _, name := range matcher.FeatureNames() {
		if !seen[name] {
			t.Errorf("no fixture ever sets %s; its weight is fitted on no evidence", name)
		}
	}
}

func TestIdentifierFeatures(t *testing.T) {
	cases := []struct {
		name    string
		obs     map[string]string
		cand    map[string]string
		want    map[string]float64
		notWant []string
	}{
		{
			name: "singleton agreement",
			obs:  map[string]string{matcher.KindSerialNumber: "abc"},
			cand: map[string]string{matcher.KindSerialNumber: "abc"},
			want: map[string]float64{matcher.FeatureIDMatchSingleton: 1, matcher.FeatureIDMatchBreadth: 0.25},
			notWant: []string{
				matcher.FeatureIDConflictSingleton, matcher.FeatureIDMatchStrong, matcher.FeatureIDMatchWeak,
			},
		},
		{
			name:    "singleton disagreement",
			obs:     map[string]string{matcher.KindCloudResourceID: "arn:a"},
			cand:    map[string]string{matcher.KindCloudResourceID: "arn:b"},
			want:    map[string]float64{matcher.FeatureIDConflictSingleton: 1, matcher.FeatureIDMatchBreadth: 0},
			notWant: []string{matcher.FeatureIDMatchSingleton},
		},
		{
			name:    "strong agreement",
			obs:     map[string]string{matcher.KindMACAddress: "aa:bb:cc:00:00:01"},
			cand:    map[string]string{matcher.KindMACAddress: "aa:bb:cc:00:00:01"},
			want:    map[string]float64{matcher.FeatureIDMatchStrong: 1},
			notWant: []string{matcher.FeatureIDMatchSingleton, matcher.FeatureIDMatchWeak},
		},
		{
			name: "a differing MAC is not a conflict — a machine has several",
			obs:  map[string]string{matcher.KindMACAddress: "aa:bb:cc:00:00:01"},
			cand: map[string]string{matcher.KindMACAddress: "aa:bb:cc:00:00:02"},
			notWant: []string{
				matcher.FeatureIDConflictSingleton, matcher.FeatureIDMatchStrong,
			},
		},
		{
			name:    "weak agreement",
			obs:     map[string]string{matcher.KindHostname: "db01"},
			cand:    map[string]string{matcher.KindHostname: "db01"},
			want:    map[string]float64{matcher.FeatureIDMatchWeak: 1},
			notWant: []string{matcher.FeatureIDMatchStrong},
		},
		{
			name: "breadth caps at four kinds",
			obs: map[string]string{
				matcher.KindSerialNumber: "s", matcher.KindMACAddress: "m", matcher.KindFQDN: "f.example.com",
				matcher.KindHostname: "f", matcher.KindIPAddress: "198.51.100.1",
			},
			cand: map[string]string{
				matcher.KindSerialNumber: "s", matcher.KindMACAddress: "m", matcher.KindFQDN: "f.example.com",
				matcher.KindHostname: "f", matcher.KindIPAddress: "198.51.100.1",
			},
			want: map[string]float64{matcher.FeatureIDMatchBreadth: 1},
		},
		{
			name:    "an empty value on one side is absent, not agreement",
			obs:     map[string]string{matcher.KindSerialNumber: ""},
			cand:    map[string]string{matcher.KindSerialNumber: ""},
			notWant: []string{matcher.FeatureIDMatchSingleton, matcher.FeatureIDConflictSingleton},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := matcher.Features(matcher.Pair{
				Observation: side("", "server", "seg", tc.obs),
				Candidate:   side("", "server", "seg", tc.cand),
			})
			for name, want := range tc.want {
				if got := v.At(name); got != want {
					t.Errorf("%s = %v, want %v", name, got, want)
				}
			}
			for _, name := range tc.notWant {
				if got := v.At(name); got != 0 {
					t.Errorf("%s = %v, want 0", name, got)
				}
			}
		})
	}
}

func TestAgreementFeaturesTreatUnknownAsNeither(t *testing.T) {
	// "Not assessed stays not assessed" (ADR-0008 D4.3) at the feature level:
	// an unknown vendor must not read as agreement OR as disagreement.
	cases := []struct {
		name                          string
		obsVendor, candVendor         string
		wantMatch, wantConflict       float64
		obsSegment, candSegment       string
		wantSegMatch, wantSegConflict float64
	}{
		{"both known and equal", "Dell", "dell", 1, 0, "s1", "s1", 1, 0},
		{"both known and different", "Dell", "HPE", 0, 1, "s1", "s2", 0, 1},
		{"one unknown", "Dell", "", 0, 0, "s1", "", 0, 0},
		{"both unknown", "", "", 0, 0, "", "", 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obs := side("a", "server", tc.obsSegment, map[string]string{matcher.KindHostname: "a"})
			cand := side("a", "server", tc.candSegment, map[string]string{matcher.KindHostname: "a"})
			obs.Vendor, cand.Vendor = tc.obsVendor, tc.candVendor
			v := matcher.Features(matcher.Pair{Observation: obs, Candidate: cand})
			if got := v.At(matcher.FeatureVendorMatch); got != tc.wantMatch {
				t.Errorf("vendor_match = %v, want %v", got, tc.wantMatch)
			}
			if got := v.At(matcher.FeatureVendorConflict); got != tc.wantConflict {
				t.Errorf("vendor_conflict = %v, want %v", got, tc.wantConflict)
			}
			if got := v.At(matcher.FeatureSegmentMatch); got != tc.wantSegMatch {
				t.Errorf("segment_match = %v, want %v", got, tc.wantSegMatch)
			}
			if got := v.At(matcher.FeatureSegmentConflict); got != tc.wantSegConflict {
				t.Errorf("segment_conflict = %v, want %v", got, tc.wantSegConflict)
			}
		})
	}
}

func TestClassFeatures(t *testing.T) {
	cases := []struct {
		obs, cand string
		want      string
	}{
		{"server", "server", matcher.FeatureClassEqual},
		{"server", "computer", matcher.FeatureClassRelated},
		{"computer", "server", matcher.FeatureClassRelated},
		{"printer", "firewall", matcher.FeatureClassConflict},
		{"", "server", ""},
		{"server", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.obs+"/"+tc.cand, func(t *testing.T) {
			v := matcher.Features(matcher.Pair{
				Observation: side("x", tc.obs, "s", nil),
				Candidate:   side("x", tc.cand, "s", nil),
			})
			for _, name := range []string{matcher.FeatureClassEqual, matcher.FeatureClassRelated, matcher.FeatureClassConflict} {
				want := 0.0
				if name == tc.want {
					want = 1
				}
				if got := v.At(name); got != want {
					t.Errorf("%s = %v, want %v", name, got, want)
				}
			}
		})
	}
}

func TestRecencyDecays(t *testing.T) {
	base := time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)
	at := func(d time.Duration) matcher.Side {
		s := side("x", "server", "s", nil)
		s.SeenAt = base.Add(d)
		return s
	}
	same := matcher.Features(matcher.Pair{Observation: at(0), Candidate: at(0)}).At(matcher.FeatureRecency)
	month := matcher.Features(matcher.Pair{Observation: at(0), Candidate: at(-30 * 24 * time.Hour)}).At(matcher.FeatureRecency)
	year := matcher.Features(matcher.Pair{Observation: at(0), Candidate: at(-365 * 24 * time.Hour)}).At(matcher.FeatureRecency)

	if same != 1 {
		t.Errorf("two sightings at the same moment: recency = %v, want 1", same)
	}
	if math.Abs(month-math.Exp(-1)) > 1e-9 {
		t.Errorf("a month apart: recency = %v, want %v", month, math.Exp(-1))
	}
	if !(year < month && month < same) {
		t.Errorf("recency is not monotonically decreasing: %v %v %v", year, month, same)
	}

	// An unknown time reads 0, not "a very long time ago". "We do not know" and
	// "last seen in 1970" are different facts and only one of them is evidence.
	unknown := side("x", "server", "s", nil)
	unknown.SeenAt = time.Time{}
	if got := matcher.Features(matcher.Pair{Observation: at(0), Candidate: unknown}).At(matcher.FeatureRecency); got != 0 {
		t.Errorf("an unknown last-seen gave recency %v, want 0", got)
	}
}

func TestNameSimilarityAndSequentialNames(t *testing.T) {
	cases := []struct {
		a, b           string
		minSimilarity  float64
		maxSimilarity  float64
		wantSequential bool
	}{
		{"db01.corp.example.com", "db01", 0.2, 1, false},
		{"esx-prod-04", "esxprod04", 0.8, 1, false},
		{"web01", "web02", 0.8, 1, true},
		{"web01.corp.example.com", "web02.corp.example.com", 0.8, 1, true},
		{"web01.corp.example.com", "web02.lab.example.net", 0, 1, false},
		{"alpha", "zulu", 0, 0.5, false},
		{"", "anything", 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.a+"/"+tc.b, func(t *testing.T) {
			v := matcher.Features(matcher.Pair{
				Observation: side(tc.a, "server", "s", nil),
				Candidate:   side(tc.b, "server", "s", nil),
			})
			sim := v.At(matcher.FeatureNameSimilarity)
			if sim < tc.minSimilarity || sim > tc.maxSimilarity {
				t.Errorf("similarity = %v, want within [%v, %v]", sim, tc.minSimilarity, tc.maxSimilarity)
			}
			seq := v.At(matcher.FeatureNameTrailingDigitsDiffer) == 1
			if seq != tc.wantSequential {
				t.Errorf("sequential = %v, want %v", seq, tc.wantSequential)
			}
		})
	}
}

// A name-like identifier on one side must be compared against the other side's
// name, not only against ITS name-like identifier: the two sources disagree
// about which field they fill far more often than about the name.
func TestNameComparisonCrossesTheNameAndTheIdentifiers(t *testing.T) {
	obs := side("", "server", "s", map[string]string{matcher.KindFQDN: "db01.corp.example.com"})
	cand := side("db01.corp.example.com", "server", "s", nil)
	if got := matcher.Features(matcher.Pair{Observation: obs, Candidate: cand}).At(matcher.FeatureNameSimilarity); got != 1 {
		t.Errorf("an FQDN identifier against the same string as a display name scored %v, want 1", got)
	}
}

func TestSymmetry(t *testing.T) {
	// Nothing about "is this the same thing as that" depends on which of the
	// two was named first, so the extractor must be symmetric. It is not a
	// property the model can be asked for — the CALLER always passes the
	// observation first — but an asymmetry here would be a silent bug in a
	// feature, and every feature is a comparison.
	m := defaultModel(t)
	for _, s := range loadFixtures(t) {
		p, _ := s.Pair()
		flipped := matcher.Pair{Observation: p.Candidate, Candidate: p.Observation}
		a, b := m.Score(p), m.Score(flipped)
		if math.Abs(a-b) > 1e-12 {
			t.Errorf("%s: score %v one way and %v the other", s.Name, a, b)
		}
	}
}

// Monotonicity: adding an identifier that AGREES can only raise the score.
//
// It is the property a reviewer assumes without being told — "more evidence
// they are the same cannot make the model less sure" — and nothing about a
// logistic regression guarantees it. It holds because the extractor's
// identifier features are all indicators that can only turn ON, the breadth
// feature can only rise, the name similarity is a maximum over a growing set,
// and the one feature that could fall (`name_sequential`) has a negative
// weight, so losing it also raises the score. [TestTrainedWeightSigns] is the
// other half: the arithmetic only works while those weights keep their signs.
func TestAddingAMatchingIdentifierNeverLowersTheScore(t *testing.T) {
	m := defaultModel(t)
	extra := []struct{ kind, value string }{
		{matcher.KindSerialNumber, "zzz-999"},
		{matcher.KindAgentID, "ag-zzz"},
		{matcher.KindCloudResourceID, "arn:aws:ec2:us-east-1:1:instance/i-0zzz"},
		{matcher.KindCMDBSysID, "sys-zzz"},
		{matcher.KindMACAddress, "aa:bb:cc:zz:zz:zz"},
		{matcher.KindSSHHostKeyFingerprint, "SHA256:zzzzzz"},
		{matcher.KindFQDN, "extra-host.corp.example.com"},
		{matcher.KindHostname, "extra-host"},
		{matcher.KindIPAddress, "198.51.100.254"},
		{matcher.KindName, "extra name"},
	}
	for _, s := range loadFixtures(t) {
		p, _ := s.Pair()
		before := m.Score(p)
		for _, e := range extra {
			if _, taken := p.Observation.Identifiers[e.kind]; taken {
				continue
			}
			if _, taken := p.Candidate.Identifiers[e.kind]; taken {
				continue
			}
			after := m.Score(withIdentifier(p, e.kind, e.value))
			if after < before-1e-12 {
				t.Errorf("%s: adding a matching %s lowered the score from %.6f to %.6f",
					s.Name, e.kind, before, after)
			}
		}
	}
}

func withIdentifier(p matcher.Pair, kind, value string) matcher.Pair {
	add := func(s matcher.Side) matcher.Side {
		ids := make(map[string]string, len(s.Identifiers)+1)
		for k, v := range s.Identifiers {
			ids[k] = v
		}
		ids[kind] = value
		s.Identifiers = ids
		return s
	}
	return matcher.Pair{Observation: add(p.Observation), Candidate: add(p.Candidate)}
}

// The signs the monotonicity argument rests on. A retrain that flipped one of
// these would leave the model still accurate and still explainable, and quietly
// untrue to the property above.
func TestTrainedWeightSigns(t *testing.T) {
	m := defaultModel(t)
	nonNegative := []string{
		matcher.FeatureIDMatchSingleton, matcher.FeatureIDMatchStrong, matcher.FeatureIDMatchWeak,
		matcher.FeatureIDMatchBreadth, matcher.FeatureNameSimilarity,
	}
	for _, name := range nonNegative {
		if m.Weights[name] < 0 {
			t.Errorf("%s has weight %v: evidence of sameness must not subtract", name, m.Weights[name])
		}
	}
	nonPositive := []string{matcher.FeatureIDConflictSingleton, matcher.FeatureNameTrailingDigitsDiffer}
	for _, name := range nonPositive {
		if m.Weights[name] > 0 {
			t.Errorf("%s has weight %v: evidence of difference must not add", name, m.Weights[name])
		}
	}
}

// The paired attribute features must not contradict each other: whatever the
// model makes of knowing an attribute, AGREEING on it may never be worse
// evidence than DISAGREEING on it.
//
// This is a separate statement from the signs above, and the one the shipped
// weights actually need. `vendor_match` is NEGATIVE (−0.38) and that is
// documented and intended — a rack of identical switches agrees on vendor and
// model and is not one switch, so "same vendor" alone is weak-to-negative
// evidence. Nothing was checking the thing that makes that reading coherent,
// namely that `vendor_conflict` is lower still. A retrain on a skewed export
// could produce `vendor_conflict > vendor_match` — a model asserting that
// *different* vendors are better evidence of sameness than the same vendor —
// and it would keep its accuracy, keep its held-out score, satisfy
// TestTrainedWeightSigns (neither feature is in either list) and ship.
//
// It is an ORDERING and not a sign, deliberately: pinning `vendor_match >= 0`
// would fail the shipped model for a fact about the world it learned correctly.
//
// `source_same` / `source_cross` are NOT a pair of this kind and are excluded.
// Both are "known", and which of them is evidence of sameness is genuinely the
// model's to learn: two independent sources corroborating is the textbook
// positive, one collector emitting two rows for one thing the textbook
// duplicate. The weights say cross +0.72 / same −0.92, which is that finding,
// not an inconsistency.
func TestAgreeingIsNeverWorseEvidenceThanDisagreeing(t *testing.T) {
	m := defaultModel(t)
	for _, pair := range []struct{ agree, conflict string }{
		{matcher.FeatureVendorMatch, matcher.FeatureVendorConflict},
		{matcher.FeatureModelMatch, matcher.FeatureModelConflict},
		{matcher.FeatureClassEqual, matcher.FeatureClassConflict},
		{matcher.FeatureClassRelated, matcher.FeatureClassConflict},
		{matcher.FeatureSegmentMatch, matcher.FeatureSegmentConflict},
		{matcher.FeatureIDMatchSingleton, matcher.FeatureIDConflictSingleton},
	} {
		if m.Weights[pair.agree] < m.Weights[pair.conflict] {
			t.Errorf("%s (%v) weighs LESS than %s (%v): the model says disagreeing is better evidence of sameness than agreeing",
				pair.agree, m.Weights[pair.agree], pair.conflict, m.Weights[pair.conflict])
		}
	}
}

// ── the singleton ceiling ──────────────────────────────────────────────────

// ADR-0002 D3's singleton erratum: a differing singleton value is always
// contested and no score may override it.
//
// Both polarities. Without the second case the cap could be a blanket "always
// return 0.05" and the test would still pass.
func TestSingletonDisagreementCapsTheScore(t *testing.T) {
	m := defaultModel(t)
	// Everything else about this pair screams "same thing": four other kinds
	// agree, the names are identical, the segment, class and hardware agree.
	ids := func(cloudID string) map[string]string {
		return map[string]string{
			matcher.KindCloudResourceID:       cloudID,
			matcher.KindMACAddress:            "aa:bb:cc:11:22:33",
			matcher.KindFQDN:                  "twin.corp.example.com",
			matcher.KindHostname:              "twin",
			matcher.KindSSHHostKeyFingerprint: "SHA256:same",
		}
	}
	agree := matcher.Pair{
		Observation: side("twin", "server", "seg", ids("arn:same")),
		Candidate:   side("twin", "server", "seg", ids("arn:same")),
	}
	disagree := matcher.Pair{
		Observation: side("twin", "server", "seg", ids("arn:one")),
		Candidate:   side("twin", "server", "seg", ids("arn:two")),
	}

	if got := m.Score(agree); got <= 0.9 {
		t.Fatalf("the agreeing twin scored %.4f; the test needs a pair the model is confident about", got)
	}
	got := m.Score(disagree)
	if got > matcher.SingletonConflictCeiling {
		t.Errorf("a singleton disagreement scored %.4f, above the %.4f ceiling", got, matcher.SingletonConflictCeiling)
	}
	// And the ceiling is not zero: zero means UNSCORED everywhere else in this
	// codebase, and a confident rejection is not an absence of opinion.
	if got <= 0 {
		t.Errorf("a singleton disagreement scored %v; zero reads as 'unscored', not as 'certainly not'", got)
	}
}

// ── explanations ───────────────────────────────────────────────────────────

func TestExplainIsTheScore(t *testing.T) {
	// The contributions plus the bias must reconstruct the log-odds exactly.
	// An explanation that does not add up to the number it explains is a
	// plausible story about a decision, which is worse than none.
	m := defaultModel(t)
	for _, s := range loadFixtures(t) {
		p, _ := s.Pair()
		v := matcher.Features(p)
		sum := m.Weights[matcher.FeatureBias]
		for _, f := range m.ExplainVector(v) {
			sum += f.Contribution
		}
		if math.Abs(sum-m.LogOdds(v)) > 1e-9 {
			t.Errorf("%s: the factors sum to %v, the model's log-odds are %v", s.Name, sum, m.LogOdds(v))
		}
	}
}

func TestExplainOrdersByContributionAndDropsZeroes(t *testing.T) {
	m := defaultModel(t)
	p := matcher.Pair{
		Observation: side("db01", "server", "seg-a", map[string]string{
			matcher.KindSerialNumber: "abc", matcher.KindHostname: "db01",
		}),
		Candidate: side("db01", "server", "seg-a", map[string]string{
			matcher.KindSerialNumber: "abc", matcher.KindHostname: "db01",
		}),
	}
	factors := m.Explain(p)
	if len(factors) == 0 {
		t.Fatal("a pair agreeing on a serial explained nothing")
	}
	for i := 1; i < len(factors); i++ {
		if math.Abs(factors[i].Contribution) > math.Abs(factors[i-1].Contribution) {
			t.Errorf("factor %d contributes more than factor %d", i, i-1)
		}
	}
	for _, f := range factors {
		if f.Contribution == 0 {
			t.Errorf("%s contributed nothing and is still in the explanation", f.Feature)
		}
		if f.Label == "" || f.Label == f.Feature {
			t.Errorf("%s has no human label", f.Feature)
		}
		if f.Feature == matcher.FeatureBias {
			t.Error("the bias is the same for every pair and explains nothing about this one")
		}
	}
	if factors[0].Feature != matcher.FeatureIDMatchSingleton {
		t.Errorf("the leading factor is %s; a matching serial should lead", factors[0].Feature)
	}
}

// No identifier VALUE may appear in an explanation. The explanation travels to
// the UI, into logs and into `asset_history`; the values are already on the
// proposal's matched-identifier list under the tenant's own access control, and
// duplicating a serial number into a model's reasoning is a second copy nobody
// asked for.
func TestExplanationsCarryNoIdentifierValues(t *testing.T) {
	m := defaultModel(t)
	secrets := []string{"abc123serial", "arn:aws:secret-instance", "aa:bb:cc:de:ad:be", "SHA256:leakme", "secret-host"}
	p := matcher.Pair{
		Observation: side(secrets[4], "server", "seg", map[string]string{
			matcher.KindSerialNumber:          secrets[0],
			matcher.KindCloudResourceID:       secrets[1],
			matcher.KindMACAddress:            secrets[2],
			matcher.KindSSHHostKeyFingerprint: secrets[3],
			matcher.KindHostname:              secrets[4],
		}),
		Candidate: side(secrets[4], "server", "seg", map[string]string{
			matcher.KindSerialNumber:          secrets[0],
			matcher.KindCloudResourceID:       secrets[1],
			matcher.KindMACAddress:            secrets[2],
			matcher.KindSSHHostKeyFingerprint: secrets[3],
			matcher.KindHostname:              secrets[4],
		}),
	}
	factors := m.Explain(p)
	rendered := m.Reason(factors)
	for _, f := range factors {
		rendered += " " + f.Feature + " " + f.Label
	}
	for _, s := range secrets {
		if strings.Contains(strings.ToLower(rendered), strings.ToLower(s)) {
			t.Errorf("the explanation repeats the identifier value %q:\n%s", s, rendered)
		}
	}
}

func TestReasonSummarises(t *testing.T) {
	m := defaultModel(t)
	if got := m.Reason(nil); got == "" {
		t.Error("an empty explanation produced an empty reason")
	}
	one := []matcher.Factor{{Feature: "a", Label: "same serial", Contribution: 1}}
	if got := m.Reason(one); got != "same serial" {
		t.Errorf("one factor: %q", got)
	}
	two := append(one, matcher.Factor{Feature: "b", Label: "same segment", Contribution: 0.5})
	if got := m.Reason(two); !strings.Contains(got, "one other") {
		t.Errorf("two factors: %q", got)
	}
	three := append(two, matcher.Factor{Feature: "c", Label: "same class", Contribution: 0.2})
	if got := m.Reason(three); !strings.Contains(got, "2 other") {
		t.Errorf("three factors: %q", got)
	}
}

// ── the vocabulary ─────────────────────────────────────────────────────────

func TestSingletonKindsAreTheFour(t *testing.T) {
	want := []string{
		matcher.KindAgentID, matcher.KindCloudResourceID,
		matcher.KindSerialNumber, matcher.KindCMDBSysID,
	}
	got := matcher.SingletonKinds()
	if len(got) != len(want) {
		t.Fatalf("singleton kinds = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("singleton kind %d = %q, want %q", i, got[i], want[i])
		}
	}
	for _, k := range []string{matcher.KindMACAddress, matcher.KindHostname, matcher.KindIPAddress, matcher.KindFQDN} {
		if matcher.IsSingleton(k) {
			t.Errorf("%s is not one per asset — a machine has several", k)
		}
	}
}

// ── training ───────────────────────────────────────────────────────────────

func TestTrainIsDeterministic(t *testing.T) {
	samples := loadFixtures(t)
	a, _, err := matcher.Train(samples, matcher.TrainOptions{ModelID: "x"})
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := matcher.Train(samples, matcher.TrainOptions{ModelID: "x"})
	if err != nil {
		t.Fatal(err)
	}
	for name, wa := range a.Weights {
		if b.Weights[name] != wa {
			t.Errorf("%s: two runs gave %v and %v", name, wa, b.Weights[name])
		}
	}
}

func TestTrainRefusesAnEmptySet(t *testing.T) {
	if _, _, err := matcher.Train(nil, matcher.TrainOptions{}); err == nil {
		t.Fatal("training on nothing succeeded")
	}
}

func TestParseSamplesRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"unnamed":     `[{"match": true}]`,
		"bad seen_at": `[{"name":"x","observation":{"seen_at":"yesterday"}}]`,
		"not a list":  `{"name":"x"}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := matcher.ParseSamples([]byte(raw)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
