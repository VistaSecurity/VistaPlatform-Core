package jobs

import "testing"

func thresholdRule(json string) bandMeasurement {
	return bandMeasurement{RuleType: "threshold", Predicate: []byte(json)}
}

// The seeded cert-expiry ladder (> 0, >= 30, >= 90) must produce a 90-day window:
// wide enough that every rung's verdict is re-checked before it can go stale.
func TestWidestBandDays_SeededLadder(t *testing.T) {
	got := widestBandDays([]bandMeasurement{
		thresholdRule(`{"operator": ">", "value": 0}`),
		thresholdRule(`{"operator": ">=", "value": 30}`),
		thresholdRule(`{"operator": ">=", "value": 90}`),
	})
	if got != 90 {
		t.Errorf("widestBandDays(seeded ladder) = %d, want 90", got)
	}
}

// It is the MAXIMUM, not the last rule read. Rows come back in whatever order the
// planner chooses, so a "widest" that is really "last" would be correct only by
// luck — and every other case in this file happens to list its widest value last,
// which is exactly how such a bug survives a suite. Both orderings, explicitly.
func TestWidestBandDays_TakesTheMaximumRegardlessOfOrder(t *testing.T) {
	ascending := []bandMeasurement{
		thresholdRule(`{"operator": ">", "value": 0}`),
		thresholdRule(`{"operator": ">=", "value": 30}`),
		thresholdRule(`{"operator": ">=", "value": 180}`),
	}
	descending := []bandMeasurement{
		thresholdRule(`{"operator": ">=", "value": 180}`),
		thresholdRule(`{"operator": ">=", "value": 30}`),
		thresholdRule(`{"operator": ">", "value": 0}`),
	}
	if got := widestBandDays(ascending); got != 180 {
		t.Errorf("widest-last ordering: band = %d, want 180", got)
	}
	if got := widestBandDays(descending); got != 180 {
		t.Errorf("widest-FIRST ordering: band = %d, want 180 — the window is the maximum, not whichever rule was read last", got)
	}
}

// A range whose wider bound is read first must still win.
func TestWidestBandDays_RangeMaxRegardlessOfOrder(t *testing.T) {
	got := widestBandDays([]bandMeasurement{
		{RuleType: "range", Predicate: []byte(`{"min": 398, "max": 30}`)},
	})
	if got != 398 {
		t.Errorf("range with the wider bound in min: band = %d, want 398", got)
	}
}

// The window must come from the catalogue, not from a constant. A platform admin
// authoring a wider control widens it; one authoring a narrower one must not.
func TestWidestBandDays_TracksTheAuthoredThreshold(t *testing.T) {
	wider := widestBandDays([]bandMeasurement{
		thresholdRule(`{"operator": ">=", "value": 90}`),
		thresholdRule(`{"operator": ">=", "value": 180}`),
	})
	if wider != 180 {
		t.Errorf("with a 180-day control authored, band = %d, want 180", wider)
	}

	narrower := widestBandDays([]bandMeasurement{
		thresholdRule(`{"operator": ">=", "value": 14}`),
	})
	if narrower != 14 {
		t.Errorf("with only a 14-day control, band = %d, want 14 (a hardcoded 90 would show up here)", narrower)
	}
}

// Operator-agnostic: a verdict moves as the measured value crosses the threshold
// whichever way the comparison points. CertPolicyRungs drops non-lower-bound
// operators because it projects ALERT rungs; a staleness window must not.
func TestWidestBandDays_IgnoresOperatorDirection(t *testing.T) {
	for _, op := range []string{">=", ">", "<=", "<", "==", "!="} {
		got := widestBandDays([]bandMeasurement{
			thresholdRule(`{"operator": "` + op + `", "value": 120}`),
		})
		if got != 120 {
			t.Errorf("operator %q: band = %d, want 120 — a verdict flips at the threshold whichever way it points", op, got)
		}
	}
}

// A range rule can flip at either edge, so both bounds count.
func TestWidestBandDays_RangeUsesBothBounds(t *testing.T) {
	got := widestBandDays([]bandMeasurement{
		{RuleType: "range", Predicate: []byte(`{"min": 30, "max": 398}`)},
	})
	if got != 398 {
		t.Errorf("range {min:30,max:398}: band = %d, want 398", got)
	}
	if got := widestBandDays([]bandMeasurement{
		{RuleType: "range", Predicate: []byte(`{"min": 45}`)},
	}); got != 45 {
		t.Errorf("range {min:45}: band = %d, want 45", got)
	}
}

// No cert_expiration_days control published means nothing time-dependent to
// re-evaluate, so the sweep scans nothing. Minus one is the correct, self-limiting
// answer — a floor here would be a phantom window.
func TestWidestBandDays_NoRulesMeansNoWindow(t *testing.T) {
	if got := widestBandDays(nil); got != -1 {
		t.Errorf("widestBandDays(nil) = %d, want -1", got)
	}
	if got := widestBandDays([]bandMeasurement{}); got != -1 {
		t.Errorf("widestBandDays(empty) = %d, want -1", got)
	}
}

// Malformed or unusable rules are skipped, never fatal, and never widen the
// window on a guess. An unknown rule type is not a threshold.
func TestWidestBandDays_SkipsUnusableRules(t *testing.T) {
	got := widestBandDays([]bandMeasurement{
		{RuleType: "threshold", Predicate: []byte(`not json`)},
		{RuleType: "threshold", Predicate: []byte(`{"operator": ">="}`)},
		{RuleType: "threshold", Predicate: []byte(`{"operator": ">=", "value": "ninety"}`)},
		{RuleType: "presence", Predicate: []byte(`{"value": 9000}`)},
		thresholdRule(`{"operator": ">=", "value": 30}`),
	})
	if got != 30 {
		t.Errorf("band = %d, want 30 — only the one well-formed threshold should count", got)
	}
}

func TestWidestBandDays_ZeroAndFractionalThresholds(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  int
	}{{"0", 0}, {"-5", 0}, {"0.5", 1}, {"90.5", 91}} {
		if got := widestBandDays([]bandMeasurement{thresholdRule(`{"operator":">", "value":` + tc.value + `}`)}); got != tc.want {
			t.Errorf("threshold %s: got %d, want %d", tc.value, got, tc.want)
		}
	}
}
