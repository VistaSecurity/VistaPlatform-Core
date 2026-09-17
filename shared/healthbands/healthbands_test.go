package healthbands

import (
	"math"
	"testing"
)

func TestHealthBoundaries(t *testing.T) {
	for _, tc := range []struct {
		score float64
		band  Band
	}{{0, Failing}, {39.999, Failing}, {40, Poor}, {59.999, Poor}, {60, Fair}, {74.999, Fair}, {75, Good}, {89.999, Good}, {90, Excellent}, {100, Excellent}} {
		got, ok := FromScore(&tc.score)
		if !ok || got != tc.band {
			t.Fatalf("%v=%s/%v want %s", tc.score, got, ok, tc.band)
		}
	}
	if got, ok := FromScore(nil); ok || got != "" || Status(nil) != Unknown {
		t.Fatal("nil received band")
	}
	for _, score := range []float64{-1, 101, math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, ok := FromScore(&score); ok {
			t.Fatalf("invalid %v received band", score)
		}
	}
}
