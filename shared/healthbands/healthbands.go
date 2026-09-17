// Package healthbands owns tenant health index bands (higher is better).
// These boundaries do not grade compliance percentages or resource utilization.
package healthbands

import "math"

type Band string

const (
	Excellent    Band = "excellent"
	Good         Band = "good"
	Fair         Band = "fair"
	Poor         Band = "poor"
	Failing      Band = "failing"
	Unknown           = "unknown"
	ExcellentMin      = 90
	GoodMin           = 75
	FairMin           = 60
	PoorMin           = 40
)

type Definition struct {
	Value Band
	Label string
	Min   float64
}

func Definitions() []Definition {
	return []Definition{
		{Excellent, "Excellent", ExcellentMin}, {Good, "Good", GoodMin},
		{Fair, "Fair", FairMin}, {Poor, "Poor", PoorMin}, {Failing, "Failing", 0},
	}
}

// FromScore returns no band for unavailable, nonfinite or out-of-range data.
// Callers with a legacy zero sentinel must pass nil when availability is unknown.
func FromScore(score *float64) (Band, bool) {
	if score == nil || math.IsNaN(*score) || math.IsInf(*score, 0) || *score < 0 || *score > 100 {
		return "", false
	}
	for _, d := range Definitions() {
		if *score >= d.Min {
			return d.Value, true
		}
	}
	return "", false
}
func Status(score *float64) string {
	band, ok := FromScore(score)
	if !ok {
		return Unknown
	}
	return string(band)
}
