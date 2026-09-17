package services

import (
	"errors"
	"testing"
)

func TestCreateAlgorithmRejectsMissingOrInvalidRiskBeforeDatabaseAccess(t *testing.T) {
	service := &AlgorithmService{}
	for _, tc := range []struct {
		name  string
		score *int
		want  error
	}{
		{name: "omitted", score: nil, want: ErrAlgorithmRiskScoreMissing},
		{name: "negative", score: algorithmServiceIntPtr(-1), want: ErrAlgorithmRiskScoreRange},
		{name: "above maximum", score: algorithmServiceIntPtr(101), want: ErrAlgorithmRiskScoreRange},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := service.CreateAlgorithm(AlgorithmCreate{Code: "TEST", Name: "Test", Category: "hash", RiskScore: tc.score})
			if !errors.Is(err, tc.want) {
				t.Fatalf("CreateAlgorithm error = %v, want %v", err, tc.want)
			}
		})
	}
}

func algorithmServiceIntPtr(value int) *int { return &value }
