package services

import (
	"strings"
	"testing"
)

func TestCatalogueRiskFactors_KeepUnassessedComponentsVisible(t *testing.T) {
	score := 73
	factors := catalogueRiskFactors([]catalogueRiskContribution{
		{Code: "ASSESSED", RiskScore: &score, Strength: "weak"},
		{Code: "CUSTOM-UNKNOWN", RiskScore: nil, Strength: "acceptable"},
	})
	if len(factors) != 2 || !strings.Contains(factors[0], "catalogue risk 73") ||
		!strings.Contains(factors[1], "no catalogue risk assessment") {
		t.Fatalf("risk factors hid or regraded unassessed evidence: %#v", factors)
	}
}
