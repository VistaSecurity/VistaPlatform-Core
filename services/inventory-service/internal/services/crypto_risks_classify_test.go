package services

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/cryptoassess"
)

// Existing size-floor regressions exercise the new shared judgment, without
// inventing catalogue assessments from protocol/cipher strings in their setup.
func (s *CryptoRisksService) classifyRisk(r *CryptoRisk, version, suite, hash, key *string, bits *int, expiry *time.Time) {
	c := cryptoassess.Configuration{}
	if version != nil {
		c.Version = *version
	}
	if suite != nil {
		c.Suite = *suite
	}
	if hash != nil {
		c.Hash = *hash
	}
	if key != nil {
		c.KeyAlgorithm = *key
	}
	if bits != nil {
		c.KeyBits = *bits
	}
	classifyConfigurationRisk(r, c, expiry, time.Now())
}
func riskSeverityValue(r *CryptoRisk) string {
	if r.Severity == nil {
		return ""
	}
	return *r.Severity
}
func TestCryptoRiskJudgment_BandsAndStrengthIndependent(t *testing.T) {
	for _, tc := range []struct {
		score          int
		strength, band string
		emit           bool
	}{
		{90, "weak", "critical", true}, {70, "weak", "high", true}, {40, "weak", "medium", true},
		{1, "weak", "low", true}, {0, "weak", "info", true}, {0, "acceptable", "info", true},
		{90, "strong", "", false}, {90, "recommended", "", false},
	} {
		t.Run(tc.strength+tc.band, func(t *testing.T) {
			components, _ := json.Marshal([]cryptoassess.Component{{Code: "TLS1.0", Role: "protocol_version", Strength: tc.strength, RiskScore: &tc.score}})
			c := cryptoassess.Configuration{Version: "TLS1.0", CatalogueRisk: &tc.score, Components: components}
			r := &CryptoRisk{}
			if got := classifyConfigurationRisk(r, c, nil, time.Now()); got != tc.emit {
				t.Fatalf("emit=%v want %v", got, tc.emit)
			}
			if got := riskSeverityValue(r); got != tc.band {
				t.Fatalf("band=%q want %q", got, tc.band)
			}
		})
	}
}
func TestCryptoRiskJudgment_NullNumericAndLifecycle(t *testing.T) {
	components := []byte(`[{"code":"CUSTOM","role":"symmetric","strength":"weak","risk_score":null}]`)
	r := &CryptoRisk{}
	if !classifyConfigurationRisk(r, cryptoassess.Configuration{Components: components}, nil, time.Now()) || r.Severity != nil || r.RiskScore != nil || len(r.AssessmentLimitations) == 0 {
		t.Fatalf("unscored weakness lost or assigned a fabricated score: %+v", r)
	}
	now := time.Now()
	for _, tc := range []struct {
		days int
		band string
	}{{-1, ""}, {10, "medium"}, {30, "medium"}, {31, "info"}, {90, "info"}, {91, ""}} {
		expiry := now.Add(time.Duration(tc.days) * 24 * time.Hour)
		got := certificateExpirySeverity(&expiry, now)
		if (got == nil) != (tc.band == "") || got != nil && *got != tc.band {
			t.Fatalf("days=%d band=%v", tc.days, got)
		}
	}
}
