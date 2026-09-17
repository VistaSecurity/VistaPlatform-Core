package cryptoassess

import (
	"strings"
	"testing"
)

func TestHistoricalObligationsAccumulateWithoutInventedHash(t *testing.T) {
	c := Configuration{KeyAlgorithm: "RSA", KeyBits: 4096, Signature: "RSA", PreviousEvidence: []byte(`{"rule_failures":[{"rule":"hash","algorithm":"SHA1"}],"unresolved_prior_assessment":{"rules":["key_size"]}}`), Components: []byte(`[{"role":"key_exchange","strength":"strong","risk_score":90},{"role":"signature","strength":"strong","risk_score":90}]`)}
	j := c.Judge()
	if !strings.Contains(string(j.PriorEvidence), `"hash"`) || strings.Contains(string(j.PriorEvidence), `"key_size"`) {
		t.Fatalf("new hash obligation lost or repaired key retained: %s", j.PriorEvidence)
	}
	c.Hash = "SHA256"
	c.Components = []byte(`[{"role":"key_exchange","strength":"strong","risk_score":90},{"role":"signature","strength":"strong","risk_score":90},{"role":"hash","strength":"strong","risk_score":0}]`)
	if j = c.Judge(); len(j.PriorEvidence) != 0 {
		t.Fatalf("affirmative facts did not resolve: %s", j.PriorEvidence)
	}
}
func TestHistoricalStrongComponentsDoNotExplainOldWeakness(t *testing.T) {
	c := Configuration{PreviousEvidence: []byte(`{"components":[{"role":"symmetric","strength":"strong","risk_score":90}]}`), Components: []byte(`[{"role":"symmetric","strength":"strong","risk_score":90}]`)}
	if j := c.Judge(); !strings.Contains(string(j.PriorEvidence), `"opaque":true`) {
		t.Fatalf("unexplained reason became safe: %+v", j)
	}
}
