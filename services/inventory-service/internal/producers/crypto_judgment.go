package producers

import (
	"fmt"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/cryptoassess"
)

type configurationComponent = cryptoassess.Component

func (c configSubject) assessment() cryptoassess.Configuration {
	return cryptoassess.Configuration{Version: c.version, Suite: c.suite, KeyAlgorithm: c.keyAlg,
		KeyBits: c.keyBits, Hash: c.hashAlg, Signature: c.sigAlg, Symmetric: c.symmetric,
		StoredRisk: c.storedRisk, CatalogueRisk: c.catalogueRisk, Components: c.components, PreviousEvidence: c.previousEvidence, PreviousScore: c.previousScore}
}
func (c configSubject) judgment() cryptoassess.Judgment { return c.assessment().Judge() }

func (c certSubject) judgment() cryptoassess.Judgment {
	j := cryptoassess.Judgment{Rules: cryptoassess.Rules(c.keyAlg, c.keyBits, c.sigAlg)}
	fields := map[string]bool{}
	for _, h := range c.catalogue {
		j.Component(h.Code, h.Field, h.Strength, h.RiskScore)
		fields[h.Field] = true
	}
	for _, fact := range []struct{ field, value string }{{"public_key_algorithm", c.keyAlg}, {"signature_algorithm", c.sigAlg}} {
		if fact.value == "" || !fields[fact.field] {
			j.Limitations = append(j.Limitations, fmt.Sprintf("%s has no resolved catalogue component", fact.field))
		}
	}
	if c.keyBits <= 0 {
		j.Limitations = append(j.Limitations, "public key size is unavailable")
	}
	return j
}

// All numeric ties are cited, independently of which components justify the
// qualitative title. A persisted score is explicitly opaque, not a rule name.
func (c configSubject) scoreSources(score int) []string { return c.assessment().ScoreSources(score) }
func (c certSubject) scoreSources(score int) []string {
	var sources []string
	for _, h := range c.catalogue {
		if h.RiskScore != nil && *h.RiskScore == score {
			sources = append(sources, fmt.Sprintf("%s [%s]", h.Code, h.Field))
		}
	}
	for _, r := range cryptoassess.Rules(c.keyAlg, c.keyBits, c.sigAlg) {
		if r.Score == score {
			sources = append(sources, fmt.Sprintf("%s rule: %s", r.Rule, r.Algorithm))
		}
	}
	return sources
}
