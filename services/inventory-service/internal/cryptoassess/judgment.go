// Package cryptoassess shares pure judgments between producers and read views.
package cryptoassess

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
)

// Configuration contains observed facts and catalogue evidence, never inferred
// strength from a numeric score. StoredRisk is a legacy persisted numeric value.
type Configuration struct {
	PreviousScore                                            *int
	PreviousEvidence                                         []byte // existing active finding evidence; nil when no prior finding
	Version, Suite, KeyAlgorithm, Hash, Signature, Symmetric string
	KeyBits, StoredRisk                                      int
	CatalogueRisk                                            *int
	Components                                               []byte
}

// Judgment keeps the reason for a qualitative title separate from the
// numeric maximum. In particular, a high-scoring recommended component cannot
// hide a low-scoring weak component (including a score of zero).
type Judgment struct {
	PriorEvidence json.RawMessage // bounded unresolved role/rule obligations, never raw nested history
	Weak          []string
	Acceptable    []string
	Limitations   []string
	Rules         []Rule
}

type Rule struct {
	Rule      string `json:"rule"`
	Algorithm string `json:"algorithm"`
	Bits      int    `json:"bits,omitempty"`
	Score     int    `json:"score"`
}

func Rules(key string, bits int, hashes ...string) []Rule {
	var rules []Rule
	if sev := cryptoparse.WeakKeySizeSeverity(key, bits); sev != "" {
		rules = append(rules, Rule{"key_size", key, bits, cryptoparse.WeakCryptoSeverityScore(sev)})
	}
	for _, hash := range hashes {
		if sev := cryptoparse.WeakHashSeverity(hash); sev != "" {
			rules = append(rules, Rule{"hash", hash, 0, cryptoparse.WeakCryptoSeverityScore(sev)})
		}
	}
	return rules
}

func (j *Judgment) Component(code, role, strength string, riskScore *int) {
	detail := fmt.Sprintf("%s [%s]", code, role)
	switch strength {
	case "weak":
		j.Weak = append(j.Weak, detail)
	case "acceptable":
		j.Acceptable = append(j.Acceptable, detail)
	case "strong", "recommended":
	default:
		j.Limitations = append(j.Limitations, detail+" has no recognized strength")
	}
	if riskScore == nil {
		j.Limitations = append(j.Limitations, detail+" has no catalogue risk score")
	}
}

func (j Judgment) Emit() bool { return len(j.Weak)+len(j.Acceptable)+len(j.Rules) > 0 }
func (j Judgment) Detail() string {
	suffix := ""
	if len(j.PriorEvidence) > 0 {
		suffix = "; prior cryptographic issue requires reassessment"
	}
	if len(j.Weak)+len(j.Rules) > 0 {
		reasons := append([]string{}, j.Weak...)
		for _, rule := range j.Rules {
			reasons = append(reasons, fmt.Sprintf("%s rule: %s", rule.Rule, rule.Algorithm))
		}
		return "uses weak cryptography (" + strings.Join(reasons, "; ") + ")" + suffix
	}
	return "uses an algorithm rated acceptable (" + strings.Join(j.Acceptable, "; ") + ")" + suffix
}
func (j Judgment) AddEvidence(e map[string]any) {
	e["weak_components"] = j.Weak
	e["acceptable_components"] = j.Acceptable
	e["rule_failures"] = j.Rules
	e["assessment_limitations"] = j.Limitations
	e["reassessment_required"] = len(j.Limitations) > 0
	// Explicitly clear a previous retention explanation after successful assessment;
	// Writer.Upsert merges evidence rather than replacing it.
	e["current_reassessment"] = nil
	e["unresolved_prior_assessment"] = nil
	if len(j.PriorEvidence) > 0 {
		e["unresolved_prior_assessment"] = j.PriorEvidence
	}
}

type Component struct {
	Code      string `json:"code"`
	Role      string `json:"role"`
	Strength  string `json:"strength"`
	RiskScore *int   `json:"risk_score"`
}

func (c Configuration) Judge() Judgment {
	// A configuration's key_size is often its SYMMETRIC key length (IPsec
	// AES-256 → 256) beside an asymmetric key-exchange name ("DH Group 14"); the
	// asymmetric floor does not apply to it (P-06), so the size rule sees no size.
	ruleBits := c.KeyBits
	if cryptoparse.SizeIsSymmetricKeyLength(c.KeyAlgorithm, c.Symmetric, c.Suite, ruleBits) {
		ruleBits = 0
	}
	j := Judgment{Rules: Rules(c.KeyAlgorithm, ruleBits, c.Hash, c.Signature)}
	// A cipher string whose enabled set could not be fully resolved is a
	// partial assessment: what was found is a lower bound, never a clean bill.
	if partial, unexpanded := cryptoparse.CipherStringAssessment(c.Suite); partial {
		j.Limitations = append(j.Limitations, fmt.Sprintf(
			"cipher string %q is only partially assessed: %s could not be expanded", c.Suite, strings.Join(unexpanded, ", ")))
	}
	var components []Component
	if len(c.Components) > 0 {
		if err := json.Unmarshal(c.Components, &components); err != nil {
			j.Limitations = append(j.Limitations, "catalogue component evidence is unreadable")
		}
	}
	roles := map[string]bool{}
	for _, component := range components {
		j.Component(component.Code, component.Role, component.Strength, component.RiskScore)
		roles[component.Role] = true
	}
	for _, fact := range []struct{ role, value string }{
		{"protocol_version", c.Version}, {"cipher_suite", c.Suite}, {"key_exchange", c.KeyAlgorithm},
		{"hash", c.Hash}, {"signature", c.Signature}, {"symmetric", c.Symmetric},
	} {
		if fact.value != "" && !roles[fact.role] {
			j.Limitations = append(j.Limitations, fmt.Sprintf("observed %s %q has no resolved catalogue component", fact.role, fact.value))
		}
	}
	if c.KeyAlgorithm != "" && c.KeyBits <= 0 {
		family := cryptoparse.KeyAlgorithmFamily(c.KeyAlgorithm)
		if family == cryptoparse.KexFamilyFiniteField || family == cryptoparse.KexFamilyEllipticCurve {
			j.Limitations = append(j.Limitations, "observed key algorithm has no key size for the applicable size rule")
		}
	}
	if len(components) == 0 {
		j.Limitations = append(j.Limitations, "no resolved catalogue components")
	}
	// An old detector score can include a size/hash failure, but carries no
	// provenance. Missing facts cannot disprove that failure; preserve an existing
	// finding and explain the gap rather than interpreting the number as strength.
	if c.CatalogueRisk != nil && c.StoredRisk > *c.CatalogueRisk && len(j.Rules) == 0 &&
		(c.KeyBits <= 0 || cryptoparse.KeyAlgorithmFamily(c.KeyAlgorithm) == cryptoparse.KexFamilyUnknown || c.Hash == "") {
		j.Limitations = append(j.Limitations, "stored risk exceeds current catalogue risk; missing key-size or hash facts prevent reassessment of the prior detector verdict")
	}
	j.retainUnrefutedHistory(c, components)
	return j
}

// Score preserves numeric absence. A legacy stored zero is not itself evidence;
// an explicit catalogue zero is. Rules contribute their actual policy score.
func (c Configuration) Score() *int {
	var score *int
	if c.StoredRisk > 0 {
		v := c.StoredRisk
		score = &v
	}
	if c.CatalogueRisk != nil && (score == nil || *c.CatalogueRisk > *score) {
		v := *c.CatalogueRisk
		score = &v
	}
	for _, rule := range Rules(c.KeyAlgorithm, c.KeyBits, c.Hash, c.Signature) {
		if score == nil || rule.Score > *score {
			v := rule.Score
			score = &v
		}
	}
	if c.RetainsNumericHistory() && (score == nil || *c.PreviousScore > *score) {
		v := *c.PreviousScore
		score = &v
	}
	return score
}

func (c Configuration) ScoreSources(score int) []string {
	var sources []string
	if c.RetainsNumericHistory() && *c.PreviousScore == score {
		sources = append(sources, "retained prior finding score (unresolved historical assessment)")
	}
	if c.StoredRisk > 0 && c.StoredRisk == score {
		sources = append(sources, "persisted configuration risk (original rule provenance unavailable)")
	}
	var components []Component
	if json.Unmarshal(c.Components, &components) == nil {
		for _, h := range components {
			if h.RiskScore != nil && *h.RiskScore == score {
				sources = append(sources, fmt.Sprintf("%s [%s]", h.Code, h.Role))
			}
		}
	}
	for _, r := range Rules(c.KeyAlgorithm, c.KeyBits, c.Hash, c.Signature) {
		if r.Score == score {
			sources = append(sources, fmt.Sprintf("%s rule: %s", r.Rule, r.Algorithm))
		}
	}
	return sources
}

// Prior failures require affirmative replacement facts. Deleting a key size,
// dropping a previously weak role, or raising a catalogue score cannot refute
// them. This reads existing finding evidence; it creates no assessment history.
type unresolvedAssessment struct {
	Roles  []string `json:"roles,omitempty"`
	Rules  []string `json:"rules,omitempty"`
	Opaque bool     `json:"opaque,omitempty"`
}

func (j *Judgment) retainUnrefutedHistory(c Configuration, components []Component) {
	var prior struct {
		Components []Component           `json:"components"`
		Rules      []Rule                `json:"rule_failures"`
		Unresolved *unresolvedAssessment `json:"unresolved_prior_assessment"`
	}
	if len(c.PreviousEvidence) == 0 || string(c.PreviousEvidence) == "null" || json.Unmarshal(c.PreviousEvidence, &prior) != nil {
		return
	}
	needed := unresolvedAssessment{}
	if prior.Unresolved != nil {
		needed = *prior.Unresolved
	}
	knownReasons := 0
	for _, rule := range prior.Rules {
		if rule.Rule == "key_size" || rule.Rule == "hash" {
			needed.Rules = append(needed.Rules, rule.Rule)
			knownReasons++
		} else {
			needed.Opaque = true
		}
	}
	for _, component := range prior.Components {
		if component.Strength == "weak" || component.Strength == "acceptable" {
			needed.Roles = append(needed.Roles, component.Role)
			knownReasons++
		}
	}
	if knownReasons == 0 && prior.Unresolved == nil {
		needed.Opaque = true
	}
	roles := map[string]bool{}
	for _, component := range components {
		if component.Strength != "" {
			roles[component.Role] = true
		}
	}
	family := cryptoparse.KeyAlgorithmFamily(c.KeyAlgorithm)
	keyKnown := family != cryptoparse.KexFamilyUnknown && roles["key_exchange"] && (family == cryptoparse.KexFamilyPostQuantum || c.KeyBits > 0)
	// A resolved signature/key family alone says nothing about the hash. Require
	// the actual current hash and its catalogue role; incomplete composite-only
	// historical evidence conservatively remains a limitation.
	hashKnown := c.Hash != "" && roles["hash"]
	pending := unresolvedAssessment{}
	slices.Sort(needed.Rules)
	needed.Rules = slices.Compact(needed.Rules)
	slices.Sort(needed.Roles)
	needed.Roles = slices.Compact(needed.Roles)
	for _, rule := range needed.Rules {
		if rule == "key_size" && !keyKnown {
			pending.Rules = append(pending.Rules, rule)
			j.Limitations = append(j.Limitations, "prior key-size failure cannot be reassessed without resolved current key algorithm and applicable size")
		}
		if rule == "hash" && !hashKnown {
			pending.Rules = append(pending.Rules, rule)
			j.Limitations = append(j.Limitations, "prior hash failure cannot be reassessed without an observed resolved current hash")
		}
	}
	for _, role := range needed.Roles {
		if !roles[role] {
			pending.Roles = append(pending.Roles, role)
			j.Limitations = append(j.Limitations, "prior "+role+" judgment has no replacement catalogue assessment")
		}
	}
	if needed.Opaque && (!keyKnown || !hashKnown) {
		pending.Opaque = true
		j.Limitations = append(j.Limitations, "prior finding reason is incomplete; affirmative current key-size and hash assessments are required for reassessment")
	}
	if pending.Opaque || len(pending.Roles)+len(pending.Rules) > 0 {
		j.PriorEvidence, _ = json.Marshal(pending)
	}
}

// RetainsNumericHistory preserves an existing numeric contribution while its
// actual prior obligations remain unresolved. Legacy integer zero without
// numeric evidence is not promoted to an assessment by this compatibility path.
func (c Configuration) RetainsNumericHistory() bool {
	if c.PreviousScore == nil || len(c.Judge().PriorEvidence) == 0 {
		return false
	}
	if *c.PreviousScore > 0 {
		return true
	}
	var evidence struct {
		Sources []string `json:"score_sources"`
	}
	return json.Unmarshal(c.PreviousEvidence, &evidence) == nil && len(evidence.Sources) > 0
}
