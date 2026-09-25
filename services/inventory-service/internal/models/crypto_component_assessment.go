package models

import (
	"encoding/json"
	"strings"

	"github.com/google/uuid"
)

// CryptoComponentAssessment is one catalogue-resolved component of a crypto
// configuration, carrying the assessment that explains the configuration's risk
// score. Returned by GET /crypto-configurations/{id}/components.
//
// It exists because the score was explainable in the data and unexplained on
// the screen: catalogueRiskForImplementation already picks the worst linked
// component, but the reasoning only ever reached a log line. This is the same
// join, shaped for a reader.
//
// Two fields carry most of the value:
//
//   - IsInferred distinguishes a component the handshake demonstrably used from
//     one the server merely OFFERS. Both raise the score — a reachable weak
//     option is a real weakness — but "this server negotiated 3DES" and "this
//     server would accept 3DES if asked" are different findings, so they must
//     not render identically.
//   - SetsScore marks the worst numerically scored component. It remains false
//     for every row when the resolved catalogue evidence is qualitative only.
//
// RiskLevel is banded SERVER-SIDE with GetRiskLevel so no consumer re-derives
// the ladder. A nil RiskScore/RiskLevel preserves a qualitative-only catalogue
// judgment without fabricating zero.
type CryptoComponentAssessment struct {
	// AlgorithmType is the junction role: protocol_version, cipher_suite,
	// key_exchange, signature, symmetric, hash.
	AlgorithmType string `json:"algorithm_type" db:"algorithm_type"`
	// IsInferred is true when the link was derived rather than observed in use.
	IsInferred bool `json:"is_inferred" db:"is_inferred"`

	AlgorithmID uuid.UUID `json:"algorithm_id" db:"algorithm_id"`
	Code        string    `json:"code" db:"code"`
	Name        string    `json:"name" db:"name"`
	Category    string    `json:"category" db:"category"`

	Strength                string   `json:"strength" db:"strength"`
	DeprecationStatus       string   `json:"deprecation_status" db:"deprecation_status"`
	RiskScore               *int     `json:"risk_score" db:"risk_score"`
	RiskLevel               *string  `json:"risk_level" db:"-"`
	MigrationGuidance       *string  `json:"migration_guidance,omitempty" db:"migration_guidance"`
	RecommendedAlternatives []string `json:"recommended_alternatives" db:"recommended_alternatives"`
	IsPQC                   bool     `json:"is_pqc" db:"is_pqc"`

	// SetsScore marks the worst component under worst-component-wins.
	SetsScore bool `json:"sets_score" db:"-"`

	// HybridKexAvailable is set on a classical key_exchange component when a
	// handshake with this configuration's server proved it ALSO accepts a
	// hybrid post-quantum key exchange ( W1.9). The server negotiated
	// classical — because the client's offer or the server's own group
	// preference chose it — so reaching post-quantum protection is a
	// preference change, not a migration project.
	//
	// It is guidance only. The component's risk, the configuration's score and
	// band, and its PQC readiness category are unchanged: what was negotiated
	// is still classical and still Shor-breakable. Nil (omitted) when the
	// server's hybrid support is false or unknown, or when the key exchange is
	// already hybrid.
	HybridKexAvailable *HybridKexAvailability `json:"hybrid_kex_available,omitempty" db:"-"`

	// RemediationGuidance is the catalogue row's curated "how to fix this":
	// impact, ordered steps, a suggested timeline, CVE references and further
	// reading, from algorithms.remediation_guidance. Nil (omitted) when the row
	// records none — only weak/deprecated rows carry it.
	//
	// Like everything else on this struct it is read live from the catalogue,
	// so correcting a row corrects the advice on screen. It changes no score,
	// band or severity: the catalogue's risk_score and strength stay the only
	// opinion about how bad the component is.
	RemediationGuidance *ComponentRemediationGuidance `json:"remediation_guidance,omitempty" db:"-"`
}

// ComponentRemediationGuidance is the typed projection of a catalogue row's
// remediation_guidance JSONB. Text fields are omitted when the row records
// none; list fields are always present (empty = none recorded).
type ComponentRemediationGuidance struct {
	Summary       string   `json:"summary,omitempty"`
	Impact        string   `json:"impact,omitempty"`
	Steps         []string `json:"steps"`
	Timeline      string   `json:"timeline,omitempty"`
	CVEReferences []string `json:"cve_references"`
	Resources     []string `json:"resources"`
}

// ParseComponentRemediationGuidance projects the catalogue's
// remediation_guidance JSONB onto ComponentRemediationGuidance.
//
// The column is free-form and platform admins edit it through the algorithms
// API, so the parse is per-field and lenient: a field of the wrong type is
// dropped on its own rather than discarding the rest of the row's advice, and
// blank strings are treated as absent. Returns nil when nothing usable remains
// — including the column default '{}' — so an empty object never reaches a
// consumer as if it were guidance.
func ParseComponentRemediationGuidance(raw []byte) *ComponentRemediationGuidance {
	if len(raw) == 0 {
		return nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil
	}
	text := func(key string) string {
		var v string
		if err := json.Unmarshal(fields[key], &v); err != nil {
			return ""
		}
		return strings.TrimSpace(v)
	}
	list := func(key string) []string {
		var items []json.RawMessage
		out := []string{}
		if err := json.Unmarshal(fields[key], &items); err != nil {
			return out
		}
		for _, item := range items {
			var v string
			if json.Unmarshal(item, &v) == nil && strings.TrimSpace(v) != "" {
				out = append(out, strings.TrimSpace(v))
			}
		}
		return out
	}
	g := &ComponentRemediationGuidance{
		Summary:       text("summary"),
		Impact:        text("impact"),
		Steps:         list("steps"),
		Timeline:      text("timeline"),
		CVEReferences: list("cve_references"),
		Resources:     list("resources"),
	}
	if g.Summary == "" && g.Impact == "" && g.Timeline == "" &&
		len(g.Steps) == 0 && len(g.CVEReferences) == 0 && len(g.Resources) == 0 {
		return nil
	}
	return g
}

// HybridKexAvailability is the evidence behind CryptoComponentAssessment's
// HybridKexAvailable hint.
type HybridKexAvailability struct {
	// Groups names the hybrid group a handshake with the server accepted, when
	// the producer recorded it. Always present; empty when it did not.
	Groups []string `json:"groups"`
}

// AnnotateComponentAssessments bands each component with the canonical risk
// ladder and marks the worst one as the score-setter.
//
// Banding happens here, once, for the same reason RiskBands generates both the
// Go label and the SQL: a hand-written ladder in a consumer is how badges once
// banded High at >= 60 while the summary used >= 70.
//
// The input MUST already be ordered worst-first with NULLS LAST — the query
// orders it, and this function asserts nothing about ties beyond taking the
// first row, which is exactly what catalogueRiskForImplementation does when it
// picks the score.
func AnnotateComponentAssessments(components []CryptoComponentAssessment) []CryptoComponentAssessment {
	setterMarked := false
	for i := range components {
		if components[i].RiskScore != nil {
			level := GetRiskLevel(*components[i].RiskScore)
			components[i].RiskLevel = &level
			if !setterMarked {
				components[i].SetsScore = true
				setterMarked = true
			}
		}
		// Never leave the JSON array null: a null "recommended_alternatives"
		// reads as "unknown" to a consumer, while the truth is "none recorded".
		if components[i].RecommendedAlternatives == nil {
			components[i].RecommendedAlternatives = []string{}
		}
	}
	return components
}
