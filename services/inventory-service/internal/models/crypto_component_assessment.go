package models

import "github.com/google/uuid"

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
//   - SetsScore marks the worst component, the one worst-component-wins
//     selected. Exactly one component carries it when the list is non-empty.
//
// RiskLevel is banded SERVER-SIDE with GetRiskLevel so no consumer re-derives
// the ladder. An EMPTY list means NOT ASSESSED, which is deliberately distinct
// from "assessed as safe".
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
	RiskScore               int      `json:"risk_score" db:"risk_score"`
	RiskLevel               string   `json:"risk_level" db:"-"`
	MigrationGuidance       *string  `json:"migration_guidance,omitempty" db:"migration_guidance"`
	RecommendedAlternatives []string `json:"recommended_alternatives" db:"recommended_alternatives"`
	IsPQC                   bool     `json:"is_pqc" db:"is_pqc"`

	// SetsScore marks the worst component under worst-component-wins.
	SetsScore bool `json:"sets_score" db:"-"`
}

// AnnotateComponentAssessments bands each component with the canonical risk
// ladder and marks the worst one as the score-setter.
//
// Banding happens here, once, for the same reason RiskBands generates both the
// Go label and the SQL: a hand-written ladder in a consumer is how badges once
// banded High at >= 60 while the summary used >= 70.
//
// The input MUST already be ordered worst-first (risk_score DESC) — the query
// orders it, and this function asserts nothing about ties beyond taking the
// first row, which is exactly what catalogueRiskForImplementation does when it
// picks the score.
func AnnotateComponentAssessments(components []CryptoComponentAssessment) []CryptoComponentAssessment {
	for i := range components {
		components[i].RiskLevel = GetRiskLevel(components[i].RiskScore)
		// Never leave the JSON array null: a null "recommended_alternatives"
		// reads as "unknown" to a consumer, while the truth is "none recorded".
		if components[i].RecommendedAlternatives == nil {
			components[i].RecommendedAlternatives = []string{}
		}
	}
	if len(components) > 0 {
		components[0].SetsScore = true
	}
	return components
}
