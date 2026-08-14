// Package services: catalogue-derived risk scoring.
//
// The `algorithms` table is documented as "the authoritative source for all
// cryptographic algorithm assessments" — strength, deprecation_status,
// risk_score, PQC status, security level. Until this file existed it had NO
// influence on any risk number: algorithms.risk_score appeared only in ORDER BY
// clauses, while the score the product actually showed came from hardcoded
// string matching in weak_crypto_detector.go (strings.Contains(hash, "MD5"),
// keySize < minRSAKeySize, ...).
//
// That left two parallel, disagreeing opinions about how risky a given
// algorithm is — one curated and citable, one hardcoded and unattributed — and
// the unattributed one won. Wiring the score to the catalogue is what makes
// every number explainable: a score now points at a catalogue row a reviewer
// can read, argue with, and correct in one place.
package services

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// catalogueRiskRoles are the junction algorithm_type values that contribute to
// an implementation's risk.
//
// Unlike the PQC classifier (which considers only real cryptographic
// primitives), risk DOES include the container rows: an obsolete protocol
// version is one of the strongest risk signals there is — TLS 1.0 carries
// catalogue risk 75, and RFC 8996 says it MUST NOT be used — and whole-suite
// entries carry their own assessment.
var catalogueRiskRoles = []string{
	"protocol_version", "cipher_suite", "key_exchange", "signature", "symmetric", "hash",
}

// catalogueRiskContribution is one algorithm's contribution to an
// implementation's risk, carrying enough context to explain the number.
type catalogueRiskContribution struct {
	Code              string
	RiskScore         int
	Strength          string
	DeprecationStatus string
}

// Reason renders the contribution as a human-readable risk factor, naming the
// catalogue row so the score is traceable to an assessment rather than to an
// opinion buried in code.
func (c catalogueRiskContribution) Reason() string {
	switch {
	case c.Strength != "" && c.DeprecationStatus != "" && c.DeprecationStatus != "current":
		return fmt.Sprintf("%s is %s and %s (catalogue risk %d)", c.Code, c.Strength, c.DeprecationStatus, c.RiskScore)
	case c.Strength != "":
		return fmt.Sprintf("%s is rated %s (catalogue risk %d)", c.Code, c.Strength, c.RiskScore)
	default:
		return fmt.Sprintf("%s (catalogue risk %d)", c.Code, c.RiskScore)
	}
}

// catalogueRiskForImplementation returns the worst catalogue risk among the
// algorithms linked to an implementation, plus the contribution that produced
// it and every other contribution for explanation.
//
// Worst-component-wins mirrors how an asset rolls up from its implementations
// (MAX): a service is only as strong as its weakest negotiated component, so an
// AES-256 cipher does not offset an RC4 fallback or a TLS 1.0 protocol version.
//
// Inferred links count. For TLS that means a component derived from the suite
// name; for SSH it means an algorithm the server OFFERS but did not negotiate
// (see ssh_ingest.go). Both belong in the score: an offered weak algorithm is
// reachable by any client that asks for it, so a server's posture is its worst
// reachable option, not merely its last observed one.
//
// Returns ok=false when nothing is linked — meaning "not assessed", which is
// deliberately distinct from "assessed as safe". Callers keep the score at 0 in
// that case so the Informational band continues to mean unassessed.
func catalogueRiskForImplementation(tx *sqlx.Tx, implID uuid.UUID) (worst catalogueRiskContribution, all []catalogueRiskContribution, ok bool, err error) {
	const q = `
		SELECT a.code,
		       COALESCE(a.risk_score, 0),
		       COALESCE(a.strength, ''),
		       COALESCE(a.deprecation_status, '')
		  FROM crypto_implementation_algorithms cia
		  JOIN algorithms a ON a.id = cia.algorithm_id
		 WHERE cia.crypto_implementation_id = $1
		   AND cia.algorithm_type = ANY($2)
		 ORDER BY COALESCE(a.risk_score, 0) DESC, a.code
	`
	rows, e := tx.Query(q, implID, pq.Array(catalogueRiskRoles))
	if e != nil {
		return worst, nil, false, fmt.Errorf("catalogue risk lookup: %w", e)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var c catalogueRiskContribution
		if e := rows.Scan(&c.Code, &c.RiskScore, &c.Strength, &c.DeprecationStatus); e != nil {
			return worst, nil, false, fmt.Errorf("scan catalogue risk: %w", e)
		}
		all = append(all, c)
	}
	if e := rows.Err(); e != nil {
		return worst, nil, false, e
	}
	if len(all) == 0 {
		return worst, nil, false, nil
	}
	// Ordered by risk_score DESC, so the first row is the worst component.
	return all[0], all, true, nil
}

// catalogueRiskFactors renders every contribution as a risk factor, worst
// first, so the UI can show WHY a score is what it is.
func catalogueRiskFactors(all []catalogueRiskContribution) []string {
	factors := make([]string, 0, len(all))
	for _, c := range all {
		factors = append(factors, c.Reason())
	}
	return factors
}
