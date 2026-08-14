// Package services: the read side of catalogue risk — the explanation.
//
// catalogue_risk.go computes an implementation's score from the algorithms
// catalogue AT INGEST and renders every contribution into a human-readable
// factor. Until this file existed those factors reached exactly one log.Printf,
// so the product showed a number it could explain and didn't.
//
// WHY THIS RECOMPUTES INSTEAD OF READING A STORED COLUMN: the catalogue is
// designed to be edited ("to change how risky an algorithm is, edit the
// catalogue row, not Go code"). A persisted explanation is a copy of a row that
// is expected to change, with no invalidation path — which would recreate the
// exact failure this subsystem was built to end: two opinions about how risky
// an algorithm is, where the stale one wins because it's the one on screen.
// Point-in-time reasoning is an evidence concern, and the product already has an
// evidence primitive for it (the immutable, hashed CBOM artifact).
package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// componentAssessmentsQuery joins the junction to the catalogue for one
// implementation.
//
// The join through crypto_implementations is what makes this tenant-safe:
// crypto_implementation_algorithms carries no tenant_id and no RLS policy of
// its own, so an unjoined read of it would be cross-tenant. Inside
// WithTenantTx the RLS policy on crypto_implementations filters the join, and
// the explicit ci.tenant_id predicate matches the belt-and-braces style of its
// neighbours in crypto_queries.go — an implementation id from another tenant
// returns zero rows rather than another tenant's assessment.
//
// Ordering is risk_score DESC first so row 0 is the worst component — the same
// worst-component-wins selection catalogueRiskForImplementation makes when it
// sets the score. `code` breaks ties so the "sets the score" marker is stable
// across requests rather than flapping between two equally-bad components.
const componentAssessmentsQuery = `
	SELECT cia.algorithm_type,
	       COALESCE(cia.is_inferred, false) AS is_inferred,
	       a.id   AS algorithm_id,
	       a.code,
	       a.name,
	       a.category,
	       COALESCE(a.strength, '')          AS strength,
	       COALESCE(a.deprecation_status, '') AS deprecation_status,
	       COALESCE(a.risk_score, 0)          AS risk_score,
	       a.migration_guidance,
	       COALESCE(a.recommended_alternatives, ARRAY[]::text[]) AS recommended_alternatives,
	       COALESCE(a.is_pqc, false)          AS is_pqc
	  FROM crypto_implementation_algorithms cia
	  JOIN algorithms a ON a.id = cia.algorithm_id
	  JOIN crypto_implementations ci ON ci.id = cia.crypto_implementation_id
	 WHERE cia.crypto_implementation_id = $1
	   AND ci.tenant_id = $2
	   AND ci.deleted_at IS NULL
	 ORDER BY COALESCE(a.risk_score, 0) DESC, a.code
`

// GetCryptoImplementationComponents returns the catalogue assessment of every
// algorithm linked to a crypto configuration, worst first, banded and with the
// score-setting component marked.
//
// An EMPTY (non-nil) slice means NOT ASSESSED — nothing on this configuration
// resolved against the catalogue. Callers must not render that as a clean bill
// of health; score 0 has always meant unassessed, and so does an empty
// component list.
func (s *CryptoImplementationService) GetCryptoImplementationComponents(tenantID, implID uuid.UUID) ([]models.CryptoComponentAssessment, error) {
	components := make([]models.CryptoComponentAssessment, 0, 8)

	// RLS-scoped read over crypto_implementations (which gates the junction).
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.Query(componentAssessmentsQuery, implID, tenantID)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var c models.CryptoComponentAssessment
			var migrationGuidance *string
			var alternatives pq.StringArray
			if err := rows.Scan(
				&c.AlgorithmType, &c.IsInferred, &c.AlgorithmID, &c.Code, &c.Name,
				&c.Category, &c.Strength, &c.DeprecationStatus, &c.RiskScore,
				&migrationGuidance, &alternatives, &c.IsPQC,
			); err != nil {
				return err
			}
			c.MigrationGuidance = migrationGuidance
			c.RecommendedAlternatives = []string(alternatives)
			components = append(components, c)
		}
		return rows.Err()
	}); err != nil {
		return nil, fmt.Errorf("failed to get crypto configuration components: %w", err)
	}

	return models.AnnotateComponentAssessments(components), nil
}
