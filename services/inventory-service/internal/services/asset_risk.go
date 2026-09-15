package services

// Per-asset risk, recomputed (ADR-0005 D4).
//
// The DEFINITION moved to internal/riskrollup in workstream 3.2 and this file
// is the merge path's call into it. What it used to hold — `MAX(risk_score)`
// over the asset's crypto configurations, with `crypto` appended to
// `risk_assessed_by` when at least one of them scored — was the whole rollup
// while `crypto` was the only producer with an opinion. It is not any more:
// `eol`, `vulnerability` and the producers after them raise findings against an
// asset's software, its hardware and its endpoints, and a rollup that reads only
// crypto configurations cannot see any of them.
//
// The crypto half is unchanged in meaning. The `crypto` producer writes a
// `weak_configuration` finding for each scored configuration, taking the worse
// of the algorithm catalogue's current verdict and the score ingest persisted,
// so the MAX over those findings is the same number this file used to compute —
// pinned by TestIntegration_CryptoProducer_MatchesTheLegacyCryptoRollup.

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/riskrollup"
)

// recomputeAssetRisk recomputes one asset's risk and coverage.
//
// Score 0 with a producer PRESENT in risk_assessed_by is "assessed, nothing
// scored"; score 0 with the array empty is "not assessed". Keeping those
// distinct is the same three-valued honesty as the PQC `unclassified` bucket,
// and it is why the statement does not skip the write when the max is 0 — a
// cleared asset has to be able to reach 0.
func (s *AssetService) recomputeAssetRisk(ctx context.Context, tenantID, assetID uuid.UUID) error {
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		return recomputeAssetRiskTx(tx, tenantID, assetID)
	})
	if err != nil {
		return fmt.Errorf("recompute risk for asset %s: %w", assetID, err)
	}
	return nil
}

// recomputeAssetRiskTx is the recompute on a transaction the caller owns.
//
// It exists for the MERGE path. A merge moves every one of the source's
// endpoints, configurations and software installs onto the survivor without any
// producer running, so the survivor keeps the rollup it had before it absorbed
// them: a clean asset that just inherited a TLS 1.0 configuration still reads 0,
// in the list, in the facets and on the dashboard, until something happens to
// re-evaluate it. The source's own rollup is likewise left describing subjects
// it no longer owns.
//
// On the caller's transaction, not its own, because a merge either happens
// entirely or not at all — a committed move with an uncommitted rollup is the
// same divergence one step later.
//
// `tx.Tx` unwraps sqlx's embedded *sql.Tx: riskrollup is written against the
// standard type because the producers reach it from a plain *sql.Tx, and one
// rollup with two signatures would be one rollup too many.
func recomputeAssetRiskTx(tx *sqlx.Tx, tenantID, assetID uuid.UUID) error {
	_, err := riskrollup.Recompute(context.Background(), tx.Tx, tenantID, assetID)
	return err
}
