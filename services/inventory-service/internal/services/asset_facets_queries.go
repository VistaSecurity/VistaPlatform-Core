// Package services: asset facet aggregation queries.
package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// GetAssetFacets returns aggregated counts for a given facet level respecting filters.
func (s *AssetService) GetAssetFacets(tenantID uuid.UUID, filters models.AssetFilters, level string, limit int) ([]models.AssetFacetBucket, error) {
	if limit <= 0 {
		limit = 50
	}
	facetExpr := ""
	switch level {
	case "business_unit":
		facetExpr = "COALESCE(a.business_unit, 'Unknown')"
	case "environment":
		facetExpr = "COALESCE(a.environment::text, 'Unknown')"
	case "asset_type":
		facetExpr = "COALESCE(a.asset_type::text, 'Unknown')"
	case "owner_email":
		facetExpr = "COALESCE(a.owner_email, 'Unknown')"
	case "operating_system":
		facetExpr = "COALESCE(a.operating_system, 'Unknown')"
	case "location.region":
		facetExpr = "COALESCE(a.tags->'location'->>'region', a.tags->>'region', 'Unknown')"
	case "location.site":
		facetExpr = "COALESCE(a.tags->'location'->>'site', a.tags->>'site', 'Unknown')"
	case "location.building":
		facetExpr = "COALESCE(a.tags->'location'->>'building', a.tags->>'building', 'Unknown')"
	case "location.zone":
		facetExpr = "COALESCE(a.tags->'location'->>'zone', a.tags->>'zone', 'Unknown')"
	default:
		return nil, fmt.Errorf("unsupported facet level: %s", level)
	}

	// Inner SELECT groups per ASSET (B-44b): the risk-level HAVING aggregates
	// MAX(ci.risk_score), and grouping straight by the facet key made that MAX
	// span the whole bucket — one asset scoring 75 would report all 50 assets in
	// a business unit as matching risk_level=high. Rolling up per a.id first and
	// counting the surviving assets in an outer aggregate is the same shape
	// GetAssets uses (buildAssetListWhereAndHaving over GROUP BY a.id).
	base := fmt.Sprintf(`
        SELECT %s AS "key", a.id AS "asset_id"
        FROM network_assets a
        LEFT JOIN crypto_implementations ci ON a.id = ci.asset_id AND ci.deleted_at IS NULL
        WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
    `, facetExpr)

	args := []interface{}{tenantID}
	argCount := 1
	whereConds := []string{}

	// Same default scope the asset list applies (buildAssetListWhereAndHaving):
	// facet counts must describe the same population the list they filter shows,
	// otherwise a bucket counts pending-approval assets the list never returns.
	if len(filters.AssetStatus) > 0 {
		argCount++
		whereConds = append(whereConds, fmt.Sprintf(`a.asset_status = ANY($%d)`, argCount))
		args = append(args, pq.Array(filters.AssetStatus))
	} else {
		whereConds = append(whereConds, `a.asset_status = 'monitoring'`)
	}

	if filters.Search != "" {
		terms := parseSearchQuery(filters.Search)
		if len(terms) > 0 {
			var searchConditions []string
			for i, term := range terms {
				pattern := term.Value
				if !term.Exact {
					pattern = "%" + term.Value + "%"
				}
				argCount++
				var condition string
				switch term.Field {
				case "hostname":
					condition = fmt.Sprintf(`a.hostname ILIKE $%d`, argCount)
				case "ip", "ip_address":
					condition = fmt.Sprintf(`a.ip_address::text ILIKE $%d`, argCount)
				case "owner", "owner_email", "email":
					condition = fmt.Sprintf(`a.owner_email ILIKE $%d`, argCount)
				case "os", "operating_system", "operating system":
					condition = fmt.Sprintf(`a.operating_system ILIKE $%d`, argCount)
				case "description", "desc":
					condition = fmt.Sprintf(`a.description ILIKE $%d`, argCount)
				case "business_unit", "business unit", "bu":
					condition = fmt.Sprintf(`a.business_unit ILIKE $%d`, argCount)
				case "tags", "tag":
					condition = fmt.Sprintf(`a.tags::text ILIKE $%d`, argCount)
				case "metadata", "meta":
					condition = fmt.Sprintf(`a.metadata::text ILIKE $%d`, argCount)
				default:
					condition = fmt.Sprintf(`(
						a.hostname ILIKE $%d OR a.ip_address::text ILIKE $%d OR a.description ILIKE $%d OR
						a.business_unit ILIKE $%d OR a.owner_email ILIKE $%d OR a.operating_system ILIKE $%d OR
						a.tags::text ILIKE $%d OR a.metadata::text ILIKE $%d
					)`, argCount, argCount, argCount, argCount, argCount, argCount, argCount, argCount)
				}
				if i > 0 && term.Operator != "" {
					condition = term.Operator + " " + condition
				}
				searchConditions = append(searchConditions, condition)
				args = append(args, pattern)
			}
			if len(searchConditions) > 0 {
				whereConds = append(whereConds, "("+strings.Join(searchConditions, " ")+")")
			}
		}
	}
	if len(filters.AssetType) > 0 {
		typePlaceholders := []string{}
		for _, assetType := range filters.AssetType {
			argCount++
			typePlaceholders = append(typePlaceholders, fmt.Sprintf(`$%d::asset_type`, argCount))
			args = append(args, assetType)
		}
		whereConds = append(whereConds, fmt.Sprintf(`a.asset_type IN (%s)`, strings.Join(typePlaceholders, ", ")))
	}
	if len(filters.Environment) > 0 {
		envPlaceholders := []string{}
		for _, env := range filters.Environment {
			argCount++
			envPlaceholders = append(envPlaceholders, fmt.Sprintf(`$%d::environment_type`, argCount))
			args = append(args, env)
		}
		whereConds = append(whereConds, fmt.Sprintf(`a.environment IN (%s)`, strings.Join(envPlaceholders, ", ")))
	}
	if len(filters.BusinessUnit) > 0 {
		argCount++
		whereConds = append(whereConds, fmt.Sprintf("a.business_unit = ANY($%d)", argCount))
		args = append(args, pq.Array(filters.BusinessUnit))
	}
	if len(filters.Protocol) > 0 {
		protocolPlaceholders := []string{}
		for _, protocol := range filters.Protocol {
			argCount++
			protocolPlaceholders = append(protocolPlaceholders, fmt.Sprintf(`$%d::protocol_type`, argCount))
			args = append(args, protocol)
		}
		whereConds = append(whereConds, fmt.Sprintf(`ci.protocol IN (%s)`, strings.Join(protocolPlaceholders, ", ")))
	}
	if len(filters.OperatingSystem) > 0 {
		argCount++
		whereConds = append(whereConds, fmt.Sprintf("a.operating_system = ANY($%d)", argCount))
		args = append(args, pq.Array(filters.OperatingSystem))
	}
	if len(filters.OwnerEmail) > 0 {
		argCount++
		whereConds = append(whereConds, fmt.Sprintf("a.owner_email = ANY($%d)", argCount))
		args = append(args, pq.Array(filters.OwnerEmail))
	}

	if len(whereConds) > 0 {
		base += " AND " + strings.Join(whereConds, " AND ")
	}

	having := ""
	if len(filters.RiskLevel) > 0 {
		var bands []string
		// The facet sidebar uses a coarser 4-value vocabulary than the five badge
		// levels: "high" means high AND ABOVE, so a Critical asset still matches
		// it. Everything is derived from the canonical ladder so the facet counts
		// and the badges cannot band the same score differently.
		const facetRisk = "COALESCE(MAX(ci.risk_score), 0)"
		for _, rl := range filters.RiskLevel {
			var (
				cond string
				ok   bool
			)
			switch strings.ToLower(rl) {
			case "high":
				cond, ok = models.RiskAtLeastSQL(facetRisk, "High")
			case "medium":
				cond, ok = models.RiskBandSQL(facetRisk, "Medium")
			case "low":
				cond, ok = models.RiskBandSQL(facetRisk, "Low")
			case "unknown":
				cond, ok = models.RiskBandSQL(facetRisk, "Informational")
			}
			if ok {
				bands = append(bands, cond)
			}
		}
		if len(bands) > 0 {
			having = " HAVING (" + strings.Join(bands, " OR ") + ")"
		}
	}

	argCount++
	query := `SELECT "key", COUNT(*) AS "count" FROM (` +
		base + "\nGROUP BY \"key\", a.id" + having +
		"\n) per_asset\nGROUP BY \"key\"\nORDER BY \"count\" DESC, \"key\" ASC\nLIMIT $" + fmt.Sprintf("%d", argCount)
	args = append(args, limit)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var buckets []models.AssetFacetBucket
	// RLS-scoped read over network_assets / crypto_implementations — wrapped in WithTenantTx.
	if err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, e := tx.QueryxContext(ctx, query, args...)
		if e != nil {
			return fmt.Errorf("failed to get asset facets: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var bucket models.AssetFacetBucket
			if e := rows.Scan(&bucket.Key, &bucket.Count); e != nil {
				return fmt.Errorf("failed to scan asset facet bucket: %w", e)
			}
			buckets = append(buckets, bucket)
		}
		if e := rows.Err(); e != nil {
			return fmt.Errorf("error iterating asset facet rows: %w", e)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return buckets, nil
}
