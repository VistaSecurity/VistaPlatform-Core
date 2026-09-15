// Package services: asset list and read queries (GetAssets, GetAssetByID, etc.).
package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// GetAssets returns one page of ASSETS — never an asset once per endpoint —
// with the page's endpoints and identifiers loaded alongside.
//
// # One predicate, one risk number
//
// The WHERE clause is compiled from the query language (QUERY_LANGUAGE.md):
// the caller's `?query=` AND the deprecated per-field filters translated into
// the same language (LegacyFiltersToQuery). There is no second WHERE-builder,
// so the list and the facet counts beside it cannot describe different sets.
//
// The risk badge reads the PERSISTED rollup, `assets.risk_score`, written by
// recomputeAssetRisk. It used to band a live `MAX(ci.risk_score)` computed in
// this query while the asset row carried the persisted value — two numbers that
// agreed only until one of them stopped being recomputed. The live MAX is gone;
// `risk_assessed_by` travels with the score so a 0 that means "nobody looked"
// stays distinguishable from a 0 that means "assessed, clean".
//
// # Four statements for a page of any size
//
// Count, page, endpoints, identifiers. The endpoint and identifier loads are
// batched over the page's ids rather than run per row, which is what keeps a
// fifty-row page at four round trips instead of a hundred and one.
func (s *AssetService) GetAssets(tenantID uuid.UUID, filters models.AssetFilters) ([]models.Asset, int, error) {
	if err := validateAssetFilters(filters); err != nil {
		return nil, 0, err
	}
	// $1 is the tenant id, so the translator's parameters start at 2.
	pred, err := buildAssetWhere(filters.Query, filters, 2, assetQueryAlias)
	if err != nil {
		return nil, 0, err
	}
	args := append([]interface{}{tenantID}, pred.Args...)

	// discovery_source is the one legacy filter the language has no field for:
	// it reads pipeline state out of assets.metadata, not a modelled property.
	// It is appended as its own predicate rather than smuggled into the
	// catalogue, and it is bound like everything else.
	where := "a.tenant_id = $1 AND a.deleted_at IS NULL AND (" + pred.Where + ")"
	discoveryWhere, args := discoverySourcePredicate(filters, args)
	where += discoveryWhere

	countQuery := `SELECT COUNT(*) FROM assets a WHERE ` + where

	baseQuery := `
		SELECT
			a.id, a.tenant_id, a.hostname, a.display_name, host(a.primary_address),
			a.class_key, a.class_path, a.class_source_kind, a.class_source_ref, a.class_confidence,
			a.attributes::text, a.environment, a.business_unit, a.owner_email, a.support_group,
			a.description, a.tags::text, a.metadata::text, a.asset_ownership, a.asset_status,
			a.stale_status, a.risk_score, a.risk_assessed_by,
			a.first_discovered_at, a.last_seen_at,
			a.created_at, a.updated_at, a.deleted_at,
			a.location_id, a.network_segment_id, ns.name AS network_segment_name,
			a.site, a.region, a.zone,
			(SELECT COUNT(DISTINCT ci2.certificate_id)
			   FROM crypto_implementations ci2
			  WHERE ci2.asset_id = a.id AND ci2.deleted_at IS NULL) AS certificate_count,
			(SELECT COUNT(*)
			   FROM crypto_implementations ci4
			  WHERE ci4.asset_id = a.id AND ci4.deleted_at IS NULL) AS crypto_implementation_count,
			-- Per-protocol rollup for the row's protocol badges. Kept server-side
			-- so the list renders badges from ONE request instead of a per-row
			-- child query (a 50-request waterfall per page).
			COALESCE((
				SELECT jsonb_agg(jsonb_build_object(
				           'protocol', p.protocol, 'count', p.n, 'max_risk_score', p.max_risk)
				       ORDER BY p.n DESC, p.protocol)
				  FROM (SELECT ci3.protocol::text AS protocol,
				               COUNT(*) AS n,
				               COALESCE(MAX(ci3.risk_score), 0) AS max_risk
				          FROM crypto_implementations ci3
				         WHERE ci3.asset_id = a.id AND ci3.deleted_at IS NULL
				           AND ci3.protocol IS NOT NULL
				         GROUP BY ci3.protocol) p
			), '[]'::jsonb)::text AS protocol_summary
		FROM assets a
		LEFT JOIN network_segments ns ON ns.id = a.network_segment_id
		WHERE ` + where

	baseQuery += " ORDER BY " + assetListOrderBy(filters)
	if filters.Page < 1 {
		filters.Page = 1
	}
	if filters.PageSize < 1 {
		filters.PageSize = 20
	}
	offset := (filters.Page - 1) * filters.PageSize
	baseQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", filters.PageSize, offset)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// RLS-scoped reads over assets / network_segments / the crypto rollups —
	// count, page and the two batched child loads run in one tenant tx, which is
	// also what makes the page and its children a consistent snapshot.
	var total int
	var assets []models.Asset
	// WithTenantTxTimeout, not WithTenantTx: `pred.Where` carries the caller's
	// own query-language predicate, and a `~` in one reaches Postgres ARE. See
	// query.StatementTimeout — the context deadline above is not a substitute,
	// because cancelling a context leaves the statement running until the
	// backend notices a cancel request sent on a second connection.
	if err := database.WithTenantTxTimeout(ctx, s.db, tenantID, assetQueryStatementTimeout, func(tx *sqlx.Tx) error {
		if e := tx.GetContext(ctx, &total, countQuery, args...); e != nil {
			return fmt.Errorf("failed to get assets count: %w", e)
		}
		rows, e := tx.QueryxContext(ctx, baseQuery, args...)
		if e != nil {
			return fmt.Errorf("failed to query assets: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			asset, e := scanAssetListRow(rows)
			if e != nil {
				return e
			}
			assets = append(assets, *asset)
		}
		if e := rows.Err(); e != nil {
			return fmt.Errorf("query execution error: %w", e)
		}
		_ = rows.Close()

		ids := assetIDs(assets)
		endpoints, e := loadEndpointsForAssets(tx, tenantID, ids)
		if e != nil {
			return e
		}
		identifiers, e := loadIdentifiersForAssets(tx, tenantID, ids)
		if e != nil {
			return e
		}
		attachChildren(assets, endpoints, identifiers)
		return nil
	}); err != nil {
		return nil, 0, err
	}
	return assets, total, nil
}

// assetListOrderBy maps the API's sort_by onto a column.
//
// Sort and page stay API parameters and are deliberately NOT part of the query
// language (QUERY_LANGUAGE §1 non-goals): the language answers which rows, never
// what about them. The whitelist is what keeps a sort key from reaching SQL as
// user text.
func assetListOrderBy(filters models.AssetFilters) string {
	sortBy := "a.hostname"
	switch filters.SortBy {
	case "hostname", "environment", "created_at", "last_seen_at", "owner_email", "display_name":
		sortBy = "a." + filters.SortBy
	case "ip_address", "primary_address":
		sortBy = "a.primary_address"
	case "asset_type", "class_key", "class":
		// `asset_type` is accepted as the old spelling of the class facet so an
		// existing saved sort keeps working; it orders by class_key.
		sortBy = "a.class_key"
	case "operating_system":
		sortBy = assetOperatingSystemSQL
	case "risk_score", "risk":
		sortBy = "a.risk_score"
	}
	sortOrder := "ASC"
	if filters.SortOrder == "desc" {
		sortOrder = "DESC"
	}
	// A stable tiebreak, so page 2 of a list sorted on a column half the rows
	// share is not a reshuffle of page 1.
	return sortBy + " " + sortOrder + ", a.id ASC"
}

func assetIDs(assets []models.Asset) []uuid.UUID {
	out := make([]uuid.UUID, len(assets))
	for i := range assets {
		out[i] = assets[i].ID
	}
	return out
}

// scanAssetListRow reads one row of the list projection above. It is a function
// rather than inline so the projection and the scan stay adjacent in a diff:
// they are positional, and a column added to one and not the other is a runtime
// error nothing catches until the query runs.
func scanAssetListRow(rows *sqlx.Rows) (*models.Asset, error) {
	var asset models.Asset
	var certCount, cfgCount sql.NullInt64
	var protocolSummaryText string
	var tagsText, metadataText, attributesText string
	var assessedBy pq.StringArray
	if err := rows.Scan(
		&asset.ID, &asset.TenantID, &asset.Hostname, &asset.DisplayName, &asset.PrimaryAddress,
		&asset.ClassKey, &asset.ClassPath, &asset.ClassSourceKind, &asset.ClassSourceRef, &asset.ClassConfidence,
		&attributesText, &asset.Environment, &asset.BusinessUnit, &asset.OwnerEmail, &asset.SupportGroup,
		&asset.Description, &tagsText, &metadataText, &asset.AssetOwnership, &asset.AssetStatus,
		&asset.StaleStatus, &asset.RiskScore, &assessedBy,
		&asset.FirstDiscoveredAt, &asset.LastSeenAt, &asset.CreatedAt, &asset.UpdatedAt,
		&asset.DeletedAt, &asset.LocationID, &asset.NetworkSegmentID, &asset.NetworkSegmentName,
		&asset.Site, &asset.Region, &asset.Zone,
		&certCount, &cfgCount, &protocolSummaryText,
	); err != nil {
		return nil, fmt.Errorf("failed to scan asset: %w", err)
	}
	asset.RiskAssessedBy = []string(assessedBy)
	unmarshalJSONInto(attributesText, &asset.Attributes)
	unmarshalJSONInto(tagsText, &asset.Tags)
	unmarshalJSONInto(metadataText, &asset.Metadata)
	normalizeAssetCollections(&asset)
	if asset.Tags == nil {
		asset.Tags = make(map[string]interface{})
	}
	if asset.Metadata == nil {
		asset.Metadata = make(map[string]interface{})
	}
	setMergedInto(&asset)
	if certCount.Valid {
		n := int(certCount.Int64)
		asset.CertificateCount = &n
	}
	if cfgCount.Valid {
		n := int(cfgCount.Int64)
		asset.CryptoImplementationCount = &n
	}
	if protocolSummaryText != "" {
		_ = json.Unmarshal([]byte(protocolSummaryText), &asset.ProtocolSummary)
	}
	// One source for the badge: the persisted rollup, banded through the one
	// ladder. HighestRisk is the same number under its older name, kept so an
	// existing consumer does not break.
	score := asset.RiskScore
	asset.HighestRisk = &score
	asset.RiskLevel = models.GetRiskLevel(score)
	return &asset, nil
}

func unmarshalJSONInto(text string, dst interface{}) {
	if text == "" {
		return
	}
	_ = json.Unmarshal([]byte(text), dst)
}

// GetAssetByID retrieves a single asset with its crypto configurations.
func (s *AssetService) GetAssetByID(tenantID, assetID uuid.UUID) (*models.Asset, error) {
	query := `
		SELECT
			a.id, a.tenant_id, a.hostname, a.display_name, host(a.primary_address),
			a.class_key, a.class_path, a.class_source_kind, a.class_source_ref, a.class_confidence,
			` + assetOperatingSystemSQL + `, a.attributes::text, a.environment, a.business_unit, a.owner_email,
			a.support_group, a.description, a.tags::text, a.metadata::text,
			a.asset_ownership, a.asset_status, a.stale_status,
			a.discovery_method, a.confidence_score,
			a.risk_score, a.risk_assessed_by,
			a.first_discovered_at, a.last_seen_at,
			a.created_at, a.updated_at, a.deleted_at,
			a.location_id, a.network_segment_id, ns.name AS network_segment_name,
			a.site, a.region, a.zone
		FROM assets a
		LEFT JOIN network_segments ns ON ns.id = a.network_segment_id
		WHERE a.id = $1 AND a.tenant_id = $2 AND a.deleted_at IS NULL
	`
	var asset models.Asset
	var tagsText, metadataText, attributesText string
	var operatingSystem *string
	var assessedBy pq.StringArray
	// RLS-scoped read over assets / network_segments — wrapped in WithTenantTx.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(query, assetID, tenantID).Scan(
			&asset.ID, &asset.TenantID, &asset.Hostname, &asset.DisplayName, &asset.PrimaryAddress,
			&asset.ClassKey, &asset.ClassPath, &asset.ClassSourceKind, &asset.ClassSourceRef, &asset.ClassConfidence,
			&operatingSystem, &attributesText, &asset.Environment, &asset.BusinessUnit, &asset.OwnerEmail,
			&asset.SupportGroup, &asset.Description, &tagsText, &metadataText,
			&asset.AssetOwnership, &asset.AssetStatus, &asset.StaleStatus,
			&asset.DiscoveryMethod, &asset.ConfidenceScore,
			&asset.RiskScore, &assessedBy,
			&asset.FirstDiscoveredAt, &asset.LastSeenAt, &asset.CreatedAt, &asset.UpdatedAt,
			&asset.DeletedAt, &asset.LocationID, &asset.NetworkSegmentID, &asset.NetworkSegmentName,
			&asset.Site, &asset.Region, &asset.Zone,
		)
	}); err != nil {
		return nil, fmt.Errorf("failed to get asset: %w", err)
	}
	asset.RiskAssessedBy = []string(assessedBy)
	if attributesText != "" {
		_ = json.Unmarshal([]byte(attributesText), &asset.Attributes)
	}
	setAssetOperatingSystem(&asset, operatingSystem)
	normalizeAssetCollections(&asset)
	// The asset page needs the children, not a stand-in for them: this is the
	// one read that returns a single asset, so it loads all of both.
	if ids, err := s.getAssetIdentifiers(tenantID, assetID); err == nil {
		asset.Identifiers = ids
	} else {
		log.Printf("[AssetService] GetAssetByID: loading identifiers for %s failed: %v", assetID, err)
	}
	if eps, err := s.getAssetEndpoints(tenantID, assetID); err == nil {
		asset.Endpoints = eps
		if len(eps) > 0 {
			ep := eps[0]
			asset.PrimaryEndpoint = &ep
		}
	} else {
		log.Printf("[AssetService] GetAssetByID: loading endpoints for %s failed: %v", assetID, err)
	}
	if tagsText != "" {
		_ = json.Unmarshal([]byte(tagsText), &asset.Tags)
	}
	if asset.Tags == nil {
		asset.Tags = make(map[string]interface{})
	}
	if metadataText != "" {
		_ = json.Unmarshal([]byte(metadataText), &asset.Metadata)
	}
	if asset.Metadata == nil {
		asset.Metadata = make(map[string]interface{})
	}
	// The tombstone pointer, if this is one. GetAssetByID is the read a stale
	// reference to a merged-away asset lands on, so it is the one that most has
	// to answer "this is now that".
	setMergedInto(&asset)
	cryptoImpls, err := s.GetCryptoImplementations(tenantID, assetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get crypto implementations: %w", err)
	}
	asset.CryptoImplementations = cryptoImpls
	// The badge reads the PERSISTED rollup, banded once. It used to call
	// CalculateAssetRiskScore here, which OVERWROTE the stored score with a MAX
	// over whatever configurations this read happened to load — a second opinion
	// that disagreed with the list, the summary and the facets the moment the
	// two were computed from different rows.
	asset.RiskLevel = models.GetRiskLevel(asset.RiskScore)
	score := asset.RiskScore
	asset.HighestRisk = &score
	return &asset, nil
}

// GetAssetHistory retrieves the history of changes for an asset, newest first.
//
// Ordered by (created_at, seq), not by created_at alone. `created_at` defaults
// to now(), which is the TRANSACTION timestamp: the identification engine
// writes `created` and then `merge_proposed` for one observation inside one
// transaction, so both carry the same instant and an ORDER BY created_at tells
// the story in whichever order the planner happens to return. `seq` is the
// append counter and the only thing that can break that tie.
func (s *AssetService) GetAssetHistory(tenantID, assetID uuid.UUID) ([]models.AssetHistory, error) {
	query := `
		SELECT
			id, asset_id, tenant_id, actor_user_id, source, action, changes_json::text, created_at
		FROM asset_history
		WHERE asset_id = $1 AND tenant_id = $2
		ORDER BY created_at DESC, seq DESC
		LIMIT 100
	`
	var history []models.AssetHistory
	// RLS-scoped read over asset_history — wrapped in WithTenantTx.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, e := tx.Query(query, assetID, tenantID)
		if e != nil {
			return fmt.Errorf("failed to query asset history: %w", e)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var h models.AssetHistory
			var changesJSONText string
			var actorUserID sql.NullString
			if e := rows.Scan(&h.ID, &h.AssetID, &h.TenantID, &actorUserID, &h.Source, &h.Action, &changesJSONText, &h.CreatedAt); e != nil {
				return fmt.Errorf("failed to scan asset history: %w", e)
			}
			if actorUserID.Valid {
				if actorUUID, e := uuid.Parse(actorUserID.String); e == nil {
					h.ActorUserID = &actorUUID
				}
			}
			if changesJSONText != "" {
				_ = json.Unmarshal([]byte(changesJSONText), &h.ChangesJSON)
			}
			if h.ChangesJSON == nil {
				h.ChangesJSON = make(map[string]interface{})
			}
			history = append(history, h)
		}
		if e := rows.Err(); e != nil {
			return fmt.Errorf("error iterating asset history: %w", e)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return history, nil
}

// AssetClassHistoryLimit is how many class changes one asset's history returns.
//
// 100, like the general asset history beside it. Unlike that one it is not a
// practical ceiling: an asset that has been reclassified a hundred times has a
// curation problem, and the hundred most recent rows are the ones that say so.
const AssetClassHistoryLimit = 100

// GetAssetClassHistory returns an asset's class changes, newest first.
//
// Read-only, and deliberately its own endpoint rather than a field on the asset:
// most assets have exactly one row (the one their creation wrote) and loading a
// timeline on every asset read would pay for a panel almost nobody opens.
//
// Ordered by (created_at, id). `created_at` is the TRANSACTION timestamp, so two
// rows written in one transaction carry the same instant — the tie-break keeps
// the order stable between calls rather than leaving it to the planner. This
// table has no `seq` counter of its own because, unlike asset_history, nothing
// writes two rows for one asset in one transaction: a class moves once.
func (s *AssetService) GetAssetClassHistory(tenantID, assetID uuid.UUID) ([]models.AssetClassChange, error) {
	query := `
		SELECT id, asset_id, tenant_id, from_class_key, to_class_key,
		       source, actor_user_id, evidence::text, created_at
		  FROM asset_class_history
		 WHERE tenant_id = $1 AND asset_id = $2
		 ORDER BY created_at DESC, id DESC
		 LIMIT $3`

	var out []models.AssetClassChange
	// RLS-scoped read over asset_class_history.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, e := tx.Query(query, tenantID, assetID, AssetClassHistoryLimit)
		if e != nil {
			return fmt.Errorf("failed to query asset class history: %w", e)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var (
				row          models.AssetClassChange
				fromClass    sql.NullString
				actorUserID  sql.NullString
				evidenceText string
			)
			if e := rows.Scan(&row.ID, &row.AssetID, &row.TenantID, &fromClass, &row.ToClassKey,
				&row.Source, &actorUserID, &evidenceText, &row.CreatedAt); e != nil {
				return fmt.Errorf("failed to scan asset class history: %w", e)
			}
			if fromClass.Valid {
				key := fromClass.String
				row.FromClassKey = &key
				row.FromClassLabel = classLabelOf(key)
			}
			row.ToClassLabel = classLabelOf(row.ToClassKey)
			if actorUserID.Valid {
				if parsed, e := uuid.Parse(actorUserID.String); e == nil {
					row.ActorUserID = &parsed
				}
			}
			row.Evidence = map[string]interface{}{}
			if evidenceText != "" {
				_ = json.Unmarshal([]byte(evidenceText), &row.Evidence)
			}
			out = append(out, row)
		}
		if e := rows.Err(); e != nil {
			return fmt.Errorf("error iterating asset class history: %w", e)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// GetRiskSummary calculates risk statistics for the tenant.
func (s *AssetService) GetRiskSummary(tenantID uuid.UUID) (*models.RiskSummary, error) {
	// Roll each asset up to its own worst score FIRST, then band it once.
	//
	// This used to band per crypto implementation and count distinct assets, so
	// an asset landed in every band any of its implementations touched: one asset
	// with a 75-scoring and a 30-scoring implementation was counted in BOTH
	// high_risk and low_risk, and the buckets summed past total_assets (the
	// dashboard distribution bar therefore exceeded 100%). Banding the per-asset
	// MAX makes the buckets mutually exclusive and exhaustive — they now sum to
	// exactly total_assets — and matches how the lens badge and facet filters
	// already roll up.
	//
	// critical_findings is deliberately a different unit: it counts high-severity
	// *implementations*, not assets, which is why it is computed separately.
	//
	// asset_status = 'monitoring' (M-3): a pending-approval asset is not yet part
	// of inventory — every Inventory lens excludes it via the same default filter
	// (buildAssetListWhereAndHaving), and the Approvals banner/tile is the
	// dedicated surface for surfacing it. Counting it here made "8 monitored
	// assets" on the Dashboard/Posture disagree with "7" everywhere else. The
	// same filter is applied to total_crypto/critical_findings so a crypto
	// configuration on a still-pending asset doesn't inflate "Configs" either —
	// keeping risk/summary's whole payload scoped to the one universe of assets
	// it claims to be monitoring (M-1: this is also the scope crypto-configurations
	// and the PQC classifier now use, see crypto_implementation_service.go and
	// pqc_readiness.go).
	//
	// The per-asset score is READ, not recomputed. It used to be
	// `MAX(ci.risk_score)` over the asset's live configurations, computed here
	// and again in the list query, while `assets.risk_score` carried the value
	// recomputeAssetRisk had written. Three places, one number, and nothing
	// asserting they matched. The rollup is now the single source in all of
	// them, so a summary that disagrees with a badge is a data bug rather than
	// two queries with different opinions.
	criticalMin, _ := models.RiskBandMin("Critical")
	query := fmt.Sprintf(`
		WITH asset_risk AS (
			-- assessed is the coverage guard the risk FACET has always
			-- carried and this summary did not: score 0 with an empty
			-- risk_assessed_by is NOT ASSESSED, and score 0 WITH a producer is
			-- assessed clean. Every band below is guarded by it, so a tenant
			-- that has never been scanned reports its assets as unknown rather
			-- than as informational — and the tile finally agrees with the rail.
			SELECT a.id, a.risk_score AS score,
			       COALESCE(array_length(a.risk_assessed_by, 1), 0) > 0 AS assessed
			FROM assets a
			WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND a.asset_status = 'monitoring'
		)
		SELECT
			(SELECT COUNT(*) FROM asset_risk) AS total_assets,
			(SELECT COUNT(*) FROM crypto_implementations ci
			   JOIN assets a ON a.tenant_id = ci.tenant_id AND a.id = ci.asset_id
			  WHERE ci.tenant_id = $1 AND ci.deleted_at IS NULL AND a.deleted_at IS NULL
			    AND a.asset_status = 'monitoring') AS total_crypto,
			(SELECT COUNT(*) FROM asset_risk WHERE assessed AND (%s)) AS high_risk,
			(SELECT COUNT(*) FROM asset_risk WHERE assessed AND (%s)) AS medium_risk,
			(SELECT COUNT(*) FROM asset_risk WHERE assessed AND (%s)) AS low_risk,
			(SELECT COUNT(*) FROM asset_risk WHERE assessed AND (%s)) AS informational,
			(SELECT COUNT(*) FROM asset_risk WHERE NOT assessed) AS unknown_risk,
			(SELECT COUNT(*) FROM crypto_implementations ci
			   JOIN assets a ON a.tenant_id = ci.tenant_id AND a.id = ci.asset_id
			  WHERE ci.tenant_id = $1 AND ci.deleted_at IS NULL AND a.deleted_at IS NULL
			    AND a.asset_status = 'monitoring'
			    AND ci.risk_score >= %d) AS critical_findings
	`,
		models.MustRiskAtLeastSQL("score", "High"), // high AND above, so Critical is included
		models.MustRiskBandSQL("score", "Medium"),
		models.MustRiskBandSQL("score", "Low"),
		models.MustRiskBandSQL("score", "Informational"),
		criticalMin,
	)
	var summary models.RiskSummary
	// RLS-scoped read over assets / crypto_implementations — wrapped in WithTenantTx.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(query, tenantID).Scan(
			&summary.TotalAssets, &summary.TotalCrypto, &summary.HighRisk, &summary.MediumRisk,
			&summary.LowRisk, &summary.Informational, &summary.UnknownRisk, &summary.CriticalFindings,
		)
	}); err != nil {
		log.Printf("[ERROR] GetRiskSummary - Query failed: %v, tenantID: %v", err, tenantID)
		return nil, fmt.Errorf("failed to get risk summary: %w", err)
	}
	return &summary, nil
}

// riskIndex is the dashboard's posture metric: the percentage of a tenant's
// assets that are at high risk. Defined once here so the trend line and the
// hero gauge can never disagree (the web-ui hero computes the same ratio).
func riskIndex(highRisk, totalAssets int) int {
	if totalAssets <= 0 {
		return 0
	}
	return int(math.Round(float64(highRisk) / float64(totalAssets) * 100))
}

// GetPostureTrend returns a continuous day-by-day risk-index series for the last
// `days` days (UTC), ending today, for the dashboard posture trend line (ADR-0007).
//
// History only accrues forward — audit-service's nightly job writes one
// posture_daily_snapshots row per tenant per day. To avoid a blank chart for a
// new tenant (no snapshots yet), days before the first real snapshot are SEEDED
// flat at the tenant's current live posture (Seeded=true). Real snapshot days
// use the stored value; gaps between real snapshots carry the last real value
// forward; and today's point always reflects the live posture so the right edge
// matches the hero gauge.
func (s *AssetService) GetPostureTrend(tenantID uuid.UUID, days int) ([]models.PostureTrendPoint, error) {
	if days < 1 {
		days = 30
	}
	if days > 365 {
		days = 365
	}

	// Real snapshots within the window, oldest first. Index by UTC date string.
	// RLS-scoped read over posture_daily_snapshots — wrapped in WithTenantTx.
	realByDate := make(map[string]int)
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, e := tx.Query(`
			SELECT snapshot_date, total_assets, high_risk
			FROM posture_daily_snapshots
			WHERE tenant_id = $1
			  AND snapshot_date > ((now() AT TIME ZONE 'UTC')::date - $2::int)
			ORDER BY snapshot_date ASC
		`, tenantID, days)
		if e != nil {
			log.Printf("[ERROR] GetPostureTrend - snapshot query failed: %v, tenantID: %v", e, tenantID)
			return fmt.Errorf("failed to get posture snapshots: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var snapDate time.Time
			var totalAssets, highRisk int
			if e := rows.Scan(&snapDate, &totalAssets, &highRisk); e != nil {
				return fmt.Errorf("failed to scan posture snapshot: %w", e)
			}
			realByDate[snapDate.UTC().Format("2006-01-02")] = riskIndex(highRisk, totalAssets)
		}
		if e := rows.Err(); e != nil {
			return fmt.Errorf("failed iterating posture snapshots: %w", e)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// Current live posture — used to seed pre-history days and to fix today's point.
	current, err := s.GetRiskSummary(tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current risk summary: %w", err)
	}
	currentIndex := riskIndex(current.HighRisk, current.TotalAssets)

	return buildPostureTrend(realByDate, currentIndex, days, time.Now().UTC()), nil
}

// buildPostureTrend assembles the continuous day-by-day series from the real
// snapshots (realByDate, keyed YYYY-MM-DD UTC → risk index) plus the current
// live posture. Pure (no DB/clock) so the seed/carry-forward rules are unit
// tested directly. Rules, oldest→newest:
//   - today (last point): always the live posture, so the right edge matches the hero gauge;
//   - a day with a real snapshot: that value (Seeded=false);
//   - a day before the first real snapshot: seeded flat at the live posture (Seeded=true);
//   - a gap after real data: carry the last real value forward (Seeded=false).
func buildPostureTrend(realByDate map[string]int, currentIndex, days int, today time.Time) []models.PostureTrendPoint {
	points := make([]models.PostureTrendPoint, 0, days)
	lastReal := currentIndex // carried forward; before any real snapshot this is the live seed
	seenReal := false
	for i := days - 1; i >= 0; i-- {
		key := today.AddDate(0, 0, -i).Format("2006-01-02")
		v, isReal := realByDate[key]
		switch {
		case i == 0:
			points = append(points, models.PostureTrendPoint{Date: key, RiskIndex: currentIndex, Seeded: false})
		case isReal:
			lastReal = v
			seenReal = true
			points = append(points, models.PostureTrendPoint{Date: key, RiskIndex: v, Seeded: false})
		case !seenReal:
			points = append(points, models.PostureTrendPoint{Date: key, RiskIndex: currentIndex, Seeded: true})
		default:
			points = append(points, models.PostureTrendPoint{Date: key, RiskIndex: lastReal, Seeded: false})
		}
	}
	return points
}

// GetPQCReadinessSummary calculates tenant PQC adoption by joining crypto_implementations
// to the algorithms catalog. An implementation is "PQC ready" when its key exchange or
// signature algorithm resolves to an entry with is_pqc=true in the algorithms table.
func (s *AssetService) GetPQCReadinessSummary(tenantID uuid.UUID) (*models.PQCReadinessSummary, error) {
	// Shares the classifier behind /pqc/progress so the product cannot report two
	// contradictory quantum-readiness numbers. This previously ran its own query
	// that string-matched ci.key_exchange_algorithm / ci.signature_algorithm
	// against algorithms.code, which diverged from the progress endpoint in three
	// ways: it only inspected two of an implementation's components, it counted an
	// implementation as ready if EITHER the key exchange or the signature was PQC
	// (a PQC key exchange with a classical RSA signature is still quantum-
	// vulnerable per NIST IR 8547, which disallows RSA after 2035), and it counted
	// implementations that use no asymmetric cryptography at all as not-ready.
	counts, err := classifyTenantImplementationsPQC(s.db, tenantID)
	if err != nil {
		log.Printf("[ERROR] GetPQCReadinessSummary - classification failed: %v, tenantID: %v", err, tenantID)
		return nil, fmt.Errorf("failed to get PQC readiness summary: %w", err)
	}

	// "Ready" means needs no PQC migration: already post-quantum, or using no
	// asymmetric cryptography. Unclassified counts against readiness.
	ready := counts.PQCReady + counts.SymmetricSafe
	return &models.PQCReadinessSummary{
		TotalImplementations: counts.Total,
		PQCImplementations:   ready,
		ReadinessPercent:     math.Round(counts.ReadyPercent()*10) / 10,
	}, nil
}

// GetAssetStats calculates asset statistics with trend data for a given period.
func (s *AssetService) GetAssetStats(tenantID uuid.UUID, period string) (*models.AssetStats, error) {
	days := 7
	switch period {
	case "7d":
		days = 7
	case "30d":
		days = 30
	}
	var currentCount, previousCount int
	previousQuery := fmt.Sprintf(`SELECT COUNT(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL AND created_at <= NOW() - INTERVAL '%d days'`, days)
	// RLS-scoped reads over assets — current + previous counts in one tenant tx.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		if e := tx.Get(&currentCount, `SELECT COUNT(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenantID); e != nil {
			return fmt.Errorf("failed to get current asset count: %w", e)
		}
		if e := tx.Get(&previousCount, previousQuery, tenantID); e != nil {
			return fmt.Errorf("failed to get previous asset count: %w", e)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	change := currentCount - previousCount
	changePercent := 0.0
	if previousCount > 0 {
		changePercent = (float64(change) / float64(previousCount)) * 100
	} else if currentCount > 0 {
		changePercent = 100.0
	}
	return &models.AssetStats{
		Current:       currentCount,
		Previous:      previousCount,
		Change:        change,
		ChangePercent: changePercent,
		Period:        period,
	}, nil
}

// GetRecentAssetsCount returns the count of assets created within the specified number of days with optional filters.
func (s *AssetService) GetRecentAssetsCount(tenantID uuid.UUID, days int, filters models.AssetFilters) (int, error) {
	if days < 0 {
		days = 7
	}
	if days > 365 {
		days = 365
	}
	pred, err := buildAssetWhere(filters.Query, filters, 2, assetQueryAlias)
	if err != nil {
		return 0, err
	}
	args := append([]interface{}{tenantID}, pred.Args...)
	// discovery_source, applied HERE too.
	//
	// The handler binds it, the list and the facets both apply it, and this
	// count did not — so "N new assets from the sensor in the last 7 days" was
	// the count of new assets from ANY source, and the dashboard tile disagreed
	// with the list it linked to. Spelled the same way as the other two, in the
	// one place each of them spells it.
	discoveryWhere, args := discoverySourcePredicate(filters, args)
	// COUNT(*) over assets, not COUNT(DISTINCT a.id) over a join that multiplied
	// them: nothing is joined any more, so there is nothing to de-duplicate.
	baseQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM assets a
		WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
		  AND a.created_at > NOW() - INTERVAL '%d days'
		  AND (%s)%s
	`, days, pred.Where, discoveryWhere)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var count int
	// RLS-scoped read over assets, with the query-language statement ceiling:
	// `pred.Where` is the caller's own predicate (query.StatementTimeout).
	if err := database.WithTenantTxTimeout(ctx, s.db, tenantID, assetQueryStatementTimeout, func(tx *sqlx.Tx) error {
		return tx.GetContext(ctx, &count, baseQuery, args...)
	}); err != nil {
		log.Printf("[ERROR] GetRecentAssetsCount - Query failed: %v, tenantID: %v, days: %d", err, tenantID, days)
		return 0, fmt.Errorf("failed to get recent assets count: %w", err)
	}
	return count, nil
}

// discoverySourcePredicate appends the one legacy filter the query language has
// no field for, and returns the extra WHERE fragment.
//
// `discovery_source` is pipeline state inside `assets.metadata`, not a modelled
// property, so it is not in the catalogue and therefore cannot appear in the
// canonical query a read echoes back. That is a real hole and it is named
// rather than hidden: every response that can carry this filter also carries
// `filters_applied.discovery_source`, and the OpenAPI description says the echo
// excludes it.
//
// Making it a first-class field would be better and is the eventual answer — a
// jsonb accessor over `metadata` would translate exactly like `attr.*` does.
// It is not done here because the field table is mirrored into
// packages/primitives and pinned by a §4.3 name list on the TypeScript side,
// so adding one field is a change across both catalogues and belongs with that
// work rather than smuggled into a read fix.
//
// One spelling, in one function: the list, the facets and the recent count each
// had (or, in the count's case, forgot to have) their own copy.
func discoverySourcePredicate(filters models.AssetFilters, args []interface{}) (string, []interface{}) {
	if len(filters.DiscoverySource) == 0 {
		return "", args
	}
	args = append(args, pq.Array(filters.DiscoverySource))
	return fmt.Sprintf(" AND a.metadata->>'discovery_source' = ANY($%d)", len(args)), args
}
