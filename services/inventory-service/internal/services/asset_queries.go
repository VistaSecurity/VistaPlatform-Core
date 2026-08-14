// Package services: asset list and read queries (GetAssets, GetAssetByID, etc.).
package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// GetAssets retrieves assets with filtering, pagination, and risk analysis.
func (s *AssetService) GetAssets(tenantID uuid.UUID, filters models.AssetFilters) ([]models.Asset, int, error) {
	if err := validateAssetFilters(filters); err != nil {
		return nil, 0, err
	}
	whereConditions, havingConditions, builtArgs := buildAssetListWhereAndHaving(filters, 2)
	args := append([]interface{}{tenantID}, builtArgs...)

	baseQuery := `
		SELECT
			a.id, a.tenant_id, a.hostname, a.ip_address, a.port, a.asset_type,
			a.operating_system, a.environment, a.business_unit, a.owner_email,
			a.description, a.tags::text, a.metadata::text, a.asset_ownership, a.asset_status,
			a.stale_status,
			a.first_discovered_at, a.last_seen_at,
			a.created_at, a.updated_at, a.deleted_at,
			a.location_id, a.network_segment_id, ns.name AS network_segment_name,
			a.site, a.region, a.zone,
			a.service_name, a.service_version,
			a.service_confidence, a.service_identification_method,
			(SELECT COUNT(DISTINCT ci2.certificate_id)
			   FROM crypto_implementations ci2
			  WHERE ci2.asset_id = a.id AND ci2.deleted_at IS NULL) AS certificate_count,
			COUNT(DISTINCT ci.id) AS crypto_implementation_count,
			-- Per-protocol rollup for the Inventory row's protocol badges. Kept
			-- server-side so the list renders badges from ONE request instead of
			-- a per-row child query (a 50-request waterfall per page).
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
			), '[]'::jsonb)::text AS protocol_summary,
			COALESCE(MAX(ci.risk_score), 0) as "HighestRisk",
			` + models.RiskLevelCaseSQL("COALESCE(MAX(ci.risk_score), 0)") + ` as "RiskLevel"
		FROM network_assets a
		LEFT JOIN network_segments ns ON ns.id = a.network_segment_id
		LEFT JOIN crypto_implementations ci ON a.id = ci.asset_id AND ci.deleted_at IS NULL
		WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
	`
	countQuery := `
		SELECT COUNT(DISTINCT a.id)
		FROM network_assets a
		LEFT JOIN network_segments ns ON ns.id = a.network_segment_id
		LEFT JOIN crypto_implementations ci ON a.id = ci.asset_id AND ci.deleted_at IS NULL
		WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
	`
	if len(whereConditions) > 0 {
		clause := " AND " + strings.Join(whereConditions, " AND ")
		baseQuery += clause
		countQuery += clause
	}
	groupByClause := " GROUP BY a.id, a.tenant_id, a.hostname, a.ip_address, a.port, a.asset_type, a.operating_system, a.environment, a.business_unit, a.owner_email, a.description, a.tags, a.metadata, a.asset_ownership, a.asset_status, a.stale_status, a.first_discovered_at, a.last_seen_at, a.created_at, a.updated_at, a.deleted_at, a.location_id, a.network_segment_id, ns.name, a.site, a.region, a.zone, a.service_name, a.service_version, a.service_confidence, a.service_identification_method"
	baseQuery += groupByClause
	if len(havingConditions) > 0 {
		havingClause := " HAVING " + strings.Join(havingConditions, " AND ")
		baseQuery += havingClause
		countQuery += groupByClause + havingClause
		countQuery = fmt.Sprintf(`SELECT COUNT(*) FROM (%s) as filtered_assets`, countQuery)
	}

	sortBy := "a.hostname"
	if filters.SortBy != "" {
		switch filters.SortBy {
		case "hostname", "ip_address", "asset_type", "environment", "created_at", "last_seen_at", "owner_email", "operating_system":
			sortBy = "a." + filters.SortBy
		case "risk_score":
			sortBy = "\"HighestRisk\""
		}
	}
	sortOrder := "ASC"
	if filters.SortOrder == "desc" {
		sortOrder = "DESC"
	}
	baseQuery += fmt.Sprintf(" ORDER BY %s %s", sortBy, sortOrder)
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

	// RLS-scoped reads over network_assets / crypto_implementations / network_segments —
	// count + page run in one tenant tx (sets app.tenant_id).
	var total int
	var assets []models.Asset
	if err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		if e := tx.GetContext(ctx, &total, countQuery, args...); e != nil {
			return fmt.Errorf("failed to get assets count: %w", e)
		}
		rows, e := tx.QueryxContext(ctx, baseQuery, args...)
		if e != nil {
			return fmt.Errorf("failed to query assets: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var asset models.Asset
			var highestRisk *int
			var certCount sql.NullInt64
			var cfgCount sql.NullInt64
			var protocolSummaryText string
			var riskLevel string
			var tagsText, metadataText string
			if e := rows.Scan(
				&asset.ID, &asset.TenantID, &asset.Hostname, &asset.IPAddress, &asset.Port,
				&asset.AssetType, &asset.OperatingSystem, &asset.Environment, &asset.BusinessUnit,
				&asset.OwnerEmail, &asset.Description, &tagsText, &metadataText, &asset.AssetOwnership, &asset.AssetStatus,
				&asset.StaleStatus,
				&asset.FirstDiscoveredAt, &asset.LastSeenAt, &asset.CreatedAt, &asset.UpdatedAt,
				&asset.DeletedAt, &asset.LocationID, &asset.NetworkSegmentID, &asset.NetworkSegmentName,
				&asset.Site, &asset.Region, &asset.Zone,
				&asset.ServiceName, &asset.ServiceVersion,
				&asset.ServiceConfidence, &asset.ServiceIdentificationMethod, &certCount,
				&cfgCount, &protocolSummaryText, &highestRisk, &riskLevel,
			); e != nil {
				return fmt.Errorf("failed to scan asset: %w", e)
			}
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
			if highestRisk != nil {
				asset.RiskScore = *highestRisk
				asset.HighestRisk = highestRisk
			}
			asset.RiskLevel = riskLevel
			assets = append(assets, asset)
		}
		if e := rows.Err(); e != nil {
			return fmt.Errorf("query execution error: %w", e)
		}
		return nil
	}); err != nil {
		return nil, 0, err
	}
	return assets, total, nil
}

// GetAssetByID retrieves a single asset with its crypto configurations.
func (s *AssetService) GetAssetByID(tenantID, assetID uuid.UUID) (*models.Asset, error) {
	query := `
		SELECT
			a.id, a.tenant_id, a.hostname, a.ip_address, a.port, a.asset_type,
			a.operating_system, a.environment, a.business_unit, a.owner_email,
			a.description, a.tags::text, a.metadata::text, a.asset_ownership, a.asset_status,
			a.first_discovered_at, a.last_seen_at,
			a.created_at, a.updated_at, a.deleted_at,
			a.location_id, a.network_segment_id, ns.name AS network_segment_name,
			a.service_name, a.service_version,
			a.service_confidence, a.service_identification_method
		FROM network_assets a
		LEFT JOIN network_segments ns ON ns.id = a.network_segment_id
		WHERE a.id = $1 AND a.tenant_id = $2 AND a.deleted_at IS NULL
	`
	var asset models.Asset
	var tagsText, metadataText string
	// RLS-scoped read over network_assets / network_segments — wrapped in WithTenantTx.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(query, assetID, tenantID).Scan(
			&asset.ID, &asset.TenantID, &asset.Hostname, &asset.IPAddress, &asset.Port,
			&asset.AssetType, &asset.OperatingSystem, &asset.Environment, &asset.BusinessUnit,
			&asset.OwnerEmail, &asset.Description, &tagsText, &metadataText, &asset.AssetOwnership, &asset.AssetStatus,
			&asset.FirstDiscoveredAt, &asset.LastSeenAt, &asset.CreatedAt, &asset.UpdatedAt,
			&asset.DeletedAt, &asset.LocationID, &asset.NetworkSegmentID, &asset.NetworkSegmentName, &asset.ServiceName, &asset.ServiceVersion,
			&asset.ServiceConfidence, &asset.ServiceIdentificationMethod,
		)
	}); err != nil {
		return nil, fmt.Errorf("failed to get asset: %w", err)
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
	cryptoImpls, err := s.GetCryptoImplementations(tenantID, assetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get crypto implementations: %w", err)
	}
	asset.CryptoImplementations = cryptoImpls
	asset.CalculateAssetRiskScore()
	return &asset, nil
}

// GetAssetHistory retrieves the history of changes for an asset.
func (s *AssetService) GetAssetHistory(tenantID, assetID uuid.UUID) ([]models.AssetHistory, error) {
	query := `
		SELECT
			id, asset_id, tenant_id, actor_user_id, source, action, changes_json::text, created_at
		FROM asset_history
		WHERE asset_id = $1 AND tenant_id = $2
		ORDER BY created_at DESC
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
	criticalMin, _ := models.RiskBandMin("Critical")
	query := fmt.Sprintf(`
		WITH asset_risk AS (
			SELECT a.id, COALESCE(MAX(ci.risk_score), 0) AS score
			FROM network_assets a
			LEFT JOIN crypto_implementations ci ON a.id = ci.asset_id AND ci.deleted_at IS NULL
			WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND a.asset_status = 'monitoring'
			GROUP BY a.id
		)
		SELECT
			(SELECT COUNT(*) FROM asset_risk) AS total_assets,
			(SELECT COUNT(*) FROM crypto_implementations ci
			   JOIN network_assets a ON a.id = ci.asset_id
			  WHERE ci.tenant_id = $1 AND ci.deleted_at IS NULL AND a.deleted_at IS NULL
			    AND a.asset_status = 'monitoring') AS total_crypto,
			(SELECT COUNT(*) FROM asset_risk WHERE %s) AS high_risk,
			(SELECT COUNT(*) FROM asset_risk WHERE %s) AS medium_risk,
			(SELECT COUNT(*) FROM asset_risk WHERE %s) AS low_risk,
			(SELECT COUNT(*) FROM asset_risk WHERE %s) AS unknown_risk,
			(SELECT COUNT(*) FROM crypto_implementations ci
			   JOIN network_assets a ON a.id = ci.asset_id
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
	// RLS-scoped read over network_assets / crypto_implementations — wrapped in WithTenantTx.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(query, tenantID).Scan(
			&summary.TotalAssets, &summary.TotalCrypto, &summary.HighRisk, &summary.MediumRisk,
			&summary.LowRisk, &summary.UnknownRisk, &summary.CriticalFindings,
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
	previousQuery := fmt.Sprintf(`SELECT COUNT(*) FROM network_assets WHERE tenant_id = $1 AND deleted_at IS NULL AND created_at <= NOW() - INTERVAL '%d days'`, days)
	// RLS-scoped reads over network_assets — current + previous counts in one tenant tx.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		if e := tx.Get(&currentCount, `SELECT COUNT(*) FROM network_assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenantID); e != nil {
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
	whereConditions, havingConditions, builtArgs := buildAssetListWhereAndHaving(filters, 2)
	args := append([]interface{}{tenantID}, builtArgs...)
	baseQuery := fmt.Sprintf(`
		SELECT COUNT(DISTINCT a.id)
		FROM network_assets a
		LEFT JOIN crypto_implementations ci ON a.id = ci.asset_id AND ci.deleted_at IS NULL
		WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND a.created_at > NOW() - INTERVAL '%d days'
	`, days)
	if len(whereConditions) > 0 {
		baseQuery += " AND " + strings.Join(whereConditions, " AND ")
	}
	groupByClause := " GROUP BY a.id"
	if len(havingConditions) > 0 {
		baseQuery += groupByClause + " HAVING " + strings.Join(havingConditions, " AND ")
		baseQuery = fmt.Sprintf(`SELECT COUNT(*) FROM (%s) as filtered_assets`, baseQuery)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var count int
	// RLS-scoped read over network_assets / crypto_implementations — wrapped in WithTenantTx.
	if err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.GetContext(ctx, &count, baseQuery, args...)
	}); err != nil {
		log.Printf("[ERROR] GetRecentAssetsCount - Query failed: %v, tenantID: %v, days: %d", err, tenantID, days)
		return 0, fmt.Errorf("failed to get recent assets count: %w", err)
	}
	return count, nil
}
