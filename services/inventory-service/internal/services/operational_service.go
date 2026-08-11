package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// OperationalService provides location summary, environment drill-down, and remediation queue from materialized views.
type OperationalService struct {
	db *database.DB
}

// NewOperationalService returns a new operational service.
func NewOperationalService(db *database.DB) *OperationalService {
	return &OperationalService{db: db}
}

// GetLocationSummaries returns all rows from mv_location_finding_summary for the tenant (all locations × environments).
func (s *OperationalService) GetLocationSummaries(tenantID uuid.UUID) ([]models.LocationFindingSummaryRow, error) {
	var rows []models.LocationFindingSummaryRow
	err := s.db.Select(&rows, `
		SELECT location_id, tenant_id, location_name, location_type, full_path, environment,
			asset_count, crypto_config_count, certificate_count,
			critical_findings, high_findings, medium_findings, low_findings,
			expiring_certs_30d, expired_certs
		FROM mv_location_finding_summary
		WHERE tenant_id = $1
		ORDER BY location_name, environment
	`, tenantID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return rows, nil
}

// GetLocationEnvironments returns environment-level stats for a single location (from mv_location_finding_summary).
func (s *OperationalService) GetLocationEnvironments(tenantID, locationID uuid.UUID) ([]models.EnvironmentSummary, error) {
	var rows []models.LocationFindingSummaryRow
	err := s.db.Select(&rows, `
		SELECT location_id, tenant_id, location_name, location_type, full_path, environment,
			asset_count, crypto_config_count, certificate_count,
			critical_findings, high_findings, medium_findings, low_findings,
			expiring_certs_30d, expired_certs
		FROM mv_location_finding_summary
		WHERE tenant_id = $1 AND location_id = $2
		ORDER BY environment
	`, tenantID, locationID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	out := make([]models.EnvironmentSummary, len(rows))
	for i := range rows {
		out[i] = models.EnvironmentSummary{
			Environment:       rows[i].Environment,
			AssetCount:        rows[i].AssetCount,
			CryptoConfigCount: rows[i].CryptoConfigCount,
			CertificateCount:  rows[i].CertificateCount,
			CriticalFindings:  rows[i].CriticalFindings,
			HighFindings:      rows[i].HighFindings,
			MediumFindings:    rows[i].MediumFindings,
			LowFindings:       rows[i].LowFindings,
			ExpiringCerts30D:  rows[i].ExpiringCerts30D,
			ExpiredCerts:      rows[i].ExpiredCerts,
		}
	}
	return out, nil
}

// GetEnvironmentAssets returns assets for a given location and environment (from network_assets).
// Uses explicit column list and tags/metadata as text so JSONB scans correctly into models.Asset.
func (s *OperationalService) GetEnvironmentAssets(tenantID, locationID uuid.UUID, environment string, page, pageSize int) ([]models.Asset, int, error) {
	if pageSize <= 0 {
		pageSize = 20
	}
	if page <= 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	query := `
		SELECT
			a.id, a.tenant_id, a.hostname, a.ip_address, a.port, a.asset_type,
			a.operating_system, a.environment::text, a.business_unit, a.owner_email,
			a.description, a.tags::text, a.metadata::text, a.asset_ownership, a.asset_status,
			a.first_discovered_at, a.last_seen_at,
			a.created_at, a.updated_at, a.deleted_at,
			a.location_id, a.network_segment_id, ns.name AS network_segment_name,
			a.service_name, a.service_version,
			a.service_confidence, a.service_identification_method,
			a.risk_score, a.risk_level
		FROM network_assets a
		LEFT JOIN network_segments ns ON ns.id = a.network_segment_id
		WHERE a.tenant_id = $1 AND a.location_id = $2 AND a.deleted_at IS NULL
		  AND (a.environment::text = $3 OR ($3 = 'unknown' AND a.environment IS NULL))
		ORDER BY a.risk_level DESC NULLS LAST, a.last_seen_at DESC
		LIMIT $4 OFFSET $5
	`

	var total int
	var assets []models.Asset
	// RLS-scoped reads over network_assets (JOIN network_segments) — count + page in one tenant tx.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		if e := tx.QueryRow(`
		SELECT COUNT(*) FROM network_assets
		WHERE tenant_id = $1 AND location_id = $2 AND deleted_at IS NULL
		  AND (environment::text = $3 OR ($3 = 'unknown' AND environment IS NULL))
	`, tenantID, locationID, environment).Scan(&total); e != nil {
			return e
		}

		rows, e := tx.Queryx(query, tenantID, locationID, environment, pageSize, offset)
		if e != nil {
			if e == sql.ErrNoRows {
				return nil
			}
			return e
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var asset models.Asset
			var tagsText, metadataText string
			if e := rows.Scan(
				&asset.ID, &asset.TenantID, &asset.Hostname, &asset.IPAddress, &asset.Port,
				&asset.AssetType, &asset.OperatingSystem, &asset.Environment, &asset.BusinessUnit,
				&asset.OwnerEmail, &asset.Description, &tagsText, &metadataText, &asset.AssetOwnership, &asset.AssetStatus,
				&asset.FirstDiscoveredAt, &asset.LastSeenAt, &asset.CreatedAt, &asset.UpdatedAt,
				&asset.DeletedAt, &asset.LocationID, &asset.NetworkSegmentID, &asset.NetworkSegmentName, &asset.ServiceName, &asset.ServiceVersion,
				&asset.ServiceConfidence, &asset.ServiceIdentificationMethod,
				&asset.RiskScore, &asset.RiskLevel,
			); e != nil {
				return e
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
			assets = append(assets, asset)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}
	return assets, total, nil
}

// GetRemediationQueue returns rows from mv_remediation_queue with optional filters and pagination.
func (s *OperationalService) GetRemediationQueue(tenantID uuid.UUID, filters models.RemediationQueueFilters) ([]models.RemediationQueueRow, int, error) {
	if filters.PageSize <= 0 {
		filters.PageSize = 50
	}
	if filters.Page <= 0 {
		filters.Page = 1
	}
	offset := (filters.Page - 1) * filters.PageSize

	baseQuery := `FROM mv_remediation_queue WHERE tenant_id = $1`
	args := []interface{}{tenantID}
	n := 2
	if filters.Severity != nil && *filters.Severity != "" {
		baseQuery += fmt.Sprintf(` AND severity = $%d`, n)
		args = append(args, *filters.Severity)
		n++
	}
	if filters.FindingType != nil && *filters.FindingType != "" {
		baseQuery += fmt.Sprintf(` AND finding_type = $%d`, n)
		args = append(args, *filters.FindingType)
		n++
	}
	if filters.Environment != nil && *filters.Environment != "" {
		baseQuery += fmt.Sprintf(` AND environment = $%d`, n)
		args = append(args, *filters.Environment)
		n++
	}

	var total int
	countQuery := `SELECT COUNT(*) ` + baseQuery
	err := s.db.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	selQuery := `SELECT tenant_id, finding_type, severity, asset_id, asset_hostname, asset_ip, asset_port,
		location_name, location_full_path, environment, service_name, certificate_id, crypto_implementation_id, detail_text, created_at ` +
		baseQuery + ` ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, created_at DESC`
	args = append(args, filters.PageSize, offset)
	selQuery += fmt.Sprintf(` LIMIT $%d OFFSET $%d`, n, n+1)

	var rows []models.RemediationQueueRow
	err = s.db.Select(&rows, selQuery, args...)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, total, nil
		}
		return nil, 0, err
	}
	return rows, total, nil
}

// GetRemediationQueueStats returns aggregate counts by severity and finding_type from mv_remediation_queue.
func (s *OperationalService) GetRemediationQueueStats(tenantID uuid.UUID) (bySeverity map[string]int, byFindingType map[string]int, total int, err error) {
	bySeverity = make(map[string]int)
	byFindingType = make(map[string]int)
	var rows []struct {
		Severity    string `db:"severity"`
		FindingType string `db:"finding_type"`
	}
	err = s.db.Select(&rows, `SELECT severity, finding_type FROM mv_remediation_queue WHERE tenant_id = $1`, tenantID)
	if err != nil {
		if err == sql.ErrNoRows {
			return bySeverity, byFindingType, 0, nil
		}
		return nil, nil, 0, err
	}
	for _, r := range rows {
		total++
		bySeverity[r.Severity]++
		byFindingType[r.FindingType]++
	}
	return bySeverity, byFindingType, total, nil
}
