package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

type AssetLifecycleService struct {
	db *database.DB
}

func NewAssetLifecycleService(db *database.DB) *AssetLifecycleService {
	return &AssetLifecycleService{
		db: db,
	}
}

// GetLifecyclePolicy retrieves the lifecycle policy for a tenant
func (s *AssetLifecycleService) GetLifecyclePolicy(tenantID uuid.UUID) (*models.AssetLifecyclePolicy, error) {
	var policy models.AssetLifecyclePolicy
	var scheduleJSON []byte

	query := `
		SELECT id, tenant_id, stale_warning_days, stale_archived_days,
		       auto_archive_enabled, notifications_enabled, revalidation_schedule,
		       created_at, updated_at
		FROM asset_lifecycle_policies
		WHERE tenant_id = $1
	`

	// RLS-scoped read over asset_lifecycle_policies — run inside WithTenantTx so
	// app.tenant_id is set for the policy. WithTenantTx returns fn's error
	// verbatim, so the sql.ErrNoRows check below still works.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(query, tenantID).Scan(
			&policy.ID, &policy.TenantID, &policy.StaleWarningDays, &policy.StaleArchivedDays,
			&policy.AutoArchiveEnabled, &policy.NotificationsEnabled, &scheduleJSON,
			&policy.CreatedAt, &policy.UpdatedAt,
		)
	})

	if err == sql.ErrNoRows {
		// Return default policy if none exists
		return &models.AssetLifecyclePolicy{
			ID:                   uuid.New(),
			TenantID:             tenantID,
			StaleWarningDays:     30,
			StaleArchivedDays:    60,
			AutoArchiveEnabled:   true,
			NotificationsEnabled: true,
			RevalidationSchedule: map[string]interface{}{
				"enabled":        false,
				"interval_hours": 168,
			},
		}, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get lifecycle policy: %w", err)
	}

	// Parse revalidation_schedule JSONB
	if len(scheduleJSON) > 0 {
		if err := json.Unmarshal(scheduleJSON, &policy.RevalidationSchedule); err != nil {
			// Use default if parsing fails
			policy.RevalidationSchedule = map[string]interface{}{
				"enabled":        false,
				"interval_hours": 168,
			}
		}
	} else {
		policy.RevalidationSchedule = map[string]interface{}{
			"enabled":        false,
			"interval_hours": 168,
		}
	}

	return &policy, nil
}

// UpdateLifecyclePolicy updates or creates a lifecycle policy for a tenant
func (s *AssetLifecycleService) UpdateLifecyclePolicy(tenantID uuid.UUID, input models.AssetLifecyclePolicyInput) (*models.AssetLifecyclePolicy, error) {
	policy, err := s.GetLifecyclePolicy(tenantID)
	if err != nil {
		return nil, err
	}

	// Update fields if provided
	if input.StaleWarningDays != nil {
		policy.StaleWarningDays = *input.StaleWarningDays
	}
	if input.StaleArchivedDays != nil {
		policy.StaleArchivedDays = *input.StaleArchivedDays
	}
	if input.AutoArchiveEnabled != nil {
		policy.AutoArchiveEnabled = *input.AutoArchiveEnabled
	}
	if input.NotificationsEnabled != nil {
		policy.NotificationsEnabled = *input.NotificationsEnabled
	}
	if input.RevalidationSchedule != nil {
		policy.RevalidationSchedule = *input.RevalidationSchedule
	}

	// Serialize revalidation_schedule
	scheduleJSON, err := json.Marshal(policy.RevalidationSchedule)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal revalidation schedule: %w", err)
	}

	// Upsert policy
	query := `
		INSERT INTO asset_lifecycle_policies (
			id, tenant_id, stale_warning_days, stale_archived_days,
			auto_archive_enabled, notifications_enabled, revalidation_schedule,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, NOW(), NOW()
		)
		ON CONFLICT (tenant_id) DO UPDATE SET
			stale_warning_days = EXCLUDED.stale_warning_days,
			stale_archived_days = EXCLUDED.stale_archived_days,
			auto_archive_enabled = EXCLUDED.auto_archive_enabled,
			notifications_enabled = EXCLUDED.notifications_enabled,
			revalidation_schedule = EXCLUDED.revalidation_schedule,
			updated_at = NOW()
	`

	// RLS-scoped write over asset_lifecycle_policies — WithTenantTx sets
	// app.tenant_id so the upsert satisfies the policy WITH CHECK.
	err = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(query,
			policy.ID, tenantID, policy.StaleWarningDays, policy.StaleArchivedDays,
			policy.AutoArchiveEnabled, policy.NotificationsEnabled, scheduleJSON,
		)
		return e
	})

	if err != nil {
		return nil, fmt.Errorf("failed to update lifecycle policy: %w", err)
	}

	policy.UpdatedAt = time.Now()
	return policy, nil
}

// DetectStaleAssets finds assets that exceed stale thresholds
func (s *AssetLifecycleService) DetectStaleAssets(tenantID uuid.UUID) ([]models.StaleAsset, error) {
	policy, err := s.GetLifecyclePolicy(tenantID)
	if err != nil {
		return nil, err
	}

	warningThreshold := time.Now().AddDate(0, 0, -policy.StaleWarningDays)
	archivedThreshold := time.Now().AddDate(0, 0, -policy.StaleArchivedDays)

	// network_assets is a view over the HASH-partitioned network_assets_partitioned
	// table, which has no declared PRIMARY KEY (partitioning by tenant_id alone
	// prevents a normal single-column PK). Postgres can therefore not infer
	// functional dependency for the other a.* columns from any GROUP BY shape, so
	// "SELECT a.*, MAX(ci.risk_score) ... GROUP BY a.id, a.tenant_id" raises a
	// strict-grouping error on whichever a.* column the planner hits first.
	// A LATERAL subquery scopes the max-risk aggregation to each a row's children
	// without forcing the outer query into a GROUP BY at all.
	query := `
		SELECT
			a.id, a.tenant_id, a.hostname, a.ip_address, a.port, a.asset_type,
			a.operating_system, a.environment, a.business_unit, a.owner_email,
			a.description, a.tags::text, a.metadata::text, a.asset_ownership, a.asset_status,
			a.first_discovered_at, a.last_seen_at, a.created_at, a.updated_at,
			a.deleted_at,
			COALESCE(lat.max_risk, 0) as risk_score,
			` + models.RiskLevelCaseSQL("COALESCE(lat.max_risk, 0)") + ` as risk_level,
			a.stale_status,
			EXTRACT(EPOCH FROM (NOW() - a.last_seen_at)) / 86400 as days_since_last_seen
		FROM network_assets a
		LEFT JOIN LATERAL (
			SELECT MAX(ci.risk_score) AS max_risk
			FROM crypto_implementations ci
			WHERE ci.asset_id = a.id AND ci.deleted_at IS NULL
		) lat ON true
		WHERE a.tenant_id = $1
		  AND a.deleted_at IS NULL
		  AND a.asset_status = 'monitoring'
		  AND a.last_seen_at < $2
		ORDER BY a.last_seen_at ASC
	`

	// RLS-scoped read over network_assets / crypto_implementations (views with
	// the tenant_isolation policy) — run inside WithTenantTx so app.tenant_id is set.
	var staleAssets []models.StaleAsset
	err = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, e := tx.Query(query, tenantID, warningThreshold)
		if e != nil {
			return fmt.Errorf("failed to query stale assets: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var asset models.StaleAsset
			var staleStatus sql.NullString
			var tagsText, metadataText sql.NullString
			var daysSinceLastSeen float64

			// tags/metadata are selected as ::text and unmarshalled here: lib/pq
			// cannot scan raw jsonb into a bare map[string]interface{} (it would
			// fail with "unsupported Scan, storing []uint8 into *map"). This is
			// the same pattern the other asset queries use (see asset_queries.go).
			if e := rows.Scan(
				&asset.ID, &asset.TenantID, &asset.Hostname, &asset.IPAddress, &asset.Port,
				&asset.AssetType, &asset.OperatingSystem, &asset.Environment,
				&asset.BusinessUnit, &asset.OwnerEmail, &asset.Description,
				&tagsText, &metadataText, &asset.AssetOwnership, &asset.AssetStatus,
				&asset.FirstDiscoveredAt, &asset.LastSeenAt, &asset.CreatedAt,
				&asset.UpdatedAt, &asset.DeletedAt, &asset.RiskScore, &asset.RiskLevel,
				&staleStatus, &daysSinceLastSeen,
			); e != nil {
				return fmt.Errorf("failed to scan stale asset: %w", e)
			}
			if tagsText.Valid && tagsText.String != "" {
				_ = json.Unmarshal([]byte(tagsText.String), &asset.Tags)
			}
			if metadataText.Valid && metadataText.String != "" {
				_ = json.Unmarshal([]byte(metadataText.String), &asset.Metadata)
			}

			if staleStatus.Valid {
				status := staleStatus.String
				asset.StaleStatus = &status
			}
			asset.DaysSinceLastSeen = int(daysSinceLastSeen)

			// Determine if should be archived
			if asset.LastSeenAt.Before(archivedThreshold) {
				if asset.StaleStatus == nil || *asset.StaleStatus != "archived" {
					status := "archived"
					asset.StaleStatus = &status
				}
			} else if asset.StaleStatus == nil {
				status := "warning"
				asset.StaleStatus = &status
			}

			staleAssets = append(staleAssets, asset)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return staleAssets, nil
}

// UpdateStaleStatus updates the stale_status for assets
func (s *AssetLifecycleService) UpdateStaleStatus(tenantID uuid.UUID, assetIDs []uuid.UUID, status string) error {
	if len(assetIDs) == 0 {
		return nil
	}

	query := `
		UPDATE network_assets
		SET stale_status = $1, updated_at = NOW()
		WHERE tenant_id = $2
		  AND id = ANY($3)
		  AND deleted_at IS NULL
	`

	// RLS-scoped write over network_assets (view with tenant_isolation policy).
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(query, status, tenantID, pq.Array(assetIDs))
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to update stale status: %w", err)
	}

	return nil
}

// GetStaleAssets retrieves stale assets for display in UI
func (s *AssetLifecycleService) GetStaleAssets(tenantID uuid.UUID, filters models.StaleAssetFilters) ([]models.StaleAsset, int, error) {
	// Build WHERE clause
	whereClauses := []string{"a.tenant_id = $1", "a.deleted_at IS NULL", "a.stale_status IS NOT NULL"}
	args := []interface{}{tenantID}
	argIdx := 2

	if len(filters.StaleStatus) > 0 {
		whereClauses = append(whereClauses, fmt.Sprintf("a.stale_status = ANY($%d)", argIdx))
		args = append(args, pq.Array(filters.StaleStatus))
		argIdx++
	}

	whereClause := "WHERE " + strings.Join(whereClauses, " AND ")

	// Count query
	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM network_assets a
		%s
	`, whereClause)

	// Snapshot the count args before pagination params are appended; the count
	// and the page run together inside one tenant tx below.
	countArgs := append([]interface{}{}, args...)

	// Pagination
	page := filters.Page
	if page < 1 {
		page = 1
	}
	pageSize := filters.PageSize
	if pageSize < 1 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize

	// Sort
	sortBy := filters.SortBy
	if sortBy == "" {
		sortBy = "last_seen_at"
	}
	sortOrder := filters.SortOrder
	if sortOrder == "" {
		sortOrder = "ASC"
	}

	// Whitelist allowed sort columns to prevent SQL injection
	validSortColumns := map[string]string{
		"hostname":            "a.hostname",
		"ip_address":          "a.ip_address",
		"asset_type":          "a.asset_type",
		"environment":         "a.environment",
		"operating_system":    "a.operating_system",
		"business_unit":       "a.business_unit",
		"owner_email":         "a.owner_email",
		"first_discovered_at": "a.first_discovered_at",
		"last_seen_at":        "a.last_seen_at",
		"created_at":          "a.created_at",
		"updated_at":          "a.updated_at",
		"risk_score":          "risk_score",
		"risk_level":          "risk_level",
	}
	safeSortBy, ok := validSortColumns[sortBy]
	if !ok {
		safeSortBy = "a.last_seen_at"
	}
	if sortOrder != "ASC" && sortOrder != "asc" {
		sortOrder = "DESC"
	}

	// LATERAL subquery for max risk_score per asset — see comment on DetectStaleAssets
	// for why a GROUP BY shape can't work here (network_assets_partitioned has no PK).
	query := fmt.Sprintf(`
		SELECT
			a.id, a.tenant_id, a.hostname, a.ip_address, a.port, a.asset_type,
			a.operating_system, a.environment, a.business_unit, a.owner_email,
			a.description, a.tags::text, a.metadata::text, a.asset_ownership, a.asset_status,
			a.first_discovered_at, a.last_seen_at, a.created_at, a.updated_at,
			a.deleted_at,
			COALESCE(lat.max_risk, 0) as risk_score,
			`+models.RiskLevelCaseSQL("COALESCE(lat.max_risk, 0)")+` as risk_level,
			a.stale_status,
			EXTRACT(EPOCH FROM (NOW() - a.last_seen_at)) / 86400 as days_since_last_seen
		FROM network_assets a
		LEFT JOIN LATERAL (
			SELECT MAX(ci.risk_score) AS max_risk
			FROM crypto_implementations ci
			WHERE ci.asset_id = a.id AND ci.deleted_at IS NULL
		) lat ON true
		%s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d
	`, whereClause, safeSortBy, sortOrder, argIdx, argIdx+1)

	args = append(args, pageSize, offset)

	// RLS-scoped reads over network_assets / crypto_implementations (views with
	// the tenant_isolation policy) — count + page run together in one tenant tx.
	var total int
	var staleAssets []models.StaleAsset
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		if e := tx.QueryRow(countQuery, countArgs...).Scan(&total); e != nil {
			return fmt.Errorf("failed to count stale assets: %w", e)
		}

		rows, e := tx.Query(query, args...)
		if e != nil {
			return fmt.Errorf("failed to query stale assets: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var asset models.StaleAsset
			var staleStatus sql.NullString
			var tagsText, metadataText sql.NullString
			var daysSinceLastSeen float64

			// tags/metadata as ::text + unmarshal — lib/pq cannot scan raw jsonb
			// into a bare map[string]interface{}. See DetectStaleAssets above.
			if e := rows.Scan(
				&asset.ID, &asset.TenantID, &asset.Hostname, &asset.IPAddress, &asset.Port,
				&asset.AssetType, &asset.OperatingSystem, &asset.Environment,
				&asset.BusinessUnit, &asset.OwnerEmail, &asset.Description,
				&tagsText, &metadataText, &asset.AssetOwnership, &asset.AssetStatus,
				&asset.FirstDiscoveredAt, &asset.LastSeenAt, &asset.CreatedAt,
				&asset.UpdatedAt, &asset.DeletedAt, &asset.RiskScore, &asset.RiskLevel,
				&staleStatus, &daysSinceLastSeen,
			); e != nil {
				return fmt.Errorf("failed to scan stale asset: %w", e)
			}
			if tagsText.Valid && tagsText.String != "" {
				_ = json.Unmarshal([]byte(tagsText.String), &asset.Tags)
			}
			if metadataText.Valid && metadataText.String != "" {
				_ = json.Unmarshal([]byte(metadataText.String), &asset.Metadata)
			}

			if staleStatus.Valid {
				asset.StaleStatus = &staleStatus.String
			}
			asset.DaysSinceLastSeen = int(daysSinceLastSeen)

			staleAssets = append(staleAssets, asset)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}

	return staleAssets, total, nil
}

// ClearStaleStatus clears stale_status when asset is seen again
func (s *AssetLifecycleService) ClearStaleStatus(tenantID uuid.UUID, assetID uuid.UUID) error {
	query := `
		UPDATE network_assets
		SET stale_status = NULL, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
	`

	// RLS-scoped write over network_assets (view with tenant_isolation policy).
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(query, tenantID, assetID)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to clear stale status: %w", err)
	}

	return nil
}
