package services

// Staleness is an ASSET property; re-validation is an ENDPOINT one.
//
// "Not seen for N days" is answered from `assets.last_seen_at` alone — the host
// is the thing that went quiet, and an endpoint of it going quiet is a
// different, narrower fact. There is deliberately no COALESCE onto an
// endpoint's last_seen: an asset whose only endpoint was retired yesterday has
// not been seen since the host was, and reading the endpoint would report it as
// fresh. Rescan and revalidate act on the endpoints, which is where a socket to
// probe exists; the row shows its primary endpoint so a person can see what
// will be probed.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	invevents "github.com/vistasecurity/vistaplatform/inventory-service/internal/events"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

type AssetLifecycleService struct {
	db *database.DB
	// events is optional. Without it archiving still happens and is still
	// recorded in history; a downstream cache just learns about it on its next
	// read instead of immediately.
	events *EventPublisherService
}

func NewAssetLifecycleService(db *database.DB) *AssetLifecycleService {
	return &AssetLifecycleService{
		db: db,
	}
}

// SetEventPublisher wires the lifecycle publisher so archiving emits
// `inventory.lifecycle.asset.archived`.
func (s *AssetLifecycleService) SetEventPublisher(p *EventPublisherService) {
	s.events = p
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

// staleDetectionBatch caps one sweep of DetectStaleAssets. See the LIMIT in its
// query for why it is a cap rather than paging.
const staleDetectionBatch = 5000

// DetectStaleAssets finds assets that exceed stale thresholds
func (s *AssetLifecycleService) DetectStaleAssets(tenantID uuid.UUID) ([]models.StaleAsset, error) {
	policy, err := s.GetLifecyclePolicy(tenantID)
	if err != nil {
		return nil, err
	}

	warningThreshold := time.Now().AddDate(0, 0, -policy.StaleWarningDays)
	archivedThreshold := time.Now().AddDate(0, 0, -policy.StaleArchivedDays)

	// The risk score is READ off the asset, not recomputed. It used to be a
	// LATERAL `MAX(ci.risk_score)` over the asset's live configurations, which
	// is a second opinion about a number `recomputeAssetRisk` already persists —
	// and the stale list is exactly where the two diverge, because a stale
	// asset's configurations are the ones nobody is still measuring.
	query := `
		SELECT
			a.id, a.tenant_id, a.hostname, host(a.primary_address), ep.port, a.class_key,
			` + assetOperatingSystemSQL + `, a.environment, a.business_unit, a.owner_email,
			a.description, a.tags::text, a.metadata::text, a.asset_ownership, a.asset_status,
			a.first_discovered_at, a.last_seen_at, a.created_at, a.updated_at,
			a.deleted_at,
			a.risk_score,
			` + models.RiskLevelCaseSQL("a.risk_score") + ` as risk_level,
			a.stale_status,
			EXTRACT(EPOCH FROM (NOW() - a.last_seen_at)) / 86400 as days_since_last_seen
		FROM assets a` + primaryEndpointJoin + `
		WHERE a.tenant_id = $1
		  AND a.deleted_at IS NULL
		  AND a.asset_status = 'monitoring'
		  AND a.last_seen_at < $2
		-- a.id is the tiebreaker: last_seen_at ties by the thousand on a tenant
		-- whose sensor stopped reporting, and an unstable order under a LIMIT
		-- means a different slice on every sweep.
		ORDER BY a.last_seen_at ASC, a.id
		-- BOUNDED. This ran unbounded, materialising every stale asset in the
		-- tenant into memory — and the tenants where this matters are exactly
		-- the ones with the most stale assets, since "stale" is what happens
		-- when a collector stops reporting for a whole segment. A sweep that
		-- has to allocate a hundred thousand rows to decide which to warn about
		-- is a sweep that takes the service down with it.
		--
		-- A cap, not paging: the caller is a periodic job that re-runs, so the
		-- overflow is picked up on the next sweep, and last_seen_at ASC means
		-- the ones it takes first are the ones that have been stale longest.
		LIMIT ` + strconv.Itoa(staleDetectionBatch) + `
	`

	// RLS-scoped read over assets / crypto_implementations (with
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
			var operatingSystem *string
			var ep models.Endpoint

			// tags/metadata are selected as ::text and unmarshalled here: lib/pq
			// cannot scan raw jsonb into a bare map[string]interface{} (it would
			// fail with "unsupported Scan, storing []uint8 into *map"). This is
			// the same pattern the other asset queries use (see asset_queries.go).
			if e := rows.Scan(
				&asset.ID, &asset.TenantID, &asset.Hostname, &asset.PrimaryAddress, &ep.Port,
				&asset.ClassKey, &operatingSystem, &asset.Environment,
				&asset.BusinessUnit, &asset.OwnerEmail, &asset.Description,
				&tagsText, &metadataText, &asset.AssetOwnership, &asset.AssetStatus,
				&asset.FirstDiscoveredAt, &asset.LastSeenAt, &asset.CreatedAt,
				&asset.UpdatedAt, &asset.DeletedAt, &asset.RiskScore, &asset.RiskLevel,
				&staleStatus, &daysSinceLastSeen,
			); e != nil {
				return fmt.Errorf("failed to scan stale asset: %w", e)
			}
			setAssetOperatingSystem(&asset.Asset, operatingSystem)
			attachPrimaryEndpoint(&asset.Asset, ep)
			normalizeAssetCollections(&asset.Asset)
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
func (s *AssetLifecycleService) UpdateStaleStatus(tenantID uuid.UUID, assetIDs []uuid.UUID, status string, actorUserID uuid.UUID) error {
	if len(assetIDs) == 0 {
		return nil
	}

	query := `
		UPDATE assets
		SET stale_status = $1, updated_at = NOW()
		WHERE tenant_id = $2
		  AND id = ANY($3)
		  AND deleted_at IS NULL
	`

	// RLS-scoped write over assets (tenant_isolation policy).
	//
	// The history row goes in the SAME transaction. Archiving is one of the
	// three decisions a person makes about an asset that is already in
	// inventory, and — like approving and denying — it wrote nothing to the
	// asset's timeline: the asset simply stopped appearing in lists, with no
	// entry saying who retired it or when.
	var moved int64
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		res, e := tx.Exec(query, status, tenantID, pq.Array(assetIDs))
		if e != nil {
			return e
		}
		moved, e = res.RowsAffected()
		if e != nil {
			return e
		}
		if status != "archived" {
			// `stale` and `active` are the staleness job's own bookkeeping,
			// re-asserted on every sweep. Recording those would bury the
			// decisions in noise, which is the mistake setAssetStatus made.
			return nil
		}
		for _, assetID := range assetIDs {
			s.recordArchive(tx, tenantID, assetID, actorUserID)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to update stale status: %w", err)
	}

	if status == "archived" && moved > 0 && s.events != nil {
		decided := ""
		if actorUserID != uuid.Nil {
			decided = actorUserID.String()
		}
		if e := s.events.PublishAssetLifecycle(context.Background(), tenantID,
			invevents.EventTypeAssetArchived,
			&invevents.AssetLifecyclePayload{AssetIDs: assetIDs, Status: "archived", DecidedBy: decided},
			"lifecycle"); e != nil {
			log.Printf("[AssetLifecycleService] archive committed but the event was not published: %v", e)
		}
	}
	return nil
}

// recordArchive appends the `archived` history entry, on the caller's
// transaction. It logs rather than fails: the archive already happened, and
// reporting a failure that did not occur is worse than a lost entry — which is
// itself logged loudly.
func (s *AssetLifecycleService) recordArchive(tx *sqlx.Tx, tenantID, assetID, actor uuid.UUID) {
	var actorArg any
	if actor != uuid.Nil {
		actorArg = actor
	}
	if _, err := tx.Exec(`
		INSERT INTO asset_history (asset_id, tenant_id, actor_user_id, source, action, changes_json)
		VALUES ($1, $2, $3, 'lifecycle', 'archived', $4::jsonb)`,
		assetID, tenantID, actorArg, `{"stale_status":"archived","source_kind":"declared"}`); err != nil {
		log.Printf("[AssetLifecycleService] history: recording archived for asset %s failed: %v", assetID, err)
	}
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

	// The caller's `?query=`, compiled by the SAME translator the asset list
	// compiles through, against the same catalogue and the same alias.
	//
	// CompileAssetQuery rather than buildAssetWhere, deliberately: buildAssetWhere
	// also synthesises the list's default `status:monitoring` term when no
	// status filter was given, and a stale list that quietly excluded archived
	// assets would answer a different question from the one the page asks. This
	// endpoint has no legacy per-field filters for buildAssetWhere to translate,
	// so what is left of it IS this call.
	if q := strings.TrimSpace(filters.Query); q != "" {
		compiled, err := CompileAssetQuery(q, QueryTargetAsset, argIdx, assetQueryAlias)
		if err != nil {
			return nil, 0, err
		}
		whereClauses = append(whereClauses, "("+compiled.Where+")")
		args = append(args, compiled.Args...)
		argIdx += len(compiled.Args)
	}

	whereClause := "WHERE " + strings.Join(whereClauses, " AND ")

	// Count query
	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM assets a
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
		"ip_address":          "a.primary_address",
		"asset_type":          "a.class_key",
		"environment":         "a.environment",
		"operating_system":    "a.attributes->>'operating_system'",
		"business_unit":       "a.business_unit",
		"owner_email":         "a.owner_email",
		"first_discovered_at": "a.first_discovered_at",
		"last_seen_at":        "a.last_seen_at",
		"created_at":          "a.created_at",
		"updated_at":          "a.updated_at",
		"risk_score":          "a.risk_score",
		"risk_level":          "a.risk_score",
	}
	safeSortBy, ok := validSortColumns[sortBy]
	if !ok {
		safeSortBy = "a.last_seen_at"
	}
	if sortOrder != "ASC" && sortOrder != "asc" {
		sortOrder = "DESC"
	}

	// The persisted per-asset rollup, as in DetectStaleAssets above.
	query := fmt.Sprintf(`
		SELECT
			a.id, a.tenant_id, a.hostname, host(a.primary_address), ep.port, a.class_key,
			`+assetOperatingSystemSQL+`, a.environment, a.business_unit, a.owner_email,
			a.description, a.tags::text, a.metadata::text, a.asset_ownership, a.asset_status,
			a.first_discovered_at, a.last_seen_at, a.created_at, a.updated_at,
			a.deleted_at,
			a.risk_score,
			`+models.RiskLevelCaseSQL("a.risk_score")+` as risk_level,
			a.stale_status,
			EXTRACT(EPOCH FROM (NOW() - a.last_seen_at)) / 86400 as days_since_last_seen
		FROM assets a`+primaryEndpointJoin+`
		%s
		-- a.id is the tiebreaker, and it is not cosmetic. Every sort column
		-- here has ties by the thousand (last_seen_at to the second,
		-- environment, class_key), and Postgres gives no stable order within a
		-- tie — so with LIMIT/OFFSET paging the same asset could appear on two
		-- pages and another on none, differently on every request.
		ORDER BY %s %s, a.id
		LIMIT $%d OFFSET $%d
	`, whereClause, safeSortBy, sortOrder, argIdx, argIdx+1)

	args = append(args, pageSize, offset)

	// RLS-scoped reads over assets / crypto_implementations (with
	// the tenant_isolation policy) — count + page run together in one tenant tx.
	var total int
	var staleAssets []models.StaleAsset
	// The caller's `?query=` is compiled into whereClause above, so this read
	// carries a tenant-supplied predicate and takes the query-language
	// statement ceiling (query.StatementTimeout).
	err := database.WithTenantTxTimeout(context.Background(), s.db, tenantID, assetQueryStatementTimeout, func(tx *sqlx.Tx) error {
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
			var operatingSystem *string
			var ep models.Endpoint

			// tags/metadata as ::text + unmarshal — lib/pq cannot scan raw jsonb
			// into a bare map[string]interface{}. See DetectStaleAssets above.
			if e := rows.Scan(
				&asset.ID, &asset.TenantID, &asset.Hostname, &asset.PrimaryAddress, &ep.Port,
				&asset.ClassKey, &operatingSystem, &asset.Environment,
				&asset.BusinessUnit, &asset.OwnerEmail, &asset.Description,
				&tagsText, &metadataText, &asset.AssetOwnership, &asset.AssetStatus,
				&asset.FirstDiscoveredAt, &asset.LastSeenAt, &asset.CreatedAt,
				&asset.UpdatedAt, &asset.DeletedAt, &asset.RiskScore, &asset.RiskLevel,
				&staleStatus, &daysSinceLastSeen,
			); e != nil {
				return fmt.Errorf("failed to scan stale asset: %w", e)
			}
			setAssetOperatingSystem(&asset.Asset, operatingSystem)
			attachPrimaryEndpoint(&asset.Asset, ep)
			normalizeAssetCollections(&asset.Asset)
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
		UPDATE assets
		SET stale_status = NULL, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
	`

	// RLS-scoped write over assets (tenant_isolation policy).
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(query, tenantID, assetID)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to clear stale status: %w", err)
	}

	return nil
}
