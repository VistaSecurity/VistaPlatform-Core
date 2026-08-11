package services

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

type RevalidationService struct {
	db               *database.DB
	discoveryService *DiscoveryService
	assetService     *AssetService
	lifecycleService *AssetLifecycleService
}

func NewRevalidationService(
	db *database.DB,
	discoveryService *DiscoveryService,
	assetService *AssetService,
	lifecycleService *AssetLifecycleService,
) *RevalidationService {
	return &RevalidationService{
		db:               db,
		discoveryService: discoveryService,
		assetService:     assetService,
		lifecycleService: lifecycleService,
	}
}

// CreateRevalidationJob creates a discovery job targeting specific assets for re-validation
func (s *RevalidationService) CreateRevalidationJob(tenantID uuid.UUID, userID uuid.UUID, assetIDs []uuid.UUID, authHeader string) (string, error) {
	if len(assetIDs) == 0 {
		return "", fmt.Errorf("at least one asset ID is required")
	}

	// Fetch assets to get their IP addresses/hostnames
	query := `
		SELECT id, hostname, ip_address, port
		FROM network_assets
		WHERE tenant_id = $1
		  AND id = ANY($2)
		  AND deleted_at IS NULL
	`

	// RLS-scoped read over network_assets.
	var targets []string
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, e := tx.Query(query, tenantID, pq.Array(assetIDs))
		if e != nil {
			return fmt.Errorf("failed to query assets: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var id uuid.UUID
			var hostname, ipAddress sql.NullString
			var port sql.NullInt64

			if e := rows.Scan(&id, &hostname, &ipAddress, &port); e != nil {
				continue
			}

			// Prefer IP address, fallback to hostname
			if ipAddress.Valid && ipAddress.String != "" {
				target := ipAddress.String
				if port.Valid {
					target = fmt.Sprintf("%s:%d", target, port.Int64)
				}
				targets = append(targets, target)
			} else if hostname.Valid && hostname.String != "" {
				target := hostname.String
				if port.Valid {
					target = fmt.Sprintf("%s:%d", target, port.Int64)
				}
				targets = append(targets, target)
			}
		}
		return rows.Err()
	})
	if err != nil {
		return "", err
	}

	if len(targets) == 0 {
		return "", fmt.Errorf("no valid targets found for re-validation")
	}

	// Create discovery job input
	jobInput := models.CreateDiscoveryJobInput{
		Targets:       targets,
		ExecutionMode: "async",
		Protocols:     []string{"TLS", "SSH"}, // Common protocols for re-validation
		Ports:         []int{443, 22, 8443},   // Common ports
	}

	// Create discovery job via discovery service
	job, err := s.discoveryService.CreateJob(
		tenantID.String(),
		userID.String(),
		jobInput,
		authHeader,
	)

	if err != nil {
		return "", fmt.Errorf("failed to create re-validation job: %w", err)
	}

	return job.ID, nil
}

// CreateActiveScanJob dispatches an on-demand Active Scan () for the given
// assets. Unlike stale revalidation, it (1) approves the targeted assets
// (pending_approval → monitoring) so the discovery pipeline extracts their crypto
// instead of deferring it, (2) stamps scan freshness (last_scanned_at / last_scan_status),
// and (3) dispatches an active TLS probe whose findings are routed into sensor_discoveries
// (result_sink option) — so the normal discovery-processor → IngestFindings pipeline
// matches each asset by IP/port and catalogs its certificates and cipher configs.
// Returns the dispatched job ID and the number of assets actually scanned.
func (s *RevalidationService) CreateActiveScanJob(tenantID uuid.UUID, userID uuid.UUID, assetIDs []uuid.UUID, authHeader string) (string, int, error) {
	if len(assetIDs) == 0 {
		return "", 0, fmt.Errorf("at least one asset ID is required")
	}

	// Resolve targets (prefer IP:port, fall back to hostname:port) and record which
	// assets we will actually scan.
	query := `
		SELECT id, hostname, ip_address, port
		FROM network_assets
		WHERE tenant_id = $1
		  AND id = ANY($2)
		  AND deleted_at IS NULL
	`
	// RLS-scoped read over network_assets.
	var targets []string
	var scanned []uuid.UUID
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, e := tx.Query(query, tenantID, pq.Array(assetIDs))
		if e != nil {
			return fmt.Errorf("failed to query assets: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var id uuid.UUID
			var hostname, ipAddress sql.NullString
			var port sql.NullInt64
			if e := rows.Scan(&id, &hostname, &ipAddress, &port); e != nil {
				continue
			}
			var target string
			switch {
			case ipAddress.Valid && ipAddress.String != "":
				target = ipAddress.String
			case hostname.Valid && hostname.String != "":
				target = hostname.String
			default:
				continue // no addressable target — skip
			}
			if port.Valid && port.Int64 > 0 {
				target = fmt.Sprintf("%s:%d", target, port.Int64)
			}
			targets = append(targets, target)
			scanned = append(scanned, id)
		}
		return rows.Err()
	})
	if err != nil {
		return "", 0, err
	}
	if len(targets) == 0 {
		return "", 0, fmt.Errorf("no valid scan targets found (assets need an IP or hostname)")
	}

	// Approve + stamp freshness BEFORE dispatch. Approving (pending_approval → monitoring)
	// is required or the pipeline defers the scanned crypto; stamping makes the asset drop
	// out of the "unscanned" coverage set immediately. Idempotent for already-monitoring assets.
	// RLS-scoped write over network_assets_partitioned.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(`
			UPDATE network_assets_partitioned
			SET asset_status     = 'monitoring',
			    last_scanned_at  = now(),
			    last_scan_status = 'scanning',
			    updated_at       = now()
			WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL
		`, tenantID, pq.Array(scanned))
		return e
	}); err != nil {
		return "", 0, fmt.Errorf("failed to mark assets for scanning: %w", err)
	}

	// Dispatch an active TLS probe. result_sink routes cluster-sensor findings into
	// sensor_discoveries so the asset pipeline catalogs the crypto (v1 = TLS only).
	jobInput := models.CreateDiscoveryJobInput{
		Targets:       targets,
		ExecutionMode: "async",
		Protocols:     []string{"TLS"},
		Ports:         []int{443, 8443},
		Options: map[string]interface{}{
			"result_sink": "sensor_discoveries",
			"active_scan": true,
		},
	}
	job, err := s.discoveryService.CreateJob(tenantID.String(), userID.String(), jobInput, authHeader)
	if err != nil {
		// Best-effort: mark the stamp as failed so the UI doesn't show a stuck "scanning".
		// RLS-scoped write over network_assets_partitioned.
		_ = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
			_, e := tx.Exec(`UPDATE network_assets_partitioned SET last_scan_status = 'failed', updated_at = now()
				WHERE tenant_id = $1 AND id = ANY($2)`, tenantID, pq.Array(scanned))
			return e
		})
		return "", 0, fmt.Errorf("failed to dispatch active scan: %w", err)
	}
	return job.ID, len(scanned), nil
}

// RevalidateStaleAssets creates a re-validation job for all stale assets
func (s *RevalidationService) RevalidateStaleAssets(tenantID uuid.UUID, userID uuid.UUID, authHeader string) (string, error) {
	// Get all stale assets
	staleAssets, err := s.lifecycleService.DetectStaleAssets(tenantID)
	if err != nil {
		return "", fmt.Errorf("failed to detect stale assets: %w", err)
	}

	if len(staleAssets) == 0 {
		return "", fmt.Errorf("no stale assets found")
	}

	// Extract asset IDs
	assetIDs := make([]uuid.UUID, len(staleAssets))
	for i, asset := range staleAssets {
		assetIDs[i] = asset.ID
	}

	return s.CreateRevalidationJob(tenantID, userID, assetIDs, authHeader)
}

// ProcessRevalidationResults processes discovery job results and updates last_seen_at
func (s *RevalidationService) ProcessRevalidationResults(tenantID uuid.UUID, jobID string) error {
	// Get job results from discovery service
	// This would need to be implemented in discovery_service.go
	// For now, we'll assume the discovery service has a method to get results

	// The actual processing would:
	// 1. Get discovery job results
	// 2. Match results to existing assets by IP/hostname/port
	// 3. Update last_seen_at for found assets
	// 4. Clear stale_status for found assets
	// 5. Keep stale_status for assets not found

	// This is a placeholder - actual implementation would depend on discovery service API
	return fmt.Errorf("not implemented: requires discovery service result retrieval")
}
