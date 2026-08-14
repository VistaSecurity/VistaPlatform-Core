package services

import (
	"context"
	"database/sql"
	"fmt"
	"log"

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

// resolveActiveScanAssets loads the requested assets and turns each into probe
// coordinates: a BARE host (never "host:port" — see active_scan_plan.go), its
// port, and the protocols already recorded against its crypto configurations.
// Assets with neither an IP nor a hostname are omitted, so the caller can tell
// which assets it is actually able to scan.
func (s *RevalidationService) resolveActiveScanAssets(tenantID uuid.UUID, assetIDs []uuid.UUID) ([]activeScanAsset, error) {
	const assetQuery = `
		SELECT id, hostname, ip_address, port
		FROM network_assets
		WHERE tenant_id = $1
		  AND id = ANY($2)
		  AND deleted_at IS NULL
	`
	// Protocols already observed on this asset — the best signal for what to
	// probe it with (an SSH host must not be probed for TLS only).
	const protocolQuery = `
		SELECT asset_id, protocol
		FROM crypto_implementations
		WHERE tenant_id = $1
		  AND asset_id = ANY($2)
		  AND deleted_at IS NULL
		  AND protocol IS NOT NULL
	`

	var assets []activeScanAsset
	// RLS-scoped reads over network_assets / crypto_implementations.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		protocols := make(map[uuid.UUID][]string)
		protoRows, e := tx.Query(protocolQuery, tenantID, pq.Array(assetIDs))
		if e != nil {
			return fmt.Errorf("failed to query crypto configurations: %w", e)
		}
		for protoRows.Next() {
			var assetID uuid.UUID
			var protocol sql.NullString
			if e := protoRows.Scan(&assetID, &protocol); e != nil {
				continue
			}
			if protocol.Valid && protocol.String != "" {
				protocols[assetID] = append(protocols[assetID], protocol.String)
			}
		}
		if e := protoRows.Err(); e != nil {
			_ = protoRows.Close()
			return e
		}
		_ = protoRows.Close()

		rows, e := tx.Query(assetQuery, tenantID, pq.Array(assetIDs))
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

			// Prefer IP address, fall back to hostname. Either way it stays a
			// bare host — the port travels in the job's Ports field.
			var host string
			switch {
			case ipAddress.Valid && ipAddress.String != "":
				host = ipAddress.String
			case hostname.Valid && hostname.String != "":
				host = hostname.String
			default:
				continue // no addressable target — skip
			}

			asset := activeScanAsset{id: id, host: host, configProtocols: protocols[id]}
			if port.Valid && port.Int64 > 0 {
				asset.port = int(port.Int64)
			}
			assets = append(assets, asset)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return assets, nil
}

// CreateRevalidationJob creates a discovery job targeting specific assets for re-validation
func (s *RevalidationService) CreateRevalidationJob(tenantID uuid.UUID, userID uuid.UUID, assetIDs []uuid.UUID, authHeader string) (string, error) {
	if len(assetIDs) == 0 {
		return "", fmt.Errorf("at least one asset ID is required")
	}

	assets, err := s.resolveActiveScanAssets(tenantID, assetIDs)
	if err != nil {
		return "", err
	}
	batches := planActiveScanBatches(assets)
	if len(batches) == 0 {
		return "", fmt.Errorf("no valid targets found for re-validation")
	}

	var firstJobID string
	var failed int
	var lastErr error
	for _, batch := range batches {
		job, e := s.discoveryService.CreateJob(
			tenantID.String(),
			userID.String(),
			models.CreateDiscoveryJobInput{
				Targets:       batch.targets,
				ExecutionMode: "async",
				Protocols:     batch.protocols,
				Ports:         batch.ports,
			},
			authHeader,
		)
		if e != nil {
			failed += len(batch.assetIDs)
			lastErr = e
			logBatchDispatchFailure(tenantID, batch, e)
			continue
		}
		if firstJobID == "" {
			firstJobID = job.ID
		}
	}
	if firstJobID == "" {
		return "", fmt.Errorf("failed to create re-validation job: %w", lastErr)
	}
	if failed > 0 {
		log.Printf("[ERROR] CreateRevalidationJob - partial dispatch: %d asset(s) NOT dispatched, tenantID: %v, last error: %v",
			failed, tenantID, lastErr)
	}
	return firstJobID, nil
}

// CreateActiveScanJob dispatches an on-demand Active Scan () for the given
// assets. Unlike stale revalidation, it (1) approves the targeted assets
// (pending_approval → monitoring) so the discovery pipeline extracts their crypto
// instead of deferring it, (2) stamps scan freshness (last_scanned_at / last_scan_status),
// and (3) dispatches an active TLS probe. Its findings reach sensor_discoveries the same
// way every discovery job's do (cluster-sensor mirrors unconditionally), so the normal
// discovery-processor → IngestFindings pipeline matches each asset by IP/port and catalogs
// its certificates and cipher configs.
// Returns the dispatched job ID and the number of assets actually scanned.
func (s *RevalidationService) CreateActiveScanJob(tenantID uuid.UUID, userID uuid.UUID, assetIDs []uuid.UUID, authHeader string) (string, int, error) {
	if len(assetIDs) == 0 {
		return "", 0, fmt.Errorf("at least one asset ID is required")
	}

	assets, err := s.resolveActiveScanAssets(tenantID, assetIDs)
	if err != nil {
		return "", 0, err
	}

	// Group into homogeneous jobs (see planActiveScanBatches for why this is not
	// one job carrying every port). Assets that produced no usable target are
	// simply absent from every batch — and, crucially, never stamped.
	batches := planActiveScanBatches(assets)
	if len(batches) == 0 {
		return "", 0, fmt.Errorf("no valid scan targets found (assets need an IP or hostname)")
	}

	var firstJobID string
	var scanned, failed int
	var lastErr error
	for _, batch := range batches {
		// Approve + stamp freshness BEFORE dispatching THIS batch. Approving
		// (pending_approval → monitoring) is required or the pipeline defers the
		// scanned crypto; stamping makes the asset drop out of the "unscanned"
		// coverage set. Idempotent for already-monitoring assets. The returned
		// stamps are what a failed dispatch restores.
		prior, e := s.stampScanning(tenantID, batch.assetIDs)
		if e != nil {
			failed += len(batch.assetIDs)
			lastErr = fmt.Errorf("failed to mark assets for scanning: %w", e)
			logBatchDispatchFailure(tenantID, batch, lastErr)
			continue
		}

		job, e := s.discoveryService.CreateJob(tenantID.String(), userID.String(), models.CreateDiscoveryJobInput{
			Targets:       batch.targets,
			ExecutionMode: "async",
			Protocols:     batch.protocols,
			Ports:         batch.ports,
			Options:       activeScanJobOptions(),
		}, authHeader)
		if e != nil {
			// Restore the pre-scan freshness so the UI doesn't show a stuck
			// "scanning" and the asset isn't reported as freshly scanned.
			s.stampScanFailed(tenantID, prior)
			failed += len(batch.assetIDs)
			lastErr = e
			logBatchDispatchFailure(tenantID, batch, e)
			continue
		}
		if firstJobID == "" {
			firstJobID = job.ID
		}
		scanned += len(batch.assetIDs)
	}

	if firstJobID == "" {
		return "", 0, fmt.Errorf("failed to dispatch active scan: %w", lastErr)
	}
	if failed > 0 {
		// Partial dispatch. The returned count already excludes these assets and
		// their freshness stamps have been restored, so they reappear on the
		// Active Scan list — but a failure that leaves no trace anywhere is the
		// silent-failure shape this whole path exists to avoid.
		log.Printf("[ERROR] CreateActiveScanJob - partial dispatch: %d asset(s) scanned, %d NOT dispatched, tenantID: %v, last error: %v",
			scanned, failed, tenantID, lastErr)
	}
	return firstJobID, scanned, nil
}

// logBatchDispatchFailure records exactly which assets were not dispatched and
// why. Without this, a batch that fails while another succeeds vanishes: the
// caller sees a job ID and a plausible count, and nothing anywhere says the
// rest never ran.
func logBatchDispatchFailure(tenantID uuid.UUID, batch activeScanBatch, err error) {
	log.Printf("[ERROR] Active scan batch dispatch failed - tenantID: %v, ports: %v, protocols: %v, %d asset(s): %v, error: %v",
		tenantID, batch.ports, batch.protocols, len(batch.assetIDs), batch.assetIDs, err)
}

// stampScanning approves the given assets, stamps scan freshness, and returns
// each asset's PRIOR last_scanned_at so a failed dispatch can put it back
// exactly as it was. The read and the write share one transaction, so the
// captured value is the one this statement overwrote.
// RLS-scoped read+write over network_assets_partitioned.
func (s *RevalidationService) stampScanning(tenantID uuid.UUID, assetIDs []uuid.UUID) ([]scanStamp, error) {
	var prior []scanStamp
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, e := tx.Query(`
			SELECT id, last_scanned_at
			FROM network_assets_partitioned
			WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL
		`, tenantID, pq.Array(assetIDs))
		if e != nil {
			return e
		}
		for rows.Next() {
			var stamp scanStamp
			if e := rows.Scan(&stamp.assetID, &stamp.lastScannedAt); e != nil {
				_ = rows.Close()
				return e
			}
			prior = append(prior, stamp)
		}
		if e := rows.Err(); e != nil {
			_ = rows.Close()
			return e
		}
		_ = rows.Close()

		_, e = tx.Exec(`
			UPDATE network_assets_partitioned
			SET asset_status     = 'monitoring',
			    last_scanned_at  = now(),
			    last_scan_status = 'scanning',
			    updated_at       = now()
			WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL
		`, tenantID, pq.Array(assetIDs))
		return e
	})
	if err != nil {
		return nil, err
	}
	return prior, nil
}

// stampScanFailed undoes the optimistic freshness stamp for assets whose scan
// was never actually dispatched, RESTORING each asset's previous
// last_scanned_at rather than blanking it.
//
// Blanking would be its own lie: last_scanned_at IS NULL is the "never scanned"
// coverage cut, so nulling it on an asset that really was scanned last week
// would erase genuine scan history and report it as never scanned. Restoring
// puts a previously-unscanned asset back to NULL (returning it to the Active
// Scan list, which is the point) and leaves a previously-scanned asset with its
// real timestamp.
//
// last_scan_status is deliberately NOT restored — it is set to 'failed', which
// is what actually happened. asset_status is left approved: approval is an
// intentional, idempotent act, and reverting it could undo an approval the
// asset already had.
//
// Best-effort by design — the dispatch error is what the caller reports.
func (s *RevalidationService) stampScanFailed(tenantID uuid.UUID, prior []scanStamp) {
	nullIDs, tsIDs, tsValues := planStampRestore(prior)

	_ = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		if len(nullIDs) > 0 {
			if _, e := tx.Exec(restoreNullStampSQL(scanStampTable), tenantID, pq.Array(nullIDs)); e != nil {
				return e
			}
		}
		if len(tsIDs) > 0 {
			if _, e := tx.Exec(restoreTimestampStampSQL(scanStampTable), tenantID, pq.Array(tsIDs), pq.Array(tsValues)); e != nil {
				return e
			}
		}
		return nil
	})
}

// scanStampTable is the table the freshness stamp lives on.
const scanStampTable = "network_assets_partitioned"

// The two restore statements are built by these helpers rather than inlined so
// the live SQL check (stamp_restore_sqlcheck_test.go) runs the SAME statements
// against a real Postgres, pointed at a probe table. Inlining them would let the
// production SQL drift away from the only thing that verifies it works.

// restoreNullStampSQL returns assets that were genuinely never scanned to NULL.
func restoreNullStampSQL(table string) string {
	return fmt.Sprintf(`
		UPDATE %s
		SET last_scan_status = 'failed',
		    last_scanned_at  = NULL,
		    updated_at       = now()
		WHERE tenant_id = $1 AND id = ANY($2)`, table)
}

// restoreTimestampStampSQL restores each asset's exact prior last_scanned_at.
// The parallel uuid[]/timestamptz[] arrays are unnested into a join so one
// statement restores many distinct instants.
func restoreTimestampStampSQL(table string) string {
	return fmt.Sprintf(`
		UPDATE %s AS a
		SET last_scan_status = 'failed',
		    last_scanned_at  = p.prior,
		    updated_at       = now()
		FROM unnest($2::uuid[], $3::timestamptz[]) AS p(id, prior)
		WHERE a.tenant_id = $1 AND a.id = p.id`, table)
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
