package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/sensorrouting"
)

type RevalidationService struct {
	db               *database.DB
	discoveryService *DiscoveryService
	assetService     *AssetService
	lifecycleService *AssetLifecycleService
	// router decides which executor a manual Active Scan runs from.
	router activeScanRouter
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
		router:           sensorrouting.NewStore(db),
	}
}

// resolveActiveScanAssets loads the requested assets and turns each into probe
// coordinates: a BARE host (never "host:port" — see active_scan_plan.go), its
// port, and the protocols already recorded against its crypto configurations.
// Assets with neither an IP nor a hostname are omitted, so the caller can tell
// which assets it is actually able to scan.
func (s *RevalidationService) resolveActiveScanAssets(tenantID uuid.UUID, assetIDs []uuid.UUID) ([]activeScanAsset, error) {
	// One row per ENDPOINT, not per asset. Scan coordinates are (address, port),
	// and that is what an endpoint is; a host exposing three ports is one asset
	// with three endpoints and must be probed on all three. (Under the old
	// port-as-asset model the same host was three assets, so "one row per asset"
	// happened to mean the same thing — it does not any more.)
	//
	// An asset with NO endpoint still yields one row, with a NULL port: an
	// at-rest cloud resource has nothing to connect to, and the caller skips it
	// for want of an address rather than probing a fabricated port.
	const assetQuery = `
		SELECT a.id,
		       a.hostname,
		       COALESCE(host(e.address), host(a.primary_address)) AS address,
		       e.port
		FROM assets a
		LEFT JOIN asset_endpoints e
		       ON e.tenant_id = a.tenant_id AND e.asset_id = a.id AND e.status <> 'closed'
		WHERE a.tenant_id = $1
		  AND a.id = ANY($2)
		  AND a.deleted_at IS NULL
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
	// RLS-scoped reads over assets / crypto_implementations.
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
func (s *RevalidationService) CreateActiveScanJob(tenantID uuid.UUID, userID uuid.UUID, assetIDs []uuid.UUID, authHeader string, runFrom RunFrom) (ActiveScanResult, error) {
	var result ActiveScanResult
	if len(assetIDs) == 0 {
		return result, fmt.Errorf("at least one asset ID is required")
	}
	if err := runFrom.validate(); err != nil {
		return result, err
	}
	now := time.Now()

	// A named sensor is checked BEFORE anything is stamped, so "that sensor is
	// offline" leaves every asset exactly as it was.
	var chosen *sensorrouting.Sensor
	if runFrom.Mode == RunFromSensor {
		if s.router == nil {
			return result, fmt.Errorf("%w: sensor routing is not available", sensorrouting.ErrSensorNotDispatchable)
		}
		sensor, err := s.router.FindDispatchable(context.Background(), tenantID, runFrom.SensorID, now)
		if err != nil {
			return result, err
		}
		chosen = &sensor
	}

	assets, err := s.resolveActiveScanAssets(tenantID, assetIDs)
	if err != nil {
		return result, err
	}

	// Group into homogeneous jobs (see planActiveScanBatches for why this is not
	// one job carrying every port). Assets that produced no usable target are
	// simply absent from every batch — and, crucially, never stamped.
	batches := planActiveScanBatches(assets)
	if len(batches) == 0 {
		return result, fmt.Errorf("no valid scan targets found (assets need an IP or hostname)")
	}

	var failed int
	var lastErr error
	for _, batch := range batches {
		for _, routed := range s.routeActiveScanBatch(tenantID, batch, runFrom, chosen, now) {
			if routed.skip != nil {
				// The observing sensor is offline. Not stamped, not scanned
				// from anywhere else; reported so the caller can say so.
				for _, id := range routed.batch.assetIDs {
					result.Skipped = append(result.Skipped, ActiveScanSkip{AssetID: id, Reason: routed.skip.Message()})
				}
				continue
			}

			// Approve + stamp freshness BEFORE dispatching THIS batch. Approving
			// (pending_approval → monitoring) is required or the pipeline defers the
			// scanned crypto; stamping makes the asset drop out of the "unscanned"
			// coverage set. Idempotent for already-monitoring assets. The returned
			// stamps are what a failed dispatch restores.
			prior, e := s.stampScanning(tenantID, routed.batch.assetIDs)
			if e != nil {
				failed += len(routed.batch.assetIDs)
				lastErr = fmt.Errorf("failed to mark assets for scanning: %w", e)
				logBatchDispatchFailure(tenantID, routed.batch, lastErr)
				continue
			}

			job, e := s.discoveryService.CreateJob(tenantID.String(), userID.String(), models.CreateDiscoveryJobInput{
				Targets:            routed.batch.targets,
				ExecutionMode:      routed.executionMode,
				PreferredSensorIDs: routed.preferredSensorIDs,
				Protocols:          routed.batch.protocols,
				Ports:              routed.batch.ports,
				Options:            activeScanJobOptions(),
			}, authHeader)
			if e != nil {
				// Restore the pre-scan freshness so the UI doesn't show a stuck
				// "scanning" and the asset isn't reported as freshly scanned.
				s.stampScanFailed(tenantID, prior)
				failed += len(routed.batch.assetIDs)
				lastErr = e
				logBatchDispatchFailure(tenantID, routed.batch, e)
				continue
			}
			dispatched := ActiveScanDispatchedJob{JobID: job.ID, Executor: "platform", Count: len(routed.batch.assetIDs)}
			if routed.sensor != nil {
				id := routed.sensor.ID
				dispatched.Executor = "sensor"
				dispatched.SensorID = &id
				dispatched.SensorName = routed.sensor.Name
			}
			result.Jobs = append(result.Jobs, dispatched)
			result.Scanned += len(routed.batch.assetIDs)
		}
	}

	if len(result.Jobs) == 0 {
		if lastErr != nil {
			return result, fmt.Errorf("failed to dispatch active scan: %w", lastErr)
		}
		// Every asset was skipped: nothing failed, nothing ran, and the caller
		// is told exactly why per asset.
		return result, nil
	}
	if failed > 0 {
		// Partial dispatch. The returned count already excludes these assets and
		// their freshness stamps have been restored, so they reappear on the
		// Active Scan list — but a failure that leaves no trace anywhere is the
		// silent-failure shape this whole path exists to avoid.
		log.Printf("[ERROR] CreateActiveScanJob - partial dispatch: %d asset(s) scanned, %d NOT dispatched, tenantID: %v, last error: %v",
			result.Scanned, failed, tenantID, lastErr)
	}
	return result, nil
}

// RunFrom is the executor a manual Active Scan asked for.
type RunFrom struct {
	// Mode is RunFromAuto, RunFromPlatform or RunFromSensor. Empty means auto.
	Mode string
	// SensorID names the tenant sensor when Mode is RunFromSensor.
	SensorID uuid.UUID
}

const (
	RunFromAuto     = "auto"
	RunFromPlatform = "platform"
	RunFromSensor   = "sensor"
)

// ErrInvalidRunFrom is a request-shape refusal: an unknown mode, or a sensor
// mode with no sensor.
var ErrInvalidRunFrom = errors.New("invalid run_from")

func (r *RunFrom) validate() error {
	switch r.Mode {
	case "":
		r.Mode = RunFromAuto
	case RunFromAuto, RunFromPlatform:
	case RunFromSensor:
		if r.SensorID == uuid.Nil {
			return fmt.Errorf("%w: run_from \"sensor\" needs a sensor_id", ErrInvalidRunFrom)
		}
	default:
		return fmt.Errorf("%w: %q (use auto, platform or sensor)", ErrInvalidRunFrom, r.Mode)
	}
	return nil
}

// ActiveScanDispatchedJob is one discovery job an Active Scan created.
type ActiveScanDispatchedJob struct {
	JobID      string
	Executor   string // "platform" | "sensor"
	SensorID   *uuid.UUID
	SensorName string
	Count      int
}

// ActiveScanSkip is an asset the scan left alone, and why.
type ActiveScanSkip struct {
	AssetID uuid.UUID
	Reason  string
}

// ActiveScanResult is what an Active Scan did.
type ActiveScanResult struct {
	Jobs    []ActiveScanDispatchedJob
	Skipped []ActiveScanSkip
	Scanned int
}

// FirstJobID keeps the pre- response shape: the first job dispatched.
func (r ActiveScanResult) FirstJobID() string {
	if len(r.Jobs) == 0 {
		return ""
	}
	return r.Jobs[0].JobID
}

// routedActiveScanBatch is a batch after the executor decision.
type routedActiveScanBatch struct {
	batch              activeScanBatch
	executionMode      string
	preferredSensorIDs []string
	sensor             *sensorrouting.Sensor
	skip               *sensorrouting.Skip
}

// activeScanRouter is the slice of sensorrouting.Store the manual scan uses.
type activeScanRouter interface {
	Resolve(ctx context.Context, tenantID uuid.UUID, targets []string, now time.Time) (sensorrouting.Plan, error)
	FindDispatchable(ctx context.Context, tenantID, sensorID uuid.UUID, now time.Time) (sensorrouting.Sensor, error)
}

// routeActiveScanBatch splits a batch across executors according to run_from.
//
// platform: everything from the platform. sensor: everything from the chosen
// sensor. auto: the routing rule — observing sensor, else segment sensor, else
// platform — with an offline observer's hosts SKIPPED rather than scanned from
// the wrong place. A router that cannot answer falls back to the platform for
// this scan, loudly, because refusing to scan at all is the worse failure and
// "from the platform" is what every manual scan did until today.
func (s *RevalidationService) routeActiveScanBatch(tenantID uuid.UUID, batch activeScanBatch, runFrom RunFrom, chosen *sensorrouting.Sensor, now time.Time) []routedActiveScanBatch {
	platform := []routedActiveScanBatch{{batch: batch, executionMode: "async"}}
	switch runFrom.Mode {
	case RunFromPlatform:
		return platform
	case RunFromSensor:
		return []routedActiveScanBatch{{batch: batch, executionMode: "sensors", preferredSensorIDs: []string{chosen.ID.String()}, sensor: chosen}}
	}
	if s.router == nil {
		return platform
	}
	plan, err := s.router.Resolve(context.Background(), tenantID, batch.targets, now)
	if err != nil {
		log.Printf("[ERROR] Active scan routing failed for tenant %v, scanning %d host(s) from the platform: %v", tenantID, len(batch.targets), err)
		return platform
	}
	var out []routedActiveScanBatch
	for _, group := range plan.Groups {
		sensor := group.Sensor
		out = append(out, routedActiveScanBatch{
			batch:              batch.subset(group.Targets),
			executionMode:      "sensors",
			preferredSensorIDs: []string{sensor.ID.String()},
			sensor:             &sensor,
		})
	}
	if len(plan.Platform) > 0 {
		out = append(out, routedActiveScanBatch{batch: batch.subset(plan.Platform), executionMode: "async"})
	}
	for _, skip := range plan.Skipped {
		sk := skip
		out = append(out, routedActiveScanBatch{batch: batch.subset([]string{skip.Target}), skip: &sk})
	}
	return out
}

// logBatchDispatchFailure records exactly which assets were not dispatched and
// why. Without this, a batch that fails while another succeeds vanishes: the
// caller sees a job ID and a plausible count, and nothing anywhere says the
// rest never ran.
func logBatchDispatchFailure(tenantID uuid.UUID, batch activeScanBatch, err error) {
	log.Printf("[ERROR] Active scan batch dispatch failed - tenantID: %v, ports: %v, protocols: %v, %d asset(s): %v, error: %v",
		tenantID, batch.ports, batch.protocols, len(batch.assetIDs), batch.assetIDs, err)
}

// stampScanning approves the given assets, stamps scan freshness on their
// endpoints, and returns each ENDPOINT's PRIOR last_scanned_at so a failed
// dispatch can put it back exactly as it was. The read and the write share one
// transaction, so the captured value is the one this statement overwrote.
//
// Scan freshness is endpoint-level (DATA_MODEL §2): a scan probes a socket, and
// "when was this last scanned" about an asset with three endpoints, two of them
// scanned, has no single true answer. Approval stays on the asset — it is a
// decision about the thing, not about one of its faces.
//
// RLS-scoped read+write over assets and asset_endpoints.
func (s *RevalidationService) stampScanning(tenantID uuid.UUID, assetIDs []uuid.UUID) ([]scanStamp, error) {
	var prior []scanStamp
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, e := tx.Query(`
			SELECT e.id, e.last_scanned_at
			FROM asset_endpoints e
			JOIN assets a ON a.tenant_id = e.tenant_id AND a.id = e.asset_id AND a.deleted_at IS NULL
			WHERE e.tenant_id = $1 AND e.asset_id = ANY($2)
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

		if _, e := tx.Exec(`
			UPDATE assets
			SET asset_status = 'monitoring',
			    updated_at   = now()
			WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL
		`, tenantID, pq.Array(assetIDs)); e != nil {
			return e
		}

		_, e = tx.Exec(`
			UPDATE asset_endpoints
			SET last_scanned_at  = now(),
			    last_scan_status = 'scanning',
			    updated_at       = now()
			WHERE tenant_id = $1 AND asset_id = ANY($2)
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

// scanStampTable is the table the freshness stamp lives on. Scan freshness is
// a property of the endpoint that was probed, not of the asset (DATA_MODEL §2).
const scanStampTable = "asset_endpoints"

// The two restore statements are built by these helpers rather than inlined so
// the live SQL check (stamp_restore_sqlcheck_test.go) runs the SAME statements
// against a real Postgres, pointed at a probe table. Inlining them would let the
// production SQL drift away from the only thing that verifies it works.

// restoreNullStampSQL returns endpoints that were genuinely never scanned to NULL.
func restoreNullStampSQL(table string) string {
	return fmt.Sprintf(`
		UPDATE %s
		SET last_scan_status = 'failed',
		    last_scanned_at  = NULL,
		    updated_at       = now()
		WHERE tenant_id = $1 AND id = ANY($2)`, table)
}

// restoreTimestampStampSQL restores each endpoint's exact prior last_scanned_at.
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
