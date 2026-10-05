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
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/autoscan"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/sensorrouting"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
)

type RevalidationService struct {
	db               *database.DB
	discoveryService *DiscoveryService
	assetService     *AssetService
	lifecycleService *AssetLifecycleService
	// router decides which executor a manual Active Scan runs from.
	router activeScanRouter
	// resolver resolves an asset known only by name, so the "outside your
	// registered networks" question is asked before anything changes
	// ( W5.13b). Nil means net.DefaultResolver.
	resolver dispatchguard.Resolver
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
// coordinates: a BARE host (never "host:port" — see active_scan_plan.go) and
// its port. Assets with neither an IP nor a hostname are omitted, so the
// caller can tell which assets it is actually able to scan.
//
// No protocol is read: the shared scan engine identifies the service from what
// answers on the port ( WP4, spec V7).
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
	var assets []activeScanAsset
	// RLS-scoped read over assets / asset_endpoints.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
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

			name := host
			if hostname.Valid && hostname.String != "" {
				name = hostname.String
			}
			asset := activeScanAsset{id: id, name: name, host: host}
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
	// The names the assets are known by, to offer a TLS port that refuses the
	// address-only handshake. Best effort: a failure costs the scan its extra
	// chance at a name, never the scan itself.
	ids := make([]uuid.UUID, 0, len(assets))
	for _, a := range assets {
		ids = append(ids, a.id)
	}
	if names, nerr := autoscan.LoadSNICandidates(context.Background(), s.db, tenantID, ids); nerr != nil {
		log.Printf("[RevalidationService] tenant %s: not offering server names to the scan: %v", tenantID, nerr)
	} else {
		for i := range assets {
			assets[i].sni = names[assets[i].id]
		}
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
	requestAt := time.Now()
	for _, batch := range batches {
		job, e := s.discoveryService.CreateJob(
			tenantID.String(),
			userID.String(),
			models.CreateDiscoveryJobInput{
				Targets:       batch.targets,
				ExecutionMode: "async",
				ScanDepth:     string(shareddisc.DepthCustom),
				TCPPorts:      shareddisc.CustomPortList(batch.ports),
				// A re-scan of known assets: its results are stamped
				// discovery_source=active_scan, not ingested as passive
				// sensor observations (sensorRowSource in the converter).
				Options:       activeScanJobOptions(),
				SNICandidates: batch.sniByHost,
			},
			authHeader,
		)
		if e != nil {
			s.markDispatchFailed(tenantID, batch)
			failed += len(batch.assetIDs)
			lastErr = e
			logBatchDispatchFailure(tenantID, batch, e)
			continue
		}
		// Recorded exactly as an Active Scan is, so the same completion logic
		// settles it. No approval: a stale-asset revalidation is not a
		// decision about the asset.
		s.recordDispatched(tenantID, batch, job.ID, requestAt)
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
// instead of deferring it, (2) dispatches an active probe, and (3) records the
// dispatched jobs on each asset and marks the probed endpoints `scanning`, which
// autoscan.FinishActiveScans settles to completed/failed when the jobs end. Both
// paths record the same way. Its findings reach sensor_discoveries the same
// way every discovery job's do (cluster-sensor mirrors unconditionally), so the normal
// discovery-processor → IngestFindings pipeline matches each asset by IP/port and catalogs
// its certificates and cipher configs.
// Returns the dispatched job ID and the number of assets actually scanned.
//
// externalConfirmed is a person's confirmation that assets whose address is
// outside the tenant's registered networks may be scanned ( W5.13b, owner
// decision Q10: pressing Scan on an asset you chose is the explicit action).
// Without it, such assets are found BEFORE anything is stamped or dispatched
// and returned as an *ExternalConfirmationError naming them; the caller asks
// and resends. The bulk stale-revalidation sweep never sets it.
func (s *RevalidationService) CreateActiveScanJob(tenantID uuid.UUID, userID uuid.UUID, assetIDs []uuid.UUID, authHeader string, runFrom RunFrom, externalConfirmed bool) (ActiveScanResult, error) {
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
	// Whatever this scan leaves alone is said in the log as well as in the
	// response: the response reaches one browser tab, once.
	defer func() { logActiveScanLeftAlone(tenantID, assetIDs, assets, result) }()
	if !externalConfirmed {
		need, err := s.externalAssets(tenantID, assets)
		if err != nil {
			return result, err
		}
		if len(need) > 0 {
			return result, &ExternalConfirmationError{Targets: need}
		}
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

			// Approve BEFORE dispatching THIS batch: an asset still
			// pending_approval has its scanned crypto deferred by the pipeline,
			// and the results can arrive within seconds of dispatch.
			// Idempotent for already-monitoring assets.
			if e := s.approveForScan(tenantID, routed.batch.assetIDs); e != nil {
				failed += len(routed.batch.assetIDs)
				lastErr = fmt.Errorf("failed to mark assets for scanning: %w", e)
				logBatchDispatchFailure(tenantID, routed.batch, lastErr)
				continue
			}

			job, e := s.discoveryService.CreateJob(tenantID.String(), userID.String(), models.CreateDiscoveryJobInput{
				Targets:            routed.batch.targets,
				ExecutionMode:      routed.executionMode,
				PreferredSensorIDs: routed.preferredSensorIDs,
				// A planned job on the shared scan engine ( WP4): the
				// batch's ports at scan depth "custom", no protocol list.
				ScanDepth: string(shareddisc.DepthCustom),
				TCPPorts:  shareddisc.CustomPortList(routed.batch.ports),
				Options:   activeScanJobOptions(),
				// Names the assets are known by, for a TLS port that wants one.
				SNICandidates: routed.batch.sniByHost,
				// Only ever true when a person confirmed it on this request.
				ExternalTargetsConfirmed: externalConfirmed,
			}, authHeader)
			if e != nil {
				// A target verdict is the caller's to act on, per asset —
				// never folded into a generic failure ( W5.13b). Nothing
				// was scanned and nothing is recorded: the person is asked.
				if s.recordTargetVerdict(&result, routed.batch, e) {
					continue
				}
				// Nothing was dispatched: the endpoints say so, and no scan
				// time or asset record is written, so the asset stays on the
				// Active Scan list.
				s.markDispatchFailed(tenantID, routed.batch)
				failed += len(routed.batch.assetIDs)
				lastErr = e
				logBatchDispatchFailure(tenantID, routed.batch, e)
				// Said in the response too. When another batch did start, the
				// request succeeds, and without this the person saw "Active
				// scan started for N assets" with these assets in no list at
				// all — only a server log line knew they never ran.
				for _, id := range routed.batch.assetIDs {
					result.Skipped = append(result.Skipped, ActiveScanSkip{AssetID: id, Reason: dispatchFailureReason(e)})
				}
				continue
			}
			// Mark this batch's endpoints `scanning` and record the job on
			// each asset, in one transaction, now that the job exists. The
			// record is what ties the endpoints to the job that settles them
			// (autoscan.FinishActiveScans) and what records a scan of an asset
			// with no endpoint at all. The scan TIME is written only when the
			// job finishes, so the asset stays on the "unscanned" list, shown
			// as scanning, until its scan has actually run.
			s.recordDispatched(tenantID, routed.batch, job.ID, now)
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

	if len(result.NeedsConfirmation) > 0 {
		return result, &ExternalConfirmationError{Targets: result.NeedsConfirmation, Partial: result}
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

// dispatchFailureReason is what a person is told about a batch whose job could
// not be created: the downstream service's own wording when it gave one.
func dispatchFailureReason(err error) string {
	var downstream *DownstreamError
	if errors.As(err, &downstream) && downstream.Message != "" {
		return "the scan could not be started: " + downstream.Message
	}
	return "the scan could not be started"
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
	// NeedsConfirmation are assets cluster-sensor-service found outside the
	// registered networks that the preflight could not see (an asset with only
	// a hostname). Not dispatched, not stamped.
	NeedsConfirmation []ActiveScanExternalTarget
	Scanned           int
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
// platform — with an offline observer's hosts handed to a live segment sensor
// when one covers them and otherwise SKIPPED, never scanned from the platform. A router that cannot answer falls back to the platform for
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

// maxActiveScanSkipLogLines bounds the per-asset lines one scan request may
// write; the summary line always carries the full counts.
const maxActiveScanSkipLogLines = 50

// logActiveScanLeftAlone records every asset a person asked to scan that was
// not dispatched, and why: skipped by routing or by a target verdict, waiting
// on a confirmation, or absent because it has no address or name to scan.
func logActiveScanLeftAlone(tenantID uuid.UUID, requested []uuid.UUID, resolved []activeScanAsset, result ActiveScanResult) {
	addressable := make(map[uuid.UUID]bool, len(resolved))
	for _, a := range resolved {
		addressable[a.id] = true
	}
	var noTarget []uuid.UUID
	for _, id := range requested {
		if !addressable[id] {
			noTarget = append(noTarget, id)
		}
	}
	if len(result.Skipped) == 0 && len(result.NeedsConfirmation) == 0 && len(noTarget) == 0 {
		return
	}
	log.Printf("[WARN] Active scan left assets alone - tenantID: %v, requested: %d, dispatched: %d, skipped: %d, awaiting confirmation: %d, no address or name: %d",
		tenantID, len(requested), result.Scanned, len(result.Skipped), len(result.NeedsConfirmation), len(noTarget))
	lines := 0
	line := func(format string, args ...interface{}) {
		if lines < maxActiveScanSkipLogLines {
			log.Printf(format, args...)
		}
		lines++
	}
	for _, sk := range result.Skipped {
		line("[WARN] Active scan skipped asset %v, tenantID: %v: %s", sk.AssetID, tenantID, sk.Reason)
	}
	for _, n := range result.NeedsConfirmation {
		line("[WARN] Active scan not started for asset %v, tenantID: %v: target %s is outside the registered networks and was not confirmed", n.AssetID, tenantID, n.Target)
	}
	for _, id := range noTarget {
		line("[WARN] Active scan skipped asset %v, tenantID: %v: it has no address or name to scan", id, tenantID)
	}
	if lines > maxActiveScanSkipLogLines {
		log.Printf("[WARN] Active scan: %d more asset(s) left alone, not listed - tenantID: %v", lines-maxActiveScanSkipLogLines, tenantID)
	}
}

// logBatchDispatchFailure records exactly which assets were not dispatched and
// why. Without this, a batch that fails while another succeeds vanishes: the
// caller sees a job ID and a plausible count, and nothing anywhere says the
// rest never ran.
func logBatchDispatchFailure(tenantID uuid.UUID, batch activeScanBatch, err error) {
	log.Printf("[ERROR] Active scan batch dispatch failed - tenantID: %v, ports: %v, %d asset(s): %v, error: %v",
		tenantID, batch.ports, len(batch.assetIDs), batch.assetIDs, err)
}

// approveForScan approves the assets an Active Scan is about to dispatch
// (pending_approval → monitoring). Approval is on the asset — a decision about
// the thing, not about one of its faces — and idempotent.
//
// RLS-scoped write over assets.
func (s *RevalidationService) approveForScan(tenantID uuid.UUID, assetIDs []uuid.UUID) error {
	return database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(`
			UPDATE assets
			SET asset_status = 'monitoring',
			    updated_at   = now()
			WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL
		`, tenantID, pq.Array(assetIDs))
		return e
	})
}

// recordDispatched records a dispatched job for its batch: the batch's
// endpoints are marked `scanning` and the job is added to each asset's Active
// Scan record (autoscan.RecordActiveScanTx), in one transaction, so there is
// never a `scanning` endpoint without the job that will settle it.
//
// It runs AFTER the job exists, so a failed dispatch leaves nothing to undo.
// last_scanned_at is not touched: it is a scan time, written by
// autoscan.FinishActiveScans when the job has actually scanned the endpoint.
// Writing it at dispatch is what made a scan that never ran look like one that
// did, and what took an asset off the unscanned list before its scan happened.
//
// Best-effort: the job is already running, and the dispatch response is what
// the caller reports. A failure is logged loudly; the asset then simply stays
// on the unscanned list and nothing is left `scanning`.
func (s *RevalidationService) recordDispatched(tenantID uuid.UUID, batch activeScanBatch, jobID string, requestAt time.Time) {
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return autoscan.RecordActiveScanTx(context.Background(), tx, tenantID, batch.assetIDs, batch.ports, jobID, requestAt)
	})
	if err != nil {
		log.Printf("[ERROR] Active scan job %s dispatched but not recorded on its %d asset(s), tenantID: %v: %v",
			jobID, len(batch.assetIDs), tenantID, err)
	}
}

// markDispatchFailed records that a batch's scan was never dispatched: its
// endpoints read `failed`. last_scanned_at is left alone (nothing scanned
// them), so a never-scanned asset stays on the Active Scan list and a scanned
// one keeps its real history. An endpoint another request is still scanning
// is not touched. asset_status is left approved: approval is intentional and
// idempotent, and reverting it could undo an approval the asset already had.
//
// Best-effort by design — the dispatch error is what the caller reports.
func (s *RevalidationService) markDispatchFailed(tenantID uuid.UUID, batch activeScanBatch) {
	_ = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(`
			UPDATE asset_endpoints
			SET last_scan_status = 'failed',
			    updated_at       = now()
			WHERE tenant_id = $1 AND asset_id = ANY($2) AND port = ANY($3)
			  AND status <> 'closed'
			  AND last_scan_status IS DISTINCT FROM 'scanning'
		`, tenantID, pq.Array(batch.assetIDs), pq.Array(batch.ports))
		return e
	})
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
