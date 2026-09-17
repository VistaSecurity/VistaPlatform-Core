package jobs

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/autoscan"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/sensorrouting"
	sharedautoscan "github.com/vistasecurity/vistaplatform/shared/autoscan"
)

// AutoActiveScanJob scans every internal host the platform knows about — when
// it is first observed, and again once the tenant's rescan interval has
// elapsed. It is the "automatically build the inventory with as much info as
// possible" half of discovery: nobody presses a button.
//
// # Why it lives in inventory-service
//
// It has to decide WHICH assets to scan, which means the assets table, the
// tenant's network segments and the per-asset scan stamp — all of which are
// this service's. Dispatch is one signed HTTP call to cluster-sensor-service,
// which already owns job execution. Putting the worker next to the executor
// instead would move three queries about the inventory into a service that has
// no business reading it.
//
// # Two triggers, one path
//
// The ticker sweep and the first-observation trigger do the SAME work; the
// difference is only which tenants are looked at and how soon. The event is a
// hint to look now, not a per-asset command — which is what makes a burst of
// 300 new hosts coalesce into a bounded number of jobs instead of 300, and what
// makes a missed or replayed event harmless: eligibility is recomputed from the
// database either way.
type AutoActiveScanJob struct {
	store      autoScanStore
	dispatcher autoScanDispatcher
	router     autoScanRouter
	bypassDB   *sql.DB
	logger     *log.Logger

	enabled         bool
	sweepInterval   time.Duration
	triggerInterval time.Duration
	excluded        []netip.Prefix

	// dirty holds tenants that have reported a new observation since the last
	// trigger pass. A set, not a queue: the same tenant reporting 300 hosts is
	// one entry, which IS the coalescing.
	mu    sync.Mutex
	dirty map[uuid.UUID]bool

	// Seams for tests. The wiring test asserts Start is called from main; these
	// let the sweep itself be driven without a database or a peer.
	listTenants func() ([]uuid.UUID, error)
	isScannable func(uuid.UUID) (bool, error)
	tryLock     func(context.Context) (func(), bool, error)
	now         func() time.Time
}

// autoScanStore is the slice of internal/autoscan.Store this job uses.
type autoScanStore interface {
	GetPolicy(ctx context.Context, tenantID uuid.UUID) (autoscan.Policy, error)
	EligibleTargets(ctx context.Context, tenantID uuid.UUID, policy autoscan.Policy, now time.Time, excluded []netip.Prefix) ([]autoscan.Target, map[sharedautoscan.Reason]int, error)
	AddressesWithScanInFlight(ctx context.Context, tenantID uuid.UUID) (map[string]bool, error)
	RecordScanned(ctx context.Context, tenantID uuid.UUID, assetIDs []uuid.UUID, jobID string, at time.Time) error
	StampCompletedScans(ctx context.Context, tenantID uuid.UUID) (int, error)
	ClearUnstartedScanStamps(ctx context.Context, tenantID uuid.UUID) (int, error)
	SetState(ctx context.Context, tenantID uuid.UUID, state autoscan.State) error
}

// autoScanDispatcher is the one call this job makes to cluster-sensor-service.
type autoScanDispatcher interface {
	CreateJobInternal(tenantID string, input models.CreateDiscoveryJobInput) (*models.DiscoveryJob, error)
}

// autoScanRouter decides which executor scans each address: the
// tenant sensor that observed it, one that shares its segment, or the
// platform. The concrete implementation is sensorrouting.Store.
type autoScanRouter interface {
	Resolve(ctx context.Context, tenantID uuid.UUID, targets []string, now time.Time) (sensorrouting.Plan, error)
}

// Environment knobs.
const (
	// EnvAutoScanEnabled is the kill switch. Anything but "false" leaves the
	// worker on, because the product decision is that the platform scans by
	// default and an operator turning it off should have to say so.
	EnvAutoScanEnabled = "DISCOVERY_AUTO_SCAN_WORKER_ENABLED"
	// EnvAutoScanSweepInterval is how often the full sweep looks for work. It is
	// NOT the rescan interval — that is the tenant's, in hours, and this only
	// decides how promptly an asset that has become due is noticed.
	EnvAutoScanSweepInterval = "DISCOVERY_AUTO_SCAN_SWEEP_INTERVAL"
	// EnvAutoScanTriggerInterval is how often tenants that reported a new
	// observation are looked at. Short, because "scan it when we first see it"
	// is the point; bounded, because it is also the coalescing window.
	EnvAutoScanTriggerInterval = "DISCOVERY_AUTO_SCAN_TRIGGER_INTERVAL"
)

const (
	defaultSweepInterval   = 15 * time.Minute
	defaultTriggerInterval = 60 * time.Second
)

// NewAutoActiveScanJob builds the worker. `store`, `dispatcher` and `router`
// are the concrete internal/autoscan.Store, services.DiscoveryService and
// sensorrouting.Store in production. A nil router scans everything from the
// platform, which is the pre- behaviour.
func NewAutoActiveScanJob(store autoScanStore, dispatcher autoScanDispatcher, router autoScanRouter, bypassDB *sql.DB) *AutoActiveScanJob {
	j := &AutoActiveScanJob{
		store:           store,
		dispatcher:      dispatcher,
		router:          router,
		bypassDB:        bypassDB,
		logger:          log.New(log.Writer(), "[AutoActiveScan] ", log.LstdFlags),
		enabled:         os.Getenv(EnvAutoScanEnabled) != "false",
		sweepInterval:   durationFromEnv(EnvAutoScanSweepInterval, defaultSweepInterval),
		triggerInterval: durationFromEnv(EnvAutoScanTriggerInterval, defaultTriggerInterval),
		excluded:        autoscan.PlatformExcludedPrefixes(),
		dirty:           map[uuid.UUID]bool{},
	}
	j.listTenants = j.tenantsToSweep
	j.isScannable = j.tenantIsScannable
	j.tryLock = j.pgTryLock
	j.now = time.Now
	return j
}

func durationFromEnv(key string, def time.Duration) time.Duration {
	if raw := os.Getenv(key); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			return d
		}
	}
	return def
}

// NoteObservation records that a tenant has just seen something new, so the
// next trigger pass looks at it.
//
// Idempotent and bounded on purpose: the set collapses a burst, and the pass it
// schedules re-derives eligibility from the database rather than trusting the
// event. A duplicate delivery, a replay, or an event for an asset that turns
// out to be public all end up doing nothing.
func (j *AutoActiveScanJob) NoteObservation(tenantID uuid.UUID) {
	if !j.enabled || tenantID == uuid.Nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.dirty[tenantID] = true
}

func (j *AutoActiveScanJob) takeDirty() []uuid.UUID {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.dirty) == 0 {
		return nil
	}
	out := make([]uuid.UUID, 0, len(j.dirty))
	for id := range j.dirty {
		out = append(out, id)
	}
	j.dirty = map[uuid.UUID]bool{}
	sort.Slice(out, func(a, b int) bool { return out[a].String() < out[b].String() })
	return out
}

// Start runs the worker until ctx is cancelled.
func (j *AutoActiveScanJob) Start(ctx context.Context) {
	if !j.enabled {
		j.logger.Printf("disabled by %s=false — no host will be scanned automatically", EnvAutoScanEnabled)
		return
	}
	j.logger.Printf("started (sweep every %v, first-observation pass every %v, %d excluded prefix(es))",
		j.sweepInterval, j.triggerInterval, len(j.excluded))

	sweep := time.NewTicker(j.sweepInterval)
	defer sweep.Stop()
	trigger := time.NewTicker(j.triggerInterval)
	defer trigger.Stop()

	j.SweepAll(ctx)

	for {
		select {
		case <-ctx.Done():
			j.logger.Println("stopped")
			return
		case <-sweep.C:
			j.SweepAll(ctx)
		case <-trigger.C:
			j.SweepObserved(ctx)
		}
	}
}

// SweepAll runs one pass over every tenant that has assets.
func (j *AutoActiveScanJob) SweepAll(ctx context.Context) {
	j.underSweepLock(ctx, "scheduled sweep", func() {
		tenants, err := j.listTenants()
		if err != nil {
			j.logger.Printf("ERROR: could not enumerate tenants: %v", err)
			return
		}
		for _, tenantID := range tenants {
			select {
			case <-ctx.Done():
				return
			default:
			}
			j.SweepTenant(ctx, tenantID, false)
		}
	})
}

// SweepObserved runs one pass over the tenants that reported a new observation.
func (j *AutoActiveScanJob) SweepObserved(ctx context.Context) {
	tenants := j.takeDirty()
	if len(tenants) == 0 {
		return
	}
	j.underSweepLock(ctx, "first-observation pass", func() {
		for _, tenantID := range tenants {
			select {
			case <-ctx.Done():
				return
			default:
			}
			j.SweepTenant(ctx, tenantID, true)
		}
	})
}

// underSweepLock runs one whole pass while holding the cross-replica advisory
// lock, or skips it when another replica already holds it.
//
// inventory-service runs two replicas under `values-ha.yaml`, and both have the
// same ticker. Without this, the same tenant's sweep runs twice in parallel:
// both read the same eligible set, both see the same (empty) in-flight set, and
// both dispatch — so every host is probed twice per interval and the tenant sees
// the duplication in their own logs before we see it in ours. The in-flight gate
// cannot close this, because the race is between two reads that both happen
// before either write.
//
// Session-level and best-effort: a replica that cannot take the lock does
// nothing this tick and tries again on the next one, which is exactly right for
// a pass that is idempotent anyway.
func (j *AutoActiveScanJob) underSweepLock(ctx context.Context, what string, pass func()) {
	release, ok, err := j.tryLock(ctx)
	if err != nil {
		j.logger.Printf("ERROR: could not take the %s lock: %v", what, err)
		return
	}
	if !ok {
		j.logger.Printf("another replica is running the %s; skipping this tick", what)
		return
	}
	defer release()
	pass()
}

// sweepAdvisoryLockKey is the fixed 64-bit key the automatic-scan pass takes.
// Hand-picked rather than hashed so it is greppable, and distinct from every
// other advisory-lock user in the platform.
const sweepAdvisoryLockKey int64 = 0x7641_5343_0000_0001

// pgTryLock takes the session-level advisory lock on the bypass handle.
func (j *AutoActiveScanJob) pgTryLock(ctx context.Context) (func(), bool, error) {
	if j.bypassDB == nil {
		// No database handle at all: single-process contexts (tests, a compose
		// run with no bypass pool) have nothing to contend with.
		return func() {}, true, nil
	}
	conn, err := j.bypassDB.Conn(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("acquire a connection for the sweep lock: %w", err)
	}
	var got bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", sweepAdvisoryLockKey).Scan(&got); err != nil {
		_ = conn.Close()
		return nil, false, fmt.Errorf("try the sweep advisory lock: %w", err)
	}
	if !got {
		_ = conn.Close()
		return nil, false, nil
	}
	return func() {
		// Released on the SAME connection that took it — a session-level lock
		// belongs to the session, so unlocking through the pool could hit a
		// different backend and leave the lock held until the pod restarts.
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", sweepAdvisoryLockKey)
		_ = conn.Close()
	}, true, nil
}

// SweepTenant dispatches the automatic scans one tenant is due.
//
// `firstObservation` marks the pass that a new observation triggered, which the
// tenant can turn off independently of scheduled rescans.
func (j *AutoActiveScanJob) SweepTenant(ctx context.Context, tenantID uuid.UUID, firstObservation bool) {
	// The tenant guard, on the path BOTH entry points share. `listTenants`
	// already excludes cancelled and deleted tenants, but the first-observation
	// pass does not go through it — it acts on whatever the NATS consumer
	// marked — so without this a cancelled tenant whose sensor is still running
	// would keep being scanned by us indefinitely.
	scannable, err := j.isScannable(tenantID)
	if err != nil {
		j.logger.Printf("ERROR: tenant %s: could not check tenant status, skipping: %v", tenantID, err)
		return
	}
	if !scannable {
		return
	}

	// Close the loop on scans an earlier pass dispatched: stamp the endpoints
	// whose automatic job has since completed and actually answered. BEFORE the
	// policy check on purpose — a job that finished after the tenant turned the
	// feature off still happened, and the manual coverage list should say so.
	// An error here is logged and the pass goes on: the stamp is a record, not
	// a gate, and it is re-attempted on every pass anyway.
	if stamped, err := j.store.StampCompletedScans(ctx, tenantID); err != nil {
		j.logger.Printf("ERROR: tenant %s: could not stamp completed automatic scans: %v", tenantID, err)
	} else if stamped > 0 {
		j.logger.Printf("tenant %s: %d endpoint(s) marked scanned by completed automatic scans", tenantID, stamped)
	}

	// And the other half of closing that loop: give back the assets whose job
	// never ran. RecordScanned stamps at enqueue, which is right for a probe
	// that went unanswered and wrong for a sensor that refused the command —
	// those addresses were never touched, and without this they sit out a full
	// rescan interval on the strength of a scan that did not happen. Also
	// before the policy check, for the same reason as the stamp above.
	if cleared, err := j.store.ClearUnstartedScanStamps(ctx, tenantID); err != nil {
		j.logger.Printf("ERROR: tenant %s: could not clear stamps for automatic scans that never started: %v", tenantID, err)
	} else if cleared > 0 {
		j.logger.Printf("tenant %s: %d asset(s) re-queued — their automatic scan never started", tenantID, cleared)
	}

	policy, err := j.store.GetPolicy(ctx, tenantID)
	if err != nil {
		j.logger.Printf("ERROR: tenant %s: could not read the policy: %v", tenantID, err)
		return
	}
	if !policy.Enabled {
		return
	}
	if firstObservation && !policy.ScanOnFirstObservation {
		return
	}

	now := j.now()
	targets, refusals, err := j.store.EligibleTargets(ctx, tenantID, policy, now, j.excluded)
	if err != nil {
		j.logger.Printf("ERROR: tenant %s: could not select targets: %v", tenantID, err)
		return
	}
	inFlight, err := j.store.AddressesWithScanInFlight(ctx, tenantID)
	if err != nil {
		// Fail CLOSED on the idempotency gate. Dispatching without knowing what
		// is already running is how one observation becomes the same host
		// probed several times over — which the tenant sees in their own logs
		// before we see it in ours.
		j.logger.Printf("ERROR: tenant %s: could not read in-flight scans, skipping this pass: %v", tenantID, err)
		return
	}

	batches, deferredCount := autoscan.PlanSweep(targets, inFlight, autoscan.MaxJobsPerSweep, autoscan.MaxTargetsPerJob)
	if len(batches) == 0 {
		// Still record the pass. "We looked and there was nothing due" and "the
		// worker has not run" are different answers, and the settings page shows
		// which one it is. The refusals travel with it: a pass that dispatched
		// nothing BECAUSE every host was refused is the case the page most
		// needs to be able to explain.
		j.recordState(ctx, tenantID, now, 0, 0, refusals)
		return
	}

	dispatched, scannedAssets, skippedOffline := 0, 0, 0
	for _, batch := range batches {
		for _, routed := range j.routeBatch(ctx, tenantID, policy, batch, now) {
			if routed.skipped != nil {
				// The observing sensor is offline. NOT stamped and NOT handed
				// to the platform: the target stays eligible and is looked at
				// again next pass, when the sensor may be back. Substituting
				// the platform would be a scan from a place that cannot see
				// the host — the wrong-executor run this feature exists to
				// prevent.
				skippedOffline += len(routed.addresses)
				j.logger.Printf("tenant %s: %d address(es) skipped this pass: %s", tenantID, len(routed.addresses), routed.skipped.Message())
				continue
			}
			job, err := j.dispatcher.CreateJobInternal(tenantID.String(), models.CreateDiscoveryJobInput{
				Targets:            routed.addresses,
				ExecutionMode:      routed.executionMode,
				PreferredSensorIDs: routed.preferredSensorIDs,
				Protocols:          policy.Protocols,
				Ports:              policy.Ports,
				Options:            autoscan.JobOptions(),
			})
			if err != nil {
				// Deliberately NOT stamped: an asset whose scan never left the
				// cluster must stay due, or a peer outage would look like a
				// completed sweep and the host would not be looked at again for a
				// whole interval.
				j.logger.Printf("ERROR: tenant %s: dispatch (%s) failed for %d address(es): %v", tenantID, routed.describe(), len(routed.addresses), err)
				continue
			}
			dispatched++
			scannedAssets += len(routed.assetIDs)
			if err := j.store.RecordScanned(ctx, tenantID, routed.assetIDs, job.ID, now); err != nil {
				// The scan IS running; only our record of it failed. Logged loudly
				// because the consequence is a host scanned again on the next pass,
				// not a host left unscanned.
				j.logger.Printf("ERROR: tenant %s: job %s dispatched but the scan stamp failed: %v", tenantID, job.ID, err)
			}
		}
	}

	if skippedOffline > 0 {
		j.logger.Printf("tenant %s: %d address(es) whose observing sensor is offline were not scanned this pass — they stay eligible", tenantID, skippedOffline)
	}
	if deferredCount > 0 {
		j.logger.Printf("tenant %s: %d asset(s) did not fit this pass (cap %d jobs × %d targets) — they are first in line next pass",
			tenantID, deferredCount, autoscan.MaxJobsPerSweep, autoscan.MaxTargetsPerJob)
	}
	if len(refusals) > 0 {
		j.logger.Printf("tenant %s: not eligible by address: %s", tenantID, formatRefusals(refusals))
	}
	j.logger.Printf("tenant %s: dispatched %d job(s) covering %d asset(s)", tenantID, dispatched, scannedAssets)
	j.recordState(ctx, tenantID, now, dispatched, scannedAssets, refusals)
}

// routedBatch is one dispatchable job after routing: its addresses, the assets
// behind them, and where it runs. `skipped` is set instead when the batch's
// observing sensor is offline.
type routedBatch struct {
	addresses          []string
	assetIDs           []uuid.UUID
	executionMode      string
	preferredSensorIDs []string
	sensorName         string
	skipped            *sensorrouting.Skip
}

func (r routedBatch) describe() string {
	if r.executionMode == "sensors" {
		return "sensor " + r.sensorName
	}
	return "platform"
}

// routeBatch splits one planned batch across executors.
//
// With the tenant's "Prefer the observing sensor" switch off, or no router
// wired, everything runs from the platform exactly as before. With it on,
// each address goes to the tenant sensor that last observed it, else a sensor
// bound to its segment, else the platform; addresses whose observing sensor is
// offline come back as skipped. A router that cannot answer at all falls back
// to the platform for this pass with an ERROR, because "scan from the platform"
// is the behaviour every tenant had until today and refusing to scan anything
// is the worse failure.
func (j *AutoActiveScanJob) routeBatch(ctx context.Context, tenantID uuid.UUID, policy autoscan.Policy, batch autoscan.Batch, now time.Time) []routedBatch {
	platformOnly := []routedBatch{{addresses: batch.Addresses, assetIDs: batch.AssetIDs, executionMode: "async"}}
	if !policy.PreferObservingSensor || j.router == nil {
		return platformOnly
	}
	plan, err := j.router.Resolve(ctx, tenantID, batch.Addresses, now)
	if err != nil {
		j.logger.Printf("ERROR: tenant %s: could not route %d address(es) to sensors, scanning from the platform this pass: %v", tenantID, len(batch.Addresses), err)
		return platformOnly
	}

	var out []routedBatch
	for _, group := range plan.Groups {
		out = append(out, routedBatch{
			addresses:          group.Targets,
			assetIDs:           batch.AssetsFor(group.Targets),
			executionMode:      "sensors",
			preferredSensorIDs: []string{group.Sensor.ID.String()},
			sensorName:         group.Sensor.Name,
		})
	}
	if len(plan.Platform) > 0 {
		out = append(out, routedBatch{addresses: plan.Platform, assetIDs: batch.AssetsFor(plan.Platform), executionMode: "async"})
	}
	// Skips are reported per observing sensor, not per address, so a sensor
	// that is down does not produce a thousand log lines. Ordered by first
	// appearance so the log reads the same for the same inventory.
	var skipOrder []uuid.UUID
	bySensor := map[uuid.UUID]*routedBatch{}
	for _, skip := range plan.Skipped {
		rb, ok := bySensor[skip.Sensor.ID]
		if !ok {
			s := skip
			rb = &routedBatch{skipped: &s, sensorName: skip.Sensor.Name}
			bySensor[skip.Sensor.ID] = rb
			skipOrder = append(skipOrder, skip.Sensor.ID)
		}
		rb.addresses = append(rb.addresses, skip.Target)
		rb.assetIDs = append(rb.assetIDs, batch.AssetsFor([]string{skip.Target})...)
	}
	for _, id := range skipOrder {
		out = append(out, *bySensor[id])
	}
	return out
}

// recordState writes the sweep's account of itself, refusals included. The
// refusal map is copied with zero counts dropped so the stored document only
// names reasons that actually fired, and an empty map is stored as absent.
func (j *AutoActiveScanJob) recordState(ctx context.Context, tenantID uuid.UUID, at time.Time, jobs, assets int, refusals map[sharedautoscan.Reason]int) {
	next := at.Add(j.sweepInterval)
	var recorded map[sharedautoscan.Reason]int
	for reason, n := range refusals {
		if n <= 0 {
			continue
		}
		if recorded == nil {
			recorded = map[sharedautoscan.Reason]int{}
		}
		recorded[reason] = n
	}
	if err := j.store.SetState(ctx, tenantID, autoscan.State{
		LastSweepAt:       &at,
		NextSweepAt:       &next,
		LastSweepJobs:     jobs,
		LastSweepAssets:   assets,
		LastSweepRefusals: recorded,
	}); err != nil {
		j.logger.Printf("ERROR: tenant %s: could not record the sweep: %v", tenantID, err)
	}
}

// formatRefusals renders the per-reason counts deterministically, so two log
// lines from the same inventory read the same.
func formatRefusals(refusals map[sharedautoscan.Reason]int) string {
	keys := make([]string, 0, len(refusals))
	for k := range refusals {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+strconv.Itoa(refusals[sharedautoscan.Reason(k)]))
	}
	return strings.Join(parts, " ")
}

// unscannableTenantStates are the `tenants.payment_status` values that stop the
// platform scanning an organization's network on its own initiative.
//
// Scanning is something we DO to a customer's estate, so the right question is
// not "can they still log in" but "is this still a live relationship". A
// cancelled account whose sensor is still running would otherwise be scanned by
// us forever — traffic they never agreed to, from a vendor they left. `suspended`
// is the same fact with a different cause.
//
// `past_due` is deliberately NOT here: they are a customer, they are late, and
// silently stopping the thing the product is for is a worse answer than the
// dunning flow they are already in. Values are from the
// `valid_payment_status` CHECK constraint on `tenants`.
var unscannableTenantStates = []string{"canceled", "suspended"}

// tenantScanEligibilitySQL is the one predicate both the enumerator and the
// per-tenant guard use, so the scheduled pass and the first-observation pass
// cannot come to disagree about who may be scanned.
const tenantScanEligibilitySQL = `t.deleted_at IS NULL AND COALESCE(t.payment_status, '') <> ALL($1)`

// tenantsToSweep enumerates the tenants with any asset that the platform may
// still scan.
//
// RLS: cross-tenant — runs on the bypass role. There is no tenant to thread
// here: finding out which tenants exist is the question.
func (j *AutoActiveScanJob) tenantsToSweep() ([]uuid.UUID, error) {
	if j.bypassDB == nil {
		return nil, nil
	}
	rows, err := j.bypassDB.Query(`
		SELECT DISTINCT a.tenant_id
		FROM assets a
		JOIN tenants t ON t.id = a.tenant_id
		WHERE a.deleted_at IS NULL AND `+tenantScanEligibilitySQL,
		pq.Array(unscannableTenantStates))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			continue
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// tenantIsScannable answers the same question for ONE tenant, for the
// first-observation pass — which acts on whatever the NATS consumer marked and
// never goes through the enumerator.
//
// RLS: cross-tenant — runs on the bypass role. `tenants` is not the calling
// tenant's own row from this worker's point of view; there is no session tenant
// to thread.
func (j *AutoActiveScanJob) tenantIsScannable(tenantID uuid.UUID) (bool, error) {
	if j.bypassDB == nil {
		return true, nil
	}
	var ok bool
	err := j.bypassDB.QueryRow(`
		SELECT EXISTS (SELECT 1 FROM tenants t WHERE t.id = $2 AND `+tenantScanEligibilitySQL+`)`,
		pq.Array(unscannableTenantStates), tenantID).Scan(&ok)
	if err != nil {
		return false, err
	}
	return ok, nil
}
