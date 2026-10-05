package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/nats-io/nats.go"
)

type JobProcessor struct {
	db *sqlx.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) handle used only by the
	// platform-wide `pollForStuckJobs` sweep, which scans queued jobs across
	// ALL tenants with no tenant filter. Under crypto_app that sweep FAILS
	// CLOSED (RLS returns zero rows); on the bypass handle it sees every
	// tenant's stuck jobs as intended.
	bypassDB         *sqlx.DB
	discoveryService *DiscoveryService
	rateLimiter      *RateLimiter
	alertService     *AlertService
	natsClient       *events.NATSClient
	subscriber       *events.Subscriber
	// ctx is the processor's lifetime. Every job's context derives from it
	// (never from the NATS handler's context — see Start), and Stop cancels it
	// with errProcessorStopping so a running job hands itself back.
	ctx    context.Context
	cancel context.CancelCauseFunc
	// leaseInterval is how often a running job's message is told InProgress
	// and its row's updated_at is touched; zero means jobLeaseInterval.
	// heartbeatLease is how stale that touch may get before the reaper fails
	// the job; zero means jobHeartbeatLease. touchJob, when set, replaces the
	// heartbeat write. All three are fields so a test can shorten or break them.
	leaseInterval  time.Duration
	heartbeatLease time.Duration
	touchJob       func(jobID string) (bool, error)
	// sweepTenant confines the stuck-job sweeps to one tenant (tests only;
	// see sweepScope).
	sweepTenant string
	// planEngineOptions are extra shared-engine options for scan-plan jobs
	// (work_unit_executor.go). Tests set a dialer here to see — and to stand in
	// for — every address the engine contacts; production sets nothing.
	planEngineOptions []shareddisc.Option
	// detachPlanJobs runs a claimed scan-plan job off the message handler (see
	// processDiscoveryJobByID). On in production; a processor built as a
	// literal (most tests) runs every job in the handler, synchronously.
	detachPlanJobs bool
	// units shares the replica's unit slots out between tenants
	// (unit_scheduler.go). Nil means unlimited (a processor built as a
	// literal).
	units *unitScheduler
	// inflight counts jobs being processed, so Stop can wait for them to hand
	// their rows back; stopping (under stopMu) refuses new ones.
	stopMu   sync.Mutex
	stopping bool
	inflight sync.WaitGroup
	// republished remembers this replica's recent republishes, so the
	// stuck-job poll does not stack copies of a job whose message is still
	// waiting in the stream (republishInterval, job_reaper.go).
	republishMu sync.Mutex
	republished map[string]republishMark
	// clock replaces time.Now for the republish memory (tests only).
	clock func() time.Time
}

// jobAckWait is how long JetStream waits for an ack before redelivering a job
// message, and jobLeaseInterval how often a running job resets that clock with
// InProgress. The interval must sit well under the wait: a missed beat or two
// (a GC pause, a slow NATS round trip) must not let the broker conclude the
// processor died and hand the job to another replica mid-scan.
const (
	jobAckWait       = 5 * time.Minute
	jobLeaseInterval = 1 * time.Minute
)

// jobHeartbeatLease is how long a `running` job's row may go without a
// heartbeat before the stuck-job poll fails it as abandoned (reapStalledJobs).
//
// Five heartbeats' worth. The owner touches the row every jobLeaseInterval
// from a goroutine the scan cannot block, and again at every host boundary, so
// a live job's row is never more than a minute old in steady state; four
// consecutive missed writes (a database failover, a long GC pause, a saturated
// pool) are tolerated before the job is declared dead. It equals jobAckWait, so
// a crashed owner's job is failed at about the time its message is redelivered
// — and that redelivery is a no-op either way. The cost is that a crashed job
// holds its tenant's concurrency slot for up to this long plus one poll.
const jobHeartbeatLease = 5 * time.Minute

// stopGrace bounds how long Stop waits for running jobs to notice the stop and
// put their rows back to queued. Kept under the pod's default 30s termination
// grace so the hand-back is written before the kill.
const stopGrace = 15 * time.Second

// errProcessorStopping is the cause the processor's context is cancelled with
// on shutdown. A job that sees it is not failed — it is put back to queued for
// the stuck-job sweep to republish, and resumes after its completed targets.
var errProcessorStopping = errors.New("job processor stopping")

// NewJobProcessor creates a new job processor using the shared NATSClient.
func NewJobProcessor(db, bypassDB *sqlx.DB, discoveryService *DiscoveryService, rateLimiter *RateLimiter, alertService *AlertService, natsClient *events.NATSClient) *JobProcessor {
	ctx, cancel := context.WithCancelCause(context.Background())
	return &JobProcessor{
		db:               db,
		bypassDB:         bypassDB,
		discoveryService: discoveryService,
		rateLimiter:      rateLimiter,
		alertService:     alertService,
		natsClient:       natsClient,
		subscriber:       events.NewSubscriber(natsClient),
		ctx:              ctx,
		cancel:           cancel,
		detachPlanJobs:   true,
		units:            newUnitScheduler(unitConcurrencyFromEnv()),
	}
}

// withTenantTxx runs fn inside a tenant-scoped sqlx transaction, preserving
// sqlx's helpers (Select/Get/Exec/QueryRow). Mirrors
// shareddatabase.WithTenantTx but yields a *sqlx.Tx; tenant context is set on
// the embedded *sql.Tx. tenantID is the string form carried on the job/finding.
func (jp *JobProcessor) withTenantTxx(ctx context.Context, tenantID string, fn func(*sqlx.Tx) error) error {
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return fmt.Errorf("invalid tenant_id: %w", err)
	}
	tx, err := jp.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("rls: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := shareddatabase.SetTenantContext(ctx, tx.Tx, tenantUUID); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (jp *JobProcessor) Start() {
	if jp.natsClient == nil || !jp.natsClient.IsConnected() {
		log.Printf("NATS client not available, job processor cannot start")
		return
	}

	// Subscribe to discovery jobs via JetStream with durable consumer.
	//
	// A job can run for hours; AckWait is not a job deadline and neither is
	// ProcessingTimeout. The handler keeps the message alive with InProgress
	// while the job runs (keepLeaseAlive) and does not hand the subscriber's
	// context to the scan — that context expires after ProcessingTimeout, and
	// a scan bound to it would be cut off at four minutes. What makes a
	// redelivery harmless anyway is the claim in processDiscoveryJobByID.
	err := jp.subscriber.Subscribe(events.SubscriptionConfig{
		Stream:            "DISCOVERY_JOBS",
		Subject:           events.SubjectDiscoveryJobsSubmit,
		Durable:           "discovery-job-processor",
		QueueGroup:        "cluster-sensor",
		MaxDeliver:        3,
		AckWait:           jobAckWait,
		ProcessingTimeout: 4 * time.Minute,
	}, jp.handleDiscoveryJobJS)
	if err != nil {
		log.Printf("Failed to subscribe to discovery jobs: %v", err)
		return
	}

	log.Println("Job processor started, listening for discovery jobs via JetStream...")

	// Start background poller to check for stuck queued jobs
	go jp.pollForStuckJobs()

	// Keep running until context is cancelled
	<-jp.ctx.Done()
}

// pollForStuckJobs periodically checks for queued jobs that haven't been processed
// and republishes them to NATS. This handles cases where jobs were published but
// failed to process due to temporary errors. It also fails `running` jobs whose
// owner stopped heartbeating (reapStalledJobs, job_reaper.go).
// Note: Only retries 'queued' jobs, not 'failed' jobs. Failed jobs have already
// been processed and marked as failed — retrying them indefinitely would cause
// duplicate notifications and spam downstream channels. A reaped job is failed
// too, and resumes only when a person retries it.
func (jp *JobProcessor) pollForStuckJobs() {
	ticker := time.NewTicker(30 * time.Second) // Check every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !jp.stuckJobPass(jp.republishJob) {
				continue
			}

			// Jobs handed to a tenant sensor that never collected the command,
			// refused it, or went quiet mid-run. Same cross-tenant sweep, same
			// bypass handle, same reason.
			jp.sweepStaleDispatches(jp.ctx)
		case <-jp.ctx.Done():
			return
		}
	}
}

// stuckJobPass is one tick of pollForStuckJobs before the sensor-dispatch
// sweep: fail abandoned running jobs, then republish queued ones. It reports
// false when the queued-job read failed, as the loop always has. A function of
// its own so a test can drive the wiring — publish is the NATS publish.
func (jp *JobProcessor) stuckJobPass(publish func(jobID string) error) bool {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). This is a
	// platform-wide background sweep across ALL tenants' queued jobs (no
	// tenant filter), so it cannot set a single app.tenant_id. Belongs
	// on bypassDB once the non-owner role split lands.
	// A `running` job whose owner stopped heartbeating (a crashed or
	// killed replica) is failed first, so it stops holding a
	// concurrency slot and a person can Retry it.
	jp.reapStalledJobs(publish)

	queued, err := jp.findQueuedJobsToRepublish()
	if err != nil {
		log.Printf("Error checking for stuck jobs: %v", err)
		return false
	}

	// A job republished within republishInterval that nobody has touched
	// since already has a message in the stream; another copy adds nothing.
	stuckJobs := jp.republishDue(queued)
	if len(stuckJobs) > 0 {
		log.Printf("Found %d stuck queued jobs, republishing to NATS...", len(stuckJobs))
		for _, job := range stuckJobs {
			if err := publish(job.ID); err != nil {
				log.Printf("Failed to republish job %s: %v", job.ID, err)
			} else {
				jp.markRepublished(job)
				log.Printf("Republished stuck job %s to NATS", job.ID)
			}
		}
	}
	return true
}

func (jp *JobProcessor) republishJob(jobID string) error {
	return events.PublishJSON(jp.natsClient, events.SubjectDiscoveryJobsSubmit, events.DiscoveryJobEvent{
		JobID: jobID,
	})
}

func (jp *JobProcessor) Stop() {
	log.Println("Stopping job processor...")
	jp.stopMu.Lock()
	jp.stopping = true
	jp.stopMu.Unlock()
	jp.cancel(errProcessorStopping)

	// Give a running job the chance to put its row back to queued. Without
	// this wait the process exits before it is written and the job is left
	// `running` with nothing running it, until the stuck-job reaper fails it a
	// heartbeat lease later — and a failed job resumes only on a person's Retry.
	done := make(chan struct{})
	go func() { jp.inflight.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(stopGrace):
		log.Printf("Job processor: a running job did not hand itself back within %s; it stays 'running' until the reaper fails it (%s without a heartbeat)", stopGrace, jobHeartbeatLease)
	}

	if jp.subscriber != nil {
		if err := jp.subscriber.Drain(); err != nil {
			log.Printf("Job processor: draining NATS subscriber failed: %v", err)
		}
	}
}

// handleDiscoveryJobJS processes discovery jobs from JetStream with ack/nack.
//
// The subscriber's ctx is deliberately unused: it expires after
// ProcessingTimeout, and a job is allowed to run far longer (see Start).
func (jp *JobProcessor) handleDiscoveryJobJS(_ context.Context, msg *nats.Msg) error {
	return jp.handleDiscoveryJob(msg, msg)
}

// messageLease is the one *nats.Msg method that keeps a delivery from being
// redelivered while it is still being worked on. An interface so a test can
// count the beats.
type messageLease interface {
	InProgress(opts ...nats.AckOpt) error
}

// handleDiscoveryJob runs one delivery of a job message, holding its lease for
// as long as the job runs.
func (jp *JobProcessor) handleDiscoveryJob(msg *nats.Msg, lease messageLease) error {
	var jobEvent events.DiscoveryJobEvent
	if err := events.UnmarshalMsg(msg, &jobEvent); err != nil {
		log.Printf("Failed to unmarshal discovery job event: %v", err)
		return nil // Don't redeliver bad data
	}
	stop := jp.keepLeaseAlive(lease, jobEvent.JobID)
	defer stop()
	return jp.processDiscoveryJobByID(jobEvent.JobID)
}

// keepLeaseAlive tells the broker every leaseInterval that this delivery is
// still being worked on, until the returned func is called ( H1).
//
// Without it a job that outlived AckWait (5 minutes) was redelivered while it
// was still running, and the redelivery scanned every target again. The claim
// in processDiscoveryJobByID is what guarantees a redelivery cannot re-scan;
// this keeps the broker from making one at all while the processor is alive,
// so the delivery stays with the replica that is running the job and is acked
// once, when the job has ended.
func (jp *JobProcessor) keepLeaseAlive(lease messageLease, jobID string) func() {
	interval := jp.leaseInterval
	if interval <= 0 {
		interval = jobLeaseInterval
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := lease.InProgress(); err != nil {
					log.Printf("Discovery job %s: could not extend the message lease (the broker may redeliver it; the claim keeps that from re-scanning): %v", jobID, err)
				}
				// The database half of the heartbeat, which the reaper reads.
				// Only while THIS replica runs the job: a duplicate delivery
				// held here must not vouch for a job another replica owns.
				if jp.discoveryService != nil && jp.discoveryService.runningJobs().has(jobID) {
					jp.heartbeat(jobID)
				}
			case <-done:
				return
			}
		}
	}()
	return func() {
		close(done)
		wg.Wait()
	}
}

// heartbeat touches a running job's updated_at, which is what tells the
// stuck-job reaper the job still has a live owner. It reports whether the row
// is still `running`. A failed write is logged and otherwise ignored: losing
// one beat must not stop a scan — the lease allows several.
func (jp *JobProcessor) heartbeat(jobID string) bool {
	touch := jp.touchJob
	if touch == nil {
		touch = jp.discoveryService.TouchRunningJob
	}
	running, err := touch(jobID)
	if err != nil {
		log.Printf("Discovery job %s: heartbeat write failed, scan continues: %v", jobID, err)
		return false
	}
	return running
}

// lifetime is the processor's context, or Background for a processor built
// as a literal (tests).
func (jp *JobProcessor) lifetime() context.Context {
	if jp.ctx == nil {
		return context.Background()
	}
	return jp.ctx
}

// enter registers a job as in flight, or refuses it once Stop has begun.
func (jp *JobProcessor) enter() bool {
	jp.stopMu.Lock()
	defer jp.stopMu.Unlock()
	if jp.stopping {
		return false
	}
	jp.inflight.Add(1)
	return true
}

func (jp *JobProcessor) processDiscoveryJobByID(jobID string) error {
	if !jp.enter() {
		// Nak: another replica (or this one, restarted) takes it.
		return fmt.Errorf("job processor stopping; not starting job %s", jobID)
	}
	defer jp.inflight.Done()
	log.Printf("Processing discovery job: %s", jobID)

	// Get job details
	job, err := jp.discoveryService.GetJob(jobID)
	if err != nil {
		return fmt.Errorf("failed to get job %s: %w", jobID, err)
	}

	// A job that is not queued is already being run, has been handed to its
	// sensor, or has ended: this delivery is a duplicate (a broker redelivery,
	// the stuck-job sweep's republish, a second replica's copy) and must not
	// scan or dispatch anything. Cheap early exit only — ClaimJob below, and
	// for a `sensors` job the dispatcher's conditional UPDATE, are what
	// actually decide, atomically. It used to skip `sensors` jobs, so every
	// duplicate of a dispatched one ran the rate-limit check and the dispatch
	// transaction and then logged itself as a failed dispatch.
	if job.Status != "queued" {
		log.Printf("Discovery job %s is %s, not queued — duplicate or late delivery, nothing to do", jobID, job.Status)
		return nil
	}

	// Check rate limits
	err = jp.rateLimiter.CheckRateLimit(job.TenantID)
	if err != nil {
		log.Printf("Rate limit exceeded for tenant %s: %v", job.TenantID, err)
		errorMsg := err.Error()
		// Only a job still queued is failed for this: a duplicate delivery that
		// trips the limit must not fail the copy another replica is running.
		statusErr := jp.discoveryService.UpdateJobStatusFrom(jobID, "failed", &errorMsg, "queued")
		if errors.Is(statusErr, ErrJobStatusConflict) {
			log.Printf("Job %s left the queue before the rate-limit verdict landed: %v", jobID, statusErr)
			return nil
		}
		if statusErr != nil {
			log.Printf("Failed to mark job %s failed after rate limit — job may be stuck in its previous state: %v", jobID, statusErr)
		}
		if alertErr := jp.alertService.SendRateLimitExceededAlert(job.TenantID); alertErr != nil {
			log.Printf("Failed to send rate-limit alert for tenant %s: %v", job.TenantID, alertErr)
		}
		return nil // Permanent failure, don't redeliver
	}

	// A `sensors` job is handed to the tenant's sensor, not run here. The
	// dispatcher records the outcome on the row (awaiting_sensor, or failed
	// with the reason) and the sensor's completion callback finishes it; this
	// processor must not touch its status again, or a dispatched job would be
	// marked completed by a scan that never ran.
	if isSensorExecutionMode(job.ExecutionMode) {
		return jp.dispatchToSensor(job)
	}

	// Claim the job: queued → running in one conditional UPDATE ( H1).
	// Exactly one delivery wins; every other — redelivered, republished, or
	// racing on another replica — finds it no longer queued and scans nothing.
	claimed, err := jp.discoveryService.ClaimJob(jobID)
	if err != nil {
		return fmt.Errorf("failed to claim job: %w", err)
	}
	if !claimed {
		log.Printf("Discovery job %s was claimed elsewhere or has ended; this delivery does nothing", jobID)
		return nil
	}

	// A scan-plan job can run for hours, and the subscription hands this
	// replica one message at a time: run in the handler, it would hold every
	// other job delivered here — any tenant's — until it ended ( WP2,
	// item 9). Once claimed it no longer needs its message: the claim makes a
	// redelivery a no-op, the row's heartbeat and the stuck-job reaper cover a
	// crash, and Stop hands it back to the queue. So it runs on its own and the
	// delivery is acked; the units it runs are what the unit scheduler shares
	// out between tenants (unit_scheduler.go).
	if job.Plan != nil && jp.detachPlanJobs {
		jp.inflight.Add(1)
		go func() {
			defer jp.inflight.Done()
			stop := jp.keepLeaseAlive(noLease{}, jobID)
			defer stop()
			if err := jp.runClaimedJob(job); err != nil {
				log.Printf("Discovery job %s: %v", jobID, err)
			}
		}()
		return nil
	}
	return jp.runClaimedJob(job)
}

// noLease is the message lease of a job that no longer holds its message: the
// heartbeat ticker still touches the row, there is nothing to extend.
type noLease struct{}

func (noLease) InProgress(...nats.AckOpt) error { return nil }

// runClaimedJob runs a job this processor has claimed, to its end: the scan,
// then the guarded transition to completed, failed, or back to queued.
func (jp *JobProcessor) runClaimedJob(job *models.DiscoveryJob) error {
	jobID := job.ID

	// The job's own context: cancelled by a cancel of this job (CancelJob, via
	// the registry) or by Stop. Derived from the processor's lifetime, never
	// from the NATS handler's context, whose ProcessingTimeout would otherwise
	// become the deadline of every scan.
	jobCtx, release := jp.discoveryService.runningJobs().start(jp.lifetime(), jobID)
	defer release()

	// Process the job
	err := jp.processDiscoveryJob(jobCtx, job)
	if errors.Is(err, dispatchguard.ErrPaused) || errors.Is(err, errProcessorStopping) {
		// Back to the queue, from running only: a cancel that landed meanwhile
		// stays a cancel. The stuck-job sweep republishes it and the next run
		// skips the targets this one completed.
		if statusErr := jp.discoveryService.UpdateJobStatusFrom(jobID, "queued", nil, "running"); statusErr != nil && !errors.Is(statusErr, ErrJobStatusConflict) {
			return statusErr
		}
		return nil
	}
	if errors.Is(err, errJobNoLongerRunning) {
		// Cancelled (here or on another replica). The row already says so;
		// nothing to write and nothing to announce.
		log.Printf("Discovery job %s stopped: %v", jobID, err)
		return nil
	}
	if err != nil {
		log.Printf("Failed to process job %s: %v", jobID, err)
		errorMsg := err.Error()
		statusErr := jp.discoveryService.UpdateJobStatus(jobID, "failed", &errorMsg)
		if errors.Is(statusErr, ErrJobStatusConflict) {
			log.Printf("Job %s ended before its failure could be recorded: %v", jobID, statusErr)
			return nil
		}
		if statusErr != nil {
			log.Printf("Failed to mark job %s failed — job may be stuck in 'running': %v", jobID, statusErr)
		}
		if alertErr := jp.alertService.SendJobFailedAlert(job.TenantID, jobID, err.Error()); alertErr != nil {
			log.Printf("Failed to send job-failed alert for job %s: %v", jobID, alertErr)
		}
		return nil // Job marked as failed, don't redeliver
	}

	// Update job status to completed — refused if the job was cancelled after
	// its last target, so a late success never overwrites a cancel.
	err = jp.discoveryService.UpdateJobStatus(jobID, "completed", nil)
	if errors.Is(err, ErrJobStatusConflict) {
		log.Printf("Job %s finished scanning but had already ended: %v", jobID, err)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to update job status: %w", err)
	}

	if alertErr := jp.alertService.SendJobCompletedAlert(job.TenantID, jobID); alertErr != nil {
		log.Printf("Failed to send job-completed alert for job %s: %v", jobID, alertErr)
	}
	log.Printf("Discovery job %s completed successfully", jobID)
	return nil
}

// getJobOptions reads scanning options from the job's metadata JSONB.
// RLS-scoped read over discovery_jobs; tenantID is threaded from the job so the
// read runs inside a tenant-scoped transaction.
func (jp *JobProcessor) getJobOptions(tenantID, jobID string) (map[string]interface{}, error) {
	var metadataJSON []byte
	err := jp.withTenantTxx(context.Background(), tenantID, func(tx *sqlx.Tx) error {
		return tx.Get(&metadataJSON, `SELECT COALESCE(metadata, '{}'::jsonb) FROM discovery_jobs WHERE id = $1`, jobID)
	})
	if err != nil {
		return nil, err
	}
	if len(metadataJSON) == 0 {
		return nil, nil
	}
	var metadata map[string]interface{}
	if err := json.Unmarshal(metadataJSON, &metadata); err != nil {
		return nil, err
	}
	if opts, ok := metadata["options"].(map[string]interface{}); ok {
		return opts, nil
	}
	if metadata["options"] != nil {
		return nil, fmt.Errorf("invalid discovery job options")
	}
	return nil, nil
}

func (jp *JobProcessor) processDiscoveryJob(ctx context.Context, job *models.DiscoveryJob) error {
	// Check execution mode - cloud jobs should be handled by device-interrogation-service
	if job.ExecutionMode == "cloud" {
		log.Printf("Job %s is a cloud discovery job, delegating to device-interrogation-service", job.ID)
		return jp.delegateToDeviceInterrogation(job)
	}

	// "sensors" means "run this from a tenant-deployed sensor", and the
	// dispatcher (sensor_dispatcher.go) is where such a job goes —
	// processDiscoveryJobByID routes it there before this function is ever
	// called. This branch is the last line: before the dispatcher existed, a
	// `sensors` job fell through to the in-cluster scan path below, the scan
	// ran from the platform cluster, could not reach a target only the
	// tenant's sensor can see, and the job finished `completed` with zero
	// findings and no indication the sensor was never involved. Any `sensors`
	// row that reaches this path — a future caller that forgets the routing,
	// a retry that skips it — must FAIL, never run somewhere the caller did
	// not ask for. Mutation-tested: TestProcessDiscoveryJob_FailsSensorExecutionMode.
	if isSensorExecutionMode(job.ExecutionMode) {
		log.Printf("Job %s asked for a tenant sensor but reached the in-cluster scan path unassigned; failing rather than running it from the cluster", job.ID)
		return fmt.Errorf("execution_mode \"sensors\": this job asked to run on a tenant-deployed sensor but reached the " +
			"in-cluster scan path; it was not run from the platform. Re-create the job to dispatch it again")
	}

	// Read scanning options from job metadata
	opts, err := jp.getJobOptions(job.TenantID, job.ID)
	if err != nil {
		return fmt.Errorf("read discovery job policy markers: %w", err)
	}

	// If active scanning is explicitly disabled, skip all scanning
	if activeScanning, ok := opts["active_scanning"].(bool); ok && !activeScanning {
		log.Printf("Active scanning disabled for job %s, skipping all probes", job.ID)
		return nil
	}

	// A scan-plan job runs on the shared engine, one durable unit per
	// address (work_unit_executor.go). It is the only kind of scan this
	// processor runs.
	if job.Plan != nil {
		return jp.processPlanJob(ctx, job, opts)
	}

	// Anything else is a protocols × ports job, and the platform has no
	// executor for one any more ( WP5): CreateJob translates every such
	// request into a plan and creates the legacy shape only for a tenant
	// sensor that cannot run a plan, which the dispatcher above hands to that
	// sensor rather than this path. A row that still reaches here (created by
	// an older release and queued across the upgrade) is FAILED with a reason
	// a person can act on, never completed with nothing scanned.
	// Mutation-tested: TestProcessDiscoveryJob_FailsALegacyPlatformJob.
	log.Printf("Job %s is a protocols × ports job with no scan plan; the platform no longer runs that shape — failing it", job.ID)
	return errLegacyPlatformJob
}

// errLegacyPlatformJob is the failure of a platform job that carries no scan
// plan. Its text is what the person reads in Discovery Jobs.
var errLegacyPlatformJob = errors.New("this job was created in the protocols × ports shape, which the platform no longer runs: " +
	"every scan now runs on the shared scan engine. Nothing was scanned. Run the scan again to create it as a planned job")

// delegateToDeviceInterrogation creates device_jobs for cloud discovery
// to be processed by device-interrogation-service
func (jp *JobProcessor) delegateToDeviceInterrogation(job *models.DiscoveryJob) error {
	// device_jobs and discovery_jobs are both RLS-scoped; the whole delegation
	// (existence check, metadata read, insert) runs inside one tenant-scoped
	// transaction keyed by job.TenantID so app.tenant_id is set on the same
	// connection as every query.
	var deviceJobID, integrationID string
	skip := false
	err := jp.withTenantTxx(context.Background(), job.TenantID, func(tx *sqlx.Tx) error {
		// Check if a device_job already exists for this discovery_job
		// This prevents duplicate device_jobs when device-interrogation-service
		// has already created one via /cloud/discover endpoint
		var existingJobID string
		checkQuery := `SELECT id FROM device_jobs WHERE parameters->>'discovery_job_id' = $1 LIMIT 1`
		if e := tx.QueryRow(checkQuery, job.ID).Scan(&existingJobID); e == nil {
			// A device_job already exists for this discovery_job
			log.Printf("⚠️ Device_job %s already exists for discovery job %s, skipping delegation", existingJobID, job.ID)
			skip = true
			return nil
		}
		// If error is sql.ErrNoRows, continue to create the device_job
		// For any other error, fall through and try to create (best effort)

		// Get metadata from discovery_jobs table
		var metadata []byte
		query := `SELECT COALESCE(metadata, '{}'::jsonb) FROM discovery_jobs WHERE id = $1`
		if e := tx.QueryRow(query, job.ID).Scan(&metadata); e != nil {
			return fmt.Errorf("failed to get job metadata: %w", e)
		}

		var meta map[string]interface{}
		if e := json.Unmarshal(metadata, &meta); e != nil {
			return fmt.Errorf("failed to parse job metadata: %w", e)
		}

		integrationID, _ = meta["integration_id"].(string)
		if integrationID == "" {
			return fmt.Errorf("no integration_id in job metadata for cloud discovery")
		}

		// Parse integration UUID
		integrationUUID := integrationID // Already a string

		// Create device_job for device-interrogation-service
		// Set parameters with discovery job context
		parameters := map[string]interface{}{
			"discovery_job_id": job.ID,
			"resource_types":   meta["resource_types"],
			"regions":          meta["regions"],
		}
		parametersJSON, e := json.Marshal(parameters)
		if e != nil {
			return fmt.Errorf("failed to marshal parameters: %w", e)
		}

		insertQuery := `
			INSERT INTO device_jobs (tenant_id, job_type, integration_id, parameters, status, created_at, updated_at)
			VALUES ($1, 'cloud_discovery', $2, $3, 'pending', NOW(), NOW())
			RETURNING id`

		if e := tx.QueryRow(insertQuery, job.TenantID, integrationUUID, parametersJSON).Scan(&deviceJobID); e != nil {
			return fmt.Errorf("failed to create device_job: %w", e)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if skip {
		return nil
	}

	log.Printf("✅ Created device_job %s for cloud discovery job %s (integration: %s)", deviceJobID, job.ID, integrationID)

	// The device-interrogation-service's platform agent worker will pick up this job
	// and update the discovery_job status when complete
	return nil
}

// stopReason reports why a job's context ended — errJobNoLongerRunning for a
// cancel, errProcessorStopping for shutdown — or nil while it is live.
func stopReason(ctx context.Context) error {
	if ctx.Err() == nil {
		return nil
	}
	cause := context.Cause(ctx)
	if errors.Is(cause, errJobNoLongerRunning) || errors.Is(cause, errProcessorStopping) {
		return cause
	}
	return fmt.Errorf("%w: %v", errProcessorStopping, cause)
}

// isJobStop reports whether err means "stop this job now", as opposed to a
// failure of one target.
func isJobStop(err error) bool {
	return errors.Is(err, errJobNoLongerRunning) || errors.Is(err, errProcessorStopping)
}

// checkStillRunning is the between-targets and between-hosts cancel check
// ( H2). The context covers a cancel handled on this replica and
// shutdown; the row covers a cancel handled by ANOTHER replica, whose
// registry cannot reach this process. One indexed read per host. Only an ENDED
// job stops the scan — the row is cancelled (or otherwise terminal), and
// nothing this run writes can change that.
//
// A failed read does not stop the scan: hours of work are not thrown away for
// one dropped query, and a cancel that lands meanwhile is still final —
// terminal states are sticky, so this run cannot overwrite it.
func (jp *JobProcessor) checkStillRunning(ctx context.Context, job *models.DiscoveryJob) error {
	if err := stopReason(ctx); err != nil {
		return err
	}
	// Each boundary is also a heartbeat. A row still `running` needs no read.
	if jp.heartbeat(job.ID) {
		return nil
	}
	var status string
	err := jp.withTenantTxx(context.Background(), job.TenantID, func(tx *sqlx.Tx) error {
		return tx.Get(&status, `SELECT status FROM discovery_jobs WHERE id = $1`, job.ID)
	})
	if err != nil {
		log.Printf("Discovery job %s: could not re-check status, continuing: %v", job.ID, err)
		return nil
	}
	for _, terminal := range terminalJobStatuses {
		if status == terminal {
			return fmt.Errorf("%w: it is now %s", errJobNoLongerRunning, status)
		}
	}
	return nil
}

// platformSensorIDTx returns the tenant's system "Platform Discovery Sensor" id
// (registered by cluster-sensor's auto-registration with profile='discovery' +
// 'system' tag), reading inside the caller's tenant-scoped transaction. Used as
// the sensor_id when mirroring active-scan findings into sensor_discoveries.
func (jp *JobProcessor) platformSensorIDTx(tx *sqlx.Tx, tenantID string) (string, error) {
	var id string
	err := tx.QueryRow(
		`SELECT id FROM sensors WHERE tenant_id = $1 AND profile = 'discovery' AND 'system' = ANY(tags) LIMIT 1`,
		tenantID,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("platform discovery sensor not found for tenant %s: %w", tenantID, err)
	}
	return id, nil
}
