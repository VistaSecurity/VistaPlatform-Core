package processor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/nats-io/nats.go"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/client"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// DiscoveryProcessor drains the sensor_discoveries queue.
//
// Every writer of that table publishes discovery.queue.ready after its
// transaction commits ( WP1); each message wakes ONE drain, which claims
// and processes batches until none is claimable. A DB poll every
// DISCOVERY_POLL_INTERVAL (default 60s, decision D6) is the fallback for a
// lost message, a writer that could not publish, and a row whose retry
// backoff has expired.
type DiscoveryProcessor struct {
	db             *sqlx.DB
	bypassDB       *sqlx.DB
	batchProcessor *BatchProcessor
	config         *config.Config
	natsClient     *events.NATSClient
	subscriber     *events.Subscriber
	stopChan       chan struct{}
	// wake carries one pending drain request. Buffered to one so a burst of
	// messages coalesces into a single drain — the drain takes everything
	// claimable anyway — and so the NATS handler never blocks on it.
	wake chan struct{}
	// processBatch and recordBatchFailure are the batch processor's two
	// entry points, as fields so a test can drive the drain loop against a
	// real claim query with a stand-in batch.
	processBatch       func(batchID string, tenantID uuid.UUID, claimedAt time.Time) error
	recordBatchFailure func(ctx context.Context, tenantID uuid.UUID, batchID string, claimedAt time.Time, cause error) (int, error)
}

// NewDiscoveryProcessor creates a new discovery processor.
//
// bypassDB is the BYPASSRLS handle (crypto_bypass role) used solely by the
// cross-tenant batch poller (processNextBatch), which scans sensor_discoveries
// across all tenants and cannot set app.tenant_id because the tenant is the
// query OUTPUT. All per-tenant work stays on the RLS-scoped primary db handle.
func NewDiscoveryProcessor(
	db *sqlx.DB,
	bypassDB *sqlx.DB,
	batchProcessor *BatchProcessor,
	cfg *config.Config,
) *DiscoveryProcessor {
	// Initialize NATS for event-driven processing
	var natsClient *events.NATSClient
	var subscriber *events.Subscriber
	nc, err := events.NewNATSClient("")
	if err != nil {
		log.Printf("[DiscoveryProcessor] WARNING: NATS unavailable — discoveries will wait for the %ds fallback poll: %v", cfg.PollIntervalSeconds, err)
	} else {
		natsClient = nc
		subscriber = events.NewSubscriber(nc)
	}

	// The retry budget for a failed ROW ( F14). DISCOVERY_MAX_RETRIES
	// keeps its meaning — attempts before giving up — but now counts per row
	// across wakes, recorded in sensor_discoveries.process_attempts, rather
	// than in-process sleeps against a whole batch.
	batchProcessor.SetRetryPolicy(RetryPolicy{
		MaxAttempts: cfg.MaxRetries,
		BackoffBase: time.Duration(cfg.RetryBackoffBase) * time.Second,
	})

	return &DiscoveryProcessor{
		db:                 db,
		bypassDB:           bypassDB,
		batchProcessor:     batchProcessor,
		config:             cfg,
		natsClient:         natsClient,
		subscriber:         subscriber,
		stopChan:           make(chan struct{}),
		wake:               make(chan struct{}, 1),
		processBatch:       batchProcessor.ProcessClaimedBatch,
		recordBatchFailure: batchProcessor.RecordBatchFailure,
	}
}

// queueReadySubscription is the processor's consumer of the wake-up subject.
// A durable in a queue group: with several replicas each message wakes one of
// them, and the others still drain on their own polls.
func queueReadySubscription() events.SubscriptionConfig {
	return events.SubscriptionConfig{
		Stream:     "DISCOVERY_QUEUE",
		Subject:    events.SubjectDiscoveryQueueReady,
		Durable:    "discovery-processor-queue-ready",
		QueueGroup: "discovery-processor",
		MaxDeliver: 3,
		AckWait:    30 * time.Second,
		// The handler only signals the drain loop, so it returns in
		// microseconds; it never holds the message while batches run.
		ProcessingTimeout: 5 * time.Second,
	}
}

// legacyPollTriggerDurable is the consumer this service used to wake on, on
// cluster-sensor's discovery.jobs.submit ( F10). Nothing binds it any
// more; deleted at start so it does not sit on the DISCOVERY_JOBS stream
// collecting every scan-job message forever.
const legacyPollTriggerDurable = "discovery-processor-poll-trigger"

// handleQueueReady is the NATS handler: request a drain and ack. Never blocks.
func (p *DiscoveryProcessor) handleQueueReady(context.Context, *nats.Msg) error {
	p.requestDrain()
	return nil
}

// requestDrain asks the processing loop for a drain. A drain already pending
// absorbs the request: it will take everything claimable, this batch included.
func (p *DiscoveryProcessor) requestDrain() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// pollInterval is the fallback poll's period.
func (p *DiscoveryProcessor) pollInterval() time.Duration {
	if p.config.PollIntervalSeconds <= 0 {
		return 60 * time.Second
	}
	return time.Duration(p.config.PollIntervalSeconds) * time.Second
}

// Start subscribes to discovery.queue.ready and runs the processing loop:
// one drain per wake, and one per fallback poll tick.
func (p *DiscoveryProcessor) Start() error {
	if p.subscriber != nil {
		if js := p.natsClient.JetStream(); js != nil {
			switch err := js.DeleteConsumer("DISCOVERY_JOBS", legacyPollTriggerDurable); {
			case err == nil:
				log.Printf("[DiscoveryProcessor] Deleted the legacy %s consumer on DISCOVERY_JOBS (this service now wakes on %s)", legacyPollTriggerDurable, events.SubjectDiscoveryQueueReady)
			case errors.Is(err, nats.ErrConsumerNotFound), errors.Is(err, nats.ErrStreamNotFound):
			default:
				log.Printf("[DiscoveryProcessor] Could not delete the legacy %s consumer (harmless): %v", legacyPollTriggerDurable, err)
			}
		}
		if err := p.subscriber.Subscribe(queueReadySubscription(), p.handleQueueReady); err != nil {
			log.Printf("[DiscoveryProcessor] WARNING: failed to subscribe to %s: %v. Discoveries will wait for the %v fallback poll.", events.SubjectDiscoveryQueueReady, err, p.pollInterval())
		} else {
			log.Printf("[DiscoveryProcessor] Subscribed to %s", events.SubjectDiscoveryQueueReady)
		}
	}

	ticker := time.NewTicker(p.pollInterval())
	defer ticker.Stop()

	fmt.Printf("Discovery processor started (fallback poll interval: %v)\n", p.pollInterval())

	// Whatever is already queued is drained at once, not a poll interval
	// from now.
	p.requestDrain()
	for {
		select {
		case <-p.stopChan:
			fmt.Println("Discovery processor stopping...")
			return nil
		case <-p.wake:
			p.drain()
		case <-ticker.C:
			p.drain()
		}
	}
}

// maxBatchesPerDrain bounds one drain. A backlog larger than this is drained
// in several passes: the loop yields (so Stop is honoured) and immediately
// requests the next pass.
const maxBatchesPerDrain = 500

// drain claims and processes batches until none is claimable, and reports
// how many it processed. It used to be one batch per trigger ( F1): a
// writer's burst of N batches waited N triggers — N poll ticks, at 15 s each,
// for every writer that published nothing.
func (p *DiscoveryProcessor) drain() int {
	n := 0
	for n < maxBatchesPerDrain {
		select {
		case <-p.stopChan:
			return n
		default:
		}
		claimed, err := p.processNextBatch()
		if err != nil {
			// The claim or the failure record could not be written — the
			// database is the problem, and hammering it helps nobody. The
			// next wake or poll tries again.
			fmt.Printf("Error processing batch: %v\n", err)
			return n
		}
		if !claimed {
			return n
		}
		n++
	}
	// More may be waiting: yield, then carry on.
	p.requestDrain()
	return n
}

// Stop stops the processing loop
func (p *DiscoveryProcessor) Stop() {
	close(p.stopChan)
	if p.subscriber != nil {
		if err := p.subscriber.Drain(); err != nil {
			log.Printf("Discovery processor: draining NATS subscriber failed: %v", err)
		}
	}
	if p.natsClient != nil {
		p.natsClient.Close()
	}
}

// batchClaimTimeout is how long a claim on a batch is honoured before another
// worker may take it over. It bounds the damage from a worker that crashes
// mid-batch: without a timeout, its claim would strand the batch forever.
// A worker that is alive renews the claim before every import chunk (see
// claim.go), so the timeout only ever releases a dead one. A row that fails
// has its claim released early, with a backoff (see recordRowFailures).
// A var only so a test can use a short one.
var batchClaimTimeout = 10 * time.Minute

// batchClaimRowLimit bounds how many rows one claim takes, and so how many one
// read pulls into memory. A batch with more is claimed in several consecutive
// claims, oldest rows first: the unclaimed remainder stays claimable, and the
// drain loop takes it next. A var so a test can use a small bound.
var batchClaimRowLimit = 1000

// claimAttempts is how many times processNextBatch re-runs the claim after
// losing a race for its candidate before deciding there is nothing to do.
const claimAttempts = 3

// claimNextBatchQuery picks the batch holding the OLDEST claimable row and
// claims up to $2 of that batch's oldest claimable rows, in one statement. The
// final SELECT returns the candidate even when the claim took nothing (another
// worker won the race for it): batch_id comes back with a NULL stamp, which is
// how "lost the race" is told apart from "nothing claimable" (no row at all).
//
// Candidates were once `GROUP BY ... LIMIT 1` with no ORDER BY, so which batch
// was picked was arbitrary and a busy tenant could starve an old one; and a
// lost race returned no rows, which drain read as an empty queue and stopped.
const claimNextBatchQuery = `
	WITH candidate AS (
		SELECT batch_id, tenant_id
		FROM sensor_discoveries
		WHERE processed_at IS NULL
		  AND (claimed_at IS NULL OR claimed_at < now() - $1::interval)
		GROUP BY batch_id, tenant_id
		ORDER BY min(created_at), batch_id
		LIMIT 1
	),
	taken AS (
		SELECT x.tenant_id, x.id
		FROM sensor_discoveries x
		JOIN candidate c ON x.tenant_id = c.tenant_id AND x.batch_id = c.batch_id
		WHERE x.processed_at IS NULL
		  AND (x.claimed_at IS NULL OR x.claimed_at < now() - $1::interval)
		ORDER BY x.created_at, x.id
		LIMIT $2
	),
	claimed AS (
		UPDATE sensor_discoveries d
		SET claimed_at = now()
		FROM taken t
		WHERE d.tenant_id = t.tenant_id
		  AND d.id = t.id
		  AND d.processed_at IS NULL
		  AND (d.claimed_at IS NULL OR d.claimed_at < now() - $1::interval)
		RETURNING d.batch_id, d.tenant_id, d.claimed_at
	)
	-- Every row the UPDATE took carries the same claimed_at (now() is the
	-- statement's transaction timestamp); it is the claim's identity, and
	-- ProcessClaimedBatch reads exactly the rows that carry it.
	SELECT c.batch_id, c.tenant_id, max(k.claimed_at)
	FROM candidate c
	LEFT JOIN claimed k ON k.batch_id = c.batch_id AND k.tenant_id = c.tenant_id
	GROUP BY c.batch_id, c.tenant_id
`

// claimNextBatch claims the next batch. found is false only when no batch is
// claimable at all; a lost race is retried, so it never reads as an empty queue.
//
// RLS: cross-tenant — runs on the bypass role (Phase 4). This is the batch
// poller: it scans sensor_discoveries (security_invoker view) across ALL
// tenants for any unprocessed batch, grouping by (batch_id, tenant_id). It
// cannot set app.tenant_id because the tenant is the query OUTPUT — the very
// thing we are discovering. The resolved tenantID is then threaded into the
// per-tenant ProcessBatch, which is RLS-scoped. Run on the BYPASSRLS handle
// (crypto_bypass) directly — no WithTenantTx; under the enforcing crypto_app
// role this query would fail closed (RLS hides every row with no app.tenant_id).
func (p *DiscoveryProcessor) claimNextBatch() (batchID string, tenantID uuid.UUID, claimedAt time.Time, found bool, err error) {
	claimInterval := fmt.Sprintf("%d seconds", int(batchClaimTimeout.Seconds()))
	for attempt := 0; attempt < claimAttempts; attempt++ {
		var stamp sql.NullTime
		scanErr := p.bypassDB.QueryRow(claimNextBatchQuery, claimInterval, batchClaimRowLimit).Scan(&batchID, &tenantID, &stamp)
		if errors.Is(scanErr, sql.ErrNoRows) {
			return "", uuid.Nil, time.Time{}, false, nil // nothing claimable
		}
		if scanErr != nil {
			return "", uuid.Nil, time.Time{}, false, fmt.Errorf("failed to claim unprocessed batch: %w", scanErr)
		}
		if stamp.Valid {
			return batchID, tenantID, stamp.Time, true, nil
		}
		// Another worker claimed the candidate between our pick and our update.
		// Pick again: the next candidate is whatever is still claimable.
	}
	// Every attempt lost a race: work exists and other workers are taking it.
	// Not an empty queue; the next wake or poll continues.
	return "", uuid.Nil, time.Time{}, false, nil
}

// processNextBatch claims and processes the next unprocessed batch.
//
// It reports whether it claimed a batch, so drain knows when to stop.
//
// The claim is what makes concurrent triggers safe. With more than one
// replica, every replica's drain runs this concurrently. Selecting on `processed_at IS NULL`
// alone let two of those pick the same batch and run it twice — duplicate
// imports and double-incremented observation counts, because rows are only
// stamped processed at the END of ProcessBatch. The claim is one statement:
// two workers racing on the same candidate serialize on the row locks, the
// loser re-evaluates the WHERE against the winner's committed claimed_at,
// matches nothing, and picks again.
func (p *DiscoveryProcessor) processNextBatch() (bool, error) {
	batchID, tenantID, claimedAt, found, err := p.claimNextBatch()
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}

	fmt.Printf("Processing batch %s for tenant %s\n", batchID, tenantID)

	// One attempt, no in-process retry. A row that fails is recorded on the
	// row (process_attempts / process_error) and released with a backoff, so
	// its retry is a later claim — by the next wake or the fallback poll —
	// rather than a time.Sleep that held the claim, and the NATS message that
	// triggered it, for the whole retry ladder ( F14).
	err = p.processBatch(batchID, tenantID, claimedAt)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, errClaimLost) {
		// Another worker owns these rows now and will settle them; writing
		// anything back would only overwrite its bookkeeping.
		fmt.Printf("Batch %s: %v; leaving it to the new owner\n", batchID, err)
		return true, nil
	}
	var settled *RowFailuresError
	if errors.As(err, &settled) {
		// The rows that did not land are already recorded; everything else
		// in the batch was processed.
		return true, nil
	}
	// Renewal moves the claim's stamp; the failure record is fenced on it.
	var moved *claimMovedError
	if errors.As(err, &moved) {
		claimedAt = moved.current
	}

	// The batch failed before any row could be settled on its own (it could
	// not be read, or failed outright). Count the attempt against every row
	// still unprocessed — the same per-row ladder, so a batch that can never
	// import still ends, and one that hit a transient fault is retried after
	// the backoff instead of at once.
	terminal, recErr := p.recordBatchFailure(context.Background(), tenantID, batchID, claimedAt, err)
	if recErr != nil {
		// The rows keep their claim; batchClaimTimeout releases it.
		return true, fmt.Errorf("batch %s failed (%v) and recording the failure failed too: %w", batchID, err, recErr)
	}
	fmt.Printf("Batch %s failed: %v (%d row(s) now terminal, the rest retried with backoff)\n", batchID, err, terminal)
	return true, nil
}

// isPermanentError reports whether a batch failure is terminal (do not retry).
//
// Classification is on FACTS, not on error text. It used to substring-match
// "400"/"401"/"403"/"404"/"validation"/"invalid" anywhere in err.Error(), which
// terminally rejected — and so permanently discarded — whole batches over text
// that merely contained those substrings: a peer URL with port 8400, a
// mid-rotation TLS failure reading "certificate is not valid for host", any
// message quoting a payload containing the word "invalid".
//
// Two classifiers remain, both exact:
//   - client.HTTPStatusError carries the status code inventory-service actually
//     returned. A 4xx is permanent (the request is wrong and will stay wrong)
//     EXCEPT the transient statuses (isTransientStatus): 401/403 are HMAC clock
//     skew or a secret mid-rotation, 404 is a route that does not exist yet
//     during an inventory rollout, 409/423 are a conflict or lock that clears,
//     408/425/429 explicitly invite a retry. None of them says anything about
//     the rows, and rejecting every chunk's rows for one made an auth blip
//     destroy evidence.
//   - ErrNoValidFindings is raised locally for a batch where every discovery was
//     skipped for missing data; nothing about a retry can change that.
//
// Anything else is treated as transient. That is the safe default: a transient
// classification costs at most the retry budget, whereas a wrong "permanent"
// verdict destroys data.
func isPermanentError(err error) bool {
	if err == nil {
		return false
	}

	var statusErr *client.HTTPStatusError
	if errors.As(err, &statusErr) {
		if isTransientStatus(statusErr.StatusCode) {
			return false
		}
		return statusErr.StatusCode >= 400 && statusErr.StatusCode < 500
	}

	// An empty/unimportable batch (every finding skipped) will never become
	// importable on retry — fail fast instead of exhausting the retry budget.
	return errors.Is(err, ErrNoValidFindings)
}

// isTransientStatus reports whether an inventory-service status says the far
// side is unwell or unready rather than that the request is wrong.
func isTransientStatus(code int) bool {
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
		http.StatusRequestTimeout, http.StatusConflict, http.StatusLocked,
		http.StatusTooEarly, http.StatusTooManyRequests:
		return true
	}
	return code >= 500
}

// isTransientError reports whether a failure is of a class that clears by
// itself — a transient inventory-service status, or a transport failure
// reaching it. Such a failure is charged against the generous
// RetryPolicy.MaxTransientAttempts, not the ordinary budget.
func isTransientError(err error) bool {
	if err == nil {
		return false
	}
	var statusErr *client.HTTPStatusError
	if errors.As(err, &statusErr) {
		return isTransientStatus(statusErr.StatusCode)
	}
	var netErr net.Error
	var urlErr *url.Error
	return errors.As(err, &netErr) || errors.As(err, &urlErr) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.ErrUnexpectedEOF)
}

// isChunkRejection reports whether inventory-service refused a whole chunk for
// its content (400, 413, 422). The chunk's other findings may be fine, so the
// importer splits it and re-sends before declaring any row permanent.
func isChunkRejection(err error) bool {
	var statusErr *client.HTTPStatusError
	if !errors.As(err, &statusErr) {
		return false
	}
	switch statusErr.StatusCode {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		return true
	}
	return false
}
