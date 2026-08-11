package processor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/nats-io/nats.go"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/client"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/config"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// DiscoveryProcessor handles polling and processing of sensor discoveries.
// It subscribes to NATS for instant notification of new batches and uses
// DB polling as a fallback for missed events.
type DiscoveryProcessor struct {
	db             *sqlx.DB
	bypassDB       *sqlx.DB
	batchProcessor *BatchProcessor
	config         *config.Config
	natsClient     *events.NATSClient
	subscriber     *events.Subscriber
	stopChan       chan struct{}
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
		log.Printf("[DiscoveryProcessor] Warning: NATS unavailable, using DB polling only: %v", err)
	} else {
		natsClient = nc
		subscriber = events.NewSubscriber(nc)
	}

	return &DiscoveryProcessor{
		db:             db,
		bypassDB:       bypassDB,
		batchProcessor: batchProcessor,
		config:         cfg,
		natsClient:     natsClient,
		subscriber:     subscriber,
		stopChan:       make(chan struct{}),
	}
}

// Start begins the processing loop with NATS subscription and DB polling fallback
func (p *DiscoveryProcessor) Start() error {
	// Subscribe to NATS for instant batch notifications
	if p.subscriber != nil {
		err := p.subscriber.Subscribe(events.SubscriptionConfig{
			Stream:            "DISCOVERY_JOBS",
			Subject:           events.SubjectDiscoveryJobsSubmit,
			Durable:           "discovery-processor-poll-trigger",
			QueueGroup:        "discovery-processor",
			MaxDeliver:        3,
			AckWait:           2 * time.Minute,
			ProcessingTimeout: 90 * time.Second,
		}, func(ctx context.Context, msg *nats.Msg) error {
			log.Printf("[DiscoveryProcessor] Received discovery job event via NATS, triggering batch poll")
			if err := p.processNextBatch(); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			log.Printf("[DiscoveryProcessor] Failed to subscribe to NATS: %v. Using DB polling only.", err)
		} else {
			log.Printf("[DiscoveryProcessor] Subscribed to NATS on %s", events.SubjectDiscoveryJobsSubmit)
		}
	}

	// DB polling fallback (longer interval since NATS handles primary delivery)
	pollInterval := time.Duration(p.config.PollIntervalSeconds) * time.Second
	if p.subscriber != nil {
		// Increase poll interval when NATS is active (it's just a fallback)
		pollInterval = pollInterval * 3
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	fmt.Printf("Discovery processor started (poll interval: %v)\n", pollInterval)

	for {
		select {
		case <-p.stopChan:
			fmt.Println("Discovery processor stopping...")
			return nil
		case <-ticker.C:
			if err := p.processNextBatch(); err != nil {
				fmt.Printf("Error processing batch: %v\n", err)
			}
		}
	}
}

// Stop stops the processing loop
func (p *DiscoveryProcessor) Stop() {
	close(p.stopChan)
	if p.subscriber != nil {
		p.subscriber.Drain()
	}
	if p.natsClient != nil {
		p.natsClient.Close()
	}
}

// batchClaimTimeout is how long a claim on a batch is honoured before another
// worker may take it over. It bounds the damage from a worker that crashes
// mid-batch: without a timeout, its claim would strand the batch forever.
// Comfortably longer than a normal batch (the NATS handler's own
// ProcessingTimeout is 90s) and than the retry ladder inside processNextBatch.
const batchClaimTimeout = 10 * time.Minute

// processNextBatch claims and processes the next unprocessed batch.
//
// The claim is what makes concurrent triggers safe. This method is invoked from
// BOTH the NATS subscription handler and the poll ticker (and, with more than
// one replica, from every replica's ticker). Selecting on `processed_at IS NULL`
// alone let two of those pick the same batch and run it twice — duplicate
// imports and double-incremented observation counts, because rows are only
// stamped processed at the END of ProcessBatch.
func (p *DiscoveryProcessor) processNextBatch() error {
	// Pick one unprocessed, unclaimed (or stale-claimed) batch and claim it in a
	// single statement. Two workers racing on the same candidate serialize on
	// the row locks; the loser re-evaluates the WHERE against the winner's
	// committed claimed_at, matches nothing, and gets an empty result — so
	// exactly one worker proceeds.
	//
	// RLS: cross-tenant — runs on the bypass role (Phase 4). This is the batch
	// poller: it scans sensor_discoveries (security_invoker view) across ALL
	// tenants for any unprocessed batch, grouping by (batch_id, tenant_id). It
	// cannot set app.tenant_id because the tenant is the query OUTPUT — the very
	// thing we are discovering. The resolved tenantID is then threaded into the
	// per-tenant ProcessBatch, which is RLS-scoped.
	query := `
		WITH candidate AS (
			SELECT batch_id, tenant_id
			FROM sensor_discoveries
			WHERE processed_at IS NULL
			  AND (claimed_at IS NULL OR claimed_at < now() - $1::interval)
			GROUP BY batch_id, tenant_id
			LIMIT 1
		),
		claimed AS (
			UPDATE sensor_discoveries d
			SET claimed_at = now()
			FROM candidate c
			WHERE d.batch_id = c.batch_id
			  AND d.tenant_id = c.tenant_id
			  AND d.processed_at IS NULL
			  AND (d.claimed_at IS NULL OR d.claimed_at < now() - $1::interval)
			RETURNING d.batch_id, d.tenant_id
		)
		SELECT batch_id, tenant_id FROM claimed GROUP BY batch_id, tenant_id
	`

	var batchID string
	var tenantID uuid.UUID

	// Run on the BYPASSRLS handle (crypto_bypass) directly — no WithTenantTx,
	// since this scan deliberately crosses tenants to discover which tenant the
	// next unprocessed batch belongs to. Under the enforcing crypto_app role this
	// query would fail closed (RLS hides every row with no app.tenant_id set).
	claimInterval := fmt.Sprintf("%d seconds", int(batchClaimTimeout.Seconds()))
	err := p.bypassDB.QueryRow(query, claimInterval).Scan(&batchID, &tenantID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// No unprocessed batches, or another worker already claimed the one
			// there was - both normal.
			return nil
		}
		return fmt.Errorf("failed to claim unprocessed batch: %w", err)
	}

	fmt.Printf("Processing batch %s for tenant %s\n", batchID, tenantID)

	// Process the batch with retry logic
	maxRetries := p.config.MaxRetries
	backoffBase := time.Duration(p.config.RetryBackoffBase) * time.Second

	for attempt := 0; attempt < maxRetries; attempt++ {
		err := p.batchProcessor.ProcessBatch(batchID, tenantID)
		if err == nil {
			// Success
			return nil
		}

		// Check if error is permanent (4xx) or transient (5xx, network errors)
		if isPermanentError(err) {
			// Permanent error - don't retry, mark batch as failed
			fmt.Printf("Permanent error processing batch %s: %v\n", batchID, err)
			return p.markBatchAsFailed(batchID, tenantID, err.Error())
		}

		// Transient error - retry with exponential backoff
		if attempt < maxRetries-1 {
			backoff := backoffBase * time.Duration(1<<uint(attempt)) // Exponential backoff
			if backoff > 30*time.Second {
				backoff = 30 * time.Second // Cap at 30 seconds
			}
			fmt.Printf("Transient error processing batch %s (attempt %d/%d): %v. Retrying in %v...\n",
				batchID, attempt+1, maxRetries, err, backoff)
			time.Sleep(backoff)
		}
	}

	// Max retries exceeded - mark as failed
	fmt.Printf("Max retries exceeded for batch %s. Marking as failed.\n", batchID)
	return p.markBatchAsFailed(batchID, tenantID, "max retries exceeded")
}

// markBatchAsFailed marks a batch's still-unprocessed discoveries as terminally
// failed so the poll loop (processNextBatch, WHERE processed_at IS NULL) stops
// re-selecting it. Without this, a batch that can never import — e.g. every
// finding skipped for missing data (cloud-API discoveries with no source IP) —
// is re-polled indefinitely, burning CPU and flooding logs on every cycle.
//
// We set processed_at (to drop it from the poll) and approval_status='rejected',
// which is the terminal "not accepted" value permitted by the
// sensor_discoveries_approval_status_check constraint.
func (p *DiscoveryProcessor) markBatchAsFailed(batchID string, tenantID uuid.UUID, errorMsg string) error {
	fmt.Printf("Batch %s failed: %s\n", batchID, errorMsg)

	// The poller already resolved tenantID for this batch, so this is a
	// single-tenant write even though the WHERE filters only by batch_id. Scope
	// it via WithTenantTx so the UPDATE on sensor_discoveries (security_invoker
	// view over the partitioned table) satisfies the tenant_isolation policy.
	// No ctx is threaded here, so use context.Background() per the existing pattern.
	ctx := context.Background()
	var rowsAffected int64
	err := shareddatabase.WithTenantTx(ctx, p.db.DB, tenantID, func(tx *sql.Tx) error {
		// tenant_id is in the predicate so the planner can prune to the single
		// hash partition that can hold this tenant's rows (the same reason
		// markProcessed carries it).
		res, e := tx.ExecContext(ctx, `
			UPDATE sensor_discoveries
			SET processed_at = $1, approval_status = 'rejected'
			WHERE tenant_id = $2 AND batch_id = $3 AND processed_at IS NULL`,
			time.Now().UTC(), tenantID, batchID)
		if e != nil {
			return e
		}
		rowsAffected, _ = res.RowsAffected()
		return nil
	})
	if err != nil {
		// Leave the rows unprocessed on a genuine DB error so the batch is
		// retried on the next poll/NATS trigger rather than silently dropped.
		return fmt.Errorf("failed to mark batch %s as failed: %w", batchID, err)
	}

	fmt.Printf("Marked %d discovery row(s) in batch %s as failed (processed_at set, approval_status=rejected)\n", rowsAffected, batchID)
	return nil
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
//     returned. 4xx is permanent (the request is wrong and will stay wrong),
//     except 408/425/429 which explicitly invite a retry.
//   - ErrNoValidFindings is raised locally for a batch where every discovery was
//     skipped for missing data; nothing about a retry can change that.
//
// Anything else is treated as transient. That is the safe default: a transient
// classification costs at most MaxRetries attempts, after which the poller marks
// the batch failed anyway — whereas a wrong "permanent" verdict destroys data.
func isPermanentError(err error) bool {
	if err == nil {
		return false
	}

	var statusErr *client.HTTPStatusError
	if errors.As(err, &statusErr) {
		switch statusErr.StatusCode {
		case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests:
			return false
		}
		return statusErr.StatusCode >= 400 && statusErr.StatusCode < 500
	}

	// An empty/unimportable batch (every finding skipped) will never become
	// importable on retry — fail fast instead of exhausting the retry budget.
	return errors.Is(err, ErrNoValidFindings)
}
