package services

// Delivery retry (Gap 2).
//
// notification_delivery_queue shipped with retry_count and next_retry_at
// columns, an index on (next_retry_at) WHERE status='retrying', a status CHECK
// admitting 'retrying', and a retention sweep that deliberately spares
// non-terminal rows — every affordance for retry except a single INSERT. Until
// now the table was only ever DELETEd from, so a channel send that failed was
// attempted exactly once and lost.
//
// Shape of the fix:
//
//   - A failed channel send enqueues a row scoped to THAT channel with the
//     notification's payload. Retries never re-send on a channel that already
//     succeeded — a duplicate page is worse than the miss we are fixing.
//   - A worker drains due rows on a ticker with exponential backoff and a
//     bounded attempt count.
//   - After the last attempt the row goes to status='failed' with the final
//     error, which retention keeps for the full window. Giving up silently is
//     the same defect class as never retrying.
//   - Provably-permanent failures (see delivery_errors.go) skip retrying
//     entirely and are written straight to the terminal 'failed' record.
//
// Row lifecycle:
//
//	retrying --claim--> pending --success--> sent
//	                       |--transient, attempts left--> retrying
//	                       |--permanent or exhausted----> failed
//
// The claim sets next_retry_at = NOW() + claimTimeout, so a row orphaned by a
// crashed pod is identifiable as (status='pending' AND next_retry_at <= NOW())
// and is returned to 'retrying' by reclaimStaleClaims. Without that, a pod
// killed mid-attempt would strand the delivery in 'pending' forever — a retry
// system that silently stops retrying.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

const (
	// defaultMaxDeliveryAttempts bounds retries per (notification, channel).
	// With the backoff below this spans ~31 minutes before giving up.
	defaultMaxDeliveryAttempts = 5
	// retryBaseDelay is the wait before the first retry; each subsequent
	// attempt doubles it, capped at retryMaxDelay.
	retryBaseDelay = 1 * time.Minute
	retryMaxDelay  = 1 * time.Hour
	// claimTimeout is how long a claimed ('pending') row may stay in flight
	// before another worker may reclaim it.
	claimTimeout = 5 * time.Minute
	// retryBatchSize bounds one drain pass.
	retryBatchSize = 100
)

// DeliveryRetryEnabled is the operator kill-switch, following the house pattern
// (compliance-engine's COMPLIANCE_RECONCILE_WORKER_ENABLED): default on,
// NOTIFICATION_DELIVERY_RETRY_ENABLED=false disables BOTH enqueuing and the
// draining worker. Disabling it degrades to the previous behaviour — one
// attempt, no second chance — rather than silently accumulating a queue nobody
// drains.
func DeliveryRetryEnabled() bool {
	return os.Getenv("NOTIFICATION_DELIVERY_RETRY_ENABLED") != "false"
}

// MaxDeliveryAttempts resolves the per-(notification, channel) attempt bound
// from NOTIFICATION_DELIVERY_MAX_ATTEMPTS. Values < 1 fall back to the default:
// a zero bound would mean "enqueue, then give up before trying", which is worse
// than not enqueueing at all.
func MaxDeliveryAttempts() int {
	if v := os.Getenv("NOTIFICATION_DELIVERY_MAX_ATTEMPTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			return n
		}
	}
	return defaultMaxDeliveryAttempts
}

// retryBackoff returns the delay before attempt n (1-based): base * 2^(n-1),
// capped at retryMaxDelay. The cap also stops the shift overflowing for large
// configured attempt counts.
func retryBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := retryBaseDelay
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= retryMaxDelay {
			return retryMaxDelay
		}
	}
	return d
}

// enqueueFailedDeliveries records each failed channel of one notification.
// Permanent failures land directly in the terminal 'failed' state; transient
// ones are scheduled for the first retry.
//
// notificationID must reference an already-persisted notification_history row —
// the queue's FK is ON DELETE CASCADE against it — so callers enqueue only
// AFTER saveNotificationHistory.
func (s *NotificationService) enqueueFailedDeliveries(ctx context.Context, req *models.SendNotificationRequest,
	notificationID uuid.UUID, failures []ChannelFailure) {
	if len(failures) == 0 {
		return
	}
	if !DeliveryRetryEnabled() {
		s.logger.Printf("delivery retry disabled; %d failed channel delivery(ies) for notification %s will NOT be retried",
			len(failures), notificationID)
		return
	}
	for _, f := range failures {
		if err := s.enqueueFailedDelivery(ctx, req, notificationID, f); err != nil {
			// The retry row is the durable record; losing it means losing the
			// delivery. Log it rather than failing the (already-recorded) send.
			s.logger.Printf("failed to enqueue delivery retry (notification=%s channel=%s): %v",
				notificationID, f.ChannelID, err)
		}
	}
}

func (s *NotificationService) enqueueFailedDelivery(ctx context.Context, req *models.SendNotificationRequest,
	notificationID uuid.UUID, f ChannelFailure) error {
	payload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal retry payload: %w", err)
	}

	status := "retrying"
	var nextRetry interface{} = time.Now().Add(retryBackoff(1))
	errMsg := f.Err.Error()
	if IsPermanentDeliveryFailure(f.Err) {
		// Retrying cannot fix it. Record the terminal failure now — durable,
		// queryable, and swept by the normal retention window.
		status = "failed"
		nextRetry = nil
		errMsg = "permanent failure, not retried: " + errMsg
	}

	const q = `
		INSERT INTO notification_delivery_queue
		  (tenant_id, notification_id, channel_id, channel_type, payload, status, retry_count, next_retry_at, error_message)
		VALUES ($1,$2,$3,$4,$5,$6,0,$7,$8)`
	args := []interface{}{req.TenantID, notificationID, f.ChannelID, f.ChannelType, payload, status, nextRetry, errMsg}

	// Platform (NULL tenant) rows can never satisfy the tenant_isolation
	// WITH CHECK, so they go through the bypass role — same split as
	// enqueueDigest and saveNotificationHistory.
	if req.TenantID == nil {
		_, err := s.bypassDB.ExecContext(ctx, q, args...)
		return err
	}
	return shareddatabase.WithTenantTx(ctx, s.db.DB, *req.TenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, q, args...)
		return e
	})
}

// pendingDelivery is one claimed row being retried.
type pendingDelivery struct {
	id          uuid.UUID
	tenantID    *uuid.UUID
	channelID   uuid.UUID
	channelType string
	payload     []byte
	retryCount  int
}

// RetryDueDeliveries drains one batch of due retries. Cross-tenant, so it runs
// on the bypass role. Returns the number of deliveries that succeeded on this
// pass. Safe to call on a ticker and safe to run in more than one replica: rows
// are claimed with FOR UPDATE SKIP LOCKED before any send.
func (s *NotificationService) RetryDueDeliveries(ctx context.Context) (int, error) {
	if !DeliveryRetryEnabled() {
		return 0, nil
	}
	if err := s.reclaimStaleClaims(ctx); err != nil {
		s.logger.Printf("delivery retry: reclaim of stale claims failed: %v", err)
	}

	claimed, err := s.claimDueDeliveries(ctx, retryBatchSize)
	if err != nil {
		return 0, err
	}

	delivered := 0
	maxAttempts := MaxDeliveryAttempts()
	for _, d := range claimed {
		if s.retryOneDelivery(ctx, d, maxAttempts) {
			delivered++
		}
	}
	return delivered, nil
}

// claimDueDeliveries atomically moves due rows to the in-flight state and
// returns them. The claim and the read are one statement: two workers cannot
// both pick up the same row and double-send it.
func (s *NotificationService) claimDueDeliveries(ctx context.Context, limit int) ([]pendingDelivery, error) {
	rows, err := s.bypassDB.QueryContext(ctx, `
		UPDATE notification_delivery_queue q
		SET status = 'pending', next_retry_at = NOW() + $2::interval
		WHERE q.id IN (
			SELECT id FROM notification_delivery_queue
			WHERE status = 'retrying' AND next_retry_at IS NOT NULL AND next_retry_at <= NOW()
			ORDER BY next_retry_at
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING q.id, q.tenant_id, q.channel_id, q.channel_type, q.payload, q.retry_count`,
		limit, fmt.Sprintf("%d seconds", int(claimTimeout.Seconds())))
	if err != nil {
		return nil, fmt.Errorf("claim due deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []pendingDelivery
	for rows.Next() {
		var d pendingDelivery
		var tid uuid.NullUUID
		if err := rows.Scan(&d.id, &tid, &d.channelID, &d.channelType, &d.payload, &d.retryCount); err != nil {
			return nil, err
		}
		if tid.Valid {
			id := tid.UUID
			d.tenantID = &id
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// reclaimStaleClaims returns rows orphaned by a worker that died mid-attempt.
func (s *NotificationService) reclaimStaleClaims(ctx context.Context) error {
	_, err := s.bypassDB.ExecContext(ctx, `
		UPDATE notification_delivery_queue
		SET status = 'retrying'
		WHERE status = 'pending' AND next_retry_at IS NOT NULL AND next_retry_at <= NOW()`)
	return err
}

// retryOneDelivery re-sends a single claimed row on its own channel and records
// the outcome. Reports whether the delivery succeeded.
func (s *NotificationService) retryOneDelivery(ctx context.Context, d pendingDelivery, maxAttempts int) bool {
	attempt := d.retryCount + 1

	var req models.SendNotificationRequest
	if err := json.Unmarshal(d.payload, &req); err != nil {
		// The stored payload is unusable; no number of retries will parse it.
		s.finishDelivery(ctx, d, "failed", attempt, "corrupt retry payload: "+err.Error())
		return false
	}
	// The payload was serialized from the original request, whose TenantID is
	// authoritative; the row's tenant_id is the same value and is what RLS
	// scoping uses. Keep them consistent.
	req.TenantID = d.tenantID

	ch, ok := s.loadOneChannel(ctx, d.tenantID, d.channelID)
	if !ok {
		// The channel was deleted or disabled between the failure and the retry.
		// Delivering is impossible and will stay impossible.
		s.finishDelivery(ctx, d, "failed", attempt, "channel no longer available or disabled")
		return false
	}
	channelID, channelType, _ := channelIDType(ch)
	config := channelConfig(ch)

	err := s.deliveryService.SendToOneChannel(ctx, d.tenantID, channelID, channelType, config, &req)
	if err == nil {
		s.finishDelivery(ctx, d, "sent", attempt, "")
		return true
	}

	switch {
	case IsPermanentDeliveryFailure(err):
		s.finishDelivery(ctx, d, "failed", attempt, "permanent failure on retry: "+err.Error())
	case attempt >= maxAttempts:
		// Terminal, and said so: a durable record beats a loop that quietly stops.
		s.logger.Printf("delivery retry EXHAUSTED after %d attempt(s) (channel=%s type=%s tenant=%v): %v",
			attempt, channelID, channelType, d.tenantID, err)
		s.finishDelivery(ctx, d, "failed", attempt,
			fmt.Sprintf("gave up after %d attempt(s): %s", attempt, err.Error()))
	default:
		s.rescheduleDelivery(ctx, d, attempt, err.Error())
	}
	return false
}

// finishDelivery writes a terminal outcome ('sent' or 'failed').
func (s *NotificationService) finishDelivery(ctx context.Context, d pendingDelivery, status string, attempt int, errMsg string) {
	var msg interface{}
	if errMsg != "" {
		msg = errMsg
	}
	var deliveredAt interface{}
	if status == "sent" {
		deliveredAt = time.Now()
	}
	if _, err := s.bypassDB.ExecContext(ctx, `
		UPDATE notification_delivery_queue
		SET status = $1, retry_count = $2, next_retry_at = NULL, delivered_at = $3, error_message = $4
		WHERE id = $5`, status, attempt, deliveredAt, msg, d.id); err != nil {
		s.logger.Printf("delivery retry: failed to record terminal state for %s: %v", d.id, err)
	}
}

// rescheduleDelivery schedules the next attempt with exponential backoff.
func (s *NotificationService) rescheduleDelivery(ctx context.Context, d pendingDelivery, attempt int, errMsg string) {
	next := time.Now().Add(retryBackoff(attempt + 1))
	if _, err := s.bypassDB.ExecContext(ctx, `
		UPDATE notification_delivery_queue
		SET status = 'retrying', retry_count = $1, next_retry_at = $2, error_message = $3
		WHERE id = $4`, attempt, next, errMsg, d.id); err != nil {
		s.logger.Printf("delivery retry: failed to reschedule %s: %v", d.id, err)
	}
}

// channelConfig extracts the delivery config map from a loaded channel object.
func channelConfig(ch interface{}) map[string]interface{} {
	switch c := ch.(type) {
	case *models.TenantNotificationChannel:
		return c.Config
	case *models.PlatformNotificationChannel:
		return c.Config
	}
	return nil
}
