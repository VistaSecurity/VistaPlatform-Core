package services

// Truthful delivery history.
//
// notification_history.status used to be "sent" whenever AT LEAST ONE channel
// delivered: SendToChannels only returns an error when EVERY channel failed, and
// the caller keyed the status off that error. A notification whose email failed
// while its in-app copy landed was recorded — and rendered — as a plain success.
// The retry worker then made it worse by never touching the history row again,
// so a delivery that eventually succeeded (or was abandoned) stayed frozen at
// whatever the first attempt said.
//
// The status vocabulary is the existing CHECK (sent / failed / pending /
// partial); nothing new is needed:
//
//	every channel delivered          -> sent
//	some delivered, some did not     -> partial
//	none delivered                   -> failed
//
// "did not" covers a failure that is still queued for retry: the row says
// partial/failed until the retry worker resolves it, at which point the worker
// recomputes the status (syncHistoryAfterRetry). The per-channel detail lives in
// the existing metadata jsonb under "channel_results" — one entry per attempted
// channel — so the row can say WHICH channel is outstanding without a schema
// change. Error text is deliberately not copied there: transport errors embed the
// request URL, and a webhook URL is a credential.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

const (
	channelResultSent     = "sent"
	channelResultRetrying = "retrying" // failed; a retry is queued
	channelResultFailed   = "failed"   // failed and will not be retried (permanent, exhausted, or retry disabled)
)

// historyStatusFor maps a delivery tally onto the notification_history status.
func historyStatusFor(delivered, unresolved int) string {
	switch {
	case unresolved == 0:
		return "sent"
	case delivered == 0:
		return "failed"
	default:
		return "partial"
	}
}

// buildChannelResults reports the outcome of one fan-out, one entry per
// attempted channel.
func buildChannelResults(attempted []interface{}, failures []ChannelFailure) []map[string]interface{} {
	failed := make(map[uuid.UUID]ChannelFailure, len(failures))
	for _, f := range failures {
		failed[f.ChannelID] = f
	}
	results := make([]map[string]interface{}, 0, len(attempted))
	for _, ch := range attempted {
		id, ctype, enabled := channelIDType(ch)
		if !enabled {
			continue
		}
		entry := map[string]interface{}{"channel_id": id.String(), "channel_type": ctype, "status": channelResultSent}
		if f, ok := failed[id]; ok {
			if IsPermanentDeliveryFailure(f.Err) || !DeliveryRetryEnabled() {
				entry["status"] = channelResultFailed
			} else {
				entry["status"] = channelResultRetrying
			}
			// Why, in the tenant-safe vocabulary (see failure_reasons.go) —
			// never the raw error, which can carry the channel's URL.
			entry["reason"] = SafeFailureReason(f.Err)
		}
		results = append(results, entry)
	}
	return results
}

// cloneMetadata copies a metadata map. history.Metadata starts out ALIASING the
// request's own Metadata (which is also what channels send and what a retry row
// serializes), so anything the history row adds must go on a copy.
func cloneMetadata(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m)+2)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// syncHistoryAfterRetry brings the notification_history row in line with a
// retry that just reached a terminal state. delivered says whether that retry
// succeeded; channelType is appended to channels_used when it did.
//
// One transaction, history row locked FOR UPDATE: two retries of the same
// notification can finish concurrently on different replicas, and the status is
// a function of the queue's current state, not of either worker's own outcome.
// Runs on the bypass role — the retry worker is cross-tenant, like the queue
// claim it follows.
func (s *NotificationService) syncHistoryAfterRetry(ctx context.Context, d pendingDelivery, delivered bool, exhausted bool, reason string) {
	if d.notificationID == uuid.Nil {
		return
	}
	if err := s.syncHistory(ctx, d, delivered, exhausted, reason); err != nil {
		// The queue row is already terminal, so the delivery outcome is safe;
		// only the summary row is stale. Say so.
		s.logger.Printf("delivery retry: failed to update notification history %s: %v", d.notificationID, err)
	}
}

func (s *NotificationService) syncHistory(ctx context.Context, d pendingDelivery, delivered, exhausted bool, reason string) error {
	tx, err := s.bypassDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var used pq.StringArray
	var metaRaw []byte
	err = tx.QueryRowContext(ctx,
		`SELECT channels_used, metadata FROM notification_history WHERE id = $1 FOR UPDATE`,
		d.notificationID).Scan(&used, &metaRaw)
	if err == sql.ErrNoRows {
		return nil // aged out by retention; nothing to update
	}
	if err != nil {
		return fmt.Errorf("lock history row: %w", err)
	}

	var unresolved int
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM notification_delivery_queue WHERE notification_id = $1 AND status <> 'sent'`,
		d.notificationID).Scan(&unresolved); err != nil {
		return fmt.Errorf("count unresolved deliveries: %w", err)
	}

	if delivered {
		used = append(used, d.channelType)
	}

	meta := map[string]interface{}{}
	if len(metaRaw) > 0 {
		_ = json.Unmarshal(metaRaw, &meta) // a non-object blob is replaced, not preserved
		if meta == nil {
			meta = map[string]interface{}{}
		}
	}
	meta["channel_results"] = updateChannelResult(meta["channel_results"], d, delivered, exhausted, reason)
	meta["last_retry_at"] = time.Now().UTC().Format(time.RFC3339)
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	status := historyStatusFor(len(used), unresolved)
	if _, err := tx.ExecContext(ctx,
		`UPDATE notification_history SET status = $1, channels_used = $2, metadata = $3 WHERE id = $4`,
		status, pq.Array([]string(used)), metaJSON, d.notificationID); err != nil {
		return fmt.Errorf("update history row: %w", err)
	}
	return tx.Commit()
}

// updateChannelResult sets this channel's entry in metadata.channel_results to
// its terminal outcome, adding the entry if the row predates channel_results
// (digest flushes, rows written before this change).
func updateChannelResult(existing interface{}, d pendingDelivery, delivered, exhausted bool, reason string) []interface{} {
	entries, _ := existing.([]interface{})
	status := channelResultFailed
	if delivered {
		status = channelResultSent
	}
	wanted := d.channelID.String()
	for _, e := range entries {
		m, ok := e.(map[string]interface{})
		if !ok || m["channel_id"] != wanted {
			continue
		}
		m["status"] = status
		if exhausted {
			m["retries_exhausted"] = true
		}
		setResultReason(m, delivered, reason)
		return entries
	}
	entry := map[string]interface{}{"channel_id": wanted, "channel_type": d.channelType, "status": status}
	if exhausted {
		entry["retries_exhausted"] = true
	}
	setResultReason(entry, delivered, reason)
	return append(entries, entry)
}

// setResultReason records why a channel's final outcome was a failure, and
// clears a stale reason once a retry finally delivers.
func setResultReason(entry map[string]interface{}, delivered bool, reason string) {
	switch {
	case delivered:
		delete(entry, "reason")
	case reason != "":
		entry["reason"] = reason
	}
}
