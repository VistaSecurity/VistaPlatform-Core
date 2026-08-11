package services

import (
	"context"
	"fmt"
	"os"
	"strconv"
)

// defaultHistoryRetentionDays bounds how long delivery logs are kept.
const defaultHistoryRetentionDays = 90

// HistoryRetentionDays resolves the retention window from
// NOTIFICATION_HISTORY_RETENTION_DAYS (falling back to the 90-day default).
// A value <= 0 disables cleanup.
func HistoryRetentionDays() int {
	if v := os.Getenv("NOTIFICATION_HISTORY_RETENTION_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return defaultHistoryRetentionDays
}

// CleanupOldHistory deletes delivery logs older than retentionDays from the
// append-only log tables (notification_history and the sent/failed rows of
// notification_delivery_queue). These are pure history — the stateful alerts /
// alert_events tables are owned by compliance-engine and are NOT touched here.
// Runs cross-scope via the bypass role. Returns the total rows removed.
func (s *NotificationService) CleanupOldHistory(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	interval := fmt.Sprintf("%d days", retentionDays)

	var total int64
	res, err := s.bypassDB.ExecContext(ctx,
		`DELETE FROM notification_history WHERE created_at < NOW() - $1::interval`, interval)
	if err != nil {
		return total, fmt.Errorf("cleanup notification_history: %w", err)
	}
	if n, e := res.RowsAffected(); e == nil {
		total += n
	}

	// Only terminal delivery-queue rows; leave pending/retrying in place.
	res, err = s.bypassDB.ExecContext(ctx,
		`DELETE FROM notification_delivery_queue
		 WHERE status IN ('sent', 'failed') AND created_at < NOW() - $1::interval`, interval)
	if err != nil {
		return total, fmt.Errorf("cleanup notification_delivery_queue: %w", err)
	}
	if n, e := res.RowsAffected(); e == nil {
		total += n
	}

	return total, nil
}
